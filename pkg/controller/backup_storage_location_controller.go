/*
Copyright the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	// keep the enqueue period a smaller value to make sure the BSL can be validated as expected.
	// The BSL validation frequency is 1 minute by default, if we set the enqueue period as 1 minute,
	// this will cause the actual validation interval for each BSL to be 2 minutes
	bslValidationEnqueuePeriod = 10 * time.Second
)

// BackupStorageLocationReconciler reconciles a BackupStorageLocation object
type backupStorageLocationReconciler struct {
	ctx                       context.Context
	client                    client.Client
	scheme                    *runtime.Scheme
	defaultBackupLocationInfo storage.DefaultBackupLocationInfo
	// use variables to refer to these functions so they can be
	// replaced with fakes for testing.
	newPluginManager  func(logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter persistence.ObjectBackupStoreGetter

	log logrus.FieldLogger
}

// NewBackupStorageLocationReconciler initialize and return a backupStorageLocationReconciler struct
func NewBackupStorageLocationReconciler(
	ctx context.Context,
	client client.Client,
	scheme *runtime.Scheme,
	defaultBackupLocationInfo storage.DefaultBackupLocationInfo,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	log logrus.FieldLogger) *backupStorageLocationReconciler {
	return &backupStorageLocationReconciler{
		ctx:                       ctx,
		client:                    client,
		scheme:                    scheme,
		defaultBackupLocationInfo: defaultBackupLocationInfo,
		newPluginManager:          newPluginManager,
		backupStoreGetter:         backupStoreGetter,
		log:                       log,
	}
}

// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations/status,verbs=get;update;patch

func (r *backupStorageLocationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var unavailableErrors []string
	var location velerov1api.BackupStorageLocation

	log := r.log.WithField("controller", BackupStorageLocation).WithField(BackupStorageLocation, req.String())
	log.Debug("Validating availability of BackupStorageLocation")

	locationList, err := storage.ListBackupStorageLocations(r.ctx, r.client, req.Namespace)
	if err != nil {
		log.WithError(err).Error("No BackupStorageLocations found, at least one is required")
		return ctrl.Result{}, nil
	}

	pluginManager := r.newPluginManager(log)
	defer pluginManager.CleanupClients()

	var defaultFound bool
	for _, bsl := range locationList.Items {
		if bsl.Spec.Default {
			defaultFound = true
		}
		if bsl.Name == req.Name && bsl.Namespace == req.Namespace {
			location = bsl
		}
	}

	if location.Name == "" || location.Namespace == "" {
		log.WithError(err).Error("BackupStorageLocation is not found")
		return ctrl.Result{}, nil
	}

	isDefault := location.Spec.Default

	// TODO(2.0) remove this check since the server default will be deprecated
	if !defaultFound && location.Name == r.defaultBackupLocationInfo.StorageLocation {
		// For backward-compatible, to configure the backup storage location as the default if
		// none of the BSLs be marked as the default and the BSL name matches against the
		// "velero server --default-backup-storage-location".
		isDefault = true
		defaultFound = true
	}

	func() {
		var err error
		original := location.DeepCopy()
		defer func() {
			location.Status.LastValidationTime = &metav1.Time{Time: time.Now().UTC()}
			if err != nil {
				log.Info("BackupStorageLocation is invalid, marking as unavailable")
				err = errors.Wrapf(err, "BackupStorageLocation %q is unavailable", location.Name)
				unavailableErrors = append(unavailableErrors, err.Error())
				location.Status.Phase = velerov1api.BackupStorageLocationPhaseUnavailable
				location.Status.Message = err.Error()
			} else {
				log.Info("BackupStorageLocations is valid, marking as available")
				location.Status.Phase = velerov1api.BackupStorageLocationPhaseAvailable
				location.Status.Message = ""
			}
			if err := r.client.Patch(r.ctx, &location, client.MergeFrom(original)); err != nil {
				log.WithError(err).Error("Error updating BackupStorageLocation phase")
			}
		}()

		backupStore, err := r.backupStoreGetter.Get(&location, pluginManager, log)
		if err != nil {
			log.WithError(err).Error("Error getting a backup store")
			return
		}

		log.Info("Validating BackupStorageLocation")
		err = backupStore.IsValid()
		if err != nil {
			log.WithError(err).Error("fail to validate backup store")
			return
		}

		// updates the default backup location
		location.Spec.Default = isDefault
	}()

	r.logReconciledPhase(defaultFound, locationList, unavailableErrors)

	return ctrl.Result{}, nil
}

func (r *backupStorageLocationReconciler) logReconciledPhase(defaultFound bool, locationList velerov1api.BackupStorageLocationList, errs []string) {
	var availableBSLs []*velerov1api.BackupStorageLocation
	var unAvailableBSLs []*velerov1api.BackupStorageLocation
	var unknownBSLs []*velerov1api.BackupStorageLocation
	log := r.log.WithField("controller", BackupStorageLocation)

	for i, location := range locationList.Items {
		phase := location.Status.Phase
		switch phase {
		case velerov1api.BackupStorageLocationPhaseAvailable:
			availableBSLs = append(availableBSLs, &locationList.Items[i])
		case velerov1api.BackupStorageLocationPhaseUnavailable:
			unAvailableBSLs = append(unAvailableBSLs, &locationList.Items[i])
		default:
			unknownBSLs = append(unknownBSLs, &locationList.Items[i])
		}
	}

	numAvailable := len(availableBSLs)
	numUnavailable := len(unAvailableBSLs)
	numUnknown := len(unknownBSLs)

	if numUnavailable+numUnknown == len(locationList.Items) { // no available BSL
		if len(errs) > 0 {
			log.Errorf("Current BackupStorageLocations available/unavailable/unknown: %v/%v/%v, %s)", numAvailable, numUnavailable, numUnknown, strings.Join(errs, "; "))
		} else {
			log.Errorf("Current BackupStorageLocations available/unavailable/unknown: %v/%v/%v)", numAvailable, numUnavailable, numUnknown)
		}
	} else if numUnavailable > 0 { // some but not all BSL unavailable
		log.Warnf("Unavailable BackupStorageLocations detected: available/unavailable/unknown: %v/%v/%v, %s)", numAvailable, numUnavailable, numUnknown, strings.Join(errs, "; "))
	}

	if !defaultFound {
		log.Warn("There is no existing BackupStorageLocation set as default. Please see `velero backup-location -h` for options.")
	}
}

func (r *backupStorageLocationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	g := kube.NewPeriodicalEnqueueSource(
		r.log,
		mgr.GetClient(),
		&velerov1api.BackupStorageLocationList{},
		bslValidationEnqueuePeriod,
		kube.PeriodicalEnqueueSourceOption{},
	)
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		location := object.(*velerov1api.BackupStorageLocation)
		return storage.IsReadyToValidate(location.Spec.ValidationFrequency, location.Status.LastValidationTime, r.defaultBackupLocationInfo.ServerValidationFrequency, r.log.WithField("controller", BackupStorageLocation))
	})
	return ctrl.NewControllerManagedBy(mgr).
		// As the "status.LastValidationTime" field is always updated, this triggers new reconciling process, skip the update event that include no spec change to avoid the reconcile loop
		For(&velerov1api.BackupStorageLocation{}, builder.WithPredicates(kube.SpecChangePredicate{})).
		Watches(g, nil, builder.WithPredicates(gp)).
		Complete(r)
}
