/*
Copyright 2017 the Velero contributors.

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
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	pkgbackup "github.com/vmware-tanzu/velero/pkg/backup"
	veleroclient "github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	veleroutil "github.com/vmware-tanzu/velero/pkg/util/velero"
)

const (
	defaultGCFrequency       = 60 * time.Minute
	garbageCollectionFailure = "velero.io/gc-failure"
	gcFailureBSLNotFound     = "BSLNotFound"
	gcFailureBSLCannotGet    = "BSLCannotGet"
	gcFailureBSLReadOnly     = "BSLReadOnly"
	gcFailureBSLUnavailable  = "BSLUnavailable"
)

// gcReconciler creates DeleteBackupRequests for expired backups.
type gcReconciler struct {
	client.Client
	logger    logrus.FieldLogger
	clock     clocks.WithTickerAndDelayedExecution
	frequency time.Duration
}

// NewGCReconciler constructs a new gcReconciler.
func NewGCReconciler(
	logger logrus.FieldLogger,
	client client.Client,
	frequency time.Duration,
) *gcReconciler {
	gcr := &gcReconciler{
		Client:    client,
		logger:    logger,
		clock:     clocks.RealClock{},
		frequency: frequency,
	}
	if gcr.frequency <= 0 {
		gcr.frequency = defaultGCFrequency
	}
	return gcr
}

// GCController only watches on CreateEvent for ensuring every new backup will be taken care of.
// Other Events will be filtered to decrease the number of reconcile call. Especially UpdateEvent must be filtered since we removed
// the backup status as the sub-resource of backup in v1.9, every change on it will be treated as UpdateEvent and trigger reconcile call.
func (c *gcReconciler) SetupWithManager(mgr ctrl.Manager) error {
	s := kube.NewPeriodicalEnqueueSource(c.logger.WithField("controller", constant.ControllerGarbageCollection), mgr.GetClient(), &velerov1api.BackupList{}, c.frequency, kube.PeriodicalEnqueueSourceOption{})
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Backup{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(ue event.UpdateEvent) bool {
				return false
			},
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
			GenericFunc: func(ge event.GenericEvent) bool {
				return false
			},
		})).
		WatchesRawSource(s).
		Named(constant.ControllerGarbageCollection).
		Complete(c)
}

// +kubebuilder:rbac:groups=velero.io,resources=backups,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=velero.io,resources=backups/status,verbs=get
// +kubebuilder:rbac:groups=velero.io,resources=deletebackuprequests,verbs=get;list;watch;create;
// +kubebuilder:rbac:groups=velero.io,resources=deletebackuprequests/status,verbs=get
// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations,verbs=get

func (c *gcReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.logger.WithField("gc backup", req.String())
	log.Debug("gcController getting backup")

	backup := &velerov1api.Backup{}
	if err := c.Get(ctx, req.NamespacedName, backup); err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Error("backup not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrapf(err, "error getting backup %s", req.String())
	}
	log.Debugf("backup: %s", backup.Name)

	log = c.logger.WithFields(
		logrus.Fields{
			"backup":     req.String(),
			"expiration": backup.Status.Expiration,
		},
	)

	now := c.clock.Now()
	if backup.Status.Expiration == nil || backup.Status.Expiration.After(now) {
		log.Debug("Backup has not expired yet, skipping")
		return ctrl.Result{}, nil
	}

	log.Infof("Backup:%s has expired", backup.Name)

	if backup.Labels == nil {
		backup.Labels = make(map[string]string)
	}

	loc := &velerov1api.BackupStorageLocation{}
	if err := c.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      backup.Spec.StorageLocation,
	}, loc); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warnf("Backup cannot be garbage-collected because backup storage location %s does not exist", backup.Spec.StorageLocation)
			backup.Labels[garbageCollectionFailure] = gcFailureBSLNotFound
		} else {
			backup.Labels[garbageCollectionFailure] = gcFailureBSLCannotGet
		}

		if err := c.Update(ctx, backup); err != nil {
			log.WithError(err).Error("error updating backup labels")
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting backup storage location")
	}

	if !veleroutil.BSLIsAvailable(*loc) {
		log.Infof("BSL %s is unavailable, cannot gc backup", loc.Name)
		return ctrl.Result{}, fmt.Errorf("bsl %s is unavailable, cannot gc backup", loc.Name)
	}

	if loc.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly {
		log.Infof("Backup cannot be garbage-collected because backup storage location %s is currently in read-only mode", loc.Name)
		backup.Labels[garbageCollectionFailure] = gcFailureBSLReadOnly
		if err := c.Update(ctx, backup); err != nil {
			log.WithError(err).Error("error updating backup labels")
		}
		return ctrl.Result{}, nil
	}

	// remove gc fail error label after this point
	delete(backup.Labels, garbageCollectionFailure)
	if err := c.Update(ctx, backup); err != nil {
		log.WithError(err).Error("error updating backup labels")
	}

	selector := client.MatchingLabels{
		velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
		velerov1api.BackupUIDLabel:  string(backup.UID),
	}

	dbrs := &velerov1api.DeleteBackupRequestList{}
	if err := c.List(ctx, dbrs, selector); err != nil {
		log.WithError(err).Error("error listing DeleteBackupRequests")
		return ctrl.Result{}, errors.Wrap(err, "error listing existing DeleteBackupRequests for backup")
	}
	log.Debugf("length of dbrs:%d", len(dbrs.Items))

	// if there's an existing unprocessed deletion request for this backup, don't create
	// another one
	for _, dbr := range dbrs.Items {
		switch dbr.Status.Phase {
		case "", velerov1api.DeleteBackupRequestPhaseNew, velerov1api.DeleteBackupRequestPhaseInProgress:
			log.Info("Backup already has a pending deletion request")
			return ctrl.Result{}, nil
		}
	}

	log.Info("Creating a new deletion request")
	ndbr := pkgbackup.NewDeleteBackupRequest(backup.Name, string(backup.UID))
	ndbr.SetNamespace(backup.Namespace)
	if err := veleroclient.CreateRetryGenerateName(c, ctx, ndbr); err != nil {
		log.WithError(err).Error("error creating DeleteBackupRequests")
		return ctrl.Result{}, errors.Wrap(err, "error creating DeleteBackupRequest")
	}

	return ctrl.Result{}, nil
}
