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
	"regexp"
	"strings"
	"time"

	"github.com/vmware-tanzu/velero/pkg/metrics"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
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

// sanitizeStorageError cleans up verbose HTTP responses from cloud provider errors,
// particularly Azure which includes full HTTP response details and XML in error messages.
// It extracts the error code and message while removing HTTP headers and response bodies.
// It also scrubs sensitive information like SAS tokens from URLs.
func sanitizeStorageError(err error) string {
	if err == nil {
		return ""
	}

	errMsg := err.Error()

	// Scrub sensitive information from URLs (SAS tokens, credentials, etc.)
	// Azure SAS token parameters: sig, se, st, sp, spr, sv, sr, sip, srt, ss
	// These appear as query parameters in URLs like: ?sig=value&se=value
	sasParamsRegex := regexp.MustCompile(`([?&])(sig|se|st|sp|spr|sv|sr|sip|srt|ss)=([^&\s<>\n]+)`)
	errMsg = sasParamsRegex.ReplaceAllString(errMsg, `${1}${2}=***REDACTED***`)

	// Check if this looks like an Azure HTTP response error
	// Azure errors contain patterns like "RESPONSE 404:" and "ERROR CODE:"
	if !strings.Contains(errMsg, "RESPONSE") || !strings.Contains(errMsg, "ERROR CODE:") {
		// Not an Azure-style error, return as-is
		return errMsg
	}

	// Extract the error code (e.g., "ContainerNotFound", "BlobNotFound")
	errorCodeRegex := regexp.MustCompile(`ERROR CODE:\s*(\w+)`)
	errorCodeMatch := errorCodeRegex.FindStringSubmatch(errMsg)
	var errorCode string
	if len(errorCodeMatch) > 1 {
		errorCode = errorCodeMatch[1]
	}

	// Extract the error message from the XML or plain text
	// Look for message between <Message> tags or after "RESPONSE XXX:"
	var errorMessage string

	// Try to extract from XML first
	messageRegex := regexp.MustCompile(`<Message>(.*?)</Message>`)
	messageMatch := messageRegex.FindStringSubmatch(errMsg)
	if len(messageMatch) > 1 {
		errorMessage = messageMatch[1]
		// Remove RequestId and Time from the message
		if idx := strings.Index(errorMessage, "\nRequestId:"); idx != -1 {
			errorMessage = errorMessage[:idx]
		}
	} else {
		// Try to extract from plain text response (e.g., "RESPONSE 404: 404 The specified container does not exist.")
		responseRegex := regexp.MustCompile(`RESPONSE\s+\d+:\s+\d+\s+([^\n]+)`)
		responseMatch := responseRegex.FindStringSubmatch(errMsg)
		if len(responseMatch) > 1 {
			errorMessage = strings.TrimSpace(responseMatch[1])
		}
	}

	// Build a clean error message
	var cleanMsg string
	if errorCode != "" && errorMessage != "" {
		cleanMsg = errorCode + ": " + errorMessage
	} else if errorCode != "" {
		cleanMsg = errorCode
	} else if errorMessage != "" {
		cleanMsg = errorMessage
	} else {
		// Fallback: try to extract the desc part from gRPC error
		descRegex := regexp.MustCompile(`desc\s*=\s*(.+)`)
		descMatch := descRegex.FindStringSubmatch(errMsg)
		if len(descMatch) > 1 {
			// Take everything up to the first newline or "RESPONSE" marker
			desc := descMatch[1]
			if idx := strings.Index(desc, "\n"); idx != -1 {
				desc = desc[:idx]
			}
			if idx := strings.Index(desc, "RESPONSE"); idx != -1 {
				desc = strings.TrimSpace(desc[:idx])
			}
			cleanMsg = desc
		} else {
			// Last resort: return first line
			if before, _, ok := strings.Cut(errMsg, "\n"); ok {
				cleanMsg = before
			} else {
				cleanMsg = errMsg
			}
		}
	}

	// Preserve the prefix part of the error (e.g., "rpc error: code = Unknown desc = ")
	// but replace the verbose description with our clean message
	if strings.Contains(errMsg, "desc = ") {
		parts := strings.SplitN(errMsg, "desc = ", 2)
		if len(parts) == 2 {
			return parts[0] + "desc = " + cleanMsg
		}
	}

	return cleanMsg
}

// BackupStorageLocationReconciler reconciles a BackupStorageLocation object
type backupStorageLocationReconciler struct {
	ctx                       context.Context
	client                    client.Client
	defaultBackupLocationInfo storage.DefaultBackupLocationInfo
	// use variables to refer to these functions so they can be
	// replaced with fakes for testing.
	newPluginManager  func(logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter persistence.ObjectBackupStoreGetter
	metrics           *metrics.ServerMetrics
	log               logrus.FieldLogger
}

// NewBackupStorageLocationReconciler initialize and return a backupStorageLocationReconciler struct
func NewBackupStorageLocationReconciler(
	ctx context.Context,
	client client.Client,
	defaultBackupLocationInfo storage.DefaultBackupLocationInfo,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	metrics *metrics.ServerMetrics,
	log logrus.FieldLogger) *backupStorageLocationReconciler {
	return &backupStorageLocationReconciler{
		ctx:                       ctx,
		client:                    client,
		defaultBackupLocationInfo: defaultBackupLocationInfo,
		newPluginManager:          newPluginManager,
		backupStoreGetter:         backupStoreGetter,
		metrics:                   metrics,
		log:                       log,
	}
}

// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations/status,verbs=get;update;patch

func (r *backupStorageLocationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var unavailableErrors []string
	var location velerov1api.BackupStorageLocation

	log := r.log.WithField("controller", constant.ControllerBackupStorageLocation).WithField(constant.ControllerBackupStorageLocation, req.NamespacedName.String())
	log.Debug("Validating availability of BackupStorageLocation")

	locationList, err := storage.ListBackupStorageLocations(r.ctx, r.client, req.Namespace)
	if err != nil {
		log.WithError(err).Error("No BackupStorageLocations found, at least one is required")
		return ctrl.Result{}, nil
	}

	pluginManager := r.newPluginManager(log)
	defer pluginManager.CleanupClients()

	// find the BSL that matches the request
	for _, bsl := range locationList.Items {
		if bsl.Name == req.Name && bsl.Namespace == req.Namespace {
			location = bsl
		}
	}

	if location.Name == "" || location.Namespace == "" {
		log.WithError(err).Error("BackupStorageLocation is not found")
		return ctrl.Result{}, nil
	}

	// decide the default BSL
	defaultFound, err := r.ensureSingleDefaultBSL(locationList)
	if err != nil {
		log.WithError(err).Error("failed to ensure single default bsl")
		return ctrl.Result{}, nil
	}

	func() {
		var err error
		original := location.DeepCopy()
		defer func() {
			location.Status.LastValidationTime = &metav1.Time{Time: time.Now().UTC()}
			if err != nil {
				log.Info("BackupStorageLocation is invalid, marking as unavailable")
				err = errors.Wrapf(err, "BackupStorageLocation %q is unavailable", location.Name)
				unavailableErrors = append(unavailableErrors, sanitizeStorageError(err))
				location.Status.Phase = velerov1api.BackupStorageLocationPhaseUnavailable
				location.Status.Message = sanitizeStorageError(err)
			} else {
				log.Info("BackupStorageLocations is valid, marking as available")
				location.Status.Phase = velerov1api.BackupStorageLocationPhaseAvailable
				location.Status.Message = ""
			}
			if err := r.client.Patch(r.ctx, &location, client.MergeFrom(original)); err != nil {
				log.WithError(err).Error("Error updating BackupStorageLocation phase")
			}
		}()

		// Validate the BackupStorageLocation spec
		if err = location.Validate(); err != nil {
			log.WithError(err).Error("BackupStorageLocation spec is invalid")
			return
		}

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
	}()

	r.logReconciledPhase(defaultFound, locationList, unavailableErrors)

	return ctrl.Result{}, nil
}

func (r *backupStorageLocationReconciler) logReconciledPhase(defaultFound bool, locationList velerov1api.BackupStorageLocationList, errs []string) {
	var availableBSLs []*velerov1api.BackupStorageLocation
	var unAvailableBSLs []*velerov1api.BackupStorageLocation
	var unknownBSLs []*velerov1api.BackupStorageLocation
	log := r.log.WithField("controller", constant.ControllerBackupStorageLocation)

	for i, location := range locationList.Items {
		phase := location.Status.Phase
		switch phase {
		case velerov1api.BackupStorageLocationPhaseAvailable:
			availableBSLs = append(availableBSLs, &locationList.Items[i])
			r.metrics.RegisterBackupLocationAvailable(locationList.Items[i].Name)
		case velerov1api.BackupStorageLocationPhaseUnavailable:
			unAvailableBSLs = append(unAvailableBSLs, &locationList.Items[i])
			r.metrics.RegisterBackupLocationUnavailable(locationList.Items[i].Name)
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
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		location := object.(*velerov1api.BackupStorageLocation)
		return storage.IsReadyToValidate(location.Spec.ValidationFrequency, location.Status.LastValidationTime, r.defaultBackupLocationInfo.ServerValidationFrequency, r.log.WithField("controller", constant.ControllerBackupStorageLocation))
	})
	g := kube.NewPeriodicalEnqueueSource(
		r.log.WithField("controller", constant.ControllerBackupStorageLocation),
		mgr.GetClient(),
		&velerov1api.BackupStorageLocationList{},
		bslValidationEnqueuePeriod,
		kube.PeriodicalEnqueueSourceOption{
			Predicates: []predicate.Predicate{gp},
		},
	)

	return ctrl.NewControllerManagedBy(mgr).
		// As the "status.LastValidationTime" field is always updated, this triggers new reconciling process, skip the update event that include no spec change to avoid the reconcile loop
		For(&velerov1api.BackupStorageLocation{}, builder.WithPredicates(kube.SpecChangePredicate{})).
		WatchesRawSource(g).
		Named(constant.ControllerBackupStorageLocation).
		Complete(r)
}

// ensureSingleDefaultBSL ensures that there is only one default BSL in the namespace.
// the default BSL priority is as follows:
// 1. follow the user's setting (the most recent validation BSL is the default BSL)
// 2. follow the server's setting ("velero server --default-backup-storage-location")
func (r *backupStorageLocationReconciler) ensureSingleDefaultBSL(locationList velerov1api.BackupStorageLocationList) (bool, error) {
	// get all default BSLs
	var defaultBSLs []*velerov1api.BackupStorageLocation
	var defaultFound bool
	for i, location := range locationList.Items {
		if location.Spec.Default {
			defaultBSLs = append(defaultBSLs, &locationList.Items[i])
		}
	}

	if len(defaultBSLs) > 1 { // more than 1 default BSL
		// find the most recent updated default BSL
		var mostRecentCreatedBSL *velerov1api.BackupStorageLocation
		defaultFound = true
		for _, bsl := range defaultBSLs {
			if mostRecentCreatedBSL == nil {
				mostRecentCreatedBSL = bsl
				continue
			}
			// For lack of a better way to compare timestamps, we use the CreationTimestamp
			// it cloud not really find the most recent updated BSL, but it is good enough for now
			bslTimestamp := bsl.CreationTimestamp
			mostRecentTimestamp := mostRecentCreatedBSL.CreationTimestamp
			if mostRecentTimestamp.Before(&bslTimestamp) {
				mostRecentCreatedBSL = bsl
			}
		}

		// unset all other default BSLs
		for _, bsl := range defaultBSLs {
			if bsl.Name != mostRecentCreatedBSL.Name {
				bsl.Spec.Default = false
				if err := r.client.Update(r.ctx, bsl); err != nil {
					return defaultFound, errors.Wrapf(err, "failed to unset default backup storage location %q", bsl.Name)
				}
				r.log.Debugf("update default backup storage location %q to false", bsl.Name)
			}
		}
	} else if len(defaultBSLs) == 0 { // no default BSL
		defaultFound = false
	} else { // only 1 default BSL
		defaultFound = true
	}
	return defaultFound, nil
}
