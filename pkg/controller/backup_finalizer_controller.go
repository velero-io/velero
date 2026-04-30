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
	"bytes"
	"context"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	pkgbackup "github.com/vmware-tanzu/velero/pkg/backup"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/util/encode"
)

// backupFinalizerReconciler reconciles a Backup object
type backupFinalizerReconciler struct {
	client            kbclient.Client
	globalCRClient    kbclient.Client
	clock             clocks.WithTickerAndDelayedExecution
	backupper         pkgbackup.Backupper
	newPluginManager  func(logrus.FieldLogger) clientmgmt.Manager
	backupTracker     BackupTracker
	metrics           *metrics.ServerMetrics
	backupStoreGetter persistence.ObjectBackupStoreGetter
	log               logrus.FieldLogger
	resourceTimeout   time.Duration
}

// NewBackupFinalizerReconciler initializes and returns backupFinalizerReconciler struct.
func NewBackupFinalizerReconciler(
	client kbclient.Client,
	globalCRClient kbclient.Client,
	clock clocks.WithTickerAndDelayedExecution,
	backupper pkgbackup.Backupper,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupTracker BackupTracker,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	log logrus.FieldLogger,
	metrics *metrics.ServerMetrics,
	resourceTimeout time.Duration,
) *backupFinalizerReconciler {
	return &backupFinalizerReconciler{
		client:            client,
		globalCRClient:    globalCRClient,
		clock:             clock,
		backupper:         backupper,
		newPluginManager:  newPluginManager,
		backupTracker:     backupTracker,
		backupStoreGetter: backupStoreGetter,
		log:               log,
		metrics:           metrics,
	}
}

// +kubebuilder:rbac:groups=velero.io,resources=backups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=backups/status,verbs=get;update;patch

func (r *backupFinalizerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.log.WithFields(logrus.Fields{
		"controller": "backup-finalizer",
		"backup":     req.NamespacedName,
	})

	// Fetch the Backup instance.
	log.Debug("Getting Backup")
	backup := &velerov1api.Backup{}
	if err := r.client.Get(ctx, req.NamespacedName, backup); err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("Unable to find Backup")
			return ctrl.Result{}, nil
		}

		log.WithError(err).Error("Error getting Backup")
		return ctrl.Result{}, errors.WithStack(err)
	}

	switch backup.Status.Phase {
	case velerov1api.BackupPhaseFinalizing, velerov1api.BackupPhaseFinalizingPartiallyFailed:
		// only process backups finalizing after  plugin operations are complete
	default:
		log.Debug("Backup is not awaiting finalizing, skipping")
		return ctrl.Result{}, nil
	}

	original := backup.DeepCopy()
	defer func() {
		switch backup.Status.Phase {
		case
			velerov1api.BackupPhaseCompleted,
			velerov1api.BackupPhasePartiallyFailed,
			velerov1api.BackupPhaseFailed,
			velerov1api.BackupPhaseFailedValidation:
			r.backupTracker.Delete(backup.Namespace, backup.Name)
		}
		// Always attempt to Patch the backup object and status after each reconciliation.
		//
		// if this patch fails, there may not be another opportunity to update the backup object without external update event.
		// so we retry
		// This retries updating Finalzing/FinalizingPartiallyFailed to Completed/PartiallyFailed
		if err := client.RetryOnErrorMaxBackOff(r.resourceTimeout, func() error { return r.client.Patch(ctx, backup, kbclient.MergeFrom(original)) }); err != nil {
			log.WithError(err).Error("Error updating backup")
			return
		}
	}()

	location := &velerov1api.BackupStorageLocation{}
	if err := r.client.Get(ctx, kbclient.ObjectKey{
		Namespace: backup.Namespace,
		Name:      backup.Spec.StorageLocation,
	}, location); err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}
	pluginManager := r.newPluginManager(log)
	defer pluginManager.CleanupClients()

	backupStore, err := r.backupStoreGetter.Get(location, pluginManager, log)
	if err != nil {
		log.WithError(err).Error("Error getting a backup store")
		return ctrl.Result{}, errors.WithStack(err)
	}

	// Download item operations list and backup contents
	operations, err := backupStore.GetBackupItemOperations(backup.Name)
	if err != nil {
		log.WithError(err).Error("Error getting backup item operations")
		return ctrl.Result{}, errors.WithStack(err)
	}

	backupRequest := &pkgbackup.Request{
		Backup:           backup,
		StorageLocation:  location,
		SkippedPVTracker: pkgbackup.NewSkipPVTracker(),
		BackedUpItems:    pkgbackup.NewBackedUpItemsMap(),
	}
	var outBackupFile *os.File
	if len(operations) > 0 {
		log.Info("Setting up finalized backup temp file")
		inBackupFile, err := downloadToTempFile(backup.Name, backupStore, log)
		if err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error downloading backup")
		}
		defer closeAndRemoveFile(inBackupFile, log)
		outBackupFile, err = os.CreateTemp("", "")
		if err != nil {
			log.WithError(err).Error("error creating temp file for backup")
			return ctrl.Result{}, errors.WithStack(err)
		}
		defer closeAndRemoveFile(outBackupFile, log)

		log.Info("Getting backup item actions")
		actions, err := pluginManager.GetBackupItemActionsV2()
		if err != nil {
			log.WithError(err).Error("error getting Backup Item Actions")
			return ctrl.Result{}, errors.WithStack(err)
		}
		backupItemActionsResolver := framework.NewBackupItemActionResolverV2(actions)

		// Call itemBackupper.BackupItem for the list of items updated by async operations
		err = r.backupper.FinalizeBackup(
			log,
			backupRequest,
			inBackupFile,
			outBackupFile,
			backupItemActionsResolver,
			operations,
			backupStore,
		)
		if err != nil {
			log.WithError(err).Error("error finalizing Backup")
			return ctrl.Result{}, errors.WithStack(err)
		}
	}
	backupScheduleName := backupRequest.GetLabels()[velerov1api.ScheduleNameLabel]

	// Determine the final phase and completion timestamp, but do NOT set them
	// on the in-memory backup object yet. We first need to upload metadata and
	// contents to object storage. If the upload fails, the deferred patch must
	// NOT write a terminal phase to the API server so the controller can retry.
	var finalPhase velerov1api.BackupPhase
	switch backup.Status.Phase {
	case velerov1api.BackupPhaseFinalizing:
		finalPhase = velerov1api.BackupPhaseCompleted
	case velerov1api.BackupPhaseFinalizingPartiallyFailed:
		finalPhase = velerov1api.BackupPhasePartiallyFailed
	}

	completionTimestamp := &metav1.Time{Time: r.clock.Now()}
	csiVolumeSnapshotsCompleted := updateCSIVolumeSnapshotsCompleted(operations)

	// Encode backup JSON with the final phase for object storage, so that the
	// metadata in storage reflects the completed state.
	backupForUpload := backup.DeepCopy()
	backupForUpload.Status.Phase = finalPhase
	backupForUpload.Status.CompletionTimestamp = completionTimestamp
	backupForUpload.Status.CSIVolumeSnapshotsCompleted = csiVolumeSnapshotsCompleted

	backupJSON := new(bytes.Buffer)
	if err := encode.To(backupForUpload, "json", backupJSON); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error encoding backup json")
	}
	err = backupStore.PutBackupMetadata(backup.Name, backupJSON)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error uploading backup json")
	}
	if len(operations) > 0 {
		err = backupStore.PutBackupContents(backup.Name, outBackupFile)
		if err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error uploading backup final contents")
		}
	}

	// Uploads succeeded — now safe to set the final phase on the in-memory
	// backup object so the deferred patch writes it to the API server.
	backup.Status.Phase = finalPhase
	backup.Status.CompletionTimestamp = completionTimestamp
	backup.Status.CSIVolumeSnapshotsCompleted = csiVolumeSnapshotsCompleted

	switch finalPhase {
	case velerov1api.BackupPhaseCompleted:
		r.metrics.RegisterBackupSuccess(backupScheduleName)
		r.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusSucc)
	case velerov1api.BackupPhasePartiallyFailed:
		r.metrics.RegisterBackupPartialFailure(backupScheduleName)
		r.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusFailure)
	}

	recordBackupMetrics(log, backup, outBackupFile, r.metrics, true)

	return ctrl.Result{}, nil
}

func (r *backupFinalizerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Backup{}).
		Named(constant.ControllerBackupFinalizer).
		Complete(r)
}

// updateCSIVolumeSnapshotsCompleted calculate the completed VS number according to
// the backup's async operation list.
func updateCSIVolumeSnapshotsCompleted(
	operations []*itemoperation.BackupOperation) int {
	completedNum := 0

	for index := range operations {
		if operations[index].Spec.ResourceIdentifier.String() == kuberesource.VolumeSnapshots.String() &&
			operations[index].Status.Phase == itemoperation.OperationPhaseCompleted {
			completedNum++
		}
	}

	return completedNum
}
