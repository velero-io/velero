/*
Copyright 2020 the Velero contributors.

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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	jsonpatch "github.com/evanphx/json-patch/v5"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/internal/credentials"
	"github.com/velero-io/velero/internal/delete"
	"github.com/velero-io/velero/internal/volume"
	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/constant"
	"github.com/velero-io/velero/pkg/discovery"
	"github.com/velero-io/velero/pkg/label"
	"github.com/velero-io/velero/pkg/metrics"
	"github.com/velero-io/velero/pkg/persistence"
	"github.com/velero-io/velero/pkg/plugin/clientmgmt"
	vsv1 "github.com/velero-io/velero/pkg/plugin/velero/volumesnapshotter/v1"
	"github.com/velero-io/velero/pkg/podvolume"
	"github.com/velero-io/velero/pkg/repository"
	repomanager "github.com/velero-io/velero/pkg/repository/manager"
	repotypes "github.com/velero-io/velero/pkg/repository/types"
	"github.com/velero-io/velero/pkg/repository/udmrepo"
	"github.com/velero-io/velero/pkg/uploader"
	"github.com/velero-io/velero/pkg/util/boolptr"
	"github.com/velero-io/velero/pkg/util/csi"
	"github.com/velero-io/velero/pkg/util/filesystem"
	"github.com/velero-io/velero/pkg/util/kube"
	retainedsnapshot "github.com/velero-io/velero/pkg/util/retainedsnapshot"
	veleroutil "github.com/velero-io/velero/pkg/util/velero"
)

const (
	deleteBackupRequestMaxAge = 24 * time.Hour
)

type backupDeletionReconciler struct {
	client.Client
	// apiReader reads from the API server instead of the cache: the reads the
	// deletion's safety decisions are made on -- whether the record family
	// has pending work, and which entries still need their handle resolved --
	// must not miss a shard a gather just created or see a pre-activation
	// copy, or the tail would remove the Backup and the tarball while
	// retained snapshots are still pending.
	apiReader         client.Reader
	logger            logrus.FieldLogger
	backupTracker     BackupTracker
	repoMgr           repomanager.Manager
	metrics           *metrics.ServerMetrics
	clock             clock.Clock
	discoveryHelper   discovery.Helper
	newPluginManager  func(logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter persistence.ObjectBackupStoreGetter
	credentialStore   credentials.FileStore
	repoEnsurer       *repository.Ensurer
}

// NewBackupDeletionReconciler creates a new backup deletion reconciler. The
// apiReader reads uncached; a nil apiReader falls back to the cached client.
func NewBackupDeletionReconciler(
	logger logrus.FieldLogger,
	client client.Client,
	apiReader client.Reader,
	backupTracker BackupTracker,
	repoMgr repomanager.Manager,
	metrics *metrics.ServerMetrics,
	helper discovery.Helper,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	credentialStore credentials.FileStore,
	repoEnsurer *repository.Ensurer,
) *backupDeletionReconciler {
	return &backupDeletionReconciler{
		Client:            client,
		apiReader:         apiReader,
		logger:            logger,
		backupTracker:     backupTracker,
		repoMgr:           repoMgr,
		metrics:           metrics,
		clock:             clock.RealClock{},
		discoveryHelper:   helper,
		newPluginManager:  newPluginManager,
		backupStoreGetter: backupStoreGetter,
		credentialStore:   credentialStore,
		repoEnsurer:       repoEnsurer,
	}
}

// familyReader returns the reader the retained snapshot record family is
// loaded through: the uncached API reader when one is given, the client
// itself otherwise, e.g. in tests.
func (r *backupDeletionReconciler) familyReader() client.Reader {
	if r.apiReader != nil {
		return r.apiReader
	}
	return r.Client
}

func (r *backupDeletionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Make sure the expired requests can be deleted eventually
	s := kube.NewPeriodicalEnqueueSource(r.logger.WithField("controller", constant.ControllerBackupDeletion), mgr.GetClient(), &velerov1api.DeleteBackupRequestList{}, time.Hour, kube.PeriodicalEnqueueSourceOption{})
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.DeleteBackupRequest{}).
		WatchesRawSource(s).
		Complete(r)
}

// +kubebuilder:rbac:groups=velero.io,resources=deletebackuprequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=deletebackuprequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=velero.io,resources=backups,verbs=delete

func (r *backupDeletionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithFields(logrus.Fields{
		"controller":          constant.ControllerBackupDeletion,
		"deletebackuprequest": req.String(),
	})
	log.Debug("Getting deletebackuprequest")
	dbr := &velerov1api.DeleteBackupRequest{}
	if err := r.Get(ctx, req.NamespacedName, dbr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("Unable to find the deletebackuprequest")
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("Error getting deletebackuprequest")
		return ctrl.Result{}, err
	}

	// Since we use the reconciler along with the PeriodicalEnqueueSource, there may be reconciliation triggered by
	// stale requests.
	// A request carrying the retained-snapshots-pending annotation is let back
	// in to evaluate completion, and only such a request: the re-entry path
	// below repairs the family activation, re-reads the family, and runs the
	// tail, meaning tarball removal and completion, only when nothing is
	// active; a re-entry that finds pending work goes back to waiting without
	// touching the tail. The annotated request is exempt from the max-age
	// deletion, so a slow snapshot controller cannot have its request deleted
	// mid-deletion.
	if dbr.Status.Phase == velerov1api.DeleteBackupRequestPhaseProcessed ||
		(dbr.Status.Phase == velerov1api.DeleteBackupRequestPhaseInProgress &&
			dbr.Annotations[velerov1api.RetainedSnapshotsPendingAnnotation] == "") {
		age := r.clock.Now().Sub(dbr.CreationTimestamp.Time)
		if age >= deleteBackupRequestMaxAge { // delete the expired request
			log.Debugf("The request is expired, status: %s, deleting it.", dbr.Status.Phase)
			if err := r.Delete(ctx, dbr); err != nil {
				log.WithError(err).Error("Error deleting DeleteBackupRequest")
			}
		} else {
			log.Infof("The request has status '%s', skip.", dbr.Status.Phase)
		}
		return ctrl.Result{}, nil
	}

	// Make sure we have the backup name
	if dbr.Spec.BackupName == "" {
		err := r.patchDeleteBackupRequestWithError(ctx, dbr, errors.New("spec.backupName is required"))
		return ctrl.Result{}, err
	}

	log = log.WithField("backup", dbr.Spec.BackupName)

	// Remove any existing deletion requests for this backup so we only have
	// one at a time
	if errs := r.deleteExistingDeletionRequests(ctx, dbr, log); errs != nil {
		return ctrl.Result{}, kubeerrs.NewAggregate(errs)
	}

	// Don't allow deleting an in-progress backup
	if r.backupTracker.Contains(dbr.Namespace, dbr.Spec.BackupName) {
		err := r.patchDeleteBackupRequestWithError(ctx, dbr, errors.New("backup is still in progress"))
		return ctrl.Result{}, err
	}

	// Get the backup we're trying to delete
	backup := &velerov1api.Backup{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: dbr.Namespace,
		Name:      dbr.Spec.BackupName,
	}, backup); apierrors.IsNotFound(err) {
		// Couldn't find backup - update status to Processed and record the not-found error
		err = r.patchDeleteBackupRequestWithError(ctx, dbr, errors.New("backup not found"))
		return ctrl.Result{}, err
	} else if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error getting backup")
	}
	// Don't allow deleting backups in read-only storage locations
	location := &velerov1api.BackupStorageLocation{}
	if err := r.Get(context.Background(), client.ObjectKey{
		Namespace: backup.Namespace,
		Name:      backup.Spec.StorageLocation,
	}, location); err != nil {
		if apierrors.IsNotFound(err) {
			err := r.patchDeleteBackupRequestWithError(ctx, dbr, fmt.Errorf("backup storage location %s not found", backup.Spec.StorageLocation))
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting backup storage location")
	}

	if location.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly {
		err := r.patchDeleteBackupRequestWithError(ctx, dbr, fmt.Errorf("cannot delete backup because backup storage location %s is currently in read-only mode", location.Name))
		return ctrl.Result{}, err
	}

	if !veleroutil.BSLIsAvailable(*location) {
		err := r.patchDeleteBackupRequestWithError(ctx, dbr, fmt.Errorf("cannot delete backup because backup storage location %s is currently in Unavailable state", location.Name))
		return ctrl.Result{}, err
	}

	if err := podvolume.ValidateBackupUploadersIfAny(ctx, r.Client, backup); err != nil {
		return ctrl.Result{}, r.patchDeleteBackupRequestWithError(ctx, dbr, err)
	}

	// if the request object has no labels defined, initialize an empty map since
	// we will be updating labels
	if dbr.Labels == nil {
		dbr.Labels = map[string]string{}
	}
	// Update status to InProgress and set backup-name and backup-uid label if needed
	dbr, err := r.patchDeleteBackupRequest(ctx, dbr, func(r *velerov1api.DeleteBackupRequest) {
		r.Status.Phase = velerov1api.DeleteBackupRequestPhaseInProgress

		if r.Labels[velerov1api.BackupNameLabel] == "" {
			r.Labels[velerov1api.BackupNameLabel] = label.GetValidName(dbr.Spec.BackupName)
		}

		if r.Labels[velerov1api.BackupUIDLabel] == "" {
			r.Labels[velerov1api.BackupUIDLabel] = string(backup.UID)
		}
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	// Set backup status to Deleting
	backup, err = r.patchBackup(ctx, backup, func(b *velerov1api.Backup) {
		b.Status.Phase = velerov1api.BackupPhaseDeleting
	})
	if err != nil {
		log.WithError(err).Error("Error setting backup phase to deleting")
		err2 := r.patchDeleteBackupRequestWithError(ctx, dbr, errors.Wrap(err, "error setting backup phase to deleting"))
		return ctrl.Result{}, err2
	}

	backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]
	r.metrics.RegisterBackupDeletionAttempt(backupScheduleName)

	pluginManager := r.newPluginManager(log)
	defer pluginManager.CleanupClients()

	backupStore, err := r.backupStoreGetter.Get(location, pluginManager, log)
	if err != nil {
		log.WithError(err).Error("Error getting the backup store")
		err2 := r.patchDeleteBackupRequestWithError(ctx, dbr, errors.Wrap(err, "error getting the backup store"))
		return ctrl.Result{}, err2
	}

	// Re-entry of a request waiting on the retained-snapshot controller: the
	// deletion steps do not re-run, the request only evaluates the record
	// family and runs the tail when nothing is active.
	if dbr.Status.Phase == velerov1api.DeleteBackupRequestPhaseInProgress &&
		dbr.Annotations[velerov1api.RetainedSnapshotsPendingAnnotation] != "" {
		return r.reconcileRetainedSnapshots(ctx, dbr, backup, backupStore, log)
	}

	actions, err := pluginManager.GetDeleteItemActions()
	log.Debugf("%d actions before invoking actions", len(actions))
	if err != nil {
		log.WithError(err).Error("Error getting delete item actions")
		err2 := r.patchDeleteBackupRequestWithError(ctx, dbr, errors.New("error getting delete item actions"))
		return ctrl.Result{}, err2
	}
	// don't defer CleanupClients here, since it was already called above.

	var errs []string

	if len(actions) > 0 {
		// Download the tarball
		backupFile, err := downloadToTempFile(backup.Name, backupStore, log)

		if err != nil {
			log.WithError(err).Errorf("Unable to download tarball for backup %s, skipping associated DeleteItemAction plugins", backup.Name)
			// for backups which failed before tarball object could be uploaded we do offline cleanup
			log.Info("Cleaning up CSI volumesnapshots")
			r.deleteCSIVolumeSnapshotsIfAny(ctx, backup, log)

			// If the tarball simply does not exist (HTTP 404 / not found), the download
			// failure is permanent and not retryable, so we let deletion proceed.
			// For transient errors (throttling, auth failures, network issues), record
			// the error to fail the deletion so it can be retried later.
			if !isTarballNotFoundError(err) {
				errs = append(errs, errors.Wrapf(err, "error downloading backup tarball, CSI snapshot cleanup was skipped").Error())
			}
		} else {
			defer closeAndRemoveFile(backupFile, r.logger)
			deleteCtx := &delete.Context{
				Backup:          backup,
				BackupReader:    backupFile,
				Actions:         actions,
				Log:             r.logger,
				DiscoveryHelper: r.discoveryHelper,
				Filesystem:      filesystem.NewFileSystem(),
			}

			// Optimization: wrap in a gofunc? Would be useful for large backups with lots of objects.
			// but what do we do with the error returned? We can't just swallow it as that may lead to dangling resources.
			err = delete.InvokeDeleteActions(deleteCtx)
			if err != nil {
				log.WithError(err).Error("Error invoking delete item actions")
				err2 := r.patchDeleteBackupRequestWithError(ctx, dbr, errors.Wrap(err, "error invoking delete item actions"))
				return ctrl.Result{}, err2
			}
		}
	}

	// VGS/VGSC resources are not stored in the Backup tarball, so clean them
	// independently of whether DeleteItemActions used the tarball.
	if err := csi.CleanupBackupVolumeGroupSnapshots(ctx, backup, r.Client, log); err != nil {
		log.WithError(err).Warn("Could not clean up VolumeGroupSnapshots")
	}

	if backupStore != nil {
		log.Info("Removing PV snapshots")

		if snapshots, err := backupStore.GetBackupVolumeSnapshots(backup.Name); err != nil {
			errs = append(errs, errors.Wrap(err, "error getting backup's volume snapshots").Error())
		} else {
			volumeSnapshotters := make(map[string]vsv1.VolumeSnapshotter)

			for _, snapshot := range snapshots {
				log.WithField("providerSnapshotID", snapshot.Status.ProviderSnapshotID).Info("Removing snapshot associated with backup")

				volumeSnapshotter, ok := volumeSnapshotters[snapshot.Spec.Location]
				if !ok {
					if volumeSnapshotter, err = r.volumeSnapshottersForVSL(ctx, backup.Namespace, snapshot.Spec.Location, pluginManager); err != nil {
						errs = append(errs, errors.Wrapf(err, "error getting volume snapshotter for location %q", snapshot.Spec.Location).Error())
						continue
					}
					volumeSnapshotters[snapshot.Spec.Location] = volumeSnapshotter
				}

				if snapshot.Status.ProviderSnapshotID == "" {
					log.WithField("volumeSnapshot", snapshot.Spec.PersistentVolumeName).Warn("Skipping snapshot deletion: empty ProviderSnapshotID")
					continue
				}
				if err := volumeSnapshotter.DeleteSnapshot(snapshot.Status.ProviderSnapshotID); err != nil {
					errs = append(errs, errors.Wrapf(err, "error deleting snapshot %s", snapshot.Status.ProviderSnapshotID).Error())
				}
			}
		}
	}
	log.Info("Removing pod volume snapshots")
	if deleteErrs := r.deletePodVolumeSnapshots(ctx, backup); len(deleteErrs) > 0 {
		for _, err := range deleteErrs {
			errs = append(errs, errors.Wrap(err, "error deleting pod volume snapshots").Error())
		}
	}

	if boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
		// The record sources are merged, not just ordered: the local
		// DataUploads are read even when the tarball exists, and where both
		// carry a record for the same DataUpload, the local record wins -- it
		// entered through the API, where the tarball record is backup-storage
		// data. Local presence is authoritative: when a local DataUpload exists
		// for an entry and carries no record, the tarball's record for that
		// DataUpload is dropped, not resurrected. When the tarball is missing,
		// the controller itself writes the family from the local DataUploads;
		// without that fallback every retained snapshot of such a backup would
		// leak silently.
		if gatherErrs := r.gatherRetainedSnapshotRecords(ctx, backup); len(gatherErrs) > 0 {
			for _, err := range gatherErrs {
				errs = append(errs, errors.Wrap(err, "error gathering the retained snapshot records").Error())
			}
		}

		// The snapshot handle of a retained snapshot that a backup taken
		// before Velero recorded them kept is only in the repository snapshot,
		// saved as the cbt-change-id tag, so it is resolved before the
		// repository data is deleted, which destroys the tag.
		if len(errs) == 0 {
			if resolveErrs := r.resolveRetainedSnapshotHandles(ctx, backup, log); len(resolveErrs) > 0 {
				for _, err := range resolveErrs {
					errs = append(errs, errors.Wrap(err, "error reading the retained snapshot handle from the snapshot data").Error())
				}
			}
		}

		log.Info("Removing snapshot data by data mover")
		if len(errs) == 0 {
			if deleteErrs := r.deleteMovedSnapshots(ctx, backup); len(deleteErrs) > 0 {
				for _, err := range deleteErrs {
					errs = append(errs, errors.Wrap(err, "error deleting moved snapshot data").Error())
				}
			}
		} else {
			log.Info("Skipping removal of snapshot data by data mover due to previous errors")
		}
		duList := &velerov2alpha1.DataUploadList{}
		log.Info("Removing local datauploads")
		if err := r.Client.List(ctx, duList, &client.ListOptions{
			Namespace: backup.Namespace,
			LabelSelector: labels.SelectorFromSet(map[string]string{
				velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
			}),
		}); err != nil {
			log.WithError(err).Error("Error listing datauploads")
			errs = append(errs, errors.Wrap(err, "error listing datauploads for backup").Error())
		} else {
			for i := range duList.Items {
				du := duList.Items[i]
				if err := r.Delete(ctx, &du); err != nil {
					errs = append(errs, errors.Wrapf(err, "error deleting dataupload %q", du.Name).Error())
				}
			}
		}
	}

	// Deleting a retained snapshot cannot be undone, which is why it runs
	// last, before the tarball is deleted: any earlier failure leaves the
	// snapshot and the record in place, and the backup deletion can be
	// retried. The request's snapshot step does not wait: a DeleteBackupRequest
	// in InProgress or Processed is not reconciled again, and the
	// backup-deletion controller runs with one worker, so any wait inside it
	// would block the deletion of every unrelated backup behind it. The step
	// writes the pending annotation and activates the record family in one
	// write -- annotate first, then activate, never the reverse -- and
	// returns, leaving the request InProgress for the retained-snapshot
	// controller, which runs its own workers and is keyed by the record
	// ConfigMaps.
	if len(errs) == 0 && boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
		family, familyErr := retainedsnapshot.LoadFamily(ctx, r.familyReader(), backup)
		if familyErr != nil {
			errs = append(errs, errors.Wrap(familyErr, "error reading the retained snapshot records").Error())
		} else if family.PendingEntries() > 0 {
			var annotateErr error
			dbr, annotateErr = r.patchDeleteBackupRequest(ctx, dbr, func(req *velerov1api.DeleteBackupRequest) {
				if req.Annotations == nil {
					req.Annotations = map[string]string{}
				}
				req.Annotations[velerov1api.RetainedSnapshotsPendingAnnotation] = "true"
			})
			if annotateErr != nil {
				errs = append(errs, errors.Wrap(annotateErr, "error marking the request as waiting on retained snapshots").Error())
			} else if activateErr := retainedsnapshot.Activate(ctx, r.Client, backup); activateErr != nil {
				errs = append(errs, errors.Wrap(activateErr, "error activating the retained snapshot records").Error())
			} else {
				log.Info("Waiting for the retained-snapshot controller to delete the retained snapshots")
				return ctrl.Result{}, nil
			}
		}
	}

	return r.runDeletionTail(ctx, dbr, backup, backupStore, backupScheduleName, errs, log)
}

// runDeletionTail runs the steps after the retained snapshots: the backup
// tarball in the backup storage is deleted only when all prior steps
// succeeded, then the restores, the Backup object and the request itself. The
// shard family of the retained snapshot records is removed by the tail itself
// -- the Backup deletion is not its GC trigger -- after the deletion finishes,
// so a shard with no pending entries keeps its completed set, the evidence
// that suppresses replay, until then.
func (r *backupDeletionReconciler) runDeletionTail(
	ctx context.Context,
	dbr *velerov1api.DeleteBackupRequest,
	backup *velerov1api.Backup,
	backupStore persistence.BackupStore,
	backupScheduleName string,
	errs []string,
	log logrus.FieldLogger,
) (ctrl.Result, error) {
	if backupStore != nil && len(errs) == 0 {
		log.Info("Removing backup from backup storage")
		if err := backupStore.DeleteBackup(backup.Name); err != nil {
			errs = append(errs, errors.Wrap(err, "error removing backup from backup storage").Error())
		}
	} else if len(errs) > 0 {
		log.Info("Skipping removal of backup from backup storage due to previous errors")
	}

	log.Info("Removing restores")
	restoreList := &velerov1api.RestoreList{}
	selector := labels.Everything()
	if err := r.List(ctx, restoreList, &client.ListOptions{
		Namespace:     backup.Namespace,
		LabelSelector: selector,
	}); err != nil {
		log.WithError(errors.WithStack(err)).Error("Error listing restore API objects")
	} else {
		// Restore files in object storage will be handled by restore finalizer, so we simply need to initiate a delete request on restores here.
		for i, restore := range restoreList.Items {
			if restore.Spec.BackupName != backup.Name {
				continue
			}
			restoreLog := log.WithField("restore", kube.NamespaceAndName(&restoreList.Items[i]))

			restoreLog.Info("Deleting restore referencing backup")
			if err := r.Delete(ctx, &restoreList.Items[i]); err != nil {
				errs = append(errs, errors.Wrapf(err, "error deleting restore %s", kube.NamespaceAndName(&restoreList.Items[i])).Error())
			}
		}

		// Wait for the deletion of restores within certain amount of time.
		// Notice that there could be potential errors during the finalization process, which may result in the failure to delete the restore.
		// Therefore, it is advisable to set a timeout period for waiting.
		err := wait.PollUntilContextTimeout(ctx, time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
			restoreList := &velerov1api.RestoreList{}
			if err := r.List(ctx, restoreList, &client.ListOptions{Namespace: backup.Namespace, LabelSelector: selector}); err != nil {
				return false, err
			}
			cnt := 0
			for _, restore := range restoreList.Items {
				if restore.Spec.BackupName != backup.Name {
					continue
				}
				cnt++
			}

			if cnt > 0 {
				return false, nil
			} else {
				return true, nil
			}
		})
		if err != nil {
			log.WithError(err).Error("Error polling for deletion of restores")
			errs = append(errs, errors.Wrapf(err, "error deleting restore %s", err).Error())
		}
	}

	if len(errs) == 0 {
		// Only try to delete the backup object from kube if everything preceding went smoothly
		if err := r.Delete(ctx, backup); err != nil {
			errs = append(errs, errors.Wrapf(err, "error deleting backup %s", kube.NamespaceAndName(backup)).Error())
		}
	}

	if len(errs) == 0 {
		r.metrics.RegisterBackupDeletionSuccess(backupScheduleName)
	} else {
		r.metrics.RegisterBackupDeletionFailed(backupScheduleName)
	}

	// Update status to processed and record errors
	if _, err := r.patchDeleteBackupRequest(ctx, dbr, func(r *velerov1api.DeleteBackupRequest) {
		r.Status.Phase = velerov1api.DeleteBackupRequestPhaseProcessed
		r.Status.Errors = errs
	}); err != nil {
		return ctrl.Result{}, err
	}
	// Everything deleted correctly, so we can delete all DeleteBackupRequests for this backup
	if len(errs) == 0 {
		labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s,%s=%s", velerov1api.BackupNameLabel, label.GetValidName(backup.Name), velerov1api.BackupUIDLabel, backup.UID))
		if err != nil {
			// Should not be here
			r.logger.WithError(err).WithField("backup", kube.NamespaceAndName(backup)).Error("error creating label selector for the backup for deleting DeleteBackupRequests")
			return ctrl.Result{}, nil
		}
		alldbr := &velerov1api.DeleteBackupRequest{}
		err = r.DeleteAllOf(ctx, alldbr, client.MatchingLabelsSelector{
			Selector: labelSelector,
		}, client.InNamespace(dbr.Namespace))
		if err != nil {
			// If this errors, all we can do is log it.
			r.logger.WithError(err).WithField("backup", kube.NamespaceAndName(backup)).Error("error deleting all associated DeleteBackupRequests after successfully deleting the backup")
		}

		// The tail removes the record family itself; a GC that finds a family
		// whose Backup is gone by other means is the retained-snapshot
		// controller's business.
		if boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
			if err := retainedsnapshot.Delete(ctx, r.Client, backup); err != nil {
				log.WithError(err).Warn("Error removing the retained snapshot record family")
			}
		}
	}
	log.Infof("Reconciliation done")

	return ctrl.Result{}, nil
}

// reconcileRetainedSnapshots is the re-entry path of a request waiting on the
// retained-snapshot controller. It is level-triggered, not edge-triggered: on
// re-entry it first repairs activation -- the annotation write and the shard
// activations cannot be one atomic write, and a crash in between must not
// strand shards -- so every nonempty shard in the family that is not yet
// activated is activated before anything else; only then does it re-read the
// family, and when there is nothing active it clears its own annotation and
// runs the tail in the same reconcile, so a retry that starts after the family
// is gone cannot wedge waiting for a transition that already fired.
func (r *backupDeletionReconciler) reconcileRetainedSnapshots(
	ctx context.Context,
	dbr *velerov1api.DeleteBackupRequest,
	backup *velerov1api.Backup,
	backupStore persistence.BackupStore,
	log logrus.FieldLogger,
) (ctrl.Result, error) {
	log.Info("Evaluating the retained snapshot records of the backup")

	// Repair the activation a crash may have interrupted.
	if err := retainedsnapshot.Activate(ctx, r.Client, backup); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error repairing the retained snapshot record activation")
	}

	family, err := retainedsnapshot.LoadFamily(ctx, r.familyReader(), backup)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error reading the retained snapshot records")
	}
	// The wait is on pending entries regardless of the activation state, not
	// only on active shards: an activation the repair above has not covered
	// yet must hold the tail back, not let it through while the shard is
	// still inactive.
	if family.PendingEntries() > 0 {
		log.Info("The retained snapshots are still being deleted, going back to waiting")
		return ctrl.Result{}, nil
	}

	// Nothing is active: no family, because a previous attempt already emptied
	// and deleted it; empty shards; or every entry escalated or skipped. The
	// request clears its own annotation -- the waker never clears it -- and
	// runs the tail.
	if _, err := r.patchDeleteBackupRequest(ctx, dbr, func(req *velerov1api.DeleteBackupRequest) {
		// The file imports the internal/delete package, which shadows the map
		// delete builtin, so the annotation is dropped by rebuild.
		if req.Annotations != nil {
			annotations := map[string]string{}
			for key, value := range req.Annotations {
				if key != velerov1api.RetainedSnapshotsPendingAnnotation {
					annotations[key] = value
				}
			}
			req.Annotations = annotations
		}
	}); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error clearing the retained snapshot pending annotation")
	}

	backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]
	return r.runDeletionTail(ctx, dbr, backup, backupStore, backupScheduleName, nil, log)
}

// gatherRetainedSnapshotRecords merges the record sources of a backup's
// retained snapshots into the shard family: the entries the DataUpload delete
// action gathered from the backup tarball, and the local DataUploads. A local
// record wins over the tarball's, a local DataUpload without a record drops
// the tarball's entry for it, and the tarball supplies entries only for
// DataUploads that no longer exist locally. Regathering respects what the
// family already did: an entry whose snapshot was confirmed deleted stays in
// the completed set and is not recreated, and a persisted attempt count is
// merged, not reset.
func (r *backupDeletionReconciler) gatherRetainedSnapshotRecords(ctx context.Context, backup *velerov1api.Backup) []error {
	family, err := retainedsnapshot.LoadFamily(ctx, r.familyReader(), backup)
	if err != nil {
		return []error{errors.Wrap(err, "error reading the retained snapshot records")}
	}

	duList := &velerov2alpha1.DataUploadList{}
	if err := r.Client.List(ctx, duList, &client.ListOptions{
		Namespace: backup.Namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
		}),
	}); err != nil {
		return []error{errors.Wrap(err, "error listing the local datauploads")}
	}

	local := map[string]*retainedsnapshot.Entry{}
	dropped := map[string]struct{}{}
	for i := range duList.Items {
		du := &duList.Items[i]
		if entry := retainedsnapshot.FromDataUploadStatus(du); entry != nil {
			local[du.Name] = entry
		} else if du.Status.Phase == velerov2alpha1.DataUploadPhaseCompleted && du.Status.SnapshotID != "" {
			// A completed DataUpload without a record is a pre-rollback
			// backup, whose record field never existed: its legacy entry --
			// the repository snapshot the handle is resolved from -- is the
			// recovery path and must survive this gather.
		} else {
			dropped[du.Name] = struct{}{}
		}
	}

	var errs []error
	for name := range dropped {
		// Local presence is authoritative for a DataUpload that did not
		// complete: the patch-back cleared the record after the snapshot was
		// released, so the tarball's record for this DataUpload is dropped,
		// not resurrected.
		if _, ok := family.Entry(name); ok {
			if err := retainedsnapshot.RemoveEntry(ctx, r.Client, backup, name); err != nil {
				errs = append(errs, errors.Wrapf(err, "error dropping the tarball record of DataUpload %s", name))
			}
		}
	}

	if len(local) == 0 && len(family.Shards) == 0 {
		return errs
	}
	if err := retainedsnapshot.WriteEntries(ctx, r.Client, backup, local); err != nil {
		errs = append(errs, errors.Wrap(err, "error writing the retained snapshot records"))
	}
	return errs
}

// getRepoSnapshotTagsFunc reads the tags of a repository snapshot. It is a
// variable so that tests can replace it.
var getRepoSnapshotTagsFunc = getRepoSnapshotTags

func getRepoSnapshotTags(ctx context.Context, repoEnsurer *repository.Ensurer, repoMgr repomanager.Manager, backup *velerov1api.Backup, snapshot repotypes.SnapshotIdentifier) (map[string]string, error) {
	repo, err := repoEnsurer.EnsureRepo(ctx, backup.Namespace, snapshot.VolumeNamespace, snapshot.BackupStorageLocation, snapshot.RepositoryType)
	if err != nil {
		return nil, errors.Wrapf(err, "error to ensure repo %s-%s-%s", snapshot.BackupStorageLocation, snapshot.VolumeNamespace, snapshot.RepositoryType)
	}
	return repoMgr.GetSnapshotTags(ctx, repo, snapshot.SnapshotID)
}

// resolveRetainedSnapshotHandles fills in the snapshot handle of the gathered
// records of backups taken before Velero recorded retained snapshots. The
// block data mover saved the CSI snapshot handle as the cbt-change-id tag of
// the repository snapshot, so it is resolved before the repository data is
// deleted, because deleting that data destroys the tag. If the tag cannot be
// read, the repository data is kept and the backup deletion fails, so a retry
// can read it; if the repository snapshot is already gone or has no tag, the
// record is dropped.
func (r *backupDeletionReconciler) resolveRetainedSnapshotHandles(ctx context.Context, backup *velerov1api.Backup, log logrus.FieldLogger) []error {
	if r.repoMgr == nil {
		return nil
	}
	family, err := retainedsnapshot.LoadFamily(ctx, r.familyReader(), backup)
	if err != nil {
		return []error{errors.Wrap(err, "error reading the retained snapshot records")}
	}

	var errs []error
	for _, shard := range family.Shards {
		for _, name := range pendingShardKeys(shard) {
			entry, ok := family.Entry(name)
			if !ok || entry == nil {
				continue
			}
			if entry.CSISnapshotHandle != "" || entry.Snapshot == nil || entry.Snapshot.SnapshotID == "" {
				continue
			}

			tags, tagsErr := getRepoSnapshotTagsFunc(ctx, r.repoEnsurer, r.repoMgr, backup, *entry.Snapshot)
			if tagsErr != nil {
				if errors.Is(tagsErr, udmrepo.ErrSnapshotNotFound) {
					// The repository snapshot is gone, e.g. deleted by an
					// earlier attempt, so there is nothing to delete.
					log.Warnf("The repository snapshot of DataUpload %s is gone, dropping its retained snapshot record", name)
					if err := retainedsnapshot.RemoveEntry(ctx, r.Client, backup, name); err != nil {
						errs = append(errs, errors.Wrapf(err, "error dropping the record of DataUpload %s", name))
					}
					continue
				}
				errs = append(errs, errors.Wrapf(tagsErr, "error reading the snapshot handle of DataUpload %s from the repository snapshot %s", name, entry.Snapshot.SnapshotID))
				continue
			}

			handle := tags[uploader.CBTChangeIDTag]
			if handle == "" {
				// The repository snapshot has no tag, so there is nothing to
				// delete.
				log.Warnf("The repository snapshot %s of DataUpload %s carries no snapshot handle, dropping its retained snapshot record", entry.Snapshot.SnapshotID, name)
				if err := retainedsnapshot.RemoveEntry(ctx, r.Client, backup, name); err != nil {
					errs = append(errs, errors.Wrapf(err, "error dropping the record of DataUpload %s", name))
				}
				continue
			}

			log.Infof("Read the retained snapshot handle %s of DataUpload %s from the repository snapshot %s", handle, name, entry.Snapshot.SnapshotID)
			entry.CSISnapshotHandle = handle
			if err := retainedsnapshot.UpdateEntry(ctx, r.Client, backup, name, entry); err != nil {
				errs = append(errs, errors.Wrapf(err, "error recording the resolved handle of DataUpload %s", name))
			}
		}
	}
	return errs
}

// pendingShardKeys lists the pending entry keys of a shard.
func pendingShardKeys(shard *corev1api.ConfigMap) []string {
	keys := []string{}
	for key := range shard.Data {
		if key == retainedsnapshot.ActiveKey || key == retainedsnapshot.CompletedKey {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

func (r *backupDeletionReconciler) volumeSnapshottersForVSL(
	ctx context.Context,
	namespace, vslName string,
	pluginManager clientmgmt.Manager,
) (vsv1.VolumeSnapshotter, error) {
	vsl := &velerov1api.VolumeSnapshotLocation{}
	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      vslName,
	}, vsl); err != nil {
		return nil, errors.Wrapf(err, "error getting volume snapshot location %s", vslName)
	}

	// add credential to config
	err := volume.UpdateVolumeSnapshotLocationWithCredentialConfig(vsl, r.credentialStore)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	volumeSnapshotter, err := pluginManager.GetVolumeSnapshotter(vsl.Spec.Provider)
	if err != nil {
		return nil, errors.Wrapf(err, "error getting volume snapshotter for provider %s", vsl.Spec.Provider)
	}

	if err = volumeSnapshotter.Init(vsl.Spec.Config); err != nil {
		return nil, errors.Wrapf(err, "error initializing volume snapshotter for volume snapshot location %s", vslName)
	}

	return volumeSnapshotter, nil
}

func (r *backupDeletionReconciler) deleteExistingDeletionRequests(ctx context.Context, req *velerov1api.DeleteBackupRequest, log logrus.FieldLogger) []error {
	log.Info("Removing existing deletion requests for backup")
	dbrList := &velerov1api.DeleteBackupRequestList{}
	selector := label.NewSelectorForBackup(req.Spec.BackupName)
	if err := r.List(ctx, dbrList, &client.ListOptions{
		Namespace:     req.Namespace,
		LabelSelector: selector,
	}); err != nil {
		return []error{errors.Wrap(err, "error listing existing DeleteBackupRequests for backup")}
	}
	var errs []error
	for i, dbr := range dbrList.Items {
		if dbr.Name == req.Name {
			continue
		}
		if err := r.Delete(ctx, &dbrList.Items[i]); err != nil {
			errs = append(errs, errors.WithStack(err))
		} else {
			log.Infof("deletion request '%s' removed.", dbr.Name)
		}
	}
	return errs
}

// deleteCSIVolumeSnapshotsIfAny clean up the CSI snapshots created by the backup, this should be called when the backup is failed
// when it's running, e.g. due to velero pod restart, and the backup.tar is failed to be downloaded from storage.
func (r *backupDeletionReconciler) deleteCSIVolumeSnapshotsIfAny(ctx context.Context, backup *velerov1api.Backup, log logrus.FieldLogger) {
	vsList := snapshotv1api.VolumeSnapshotList{}
	if err := r.Client.List(ctx, &vsList, &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
		}),
	}); err != nil {
		log.WithError(err).Warnf("Could not list volume snapshots, abort")
		return
	}
	for _, item := range vsList.Items {
		vs := item
		csi.CleanupVolumeSnapshot(ctx, &vs, r.Client, log)
	}
}

func (r *backupDeletionReconciler) deletePodVolumeSnapshots(ctx context.Context, backup *velerov1api.Backup) []error {
	if r.repoMgr == nil {
		return nil
	}

	directSnapshots, err := getSnapshotsInBackup(ctx, backup, r.Client)
	if err != nil {
		return []error{err}
	}

	return batchDeleteSnapshots(ctx, r.repoEnsurer, r.repoMgr, directSnapshots, backup, r.logger)
}

var batchDeleteSnapshotFunc = batchDeleteSnapshots

func (r *backupDeletionReconciler) deleteMovedSnapshots(ctx context.Context, backup *velerov1api.Backup) []error {
	if r.repoMgr == nil {
		return nil
	}
	list := &corev1api.ConfigMapList{}
	if err := r.Client.List(ctx, list, &client.ListOptions{
		Namespace: backup.Namespace,
		LabelSelector: labels.SelectorFromSet(
			map[string]string{
				velerov1api.BackupNameLabel:             label.GetValidName(backup.Name),
				velerov1api.DataUploadSnapshotInfoLabel: "true",
			}),
	}); err != nil {
		return []error{errors.Wrapf(err, "failed to retrieve config for snapshot info")}
	}
	var errs []error
	directSnapshots := map[string][]repotypes.SnapshotIdentifier{}
	for i := range list.Items {
		cm := list.Items[i]
		if len(cm.Data) == 0 {
			errs = append(errs, errors.New("no snapshot info in config"))
			continue
		}

		b, err := json.Marshal(cm.Data)
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "fail to marshal the snapshot info into JSON"))
			continue
		}

		snapshot := repotypes.SnapshotIdentifier{}
		if err := json.Unmarshal(b, &snapshot); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to unmarshal snapshot info"))
			continue
		}

		if snapshot.SnapshotID == "" || snapshot.VolumeNamespace == "" || snapshot.RepositoryType == "" {
			errs = append(errs, errors.Errorf("invalid snapshot, ID %s, namespace %s, repository %s", snapshot.SnapshotID, snapshot.VolumeNamespace, snapshot.RepositoryType))
			continue
		}

		if directSnapshots[snapshot.VolumeNamespace] == nil {
			directSnapshots[snapshot.VolumeNamespace] = []repotypes.SnapshotIdentifier{}
		}

		directSnapshots[snapshot.VolumeNamespace] = append(directSnapshots[snapshot.VolumeNamespace], snapshot)

		r.logger.Infof("Deleting snapshot %s, namespace: %s, repo type: %s", snapshot.SnapshotID, snapshot.VolumeNamespace, snapshot.RepositoryType)
	}

	for i := range list.Items {
		cm := list.Items[i]
		if err := r.Client.Delete(ctx, &cm); err != nil {
			r.logger.Warnf("Failed to delete snapshot info configmap %s/%s: %v", cm.Namespace, cm.Name, err)
		}
	}

	if len(directSnapshots) > 0 {
		deleteErrs := batchDeleteSnapshotFunc(ctx, r.repoEnsurer, r.repoMgr, directSnapshots, backup, r.logger)
		errs = append(errs, deleteErrs...)
	}

	return errs
}

func (r *backupDeletionReconciler) patchDeleteBackupRequest(ctx context.Context, req *velerov1api.DeleteBackupRequest, mutate func(*velerov1api.DeleteBackupRequest)) (*velerov1api.DeleteBackupRequest, error) {
	original := req.DeepCopy()
	mutate(req)
	if err := r.Patch(ctx, req, client.MergeFrom(original)); err != nil {
		return nil, errors.Wrap(err, "error patching the deletebackuprquest")
	}
	return req, nil
}

func (r *backupDeletionReconciler) patchDeleteBackupRequestWithError(ctx context.Context, req *velerov1api.DeleteBackupRequest, err error) error {
	_, err = r.patchDeleteBackupRequest(ctx, req, func(r *velerov1api.DeleteBackupRequest) {
		r.Status.Phase = velerov1api.DeleteBackupRequestPhaseProcessed
		r.Status.Errors = []string{errors.WithMessage(err, "backup deletion failed").Error()}
	})
	return err
}

func (r *backupDeletionReconciler) patchBackup(ctx context.Context, backup *velerov1api.Backup, mutate func(*velerov1api.Backup)) (*velerov1api.Backup, error) {
	//TODO: The patchHelper can't be used here because the `backup/xxx/status` does not exist, until the backup resource is refactored

	// Record original json
	oldData, err := json.Marshal(backup)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling original Backup")
	}

	newBackup := backup.DeepCopy()
	mutate(newBackup)
	newData, err := json.Marshal(newBackup)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling updated Backup")
	}
	patchBytes, err := jsonpatch.CreateMergePatch(oldData, newData)
	if err != nil {
		return nil, errors.Wrap(err, "error creating json merge patch for Backup")
	}

	if err := r.Client.Patch(ctx, backup, client.RawPatch(types.MergePatchType, patchBytes)); err != nil {
		return nil, errors.Wrap(err, "error patching Backup")
	}
	return backup, nil
}

// getSnapshotsInBackup returns a list of all pod volume snapshot ids associated with
// a given Velero backup.
func getSnapshotsInBackup(ctx context.Context, backup *velerov1api.Backup, kbClient client.Client) (map[string][]repotypes.SnapshotIdentifier, error) {
	podVolumeBackups := &velerov1api.PodVolumeBackupList{}
	options := &client.ListOptions{
		LabelSelector: labels.Set(map[string]string{
			velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
		}).AsSelector(),
	}

	err := kbClient.List(ctx, podVolumeBackups, options)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return podvolume.GetSnapshotIdentifier(podVolumeBackups), nil
}

func batchDeleteSnapshots(ctx context.Context, repoEnsurer *repository.Ensurer, repoMgr repomanager.Manager,
	directSnapshots map[string][]repotypes.SnapshotIdentifier, backup *velerov1api.Backup, logger logrus.FieldLogger) []error {
	var errs []error
	for volumeNamespace, snapshots := range directSnapshots {
		batchForget := []string{}
		for _, snapshot := range snapshots {
			batchForget = append(batchForget, snapshot.SnapshotID)
		}

		// For volumes in one backup, the BSL and repositoryType should always be the same
		repoType := snapshots[0].RepositoryType
		repo, err := repoEnsurer.EnsureRepo(ctx, backup.Namespace, volumeNamespace, backup.Spec.StorageLocation, repoType)
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "error to ensure repo %s-%s-%s, skip deleting PVB snapshots %v", backup.Spec.StorageLocation, volumeNamespace, repoType, batchForget))
			continue
		}

		if forgetErrs := repoMgr.BatchForget(ctx, repo, batchForget); len(forgetErrs) > 0 {
			errs = append(errs, forgetErrs...)
			continue
		}

		logger.Infof("Batch deleted snapshots %v", batchForget)
	}

	return errs
}

// isTarballNotFoundError reports whether err indicates that the backup tarball
// does not exist in object storage (e.g. HTTP 404 / not-found). Such errors are
// permanent and not retryable, so callers should let deletion proceed (skipping
// DeleteItemAction plugins) rather than failing the entire deletion.
//
// Transient errors (throttling, auth failures, network timeouts) return false so
// the deletion is failed and can be retried once the storage is reachable again.
func isTarballNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Lower-case once for all comparisons.
	msg := strings.ToLower(err.Error())
	// Common "not found" indicators across cloud providers:
	//   - "not found" / "does not exist": generic, in-memory object store
	//   - "nosuchkey":                    AWS S3
	//   - "blobnotfound":                 Azure Blob Storage
	//   - "objectnotexist":               GCS
	//   - "doesn't exist":                GCS
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "nosuchkey") ||
		strings.Contains(msg, "blobnotfound") ||
		strings.Contains(msg, "objectnotexist") ||
		strings.Contains(msg, "doesn't exist")
}
