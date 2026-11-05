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
	veleroutil "github.com/velero-io/velero/pkg/util/velero"
)

const (
	deleteBackupRequestMaxAge = 24 * time.Hour
)

type backupDeletionReconciler struct {
	client.Client
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
	// apiReader reads from the API server instead of the manager's cache, which
	// only covers the Velero namespace.
	apiReader client.Reader
}

// NewBackupDeletionReconciler creates a new backup deletion reconciler.
func NewBackupDeletionReconciler(
	logger logrus.FieldLogger,
	client client.Client,
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

func (r *backupDeletionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.apiReader = mgr.GetAPIReader()
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
	if dbr.Status.Phase == velerov1api.DeleteBackupRequestPhaseProcessed ||
		dbr.Status.Phase == velerov1api.DeleteBackupRequestPhaseInProgress {
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
		// The snapshot handle of a retained snapshot that a backup taken before
		// Velero recorded them kept is only in the repository snapshot, so read it
		// before the repository snapshot is deleted.
		if resolveErrs := r.resolveUnrecordedRetainedSnapshots(ctx, backup, log); len(resolveErrs) > 0 {
			log.Info("Skipping removal of snapshot data by data mover due to previous errors")
			for _, err := range resolveErrs {
				errs = append(errs, errors.Wrap(err, "error reading retained volume snapshot from snapshot data").Error())
			}
		} else {
			log.Info("Removing snapshot data by data mover")
			if deleteErrs := r.deleteMovedSnapshots(ctx, backup); len(deleteErrs) > 0 {
				for _, err := range deleteErrs {
					errs = append(errs, errors.Wrap(err, "error deleting moved snapshot data").Error())
				}
			}
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

		// Deleting a retained snapshot can't be undone and it is the base of the next
		// incremental backup, so it is deleted only after the other data of the backup is
		// deleted. Otherwise the snapshot is kept, and a retry of the deletion deletes it.
		if len(errs) > 0 {
			log.Info("Skipping removal of retained volume snapshots due to previous errors")
		} else {
			log.Info("Removing retained volume snapshots")
			for _, err := range r.deleteRetainedSnapshots(ctx, backup, log) {
				errs = append(errs, errors.Wrap(err, "error deleting retained volume snapshot").Error())
			}
		}
	}

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
	}
	log.Infof("Reconciliation done")

	return ctrl.Result{}, nil
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

// Lifecycle of the volume snapshot of a CSI DataUpload, by how the DataUpload ends
// and the deletionPolicy of its backup VolumeSnapshotContent (the VSC the exposer
// creates for the DataUpload). That VSC inherits the deletionPolicy of the source
// VSC, which comes from the VolumeSnapshotClass:
//
//	DataUpload ends        | Delete                          | Retain
//	-----------------------+---------------------------------+------------------------------------------
//	Completed              | the CSI driver deletes it when  | kept in the storage and recorded in
//	                       | the node-agent cleans up the    | status.retainedSnapshot; deleted here
//	                       | exposed snapshot                | when the backup is deleted
//	Failed, Canceled, or   | same as Completed               | the node-agent patches the deletionPolicy
//	timed out in prepare   |                                 | of the backup VSC (not the class) to
//	                       |                                 | Delete before the cleanup, so the CSI
//	                       |                                 | driver deletes it then; nothing recorded
//
// When the backup is deleted, a retained snapshot is deleted after the other data
// of the backup:
//   - An earlier deletion step fails: the snapshot and its configmap are kept, and a
//     retry of the backup deletion deletes them.
//   - The CSI driver reports a failure (SnapshotDeleteError event): the backup
//     deletion fails and the configmap is kept for a retry.
//   - The CSI driver is not done within 30 seconds: the backup deletion completes
//     with a warning, and the temp VSC stays until the driver deletes the snapshot.
//
// getRepoSnapshotTagsFunc reads the tags of a repository snapshot. It is a variable
// so that tests can replace it.
var getRepoSnapshotTagsFunc = getRepoSnapshotTags

func getRepoSnapshotTags(ctx context.Context, repoEnsurer *repository.Ensurer, repoMgr repomanager.Manager, backup *velerov1api.Backup, snapshot repotypes.SnapshotIdentifier) (map[string]string, error) {
	repo, err := repoEnsurer.EnsureRepo(ctx, backup.Namespace, snapshot.VolumeNamespace, snapshot.BackupStorageLocation, snapshot.RepositoryType)
	if err != nil {
		return nil, errors.Wrapf(err, "error to ensure repo %s-%s-%s", snapshot.BackupStorageLocation, snapshot.VolumeNamespace, snapshot.RepositoryType)
	}
	return repoMgr.GetSnapshotTags(ctx, repo, snapshot.SnapshotID)
}

// resolveUnrecordedRetainedSnapshots fills in the snapshot handle of the retained
// snapshot configmaps that the DataUpload DeleteItemAction created for backups taken
// before Velero recorded retained snapshots. The block data mover saved the handle
// as the CBT change ID tag of the repository snapshot. The handle is written to the
// configmap, so that it survives the deletion of the repository snapshot.
func (r *backupDeletionReconciler) resolveUnrecordedRetainedSnapshots(ctx context.Context, backup *velerov1api.Backup, log logrus.FieldLogger) []error {
	if r.repoMgr == nil {
		return nil
	}
	list := &corev1api.ConfigMapList{}
	if err := r.Client.List(ctx, list, &client.ListOptions{
		Namespace: backup.Namespace,
		LabelSelector: labels.SelectorFromSet(
			map[string]string{
				velerov1api.BackupNameLabel:                 label.GetValidName(backup.Name),
				velerov1api.DataUploadRetainedSnapshotLabel: "true",
			}),
	}); err != nil {
		return []error{errors.Wrapf(err, "failed to retrieve config for retained snapshots")}
	}

	var errs []error
	for i := range list.Items {
		cm := list.Items[i]
		if cm.Data["snapshotHandle"] != "" {
			continue
		}

		b, err := json.Marshal(cm.Data)
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "fail to marshal configmap %s into JSON", cm.Name))
			continue
		}
		snapshot := repotypes.SnapshotIdentifier{}
		if err := json.Unmarshal(b, &snapshot); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to unmarshal the repository snapshot in configmap %s", cm.Name))
			continue
		}

		handle := ""
		if snapshot.SnapshotID != "" {
			tags, err := getRepoSnapshotTagsFunc(ctx, r.repoEnsurer, r.repoMgr, backup, snapshot)
			if err != nil && !errors.Is(err, udmrepo.ErrSnapshotNotFound) {
				errs = append(errs, errors.Wrapf(err, "failed to read the snapshot handle from repository snapshot %s in configmap %s", snapshot.SnapshotID, cm.Name))
				continue
			}
			handle = tags[uploader.CBTChangeIDTag]
		}
		if handle == "" {
			// The repository snapshot is gone, e.g. deleted by an earlier attempt,
			// or doesn't have the handle, so there is nothing to delete.
			log.Warnf("No snapshot handle in repository snapshot %s for configmap %s, a retained snapshot can't be found", snapshot.SnapshotID, cm.Name)
			if err := r.Client.Delete(ctx, &cm); err != nil && !apierrors.IsNotFound(err) {
				log.Warnf("Failed to delete retained snapshot configmap %s/%s: %v", cm.Namespace, cm.Name, err)
			}
			continue
		}

		log.Infof("Read retained snapshot %s from repository snapshot %s for configmap %s", handle, snapshot.SnapshotID, cm.Name)
		cm.Data["snapshotHandle"] = handle
		if err := r.Client.Update(ctx, &cm); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to record retained snapshot %s in configmap %s", handle, cm.Name))
		}
	}

	return errs
}

// deleteRetainedSnapshots has the CSI driver delete the volume snapshots that the
// DataUploads of the backup retained in the storage. The configmaps that pass the
// snapshots from the DataUpload DeleteItemAction are the only record of the
// snapshots once the DataUploads are deleted, so a configmap is removed only after
// its snapshot is deleted.
func (r *backupDeletionReconciler) deleteRetainedSnapshots(ctx context.Context, backup *velerov1api.Backup, log logrus.FieldLogger) []error {
	list := &corev1api.ConfigMapList{}
	if err := r.Client.List(ctx, list, &client.ListOptions{
		Namespace: backup.Namespace,
		LabelSelector: labels.SelectorFromSet(
			map[string]string{
				velerov1api.BackupNameLabel:                 label.GetValidName(backup.Name),
				velerov1api.DataUploadRetainedSnapshotLabel: "true",
			}),
	}); err != nil {
		return []error{errors.Wrapf(err, "failed to retrieve config for retained snapshots")}
	}

	var errs []error
	for i := range list.Items {
		cm := list.Items[i]
		if err := r.deleteRetainedSnapshot(ctx, backup, &cm, log); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := r.Client.Delete(ctx, &cm); err != nil && !apierrors.IsNotFound(err) {
			log.Warnf("Failed to delete retained snapshot configmap %s/%s: %v", cm.Namespace, cm.Name, err)
		}
	}

	return errs
}

func (r *backupDeletionReconciler) deleteRetainedSnapshot(ctx context.Context, backup *velerov1api.Backup, cm *corev1api.ConfigMap, log logrus.FieldLogger) error {
	b, err := json.Marshal(cm.Data)
	if err != nil {
		return errors.Wrapf(err, "fail to marshal the retained snapshot in configmap %s into JSON", cm.Name)
	}
	retained := &velerov2alpha1.RetainedSnapshot{}
	if err := json.Unmarshal(b, retained); err != nil {
		return errors.Wrapf(err, "failed to unmarshal the retained snapshot in configmap %s", cm.Name)
	}

	log.Infof("Deleting retained snapshot %s from configmap %s", retained.SnapshotHandle, cm.Name)
	if err := csi.DeleteRetainedSnapshot(ctx, r.snapshotDeletionClient(), retained, label.GetValidName(backup.Name), log); err != nil {
		return errors.Wrapf(err, "failed to delete retained snapshot %s from configmap %s", retained.SnapshotHandle, cm.Name)
	}
	return nil
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

// snapshotDeletionClient returns the client to delete retained snapshots with. Its
// reads go to the API server: the CSI snapshotter records the events of a
// VolumeSnapshotContent in the default namespace, which the manager's cache doesn't
// cover, so listing them from the cache fails and a failed deletion goes unnoticed.
func (r *backupDeletionReconciler) snapshotDeletionClient() client.Client {
	if r.apiReader == nil {
		return r.Client
	}
	return &apiReadClient{Client: r.Client, reader: r.apiReader}
}

// apiReadClient reads through reader and writes through Client.
type apiReadClient struct {
	client.Client
	reader client.Reader
}

func (c *apiReadClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.reader.Get(ctx, key, obj, opts...)
}

func (c *apiReadClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.reader.List(ctx, list, opts...)
}
