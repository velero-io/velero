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
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/constant"
	"github.com/velero-io/velero/pkg/util/csi"
	retainedsnapshot "github.com/velero-io/velero/pkg/util/retainedsnapshot"
)

// retainedSnapshotReconciler deletes the retained snapshots of a backup whose
// deletion is in progress. It is keyed by the record ConfigMap family, runs
// its own workers and requeues on its own objects, so a slow snapshot delays
// only its own entry; the DeleteBackupRequest itself never waits.
type retainedSnapshotReconciler struct {
	client.Client
	logger   logrus.FieldLogger
	clock    clock.Clock
	recorder record.EventRecorder
}

// NewRetainedSnapshotReconciler creates a new retained-snapshot reconciler.
func NewRetainedSnapshotReconciler(logger logrus.FieldLogger, client client.Client, clock clock.Clock) *retainedSnapshotReconciler {
	return &retainedSnapshotReconciler{
		Client: client,
		logger: logger,
		clock:  clock,
	}
}

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;update;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=storage.k8s.io,resources=csidrivers,verbs=get;list;watch
// +kubebuilder:rbac:groups=velero.io,resources=deletebackuprequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=velero.io,resources=deletebackuprequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=snapshot.storage.k8s.io,resources=volumesnapshotcontents,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=snapshot.storage.k8s.io,resources=volumesnapshotcontents/status,verbs=get;update;patch

func (r *retainedSnapshotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.recorder == nil {
		r.recorder = mgr.GetEventRecorderFor("velero-retained-snapshot")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1api.ConfigMap{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(object client.Object) bool {
			// Keyed by the record ConfigMap family, not by the backup or the
			// request.
			return object.GetLabels()[retainedsnapshot.FamilyLabel] == "true"
		})).
		WithOptions(controller.Options{MaxConcurrentReconciles: 10}).
		Named(constant.ControllerRetainedSnapshot).
		Complete(r)
}

func (r *retainedSnapshotReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithFields(logrus.Fields{
		"controller": constant.ControllerRetainedSnapshot,
		"configmap":  req.String(),
	})

	shard := &corev1api.ConfigMap{}
	if err := r.Get(ctx, req.NamespacedName, shard); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting the retained snapshot record shard")
	}
	if shard.Labels[retainedsnapshot.FamilyLabel] != "true" {
		return ctrl.Result{}, nil
	}
	// The retained-snapshot controller ignores an inactive ConfigMap, so a
	// deletion whose repository step failed gathers records but never creates
	// a temporary content.
	if shard.Data[retainedsnapshot.ActiveKey] != "true" {
		log.Debug("The record shard is not activated, ignoring it")
		return ctrl.Result{}, nil
	}

	backup, err := r.backupOfShard(ctx, shard)
	if err != nil {
		return ctrl.Result{}, err
	}
	if backup == nil {
		// The Backup is gone by other means. A GC that finds a family whose
		// Backup is gone removes it only when it has no pending entries; when
		// pending entries exist, they are moved to the orphan-snapshot
		// ConfigMap with an event, the same path as escalation and skip, and
		// only then is the family removed, so no path deletes a pending record
		// without leaving the orphan trace the Security section requires.
		return ctrl.Result{}, r.garbageCollectShard(ctx, shard, log)
	}

	log = log.WithField("backup", backup.Name)

	pending := pendingShardKeys(shard)
	for _, name := range pending {
		done, requeue, err := r.deleteEntry(ctx, backup, shard, name, log)
		if err != nil {
			// The deletion of one entry fails the backup deletion, so it can
			// be retried; a retry regathers from the ConfigMap, which is
			// idempotent, and replays only the unfinished entries.
			if failErr := r.failDeleteBackupRequest(ctx, backup, err); failErr != nil {
				log.WithError(failErr).Error("Error failing the backup deletion")
				return ctrl.Result{}, failErr
			}
			log.WithError(err).Errorf("Error deleting the retained snapshot of DataUpload %s, failing the backup deletion", name)
			return ctrl.Result{}, nil
		}
		if !done {
			// The entry was skipped or escalated, its record moved to the
			// orphan-snapshot ConfigMap; the deletion proceeds.
			log.Infof("The retained snapshot of DataUpload %s was skipped, its record is in the orphan-snapshot ConfigMap", name)
			continue
		}
		if requeue {
			return ctrl.Result{RequeueAfter: csi.RetainedSnapshotDeletionTimeout}, nil
		}
	}

	// Wake the waiting request when nothing is pending anymore: the request
	// re-enters, clears its own annotation and runs the tail. While pending
	// work remains, this reconcile's writes re-enqueue the shard, and the
	// requeue is the backstop for a deletion whose wait expired without a
	// further write.
	family, err := retainedsnapshot.LoadFamily(ctx, r.Client, backup)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error re-reading the retained snapshot records")
	}
	if !family.HasPendingWork() {
		if err := r.wakeDeleteBackupRequest(ctx, backup, log); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("The retained snapshots are deleted, the backup deletion is woken up")
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: csi.RetainedSnapshotDeletionTimeout}, nil
}

// backupOfShard resolves the Backup a record shard belongs to through its
// labels, and returns nil when the Backup is gone.
func (r *retainedSnapshotReconciler) backupOfShard(ctx context.Context, shard *corev1api.ConfigMap) (*velerov1api.Backup, error) {
	backupName := shard.Labels[velerov1api.BackupNameLabel]
	if backupName == "" {
		return nil, errors.Errorf("the record shard %s carries no %s label", shard.Name, velerov1api.BackupNameLabel)
	}
	backup := &velerov1api.Backup{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: shard.Namespace, Name: backupName}, backup); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "error getting the backup %s of the record shard %s", backupName, shard.Name)
	}
	// The name can repeat; the UID is the identity the family was gathered for.
	if uid := shard.Labels[velerov1api.BackupUIDLabel]; uid != "" && string(backup.UID) != uid {
		return nil, nil
	}
	return backup, nil
}

// deleteEntry deletes the retained snapshot of one DataUpload. It returns
// done=false when the record was moved to the orphan-snapshot ConfigMap --
// skipped for an unknown driver, or escalated after the bounded number of
// persisted DeleteSnapshot failures -- so the backup deletion proceeds, and
// requeue=true when the entry stays pending.
func (r *retainedSnapshotReconciler) deleteEntry(ctx context.Context, backup *velerov1api.Backup, shard *corev1api.ConfigMap, name string, log logrus.FieldLogger) (done, requeue bool, err error) {
	value, ok := shard.Data[name]
	if !ok {
		return true, false, nil
	}
	entry, err := retainedsnapshot.UnmarshalEntry(value)
	if err != nil {
		// A record that cannot be decoded can never be deleted; it is moved to
		// the orphan ConfigMap for manual cleanup instead of failing the
		// deletion forever.
		r.eventf(shard, backup, "RetainedSnapshotRecordInvalid", "the retained snapshot record of DataUpload %s cannot be decoded and was moved to the orphan-snapshot ConfigMap: %v", name, err)
		return false, false, r.moveToOrphan(ctx, backup, name, &retainedsnapshot.Entry{Attempts: retainedsnapshot.MaxAttempts})
	}
	if entry.CSISnapshotHandle == "" {
		return true, false, errors.Errorf("the retained snapshot record of DataUpload %s carries no handle", name)
	}

	// Records sourced from DataUpload.status are trusted -- they entered
	// through the API -- and are preferred over tarball- or tag-derived values
	// wherever both exist. For an untrusted record naming a driver the cluster
	// does not run, the deletion neither issues the DeleteSnapshot call nor
	// hard-fails: a secondary cluster that runs no such driver is exactly the
	// sync use case, and a hard failure would make synced backups undeletable.
	if !entry.Trusted {
		known, err := r.driverExists(ctx, entry.Driver)
		if err != nil {
			return true, false, errors.Wrapf(err, "error checking whether the cluster runs driver %s", entry.Driver)
		}
		if !known {
			r.eventf(shard, backup, "RetainedSnapshotDriverUnknown", "the cluster does not run driver %s, the retained snapshot of DataUpload %s was moved to the orphan-snapshot ConfigMap for manual cleanup", entry.Driver, name)
			return false, false, r.moveToOrphan(ctx, backup, name, entry)
		}
	}

	err = csi.DeleteRetainedSnapshot(ctx, r.Client, entry.Record(), log)
	if err == nil {
		// The entry is removed only after the snapshot is confirmed deleted.
		if err := retainedsnapshot.MarkCompleted(ctx, r.Client, backup, name); err != nil {
			return true, true, errors.Wrapf(err, "error marking the retained snapshot of DataUpload %s as deleted", name)
		}
		log.Infof("Deleted the retained snapshot %s of DataUpload %s", entry.CSISnapshotHandle, name)
		return true, false, nil
	}

	var callErr *csi.SnapshotDeleteCallError
	if errors.As(err, &callErr) {
		// Only a failure of the DeleteSnapshot call itself is a stale-snapshot
		// signal: the sidecar emits the same reason for credential failures,
		// which are an environment problem that stays retryable, and for
		// status-clear failures, which follow a successful delete. A driver
		// that answers an already-gone snapshot with an internal error can
		// fail every retry, so the deletion escalates after a bounded number
		// of these instead of relying on driver compliance. Escalating trades
		// a possible leak against an undeletable backup, and that trade is
		// deliberate.
		entry.Attempts++
		if entry.Attempts >= retainedsnapshot.MaxAttempts {
			r.eventf(shard, backup, "RetainedSnapshotDeleteEscalated",
				"the CSI driver failed to delete the snapshot %s of DataUpload %s %d times (%v); it was moved to the orphan-snapshot ConfigMap for manual cleanup, and the backup deletion proceeds",
				entry.CSISnapshotHandle, name, entry.Attempts, callErr)
			return false, false, r.moveToOrphan(ctx, backup, name, entry)
		}
		// The counter is persisted, so a retry of `velero backup delete`,
		// which is a new DeleteBackupRequest, still reaches the bound across
		// retries instead of looping forever.
		if err := retainedsnapshot.UpdateEntry(ctx, r.Client, backup, name, entry); err != nil {
			return true, true, errors.Wrapf(err, "error persisting the failed attempt count of DataUpload %s", name)
		}
		return true, false, errors.Wrapf(callErr, "the CSI driver failed to delete the snapshot of DataUpload %s, attempt %d of %d", name, entry.Attempts, retainedsnapshot.MaxAttempts)
	}

	// Any other failure -- a timeout, a credential failure, an API error --
	// fails the backup deletion so it can be retried.
	return true, false, err
}

// moveToOrphan moves an escalated or skipped record to the orphan-snapshot
// ConfigMap, keyed by <backup-UID>.<DataUpload-name>, which satisfies the
// ConfigMap data key charset and cannot collide across backups once the
// backup label is absent. The orphan ConfigMap is not labeled by backup and is
// therefore neither deleted by the family's last-entry rule nor
// garbage-collected when the Backup is gone; it is the durable home for manual
// cleanup, and removing an entry after its snapshot is cleaned up by hand is
// the operator's action.
func (r *retainedSnapshotReconciler) moveToOrphan(ctx context.Context, backup *velerov1api.Backup, name string, entry *retainedsnapshot.Entry) error {
	if err := retainedsnapshot.WriteOrphanEntry(ctx, r.Client, backup, name, entry); err != nil {
		return errors.Wrapf(err, "error moving the record of DataUpload %s to the orphan-snapshot ConfigMap", name)
	}
	return retainedsnapshot.RemoveEntry(ctx, r.Client, backup, name)
}

// driverExists reports whether the cluster runs the named CSI driver.
func (r *retainedSnapshotReconciler) driverExists(ctx context.Context, driver string) (bool, error) {
	list := &storagev1api.CSIDriverList{}
	if err := r.Client.List(ctx, list); err != nil {
		return false, errors.Wrap(err, "error listing the CSIDrivers")
	}
	for i := range list.Items {
		if list.Items[i].Name == driver {
			return true, nil
		}
	}
	return false, nil
}

// garbageCollectShard removes a record family whose Backup is gone by other
// means: without pending entries the shard is simply deleted; with pending
// entries they are moved to the orphan-snapshot ConfigMap with an event first,
// so no path deletes a pending record without leaving the orphan trace.
func (r *retainedSnapshotReconciler) garbageCollectShard(ctx context.Context, shard *corev1api.ConfigMap, log logrus.FieldLogger) error {
	pending := pendingShardKeys(shard)
	if len(pending) == 0 {
		return client.IgnoreNotFound(r.Delete(ctx, shard))
	}

	// The Backup is gone, so the orphan entries are keyed by the backup name
	// and UID the shard still carries.
	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: shard.Namespace,
			Name:      shard.Labels[velerov1api.BackupNameLabel],
			UID:       types.UID(shard.Labels[velerov1api.BackupUIDLabel]),
		},
	}
	for _, name := range pending {
		entry, err := retainedsnapshot.UnmarshalEntry(shard.Data[name])
		if err != nil {
			entry = &retainedsnapshot.Entry{Attempts: retainedsnapshot.MaxAttempts}
		}
		if err := retainedsnapshot.WriteOrphanEntry(ctx, r.Client, backup, name, entry); err != nil {
			return errors.Wrapf(err, "error moving the record of DataUpload %s to the orphan-snapshot ConfigMap", name)
		}
	}
	r.eventf(shard, backup, "RetainedSnapshotOrphaned", "the backup is gone; %d pending retained snapshot records were moved to the orphan-snapshot ConfigMap for manual cleanup", len(pending))
	log.Warnf("The backup is gone; moved %d pending retained snapshot records to the orphan-snapshot ConfigMap", len(pending))
	return client.IgnoreNotFound(r.Delete(ctx, shard))
}

// wakeDeleteBackupRequest enqueues the DeleteBackupRequest that waits on this
// family with an update that leaves the pending annotation in place -- the
// annotation is what lets the request back in, so the waker never clears it.
func (r *retainedSnapshotReconciler) wakeDeleteBackupRequest(ctx context.Context, backup *velerov1api.Backup, log logrus.FieldLogger) error {
	return r.patchWaitingRequest(ctx, backup, func(req *velerov1api.DeleteBackupRequest) {
		if req.Annotations == nil {
			req.Annotations = map[string]string{}
		}
		req.Annotations[velerov1api.RetainedSnapshotsWakeAnnotation] = r.clock.Now().UTC().Format(time.RFC3339)
	}, log)
}

// failDeleteBackupRequest marks the DeleteBackupRequest that waits on this
// family Processed with the deletion error, so the backup deletion fails and
// can be retried; a retry creates a new request that regathers from the
// ConfigMap, which is idempotent.
func (r *retainedSnapshotReconciler) failDeleteBackupRequest(ctx context.Context, backup *velerov1api.Backup, err error) error {
	message := fmt.Sprintf("backup deletion failed: error deleting the retained snapshots: %v", err)
	return r.patchWaitingRequest(ctx, backup, func(req *velerov1api.DeleteBackupRequest) {
		req.Status.Phase = velerov1api.DeleteBackupRequestPhaseProcessed
		req.Status.Errors = []string{message}
	}, r.logger)
}

func (r *retainedSnapshotReconciler) patchWaitingRequest(ctx context.Context, backup *velerov1api.Backup, mutate func(*velerov1api.DeleteBackupRequest), log logrus.FieldLogger) error {
	list := &velerov1api.DeleteBackupRequestList{}
	selector := labels.SelectorFromSet(map[string]string{
		velerov1api.BackupNameLabel: backup.Name,
		velerov1api.BackupUIDLabel:  string(backup.UID),
	})
	if err := r.List(ctx, list, &client.ListOptions{Namespace: backup.Namespace, LabelSelector: selector}); err != nil {
		return errors.Wrap(err, "error listing the DeleteBackupRequests of the backup")
	}
	for i := range list.Items {
		req := &list.Items[i]
		if req.Status.Phase != velerov1api.DeleteBackupRequestPhaseInProgress ||
			req.Annotations[velerov1api.RetainedSnapshotsPendingAnnotation] == "" {
			continue
		}
		original := req.DeepCopy()
		mutate(req)
		if err := r.Patch(ctx, req, client.MergeFrom(original)); err != nil {
			return errors.Wrap(err, "error patching the DeleteBackupRequest")
		}
	}
	return nil
}

func (r *retainedSnapshotReconciler) eventf(shard *corev1api.ConfigMap, backup *velerov1api.Backup, reason, message string, args ...any) {
	if r.recorder == nil {
		r.logger.WithField("backup", backup.Name).Warningf(reason+": "+message, args...)
		return
	}
	r.recorder.Eventf(shard, corev1api.EventTypeWarning, reason, message, args...)
}
