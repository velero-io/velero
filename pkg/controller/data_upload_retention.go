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
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/util/csi"
	"github.com/velero-io/velero/pkg/util/datamover"
	"github.com/velero-io/velero/pkg/util/kube"
)

const (
	// dataUploadRetainLeaseAnnotation marks a DataUpload whose completion
	// callback is between the persisted record and the Retain patch of the
	// backup VolumeSnapshotContent. A rollback that finds an unexpired mark
	// fails and retries after the mark expires, so the two intents serialize
	// through the DataUpload object.
	dataUploadRetainLeaseAnnotation = "velero.io/dataupload-retain-snapshot-lease"

	// dataUploadRollbackLeaseAnnotation marks a DataUpload whose retained
	// snapshot is being released by the patch-back. Every patch-back actor
	// conditionally marks the DataUpload as rolling back as its first write,
	// which fails while an unexpired retaining mark exists.
	dataUploadRollbackLeaseAnnotation = "velero.io/dataupload-release-snapshot-lease"

	// dataUploadLeaseDuration is long enough for the two writes each lease
	// guards, and short enough that a crashed holder does not block the other
	// side for long.
	dataUploadLeaseDuration = time.Minute
)

// leaseRefusedError reports that a lease was not acquired because another
// holder's unexpired mark is on the DataUpload. The caller requeues for the
// lease duration, when the mark has expired, instead of relying on another
// event to retry.
type leaseRefusedError struct {
	error
}

// dataUploadLease is the value of a lease annotation: the holder's identity and
// the time the lease expires.
type dataUploadLease struct {
	Holder    string
	ExpiresAt time.Time
}

func (l *dataUploadLease) String() string {
	return l.Holder + "/" + strconv.FormatInt(l.ExpiresAt.Unix(), 10)
}

func parseDataUploadLease(value string) (*dataUploadLease, bool) {
	holder, expiry, found := strings.Cut(value, "/")
	if !found {
		return nil, false
	}
	unix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return nil, false
	}
	return &dataUploadLease{Holder: holder, ExpiresAt: time.Unix(unix, 0)}, true
}

// tryAcquireDataUploadLease conditionally sets the lease annotation on the
// DataUpload to the given holder. It fails, without writing, while another
// holder's unexpired lease is on either lease annotation -- the completion
// callback and the rollback path serialize their two intents through the one
// object, so an unexpired retaining mark blocks a rollback and an unexpired
// rolling-back mark blocks a retention. An absent, expired or own lease is
// (re-)acquired. The update is conflict-retried with a fresh read, so two
// racers cannot both acquire.
func (r *DataUploadReconciler) tryAcquireDataUploadLease(ctx context.Context, du *velerov2alpha1api.DataUpload, annotation, holder string, log logrus.FieldLogger) (bool, error) {
	acquired := false
	err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(current *velerov2alpha1api.DataUpload) bool {
		if isDataUploadInFinalState(current) {
			return false
		}
		for _, leaseAnnotation := range []string{dataUploadRetainLeaseAnnotation, dataUploadRollbackLeaseAnnotation} {
			if lease, ok := parseDataUploadLease(current.Annotations[leaseAnnotation]); ok &&
				lease.Holder != holder && r.Clock.Now().Before(lease.ExpiresAt) {
				return false
			}
		}
		if current.Annotations == nil {
			current.Annotations = make(map[string]string)
		}
		current.Annotations[annotation] = (&dataUploadLease{
			Holder:    holder,
			ExpiresAt: r.Clock.Now().Add(dataUploadLeaseDuration),
		}).String()
		acquired = true
		return true
	})
	if err != nil {
		return false, errors.Wrapf(err, "error acquiring the %s lease of DataUpload %s", annotation, du.Name)
	}
	return acquired, nil
}

// dataUploadLeaseHeld reports whether the lease annotation on the DataUpload is
// still held by the given holder and has not expired. The read goes through the
// uncached reader, so a throttled cached client cannot fail the check
// spuriously.
func (r *DataUploadReconciler) dataUploadLeaseHeld(ctx context.Context, du *velerov2alpha1api.DataUpload, annotation, holder string) (bool, error) {
	current := &velerov2alpha1api.DataUpload{}
	if err := r.uncachedReader().Get(ctx, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, current); err != nil {
		return false, errors.Wrap(err, "error reading the DataUpload lease")
	}
	lease, ok := parseDataUploadLease(current.Annotations[annotation])
	return ok && lease.Holder == holder && r.Clock.Now().Before(lease.ExpiresAt), nil
}

// uncachedReader reads DataUploads from the API server. The node-agent's cached
// client can return the pre-write object for a plain status update, and both
// the persisted-record verification and the lease re-check need what the API
// server actually holds. Without a manager, e.g. in tests, the client itself is
// a direct client.
func (r *DataUploadReconciler) uncachedReader() crclient.Reader {
	if r.apiReader != nil {
		return r.apiReader
	}
	return r.client
}

// shouldRetainSnapshot reports whether the DataUpload opted into base snapshot
// retention. The decision was made server-side, where the DataUpload was
// created, and travels in spec.dataMoverConfig; the node-agent never
// re-evaluates the volume policy, because the policy ConfigMap is not
// guaranteed to be readable from the node-agent.
func shouldRetainSnapshot(du *velerov2alpha1api.DataUpload) bool {
	return du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI &&
		datamover.IsVeleroBlockDataMover(du.Spec.DataMover) &&
		du.Spec.DataMoverConfig[velerov2alpha1api.RetainSnapshotDataMoverConfigKey] == "true"
}

// retainSnapshotOnCompletion records the snapshot of a completed DataUpload and
// switches the backup VolumeSnapshotContent to Retain, so the snapshot survives
// the exposer cleanup that follows.
//
// The ordering is a hard rule, not an implementation detail:
//
//   - The record is persisted before the content is switched to Retain, because
//     a retained storage snapshot whose record was never serialized into the
//     backup tarball is an unrecoverable leak, while the other order at worst
//     deletes a snapshot and the next incremental falls back to a full backup.
//   - Persisted means verified: after the status write, the DataUpload is read
//     back through an uncached reader and the record is asserted to carry the
//     handle and the driver, before the content is patched. A cluster whose
//     DataUpload CRD predates the field prunes it on write while the update
//     still reports success, so the read-back, not the API response, is the
//     proof; if the field comes back empty, the caller fails the DataUpload and
//     the content keeps Delete.
//   - The completion callback and the rollback path are fenced against each
//     other by a lease on the DataUpload: the callback conditionally marks the
//     DataUpload as retaining, re-checks that the mark is still its own
//     immediately before it patches the content, and the Retain patch is itself
//     preconditioned on the content's resourceVersion, captured right after the
//     re-check and used without a re-read, so a rollback that has patched or
//     deleted the content in between makes the delayed write fail instead of
//     landing after it.
//
// Any error returned here must fail the DataUpload and release the snapshot;
// the content keeps Delete in that case and section 3's patch-back reclaims it.
func (r *DataUploadReconciler) retainSnapshotOnCompletion(ctx context.Context, du *velerov2alpha1api.DataUpload, log logrus.FieldLogger) error {
	if !shouldRetainSnapshot(du) {
		return nil
	}

	// The backup VSC is named after the DataUpload, see
	// csiSnapshotExposer.createBackupVSC. The exposer creates it synchronously,
	// with the handle already in spec.source.snapshotHandle.
	vsc, err := r.csiSnapshotClient.VolumeSnapshotContents().Get(ctx, du.Name, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "error getting the backup VolumeSnapshotContent %s to retain its snapshot", du.Name)
	}
	record := csi.GetRetainedSnapshotFromVSC(vsc)
	if record == nil {
		return errors.Errorf("the backup VolumeSnapshotContent %s carries no snapshot handle to retain", du.Name)
	}

	holder := fmt.Sprintf("%s-%d", r.nodeName, r.Clock.Now().UnixNano())
	acquired, err := r.tryAcquireDataUploadLease(ctx, du, dataUploadRetainLeaseAnnotation, holder, log)
	if err != nil {
		return err
	}
	if !acquired {
		return errors.Errorf("another actor holds the retention lease of DataUpload %s", du.Name)
	}

	if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(current *velerov2alpha1api.DataUpload) bool {
		if isDataUploadInFinalState(current) {
			return false
		}
		current.Status.RetainedCSIStorageSnapshot = record
		return true
	}); err != nil {
		return errors.Wrapf(err, "error recording the retained snapshot %s on DataUpload %s", record.CSISnapshotHandle, du.Name)
	}

	// Persisted means verified, through an uncached read.
	updated := &velerov2alpha1api.DataUpload{}
	if err := r.uncachedReader().Get(ctx, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, updated); err != nil {
		return errors.Wrap(err, "error reading back the retained snapshot record")
	}
	persisted := updated.Status.RetainedCSIStorageSnapshot
	if persisted == nil || persisted.CSISnapshotHandle != record.CSISnapshotHandle || persisted.Driver != record.Driver {
		return errors.Errorf("the retained snapshot record of DataUpload %s did not persist, the DataUpload CRD may predate the %s field and must be upgraded before enabling retention",
			du.Name, "retainedCSIStorageSnapshot")
	}
	log.Infof("Recorded retained snapshot %s of driver %s on DataUpload %s", record.CSISnapshotHandle, record.Driver, du.Name)

	// Re-check the lease immediately before patching the content: for expiry or
	// for client throttling, the callback does not patch Retain, fails the
	// DataUpload and keeps the record, leaving the content Delete.
	held, err := r.dataUploadLeaseHeld(ctx, du, dataUploadRetainLeaseAnnotation, holder)
	if err != nil {
		return err
	}
	if !held {
		return errors.Errorf("the retention lease of DataUpload %s was lost before its snapshot was retained", du.Name)
	}

	if err := csi.PatchVSCDeletionPolicy(ctx, r.csiSnapshotClient, vsc.Name, snapshotv1api.VolumeSnapshotContentRetain, vsc.ResourceVersion); err != nil {
		if apierrors.IsNotFound(err) {
			// The rollback path already removed the content; the record is kept
			// and the backup deletion owns the snapshot.
			return errors.Wrapf(err, "the backup VolumeSnapshotContent %s vanished before its snapshot was retained", du.Name)
		}
		return errors.Wrapf(err, "error switching the backup VolumeSnapshotContent %s to Retain", vsc.Name)
	}
	log.Infof("Switched the backup VolumeSnapshotContent %s to Retain, snapshot %s survives the cleanup", vsc.Name, record.CSISnapshotHandle)

	return nil
}

// confirmRetainedSnapshotCleanup finishes the exposer cleanup on the retention
// path. The exposer cleanup deletes the backup pod, PVC and VolumeSnapshot, but
// a VolumeSnapshot deletion cascades to its content only when the content's
// policy is Delete, so under Retain the content object would stay behind, one
// per volume per backup, while the storage snapshot survives as intended. The
// content is therefore deleted explicitly, and the Completed mark is held until
// the intended end state is confirmed: deleting a Retain content is exactly
// what leaves the storage snapshot in place.
func (r *DataUploadReconciler) confirmRetainedSnapshotCleanup(ctx context.Context, du *velerov2alpha1api.DataUpload, log logrus.FieldLogger) error {
	if !shouldRetainSnapshot(du) {
		return nil
	}

	vsc, err := r.csiSnapshotClient.VolumeSnapshotContents().Get(ctx, du.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "error getting the backup VolumeSnapshotContent %s to clean it up", du.Name)
	}
	if vsc.Spec.DeletionPolicy != snapshotv1api.VolumeSnapshotContentRetain {
		// Never switched to Retain; the VolumeSnapshot deletion cascades.
		return nil
	}

	if err := r.csiSnapshotClient.VolumeSnapshotContents().Delete(ctx, du.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error deleting the retained backup VolumeSnapshotContent %s", du.Name)
	}
	if err := csi.EnsureDeleteVSC(ctx, r.csiSnapshotClient, du.Name, csi.RetainedSnapshotDeletionTimeout); err != nil {
		return errors.Wrapf(err, "the retained backup VolumeSnapshotContent %s is not gone", du.Name)
	}
	log.Infof("Deleted the retained backup VolumeSnapshotContent %s, the storage snapshot stays", du.Name)
	return nil
}

// releaseRetainedSnapshot reclaims the snapshot of a DataUpload that did not
// complete: it patches the backup VolumeSnapshotContent, never the user's
// VolumeSnapshotClass, back to Delete before the cleanup, so the CSI driver
// deletes the snapshot instead of leaving it in the storage untracked.
//
// The patch-back is owned by the reconcile, not only by the failing code path:
// a hard kill of the node-agent (OOM, force delete) inside the switch window
// leaves no in-process retry, so any reconciler must be able to run it. It is
// idempotent and safe for any node-agent to run, last-writer-wins on each
// step; the backup VolumeSnapshotContent, VolumeSnapshot and PVC are all named
// after the DataUpload.
//
// The patch-back is ordered delete-first, clear-last:
//
//   - patch the content to Delete with a resourceVersion precondition;
//   - delete the backup PVC, the backup VolumeSnapshot and the backup
//     VolumeSnapshotContent. The PVC deletion is a prerequisite because the
//     common snapshot controller refuses to delete a VolumeSnapshot that a
//     pending claim is being provisioned from, reporting SnapshotDeletePending,
//     and a failed exposer leaves exactly that state when it dies after
//     creating the backup PVC. The VolumeSnapshot deletion is a prerequisite
//     because the snapshotter deletes a bound content only after the snapshot
//     deletion has begun, so deleting the content alone leaves it waiting;
//   - wait for the content to disappear, bounded by the deletion timeout, so a
//     driver that keeps failing DeleteSnapshot cannot block the reconcile
//     forever. At the bound, the DataUpload fails, the record stays in place
//     so backup deletion owns the snapshot;
//   - only then clear the record. Confirming the policy is not release: a
//     Delete content still has to be deleted for the sidecar to call
//     DeleteSnapshot, and a crash between a record clear and that deletion
//     would strand the snapshot with no record at all, the one leak this path
//     exists to prevent.
//
// A NotFound at any step clears nothing: the content can be absent because the
// retention-path cleanup already deleted it under a Retain policy -- the
// storage snapshot then still exists -- after a Completed update that failed to
// stick. Clearing the record on absence alone would strand a retained snapshot
// with no cleanup record, so the record is kept and the backup deletion owns
// the snapshot by rebuilding the temp content from it, which is safe whether
// the snapshot exists or not.
func (r *DataUploadReconciler) releaseRetainedSnapshot(ctx context.Context, du *velerov2alpha1api.DataUpload, log logrus.FieldLogger) error {
	if du.Spec.SnapshotType != velerov2alpha1api.SnapshotTypeCSI {
		return nil
	}

	// The patch-back no-ops on a DataUpload in a final state: the cancel path
	// can reach a DataUpload that already reached a terminal phase, and a
	// patch-back that ran there would delete the base snapshot of a completed
	// backup. The in-memory DataUpload can be stale, e.g. the cancel path marks
	// the object Canceled before it cleans up, so the guard reads the object
	// the API server holds.
	current := &velerov2alpha1api.DataUpload{}
	if err := r.uncachedReader().Get(ctx, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, current); err != nil {
		return errors.Wrap(err, "error reading the DataUpload before releasing its snapshot")
	}
	if isDataUploadInFinalState(current) {
		log.Infof("DataUpload %s is in the final phase %s, not releasing its snapshot; a surviving record is owned by the backup deletion", du.Name, current.Status.Phase)
		return nil
	}

	vsc, err := r.csiSnapshotClient.VolumeSnapshotContents().Get(ctx, du.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if du.Status.RetainedCSIStorageSnapshot != nil {
			log.Infof("The backup VolumeSnapshotContent %s is gone; keeping the retained snapshot record so the backup deletion owns the snapshot", du.Name)
		}
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "error getting the backup VolumeSnapshotContent %s to release its snapshot", du.Name)
	}

	record := du.Status.RetainedCSIStorageSnapshot
	if record == nil && vsc.Spec.DeletionPolicy != snapshotv1api.VolumeSnapshotContentRetain {
		// Nothing was retained: the exposer cleanup reclaims the snapshot
		// through the VolumeSnapshot deletion cascade.
		return nil
	}

	// Lease fence: the patch-back marks its intent first and fails while an
	// unexpired retaining mark exists, retrying after it expires, so the two
	// intents serialize through one object. Both marks carry the same
	// expiry and steal an expired mark, so a crashed holder blocks the other
	// side for at most the lease duration.
	holder := fmt.Sprintf("%s-%d", r.nodeName, r.Clock.Now().UnixNano())
	acquired, err := r.tryAcquireDataUploadLease(ctx, du, dataUploadRollbackLeaseAnnotation, holder, log)
	if err != nil {
		return err
	}
	if !acquired {
		// A refused mark must drive a retry: nothing else re-enqueues the
		// DataUpload for this, the node-agent has no sync period. The caller
		// requeues for the lease expiry.
		return &leaseRefusedError{errors.Errorf("another actor holds the retention lease of DataUpload %s, retrying the release after it expires", du.Name)}
	}

	if vsc.Spec.DeletionPolicy == snapshotv1api.VolumeSnapshotContentRetain {
		// A raced Retain write makes this fail and be retried instead of
		// slipping between a confirm and a delete: the patch carries the
		// content's captured resourceVersion, so a concurrent write in between
		// makes it fail with a conflict instead of landing after it.
		if err := csi.PatchVSCDeletionPolicy(ctx, r.csiSnapshotClient, vsc.Name, snapshotv1api.VolumeSnapshotContentDelete, vsc.ResourceVersion); err != nil {
			return errors.Wrapf(err, "error switching the backup VolumeSnapshotContent %s back to Delete", vsc.Name)
		}
		log.Infof("Switched the backup VolumeSnapshotContent %s back to Delete to release its snapshot", vsc.Name)
	}

	// Seed status.snapshotHandle before the deletions: the sidecar only issues
	// DeleteSnapshot for a content being deleted when its policy is Delete and
	// its status carries the handle, otherwise it removes the finalizer with no
	// CSI call and the content's disappearance would read as release while the
	// snapshot leaks.
	seedHandle := ""
	if record != nil {
		seedHandle = record.CSISnapshotHandle
	}
	if seedHandle == "" && vsc.Spec.Source.SnapshotHandle != nil {
		seedHandle = *vsc.Spec.Source.SnapshotHandle
	}
	if err := csi.SeedVSCStatusSnapshotHandle(ctx, r.csiSnapshotClient, vsc, seedHandle); err != nil {
		return errors.Wrapf(err, "error seeding the status of the backup VolumeSnapshotContent %s before releasing its snapshot", vsc.Name)
	}

	// The PVC is a prerequisite of the VolumeSnapshot deletion, see the comment
	// above; it is owner-referenced by the DataUpload, so nothing but this path
	// removes it before DataUpload deletion.
	kube.DeletePVCIfAny(ctx, r.kubeClient.CoreV1(), du.Name, du.Namespace, time.Minute, log)

	vs, err := r.csiSnapshotClient.VolumeSnapshots(du.Namespace).Get(ctx, du.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error getting the backup VolumeSnapshot %s/%s", du.Namespace, du.Name)
	}
	if err == nil {
		if err := csi.DeleteVSWithResourceVersion(ctx, r.csiSnapshotClient, du.Namespace, du.Name, vs.ResourceVersion); err != nil {
			return err
		}
	}

	if err := csi.DeleteVSCWithResourceVersion(ctx, r.csiSnapshotClient, du.Name, vsc.ResourceVersion); err != nil {
		return err
	}

	if err := csi.EnsureDeleteVSC(ctx, r.csiSnapshotClient, du.Name, csi.RetainedSnapshotDeletionTimeout); err != nil {
		// At the bound, the record is kept so the backup deletion owns the
		// snapshot.
		return errors.Wrapf(err, "error confirming the release of the snapshot of DataUpload %s", du.Name)
	}

	// Delete-first, clear-last.
	if record != nil {
		if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(current *velerov2alpha1api.DataUpload) bool {
			current.Status.RetainedCSIStorageSnapshot = nil
			return true
		}); err != nil {
			return errors.Wrapf(err, "error clearing the retained snapshot record of DataUpload %s", du.Name)
		}
		log.Infof("Released the retained snapshot %s of DataUpload %s, the record is cleared", record.CSISnapshotHandle, du.Name)
	}
	return nil
}
