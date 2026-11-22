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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/velero-io/velero/pkg/plugin/mocks"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/repository"
	repomanager "github.com/velero-io/velero/pkg/repository/manager"
	repomocks "github.com/velero-io/velero/pkg/repository/mocks"
	repotypes "github.com/velero-io/velero/pkg/repository/types"
	"github.com/velero-io/velero/pkg/repository/udmrepo"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/uploader"
	"github.com/velero-io/velero/pkg/util/csi"
	retainedsnapshot "github.com/velero-io/velero/pkg/util/retainedsnapshot"
)

const (
	retainedTestHandle = "0001-0009-rook-ceph-0000000000000001-snap"
	retainedTestDriver = "rbd.csi.ceph.com"
)

// fakeSnapshotBackend plays the CSI snapshotter and the storage for the
// temporary VolumeSnapshotContent of a retained snapshot, following
// external-snapshotter v8.6: the sidecar calls DeleteSnapshot only for a
// content being deleted whose policy is Delete and whose status carries the
// handle; it then removes the bound-protection finalizer, which makes the
// content disappear. A snapshot that is absent from the storage makes the
// DeleteSnapshot call fail, which the sidecar reports only as a
// SnapshotDeleteError event, never as status.error.
type fakeSnapshotBackend struct {
	// snapshots maps handle -> exists.
	snapshots map[string]bool
	// deleteErrorMessage, when set, makes the DeleteSnapshot call fail with a
	// SnapshotDeleteError event carrying this message, as the sidecar does.
	deleteErrorMessage string
	// deleteCallsTo records the handles DeleteSnapshot was called for.
	deleteCallsTo []string
}

func (b *fakeSnapshotBackend) client(t *testing.T, objs ...runtime.Object) client.Client {
	t.Helper()
	// The status subresource must be modeled for the VolumeSnapshotContent:
	// without it the fake client treats a status update as a full-object
	// update and wipes the spec, which a real API server never does.
	fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithRuntimeObjects(objs...).
		WithStatusSubresource(&snapshotv1api.VolumeSnapshotContent{}).
		Build()
	return interceptor.NewClient(fakeClient.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			vsc, ok := obj.(*snapshotv1api.VolumeSnapshotContent)
			if !ok {
				return nil
			}
			deleting := &snapshotv1api.VolumeSnapshotContent{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(vsc), deleting); err != nil {
				return client.IgnoreNotFound(err)
			}
			if deleting.Spec.DeletionPolicy == snapshotv1api.VolumeSnapshotContentDelete &&
				deleting.Status != nil && deleting.Status.SnapshotHandle != nil {
				if b.deleteErrorMessage != "" || !b.snapshots[*deleting.Status.SnapshotHandle] {
					// The sidecar keeps the finalizer and retries, reporting
					// the failure only as an event, never as status.error.
					if b.deleteErrorMessage != "" {
						event := &corev1api.Event{
							ObjectMeta: metav1.ObjectMeta{
								GenerateName: "event-",
								Namespace:    metav1.NamespaceDefault,
							},
							InvolvedObject: corev1api.ObjectReference{
								Kind: "VolumeSnapshotContent",
								Name: deleting.Name,
							},
							Reason:        csi.SnapshotDeleteErrorEventReason,
							Message:       b.deleteErrorMessage,
							LastTimestamp: metav1.Now(),
						}
						if err := c.Create(ctx, event); err != nil {
							return err
						}
					}
					return nil
				}
				b.deleteCallsTo = append(b.deleteCallsTo, *deleting.Status.SnapshotHandle)
				b.snapshots[*deleting.Status.SnapshotHandle] = false
			}
			// The finalizer is removed once the sidecar is done with the
			// content, which makes it disappear.
			deleting.Finalizers = nil
			return c.Update(ctx, deleting)
		},
	})
}

func retainedTestBackup() *velerov1api.Backup {
	backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").SnapshotMoveData(true).Result()
	backup.UID = "uid"
	return backup
}

// retainedTestFamily writes one activated shard with the given entries and
// returns the shard.
func retainedTestFamily(t *testing.T, c client.Client, backup *velerov1api.Backup, entries map[string]*retainedsnapshot.Entry) *corev1api.ConfigMap {
	t.Helper()
	require.NoError(t, retainedsnapshot.WriteEntries(t.Context(), c, backup, entries))
	require.NoError(t, retainedsnapshot.Activate(t.Context(), c, backup))
	family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	require.Len(t, family.Shards, 1)
	return family.Shards[0]
}

// retainedTestRequest creates the DeleteBackupRequest that waits on the
// family, as the backup-deletion controller's handoff leaves it.
func retainedTestRequest(t *testing.T, c client.Client, backup *velerov1api.Backup) *velerov1api.DeleteBackupRequest {
	t.Helper()
	dbr := defaultTestDbr()
	dbr.Status.Phase = velerov1api.DeleteBackupRequestPhaseInProgress
	dbr.Labels[velerov1api.BackupNameLabel] = backup.Name
	dbr.Labels[velerov1api.BackupUIDLabel] = string(backup.UID)
	dbr.Annotations = map[string]string{velerov1api.RetainedSnapshotsPendingAnnotation: "true"}
	require.NoError(t, c.Create(t.Context(), dbr))
	return dbr
}

func newRetainedTestReconciler(c client.Client) *retainedSnapshotReconciler {
	return NewRetainedSnapshotReconciler(velerotest.NewLogger(), c, nil, clock.RealClock{})
}

func reconcileShard(t *testing.T, r *retainedSnapshotReconciler, shard *corev1api.ConfigMap) {
	t.Helper()
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: shard.Namespace, Name: shard.Name}})
	require.NoError(t, err)
}

func getShard(t *testing.T, c client.Client, shard *corev1api.ConfigMap) *corev1api.ConfigMap {
	t.Helper()
	current := &corev1api.ConfigMap{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(shard), current))
	return current
}

func getRequest(t *testing.T, c client.Client, dbr *velerov1api.DeleteBackupRequest) *velerov1api.DeleteBackupRequest {
	t.Helper()
	current := &velerov1api.DeleteBackupRequest{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(dbr), current))
	return current
}

// TestRetainedSnapshotControllerDeletesEntry proves the core deletion
// behavior: the entry is removed only after the snapshot is confirmed deleted
// by the CSI driver, and the waiting request is woken with an update that
// leaves its pending annotation in place.
func TestRetainedSnapshotControllerDeletesEntry(t *testing.T) {
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true, "another-snapshot": true}}
	backup := retainedTestBackup()
	c := backend.client(t, backup)

	shard := retainedTestFamily(t, c, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true},
	})
	dbr := retainedTestRequest(t, c, backup)

	reconcileShard(t, newRetainedTestReconciler(c), shard)

	// The driver deleted the snapshot, and only that snapshot.
	assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)
	assert.True(t, backend.snapshots["another-snapshot"], "snapshots of other backups must stay")

	// The entry is removed after the confirmed deletion and recorded in the
	// completed set, so a regather does not replay it.
	current := getShard(t, c, shard)
	assert.NotContains(t, current.Data, "foo-du")
	family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.Contains(t, family.CompletedSet(), "foo-du")

	// The waiting request is woken, its pending annotation still in place.
	req := getRequest(t, c, dbr)
	assert.NotEmpty(t, req.Annotations[velerov1api.RetainedSnapshotsWakeAnnotation])
	assert.NotEmpty(t, req.Annotations[velerov1api.RetainedSnapshotsPendingAnnotation],
		"the waker never clears the pending annotation")
	assert.Equal(t, velerov1api.DeleteBackupRequestPhaseInProgress, req.Status.Phase)
}

// TestRetainedSnapshotControllerIgnoresInactiveShard proves the activation
// guard: a deletion whose repository step failed gathers records but never has
// them deleted, because the controller ignores an inactive ConfigMap.
func TestRetainedSnapshotControllerIgnoresInactiveShard(t *testing.T) {
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true}}
	backup := retainedTestBackup()
	c := backend.client(t, backup)

	require.NoError(t, retainedsnapshot.WriteEntries(t.Context(), c, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true},
	}))
	family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	shard := family.Shards[0]

	reconcileShard(t, newRetainedTestReconciler(c), shard)

	assert.Empty(t, backend.deleteCallsTo, "an inactive shard must not create a temporary content")
	current := getShard(t, c, shard)
	assert.Contains(t, current.Data, "foo-du")
}

// TestRetainedSnapshotControllerSkipsUnknownDriver proves the Security rule:
// for a record sourced from the tarball or the tag naming a driver the cluster
// does not run, the deletion neither issues the DeleteSnapshot call nor
// hard-fails -- a secondary cluster that runs no such driver is exactly the
// sync use case -- the record is skipped with an event and moved to the
// orphan-snapshot ConfigMap.
func TestRetainedSnapshotControllerSkipsUnknownDriver(t *testing.T) {
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true}}
	backup := retainedTestBackup()
	c := backend.client(t, backup)

	shard := retainedTestFamily(t, c, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: false},
	})
	dbr := retainedTestRequest(t, c, backup)

	reconcileShard(t, newRetainedTestReconciler(c), shard)

	assert.Empty(t, backend.deleteCallsTo, "no DeleteSnapshot call for a driver the cluster does not run")
	// The record moved to the orphan-snapshot ConfigMap and the deletion
	// proceeds.
	assert.NotContains(t, getShard(t, c, shard).Data, "foo-du")
	orphans := &corev1api.ConfigMapList{}
	require.NoError(t, c.List(t.Context(), orphans, client.MatchingLabels{retainedsnapshot.OrphanLabel: "true"}))
	require.Len(t, orphans.Items, 1)
	assert.Contains(t, orphans.Items[0].Data, string(backup.UID)+".foo-du")

	// The request is woken rather than failed.
	req := getRequest(t, c, dbr)
	assert.Equal(t, velerov1api.DeleteBackupRequestPhaseInProgress, req.Status.Phase)
}

// TestRetainedSnapshotControllerEscalatesAfterBoundedAttempts proves the
// escalation: a driver that keeps failing the DeleteSnapshot call itself is
// skipped with an event after a bounded, persisted number of attempts, and the
// backup deletion proceeds; the record lands in the orphan-snapshot ConfigMap
// with its attempt count.
func TestRetainedSnapshotControllerEscalatesAfterBoundedAttempts(t *testing.T) {
	// Shorten the deletion wait so the failing call surfaces quickly.
	originalTimeout := csi.RetainedSnapshotDeletionTimeout
	t.Cleanup(func() { csi.RetainedSnapshotDeletionTimeout = originalTimeout })
	csi.RetainedSnapshotDeletionTimeout = 200 * time.Millisecond

	// The driver fails the call itself, as a stale record whose snapshot is
	// already gone can on drivers that answer with an internal error instead
	// of a not-found code: only this message counts toward the bound.
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{}, deleteErrorMessage: "Failed to delete snapshot"}
	backup := retainedTestBackup()
	c := backend.client(t, backup)

	// The entry already carries the attempts of the earlier retries, persisted
	// in the ConfigMap, so a driver that fails slowly still reaches the bound
	// across retries of the backup deletion.
	shard := retainedTestFamily(t, c, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true, Attempts: retainedsnapshot.MaxAttempts - 1},
	})
	dbr := retainedTestRequest(t, c, backup)

	reconcileShard(t, newRetainedTestReconciler(c), shard)

	// The record escalated to the orphan-snapshot ConfigMap...
	assert.NotContains(t, getShard(t, c, shard).Data, "foo-du")
	orphans := &corev1api.ConfigMapList{}
	require.NoError(t, c.List(t.Context(), orphans, client.MatchingLabels{retainedsnapshot.OrphanLabel: "true"}))
	require.Len(t, orphans.Items, 1)
	entry, err := retainedsnapshot.UnmarshalEntry(orphans.Items[0].Data[string(backup.UID)+".foo-du"])
	require.NoError(t, err)
	assert.Equal(t, retainedsnapshot.MaxAttempts, entry.Attempts)

	// ... and the backup deletion proceeds: the request is woken, not failed.
	req := getRequest(t, c, dbr)
	assert.Equal(t, velerov1api.DeleteBackupRequestPhaseInProgress, req.Status.Phase)
	assert.Empty(t, req.Status.Errors)
}

// TestRetainedSnapshotControllerFailsRequestOnRetryableError proves the
// failure propagation: a credential failure or a timeout fails the backup
// deletion -- the request is marked Processed with the error -- so it can be
// retried, and the entry stays pending with its attempt count persisted.
func TestRetainedSnapshotControllerFailsRequestOnRetryableError(t *testing.T) {
	// Shorten the deletion wait: a deletion that is merely slow surfaces as a
	// pending timeout instead of blocking the test.
	originalTimeout := csi.RetainedSnapshotDeletionTimeout
	t.Cleanup(func() { csi.RetainedSnapshotDeletionTimeout = originalTimeout })
	csi.RetainedSnapshotDeletionTimeout = 200 * time.Millisecond

	// The sidecar cannot get the snapshot credentials, an environment problem
	// that fails the backup deletion and stays retryable: a restored secret
	// lets the deletion succeed.
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true}, deleteErrorMessage: "Failed to get snapshot credentials"}
	backup := retainedTestBackup()
	c := backend.client(t, backup)

	shard := retainedTestFamily(t, c, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true},
	})
	dbr := retainedTestRequest(t, c, backup)

	reconcileShard(t, newRetainedTestReconciler(c), shard)

	// The request is failed with the error, so the deletion can be retried.
	req := getRequest(t, c, dbr)
	assert.Equal(t, velerov1api.DeleteBackupRequestPhaseProcessed, req.Status.Phase)
	assert.NotEmpty(t, req.Status.Errors)

	// The entry stays pending; a credential failure is not a DeleteSnapshot
	// call failure, so it does not count toward the escalation bound.
	family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	entry, ok := family.Entry("foo-du")
	require.True(t, ok, "the entry stays pending")
	assert.Zero(t, entry.Attempts, "a credential failure does not count toward the escalation bound")
}

// TestRetainedSnapshotControllerGarbageCollects proves the GC rule: a family
// whose Backup is gone by other means is removed only when it has no pending
// entries; when pending entries exist, they are moved to the orphan-snapshot
// ConfigMap first, so no path deletes a pending record without leaving the
// orphan trace.
func TestRetainedSnapshotControllerGarbageCollects(t *testing.T) {
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true}}
	// No Backup object exists: it is gone by other means.
	c := backend.client(t)

	t.Run("no pending entries, the shard is deleted", func(t *testing.T) {
		backup := retainedTestBackup()
		// A shard with no pending entries keeps its completed set until the
		// deletion finishes.
		require.NoError(t, retainedsnapshot.WriteEntries(t.Context(), c, backup, map[string]*retainedsnapshot.Entry{
			"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true},
		}))
		require.NoError(t, retainedsnapshot.MarkCompleted(t.Context(), c, backup, "foo-du"))
		require.NoError(t, retainedsnapshot.Activate(t.Context(), c, backup))
		family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
		require.NoError(t, err)
		require.Len(t, family.Shards, 1)
		shard := family.Shards[0]

		reconcileShard(t, newRetainedTestReconciler(c), shard)

		err = c.Get(t.Context(), client.ObjectKeyFromObject(shard), &corev1api.ConfigMap{})
		assert.True(t, apierrors.IsNotFound(err), "the empty shard is garbage collected")
	})

	t.Run("pending entries are moved to the orphan ConfigMap first", func(t *testing.T) {
		backup := retainedTestBackup()
		shard := retainedTestFamily(t, c, backup, map[string]*retainedsnapshot.Entry{
			"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true},
		})

		reconcileShard(t, newRetainedTestReconciler(c), shard)

		assert.Empty(t, backend.deleteCallsTo, "no DeleteSnapshot call without the Backup")
		orphans := &corev1api.ConfigMapList{}
		require.NoError(t, c.List(t.Context(), orphans, client.MatchingLabels{retainedsnapshot.OrphanLabel: "true"}))
		require.Len(t, orphans.Items, 1)
		assert.Contains(t, orphans.Items[0].Data, string(backup.UID)+".foo-du")
		err := c.Get(t.Context(), client.ObjectKeyFromObject(shard), &corev1api.ConfigMap{})
		assert.True(t, apierrors.IsNotFound(err), "the shard is removed after the move")
	})
}

// TestRetainedSnapshotControllerRetriggersItself proves the convergence of a
// multi-shard family: a reconcile that finishes its own shard while a sibling
// shard still has pending work re-enqueues itself with a requeue instead of
// waking the request, so the deletion converges one bounded cycle at a time
// without relying on a further write to trigger the next reconcile; the last
// shard to empty wakes the request.
func TestRetainedSnapshotControllerRetriggersItself(t *testing.T) {
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true, "another-snapshot": true}}
	backup := retainedTestBackup()
	c := backend.client(t, backup)

	shardA := retainedTestFamily(t, c, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {CSISnapshotHandle: retainedTestHandle, Driver: retainedTestDriver, Trusted: true},
	})
	dbr := retainedTestRequest(t, c, backup)
	// A sibling shard the gather split the family into, with its own pending
	// entry, activated like the first.
	siblingEntry, err := json.Marshal(&retainedsnapshot.Entry{CSISnapshotHandle: "another-snapshot", Driver: retainedTestDriver, Trusted: true})
	require.NoError(t, err)
	shardB := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      retainedsnapshot.FamilyNamePrefix(string(backup.UID)) + "1",
			Namespace: backup.Namespace,
			Labels:    retainedsnapshot.FamilyLabels(backup),
		},
		Data: map[string]string{
			retainedsnapshot.ActiveKey: "true",
			"bar-du":                   string(siblingEntry),
		},
	}
	require.NoError(t, c.Create(t.Context(), shardB))

	r := newRetainedTestReconciler(c)

	// Reconciling the first shard deletes its own snapshot but leaves the
	// sibling pending: the controller re-enqueues itself rather than waking
	// the request early or stalling until an external write re-triggers it.
	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: shardA.Namespace, Name: shardA.Name}})
	require.NoError(t, err)
	assert.Equal(t, csi.RetainedSnapshotDeletionTimeout, result.RequeueAfter,
		"a reconcile with pending work left in the family must re-enqueue itself")
	assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)
	assert.Empty(t, getRequest(t, c, dbr).Annotations[velerov1api.RetainedSnapshotsWakeAnnotation],
		"the request must not be woken while the sibling shard is pending")

	// The self-requeue reconciles the sibling shard, empties the family and
	// wakes the request.
	result, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: shardB.Namespace, Name: shardB.Name}})
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter, "an emptied family needs no further requeue")
	assert.Equal(t, []string{retainedTestHandle, "another-snapshot"}, backend.deleteCallsTo)
	assert.NotEmpty(t, getRequest(t, c, dbr).Annotations[velerov1api.RetainedSnapshotsWakeAnnotation])
}

// TestBackupDeletionHandsOffToRetainedSnapshotController proves the handoff of
// section 4: the request's snapshot step annotates the request, activates the
// record family and returns, leaving the request InProgress without waiting;
// the re-entry clears its own annotation and runs the tail only when nothing
// is active.
func TestBackupDeletionHandsOffToRetainedSnapshotController(t *testing.T) {
	backend := &fakeSnapshotBackend{snapshots: map[string]bool{retainedTestHandle: true}}
	backup := retainedTestBackup()
	backup.Status.Phase = velerov1api.BackupPhaseDeleting
	location := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Provider("objStoreProvider").Bucket("bucket").Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result()

	du := builder.ForDataUpload(velerov1api.DefaultNamespace, "foo-du").
		Labels(map[string]string{velerov1api.BackupNameLabel: "foo"}).
		SnapshotType(velerov2alpha1api.SnapshotTypeCSI).
		SourceNamespace("app").
		SourcePVC("data").
		DataMover("velero-block").
		Phase(velerov2alpha1api.DataUploadPhaseCompleted).
		Result()
	du.Status.RetainedCSIStorageSnapshot = &velerov2alpha1api.RetainedCSIStorageSnapshot{
		CSISnapshotHandle: retainedTestHandle,
		Driver:            retainedTestDriver,
	}

	dbr := defaultTestDbr()
	td := setupBackupDeletionControllerTest(t, dbr)
	// Everything the deletion touches lives on the client with the fake CSI
	// backend, including the request itself.
	c := backend.client(t, backup, location, du, dbr)
	td.controller.Client = c

	pluginManager := &pluginmocks.Manager{}
	pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{}, nil)
	pluginManager.On("CleanupClients")
	td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }
	td.backupStore.On("GetBackupVolumeSnapshots", dbr.Spec.BackupName).Return(nil, nil)
	td.backupStore.On("DeleteBackup", dbr.Spec.BackupName).Return(nil)

	// First pass: the deletion runs the earlier steps, then hands off.
	_, err := td.controller.Reconcile(t.Context(), td.req)
	require.NoError(t, err)

	res := getRequest(t, c, dbr)
	assert.Equal(t, velerov1api.DeleteBackupRequestPhaseInProgress, res.Status.Phase,
		"the request waits instead of blocking on the snapshot deletion")
	assert.NotEmpty(t, res.Annotations[velerov1api.RetainedSnapshotsPendingAnnotation])
	td.backupStore.AssertNotCalled(t, "DeleteBackup", mock.Anything)

	family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.True(t, family.HasPendingWork(), "the family is activated with the pending record")

	// The local DataUpload was deleted by the earlier step; the record
	// survives in the family.
	err = c.Get(t.Context(), types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, &velerov2alpha1api.DataUpload{})
	assert.True(t, apierrors.IsNotFound(err))

	// The retained-snapshot controller deletes the snapshot and wakes the
	// request.
	require.Len(t, family.Shards, 1)
	reconcileShard(t, newRetainedTestReconciler(c), family.Shards[0])
	assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)

	// Re-entry: the request clears its own annotation and runs the tail in
	// the same reconcile.
	_, err = td.controller.Reconcile(t.Context(), td.req)
	require.NoError(t, err)

	// The tail processed the deletion: the tarball is removed and every
	// DeleteBackupRequest of the backup, this one included, is deleted.
	td.backupStore.AssertCalled(t, "DeleteBackup", dbr.Spec.BackupName)
	err = c.Get(t.Context(), client.ObjectKeyFromObject(dbr), &velerov1api.DeleteBackupRequest{})
	assert.True(t, apierrors.IsNotFound(err), "the request is deleted with the backup, got %v", err)

	// The tail removed the family itself.
	family, err = retainedsnapshot.LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.Empty(t, family.Shards)
}

// TestBackupDeletionKeepsSnapshotWhenUnrecordedHandleCantBeRead proves the
// pre-rollback recovery rule: if the tag cannot be read, the repository data
// is kept and the backup deletion fails, so a retry can read it.
func TestBackupDeletionKeepsSnapshotWhenUnrecordedHandleCantBeRead(t *testing.T) {
	backup := retainedTestBackup()
	location := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Provider("objStoreProvider").Bucket("bucket").Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result()

	// The delete action gathered an unrecorded entry from the tarball.
	require.NoError(t, retainedsnapshot.WriteEntries(t.Context(), velerotest.NewFakeControllerRuntimeClient(t), backup, nil))

	dbr := defaultTestDbr()
	td := setupBackupDeletionControllerTest(t, dbr, backup, location)
	td.controller.repoMgr = repomocks.NewManager(t)

	// The repository read fails.
	originalTags := getRepoSnapshotTagsFunc
	t.Cleanup(func() { getRepoSnapshotTagsFunc = originalTags })
	getRepoSnapshotTagsFunc = func(context.Context, *repository.Ensurer, repomanager.Manager, *velerov1api.Backup, repotypes.SnapshotIdentifier) (map[string]string, error) {
		return nil, errors.New("fake-repo-error")
	}

	// Write the family with an unrecorded entry on the test client.
	require.NoError(t, retainedsnapshot.WriteEntries(t.Context(), td.fakeClient, backup, map[string]*retainedsnapshot.Entry{
		"foo-du": {
			Driver:  retainedTestDriver,
			Trusted: false,
			Snapshot: &repotypes.SnapshotIdentifier{
				SnapshotID:      "kopia-1",
				VolumeNamespace: "app",
				RepositoryType:  "kopia",
			},
		},
	}))

	pluginManager := &pluginmocks.Manager{}
	pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{}, nil)
	pluginManager.On("CleanupClients")
	td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }
	td.backupStore.On("GetBackupVolumeSnapshots", dbr.Spec.BackupName).Return(nil, nil)

	_, err := td.controller.Reconcile(t.Context(), td.req)
	require.NoError(t, err)

	res := getRequest(t, td.fakeClient, dbr)
	assert.Equal(t, velerov1api.DeleteBackupRequestPhaseProcessed, res.Status.Phase)
	assert.Contains(t, strings.Join(res.Status.Errors, "\n"), "error reading the retained snapshot handle from the snapshot data")
	td.backupStore.AssertNotCalled(t, "DeleteBackup", mock.Anything)
}

// TestResolveRetainedSnapshotHandles proves the tag resolution: the handle is
// read from the cbt-change-id tag of the repository snapshot into the entry,
// and a repository snapshot that is gone or has no tag drops the record.
func TestResolveRetainedSnapshotHandles(t *testing.T) {
	tests := []struct {
		name        string
		tags        map[string]string
		tagsErr     error
		wantHandle  string
		wantDropped bool
		wantErr     bool
	}{
		{
			name:       "the handle is read from the cbt-change-id tag",
			tags:       map[string]string{uploader.CBTChangeIDTag: "snap-handle"},
			wantHandle: "snap-handle",
		},
		{
			name:        "a repository snapshot that is gone drops the record",
			tagsErr:     udmrepo.SnapshotNotFound(errors.New("snapshot not found")),
			wantDropped: true,
		},
		{
			name:        "a repository snapshot without the tag drops the record",
			tags:        map[string]string{},
			wantDropped: true,
		},
		{
			name:    "an unreadable repository fails the deletion so a retry can read it",
			tagsErr: errors.New("fake-repo-error"),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backup := retainedTestBackup()
			c := velerotest.NewFakeControllerRuntimeClient(t)
			require.NoError(t, retainedsnapshot.WriteEntries(t.Context(), c, backup, map[string]*retainedsnapshot.Entry{
				"foo-du": {
					Driver:  retainedTestDriver,
					Trusted: false,
					Snapshot: &repotypes.SnapshotIdentifier{
						SnapshotID:      "kopia-1",
						VolumeNamespace: "app",
						RepositoryType:  "kopia",
					},
				},
			}))

			looked := ""
			originalTags := getRepoSnapshotTagsFunc
			t.Cleanup(func() { getRepoSnapshotTagsFunc = originalTags })
			getRepoSnapshotTagsFunc = func(_ context.Context, _ *repository.Ensurer, _ repomanager.Manager, _ *velerov1api.Backup, snapshot repotypes.SnapshotIdentifier) (map[string]string, error) {
				looked = snapshot.SnapshotID
				return tc.tags, tc.tagsErr
			}

			r := &backupDeletionReconciler{Client: c, logger: velerotest.NewLogger(), repoMgr: repomocks.NewManager(t), repoEnsurer: repository.NewEnsurer(c, velerotest.NewLogger(), time.Hour)}
			errs := r.resolveRetainedSnapshotHandles(t.Context(), backup, velerotest.NewLogger())

			assert.Equal(t, "kopia-1", looked)
			if tc.wantErr {
				require.Len(t, errs, 1)
				return
			}
			assert.Empty(t, errs)
			family, err := retainedsnapshot.LoadFamily(t.Context(), c, backup)
			require.NoError(t, err)
			if tc.wantDropped {
				assert.Zero(t, family.PendingEntries())
				return
			}
			entry, ok := family.Entry("foo-du")
			require.True(t, ok)
			assert.Equal(t, tc.wantHandle, entry.CSISnapshotHandle)
		})
	}
}
