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
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/datamover"
	"github.com/velero-io/velero/pkg/plugin/velero"
	repomocks "github.com/velero-io/velero/pkg/repository/mocks"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/uploader"
	"github.com/velero-io/velero/pkg/util/csi"
)

const (
	lifecycleDriver = "rbd.csi.ceph.com"
	lifecycleHandle = "0001-0009-rook-ceph-0000000000000001-snap"
)

// fakeCSIBackend plays the CSI snapshot controller, the CSI snapshotter and the
// storage, following external-snapshotter v8.6.0 for a statically provisioned
// VolumeSnapshotContent:
//   - The snapshotter sets status.snapshotHandle once it has found the snapshot in
//     the storage, or status.error if it can't find it. It does so on the
//     statusAfterGets-th read of the VSC, to model a slow first reconcile.
//   - When the VSC is deleted, the snapshotter calls DeleteSnapshot only if the
//     status has the snapshot handle, and then removes the finalizer.
type fakeCSIBackend struct {
	snapshots       map[string]bool
	statusAfterGets int
	deleteCallsTo   []string
	gets            map[string]int
}

func (b *fakeCSIBackend) client(t *testing.T, objs ...runtime.Object) client.Client {
	t.Helper()
	b.gets = map[string]int{}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)
	return interceptor.NewClient(fakeClient.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			vsc, ok := obj.(*snapshotv1api.VolumeSnapshotContent)
			if !ok || vsc.Status != nil || vsc.Spec.Source.SnapshotHandle == nil {
				return nil
			}
			b.gets[key.Name]++
			if b.gets[key.Name] < b.statusAfterGets {
				return nil
			}
			if b.snapshots[*vsc.Spec.Source.SnapshotHandle] {
				vsc.Status = &snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: vsc.Spec.Source.SnapshotHandle}
			} else {
				msg := "can not find snapshot for snapshotID " + *vsc.Spec.Source.SnapshotHandle
				vsc.Status = &snapshotv1api.VolumeSnapshotContentStatus{Error: &snapshotv1api.VolumeSnapshotError{Message: &msg}}
			}
			return c.Update(ctx, vsc)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*snapshotv1api.VolumeSnapshotContent); !ok {
				return nil
			}
			vsc := &snapshotv1api.VolumeSnapshotContent{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), vsc); err != nil {
				return client.IgnoreNotFound(err)
			}
			if vsc.Spec.DeletionPolicy == snapshotv1api.VolumeSnapshotContentDelete && vsc.Status != nil && vsc.Status.SnapshotHandle != nil {
				b.deleteCallsTo = append(b.deleteCallsTo, *vsc.Status.SnapshotHandle)
				delete(b.snapshots, *vsc.Status.SnapshotHandle)
			}
			vsc.Finalizers = nil
			return c.Update(ctx, vsc)
		},
	})
}

func lifecycleBackupVSC(policy snapshotv1api.DeletionPolicy) *snapshotv1api.VolumeSnapshotContent {
	handle := lifecycleHandle
	return &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo-du",
			Annotations: map[string]string{
				csi.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csi.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy: policy,
			Driver:         lifecycleDriver,
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &handle},
	}
}

func lifecycleDataUpload(retained *velerov2alpha1api.RetainedSnapshot) *velerov2alpha1api.DataUpload {
	du := builder.ForDataUpload(velerov1api.DefaultNamespace, "foo-du").
		Labels(map[string]string{velerov1api.BackupNameLabel: "foo"}).
		SnapshotType(velerov2alpha1api.SnapshotTypeCSI).
		SourceNamespace("app").
		SourcePVC("data").
		DataMover("velero-block").
		Phase(velerov2alpha1api.DataUploadPhaseCompleted).
		SnapshotID("kopia-snapshot-1").
		Result()
	du.Status.RetainedSnapshot = retained
	return du
}

// executeDataUploadDeleteAction runs the DataUpload DeleteItemAction for the
// DataUpload as it is stored in the backup tarball.
func executeDataUploadDeleteAction(t *testing.T, c client.Client, backup *velerov1api.Backup, du *velerov2alpha1api.DataUpload) {
	t.Helper()
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(du)
	require.NoError(t, err)
	require.NoError(t, datamover.NewDataUploadDeleteAction(velerotest.NewLogger(), c).Execute(&velero.DeleteItemActionExecuteInput{
		Item:   &unstructured.Unstructured{Object: content},
		Backup: backup,
	}))
}

// shortenTempVSCStatusWait keeps the real wait for the temp VSC status, with a
// shorter timeout.
func shortenTempVSCStatusWait(t *testing.T) {
	t.Helper()
	original := csi.WaitTempVSCStatus
	t.Cleanup(func() { csi.WaitTempVSCStatus = original })
	csi.WaitTempVSCStatus = func(ctx context.Context, c client.Client, vsc *snapshotv1api.VolumeSnapshotContent, _ time.Duration, log logrus.FieldLogger) error {
		return original(ctx, c, vsc, 1500*time.Millisecond, log)
	}
}

// TestRetainedSnapshotLifecycle follows a snapshot from the end of the data
// movement to the backup deletion: the node-agent records the snapshot of a
// completed DataUpload, the DataUpload DeleteItemAction passes it on, and the
// backup deletion has the CSI driver delete it from the storage.
func TestRetainedSnapshotLifecycle(t *testing.T) {
	tests := []struct {
		name          string
		policy        snapshotv1api.DeletionPolicy
		wantRecorded  bool
		wantDeleteRPC []string
		// statusAfterGets delays the snapshotter's first reconcile of the temp VSC.
		statusAfterGets int
	}{
		{
			name:          "Retain: the snapshot is kept after the backup and deleted from the storage with the backup",
			policy:        snapshotv1api.VolumeSnapshotContentRetain,
			wantRecorded:  true,
			wantDeleteRPC: []string{lifecycleHandle},
		},
		{
			// Deleting the temp VSC before the snapshotter sets its status would
			// remove it without calling DeleteSnapshot.
			name:            "Retain: the snapshot is deleted when the snapshotter is slow to reconcile the temp VSC",
			policy:          snapshotv1api.VolumeSnapshotContentRetain,
			wantRecorded:    true,
			wantDeleteRPC:   []string{lifecycleHandle},
			statusAfterGets: 2,
		},
		{
			// The CSI driver deletes the snapshot when the node-agent cleans up
			// the backup VolumeSnapshotContent, so nothing is left to delete.
			name:   "Delete: nothing is recorded and the backup deletion doesn't touch the storage",
			policy: snapshotv1api.VolumeSnapshotContentDelete,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shortenTempVSCStatusWait(t)
			backend := &fakeCSIBackend{snapshots: map[string]bool{lifecycleHandle: true, "snapshot-of-another-backup": true}, statusAfterGets: tc.statusAfterGets}
			c := backend.client(t)
			backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()

			// The node-agent records the snapshot when the DataUpload completes.
			retained := csi.GetRetainedSnapshot(lifecycleBackupVSC(tc.policy))
			assert.Equal(t, tc.wantRecorded, retained != nil)

			// The backup is deleted.
			executeDataUploadDeleteAction(t, c, backup, lifecycleDataUpload(retained))
			r := &backupDeletionReconciler{Client: c, logger: velerotest.NewLogger()}
			assert.Empty(t, r.deleteRetainedSnapshots(t.Context(), backup, velerotest.NewLogger()))

			assert.Equal(t, tc.wantDeleteRPC, backend.deleteCallsTo)
			assert.Equal(t, !tc.wantRecorded, backend.snapshots[lifecycleHandle], "snapshot of the deleted backup in the storage")
			assert.True(t, backend.snapshots["snapshot-of-another-backup"], "snapshots of other backups must stay")

			vscs := &snapshotv1api.VolumeSnapshotContentList{}
			require.NoError(t, c.List(t.Context(), vscs))
			assert.Empty(t, vscs.Items)
			cms := &corev1api.ConfigMapList{}
			require.NoError(t, c.List(t.Context(), cms, client.MatchingLabels{velerov1api.DataUploadRetainedSnapshotLabel: "true"}))
			assert.Empty(t, cms.Items)
		})
	}
}

// TestRetainedSnapshotDeletionIdempotent checks that the retained snapshot
// deletion succeeds however much of it an earlier attempt already did.
func TestRetainedSnapshotDeletionIdempotent(t *testing.T) {
	retained := &velerov2alpha1api.RetainedSnapshot{SnapshotHandle: lifecycleHandle, Driver: lifecycleDriver}
	sum := sha256.Sum256([]byte(lifecycleDriver + "/" + lifecycleHandle))
	tempVSCName := "vsc-" + hex.EncodeToString(sum[:16])

	tests := []struct {
		name string
		// retained is the DataUpload's status.retainedSnapshot in the backup tarball.
		retained *velerov2alpha1api.RetainedSnapshot
		// snapshotInStorage is whether the storage still has the snapshot.
		snapshotInStorage bool
		// tempVSCLeft is whether an interrupted attempt left the temp VSC.
		tempVSCLeft bool
		// skipDeleteAction leaves out the DeleteItemAction, so no configmap records the snapshot.
		skipDeleteAction bool
		attempts         int
		wantDeleteRPC    []string
	}{
		{
			// The second attempt creates the temp VSC again. The snapshotter can't
			// find the snapshot, so it removes the VSC without calling DeleteSnapshot.
			name:              "deleting again after a successful deletion",
			retained:          retained,
			snapshotInStorage: true,
			attempts:          2,
			wantDeleteRPC:     []string{lifecycleHandle},
		},
		{
			name:     "snapshot already gone from the storage",
			retained: retained,
			attempts: 1,
		},
		{
			name:              "temp VSC left by an interrupted attempt",
			retained:          retained,
			snapshotInStorage: true,
			tempVSCLeft:       true,
			attempts:          1,
			wantDeleteRPC:     []string{lifecycleHandle},
		},
		{
			name:              "no configmap records the snapshot",
			retained:          retained,
			snapshotInStorage: true,
			skipDeleteAction:  true,
			attempts:          1,
		},
		{
			name:     "DataUpload without retainedSnapshot",
			attempts: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shortenTempVSCStatusWait(t)
			backend := &fakeCSIBackend{snapshots: map[string]bool{lifecycleHandle: tc.snapshotInStorage}}
			var objs []runtime.Object
			if tc.tempVSCLeft {
				handle := lifecycleHandle
				objs = append(objs, &snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{Name: tempVSCName, Finalizers: []string{csi.VSCBoundProtectionFinalizer}},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
						Driver:         lifecycleDriver,
						Source:         snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: &handle},
					},
				})
			}
			c := backend.client(t, objs...)
			backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()
			r := &backupDeletionReconciler{Client: c, logger: velerotest.NewLogger()}

			for i := 0; i < tc.attempts; i++ {
				if !tc.skipDeleteAction {
					executeDataUploadDeleteAction(t, c, backup, lifecycleDataUpload(tc.retained))
				}
				assert.Empty(t, r.deleteRetainedSnapshots(t.Context(), backup, velerotest.NewLogger()), "attempt %d", i+1)
			}

			assert.Equal(t, tc.wantDeleteRPC, backend.deleteCallsTo)
			vscs := &snapshotv1api.VolumeSnapshotContentList{}
			require.NoError(t, c.List(t.Context(), vscs))
			assert.Empty(t, vscs.Items)
			cms := &corev1api.ConfigMapList{}
			require.NoError(t, c.List(t.Context(), cms, client.MatchingLabels{velerov1api.DataUploadRetainedSnapshotLabel: "true"}))
			assert.Empty(t, cms.Items)
		})
	}
}

// TestUnrecordedRetainedSnapshotLifecycle deletes the retained snapshot of a backup
// taken before Velero recorded retained snapshots. The DataUpload has no record,
// so the handle comes from the CBT change ID tag of the repository snapshot.
func TestUnrecordedRetainedSnapshotLifecycle(t *testing.T) {
	tests := []struct {
		name              string
		classPolicy       snapshotv1api.DeletionPolicy
		snapshotInStorage bool
		wantDeleteRPC     []string
	}{
		{
			name:              "Retain class: the snapshot is deleted with the backup",
			classPolicy:       snapshotv1api.VolumeSnapshotContentRetain,
			snapshotInStorage: true,
			wantDeleteRPC:     []string{lifecycleHandle},
		},
		{
			// The snapshotter can't find the snapshot, so it removes the temp VSC
			// without calling DeleteSnapshot, and the deletion still succeeds.
			name:        "Retain class, snapshot already gone from the storage",
			classPolicy: snapshotv1api.VolumeSnapshotContentRetain,
		},
		{
			// The backup didn't keep the snapshot, so there is nothing to delete.
			name:              "Delete class",
			classPolicy:       snapshotv1api.VolumeSnapshotContentDelete,
			snapshotInStorage: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shortenTempVSCStatusWait(t)
			stubRepoSnapshotTags(t, map[string]string{uploader.CBTChangeIDTag: lifecycleHandle}, nil)
			backend := &fakeCSIBackend{snapshots: map[string]bool{lifecycleHandle: tc.snapshotInStorage, "snapshot-of-another-backup": true}}
			class := &snapshotv1api.VolumeSnapshotClass{
				ObjectMeta:     metav1.ObjectMeta{Name: "rbd-class"},
				Driver:         lifecycleDriver,
				DeletionPolicy: tc.classPolicy,
			}
			c := backend.client(t, class)
			backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()

			du := lifecycleDataUpload(nil)
			du.Spec.CSISnapshot = &velerov2alpha1api.CSISnapshotSpec{Driver: lifecycleDriver, SnapshotClass: "rbd-class"}
			executeDataUploadDeleteAction(t, c, backup, du)

			r := &backupDeletionReconciler{Client: c, logger: velerotest.NewLogger(), repoMgr: repomocks.NewManager(t)}
			assert.Empty(t, r.resolveUnrecordedRetainedSnapshots(t.Context(), backup, velerotest.NewLogger()))
			assert.Empty(t, r.deleteRetainedSnapshots(t.Context(), backup, velerotest.NewLogger()))

			assert.Equal(t, tc.wantDeleteRPC, backend.deleteCallsTo)
			assert.True(t, backend.snapshots["snapshot-of-another-backup"], "snapshots of other backups must stay")
			vscs := &snapshotv1api.VolumeSnapshotContentList{}
			require.NoError(t, c.List(t.Context(), vscs))
			assert.Empty(t, vscs.Items)
			cms := &corev1api.ConfigMapList{}
			require.NoError(t, c.List(t.Context(), cms, client.MatchingLabels{velerov1api.DataUploadRetainedSnapshotLabel: "true"}))
			assert.Empty(t, cms.Items)
		})
	}
}
