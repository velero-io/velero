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
	snapshotv1fake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/typed/volumesnapshot/v1/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgofake "k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	testclocks "k8s.io/utils/clock/testing"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	ctrl "sigs.k8s.io/controller-runtime"

	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/datapath"
	"github.com/velero-io/velero/pkg/exposer"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util/csi"
)

const (
	retentionHandle = "0001-0009-rook-ceph-0000000000000001-snap"
	retentionDriver = "rbd.csi.ceph.com"
)

// retentionDataUploadBuilder returns a DataUpload that opted into base snapshot
// retention through the volume policy, with the decision carried on
// spec.dataMoverConfig.
func retentionDataUploadBuilder() *builder.DataUploadBuilder {
	return dataUploadBuilder().
		DataMover("velero-block").
		DataMoverConfig(map[string]string{velerov2alpha1api.RetainSnapshotDataMoverConfigKey: "true"})
}

// retentionBackupVSC returns the backup VolumeSnapshotContent the exposer
// creates for the DataUpload: named after it, statically provisioned from the
// source snapshot handle, with the deletion secret annotations the CSI
// snapshot controller sets.
func retentionBackupVSC() *snapshotv1api.VolumeSnapshotContent {
	handle := retentionHandle
	return &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: dataUploadName,
			Annotations: map[string]string{
				csi.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csi.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
			ResourceVersion: "42",
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
			Driver:         retentionDriver,
			Source: snapshotv1api.VolumeSnapshotContentSource{
				SnapshotHandle: &handle,
			},
		},
	}
}

func retentionRecord() *velerov2alpha1api.RetainedCSIStorageSnapshot {
	return &velerov2alpha1api.RetainedCSIStorageSnapshot{
		CSISnapshotHandle: retentionHandle,
		Driver:            retentionDriver,
		DeletionSecretRef: &corev1api.SecretReference{
			Name:      "rook-csi-rbd-provisioner",
			Namespace: "rook-ceph",
		},
	}
}

// pruningDataUploadClient simulates a cluster whose DataUpload CRD predates
// the retainedCSIStorageSnapshot field: the API server prunes it on write and
// the update still reports success.
type pruningDataUploadClient struct {
	kbclient.Client
}

func (c *pruningDataUploadClient) Update(ctx context.Context, obj kbclient.Object, opts ...kbclient.UpdateOption) error {
	if du, ok := obj.(*velerov2alpha1api.DataUpload); ok {
		du.Status.RetainedCSIStorageSnapshot = nil
	}
	return c.Client.Update(ctx, obj, opts...)
}

// vscPatchRecorder records the payloads of the VolumeSnapshotContent patches.
type vscPatchRecorder struct {
	patches []string
}

func (p *vscPatchRecorder) hasDeletionPolicy(policy string) bool {
	for _, patch := range p.patches {
		var payload map[string]any
		if err := json.Unmarshal([]byte(patch), &payload); err != nil {
			continue
		}
		spec, _ := payload["spec"].(map[string]any)
		if spec != nil && spec["deletionPolicy"] == policy {
			return true
		}
	}
	return false
}

func createRetainedSnapshotObjects(t *testing.T, r *DataUploadReconciler, du *velerov2alpha1api.DataUpload, vsc *snapshotv1api.VolumeSnapshotContent) {
	t.Helper()
	ctx := t.Context()
	require.NoError(t, r.client.Create(ctx, du))
	if vsc != nil {
		_, err := r.csiSnapshotClient.VolumeSnapshotContents().Create(ctx, vsc, metav1.CreateOptions{})
		require.NoError(t, err)
	}
}

func getDataUpload(t *testing.T, r *DataUploadReconciler, du *velerov2alpha1api.DataUpload) *velerov2alpha1api.DataUpload {
	t.Helper()
	current := &velerov2alpha1api.DataUpload{}
	require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, current))
	return current
}

func getBackupVSC(t *testing.T, r *DataUploadReconciler, du *velerov2alpha1api.DataUpload) (*snapshotv1api.VolumeSnapshotContent, error) {
	t.Helper()
	return r.csiSnapshotClient.VolumeSnapshotContents().Get(t.Context(), du.Name, metav1.GetOptions{})
}

// TestOnDataUploadCompletedRetentionRecordBeforeRetain proves the ordering
// rule of section 2 of the design: the record is persisted on the DataUpload
// before the backup VolumeSnapshotContent is switched to Retain, and the
// switch only happens when the uncached read-back confirms the record. A
// cluster whose CRD prunes the field must keep the Delete policy.
func TestOnDataUploadCompletedRetentionRecordBeforeRetain(t *testing.T) {
	tests := []struct {
		name             string
		pruneRecord      bool
		wantRetained     bool
		wantPhase        velerov2alpha1api.DataUploadPhase
		wantRecordOnFail bool
	}{
		{
			name:         "the record is verified and the content is switched to Retain",
			wantRetained: true,
			wantPhase:    velerov2alpha1api.DataUploadPhaseCompleted,
		},
		{
			// The update reports success but the field comes back empty: the
			// read-back, not the API response, is the proof. The DataUpload
			// fails and the content keeps Delete.
			name:        "a CRD that prunes the record fails the DataUpload and keeps Delete",
			pruneRecord: true,
			wantPhase:   velerov2alpha1api.DataUploadPhaseFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := initDataUploaderReconciler()
			require.NoError(t, err)

			du := retentionDataUploadBuilder().Result()
			if tc.pruneRecord {
				r.client = &pruningDataUploadClient{Client: r.client}
			}
			createRetainedSnapshotObjects(t, r, du, retentionBackupVSC())

			// The switch to Retain happens only after the record is read back.
			patches := &vscPatchRecorder{}
			r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
				patches.patches = append(patches.patches, string(action.(clientTesting.PatchAction).GetPatch()))
				if action.(clientTesting.PatchAction).GetName() == dataUploadName {
					current := getDataUpload(t, r, du)
					if tc.wantRetained {
						// Persisted before retained.
						require.NotNil(t, current.Status.RetainedCSIStorageSnapshot, "the record must be persisted before the Retain patch")
						require.Equal(t, retentionHandle, current.Status.RetainedCSIStorageSnapshot.CSISnapshotHandle)
					}
				}
				return false, nil, nil
			})
			r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{
				velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger()),
			}

			r.OnDataUploadCompleted(t.Context(), du.Namespace, du.Name, datapath.Result{Backup: datapath.BackupResult{SnapshotID: "fake-id"}})

			updated := getDataUpload(t, r, du)
			assert.Equal(t, tc.wantPhase, updated.Status.Phase)
			if tc.wantRetained {
				assert.Equal(t, retentionRecord(), updated.Status.RetainedCSIStorageSnapshot)
				assert.True(t, patches.hasDeletionPolicy("Retain"), "the backup VSC must be switched to Retain, patches: %v", patches.patches)
				// The retention-path cleanup deletes the content explicitly.
				_, err := getBackupVSC(t, r, du)
				assert.True(t, apierrors.IsNotFound(err), "the retained backup VSC must be deleted, got %v", err)
			} else {
				assert.Nil(t, updated.Status.RetainedCSIStorageSnapshot)
				assert.False(t, patches.hasDeletionPolicy("Retain"), "the backup VSC must keep Delete when the record did not persist, patches: %v", patches.patches)
				// The content keeps the Delete policy, so the exposer cleanup
				// reclaims the snapshot through the VolumeSnapshot deletion
				// cascade.
				vsc, getErr := getBackupVSC(t, r, du)
				if getErr == nil {
					assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, vsc.Spec.DeletionPolicy)
				} else {
					assert.True(t, apierrors.IsNotFound(getErr))
				}
			}
		})
	}
}

// TestRetainSnapshotOnCompletionLeaseFencing proves the lease fence of section
// 3: the rollback path cannot run while an unexpired retaining mark exists,
// and the completion callback cannot retain while a rollback is in progress.
func TestRetainSnapshotOnCompletionLeaseFencing(t *testing.T) {
	tests := []struct {
		name         string
		annotation   string
		future       bool
		wantRetained bool
	}{
		{
			name:         "an unexpired retaining lease blocks the completion callback",
			annotation:   dataUploadRetainLeaseAnnotation,
			future:       true,
			wantRetained: false,
		},
		{
			name:         "an expired retaining lease does not block",
			annotation:   dataUploadRetainLeaseAnnotation,
			wantRetained: true,
		},
		{
			name:         "an unexpired rollback lease blocks the completion callback",
			annotation:   dataUploadRollbackLeaseAnnotation,
			future:       true,
			wantRetained: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := initDataUploaderReconciler()
			require.NoError(t, err)
			// The lease expiry is evaluated against the reconciler's clock.
			offset := -10 * time.Minute
			if tc.future {
				offset = 10 * time.Minute
			}
			lease := (&dataUploadLease{Holder: "other-node-1", ExpiresAt: r.Clock.Now().Add(offset)}).String()

			du := retentionDataUploadBuilder().Annotations(map[string]string{tc.annotation: lease}).Result()
			createRetainedSnapshotObjects(t, r, du, retentionBackupVSC())

			patches := &vscPatchRecorder{}
			r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
				patches.patches = append(patches.patches, string(action.(clientTesting.PatchAction).GetPatch()))
				return false, nil, nil
			})
			r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{
				velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger()),
			}

			retainErr := r.retainSnapshotOnCompletion(t.Context(), du, velerotest.NewLogger())

			updated := getDataUpload(t, r, du)
			if tc.wantRetained {
				require.NoError(t, retainErr)
				assert.Equal(t, retentionRecord(), updated.Status.RetainedCSIStorageSnapshot)
				assert.True(t, patches.hasDeletionPolicy("Retain"))
				return
			}
			require.Error(t, retainErr)
			assert.Nil(t, updated.Status.RetainedCSIStorageSnapshot)
			assert.False(t, patches.hasDeletionPolicy("Retain"), "the content must keep Delete when the callback is fenced out")
		})
	}
}

// TestRetainSnapshotOnCompletionPatchPrecondition proves that the Retain patch
// carries the content's resourceVersion, so a rollback that has patched or
// deleted the content in between makes the delayed write fail instead of
// landing after it.
func TestRetainSnapshotOnCompletionPatchPrecondition(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Result()
	createRetainedSnapshotObjects(t, r, du, retentionBackupVSC())

	var patchPayloads []map[string]any
	r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		payload := map[string]any{}
		if err := json.Unmarshal(action.(clientTesting.PatchAction).GetPatch(), &payload); err == nil {
			patchPayloads = append(patchPayloads, payload)
		}
		return false, nil, nil
	})

	require.NoError(t, r.retainSnapshotOnCompletion(t.Context(), du, velerotest.NewLogger()))

	require.Len(t, patchPayloads, 1)
	assert.Equal(t, "42", patchPayloads[0]["resourceVersion"], "the Retain patch must be preconditioned on the content's resourceVersion")
	assert.Equal(t, "Retain", patchPayloads[0]["spec"].(map[string]any)["deletionPolicy"])
}

// TestReleaseRetainedSnapshotOrdering proves the patch-back rule of section 3:
// delete-first, clear-last. The content is patched to Delete before the backup
// VolumeSnapshot and VolumeSnapshotContent are deleted, and the record is
// cleared only after the content is confirmed gone.
func TestReleaseRetainedSnapshotOrdering(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).
		Annotations(map[string]string{}).Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	createRetainedSnapshotObjects(t, r, du, func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC()
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		return vsc
	}())

	// The backup VS and PVC, named after the DataUpload as the exposer does.
	_, err = r.csiSnapshotClient.VolumeSnapshots(du.Namespace).Create(t.Context(), &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: dataUploadName, Namespace: du.Namespace, ResourceVersion: "7"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	pvcClient := r.kubeClient.(*clientgofake.Clientset)
	_, err = pvcClient.CoreV1().PersistentVolumeClaims(du.Namespace).Create(t.Context(), &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: dataUploadName, Namespace: du.Namespace},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	var events []string
	r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("*", "*", func(action clientTesting.Action) (bool, runtime.Object, error) {
		switch a := action.(type) {
		case clientTesting.PatchAction:
			if a.GetResource().Resource == "volumesnapshotcontents" {
				events = append(events, "patch-vsc:"+string(a.GetPatch()))
			}
		case clientTesting.DeleteAction:
			switch a.GetResource().Resource {
			case "volumesnapshots":
				events = append(events, "delete-vs")
			case "volumesnapshotcontents":
				events = append(events, "delete-vsc")
			}
		}
		return false, nil, nil
	})
	pvcClient.PrependReactor("*", "persistentvolumeclaims", func(action clientTesting.Action) (bool, runtime.Object, error) {
		if d, ok := action.(clientTesting.DeleteAction); ok {
			events = append(events, "delete-pvc:"+d.GetName())
		}
		return false, nil, nil
	})

	// Record what the DataUpload carries at the moment the content is deleted:
	// the record must still be there.
	r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("delete", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		current := getDataUpload(t, r, du)
		if current.Status.RetainedCSIStorageSnapshot == nil {
			t.Error("the record must be cleared only after the content is deleted")
		}
		return false, nil, nil
	})

	require.NoError(t, r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger()))

	// Delete-first: the Delete patch precedes the PVC, VS and VSC deletions.
	deletePatchIdx, pvcIdx, vsIdx, vscIdx := -1, -1, -1, -1
	for i, event := range events {
		if deletePatchIdx < 0 && strings.HasPrefix(event, "patch-vsc:") && strings.Contains(event, `"Delete"`) {
			deletePatchIdx = i
		}
		if pvcIdx < 0 && strings.HasPrefix(event, "delete-pvc:") {
			pvcIdx = i
		}
		if vsIdx < 0 && event == "delete-vs" {
			vsIdx = i
		}
		if vscIdx < 0 && event == "delete-vsc" {
			vscIdx = i
		}
	}
	require.GreaterOrEqual(t, deletePatchIdx, 0, "the content must be patched to Delete, events: %v", events)
	require.GreaterOrEqual(t, pvcIdx, 0, "the backup PVC must be deleted, events: %v", events)
	require.GreaterOrEqual(t, vsIdx, 0, "the backup VS must be deleted, events: %v", events)
	require.GreaterOrEqual(t, vscIdx, 0, "the backup VSC must be deleted, events: %v", events)
	assert.Less(t, deletePatchIdx, pvcIdx, "the Delete patch precedes the PVC deletion")
	assert.Less(t, pvcIdx, vsIdx, "the PVC deletion precedes the VS deletion")
	assert.Less(t, vsIdx, vscIdx, "the VS deletion precedes the VSC deletion")

	// Clear-last: the record is gone after the release.
	assert.Nil(t, getDataUpload(t, r, du).Status.RetainedCSIStorageSnapshot)
}

// TestReleaseRetainedSnapshotNotFoundKeepsRecord proves the NotFound rule of
// section 3: a content that is absent, e.g. because the retention-path cleanup
// already deleted it under Retain after a Completed update that failed to
// stick, must not clear the record, or a retained snapshot would be stranded
// with no cleanup record.
func TestReleaseRetainedSnapshotNotFoundKeepsRecord(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	createRetainedSnapshotObjects(t, r, du, nil)

	require.NoError(t, r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger()))
	assert.Equal(t, retentionRecord(), getDataUpload(t, r, du).Status.RetainedCSIStorageSnapshot,
		"the record must be kept when the content is absent")
}

// TestReleaseRetainedSnapshotBlockedByRetainLease proves the other side of the
// fence: the patch-back fails while an unexpired retaining mark exists.
func TestReleaseRetainedSnapshotBlockedByRetainLease(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	lease := &dataUploadLease{Holder: "other-node-1", ExpiresAt: r.Clock.Now().Add(10 * time.Minute)}
	du.Annotations = map[string]string{dataUploadRetainLeaseAnnotation: lease.String()}
	createRetainedSnapshotObjects(t, r, du, func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC()
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		return vsc
	}())

	err = r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retention lease")

	vsc, getErr := getBackupVSC(t, r, du)
	require.NoError(t, getErr)
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentRetain, vsc.Spec.DeletionPolicy,
		"the content must not be touched while the retaining mark is unexpired")
	assert.Equal(t, retentionRecord(), getDataUpload(t, r, du).Status.RetainedCSIStorageSnapshot)
}

// TestReleaseRetainedSnapshotNothingRetained proves the fast path: a DataUpload
// without a record whose content has the Delete policy releases nothing, so
// the failure paths of an ordinary data movement are not slowed down.
func TestReleaseRetainedSnapshotNothingRetained(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := dataUploadBuilder().Result()
	createRetainedSnapshotObjects(t, r, du, retentionBackupVSC())

	var deletions int
	r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("delete", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		deletions++
		return false, nil, nil
	})

	require.NoError(t, r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger()))
	assert.Zero(t, deletions)
}

// TestReconcileReleasesRetainedSnapshotOfUnfinishedDataUpload proves that the
// patch-back is owned by the reconcile and that the node gate is dropped for
// it: a reconciler on another node releases the snapshot of an unfinished
// DataUpload, the case a hard kill of the owning node-agent leaves behind.
func TestReconcileReleasesRetainedSnapshotOfUnfinishedDataUpload(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)
	// This reconciler is not the node the DataUpload was assigned to.
	r.nodeName = "other-node"

	du := retentionDataUploadBuilder().
		Phase(velerov2alpha1api.DataUploadPhaseInProgress).
		Node("dead-node").
		Finalizers([]string{DataUploadDownloadFinalizer}).
		Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	createRetainedSnapshotObjects(t, r, du, func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC()
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		return vsc
	}())
	r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{
		velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger()),
	}

	// The first reconcile adds the finalizer; the second one runs the release.
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: du.Namespace, Name: du.Name}})
	require.NoError(t, err)
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: du.Namespace, Name: du.Name}})
	require.NoError(t, err)

	assert.Nil(t, getDataUpload(t, r, du).Status.RetainedCSIStorageSnapshot,
		"the record must be cleared after the release")
	vsc, getErr := getBackupVSC(t, r, du)
	if getErr == nil {
		// The fake snapshot clientset has no snapshotter running, so the
		// content keeps its finalizer; the Delete policy is what the release
		// controls.
		assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, vsc.Spec.DeletionPolicy)
	} else {
		assert.True(t, apierrors.IsNotFound(getErr))
	}
}

// TestReconcileSkipsReleaseForDataUploadWithoutRecord proves the hook's gate:
// only a DataUpload carrying a retained snapshot record runs the release,
// because the record provably precedes the Retain patch, so it covers every
// retained case. An in-flight CSI DataUpload without a record -- including a
// progress-update-driven reconcile and a file system data mover one -- must
// not pay the release's uncached DataUpload and VolumeSnapshotContent reads.
func TestReconcileSkipsReleaseForDataUploadWithoutRecord(t *testing.T) {
	tests := []struct {
		name   string
		du     *velerov2alpha1api.DataUpload
		cancel bool
	}{
		{
			name: "an in-progress CSI data upload without a record",
			du: retentionDataUploadBuilder().
				Phase(velerov2alpha1api.DataUploadPhaseInProgress).
				Node("node-1").
				Finalizers([]string{DataUploadDownloadFinalizer}).
				Result(),
		},
		{
			name: "a prepared CSI data upload without a record",
			du: retentionDataUploadBuilder().
				Phase(velerov2alpha1api.DataUploadPhasePrepared).
				Node("node-1").
				Finalizers([]string{DataUploadDownloadFinalizer}).
				Result(),
		},
		{
			name: "a canceling CSI data upload without a record",
			du: retentionDataUploadBuilder().
				Phase(velerov2alpha1api.DataUploadPhaseCanceling).
				Node("node-1").
				Finalizers([]string{DataUploadDownloadFinalizer}).
				Result(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := initDataUploaderReconciler()
			require.NoError(t, err)

			createRetainedSnapshotObjects(t, r, tc.du, retentionBackupVSC())

			var vscReads int
			r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("*", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
				if _, ok := action.(clientTesting.GetAction); ok {
					vscReads++
				}
				return false, nil, nil
			})

			// The finalizer is already in place, so one reconcile reaches the hook.
			_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: tc.du.Namespace, Name: tc.du.Name}})
			require.NoError(t, err)

			assert.Zero(t, vscReads, "a DataUpload without a record must not read the VolumeSnapshotContent")
		})
	}
}

// TestReconcileDoesNotReleaseDuringRetentionCleanup proves the lease renewal
// of the completion callback: the retention-path cleanup that follows the
// Retain patch is bounded by the deletion timeout, which outlasts the
// one-minute lease, so at T+1min -- with the callback still inside the
// cleanup and the DataUpload not yet final -- an expired, stealable mark must
// not let the reconcile hook patch the content back to Delete and destroy a
// successfully retained snapshot. Once the renewal expires too, the hook
// steals the mark and the hard-kill recovery keeps working.
func TestReconcileDoesNotReleaseDuringRetentionCleanup(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().
		Phase(velerov2alpha1api.DataUploadPhaseInProgress).
		Node("node-1").
		Finalizers([]string{DataUploadDownloadFinalizer}).
		Result()
	createRetainedSnapshotObjects(t, r, du, retentionBackupVSC())
	r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{
		velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger()),
	}

	// The completion callback persists the record and switches the content to
	// Retain; the lease is renewed to cover the cleanup that follows.
	require.NoError(t, r.retainSnapshotOnCompletion(t.Context(), du, velerotest.NewLogger()))

	// The callback is now inside the retention-path cleanup, bounded by the
	// deletion timeout. Advance the clock past the original one-minute lease
	// expiry, as a progress-update-driven reconcile observes it.
	fakeClock := r.Clock.(*testclocks.FakeClock)
	fakeClock.Step(2 * time.Minute)

	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: du.Namespace, Name: du.Name}})
	require.NoError(t, err)

	vsc, getErr := getBackupVSC(t, r, du)
	require.NoError(t, getErr)
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentRetain, vsc.Spec.DeletionPolicy,
		"the successfully retained snapshot must not be released while the completion callback is still cleaning up")
	assert.NotNil(t, getDataUpload(t, r, du).Status.RetainedCSIStorageSnapshot,
		"the record must survive the interleaving")

	// Past the renewed expiry the mark is stealable again and the hook
	// recovers the hard-kill case: the release proceeds.
	fakeClock.Step(csi.RetainedSnapshotDeletionTimeout + 2*time.Minute)
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: du.Namespace, Name: du.Name}})
	require.NoError(t, err)

	assert.Nil(t, getDataUpload(t, r, du).Status.RetainedCSIStorageSnapshot,
		"the release must proceed once the renewed lease has expired")
	vsc, getErr = getBackupVSC(t, r, du)
	if getErr == nil {
		assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, vsc.Spec.DeletionPolicy)
	} else {
		assert.True(t, apierrors.IsNotFound(getErr))
	}
}

// TestOnDataUploadFailedReleasesRetainedSnapshot proves the failure
// propagation: a DataUpload that fails after the record was persisted carries
// a stale record only until the patch-back clears it after the release.
func TestOnDataUploadFailedReleasesRetainedSnapshot(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	createRetainedSnapshotObjects(t, r, du, func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC()
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		return vsc
	}())
	r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{
		velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger()),
	}

	r.OnDataUploadFailed(t.Context(), du.Namespace, du.Name, errors.New("fake data path failure"))

	updated := getDataUpload(t, r, du)
	assert.Equal(t, velerov2alpha1api.DataUploadPhaseFailed, updated.Status.Phase)
	assert.Nil(t, updated.Status.RetainedCSIStorageSnapshot, "the stale record must be cleared after the release")

	vsc, getErr := getBackupVSC(t, r, du)
	if getErr == nil {
		assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, vsc.Spec.DeletionPolicy,
			"the content must be switched back to Delete so the driver deletes the snapshot")
	} else {
		assert.True(t, apierrors.IsNotFound(getErr))
	}
}

// TestRetainSnapshotOnCompletionStaleResourceVersionConflicts proves that the
// resourceVersion precondition on the Retain patch is real optimistic locking:
// when the content changed between the capture and the patch, the patch fails
// with a conflict instead of landing after the concurrent write, where the
// sidecar would remove the finalizer under Retain with no DeleteSnapshot.
func TestRetainSnapshotOnCompletionStaleResourceVersionConflicts(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Result()
	vsc := retentionBackupVSC() // resourceVersion 42
	createRetainedSnapshotObjects(t, r, du, vsc)

	fakeV1 := r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1)
	// Serve the callback a stale read, as a cached client or a slow request
	// would: the object the callback sees carries resourceVersion 41, while the
	// API server holds 42.
	fakeV1.PrependReactor("get", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		if action.(clientTesting.GetAction).GetName() != dataUploadName {
			return false, nil, nil
		}
		stale := vsc.DeepCopy()
		stale.ResourceVersion = "41"
		return true, stale, nil
	})
	// Enforce the precondition semantics the real API server provides: a merge
	// patch that carries a resourceVersion must match the stored object, which
	// the API server holds at resourceVersion 42.
	storedResourceVersion := "42"
	fakeV1.PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(clientTesting.PatchAction)
		if patchAction.GetName() != dataUploadName {
			return false, nil, nil
		}
		payload := map[string]any{}
		if err := json.Unmarshal(patchAction.GetPatch(), &payload); err != nil {
			return true, nil, err
		}
		if rv, ok := payload["resourceVersion"].(string); ok && rv != storedResourceVersion {
			return true, nil, apierrors.NewConflict(snapshotv1api.Resource("volumesnapshotcontents"), dataUploadName, errors.New("resourceVersion mismatch"))
		}
		return false, nil, nil
	})

	err = r.retainSnapshotOnCompletion(t.Context(), du, velerotest.NewLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error switching the backup VolumeSnapshotContent", "the stale Retain patch must fail")

	// The content keeps its policy; nothing landed.
	current, getErr := getBackupVSC(t, r, du)
	require.NoError(t, getErr)
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, current.Spec.DeletionPolicy,
		"the stale Retain patch must not land")
}

// TestRetainSnapshotOnCompletionFreshResourceVersionAfterRecheck proves the
// capture point of the Retain patch precondition: the resourceVersion is read
// immediately after the lease re-check, not reused from the Get at the top of
// the callback, which predates the lease acquisition, the record persist and
// the read-back -- a window in which the snapshot controllers update the
// content routinely. A stale capture there fails the patch spuriously, which
// fails the DataUpload and degrades the next incremental to a full backup.
func TestRetainSnapshotOnCompletionFreshResourceVersionAfterRecheck(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Result()
	vsc := retentionBackupVSC() // stored at resourceVersion 42
	createRetainedSnapshotObjects(t, r, du, vsc)

	fakeV1 := r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1)
	// Serve the callback a stale first read, as a cached client or a slow
	// request would: the object the callback starts from carries
	// resourceVersion 41, while the API server holds 42 and a snapshot
	// controller write has landed in between.
	var gets int
	fakeV1.PrependReactor("get", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		if action.(clientTesting.GetAction).GetName() != dataUploadName {
			return false, nil, nil
		}
		gets++
		if gets == 1 {
			stale := vsc.DeepCopy()
			stale.ResourceVersion = "41"
			return true, stale, nil
		}
		return false, nil, nil
	})
	// Enforce the precondition semantics the real API server provides.
	fakeV1.PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(clientTesting.PatchAction)
		if patchAction.GetName() != dataUploadName {
			return false, nil, nil
		}
		payload := map[string]any{}
		if err := json.Unmarshal(patchAction.GetPatch(), &payload); err != nil {
			return true, nil, err
		}
		if rv, ok := payload["resourceVersion"].(string); ok && rv != "42" {
			return true, nil, apierrors.NewConflict(snapshotv1api.Resource("volumesnapshotcontents"), dataUploadName, errors.New("resourceVersion mismatch"))
		}
		return false, nil, nil
	})

	require.NoError(t, r.retainSnapshotOnCompletion(t.Context(), du, velerotest.NewLogger()),
		"the Retain patch must carry the post-recheck resourceVersion, not the stale one from the first Get")

	current, getErr := getBackupVSC(t, r, du)
	require.NoError(t, getErr)
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentRetain, current.Spec.DeletionPolicy)
}

// TestReleaseRetainedSnapshotUsesFreshResourceVersions proves the
// resourceVersion chain of the patch-back: every write bumps the content's
// resourceVersion, so the status seed must carry the resourceVersion the
// Delete patch returned and the content delete must be preconditioned on the
// post-seed resourceVersion -- never on the one from the Get at the top,
// which would self-conflict on every release against a real API server. The
// fake snapshot clientset neither bumps resourceVersions nor enforces the
// delete preconditions, so the reactors simulate the bumps and the test
// asserts the resourceVersions the operations actually carry.
func TestReleaseRetainedSnapshotUsesFreshResourceVersions(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	stored := func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC() // resourceVersion 42
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		vsc.Status = nil
		return vsc
	}()
	createRetainedSnapshotObjects(t, r, du, stored)

	var statusUpdateResourceVersions []string
	var deletePreconditions []string
	fakeV1 := r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1)
	// The Delete patch bumps the resourceVersion, as the API server does.
	fakeV1.PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(clientTesting.PatchAction)
		if patchAction.GetName() != dataUploadName {
			return false, nil, nil
		}
		stored = stored.DeepCopy()
		stored.ResourceVersion = "43"
		stored.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentDelete
		return true, stored, nil
	})
	// The status seed bumps it again.
	fakeV1.PrependReactor("update", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clientTesting.UpdateAction)
		updated, ok := updateAction.GetObject().(*snapshotv1api.VolumeSnapshotContent)
		if !ok || updateAction.GetSubresource() != "status" || updated.Name != dataUploadName {
			return false, nil, nil
		}
		statusUpdateResourceVersions = append(statusUpdateResourceVersions, updated.ResourceVersion)
		stored = stored.DeepCopy()
		stored.ResourceVersion = "44"
		handle := retentionHandle
		stored.Status = &snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &handle}
		return true, stored, nil
	})
	// The delete's resourceVersion precondition is what the test asserts.
	fakeV1.PrependReactor("delete", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		deleteAction := action.(clientTesting.DeleteAction)
		if deleteAction.GetName() != dataUploadName {
			return false, nil, nil
		}
		if deleteAction.GetDeleteOptions().Preconditions != nil && deleteAction.GetDeleteOptions().Preconditions.ResourceVersion != nil {
			deletePreconditions = append(deletePreconditions, *deleteAction.GetDeleteOptions().Preconditions.ResourceVersion)
		}
		return false, nil, nil
	})

	require.NoError(t, r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger()))

	require.Len(t, statusUpdateResourceVersions, 1, "the status must be seeded exactly once")
	assert.Equal(t, "43", statusUpdateResourceVersions[0],
		"the status seed must carry the post-patch resourceVersion, not the original Get's")
	require.NotEmpty(t, deletePreconditions, "the content must be deleted with a resourceVersion precondition")
	assert.Equal(t, "44", deletePreconditions[0],
		"the content delete must be preconditioned on the post-seed resourceVersion, not the original Get's")
}

// TestReleaseRetainedSnapshotSeedsStatus proves that the patch-back seeds
// status.snapshotHandle before deleting the content: the sidecar only issues
// DeleteSnapshot when the policy is Delete and the status carries the handle,
// otherwise it removes the finalizer with no CSI call and the content's
// disappearance would read as release while the snapshot leaks.
func TestReleaseRetainedSnapshotSeedsStatus(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	du := retentionDataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	vsc := func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC()
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		vsc.Status = nil // the sidecar never got to set it
		return vsc
	}()
	createRetainedSnapshotObjects(t, r, du, vsc)

	var events []string
	fakeV1 := r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1)
	fakeV1.PrependReactor("*", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		switch a := action.(type) {
		case clientTesting.PatchAction:
			events = append(events, "patch")
		case clientTesting.UpdateAction:
			if a.GetSubresource() == "status" {
				events = append(events, "update-status")
			}
		case clientTesting.DeleteAction:
			events = append(events, "delete")
		}
		return false, nil, nil
	})

	require.NoError(t, r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger()))

	statusIdx, deleteIdx := -1, -1
	for i, event := range events {
		if statusIdx < 0 && event == "update-status" {
			statusIdx = i
		}
		if deleteIdx < 0 && event == "delete" {
			deleteIdx = i
		}
	}
	require.GreaterOrEqual(t, statusIdx, 0, "the patch-back must seed the content status, events: %v", events)
	require.GreaterOrEqual(t, deleteIdx, 0, "the patch-back must delete the content, events: %v", events)
	assert.Less(t, statusIdx, deleteIdx, "the status must be seeded before the content is deleted")

	// The seeded status carries the record's handle.
	current, getErr := getBackupVSC(t, r, du)
	if getErr == nil {
		require.NotNil(t, current.Status)
		require.NotNil(t, current.Status.SnapshotHandle)
		assert.Equal(t, retentionHandle, *current.Status.SnapshotHandle)
	} else {
		assert.True(t, apierrors.IsNotFound(getErr))
	}
}

// TestReleaseRetainedSnapshotNoopsOnFinalStateDataUpload proves the cancel-path
// guard: a DataUpload that already reached a terminal phase, e.g. because the
// cancel path overwrote a completed one, must not have its base snapshot
// deleted by the patch-back; a surviving record is owned by the backup
// deletion instead.
func TestReleaseRetainedSnapshotNoopsOnFinalStateDataUpload(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	// The in-memory DataUpload looks unfinished, but the API object has
	// already reached a terminal phase.
	du := retentionDataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result()
	du.Status.RetainedCSIStorageSnapshot = retentionRecord()
	vsc := func() *snapshotv1api.VolumeSnapshotContent {
		vsc := retentionBackupVSC()
		vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
		return vsc
	}()
	createRetainedSnapshotObjects(t, r, du, vsc)

	// Move the API object to a final phase, as the cancel path would when it
	// overwrites a terminal DataUpload.
	completed := getDataUpload(t, r, du)
	completed.Status.Phase = velerov2alpha1api.DataUploadPhaseCompleted
	require.NoError(t, r.client.Update(t.Context(), completed))

	var actions int
	r.csiSnapshotClient.(*snapshotv1fake.FakeSnapshotV1).PrependReactor("*", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		if _, ok := action.(clientTesting.GetAction); !ok {
			actions++
		}
		return false, nil, nil
	})

	require.NoError(t, r.releaseRetainedSnapshot(t.Context(), du, velerotest.NewLogger()))
	assert.Zero(t, actions, "the patch-back must not touch the content of a final-state DataUpload")

	current, getErr := getBackupVSC(t, r, du)
	require.NoError(t, getErr)
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentRetain, current.Spec.DeletionPolicy,
		"the base snapshot of the completed backup must stay retained")
}
