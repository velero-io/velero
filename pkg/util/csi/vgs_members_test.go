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

package csi

import (
	"context"
	"testing"
	"time"

	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util"
)

// recordingClient captures the live state of an object right before it is
// deleted, so tests can assert on the complete object the release flow
// produced — including the status set after creation via Status().Update(),
// which a Create-time snapshot would never see, and which the object itself
// no longer exists to be queried after the real Delete below runs.
type recordingClient struct {
	crclient.Client
	deleted []crclient.Object
}

func (c *recordingClient) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		current := u.DeepCopy()
		if err := c.Client.Get(ctx, crclient.ObjectKeyFromObject(obj), current); err == nil {
			c.deleted = append(c.deleted, current)
		}
	}
	return c.Client.Delete(ctx, obj, opts...)
}

// deleteFailingClient fails Delete for the given object names.
type deleteFailingClient struct {
	crclient.Client
	deleteErrByName map[string]error
}

// listCountingClient counts List calls for a given unstructured list kind,
// so a test can assert how many times a cluster-scoped list (like
// VolumeGroupSnapshotClasses) was actually re-fetched from the API server.
type listCountingClient struct {
	crclient.Client
	kind  string
	calls int
}

func (c *listCountingClient) List(ctx context.Context, list crclient.ObjectList, opts ...crclient.ListOption) error {
	if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Kind == c.kind {
		c.calls++
	}
	return c.Client.List(ctx, list, opts...)
}

func (c *deleteFailingClient) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	if err, found := c.deleteErrByName[obj.GetName()]; found {
		return err
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func listVGSMemberConfigMaps(t *testing.T, c crclient.Client, backupUID string) []corev1api.ConfigMap {
	t.Helper()
	list := &corev1api.ConfigMapList{}
	require.NoError(t, c.List(t.Context(), list, crclient.MatchingLabels(map[string]string{
		velerov1.BackupUIDLabel:                 backupUID,
		velerov1.VolumeGroupSnapshotMemberLabel: "true",
	})))
	return list.Items
}

func TestAccumulateVGSMembers(t *testing.T) {
	log := logrus.New()
	backup := &velerov1.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "velero", UID: "backup-uid"},
	}
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup)

	// An empty group handle is a no-op: no ConfigMap is created.
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "driver", "", "member-1", "content-0"))
	assert.Empty(t, listVGSMemberConfigMaps(t, client, string(backup.UID)))

	// Two distinct members of the same group each get their own ConfigMap.
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "rbd.csi.ceph.com", "group-1", "member-1", "content-1"))
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "rbd.csi.ceph.com", "group-1", "member-2", "content-2"))
	// A member without a reported snapshot handle still gets a ConfigMap,
	// keyed by its content name so it does not collide with other members.
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "rbd.csi.ceph.com", "group-1", "", "content-3"))

	cms := listVGSMemberConfigMaps(t, client, string(backup.UID))
	require.Len(t, cms, 3)
	for _, cm := range cms {
		assert.Equal(t, "backup", cm.Labels[velerov1.BackupNameLabel])
		assert.Equal(t, "backup-uid", cm.Labels[velerov1.BackupUIDLabel])
		assert.Equal(t, "true", cm.Labels[velerov1.VolumeGroupSnapshotMemberLabel])
		assert.Contains(t, cm.Data["member"], `"groupSnapshotHandle":"group-1"`)
	}

	// Reprocessing the same tarball item (e.g. after a failed deletion
	// attempt is retried) is idempotent: the same ConfigMap name is derived
	// and AlreadyExists is treated as success, not an error.
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "rbd.csi.ceph.com", "group-1", "member-1", "content-1"))
	assert.Len(t, listVGSMemberConfigMaps(t, client, string(backup.UID)), 3)
}

func TestReleaseBackupVolumeGroupSnapshots(t *testing.T) {
	origSleep := sleepBetweenTempVGSCCreateAndDelete
	sleepBetweenTempVGSCCreateAndDelete = func(time.Duration) {}
	t.Cleanup(func() { sleepBetweenTempVGSCCreateAndDelete = origSleep })

	log := logrus.New()
	driver := "rbd.csi.ceph.com"
	class := &volumegroupsnapshotv1.VolumeGroupSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{Name: "vgs-class"},
		Driver:     driver,
		Parameters: map[string]string{
			"csi.storage.k8s.io/group-snapshotter-secret-name":      "group-secret",
			"csi.storage.k8s.io/group-snapshotter-secret-namespace": "group-secret-ns",
		},
	}
	backup := &velerov1.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "velero", UID: "backup-uid"},
	}
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, class)

	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, driver, "group-1", "member-1", "content-1"))
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, driver, "group-1", "member-2", "content-2"))
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "other.driver", "group-2", "", "content-3"))

	// Releasing a backup with no member ConfigMaps is a no-op.
	otherBackup := &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "velero", UID: "other-uid"}}
	require.NoError(t, ReleaseBackupVolumeGroupSnapshots(t.Context(), otherBackup, client, log))

	recorder := &recordingClient{Client: client}
	require.NoError(t, ReleaseBackupVolumeGroupSnapshots(t.Context(), backup, recorder, log))

	// One temporary static VGSC per group was created, complete, with
	// deletionPolicy Delete, the group snapshotter deletion secrets, a
	// placeholder VolumeGroupSnapshotRef (the CRD requires name and
	// namespace to be set) and the status set by the post-create retry
	// before the content was deleted again to trigger the release.
	var createdVGSCs []*volumegroupsnapshotv1.VolumeGroupSnapshotContent
	for _, obj := range recorder.deleted {
		u, ok := obj.(*unstructured.Unstructured)
		if !ok || u.GroupVersionKind().Kind != "VolumeGroupSnapshotContent" {
			continue
		}
		vgsc := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
		require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(u.UnstructuredContent(), vgsc))
		createdVGSCs = append(createdVGSCs, vgsc)
	}
	require.Len(t, createdVGSCs, 2)

	byGroupHandle := map[string]*volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
	for _, vgsc := range createdVGSCs {
		require.NotNil(t, vgsc.Spec.Source.GroupSnapshotHandles)
		byGroupHandle[vgsc.Spec.Source.GroupSnapshotHandles.VolumeGroupSnapshotHandle] = vgsc
	}

	released1 := byGroupHandle["group-1"]
	require.NotNil(t, released1)
	assert.Equal(t, snapshotv1.VolumeSnapshotContentDelete, released1.Spec.DeletionPolicy)
	assert.Equal(t, driver, released1.Spec.Driver)
	assert.ElementsMatch(t, []string{"member-1", "member-2"}, released1.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles)
	assert.NotEmpty(t, released1.Spec.VolumeGroupSnapshotRef.Name)
	assert.Equal(t, "velero", released1.Spec.VolumeGroupSnapshotRef.Namespace)
	assert.Equal(t, "true", released1.Labels[velerov1.VolumeGroupSnapshotTempContentLabel])
	assert.Equal(t, "backup-uid", released1.Labels[velerov1.BackupUIDLabel])
	assert.Equal(t, "group-secret", released1.Annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-name"])
	assert.Equal(t, "group-secret-ns", released1.Annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-namespace"])
	require.NotNil(t, released1.Status)
	require.NotNil(t, released1.Status.VolumeGroupSnapshotHandle)
	assert.Equal(t, "group-1", *released1.Status.VolumeGroupSnapshotHandle)
	require.NotNil(t, released1.Status.ReadyToUse,
		"readyToUse must be set so the sidecar skips GetVolumeGroupSnapshot validation, which has no annotation-based credential fallback")
	assert.True(t, *released1.Status.ReadyToUse)
	assert.Contains(t, released1.Finalizers, "groupsnapshot.storage.kubernetes.io/volumegroupsnapshotcontent-bound-protection",
		"the common controller never adds this finalizer to a content whose VolumeGroupSnapshotRef has no UID, so Velero must set it itself or Delete removes the object immediately instead of giving the sidecar a live object to process")

	// A group whose only member reported no snapshot handle still releases
	// through the group handle, with an empty (but present) member handle
	// list: volumeSnapshotHandles is a required field of groupSnapshotHandles.
	released2 := byGroupHandle["group-2"]
	require.NotNil(t, released2)
	require.NotNil(t, released2.Spec.Source.GroupSnapshotHandles)
	assert.Equal(t, []string{}, released2.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles)

	// Delete was requested for both temporary contents. They carry the
	// bound-protection finalizer Velero sets explicitly (the common
	// controller never adds it to a content whose ref has no UID), so —
	// exactly like a real cluster, where only the sidecar removing that
	// finalizer after a successful backend delete lets the object actually
	// disappear — the fake client correctly keeps them present with
	// DeletionTimestamp set rather than removing them outright. No sidecar
	// is simulated here, so that's as far as this test can observe; the
	// member ConfigMaps that contributed to a successful release step are
	// still cleaned up immediately, independent of the content's own
	// lifecycle.
	vgscList, err := ListVGSC(t.Context(), client, nil)
	require.NoError(t, err)
	require.Len(t, vgscList.Items, 2)
	for _, vgsc := range vgscList.Items {
		assert.NotNil(t, vgsc.DeletionTimestamp, "content %s should be marked for deletion", vgsc.Name)
		assert.Contains(t, vgsc.Finalizers, "groupsnapshot.storage.kubernetes.io/volumegroupsnapshotcontent-bound-protection")
	}
	assert.Empty(t, listVGSMemberConfigMaps(t, client, string(backup.UID)))

	// A second release, with nothing left to release, is a no-op.
	require.NoError(t, ReleaseBackupVolumeGroupSnapshots(t.Context(), backup, client, log))
}

func TestReleaseBackupVolumeGroupSnapshotsSharesVGSClassList(t *testing.T) {
	origSleep := sleepBetweenTempVGSCCreateAndDelete
	sleepBetweenTempVGSCCreateAndDelete = func(time.Duration) {}
	t.Cleanup(func() { sleepBetweenTempVGSCCreateAndDelete = origSleep })

	log := logrus.New()
	rbdDriver := "rbd.csi.ceph.com"
	cephfsDriver := "cephfs.csi.ceph.com"
	rbdClass := &volumegroupsnapshotv1.VolumeGroupSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{Name: "rbd-class"},
		Driver:     rbdDriver,
		Parameters: map[string]string{
			"csi.storage.k8s.io/group-snapshotter-secret-name":      "rbd-secret",
			"csi.storage.k8s.io/group-snapshotter-secret-namespace": "rbd-secret-ns",
		},
	}
	cephfsClass := &volumegroupsnapshotv1.VolumeGroupSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cephfs-class"},
		Driver:     cephfsDriver,
		Parameters: map[string]string{
			"csi.storage.k8s.io/group-snapshotter-secret-name":      "cephfs-secret",
			"csi.storage.k8s.io/group-snapshotter-secret-namespace": "cephfs-secret-ns",
		},
	}
	backup := &velerov1.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "velero", UID: "backup-uid"},
	}
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, rbdClass, cephfsClass)

	// Three distinct VolumeGroupSnapshot groups in the same backup, two of
	// them on different drivers, so each needs its own deletion-secret
	// lookup result.
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, rbdDriver, "group-1", "member-1", "content-1"))
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, rbdDriver, "group-2", "member-2", "content-2"))
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, cephfsDriver, "group-3", "member-3", "content-3"))

	recorder := &recordingClient{Client: client}
	counter := &listCountingClient{Client: recorder, kind: "VolumeGroupSnapshotClassList"}
	require.NoError(t, ReleaseBackupVolumeGroupSnapshots(t.Context(), backup, counter, log))

	// One List for three groups, not one List per group: the class list is
	// cluster-scoped and identical for every group released in this call.
	assert.Equal(t, 1, counter.calls)

	var createdVGSCs []*volumegroupsnapshotv1.VolumeGroupSnapshotContent
	for _, obj := range recorder.deleted {
		u, ok := obj.(*unstructured.Unstructured)
		if !ok || u.GroupVersionKind().Kind != "VolumeGroupSnapshotContent" {
			continue
		}
		vgsc := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
		require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(u.UnstructuredContent(), vgsc))
		createdVGSCs = append(createdVGSCs, vgsc)
	}
	require.Len(t, createdVGSCs, 3)

	// Despite being resolved only once, the shared list still produces the
	// correct per-driver secret for each group.
	for _, vgsc := range createdVGSCs {
		switch vgsc.Spec.Driver {
		case rbdDriver:
			assert.Equal(t, "rbd-secret", vgsc.Annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-name"])
			assert.Equal(t, "rbd-secret-ns", vgsc.Annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-namespace"])
		case cephfsDriver:
			assert.Equal(t, "cephfs-secret", vgsc.Annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-name"])
			assert.Equal(t, "cephfs-secret-ns", vgsc.Annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-namespace"])
		default:
			t.Fatalf("unexpected driver %s", vgsc.Spec.Driver)
		}
	}
}

func TestReleaseBackupVolumeGroupSnapshotsKeepsMemberConfigMapsOnFailure(t *testing.T) {
	origSleep := sleepBetweenTempVGSCCreateAndDelete
	sleepBetweenTempVGSCCreateAndDelete = func(time.Duration) {}
	t.Cleanup(func() { sleepBetweenTempVGSCCreateAndDelete = origSleep })

	log := logrus.New()
	backup := &velerov1.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "velero", UID: "backup-uid"},
	}
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup)
	require.NoError(t, AccumulateVGSMembers(t.Context(), client, log, backup, "rbd.csi.ceph.com", "group-1", "member-1", "content-1"))

	contentName := "velero-tmp-vgsc-" + releaseTempContentNameForTest(string(backup.UID), "group-1")
	failing := &deleteFailingClient{
		Client:          client,
		deleteErrByName: map[string]error{contentName: apierrors.NewBadRequest("delete failed")},
	}

	err := ReleaseBackupVolumeGroupSnapshots(t.Context(), backup, failing, log)
	require.ErrorContains(t, err, "deleting temporary VolumeGroupSnapshotContent")

	// The member ConfigMap is kept so a retried deletion attempt has the
	// full member list again.
	require.Len(t, listVGSMemberConfigMaps(t, client, string(backup.UID)), 1)

	// A retry without the failure succeeds and removes the member ConfigMap.
	require.NoError(t, ReleaseBackupVolumeGroupSnapshots(t.Context(), backup, client, log))
	assert.Empty(t, listVGSMemberConfigMaps(t, client, string(backup.UID)))
}

// releaseTempContentNameForTest mirrors the temporary content name suffix
// computed by releaseVolumeGroupSnapshot.
func releaseTempContentNameForTest(backupUID, groupSnapshotHandle string) string {
	return util.GenerateSha256FromRestoreUIDAndVsName(backupUID, groupSnapshotHandle)
}
