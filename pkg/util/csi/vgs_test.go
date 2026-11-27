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

package csi_test

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util/boolptr"
	"github.com/velero-io/velero/pkg/util/csi"
)

type failingVGSClient struct {
	crclient.Client
	listErr         error
	updateErr       error
	updateErrByName map[string]error
	patchErrByName  map[string]error
	deleteErr       error
	deleteErrByName map[string]error
	statusUpdateErr error
}

func (c *failingVGSClient) List(ctx context.Context, list crclient.ObjectList, opts ...crclient.ListOption) error {
	if c.listErr != nil {
		return c.listErr
	}
	return c.Client.List(ctx, list, opts...)
}

func (c *failingVGSClient) Update(ctx context.Context, obj crclient.Object, opts ...crclient.UpdateOption) error {
	if err, found := c.updateErrByName[obj.GetName()]; found {
		return err
	}
	if c.updateErr != nil {
		return c.updateErr
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (c *failingVGSClient) Patch(ctx context.Context, obj crclient.Object, patch crclient.Patch, opts ...crclient.PatchOption) error {
	if err, found := c.patchErrByName[obj.GetName()]; found {
		return err
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *failingVGSClient) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	if err, found := c.deleteErrByName[obj.GetName()]; found {
		return err
	}
	if c.deleteErr != nil {
		return c.deleteErr
	}
	return c.Client.Delete(ctx, obj, opts...)
}

// statusUpdateErr, when set, makes every Status().Update() call fail.
func (c *failingVGSClient) Status() crclient.SubResourceWriter {
	return &failingVGSStatusWriter{SubResourceWriter: c.Client.Status(), err: c.statusUpdateErr}
}

type failingVGSStatusWriter struct {
	crclient.SubResourceWriter
	err error
}

func (w *failingVGSStatusWriter) Update(ctx context.Context, obj crclient.Object, opts ...crclient.SubResourceUpdateOption) error {
	if w.err != nil {
		return w.err
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestResolveVGSGroupVersion(t *testing.T) {
	tests := []struct {
		name        string
		served      []string
		expectVer   string
		expectErr   bool
		expectNoAPI bool
	}{
		{name: "v1 only", served: []string{"v1"}, expectVer: "v1"},
		{name: "v1beta1 only", served: []string{"v1beta1"}, expectVer: "v1beta1"},
		{name: "v1beta2 only", served: []string{"v1beta2"}, expectVer: "v1beta2"},
		{name: "all served prefers v1", served: []string{"v1beta1", "v1beta2", "v1"}, expectVer: "v1"},
		{name: "betas served prefers v1beta2", served: []string{"v1beta1", "v1beta2"}, expectVer: "v1beta2"},
		{name: "none served", served: nil, expectNoAPI: true},
		{name: "only unknown version", served: []string{"v2"}, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gv, err := csi.ResolveVGSGroupVersion(velerotest.VGSTestRESTMapper(tt.served...))

			switch {
			case tt.expectNoAPI:
				require.ErrorIs(t, err, csi.ErrVGSAPINotAvailable)
			case tt.expectErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
				require.Equal(t, csi.VGSGroup, gv.Group)
				require.Equal(t, tt.expectVer, gv.Version)
			}
		})
	}
}

// TestVGSHelpersRoundTrip exercises the unstructured-on-crClient helpers against a
// fake client whose RESTMapper serves the VGS API.
func TestVGSHelpersRoundTrip(t *testing.T) {
	className := "rbd-class"
	seedClass := &volumegroupsnapshotv1.VolumeGroupSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   className,
			Labels: map[string]string{"velero.io/csi-volumegroupsnapshot-class": "true"},
		},
		Driver: "rbd.csi.ceph.com",
	}
	c := velerotest.NewFakeControllerRuntimeClientWithVGS(t, seedClass)

	// List VGSClasses
	classes, err := csi.ListVGSClasses(t.Context(), c)
	require.NoError(t, err)
	require.Len(t, classes.Items, 1)
	require.Equal(t, "rbd.csi.ceph.com", classes.Items[0].Driver)

	// Create + Get VGS
	created, err := csi.CreateVGS(t.Context(), c, &volumegroupsnapshotv1.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "vgs-1", Namespace: "ns-1"},
		Spec:       volumegroupsnapshotv1.VolumeGroupSnapshotSpec{VolumeGroupSnapshotClassName: &className},
	})
	require.NoError(t, err)
	require.Equal(t, "vgs-1", created.Name)

	got, err := csi.GetVGS(t.Context(), c, "ns-1", "vgs-1")
	require.NoError(t, err)
	require.NotNil(t, got.Spec.VolumeGroupSnapshotClassName)
	require.Equal(t, className, *got.Spec.VolumeGroupSnapshotClassName)

	// Delete VGS
	require.NoError(t, csi.DeleteVGS(t.Context(), c, "ns-1", "vgs-1"))
	_, err = csi.GetVGS(t.Context(), c, "ns-1", "vgs-1")
	require.Error(t, err)
}

func TestCleanupBackupVolumeGroupSnapshots(t *testing.T) {
	newBackup := func(snapshotMoveData bool) *velerov1.Backup {
		backup := &velerov1.Backup{
			ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "velero", UID: "backup-uid"},
			Spec:       velerov1.BackupSpec{VolumeGroupSnapshotLabelKey: "velero.io/volume-group"},
			Status:     velerov1.BackupStatus{Phase: velerov1.BackupPhaseDeleting},
		}
		if snapshotMoveData {
			backup.Spec.SnapshotMoveData = boolptr.True()
		}
		return backup
	}

	// seed builds one backup's worth of API objects. The member content
	// intentionally carries no Backup labels: member VolumeSnapshotContents
	// are discovered through the member VolumeSnapshot's status in production.
	seed := func(backup *velerov1.Backup, memberPolicy snapshotv1.DeletionPolicy) (crclient.Client, *volumegroupsnapshotv1.VolumeGroupSnapshot, *snapshotv1.VolumeSnapshotContent, *snapshotv1.VolumeSnapshotContent) {
		groupContentName := "group-content"
		processedContentName := "processed-content"
		group := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{
				velerov1.BackupNameLabel: "backup", velerov1.BackupUIDLabel: "backup-uid",
			}},
			Status: &volumegroupsnapshotv1.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &groupContentName},
		}
		processedGroup := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "processed-group", Namespace: "app", UID: "processed-group-uid", Labels: map[string]string{
				velerov1.BackupUIDLabel: string(backup.UID),
			}},
			Status: &volumegroupsnapshotv1.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &processedContentName},
		}
		content := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: groupContentName},
			Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{
				DeletionPolicy:         snapshotv1.VolumeSnapshotContentRetain,
				VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: group.Name, Namespace: group.Namespace, UID: group.UID},
			},
		}
		processedContent := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: processedContentName, Labels: map[string]string{
				velerov1.BackupUIDLabel: string(backup.UID),
			}},
			Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{
				DeletionPolicy:         snapshotv1.VolumeSnapshotContentRetain,
				VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: processedGroup.Name, Namespace: processedGroup.Namespace, UID: processedGroup.UID},
			},
		}
		memberContent := &snapshotv1.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "member-content"},
			Spec:       snapshotv1.VolumeSnapshotContentSpec{DeletionPolicy: memberPolicy},
		}
		memberVS := &snapshotv1.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "member-vs", Namespace: "app", Labels: map[string]string{
				velerov1.BackupUIDLabel: string(backup.UID),
			}},
			Status: &snapshotv1.VolumeSnapshotStatus{
				VolumeGroupSnapshotName:        &group.Name,
				BoundVolumeSnapshotContentName: &memberContent.Name,
			},
		}
		ordinaryContent := &snapshotv1.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "ordinary-content", Labels: map[string]string{
				velerov1.BackupUIDLabel: string(backup.UID),
			}},
			Spec: snapshotv1.VolumeSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete},
		}
		orphanContent := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "orphan-content", Labels: map[string]string{
				velerov1.BackupUIDLabel: string(backup.UID),
			}},
			Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete},
		}
		client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, content, processedGroup, processedContent, orphanContent, memberContent, memberVS, ordinaryContent)
		return client, group, memberContent, ordinaryContent
	}

	assertCommonCleanup := func(t *testing.T, client crclient.Client, group *volumegroupsnapshotv1.VolumeGroupSnapshot, processedContent *volumegroupsnapshotv1.VolumeGroupSnapshotContent) {
		t.Helper()
		_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
		require.Error(t, err)
		_, err = csi.GetVGSC(t.Context(), client, "group-content")
		require.Error(t, err)
		_, err = csi.GetVGSC(t.Context(), client, "orphan-content")
		require.Error(t, err)
		_, err = csi.GetVGSC(t.Context(), client, processedContent.Name)
		require.Error(t, err)
	}

	t.Run("snapshot backup retains member contents", func(t *testing.T) {
		backup := newBackup(false)
		client, group, memberContent, ordinaryContent := seed(backup, snapshotv1.VolumeSnapshotContentDelete)
		processedContent := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{ObjectMeta: metav1.ObjectMeta{Name: "processed-content"}}
		require.NoError(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
		assertCommonCleanup(t, client, group, processedContent)
		// The member content object is deleted; the backend snapshot is kept
		// through the Retain policy for restores. The ordinary content is not
		// a member and is left untouched.
		updatedMemberContent := &snapshotv1.VolumeSnapshotContent{}
		err := client.Get(t.Context(), crclient.ObjectKeyFromObject(memberContent), updatedMemberContent)
		require.ErrorContains(t, err, "not found")
		updatedOrdinaryContent := &snapshotv1.VolumeSnapshotContent{}
		require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(ordinaryContent), updatedOrdinaryContent))
		require.Equal(t, snapshotv1.VolumeSnapshotContentDelete, updatedOrdinaryContent.Spec.DeletionPolicy)
	})

	t.Run("data mover backup releases member contents", func(t *testing.T) {
		backup := newBackup(true)
		client, group, memberContent, ordinaryContent := seed(backup, snapshotv1.VolumeSnapshotContentRetain)
		processedContent := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{ObjectMeta: metav1.ObjectMeta{Name: "processed-content"}}
		require.NoError(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
		assertCommonCleanup(t, client, group, processedContent)
		updatedMemberContent := &snapshotv1.VolumeSnapshotContent{}
		err := client.Get(t.Context(), crclient.ObjectKeyFromObject(memberContent), updatedMemberContent)
		require.ErrorContains(t, err, "not found")
		updatedOrdinaryContent := &snapshotv1.VolumeSnapshotContent{}
		require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(ordinaryContent), updatedOrdinaryContent))
		require.Equal(t, snapshotv1.VolumeSnapshotContentDelete, updatedOrdinaryContent.Spec.DeletionPolicy)
	})
}

func TestCleanupBackupVolumeGroupSnapshotsErrors(t *testing.T) {
	backup := &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{Name: "backup", UID: "backup-uid"}}
	base := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup)

	t.Run("list VGS", func(t *testing.T) {
		client := &failingVGSClient{Client: base, listErr: errors.New("list failed")}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "listing backup VolumeGroupSnapshots")
	})

	content := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "content", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
		Spec:       volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentRetain},
	}
	t.Run("update VGSC", func(t *testing.T) {
		client := &failingVGSClient{Client: velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, content), updateErr: errors.New("update failed")}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "setting DeletionPolicy Retain on VolumeGroupSnapshotContent")
	})

	t.Run("delete VGSC", func(t *testing.T) {
		client := &failingVGSClient{Client: velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, content), deleteErr: errors.New("delete failed")}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "deleting VolumeGroupSnapshotContent")
	})

	t.Run("continues cleanup after a content failure", func(t *testing.T) {
		failedContentName := "failed-content"
		completedContentName := "completed-content"
		failedGroup := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "failed-group", Namespace: "app", UID: "failed-group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status:     &volumegroupsnapshotv1.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &failedContentName},
		}
		completedGroup := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "completed-group", Namespace: "app", UID: "completed-group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status:     &volumegroupsnapshotv1.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &completedContentName},
		}
		failedContent := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: failedContentName, Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Spec:       volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: failedGroup.Name, Namespace: failedGroup.Namespace, UID: failedGroup.UID}},
		}
		completedContent := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: completedContentName, Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Spec:       volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: completedGroup.Name, Namespace: completedGroup.Namespace, UID: completedGroup.UID}},
		}
		client := &failingVGSClient{
			Client:          velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, failedGroup, completedGroup, failedContent, completedContent),
			updateErrByName: map[string]error{failedContentName: errors.New("update failed")},
		}
		require.Error(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
		_, err := csi.GetVGS(t.Context(), client, completedGroup.Namespace, completedGroup.Name)
		require.Error(t, err)
		_, err = csi.GetVGS(t.Context(), client, failedGroup.Namespace, failedGroup.Name)
		require.NoError(t, err)
	})

	t.Run("does not delete VGS when member policy patch fails", func(t *testing.T) {
		group := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
		}
		memberContent := &snapshotv1.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "member-content", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Spec:       snapshotv1.VolumeSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete},
		}
		memberVS := &snapshotv1.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "member-vs", Namespace: "app", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status: &snapshotv1.VolumeSnapshotStatus{
				VolumeGroupSnapshotName:        &group.Name,
				BoundVolumeSnapshotContentName: &memberContent.Name,
			},
		}
		client := &failingVGSClient{
			Client:         velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, memberContent, memberVS),
			patchErrByName: map[string]error{memberContent.Name: errors.New("patch failed")},
		}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "setting DeletionPolicy Retain for member VolumeSnapshotContent")
		_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
		require.NoError(t, err)
	})

	t.Run("does not delete VGS when member content deletion fails", func(t *testing.T) {
		group := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
		}
		memberContent := &snapshotv1.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "member-content"},
			Spec:       snapshotv1.VolumeSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete},
		}
		memberVS := &snapshotv1.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "member-vs", Namespace: "app", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status: &snapshotv1.VolumeSnapshotStatus{
				VolumeGroupSnapshotName:        &group.Name,
				BoundVolumeSnapshotContentName: &memberContent.Name,
			},
		}
		client := &failingVGSClient{
			Client:          velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, memberContent, memberVS),
			deleteErrByName: map[string]error{memberContent.Name: errors.New("delete failed")},
		}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "deleting member VolumeSnapshotContent")
		// The policy was still settled before the deletion failed, so a
		// retry only needs the object deletion.
		updatedMemberContent := &snapshotv1.VolumeSnapshotContent{}
		require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(memberContent), updatedMemberContent))
		require.Equal(t, snapshotv1.VolumeSnapshotContentRetain, updatedMemberContent.Spec.DeletionPolicy)
		_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
		require.NoError(t, err)
	})

	t.Run("data mover backup sets Delete policy on group content", func(t *testing.T) {
		backup := &velerov1.Backup{
			ObjectMeta: metav1.ObjectMeta{Name: "backup", UID: "backup-uid"},
			Spec:       velerov1.BackupSpec{SnapshotMoveData: boolptr.True()},
		}
		groupContentName := "dm-group-content"
		group := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{
				velerov1.BackupUIDLabel: string(backup.UID),
			}},
			Status: &volumegroupsnapshotv1.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &groupContentName},
		}
		content := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: groupContentName},
			Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{
				DeletionPolicy:         snapshotv1.VolumeSnapshotContentRetain,
				VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: group.Name, Namespace: group.Namespace, UID: group.UID},
			},
		}
		client := &failingVGSClient{
			Client:          velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, content),
			deleteErrByName: map[string]error{groupContentName: errors.New("delete failed")},
		}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "deleting VolumeGroupSnapshotContent")
		updated := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
		require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(content), updated))
		require.Equal(t, snapshotv1.VolumeSnapshotContentDelete, updated.Spec.DeletionPolicy)
		// The VGS is not deleted while its content cleanup failed, so the
		// finalizer retries the whole cleanup.
		_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
		require.NoError(t, err)
	})

	t.Run("deletes VGS when bound content is misbound", func(t *testing.T) {
		contentName := "misbound-content"
		group := &volumegroupsnapshotv1.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status:     &volumegroupsnapshotv1.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &contentName},
		}
		content := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: contentName},
			Spec:       volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: "other", Namespace: "app", UID: "other-uid"}},
		}
		client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, content)
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "is not bound")
		_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
		require.Error(t, err)
	})
}

func TestVGSHelpersAPINotAvailable(t *testing.T) {
	// Fake client whose RESTMapper serves no VGS API.
	c := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithRESTMapper(velerotest.VGSTestRESTMapper()).
		Build()

	_, err := csi.ListVGSClasses(t.Context(), c)
	require.ErrorIs(t, err, csi.ErrVGSAPINotAvailable)
}

// TestCreateStaticVGSCForHandlesStatusUpdateFailure guards against treating a
// content whose status could not be set as successfully released: without
// ReadyToUse, the CSI snapshotter sidecar's GetVolumeGroupSnapshot validation
// can fail on missing credentials, so the real DeleteVolumeGroupSnapshot may
// never run. The function must report this failure rather than silently
// returning success, so the release path can retry instead of discarding the
// only record of the handle.
func TestCreateStaticVGSCForHandlesStatusUpdateFailure(t *testing.T) {
	real := velerotest.NewFakeControllerRuntimeClientWithVGS(t)
	c := &failingVGSClient{
		Client: real,
		statusUpdateErr: apierrors.NewConflict(
			schema.GroupResource{Group: "groupsnapshot.storage.k8s.io", Resource: "volumegroupsnapshotcontents"},
			"content-1", errors.New("conflict")),
	}

	created, err := csi.CreateStaticVGSCForHandles(
		t.Context(), c, logrus.StandardLogger(), "content-1", "fake.csi.driver", "group-handle",
		[]string{"handle-1"}, snapshotv1.VolumeSnapshotContentDelete, nil,
		corev1api.ObjectReference{Name: "ref", Namespace: "velero"}, nil,
	)

	require.True(t, created, "the object itself was created even though its status could not be")
	require.ErrorIs(t, err, csi.ErrStaticVGSCStatusNotSet)

	content, getErr := csi.GetVGSC(t.Context(), real, "content-1")
	require.NoError(t, getErr)
	require.Nil(t, content.Status, "status must not appear set when the update that would set it failed")
}

// TestCreateStaticVGSCForHandlesRetryRepairsStatus guards the companion fix:
// a retried call (AlreadyExists, from the exact same deterministically-named
// content a previous attempt left behind) must still try to set status,
// since that previous attempt may be the one from
// TestCreateStaticVGSCForHandlesStatusUpdateFailure above. Silently treating
// AlreadyExists as done would leave the content permanently without
// ReadyToUse.
func TestCreateStaticVGSCForHandlesRetryRepairsStatus(t *testing.T) {
	existing := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "content-1"},
		Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{
			DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete,
			Driver:         "fake.csi.driver",
			Source: volumegroupsnapshotv1.VolumeGroupSnapshotContentSource{
				GroupSnapshotHandles: &volumegroupsnapshotv1.GroupSnapshotHandles{
					VolumeGroupSnapshotHandle: "group-handle",
					VolumeSnapshotHandles:     []string{"handle-1"},
				},
			},
			VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: "ref", Namespace: "velero"},
		},
	}
	c := velerotest.NewFakeControllerRuntimeClientWithVGS(t, existing)

	created, err := csi.CreateStaticVGSCForHandles(
		t.Context(), c, logrus.StandardLogger(), "content-1", "fake.csi.driver", "group-handle",
		[]string{"handle-1"}, snapshotv1.VolumeSnapshotContentDelete, nil,
		corev1api.ObjectReference{Name: "ref", Namespace: "velero"}, nil,
	)

	require.NoError(t, err)
	require.False(t, created, "the content already existed, so this call did not create it")

	content, getErr := csi.GetVGSC(t.Context(), c, "content-1")
	require.NoError(t, getErr)
	require.NotNil(t, content.Status)
	require.NotNil(t, content.Status.ReadyToUse)
	assert.True(t, *content.Status.ReadyToUse, "retrying against an already-existing content must still repair a previously failed status update")
}
