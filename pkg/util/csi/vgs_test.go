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
	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
)

type failingVGSClient struct {
	crclient.Client
	listErr         error
	updateErr       error
	updateErrByName map[string]error
	deleteErr       error
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

func (c *failingVGSClient) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	if c.deleteErr != nil {
		return c.deleteErr
	}
	return c.Client.Delete(ctx, obj, opts...)
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
	seedClass := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotClass{
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
	created, err := csi.CreateVGS(t.Context(), c, &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "vgs-1", Namespace: "ns-1"},
		Spec:       volumegroupsnapshotv1beta2.VolumeGroupSnapshotSpec{VolumeGroupSnapshotClassName: &className},
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
	backup := &velerov1.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "velero", UID: "backup-uid"},
		Spec:       velerov1.BackupSpec{VolumeGroupSnapshotLabelKey: "velero.io/volume-group"},
		Status:     velerov1.BackupStatus{Phase: velerov1.BackupPhaseDeleting},
	}
	groupContentName := "group-content"
	processedContentName := "processed-content"
	group := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{
			velerov1.BackupNameLabel: "backup", velerov1.BackupUIDLabel: "backup-uid",
		}},
		Status: &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &groupContentName},
	}
	processedGroup := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "processed-group", Namespace: "app", UID: "processed-group-uid", Labels: map[string]string{
			velerov1.BackupUIDLabel: string(backup.UID),
		}},
		Status: &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &processedContentName},
	}
	content := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: groupContentName},
		Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
			DeletionPolicy:         snapshotv1.VolumeSnapshotContentRetain,
			VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: group.Name, Namespace: group.Namespace, UID: group.UID},
		},
	}
	processedContent := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: processedContentName, Labels: map[string]string{
			velerov1.BackupUIDLabel: string(backup.UID),
		}},
		Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
			DeletionPolicy:         snapshotv1.VolumeSnapshotContentRetain,
			VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: processedGroup.Name, Namespace: processedGroup.Namespace, UID: processedGroup.UID},
		},
	}
	memberContent := &snapshotv1.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "member-content", Labels: map[string]string{
			velerov1.BackupUIDLabel: string(backup.UID),
		}},
		Spec: snapshotv1.VolumeSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete},
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
	orphanContent := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-content", Labels: map[string]string{
			velerov1.BackupUIDLabel: string(backup.UID),
		}},
		Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentDelete},
	}
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, content, processedGroup, processedContent, orphanContent, memberContent, memberVS, ordinaryContent)
	require.NoError(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
	_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
	require.Error(t, err)
	_, err = csi.GetVGSC(t.Context(), client, groupContentName)
	require.Error(t, err)
	_, err = csi.GetVGSC(t.Context(), client, orphanContent.Name)
	require.Error(t, err)
	_, err = csi.GetVGSC(t.Context(), client, processedContent.Name)
	require.Error(t, err)
	updatedMemberContent := &snapshotv1.VolumeSnapshotContent{}
	require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(memberContent), updatedMemberContent))
	require.Equal(t, snapshotv1.VolumeSnapshotContentRetain, updatedMemberContent.Spec.DeletionPolicy)
	updatedOrdinaryContent := &snapshotv1.VolumeSnapshotContent{}
	require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(ordinaryContent), updatedOrdinaryContent))
	require.Equal(t, snapshotv1.VolumeSnapshotContentDelete, updatedOrdinaryContent.Spec.DeletionPolicy)
}

func TestCleanupBackupVolumeGroupSnapshotsErrors(t *testing.T) {
	backup := &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{Name: "backup", UID: "backup-uid"}}
	base := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup)

	t.Run("list VGS", func(t *testing.T) {
		client := &failingVGSClient{Client: base, listErr: errors.New("list failed")}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "listing backup VolumeGroupSnapshots")
	})

	content := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "content", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
		Spec:       volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{DeletionPolicy: snapshotv1.VolumeSnapshotContentRetain},
	}
	t.Run("update VGSC", func(t *testing.T) {
		client := &failingVGSClient{Client: velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, content), updateErr: errors.New("update failed")}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "retaining VolumeGroupSnapshotContent")
	})

	t.Run("delete VGSC", func(t *testing.T) {
		client := &failingVGSClient{Client: velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, content), deleteErr: errors.New("delete failed")}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "deleting VolumeGroupSnapshotContent")
	})

	t.Run("continues cleanup after a content failure", func(t *testing.T) {
		failedContentName := "failed-content"
		completedContentName := "completed-content"
		failedGroup := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "failed-group", Namespace: "app", UID: "failed-group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status:     &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &failedContentName},
		}
		completedGroup := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "completed-group", Namespace: "app", UID: "completed-group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status:     &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &completedContentName},
		}
		failedContent := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: failedContentName, Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Spec:       volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: failedGroup.Name, Namespace: failedGroup.Namespace, UID: failedGroup.UID}},
		}
		completedContent := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: completedContentName, Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Spec:       volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: completedGroup.Name, Namespace: completedGroup.Namespace, UID: completedGroup.UID}},
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

	t.Run("does not delete VGS when member retention fails", func(t *testing.T) {
		group := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
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
			Client:          velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, group, memberContent, memberVS),
			updateErrByName: map[string]error{memberContent.Name: errors.New("update failed")},
		}
		require.ErrorContains(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()), "retaining VolumeSnapshotContent")
		_, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
		require.NoError(t, err)
	})

	t.Run("deletes VGS when bound content is misbound", func(t *testing.T) {
		contentName := "misbound-content"
		group := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", UID: "group-uid", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
			Status:     &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{BoundVolumeGroupSnapshotContentName: &contentName},
		}
		content := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: contentName},
			Spec:       volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{VolumeGroupSnapshotRef: corev1api.ObjectReference{Name: "other", Namespace: "app", UID: "other-uid"}},
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
