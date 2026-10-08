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
	"testing"

	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
)

func TestVGSMembershipCleanup(t *testing.T) {
	for _, scenario := range []string{"completed group", "failed before group creation", "group deletion pending"} {
		t.Run(scenario, func(t *testing.T) {
			backup := &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{
				Name: "backup", UID: "backup-a",
				Annotations: map[string]string{velerov1.VolumeGroupSnapshotBackupAnnotation: "true"},
			}}
			key := csi.VGSMembershipLabelKey(backup.UID)
			otherKey := csi.VGSMembershipLabelKey("backup-b")
			pvc := &corev1api.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
				Name: "mysql", Namespace: "app", UID: "pvc-uid",
				Labels: map[string]string{"app": "database", key: "group", otherKey: "group"},
			}}
			group := &volumegroupsnapshotv1.VolumeGroupSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "app", Labels: map[string]string{velerov1.BackupUIDLabel: string(backup.UID)}},
				Spec: volumegroupsnapshotv1.VolumeGroupSnapshotSpec{Source: volumegroupsnapshotv1.VolumeGroupSnapshotSource{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{key: "group"}},
				}},
			}
			objects := []runtime.Object{backup, pvc}
			if scenario != "failed before group creation" {
				if scenario == "group deletion pending" {
					group.Finalizers = []string{"test.example.com/hold"}
				}
				objects = append(objects, group)
			}
			client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, objects...)
			if scenario == "group deletion pending" {
				err := csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New())
				require.ErrorContains(t, err, "deletion before cleaning membership labels")
				current := &corev1api.PersistentVolumeClaim{}
				require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(pvc), current))
				require.Equal(t, "group", current.Labels[key])
				deletingGroup, err := csi.GetVGS(t.Context(), client, group.Namespace, group.Name)
				require.NoError(t, err)
				deletingGroup.Finalizers = nil
				require.NoError(t, client.Update(t.Context(), deletingGroup))
			}
			require.NoError(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
			current := &corev1api.PersistentVolumeClaim{}
			require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(pvc), current))
			require.NotContains(t, current.Labels, key)
			require.Equal(t, "group", current.Labels[otherKey])
			require.Equal(t, "database", current.Labels["app"])
			require.NoError(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
		})
	}
}

func TestVGSMembershipPartialFailure(t *testing.T) {
	backup := &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{
		UID: "backup-uid", Annotations: map[string]string{velerov1.VolumeGroupSnapshotBackupAnnotation: "true"},
	}}
	pvc := &corev1api.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "present", Namespace: "app", UID: "pvc-uid"}}
	missing := corev1api.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "app"}}
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, pvc)
	err := csi.MarkVGSMembers(t.Context(), client, backup.UID, "group", []corev1api.PersistentVolumeClaim{*pvc, missing})
	require.ErrorContains(t, err, "labeling VolumeGroupSnapshot member PVC app/missing")
	current := &corev1api.PersistentVolumeClaim{}
	require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(pvc), current))
	require.Equal(t, "group", current.Labels[csi.VGSMembershipLabelKey(backup.UID)])
	require.NoError(t, csi.CleanupBackupVolumeGroupSnapshots(t.Context(), backup, client, logrus.New()))
	require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(pvc), current))
	require.NotContains(t, current.Labels, csi.VGSMembershipLabelKey(backup.UID))
}

func TestVGSMembershipRejectsReplacedPVC(t *testing.T) {
	original := corev1api.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "mysql", Namespace: "app", UID: "original"}}
	replacement := original.DeepCopy()
	replacement.UID = "replacement"
	client := velerotest.NewFakeControllerRuntimeClientWithVGS(t, replacement)
	err := csi.MarkVGSMembers(t.Context(), client, "backup-uid", "group", []corev1api.PersistentVolumeClaim{original})
	require.ErrorContains(t, err, "was replaced")
	current := &corev1api.PersistentVolumeClaim{}
	require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(replacement), current))
	require.Empty(t, current.Labels)
}
