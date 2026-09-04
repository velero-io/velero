/*
Copyright The Velero Contributors.

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

package volume

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	veleroshared "github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

func TestGenerateVolumeInfoForSkippedPV(t *testing.T) {
	tests := []struct {
		name                string
		skippedPVName       string
		pvMap               map[string]pvcPvInfo
		expectedVolumeInfos []*BackupVolumeInfo
	}{
		{
			name:          "Cannot find info for PV",
			skippedPVName: "testPV",
			pvMap: map[string]pvcPvInfo{
				"velero/testPVC": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name:          "Normal Skipped PV info",
			skippedPVName: "testPV",
			pvMap: map[string]pvcPvInfo{
				"velero/testPVC": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:       "testPVC",
					PVCNamespace:  "velero",
					PVName:        "testPV",
					Skipped:       true,
					SkippedReason: "CSI: skipped for PodVolumeBackup",
					PVInfo: &PVInfo{
						ReclaimPolicy: "Delete",
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			volumesInfo := BackupVolumesInformation{}
			volumesInfo.Init()

			if tc.skippedPVName != "" {
				volumesInfo.SkippedPVs = map[string]string{
					tc.skippedPVName: "CSI: skipped for PodVolumeBackup",
				}
			}

			if tc.pvMap != nil {
				for k, v := range tc.pvMap {
					if k == v.PV.Name {
						volumesInfo.pvMap.insert(v.PV, v.PVCName, v.PVCNamespace)
					}
				}
			}
			volumesInfo.logger = logging.DefaultLogger(logrus.DebugLevel, logging.FormatJSON)

			volumesInfo.generateVolumeInfoForSkippedPV()
			require.Equal(t, tc.expectedVolumeInfos, volumesInfo.volumeInfos)
		})
	}
}

func TestGenerateVolumeInfoForVeleroNativeSnapshot(t *testing.T) {
	tests := []struct {
		name                string
		nativeSnapshot      Snapshot
		pvMap               map[string]pvcPvInfo
		expectedVolumeInfos []*BackupVolumeInfo
	}{
		{
			name: "Native snapshot's IPOS pointer is nil",
			nativeSnapshot: Snapshot{
				Spec: SnapshotSpec{
					PersistentVolumeName: "testPV",
					VolumeIOPS:           nil,
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Cannot find info for the PV",
			nativeSnapshot: Snapshot{
				Spec: SnapshotSpec{
					PersistentVolumeName: "testPV",
					VolumeIOPS:           int64Ptr(100),
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Cannot find PV info in pvMap",
			pvMap: map[string]pvcPvInfo{
				"velero/testPVC": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			nativeSnapshot: Snapshot{
				Spec: SnapshotSpec{
					PersistentVolumeName: "testPV",
					VolumeIOPS:           int64Ptr(100),
					VolumeType:           "ssd",
					VolumeAZ:             "us-central1-a",
				},
				Status: SnapshotStatus{
					ProviderSnapshotID: "pvc-b31e3386-4bbb-4937-95d-7934cd62-b0a1-494b-95d7-0687440e8d0c",
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Normal native snapshot with failed phase",
			pvMap: map[string]pvcPvInfo{
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			nativeSnapshot: Snapshot{
				Spec: SnapshotSpec{
					PersistentVolumeName: "testPV",
					VolumeIOPS:           int64Ptr(100),
					VolumeType:           "ssd",
					VolumeAZ:             "us-central1-a",
				},
				Status: SnapshotStatus{
					ProviderSnapshotID: "pvc-b31e3386-4bbb-4937-95d-7934cd62-b0a1-494b-95d7-0687440e8d0c",
					Phase:              SnapshotPhaseFailed,
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PVName:       "testPV",
					BackupMethod: NativeSnapshot,
					Result:       VolumeResultFailed,
					PVInfo: &PVInfo{
						ReclaimPolicy: "Delete",
						Labels: map[string]string{
							"a": "b",
						},
					},
					NativeSnapshotInfo: &NativeSnapshotInfo{
						SnapshotHandle: "pvc-b31e3386-4bbb-4937-95d-7934cd62-b0a1-494b-95d7-0687440e8d0c",
						VolumeType:     "ssd",
						VolumeAZ:       "us-central1-a",
						IOPS:           "100",
						Phase:          SnapshotPhaseFailed,
					},
				},
			},
		},
		{
			name: "Normal native snapshot",
			pvMap: map[string]pvcPvInfo{
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			nativeSnapshot: Snapshot{
				Spec: SnapshotSpec{
					PersistentVolumeName: "testPV",
					VolumeIOPS:           int64Ptr(100),
					VolumeType:           "ssd",
					VolumeAZ:             "us-central1-a",
				},
				Status: SnapshotStatus{
					ProviderSnapshotID: "pvc-b31e3386-4bbb-4937-95d-7934cd62-b0a1-494b-95d7-0687440e8d0c",
					Phase:              SnapshotPhaseCompleted,
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PVName:       "testPV",
					BackupMethod: NativeSnapshot,
					Result:       VolumeResultSucceeded,
					PVInfo: &PVInfo{
						ReclaimPolicy: "Delete",
						Labels: map[string]string{
							"a": "b",
						},
					},
					NativeSnapshotInfo: &NativeSnapshotInfo{
						SnapshotHandle: "pvc-b31e3386-4bbb-4937-95d-7934cd62-b0a1-494b-95d7-0687440e8d0c",
						VolumeType:     "ssd",
						VolumeAZ:       "us-central1-a",
						IOPS:           "100",
						Phase:          SnapshotPhaseCompleted,
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			volumesInfo := BackupVolumesInformation{}
			volumesInfo.Init()
			volumesInfo.NativeSnapshots = append(volumesInfo.NativeSnapshots, &tc.nativeSnapshot)
			if tc.pvMap != nil {
				for k, v := range tc.pvMap {
					if k == v.PV.Name {
						volumesInfo.pvMap.insert(v.PV, v.PVCName, v.PVCNamespace)
					}
				}
			}
			volumesInfo.logger = logging.DefaultLogger(logrus.DebugLevel, logging.FormatJSON)

			volumesInfo.generateVolumeInfoForVeleroNativeSnapshot()
			require.Equal(t, tc.expectedVolumeInfos, volumesInfo.volumeInfos)
		})
	}
}

func TestGenerateVolumeInfoForCSIVolumeSnapshot(t *testing.T) {
	resourceQuantity := resource.MustParse("100Gi")
	now := metav1.Now()
	readyToUse := true
	tests := []struct {
		name                  string
		volumeSnapshot        snapshotv1api.VolumeSnapshot
		volumeSnapshotContent snapshotv1api.VolumeSnapshotContent
		volumeSnapshotClass   snapshotv1api.VolumeSnapshotClass
		pvMap                 map[string]pvcPvInfo
		operation             *itemoperation.BackupOperation
		expectedVolumeInfos   []*BackupVolumeInfo
	}{
		{
			name: "VS doesn't have VolumeSnapshotClass name",
			volumeSnapshot: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testVS",
					Namespace: "velero",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "VS doesn't have status",
			volumeSnapshot: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testVS",
					Namespace: "velero",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					VolumeSnapshotClassName: stringPtr("testClass"),
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "VS doesn't have PVC",
			volumeSnapshot: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testVS",
					Namespace: "velero",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					VolumeSnapshotClassName: stringPtr("testClass"),
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: stringPtr("testContent"),
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Cannot find VSC for VS",
			volumeSnapshot: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testVS",
					Namespace: "velero",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					VolumeSnapshotClassName: stringPtr("testClass"),
					Source: snapshotv1api.VolumeSnapshotSource{
						PersistentVolumeClaimName: stringPtr("testPVC"),
					},
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: stringPtr("testContent"),
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Cannot find BackupVolumeInfo for PVC",
			volumeSnapshot: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testVS",
					Namespace: "velero",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					VolumeSnapshotClassName: stringPtr("testClass"),
					Source: snapshotv1api.VolumeSnapshotSource{
						PersistentVolumeClaimName: stringPtr("testPVC"),
					},
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: stringPtr("testContent"),
				},
			},
			volumeSnapshotContent: *builder.ForVolumeSnapshotContent("testContent").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: stringPtr("testSnapshotHandle")}).Result(),
			expectedVolumeInfos:   []*BackupVolumeInfo{},
		},
		{
			name: "Normal VolumeSnapshot case",
			volumeSnapshot: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "testVS",
					Namespace:         "velero",
					CreationTimestamp: now,
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					VolumeSnapshotClassName: stringPtr("testClass"),
					Source: snapshotv1api.VolumeSnapshotSource{
						PersistentVolumeClaimName: stringPtr("testPVC"),
					},
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: stringPtr("testContent"),
					CreationTime:                   &now,
					RestoreSize:                    &resourceQuantity,
					ReadyToUse:                     &readyToUse,
				},
			},
			volumeSnapshotContent: *builder.ForVolumeSnapshotContent("testContent").Driver("pd.csi.storage.gke.io").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: stringPtr("testSnapshotHandle")}).Result(),
			pvMap: map[string]pvcPvInfo{
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			operation: &itemoperation.BackupOperation{
				Spec: itemoperation.BackupOperationSpec{
					OperationID: "testID",
					ResourceIdentifier: velero.ResourceIdentifier{
						GroupResource: schema.GroupResource{
							Group:    "snapshot.storage.k8s.io",
							Resource: "volumesnapshots",
						},
						Namespace: "velero",
						Name:      "testVS",
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:               "testPVC",
					PVCNamespace:          "velero",
					PVName:                "testPV",
					BackupMethod:          CSISnapshot,
					Result:                VolumeResultSucceeded,
					StartTimestamp:        &now,
					PreserveLocalSnapshot: true,
					CSISnapshotInfo: &CSISnapshotInfo{
						Driver:         "pd.csi.storage.gke.io",
						SnapshotHandle: "testSnapshotHandle",
						Size:           107374182400,
						VSCName:        "testContent",
						OperationID:    "testID",
						ReadyToUse:     &readyToUse,
					},
					PVInfo: &PVInfo{
						ReclaimPolicy: "Delete",
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			volumesInfo := BackupVolumesInformation{}
			volumesInfo.Init()

			if tc.pvMap != nil {
				for k, v := range tc.pvMap {
					if k == v.PV.Name {
						volumesInfo.pvMap.insert(v.PV, v.PVCName, v.PVCNamespace)
					}
				}
			}

			if tc.operation != nil {
				volumesInfo.BackupOperations = append(volumesInfo.BackupOperations, tc.operation)
			}

			volumesInfo.volumeSnapshots = []snapshotv1api.VolumeSnapshot{tc.volumeSnapshot}
			volumesInfo.volumeSnapshotContents = []snapshotv1api.VolumeSnapshotContent{tc.volumeSnapshotContent}
			volumesInfo.volumeSnapshotClasses = []snapshotv1api.VolumeSnapshotClass{tc.volumeSnapshotClass}
			volumesInfo.logger = logging.DefaultLogger(logrus.DebugLevel, logging.FormatJSON)

			volumesInfo.generateVolumeInfoForCSIVolumeSnapshot()
			require.Equal(t, tc.expectedVolumeInfos, volumesInfo.volumeInfos)
		})
	}
}

func TestGenerateVolumeInfoFromPVB(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name                string
		pvb                 *velerov1api.PodVolumeBackup
		pod                 *corev1api.Pod
		pvMap               map[string]pvcPvInfo
		expectedVolumeInfos []*BackupVolumeInfo
	}{
		{
			name:                "cannot find PVB's pod, should fail",
			pvb:                 builder.ForPodVolumeBackup("velero", "testPVB").PodName("testPod").PodNamespace("velero").Result(),
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "PVB doesn't have a related PVC",
			pvb:  builder.ForPodVolumeBackup("velero", "testPVB").PodName("testPod").PodNamespace("velero").Result(),
			pod: builder.ForPod("velero", "testPod").Containers(&corev1api.Container{
				Name: "test",
				VolumeMounts: []corev1api.VolumeMount{
					{
						Name:      "testVolume",
						MountPath: "/data",
					},
				},
			}).Volumes(
				&corev1api.Volume{
					Name: "",
					VolumeSource: corev1api.VolumeSource{
						HostPath: &corev1api.HostPathVolumeSource{},
					},
				},
			).Result(),
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:      "",
					PVCNamespace: "",
					PVName:       "",
					BackupMethod: PodVolumeBackup,
					BackupType:   velerov1api.BackupTypeIncremental,
					Result:       VolumeResultFailed,
					PVBInfo: &PodVolumeBackupInfo{
						PodName:      "testPod",
						PodNamespace: "velero",
					},
				},
			},
		},
		{
			name: "Backup doesn't have information for PVC",
			pvb:  builder.ForPodVolumeBackup("velero", "testPVB").PodName("testPod").PodNamespace("velero").Result(),
			pod: builder.ForPod("velero", "testPod").Containers(&corev1api.Container{
				Name: "test",
				VolumeMounts: []corev1api.VolumeMount{
					{
						Name:      "testVolume",
						MountPath: "/data",
					},
				},
			}).Volumes(
				&corev1api.Volume{
					Name: "",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "testPVC",
						},
					},
				},
			).Result(),
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "PVB's volume has a PVC with failed phase",
			pvMap: map[string]pvcPvInfo{
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			pvb: builder.ForPodVolumeBackup("velero", "testPVB").
				PodName("testPod").
				PodNamespace("velero").
				StartTimestamp(&now).
				CompletionTimestamp(&now).
				Phase(velerov1api.PodVolumeBackupPhaseFailed).
				Result(),
			pod: builder.ForPod("velero", "testPod").Containers(&corev1api.Container{
				Name: "test",
				VolumeMounts: []corev1api.VolumeMount{
					{
						Name:      "testVolume",
						MountPath: "/data",
					},
				},
			}).Volumes(
				&corev1api.Volume{
					Name: "",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "testPVC",
						},
					},
				},
			).Result(),
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:             "testPVC",
					PVCNamespace:        "velero",
					PVName:              "testPV",
					BackupMethod:        PodVolumeBackup,
					BackupType:          velerov1api.BackupTypeIncremental,
					StartTimestamp:      &now,
					CompletionTimestamp: &now,
					Result:              VolumeResultFailed,
					PVBInfo: &PodVolumeBackupInfo{
						PodName:      "testPod",
						PodNamespace: "velero",
						Phase:        velerov1api.PodVolumeBackupPhaseFailed,
					},
					PVInfo: &PVInfo{
						ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
						Labels:        map[string]string{"a": "b"},
					},
				},
			},
		},
		{
			name: "PVB's volume has a PVC",
			pvMap: map[string]pvcPvInfo{
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			pvb: builder.ForPodVolumeBackup("velero", "testPVB").
				PodName("testPod").
				PodNamespace("velero").
				StartTimestamp(&now).
				CompletionTimestamp(&now).
				Phase(velerov1api.PodVolumeBackupPhaseCompleted).
				Result(),
			pod: builder.ForPod("velero", "testPod").Containers(&corev1api.Container{
				Name: "test",
				VolumeMounts: []corev1api.VolumeMount{
					{
						Name:      "testVolume",
						MountPath: "/data",
					},
				},
			}).Volumes(
				&corev1api.Volume{
					Name: "",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "testPVC",
						},
					},
				},
			).Result(),
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:             "testPVC",
					PVCNamespace:        "velero",
					PVName:              "testPV",
					BackupMethod:        PodVolumeBackup,
					BackupType:          velerov1api.BackupTypeIncremental,
					StartTimestamp:      &now,
					CompletionTimestamp: &now,
					Result:              VolumeResultSucceeded,
					PVBInfo: &PodVolumeBackupInfo{
						PodName:      "testPod",
						PodNamespace: "velero",
						Phase:        velerov1api.PodVolumeBackupPhaseCompleted,
					},
					PVInfo: &PVInfo{
						ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
						Labels:        map[string]string{"a": "b"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			volumesInfo := BackupVolumesInformation{}
			volumesInfo.Init()
			volumesInfo.crClient = velerotest.NewFakeControllerRuntimeClient(t)

			volumesInfo.PodVolumeBackups = append(volumesInfo.PodVolumeBackups, tc.pvb)

			if tc.pvMap != nil {
				for k, v := range tc.pvMap {
					if k == v.PV.Name {
						volumesInfo.pvMap.insert(v.PV, v.PVCName, v.PVCNamespace)
					}
				}
			}
			if tc.pod != nil {
				require.NoError(t, volumesInfo.crClient.Create(t.Context(), tc.pod))
			}
			volumesInfo.logger = logging.DefaultLogger(logrus.DebugLevel, logging.FormatJSON)

			volumesInfo.generateVolumeInfoFromPVB()
			require.Equal(t, tc.expectedVolumeInfos, volumesInfo.volumeInfos)
		})
	}
}

func TestGenerateVolumeInfoFromDataUpload(t *testing.T) {
	// The unstructured conversion will loose the time precision to second
	// level. To make test pass. Set the now precision at second at the
	// beginning.
	now := metav1.Now().Rfc3339Copy()
	features.Enable(velerov1api.CSIFeatureFlag)
	defer features.Disable(velerov1api.CSIFeatureFlag)
	tests := []struct {
		name                string
		vs                  *snapshotv1api.VolumeSnapshot
		vsc                 *snapshotv1api.VolumeSnapshotContent
		dataUpload          *velerov2alpha1.DataUpload
		operation           *itemoperation.BackupOperation
		pvMap               map[string]pvcPvInfo
		expectedVolumeInfos []*BackupVolumeInfo
	}{
		{
			name: "Operation is not for PVC",
			operation: &itemoperation.BackupOperation{
				Spec: itemoperation.BackupOperationSpec{
					ResourceIdentifier: velero.ResourceIdentifier{
						GroupResource: schema.GroupResource{
							Group:    "",
							Resource: "configmaps",
						},
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Operation doesn't have DataUpload PostItemOperation",
			operation: &itemoperation.BackupOperation{
				Spec: itemoperation.BackupOperationSpec{
					ResourceIdentifier: velero.ResourceIdentifier{
						GroupResource: schema.GroupResource{
							Group:    "",
							Resource: "persistentvolumeclaims",
						},
						Namespace: "velero",
						Name:      "testPVC",
					},
					PostOperationItems: []velero.ResourceIdentifier{
						{
							GroupResource: schema.GroupResource{
								Group:    "",
								Resource: "configmaps",
							},
						},
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "DataUpload cannot be found for operation",
			operation: &itemoperation.BackupOperation{
				Spec: itemoperation.BackupOperationSpec{
					OperationID: "testOperation",
					ResourceIdentifier: velero.ResourceIdentifier{
						GroupResource: schema.GroupResource{
							Group:    "",
							Resource: "persistentvolumeclaims",
						},
						Namespace: "velero",
						Name:      "testPVC",
					},
					PostOperationItems: []velero.ResourceIdentifier{
						{
							GroupResource: schema.GroupResource{
								Group:    "velero.io",
								Resource: "datauploads",
							},
							Namespace: "velero",
							Name:      "testDU",
						},
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{},
		},
		{
			name: "Normal DataUpload case",
			dataUpload: builder.ForDataUpload("velero", "testDU").
				DataMover("velero").
				CSISnapshot(&velerov2alpha1.CSISnapshotSpec{
					VolumeSnapshot: "vs-01",
					SnapshotClass:  "testClass",
					Driver:         "pd.csi.storage.gke.io",
				}).SnapshotID("testSnapshotHandle").
				StartTimestamp(&now).
				CompletionTimestamp(&now).
				TotalBytes(1024).
				IncrementalBytes(512).
				Phase(velerov2alpha1.DataUploadPhaseCompleted).
				Result(),
			vs:  builder.ForVolumeSnapshot(velerov1api.DefaultNamespace, "vs-01").Status().BoundVolumeSnapshotContentName("vsc-01").Result(),
			vsc: builder.ForVolumeSnapshotContent("vsc-01").Driver("pd.csi.storage.gke.io").Result(),
			operation: &itemoperation.BackupOperation{
				Spec: itemoperation.BackupOperationSpec{
					OperationID: "testOperation",
					ResourceIdentifier: velero.ResourceIdentifier{
						GroupResource: schema.GroupResource{
							Group:    "",
							Resource: "persistentvolumeclaims",
						},
						Namespace: "velero",
						Name:      "testPVC",
					},
					PostOperationItems: []velero.ResourceIdentifier{
						{
							GroupResource: schema.GroupResource{
								Group:    "velero.io",
								Resource: "datauploads",
							},
							Namespace: "velero",
							Name:      "testDU",
						},
					},
				},
			},
			pvMap: map[string]pvcPvInfo{
				"testPV": {
					PVCName:      "testPVC",
					PVCNamespace: "velero",
					PV: corev1api.PersistentVolume{
						ObjectMeta: metav1.ObjectMeta{
							Name:   "testPV",
							Labels: map[string]string{"a": "b"},
						},
						Spec: corev1api.PersistentVolumeSpec{
							PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
						},
					},
				},
			},
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVCName:             "testPVC",
					PVCNamespace:        "velero",
					PVName:              "testPV",
					BackupMethod:        CSISnapshot,
					SnapshotDataMoved:   true,
					BackupType:          velerov1api.BackupTypeIncremental,
					Result:              VolumeResultSucceeded,
					StartTimestamp:      &now,
					CompletionTimestamp: &now,
					CSISnapshotInfo: &CSISnapshotInfo{
						VSCName:        FieldValueIsUnknown,
						SnapshotHandle: FieldValueIsUnknown,
						OperationID:    FieldValueIsUnknown,
						Size:           0,
						Driver:         "pd.csi.storage.gke.io",
					},
					SnapshotDataMovementInfo: &BackupSnapshotDataMovementInfo{
						DataMover:       "velero",
						UploaderType:    "kopia",
						OperationID:     "testOperation",
						Phase:           velerov2alpha1.DataUploadPhaseCompleted,
						SnapshotHandle:  "testSnapshotHandle",
						Size:            1024,
						IncrementalSize: ptr.To(int64(512)),
					},
					PVInfo: &PVInfo{
						ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
						Labels:        map[string]string{"a": "b"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			volumesInfo := BackupVolumesInformation{}
			volumesInfo.Init()

			if tc.operation != nil {
				volumesInfo.BackupOperations = append(volumesInfo.BackupOperations, tc.operation)
			}

			if tc.pvMap != nil {
				for k, v := range tc.pvMap {
					if k == v.PV.Name {
						volumesInfo.pvMap.insert(v.PV, v.PVCName, v.PVCNamespace)
					}
				}
			}

			objects := make([]runtime.Object, 0)
			if tc.dataUpload != nil {
				objects = append(objects, tc.dataUpload)
			}
			if tc.vs != nil {
				objects = append(objects, tc.vs)
			}
			if tc.vsc != nil {
				objects = append(objects, tc.vsc)
			}
			volumesInfo.crClient = velerotest.NewFakeControllerRuntimeClient(t, objects...)

			volumesInfo.logger = logging.DefaultLogger(logrus.DebugLevel, logging.FormatJSON)

			volumesInfo.generateVolumeInfoFromDataUpload()

			if len(tc.expectedVolumeInfos) > 0 {
				require.Equal(t, tc.expectedVolumeInfos[0].PVInfo, volumesInfo.volumeInfos[0].PVInfo)
				require.Equal(t, tc.expectedVolumeInfos[0].SnapshotDataMovementInfo, volumesInfo.volumeInfos[0].SnapshotDataMovementInfo)
				require.Equal(t, tc.expectedVolumeInfos[0].CSISnapshotInfo, volumesInfo.volumeInfos[0].CSISnapshotInfo)
				require.Equal(t, tc.expectedVolumeInfos[0].Result, volumesInfo.volumeInfos[0].Result)
				require.Equal(t, tc.expectedVolumeInfos[0].StartTimestamp, volumesInfo.volumeInfos[0].StartTimestamp)
				require.Equal(t, tc.expectedVolumeInfos[0].CompletionTimestamp, volumesInfo.volumeInfos[0].CompletionTimestamp)
			}
		})
	}
}

func TestRestoreVolumeInfoTrackNativeSnapshot(t *testing.T) {
	fakeCilent := velerotest.NewFakeControllerRuntimeClient(t)

	restore := builder.ForRestore("velero", "testRestore").Result()
	tracker := NewRestoreVolInfoTracker(restore, logrus.New(), fakeCilent)
	tracker.TrackNativeSnapshot("testPV", "snap-001", "ebs", "us-west-1", 10000)
	assert.Equal(t, NativeSnapshotInfo{
		SnapshotHandle: "snap-001",
		VolumeType:     "ebs",
		VolumeAZ:       "us-west-1",
		IOPS:           "10000",
	}, *tracker.pvNativeSnapshotMap["testPV"])
	tracker.TrackNativeSnapshot("testPV", "snap-002", "ebs", "us-west-2", 15000)
	assert.Equal(t, NativeSnapshotInfo{
		SnapshotHandle: "snap-002",
		VolumeType:     "ebs",
		VolumeAZ:       "us-west-2",
		IOPS:           "15000",
	}, *tracker.pvNativeSnapshotMap["testPV"])
	tracker.RenamePVForNativeSnapshot("testPV", "newPV")
	_, ok := tracker.pvNativeSnapshotMap["testPV"]
	assert.False(t, ok)
	assert.Equal(t, NativeSnapshotInfo{
		SnapshotHandle: "snap-002",
		VolumeType:     "ebs",
		VolumeAZ:       "us-west-2",
		IOPS:           "15000",
	}, *tracker.pvNativeSnapshotMap["newPV"])
}

func TestRestoreVolumeInfoResult(t *testing.T) {
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t,
		builder.ForPod("testNS", "testPod").
			Volumes(builder.ForVolume("data-volume-1").PersistentVolumeClaimSource("testPVC2").Result()).
			Result())
	testRestore := builder.ForRestore("velero", "testRestore").Result()
	tests := []struct {
		name               string
		tracker            *RestoreVolumeInfoTracker
		expectResultValues []RestoreVolumeInfo
	}{
		{
			name: "empty",
			tracker: &RestoreVolumeInfoTracker{
				Mutex:   &sync.Mutex{},
				client:  fakeClient,
				log:     logrus.New(),
				restore: testRestore,
				pvPvc: &pvcPvMap{
					data: make(map[string]pvcPvInfo),
				},
				pvNativeSnapshotMap: map[string]*NativeSnapshotInfo{},
				pvcCSISnapshotMap:   map[string]snapshotv1api.VolumeSnapshot{},
				datadownloadList:    &velerov2alpha1.DataDownloadList{},
				pvrs:                []*velerov1api.PodVolumeRestore{},
			},
			expectResultValues: []RestoreVolumeInfo{},
		},
		{
			name: "native snapshot and podvolumes",
			tracker: &RestoreVolumeInfoTracker{
				Mutex:   &sync.Mutex{},
				client:  fakeClient,
				log:     logrus.New(),
				restore: testRestore,
				pvPvc: &pvcPvMap{
					data: map[string]pvcPvInfo{
						"testPV": {
							PVCName:      "testPVC",
							PVCNamespace: "testNS",
							PV:           *builder.ForPersistentVolume("testPV").Result(),
						},
						"testPV2": {
							PVCName:      "testPVC2",
							PVCNamespace: "testNS",
							PV:           *builder.ForPersistentVolume("testPV2").Result(),
						},
					},
				},
				pvNativeSnapshotMap: map[string]*NativeSnapshotInfo{
					"testPV": {
						SnapshotHandle: "snap-001",
						VolumeType:     "ebs",
						VolumeAZ:       "us-west-1",
						IOPS:           "10000",
					},
				},
				pvcCSISnapshotMap: map[string]snapshotv1api.VolumeSnapshot{},
				datadownloadList:  &velerov2alpha1.DataDownloadList{},
				pvrs: []*velerov1api.PodVolumeRestore{
					builder.ForPodVolumeRestore("velero", "testRestore-1234").
						PodNamespace("testNS").
						PodName("testPod").
						Volume("data-volume-1").
						UploaderType("kopia").
						SnapshotID("pvr-snap-001").Result(),
				},
			},
			expectResultValues: []RestoreVolumeInfo{
				{
					PVCName:           "testPVC2",
					PVCNamespace:      "testNS",
					PVName:            "testPV2",
					RestoreMethod:     PodVolumeRestore,
					SnapshotDataMoved: false,
					PVRInfo: &PodVolumeRestoreInfo{
						SnapshotHandle: "pvr-snap-001",
						PodName:        "testPod",
						PodNamespace:   "testNS",
						UploaderType:   "kopia",
						VolumeName:     "data-volume-1",
					},
				},
				{
					PVCName:           "testPVC",
					PVCNamespace:      "testNS",
					PVName:            "testPV",
					RestoreMethod:     NativeSnapshot,
					SnapshotDataMoved: false,
					NativeSnapshotInfo: &NativeSnapshotInfo{
						SnapshotHandle: "snap-001",
						VolumeType:     "ebs",
						VolumeAZ:       "us-west-1",
						IOPS:           "10000",
					},
				},
			},
		},
		{
			name: "CSI snapshot without datamovement and podvolumes",
			tracker: &RestoreVolumeInfoTracker{
				Mutex:   &sync.Mutex{},
				client:  fakeClient,
				log:     logrus.New(),
				restore: testRestore,
				pvPvc: &pvcPvMap{
					data: map[string]pvcPvInfo{
						"testPV": {
							PVCName:      "testPVC",
							PVCNamespace: "testNS",
							PV:           *builder.ForPersistentVolume("testPV").Result(),
						},
						"testPV2": {
							PVCName:      "testPVC2",
							PVCNamespace: "testNS",
							PV:           *builder.ForPersistentVolume("testPV2").Result(),
						},
					},
				},
				pvNativeSnapshotMap: map[string]*NativeSnapshotInfo{},
				pvcCSISnapshotMap: map[string]snapshotv1api.VolumeSnapshot{
					"testNS/testPVC": *builder.ForVolumeSnapshot("sourceNS", "testCSISnapshot").
						ObjectMeta(
							builder.WithAnnotations(velerov1api.VolumeSnapshotHandleAnnotation, "csi-snap-001",
								velerov1api.DriverNameAnnotation, "test-csi-driver"),
						).SourceVolumeSnapshotContentName("test-vsc-001").
						Status().RestoreSize("1Gi").Result(),
				},
				datadownloadList: &velerov2alpha1.DataDownloadList{},
				pvrs: []*velerov1api.PodVolumeRestore{
					builder.ForPodVolumeRestore("velero", "testRestore-1234").
						PodNamespace("testNS").
						PodName("testPod").
						Volume("data-volume-1").
						UploaderType("kopia").
						SnapshotID("pvr-snap-001").Result(),
				},
			},
			expectResultValues: []RestoreVolumeInfo{
				{
					PVCName:           "testPVC2",
					PVCNamespace:      "testNS",
					PVName:            "testPV2",
					RestoreMethod:     PodVolumeRestore,
					SnapshotDataMoved: false,
					PVRInfo: &PodVolumeRestoreInfo{
						SnapshotHandle: "pvr-snap-001",
						PodName:        "testPod",
						PodNamespace:   "testNS",
						UploaderType:   "kopia",
						VolumeName:     "data-volume-1",
					},
				},
				{
					PVCName:           "testPVC",
					PVCNamespace:      "testNS",
					PVName:            "testPV",
					RestoreMethod:     CSISnapshot,
					SnapshotDataMoved: false,
					CSISnapshotInfo: &CSISnapshotInfo{
						SnapshotHandle: "csi-snap-001",
						VSCName:        "test-vsc-001",
						Size:           1073741824,
						Driver:         "test-csi-driver",
					},
				},
			},
		},
		{
			name: "CSI snapshot with datamovement",
			tracker: &RestoreVolumeInfoTracker{
				Mutex:   &sync.Mutex{},
				client:  fakeClient,
				log:     logrus.New(),
				restore: testRestore,
				pvPvc: &pvcPvMap{
					data: map[string]pvcPvInfo{
						"testPV": {
							PVCName:      "testPVC",
							PVCNamespace: "testNS",
							PV:           *builder.ForPersistentVolume("testPV").Result(),
						},
						"testPV2": {
							PVCName:      "testPVC2",
							PVCNamespace: "testNS",
							PV:           *builder.ForPersistentVolume("testPV2").Result(),
						},
					},
				},
				pvNativeSnapshotMap: map[string]*NativeSnapshotInfo{},
				pvcCSISnapshotMap:   map[string]snapshotv1api.VolumeSnapshot{},
				datadownloadList: &velerov2alpha1.DataDownloadList{
					Items: []velerov2alpha1.DataDownload{
						*builder.ForDataDownload("velero", "testDataDownload-1").
							ObjectMeta(builder.WithLabels(velerov1api.AsyncOperationIDLabel, "dd-operation-001")).
							SnapshotID("dd-snap-001").
							TargetVolume(velerov2alpha1.TargetVolumeSpec{
								PVC:       "testPVC",
								Namespace: "testNS",
							}).
							Phase(velerov2alpha1.DataDownloadPhaseCompleted).
							Progress(veleroshared.DataMoveOperationProgress{TotalBytes: 2048}).
							RestoreType("Incremental").
							Result(),
						*builder.ForDataDownload("velero", "testDataDownload-2").
							ObjectMeta(builder.WithLabels(velerov1api.AsyncOperationIDLabel, "dd-operation-002")).
							SnapshotID("dd-snap-002").
							TargetVolume(velerov2alpha1.TargetVolumeSpec{
								PVC:       "testPVC2",
								Namespace: "testNS",
							}).
							Phase(velerov2alpha1.DataDownloadPhaseCompleted).
							Progress(veleroshared.DataMoveOperationProgress{TotalBytes: 4096}).
							RestoreType("Full").
							Result(),
					},
				},
				pvrs: []*velerov1api.PodVolumeRestore{},
			},
			expectResultValues: []RestoreVolumeInfo{
				{
					PVCName:           "testPVC",
					PVCNamespace:      "testNS",
					PVName:            "testPV",
					RestoreMethod:     CSISnapshot,
					SnapshotDataMoved: true,
					SnapshotDataMovementInfo: &RestoreSnapshotDataMovementInfo{
						DataMover:      "velero",
						UploaderType:   velerov1api.BackupRepositoryTypeKopia,
						SnapshotHandle: "dd-snap-001",
						OperationID:    "dd-operation-001",
						Phase:          velerov2alpha1.DataDownloadPhaseCompleted,
						Size:           2048,
						RestoreType:    "Incremental",
					},
				},
				{
					PVCName:           "testPVC2",
					PVCNamespace:      "testNS",
					PVName:            "testPV2",
					RestoreMethod:     CSISnapshot,
					SnapshotDataMoved: true,
					SnapshotDataMovementInfo: &RestoreSnapshotDataMovementInfo{
						DataMover:      "velero",
						UploaderType:   velerov1api.BackupRepositoryTypeKopia,
						SnapshotHandle: "dd-snap-002",
						OperationID:    "dd-operation-002",
						Phase:          velerov2alpha1.DataDownloadPhaseCompleted,
						Size:           4096,
						RestoreType:    "Full",
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.tracker.Result()
			valuesList := []RestoreVolumeInfo{}
			for _, item := range result {
				valuesList = append(valuesList, *item)
			}
			assert.Equal(t, tc.expectResultValues, valuesList)
		})
	}
}

func stringPtr(str string) *string {
	return &str
}

func int64Ptr(val int) *int64 {
	i := int64(val)
	return &i
}

func TestGetVolumeSnapshotClasses(t *testing.T) {
	class := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "class",
			ResourceVersion: "999",
		},
	}
	volumesInfo := BackupVolumesInformation{
		logger:   logging.DefaultLogger(logrus.DebugLevel, logging.FormatJSON),
		crClient: velerotest.NewFakeControllerRuntimeClient(t, class),
	}

	result, err := volumesInfo.getVolumeSnapshotClasses()
	require.NoError(t, err)
	require.Equal(t, []snapshotv1api.VolumeSnapshotClass{*class}, result)
}

func TestBackupVolumeInfoJSONRoundTrip(t *testing.T) {
	orig := BackupVolumeInfo{
		PVCName:               "pvc-1",
		PVCNamespace:          "ns-1",
		PVName:                "pv-1",
		BackupMethod:          CSISnapshot,
		SnapshotDataMoved:     true,
		PreserveLocalSnapshot: false,
		Skipped:               false,
		Result:                VolumeResultSucceeded,
		BackupType:            velerov1api.BackupTypeIncremental,
		CSISnapshotInfo: &CSISnapshotInfo{
			SnapshotHandle:            "csi-snap-1",
			Size:                      2000,
			Driver:                    "csi.driver.com",
			VSCName:                   "vsc-1",
			OperationID:               "op-2",
			VolumeGroupSnapshotHandle: "vgsh-1",
		},
		SnapshotDataMovementInfo: &BackupSnapshotDataMovementInfo{
			DataMover:        "velero",
			UploaderType:     "kopia",
			RetainedSnapshot: "retain-1",
			SnapshotHandle:   "snap-1",
			OperationID:      "op-1",
			Size:             1000,
			IncrementalSize:  int64Ptr(200),
			ParentSnapshot:   "parent-1",
			Phase:            velerov2alpha1.DataUploadPhaseCompleted,
		},
		NativeSnapshotInfo: &NativeSnapshotInfo{
			SnapshotHandle: "native-snap-1",
			VolumeType:     "gp3",
			VolumeAZ:       "us-west-2a",
			IOPS:           "3000",
		},
		PVBInfo: &PodVolumeBackupInfo{
			SnapshotHandle:  "pvb-snap-1",
			Size:            500,
			IncrementalSize: int64Ptr(50),
			UploaderType:    "kopia",
			VolumeName:      "vol-1",
			PodName:         "pod-1",
			PodNamespace:    "ns-1",
			NodeName:        "node-1",
			Phase:           velerov1api.PodVolumeBackupPhaseCompleted,
		},
		PVInfo: &PVInfo{
			ReclaimPolicy: "Delete",
			Labels:        map[string]string{"env": "test"},
		},
	}

	data, err := json.Marshal(orig)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"pvcName":"pvc-1"`)
	assert.Contains(t, jsonStr, `"pvcNamespace":"ns-1"`)
	assert.Contains(t, jsonStr, `"pvName":"pv-1"`)
	assert.Contains(t, jsonStr, `"backupMethod":"CSISnapshot"`)
	assert.Contains(t, jsonStr, `"snapshotDataMoved":true`)
	assert.Contains(t, jsonStr, `"result":"succeeded"`)
	assert.Contains(t, jsonStr, `"backupType":"Incremental"`)
	assert.Contains(t, jsonStr, `"snapshotDataMovementInfo":{`)
	assert.Contains(t, jsonStr, `"dataMover":"velero"`)
	assert.Contains(t, jsonStr, `"uploaderType":"kopia"`)
	assert.Contains(t, jsonStr, `"retainedSnapshot":"retain-1"`)
	assert.Contains(t, jsonStr, `"snapshotHandle":"snap-1"`)
	assert.Contains(t, jsonStr, `"operationID":"op-1"`)
	assert.Contains(t, jsonStr, `"size":1000`)
	assert.Contains(t, jsonStr, `"incrementalSize":200`)
	assert.Contains(t, jsonStr, `"parentSnapshot":"parent-1"`)
	assert.Contains(t, jsonStr, `"phase":"Completed"`)
	assert.Contains(t, jsonStr, `"pvbInfo":{`)
	assert.Contains(t, jsonStr, `"podName":"pod-1"`)
	assert.Contains(t, jsonStr, `"podNamespace":"ns-1"`)
	assert.Contains(t, jsonStr, `"nodeName":"node-1"`)
	assert.Contains(t, jsonStr, `"csiSnapshotInfo":{`)
	assert.Contains(t, jsonStr, `"driver":"csi.driver.com"`)
	assert.Contains(t, jsonStr, `"vscName":"vsc-1"`)
	assert.Contains(t, jsonStr, `"volumeGroupSnapshotHandle":"vgsh-1"`)
	assert.Contains(t, jsonStr, `"nativeSnapshotInfo":{`)
	assert.Contains(t, jsonStr, `"volumeType":"gp3"`)
	assert.Contains(t, jsonStr, `"volumeAZ":"us-west-2a"`)
	assert.Contains(t, jsonStr, `"iops":"3000"`)
	assert.Contains(t, jsonStr, `"pvInfo":{`)
	assert.Contains(t, jsonStr, `"reclaimPolicy":"Delete"`)

	var unmarshaled BackupVolumeInfo
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, orig, unmarshaled)
}

func TestRestoreVolumeInfoJSONRoundTrip(t *testing.T) {
	orig := RestoreVolumeInfo{
		PVCName:           "pvc-2",
		PVCNamespace:      "ns-2",
		PVName:            "pv-2",
		RestoreMethod:     CSISnapshot,
		SnapshotDataMoved: true,
		SnapshotDataMovementInfo: &RestoreSnapshotDataMovementInfo{
			DataMover:        "velero",
			UploaderType:     "kopia",
			RetainedSnapshot: "retain-2",
			SnapshotHandle:   "snap-2",
			OperationID:      "op-3",
			Size:             3000,
			IncrementalSize:  int64Ptr(300),
			Phase:            velerov2alpha1.DataDownloadPhaseCompleted,
			RestoreType:      "Incremental",
		},
		PVRInfo: &PodVolumeRestoreInfo{
			SnapshotHandle:  "pvr-snap-1",
			Size:            600,
			IncrementalSize: int64Ptr(60),
			UploaderType:    "kopia",
			VolumeName:      "vol-2",
			PodName:         "pod-2",
			PodNamespace:    "ns-2",
			NodeName:        "node-2",
			Phase:           velerov1api.PodVolumeRestorePhaseCompleted,
			RestoreType:     "Incremental",
		},
		CSISnapshotInfo: &CSISnapshotInfo{
			SnapshotHandle: "csi-snap-2",
			Size:           4000,
			Driver:         "csi.driver.com",
			VSCName:        "vsc-2",
		},
		NativeSnapshotInfo: &NativeSnapshotInfo{
			SnapshotHandle: "native-snap-2",
			VolumeType:     "ebs",
			VolumeAZ:       "us-east-1a",
			IOPS:           "1000",
		},
	}

	data, err := json.Marshal(orig)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"pvcName":"pvc-2"`)
	assert.Contains(t, jsonStr, `"pvcNamespace":"ns-2"`)
	assert.Contains(t, jsonStr, `"pvName":"pv-2"`)
	assert.Contains(t, jsonStr, `"restoreMethod":"CSISnapshot"`)
	assert.Contains(t, jsonStr, `"snapshotDataMoved":true`)
	assert.Contains(t, jsonStr, `"snapshotDataMovementInfo":{`)
	assert.Contains(t, jsonStr, `"dataMover":"velero"`)
	assert.Contains(t, jsonStr, `"uploaderType":"kopia"`)
	assert.Contains(t, jsonStr, `"retainedSnapshot":"retain-2"`)
	assert.Contains(t, jsonStr, `"snapshotHandle":"snap-2"`)
	assert.Contains(t, jsonStr, `"operationID":"op-3"`)
	assert.Contains(t, jsonStr, `"size":3000`)
	assert.Contains(t, jsonStr, `"incrementalSize":300`)
	assert.Contains(t, jsonStr, `"phase":"Completed"`)
	assert.Contains(t, jsonStr, `"restoreType":"Incremental"`)
	assert.Contains(t, jsonStr, `"pvrInfo":{`)
	assert.Contains(t, jsonStr, `"podName":"pod-2"`)
	assert.Contains(t, jsonStr, `"podNamespace":"ns-2"`)
	assert.Contains(t, jsonStr, `"nodeName":"node-2"`)
	assert.Contains(t, jsonStr, `"csiSnapshotInfo":{`)
	assert.Contains(t, jsonStr, `"nativeSnapshotInfo":{`)

	var unmarshaled RestoreVolumeInfo
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, orig, unmarshaled)
}
