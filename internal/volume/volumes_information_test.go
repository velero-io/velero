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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	veleroshared "github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

func TestGenerateVolumeInfoForSkippedVolume(t *testing.T) {
	tests := []struct {
		name                string
		skippedVolumeName   string
		skippedPVCName      string
		skippedPVCNamespace string
		pvMap               map[string]pvcPvInfo
		expectedVolumeInfos []*BackupVolumeInfo
	}{
		{
			name:                "Skipped volume with empty PV name but with PVC info",
			skippedVolumeName:   "",
			skippedPVCName:      "testPVC",
			skippedPVCNamespace: "velero",
			pvMap:               map[string]pvcPvInfo{},
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVName:        "",
					PVCName:       "testPVC",
					PVCNamespace:  "velero",
					Skipped:       true,
					SkippedReason: "CSI: skipped for PodVolumeBackup",
				},
			},
		},
		{
			name:              "Cannot find info for PV",
			skippedVolumeName: "testPV",
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
			expectedVolumeInfos: []*BackupVolumeInfo{
				{
					PVName:        "testPV",
					Skipped:       true,
					SkippedReason: "CSI: skipped for PodVolumeBackup",
				},
			},
		},
		{
			name:              "Normal Skipped Volume info",
			skippedVolumeName: "testPV",
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

			if tc.skippedVolumeName != "" || tc.skippedPVCName != "" {
				volumesInfo.SkippedVolumes = []SkippedVolume{
					{
						PVName:       tc.skippedVolumeName,
						PVCName:      tc.skippedPVCName,
						PVCNamespace: tc.skippedPVCNamespace,
						Reasons:      "CSI: skipped for PodVolumeBackup",
					},
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

			volumesInfo.generateVolumeInfoForSkippedVolume()
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
				TotalBytes(1024).
				IncrementalBytes(512).
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
						PodName:         "testPod",
						PodNamespace:    "velero",
						Phase:           velerov1api.PodVolumeBackupPhaseCompleted,
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
		{
			name: "PVB's volume has a PVC with fallback to full",
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
			pvb: func() *velerov1api.PodVolumeBackup {
				pvb := builder.ForPodVolumeBackup("velero", "testPVB").
					PodName("testPod").
					PodNamespace("velero").
					StartTimestamp(&now).
					CompletionTimestamp(&now).
					Phase(velerov1api.PodVolumeBackupPhaseCompleted).
					TotalBytes(1024).
					IncrementalBytes(512).
					Result()
				pvb.Status.FallbackFull = true
				return pvb
			}(),
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
					FallbackFull:        true,
					StartTimestamp:      &now,
					CompletionTimestamp: &now,
					Result:              VolumeResultSucceeded,
					PVBInfo: &PodVolumeBackupInfo{
						PodName:         "testPod",
						PodNamespace:    "velero",
						Phase:           velerov1api.PodVolumeBackupPhaseCompleted,
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
				pvrs: []*velerov1api.PodVolumeRestore{
					builder.ForPodVolumeRestore("velero", "testRestore-1234").
						PodNamespace("testNS").
						PodName("testPod").
						Volume("data-volume-1").
						UploaderType("kopia").
						SnapshotID("pvr-snap-001").
						Phase(velerov1api.PodVolumeRestorePhaseCompleted).
						RestoreType("Incremental").
						TotalBytes(1024).
						IncrementalBytes(512).
						Result(),
				},
			},
			expectResultValues: []RestoreVolumeInfo{
				{
					PVCName:           "testPVC2",
					PVCNamespace:      "testNS",
					PVName:            "testPV2",
					RestoreMethod:     PodVolumeRestore,
					SnapshotDataMoved: false,
					RestoreType:       "Incremental",
					PVRInfo: &PodVolumeRestoreInfo{
						SnapshotHandle:  "pvr-snap-001",
						PodName:         "testPod",
						PodNamespace:    "testNS",
						UploaderType:    "kopia",
						VolumeName:      "data-volume-1",
						Phase:           velerov1api.PodVolumeRestorePhaseCompleted,
						Size:            1024,
						IncrementalSize: ptr.To(int64(512)),
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
		FallbackFull:          true,
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
	assert.Contains(t, jsonStr, `"fallbackFull":true`)
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
		RestoreType:       "Incremental",
		FallbackFull:      true,
		SnapshotDataMovementInfo: &RestoreSnapshotDataMovementInfo{
			DataMover:        "velero",
			UploaderType:     "kopia",
			RetainedSnapshot: "retain-2",
			SnapshotHandle:   "snap-2",
			OperationID:      "op-3",
			Size:             3000,
			IncrementalSize:  int64Ptr(300),
			Phase:            velerov2alpha1.DataDownloadPhaseCompleted,
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
	assert.Contains(t, jsonStr, `"fallbackFull":true`)
	assert.Contains(t, jsonStr, `"pvrInfo":{`)
	assert.Contains(t, jsonStr, `"podName":"pod-2"`)
	assert.Contains(t, jsonStr, `"podNamespace":"ns-2"`)
	assert.Contains(t, jsonStr, `"nodeName":"node-2"`)
	assert.Contains(t, jsonStr, `"incrementalSize":60`)
	assert.Contains(t, jsonStr, `"csiSnapshotInfo":{`)
	assert.Contains(t, jsonStr, `"nativeSnapshotInfo":{`)

	var unmarshaled RestoreVolumeInfo
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, orig, unmarshaled)
}

func TestNewPodVolumeInfoFromPVR(t *testing.T) {
	tests := []struct {
		name     string
		pvr      *velerov1api.PodVolumeRestore
		expected *PodVolumeRestoreInfo
	}{
		{
			name: "all fields populated including incremental bytes and restore type",
			pvr: builder.ForPodVolumeRestore("velero", "pvr-1").
				SnapshotID("snap-1").
				Volume("vol-1").
				PodName("pod-1").
				PodNamespace("ns-1").
				UploaderType("kopia").
				Phase(velerov1api.PodVolumeRestorePhaseCompleted).
				RestoreType("Incremental").
				TotalBytes(2048).
				IncrementalBytes(512).
				Result(),
			expected: &PodVolumeRestoreInfo{
				SnapshotHandle:  "snap-1",
				Size:            2048,
				IncrementalSize: ptr.To(int64(512)),
				UploaderType:    "kopia",
				VolumeName:      "vol-1",
				PodName:         "pod-1",
				PodNamespace:    "ns-1",
				Phase:           velerov1api.PodVolumeRestorePhaseCompleted,
			},
		},
		{
			name: "optional fields empty or nil",
			pvr: builder.ForPodVolumeRestore("velero", "pvr-2").
				SnapshotID("snap-2").
				Volume("vol-2").
				PodName("pod-2").
				PodNamespace("ns-2").
				UploaderType("restic").
				Result(),
			expected: &PodVolumeRestoreInfo{
				SnapshotHandle: "snap-2",
				Size:           0,
				UploaderType:   "restic",
				VolumeName:     "vol-2",
				PodName:        "pod-2",
				PodNamespace:   "ns-2",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := newPodVolumeInfoFromPVR(tc.pvr)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestNewPodVolumeInfoFromPVB(t *testing.T) {
	tests := []struct {
		name     string
		pvb      *velerov1api.PodVolumeBackup
		expected *PodVolumeBackupInfo
	}{
		{
			name: "all fields populated including incremental bytes",
			pvb: func() *velerov1api.PodVolumeBackup {
				pvb := builder.ForPodVolumeBackup("velero", "pvb-1").
					SnapshotID("snap-1").
					Volume("vol-1").
					PodName("pod-1").
					PodNamespace("ns-1").
					Node("node-1").
					UploaderType("kopia").
					Phase(velerov1api.PodVolumeBackupPhaseCompleted).
					TotalBytes(2048).
					IncrementalBytes(512).
					Result()
				pvb.Status.FallbackFull = true
				return pvb
			}(),
			expected: &PodVolumeBackupInfo{
				SnapshotHandle:  "snap-1",
				Size:            2048,
				IncrementalSize: ptr.To(int64(512)),
				UploaderType:    "kopia",
				VolumeName:      "vol-1",
				PodName:         "pod-1",
				PodNamespace:    "ns-1",
				NodeName:        "node-1",
				Phase:           velerov1api.PodVolumeBackupPhaseCompleted,
			},
		},
		{
			name: "optional fields empty or nil",
			pvb: builder.ForPodVolumeBackup("velero", "pvb-2").
				SnapshotID("snap-2").
				Volume("vol-2").
				PodName("pod-2").
				PodNamespace("ns-2").
				UploaderType("restic").
				Result(),
			expected: &PodVolumeBackupInfo{
				SnapshotHandle: "snap-2",
				Size:           0,
				UploaderType:   "restic",
				VolumeName:     "vol-2",
				PodName:        "pod-2",
				PodNamespace:   "ns-2",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := newPodVolumeInfoFromPVB(tc.pvb)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestNewPVInfo(t *testing.T) {
	csiPV := builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
		ObjectMeta(builder.WithLabels("k", "v")).Result()
	csiPV.Spec.CSI = &corev1api.CSIPersistentVolumeSource{Driver: "fake.csi", VolumeHandle: "vol-1"}
	require.Equal(t, &PVInfo{ReclaimPolicy: "Retain", Labels: map[string]string{"k": "v"}, VolumeHandle: "vol-1"}, NewPVInfo(csiPV))

	localPV := builder.ForPersistentVolume("pv-2").ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).Result()
	require.Equal(t, &PVInfo{ReclaimPolicy: "Delete"}, NewPVInfo(localPV))
}

func TestNewRestoreVolumeInfoFromDataDownload(t *testing.T) {
	dd := builder.ForDataDownload("velero", "test-dd").
		ObjectMeta(builder.WithLabels(velerov1api.AsyncOperationIDLabel, "dd-op-1")).
		SnapshotID("snap-123").
		TargetVolume(velerov2alpha1.TargetVolumeSpec{
			PVC:       "test-pvc",
			PV:        "test-pv",
			Namespace: "test-ns",
		}).
		Phase(velerov2alpha1.DataDownloadPhaseCompleted).
		Progress(veleroshared.DataMoveOperationProgress{TotalBytes: 2048}).
		IncrementalBytes(512).
		RestoreType("Incremental").
		FallbackFull(true).
		Result()

	info := NewRestoreVolumeInfoFromDataDownload(dd, "custom-pv")
	require.NotNil(t, info)
	assert.Equal(t, "custom-pv", info.PVName)
	assert.Equal(t, "test-pvc", info.PVCName)
	assert.Equal(t, "test-ns", info.PVCNamespace)
	assert.True(t, info.SnapshotDataMoved)
	assert.Equal(t, CSISnapshot, info.RestoreMethod)
	assert.Equal(t, "Incremental", info.RestoreType)
	assert.True(t, info.FallbackFull)
	require.NotNil(t, info.SnapshotDataMovementInfo)
	assert.Equal(t, "velero", info.SnapshotDataMovementInfo.DataMover)
	assert.Equal(t, velerov1api.BackupRepositoryTypeKopia, info.SnapshotDataMovementInfo.UploaderType)
	assert.Equal(t, "snap-123", info.SnapshotDataMovementInfo.SnapshotHandle)
	assert.Equal(t, "dd-op-1", info.SnapshotDataMovementInfo.OperationID)
	assert.Equal(t, int64(2048), info.SnapshotDataMovementInfo.Size)
	assert.Equal(t, ptr.To(int64(512)), info.SnapshotDataMovementInfo.IncrementalSize)
	assert.Equal(t, velerov2alpha1.DataDownloadPhaseCompleted, info.SnapshotDataMovementInfo.Phase)
}

func TestNewBackupVolumeInfoFromDataUpload(t *testing.T) {
	now := metav1.Now()
	du := builder.ForDataUpload("velero", "test-du").
		SourcePVC("test-pvc").
		SourceNamespace("test-ns").
		DataMover("velero").
		SnapshotID("snap-456").
		CSISnapshot(&velerov2alpha1.CSISnapshotSpec{VolumeSnapshot: "vs-1", Driver: "driver.csi"}).
		Phase(velerov2alpha1.DataUploadPhaseCompleted).
		Progress(veleroshared.DataMoveOperationProgress{TotalBytes: 4096}).
		IncrementalBytes(1024).
		StartTimestamp(&now).
		CompletionTimestamp(&now).
		Result()
	du.Status.FallbackFull = false

	op := &itemoperation.BackupOperation{
		Spec: itemoperation.BackupOperationSpec{
			OperationID: "op-1",
		},
	}
	pv := builder.ForPersistentVolume("test-pv").ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).Result()

	info := NewBackupVolumeInfoFromDataUpload(du, op, pv, "test-pv")
	require.NotNil(t, info)
	assert.Equal(t, CSISnapshot, info.BackupMethod)
	assert.Equal(t, "test-pvc", info.PVCName)
	assert.Equal(t, "test-ns", info.PVCNamespace)
	assert.Equal(t, "test-pv", info.PVName)
	assert.True(t, info.SnapshotDataMoved)
	assert.False(t, info.Skipped)
	assert.Equal(t, VolumeResultSucceeded, info.Result)
	assert.Equal(t, &now, info.StartTimestamp)
	assert.Equal(t, &now, info.CompletionTimestamp)
	require.NotNil(t, info.SnapshotDataMovementInfo)
	assert.Equal(t, "velero", info.SnapshotDataMovementInfo.DataMover)
	assert.Equal(t, velerov1api.BackupRepositoryTypeKopia, info.SnapshotDataMovementInfo.UploaderType)
	assert.Equal(t, "op-1", info.SnapshotDataMovementInfo.OperationID)
	assert.Equal(t, "snap-456", info.SnapshotDataMovementInfo.SnapshotHandle)
	assert.Equal(t, "vs-1", info.SnapshotDataMovementInfo.RetainedSnapshot)
	assert.Equal(t, int64(4096), info.SnapshotDataMovementInfo.Size)
	assert.Equal(t, ptr.To(int64(1024)), info.SnapshotDataMovementInfo.IncrementalSize)
	assert.Equal(t, velerov2alpha1.DataUploadPhaseCompleted, info.SnapshotDataMovementInfo.Phase)
	require.NotNil(t, info.PVInfo)
	assert.Equal(t, "Delete", info.PVInfo.ReclaimPolicy)
}

func TestNewBackupVolumeInfoFromCSISnapshot(t *testing.T) {
	now := metav1.Now()
	vscName := "test-vsc"
	snapshotHandle := "snap-handle-789"
	driver := "test.csi.driver"

	vs := builder.ForVolumeSnapshot("test-ns", "test-vs").
		SourcePVC("test-pvc").
		Status().
		BoundVolumeSnapshotContentName(vscName).
		RestoreSize("1Gi").
		ReadyToUse(true).
		Result()
	vs.Status.CreationTime = &now

	vsc := builder.ForVolumeSnapshotContent(vscName).
		Driver(driver).
		Status(&snapshotv1api.VolumeSnapshotContentStatus{
			SnapshotHandle: &snapshotHandle,
		}).
		Result()

	op := &itemoperation.BackupOperation{
		Spec: itemoperation.BackupOperationSpec{
			OperationID: "op-csi-1",
		},
		Status: itemoperation.OperationStatus{
			Updated: &now,
		},
	}

	pv := builder.ForPersistentVolume("test-pv").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result()

	info := NewBackupVolumeInfoFromCSISnapshot(vs, vsc, op, pv, "test-pv")
	require.NotNil(t, info)
	assert.Equal(t, CSISnapshot, info.BackupMethod)
	assert.Equal(t, "test-pvc", info.PVCName)
	assert.Equal(t, "test-ns", info.PVCNamespace)
	assert.Equal(t, "test-pv", info.PVName)
	assert.False(t, info.SnapshotDataMoved)
	assert.False(t, info.Skipped)
	assert.True(t, info.PreserveLocalSnapshot)
	assert.Equal(t, VolumeResultSucceeded, info.Result)
	assert.Equal(t, &now, info.StartTimestamp)
	assert.Equal(t, &now, info.CompletionTimestamp)
	require.NotNil(t, info.CSISnapshotInfo)
	assert.Equal(t, vscName, info.CSISnapshotInfo.VSCName)
	assert.Equal(t, int64(1073741824), info.CSISnapshotInfo.Size)
	assert.Equal(t, driver, info.CSISnapshotInfo.Driver)
	assert.Equal(t, snapshotHandle, info.CSISnapshotInfo.SnapshotHandle)
	assert.Equal(t, "op-csi-1", info.CSISnapshotInfo.OperationID)
	assert.True(t, *info.CSISnapshotInfo.ReadyToUse)
	require.NotNil(t, info.PVInfo)
	assert.Equal(t, "Retain", info.PVInfo.ReclaimPolicy)
}
