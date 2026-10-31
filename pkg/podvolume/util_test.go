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

package podvolume

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestGetVolumeBackupsForPod(t *testing.T) {
	tests := []struct {
		name             string
		podVolumeBackups []*velerov1api.PodVolumeBackup
		podVolumes       []corev1api.Volume
		podAnnotations   map[string]string
		podName          string
		sourcePodNs      string
		expected         map[string]string
	}{
		{
			name:           "nil annotations results in no volume backups returned",
			podAnnotations: nil,
			expected:       nil,
		},
		{
			name:           "empty annotations results in no volume backups returned",
			podAnnotations: make(map[string]string),
			expected:       nil,
		},
		{
			name:           "pod annotations with no snapshot annotation prefix results in no volume backups returned",
			podAnnotations: map[string]string{"foo": "bar"},
			expected:       nil,
		},
		{
			name:           "pod annotation with only snapshot annotation prefix, results in volume backup with empty volume key",
			podAnnotations: map[string]string{podAnnotationPrefix: "snapshotID"},
			expected:       map[string]string{"": "snapshotID"},
		},
		{
			name:           "pod annotation with snapshot annotation prefix results in volume backup with volume name and snapshot ID",
			podAnnotations: map[string]string{podAnnotationPrefix + "volume": "snapshotID"},
			expected:       map[string]string{"volume": "snapshotID"},
		},
		{
			name:           "only pod annotations with snapshot annotation prefix are considered",
			podAnnotations: map[string]string{"x": "y", podAnnotationPrefix + "volume1": "snapshot1", podAnnotationPrefix + "volume2": "snapshot2"},
			expected:       map[string]string{"volume1": "snapshot1", "volume2": "snapshot2"},
		},
		{
			name: "pod annotations are not considered if PVBs are provided",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvbtest1-foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvbtest2-abc").Result(),
			},
			podName:        "TestPod",
			sourcePodNs:    "TestNS",
			podAnnotations: map[string]string{"x": "y", podAnnotationPrefix + "foo": "bar", podAnnotationPrefix + "abc": "123"},
			expected:       map[string]string{"pvbtest1-foo": "snapshot1", "pvbtest2-abc": "snapshot2"},
		},
		{
			name: "volume backups are returned even if no pod annotations are present",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvbtest1-foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvbtest2-abc").Result(),
			},
			podName:     "TestPod",
			sourcePodNs: "TestNS",
			expected:    map[string]string{"pvbtest1-foo": "snapshot1", "pvbtest2-abc": "snapshot2"},
		},
		{
			name: "only volumes from PVBs with snapshot IDs are returned",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvbtest1-foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvbtest2-abc").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-3").PodName("TestPod").PodNamespace("TestNS").Volume("pvbtest3-foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-4").PodName("TestPod").PodNamespace("TestNS").Volume("pvbtest4-abc").Result(),
			},
			podName:     "TestPod",
			sourcePodNs: "TestNS",
			expected:    map[string]string{"pvbtest1-foo": "snapshot1", "pvbtest2-abc": "snapshot2"},
		},
		{
			name: "only volumes from PVBs for the given pod are returned",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvbtest1-foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvbtest2-abc").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-3").PodName("TestAnotherPod").SnapshotID("snapshot3").Volume("pvbtest3-xyz").Result(),
			},
			podName:     "TestPod",
			sourcePodNs: "TestNS",
			expected:    map[string]string{"pvbtest1-foo": "snapshot1", "pvbtest2-abc": "snapshot2"},
		},
		{
			name: "only volumes from PVBs which match the pod name and source pod namespace are returned",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvbtest1-foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("TestAnotherPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvbtest2-abc").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-3").PodName("TestPod").PodNamespace("TestAnotherNS").SnapshotID("snapshot3").Volume("pvbtest3-xyz").Result(),
			},
			podName:     "TestPod",
			sourcePodNs: "TestNS",
			expected:    map[string]string{"pvbtest1-foo": "snapshot1"},
		},
		{
			name: "volumes from PVBs that correspond to a pod volume from a projected source are not returned",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvb-non-projected").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvb-projected").Result(),
			},
			podVolumes: []corev1api.Volume{
				{
					Name: "pvb-non-projected",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{},
					},
				},
				{
					Name: "pvb-projected",
					VolumeSource: corev1api.VolumeSource{
						Projected: &corev1api.ProjectedVolumeSource{},
					},
				},
			},
			podName:     "TestPod",
			sourcePodNs: "TestNS",
			expected:    map[string]string{"pvb-non-projected": "snapshot1"},
		},
		{
			name: "volumes from PVBs that correspond to a pod volume from a DownwardAPI source are not returned",
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot1").Volume("pvb-non-downwardapi").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("TestPod").PodNamespace("TestNS").SnapshotID("snapshot2").Volume("pvb-downwardapi").Result(),
			},
			podVolumes: []corev1api.Volume{
				{
					Name: "pvb-non-downwardapi",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{},
					},
				},
				{
					Name: "pvb-downwardapi",
					VolumeSource: corev1api.VolumeSource{
						DownwardAPI: &corev1api.DownwardAPIVolumeSource{},
					},
				},
			},
			podName:     "TestPod",
			sourcePodNs: "TestNS",
			expected:    map[string]string{"pvb-non-downwardapi": "snapshot1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := &corev1api.Pod{}
			pod.Annotations = test.podAnnotations
			pod.Name = test.podName
			pod.Spec.Volumes = test.podVolumes

			res := GetVolumeBackupsForPod(test.podVolumeBackups, pod, test.sourcePodNs)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestVolumeHasNonRestorableSource(t *testing.T) {
	testCases := []struct {
		name       string
		volumeName string
		podVolumes []corev1api.Volume
		expected   bool
	}{
		{
			name:       "volume name not in list of volumes",
			volumeName: "missing-volume",
			podVolumes: []corev1api.Volume{
				{
					Name: "restorable",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{},
					},
				},
				{
					Name: "projected",
					VolumeSource: corev1api.VolumeSource{
						Projected: &corev1api.ProjectedVolumeSource{},
					},
				},
				{
					Name: "downwardapi",
					VolumeSource: corev1api.VolumeSource{
						DownwardAPI: &corev1api.DownwardAPIVolumeSource{},
					},
				},
			},
			expected: false,
		},
		{
			name:       "volume name in list of volumes but not projected or DownwardAPI",
			volumeName: "restorable",
			podVolumes: []corev1api.Volume{
				{
					Name: "restorable",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{},
					},
				},
				{
					Name: "projected",
					VolumeSource: corev1api.VolumeSource{
						Projected: &corev1api.ProjectedVolumeSource{},
					},
				},
				{
					Name: "downwardapi",
					VolumeSource: corev1api.VolumeSource{
						DownwardAPI: &corev1api.DownwardAPIVolumeSource{},
					},
				},
			},
			expected: false,
		},
		{
			name:       "volume name in list of volumes and projected",
			volumeName: "projected",
			podVolumes: []corev1api.Volume{
				{
					Name: "restorable",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{},
					},
				},
				{
					Name: "projected",
					VolumeSource: corev1api.VolumeSource{
						Projected: &corev1api.ProjectedVolumeSource{},
					},
				},
				{
					Name: "downwardapi",
					VolumeSource: corev1api.VolumeSource{
						DownwardAPI: &corev1api.DownwardAPIVolumeSource{},
					},
				},
			},
			expected: true,
		},
		{
			name:       "volume name in list of volumes and is a DownwardAPI volume",
			volumeName: "downwardapi",
			podVolumes: []corev1api.Volume{
				{
					Name: "restorable",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{},
					},
				},
				{
					Name: "projected",
					VolumeSource: corev1api.VolumeSource{
						Projected: &corev1api.ProjectedVolumeSource{},
					},
				},
				{
					Name: "downwardapi",
					VolumeSource: corev1api.VolumeSource{
						DownwardAPI: &corev1api.DownwardAPIVolumeSource{},
					},
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := volumeHasNonRestorableSource(tc.volumeName, tc.podVolumes)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGetRealSource(t *testing.T) {
	testCases := []struct {
		name     string
		pvb      *velerov1api.PodVolumeBackup
		expected string
	}{
		{
			name:     "pvb with empty annotation",
			pvb:      builder.ForPodVolumeBackup("fake-ns", "fake-name").PodNamespace("fake-pod-ns").PodName("fake-pod-name").Volume("fake-volume").Result(),
			expected: "fake-pod-ns/fake-pod-name/fake-volume",
		},
		{
			name:     "pvb without pvc name annotation",
			pvb:      builder.ForPodVolumeBackup("fake-ns", "fake-name").PodNamespace("fake-pod-ns").PodName("fake-pod-name").Volume("fake-volume").Annotations(map[string]string{}).Result(),
			expected: "fake-pod-ns/fake-pod-name/fake-volume",
		},
		{
			name:     "pvb with pvc name annotation",
			pvb:      builder.ForPodVolumeBackup("fake-ns", "fake-name").PodNamespace("fake-pod-ns").PodName("fake-pod-name").Volume("fake-volume").Annotations(map[string]string{"velero.io/pvc-name": "fake-pvc-name"}).Result(),
			expected: "fake-pod-ns/fake-pod-name/fake-pvc-name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetRealSource(tc.pvb)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestValidateBackupUploadersIfAny(t *testing.T) {
	for _, tc := range []struct {
		name, uploader     string
		missing, wantError bool
	}{
		{name: "kopia", uploader: "kopia"},
		{name: "block", uploader: "velero-block"},
		{name: "unsupported", uploader: "unsupported", wantError: true},
		{name: "restic", uploader: "restic", wantError: true},
		{name: "empty", wantError: true},
		{name: "no PVBs", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backup := builder.ForBackup("velero", "backup").Result()
			c := velerotest.NewFakeControllerRuntimeClient(t)
			if !tc.missing {
				pvb := builder.ForPodVolumeBackup("velero", "pvb").UploaderType(tc.uploader).ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backup.Name)).Result()
				require.NoError(t, c.Create(t.Context(), pvb))
			}
			// Unsupported PVBs belonging to another backup or namespace must not interfere.
			require.NoError(t, c.Create(t.Context(), builder.ForPodVolumeBackup("velero", "other").ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, "other")).Result()))
			require.NoError(t, c.Create(t.Context(), builder.ForPodVolumeBackup("other", "pvb").ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backup.Name)).Result()))
			err := ValidateBackupUploadersIfAny(t.Context(), c, backup)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
