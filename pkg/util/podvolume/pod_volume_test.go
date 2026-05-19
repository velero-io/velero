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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestGetVolumesToBackup(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    []string
	}{
		{
			name:        "nil annotations",
			annotations: nil,
			expected:    nil,
		},
		{
			name:        "no volumes to backup",
			annotations: map[string]string{"foo": "bar"},
			expected:    nil,
		},
		{
			name:        "one volume to backup",
			annotations: map[string]string{"foo": "bar", velerov1api.VolumesToBackupAnnotation: "volume-1"},
			expected:    []string{"volume-1"},
		},
		{
			name:        "multiple volumes to backup",
			annotations: map[string]string{"foo": "bar", velerov1api.VolumesToBackupAnnotation: "volume-1,volume-2,volume-3"},
			expected:    []string{"volume-1", "volume-2", "volume-3"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := &corev1api.Pod{}
			pod.Annotations = test.annotations

			res := GetVolumesToBackup(pod)

			// sort to ensure good compare of slices
			sort.Strings(test.expected)
			sort.Strings(res)

			assert.Equal(t, test.expected, res)
		})
	}
}

func TestGetVolumesByPod(t *testing.T) {
	testCases := []struct {
		name     string
		pod      *corev1api.Pod
		expected struct {
			included []string
			optedOut []string
		}
		defaultVolumesToFsBackup bool
		backupExcludePVC         bool
	}{
		{
			name:                     "should get PVs from VolumesToBackupAnnotation when defaultVolumesToFsBackup is false",
			defaultVolumesToFsBackup: false,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToBackupAnnotation: "pvbPV1,pvbPV2,pvbPV3",
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{},
			},
		},
		{
			name:                     "should get all pod volumes when defaultVolumesToFsBackup is true and no PVs are excluded",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						// PVB Volumes
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{},
			},
		},
		{
			name:                     "should get all pod volumes except ones excluded when defaultVolumesToFsBackup is true",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						// PVB Volumes
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						/// Excluded from PVB through annotation
						{Name: "nonPvbPV1"}, {Name: "nonPvbPV2"}, {Name: "nonPvbPV3"},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{"nonPvbPV1", "nonPvbPV2", "nonPvbPV3"},
			},
		},
		{
			name:                     "should exclude default service account token from pod volume backup",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						// PVB Volumes
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						/// Excluded from PVB because volume mounting default service account token
						{Name: "default-token-5xq45"},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{},
			},
		},
		{
			name:                     "should exclude host path volumes from pod volume backups",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						// PVB Volumes
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						/// Excluded from pod volume backup through annotation
						{Name: "nonPvbPV1"}, {Name: "nonPvbPV2"}, {Name: "nonPvbPV3"},
						// Excluded from pod volume backup because hostpath
						{Name: "hostPath1", VolumeSource: corev1api.VolumeSource{HostPath: &corev1api.HostPathVolumeSource{Path: "/hostpathVol"}}},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{"nonPvbPV1", "nonPvbPV2", "nonPvbPV3"},
			},
		},
		{
			name:                     "should exclude volumes mounting secrets",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						// PVB Volumes
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						/// Excluded from pod volume backup through annotation
						{Name: "nonPvbPV1"}, {Name: "nonPvbPV2"}, {Name: "nonPvbPV3"},
						// Excluded from pod volume backup because hostpath
						{Name: "superSecret", VolumeSource: corev1api.VolumeSource{Secret: &corev1api.SecretVolumeSource{SecretName: "super-secret"}}},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{"nonPvbPV1", "nonPvbPV2", "nonPvbPV3"},
			},
		},
		{
			name:                     "should exclude volumes mounting ConfigMaps",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						// PVB Volumes
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						/// Excluded from pod volume backup through annotation
						{Name: "nonPvbPV1"}, {Name: "nonPvbPV2"}, {Name: "nonPvbPV3"},
						// Excluded from pod volume backup because hostpath
						{Name: "appCOnfig", VolumeSource: corev1api.VolumeSource{ConfigMap: &corev1api.ConfigMapVolumeSource{LocalObjectReference: corev1api.LocalObjectReference{Name: "app-config"}}}},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{"nonPvbPV1", "nonPvbPV2", "nonPvbPV3"},
			},
		},
		{
			name:                     "should exclude projected volumes",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						{
							Name: "projected",
							VolumeSource: corev1api.VolumeSource{
								Projected: &corev1api.ProjectedVolumeSource{
									Sources: []corev1api.VolumeProjection{{
										Secret: &corev1api.SecretProjection{
											LocalObjectReference: corev1api.LocalObjectReference{},
											Items:                nil,
											Optional:             nil,
										},
										DownwardAPI:         nil,
										ConfigMap:           nil,
										ServiceAccountToken: nil,
									}},
									DefaultMode: nil,
								},
							},
						},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{},
			},
		},
		{
			name:                     "should exclude DownwardAPI volumes",
			defaultVolumesToFsBackup: true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						{
							Name: "downwardAPI",
							VolumeSource: corev1api.VolumeSource{
								DownwardAPI: &corev1api.DownwardAPIVolumeSource{
									Items: []corev1api.DownwardAPIVolumeFile{
										{
											Path: "labels",
											FieldRef: &corev1api.ObjectFieldSelector{
												APIVersion: "v1",
												FieldPath:  "metadata.labels",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{},
			},
		},
		{
			name:                     "should exclude PVC volume when backup excludes PVC resource",
			defaultVolumesToFsBackup: true,
			backupExcludePVC:         true,
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumesToExcludeAnnotation: "nonPvbPV1,nonPvbPV2,nonPvbPV3",
					},
				},
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						{Name: "pvbPV1"}, {Name: "pvbPV2"}, {Name: "pvbPV3"},
						{
							Name: "downwardAPI",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "testPVC",
								},
							},
						},
					},
				},
			},
			expected: struct {
				included []string
				optedOut []string
			}{
				included: []string{"pvbPV1", "pvbPV2", "pvbPV3"},
				optedOut: []string{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualIncluded, actualOptedOut := GetVolumesByPod(tc.pod, tc.defaultVolumesToFsBackup, tc.backupExcludePVC, []string{})

			sort.Strings(tc.expected.included)
			sort.Strings(actualIncluded)
			assert.Equal(t, tc.expected.included, actualIncluded)

			sort.Strings(tc.expected.optedOut)
			sort.Strings(actualOptedOut)
			assert.Equal(t, tc.expected.optedOut, actualOptedOut)
		})
	}
}

func TestGetPodVolumeNameForPVC(t *testing.T) {
	testCases := []struct {
		name               string
		pod                corev1api.Pod
		pvcName            string
		expectError        bool
		expectedVolumeName string
	}{
		{
			name: "should get volume name for pod with multiple PVCs",
			pod: corev1api.Pod{
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						{
							Name: "csi-vol1",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "csi-pvc1",
								},
							},
						},
						{
							Name: "csi-vol2",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "csi-pvc2",
								},
							},
						},
						{
							Name: "csi-vol3",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "csi-pvc3",
								},
							},
						},
					},
				},
			},
			pvcName:            "csi-pvc2",
			expectedVolumeName: "csi-vol2",
			expectError:        false,
		},
		{
			name: "should get volume name from pod using exactly one PVC",
			pod: corev1api.Pod{
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						{
							Name: "csi-vol1",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "csi-pvc1",
								},
							},
						},
					},
				},
			},
			pvcName:            "csi-pvc1",
			expectedVolumeName: "csi-vol1",
			expectError:        false,
		},
		{
			name: "should return error for pod with no PVCs",
			pod: corev1api.Pod{
				Spec: corev1api.PodSpec{},
			},
			pvcName:     "csi-pvc2",
			expectError: true,
		},
		{
			name: "should return error for pod with no matching PVC",
			pod: corev1api.Pod{
				Spec: corev1api.PodSpec{
					Volumes: []corev1api.Volume{
						{
							Name: "csi-vol1",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "csi-pvc1",
								},
							},
						},
					},
				},
			},
			pvcName:     "mismatch-pvc",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualVolumeName, err := getPodVolumeNameForPVC(tc.pod, tc.pvcName)
			if tc.expectError && err == nil {
				assert.Error(t, err, "Want error; Got nil error")
				return
			}
			assert.Equalf(t, tc.expectedVolumeName, actualVolumeName, "unexpected podVolumename returned. Want %s; Got %s", tc.expectedVolumeName, actualVolumeName)
		})
	}
}

func TestGetVolumesToProcess(t *testing.T) {
	testCases := []struct {
		name                          string
		volumes                       []corev1api.Volume
		volsToProcessByLegacyApproach []string
		expectedVolumes               []corev1api.Volume
	}{
		{
			name: "pod has 2 volumes empty volsToProcessByLegacyApproach list return 2 volumes",
			volumes: []corev1api.Volume{
				{
					Name: "sample-volume-1",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-1",
						},
					},
				},
				{
					Name: "sample-volume-2",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-2",
						},
					},
				},
			},
			volsToProcessByLegacyApproach: []string{},
			expectedVolumes: []corev1api.Volume{
				{
					Name: "sample-volume-1",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-1",
						},
					},
				},
				{
					Name: "sample-volume-2",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-2",
						},
					},
				},
			},
		},
		{
			name: "pod has 2 volumes non-empty volsToProcessByLegacyApproach list returns 1 volumes",
			volumes: []corev1api.Volume{
				{
					Name: "sample-volume-1",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-1",
						},
					},
				},
				{
					Name: "sample-volume-2",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-2",
						},
					},
				},
			},
			volsToProcessByLegacyApproach: []string{"sample-volume-2"},
			expectedVolumes: []corev1api.Volume{
				{
					Name: "sample-volume-2",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "sample-pvc-2",
						},
					},
				},
			},
		},
		{
			name:                          "empty case, return empty list",
			volumes:                       []corev1api.Volume{},
			volsToProcessByLegacyApproach: []string{},
			expectedVolumes:               []corev1api.Volume{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualVolumes := GetVolumesToProcess(tc.volumes, tc.volsToProcessByLegacyApproach)
			assert.Equal(t, tc.expectedVolumes, actualVolumes, "Want Volumes List %v; Got Volumes List %v", tc.expectedVolumes, actualVolumes)
		})
	}
}

func TestPVCPodCache_BuildAndGet(t *testing.T) {
	objs := []runtime.Object{
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc1",
							},
						},
					},
				},
			},
		},
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod2",
				Namespace: "default",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc1",
							},
						},
					},
					{
						Name: "vol2",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc2",
							},
						},
					},
				},
			},
		},
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod3",
				Namespace: "default",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							EmptyDir: &corev1api.EmptyDirVolumeSource{},
						},
					},
				},
			},
		},
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod4",
				Namespace: "other-ns",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc1",
							},
						},
					},
				},
			},
		},
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)

	testCases := []struct {
		name             string
		namespaces       []string
		pvcNamespace     string
		pvcName          string
		expectedPodCount int
	}{
		{
			name:             "should find 2 pods using pvc1 in default namespace",
			namespaces:       []string{"default", "other-ns"},
			pvcNamespace:     "default",
			pvcName:          "pvc1",
			expectedPodCount: 2,
		},
		{
			name:             "should find 1 pod using pvc2 in default namespace",
			namespaces:       []string{"default", "other-ns"},
			pvcNamespace:     "default",
			pvcName:          "pvc2",
			expectedPodCount: 1,
		},
		{
			name:             "should find 1 pod using pvc1 in other-ns",
			namespaces:       []string{"default", "other-ns"},
			pvcNamespace:     "other-ns",
			pvcName:          "pvc1",
			expectedPodCount: 1,
		},
		{
			name:             "should find 0 pods for non-existent PVC",
			namespaces:       []string{"default", "other-ns"},
			pvcNamespace:     "default",
			pvcName:          "non-existent",
			expectedPodCount: 0,
		},
		{
			name:             "should find 0 pods for non-existent namespace",
			namespaces:       []string{"default", "other-ns"},
			pvcNamespace:     "non-existent-ns",
			pvcName:          "pvc1",
			expectedPodCount: 0,
		},
		{
			name:             "should find 0 pods when namespace not in cache",
			namespaces:       []string{"default"},
			pvcNamespace:     "other-ns",
			pvcName:          "pvc1",
			expectedPodCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewPVCPodCache()
			err := cache.BuildCacheForNamespaces(t.Context(), tc.namespaces, fakeClient)
			require.NoError(t, err)
			assert.True(t, cache.IsBuilt())

			pods := cache.GetPodsUsingPVC(tc.pvcNamespace, tc.pvcName)
			assert.Len(t, pods, tc.expectedPodCount, "unexpected number of pods")
		})
	}
}

func TestGetPodsUsingPVCWithCache(t *testing.T) {
	objs := []runtime.Object{
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc1",
							},
						},
					},
				},
			},
		},
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod2",
				Namespace: "default",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc1",
							},
						},
					},
				},
			},
		},
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)

	testCases := []struct {
		name             string
		pvcNamespace     string
		pvcName          string
		buildCache       bool
		useNilCache      bool
		expectedPodCount int
	}{
		{
			name:             "returns cached results when cache is available",
			pvcNamespace:     "default",
			pvcName:          "pvc1",
			buildCache:       true,
			useNilCache:      false,
			expectedPodCount: 2,
		},
		{
			name:             "falls back to direct lookup when cache is nil",
			pvcNamespace:     "default",
			pvcName:          "pvc1",
			buildCache:       false,
			useNilCache:      true,
			expectedPodCount: 2,
		},
		{
			name:             "falls back to direct lookup when cache is not built",
			pvcNamespace:     "default",
			pvcName:          "pvc1",
			buildCache:       false,
			useNilCache:      false,
			expectedPodCount: 2,
		},
		{
			name:             "returns empty slice for non-existent PVC with cache",
			pvcNamespace:     "default",
			pvcName:          "non-existent",
			buildCache:       true,
			useNilCache:      false,
			expectedPodCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cache *PVCPodCache
			if !tc.useNilCache {
				cache = NewPVCPodCache()
				if tc.buildCache {
					err := cache.BuildCacheForNamespaces(t.Context(), []string{"default"}, fakeClient)
					require.NoError(t, err)
				}
			}

			pods, err := GetPodsUsingPVCWithCache(tc.pvcNamespace, tc.pvcName, fakeClient, cache)
			require.NoError(t, err)
			assert.Len(t, pods, tc.expectedPodCount, "unexpected number of pods")
		})
	}
}

func TestIsPVCDefaultToFSBackupWithCache(t *testing.T) {
	objs := []runtime.Object{
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "default",
				Annotations: map[string]string{
					"backup.velero.io/backup-volumes": "vol1",
				},
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc1",
							},
						},
					},
				},
			},
		},
		&corev1api.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod2",
				Namespace: "default",
			},
			Spec: corev1api.PodSpec{
				Volumes: []corev1api.Volume{
					{
						Name: "vol1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc2",
							},
						},
					},
				},
			},
		},
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)

	testCases := []struct {
		name                     string
		pvcNamespace             string
		pvcName                  string
		defaultVolumesToFsBackup bool
		buildCache               bool
		useNilCache              bool
		expectedResult           bool
	}{
		{
			name:                     "returns true for PVC with opt-in annotation using cache",
			pvcNamespace:             "default",
			pvcName:                  "pvc1",
			defaultVolumesToFsBackup: false,
			buildCache:               true,
			useNilCache:              false,
			expectedResult:           true,
		},
		{
			name:                     "returns false for PVC without annotation using cache",
			pvcNamespace:             "default",
			pvcName:                  "pvc2",
			defaultVolumesToFsBackup: false,
			buildCache:               true,
			useNilCache:              false,
			expectedResult:           false,
		},
		{
			name:                     "returns true for any PVC with defaultVolumesToFsBackup using cache",
			pvcNamespace:             "default",
			pvcName:                  "pvc2",
			defaultVolumesToFsBackup: true,
			buildCache:               true,
			useNilCache:              false,
			expectedResult:           true,
		},
		{
			name:                     "falls back to direct lookup when cache is nil",
			pvcNamespace:             "default",
			pvcName:                  "pvc1",
			defaultVolumesToFsBackup: false,
			buildCache:               false,
			useNilCache:              true,
			expectedResult:           true,
		},
		{
			name:                     "returns false for non-existent PVC",
			pvcNamespace:             "default",
			pvcName:                  "non-existent",
			defaultVolumesToFsBackup: false,
			buildCache:               true,
			useNilCache:              false,
			expectedResult:           false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cache *PVCPodCache
			if !tc.useNilCache {
				cache = NewPVCPodCache()
				if tc.buildCache {
					err := cache.BuildCacheForNamespaces(t.Context(), []string{"default"}, fakeClient)
					require.NoError(t, err)
				}
			}

			result, err := IsPVCDefaultToFSBackupWithCache(tc.pvcNamespace, tc.pvcName, fakeClient, tc.defaultVolumesToFsBackup, cache)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

// TestIsNamespaceBuilt tests the IsNamespaceBuilt method for lazy per-namespace caching.
func TestIsNamespaceBuilt(t *testing.T) {
	cache := NewPVCPodCache()

	// Initially no namespace should be built
	assert.False(t, cache.IsNamespaceBuilt("ns1"), "namespace should not be built initially")
	assert.False(t, cache.IsNamespaceBuilt("ns2"), "namespace should not be built initially")

	// Create a fake client with a pod in ns1
	pod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "ns1",
		},
		Spec: corev1api.PodSpec{
			Volumes: []corev1api.Volume{
				{
					Name: "vol1",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "pvc1",
						},
					},
				},
			},
		},
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, pod)

	// Build cache for ns1
	err := cache.BuildCacheForNamespace(t.Context(), "ns1", fakeClient)
	require.NoError(t, err)

	// ns1 should be built, ns2 should not
	assert.True(t, cache.IsNamespaceBuilt("ns1"), "namespace ns1 should be built")
	assert.False(t, cache.IsNamespaceBuilt("ns2"), "namespace ns2 should not be built")

	// Build cache for ns2 (empty namespace)
	err = cache.BuildCacheForNamespace(t.Context(), "ns2", fakeClient)
	require.NoError(t, err)

	// Both should now be built
	assert.True(t, cache.IsNamespaceBuilt("ns1"), "namespace ns1 should still be built")
	assert.True(t, cache.IsNamespaceBuilt("ns2"), "namespace ns2 should now be built")
}

// TestBuildCacheForNamespace tests the lazy per-namespace cache building.
func TestBuildCacheForNamespace(t *testing.T) {
	tests := []struct {
		name         string
		pods         []runtime.Object
		namespace    string
		expectedPVCs map[string]int // pvcName -> expected pod count
		expectError  bool
	}{
		{
			name:      "build cache for namespace with pods using PVCs",
			namespace: "ns1",
			pods: []runtime.Object{
				&corev1api.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
					Spec: corev1api.PodSpec{
						Volumes: []corev1api.Volume{
							{
								Name: "vol1",
								VolumeSource: corev1api.VolumeSource{
									PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
										ClaimName: "pvc1",
									},
								},
							},
						},
					},
				},
				&corev1api.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "ns1"},
					Spec: corev1api.PodSpec{
						Volumes: []corev1api.Volume{
							{
								Name: "vol1",
								VolumeSource: corev1api.VolumeSource{
									PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
										ClaimName: "pvc1",
									},
								},
							},
						},
					},
				},
			},
			expectedPVCs: map[string]int{"pvc1": 2},
		},
		{
			name:         "build cache for empty namespace",
			namespace:    "empty-ns",
			pods:         []runtime.Object{},
			expectedPVCs: map[string]int{},
		},
		{
			name:      "build cache ignores pods without PVCs",
			namespace: "ns1",
			pods: []runtime.Object{
				&corev1api.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
					Spec: corev1api.PodSpec{
						Volumes: []corev1api.Volume{
							{
								Name: "config-vol",
								VolumeSource: corev1api.VolumeSource{
									ConfigMap: &corev1api.ConfigMapVolumeSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "my-config",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedPVCs: map[string]int{},
		},
		{
			name:      "build cache only for specified namespace",
			namespace: "ns1",
			pods: []runtime.Object{
				&corev1api.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
					Spec: corev1api.PodSpec{
						Volumes: []corev1api.Volume{
							{
								Name: "vol1",
								VolumeSource: corev1api.VolumeSource{
									PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
										ClaimName: "pvc1",
									},
								},
							},
						},
					},
				},
				&corev1api.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: "pod2", Namespace: "ns2"},
					Spec: corev1api.PodSpec{
						Volumes: []corev1api.Volume{
							{
								Name: "vol1",
								VolumeSource: corev1api.VolumeSource{
									PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
										ClaimName: "pvc2",
									},
								},
							},
						},
					},
				},
			},
			expectedPVCs: map[string]int{"pvc1": 1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, tc.pods...)
			cache := NewPVCPodCache()

			// Build cache for the namespace
			err := cache.BuildCacheForNamespace(t.Context(), tc.namespace, fakeClient)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify namespace is marked as built
			assert.True(t, cache.IsNamespaceBuilt(tc.namespace))

			// Verify PVC to pod mappings
			for pvcName, expectedCount := range tc.expectedPVCs {
				pods := cache.GetPodsUsingPVC(tc.namespace, pvcName)
				assert.Len(t, pods, expectedCount, "unexpected pod count for PVC %s", pvcName)
			}

			// Calling BuildCacheForNamespace again should be a no-op
			err = cache.BuildCacheForNamespace(t.Context(), tc.namespace, fakeClient)
			require.NoError(t, err)
		})
	}
}

// TestBuildCacheForNamespaceIdempotent verifies that building cache multiple times is safe.
func TestBuildCacheForNamespaceIdempotent(t *testing.T) {
	pod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns1"},
		Spec: corev1api.PodSpec{
			Volumes: []corev1api.Volume{
				{
					Name: "vol1",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "pvc1",
						},
					},
				},
			},
		},
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, pod)
	cache := NewPVCPodCache()

	// Build cache multiple times - should be idempotent
	for range 3 {
		err := cache.BuildCacheForNamespace(t.Context(), "ns1", fakeClient)
		require.NoError(t, err)
		assert.True(t, cache.IsNamespaceBuilt("ns1"))

		pods := cache.GetPodsUsingPVC("ns1", "pvc1")
		assert.Len(t, pods, 1, "should have exactly 1 pod using pvc1")
	}
}
