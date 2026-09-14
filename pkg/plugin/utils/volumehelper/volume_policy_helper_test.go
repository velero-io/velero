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

package volumehelper

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/internal/volumehelper"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestShouldPerformSnapshotWithBackup(t *testing.T) {
	tests := []struct {
		name         string
		pvc          *corev1api.PersistentVolumeClaim
		pv           *corev1api.PersistentVolume
		backup       *velerov1api.Backup
		wantSnapshot bool
		wantError    bool
	}{
		{
			name: "Returns true when snapshotVolumes not set",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "default",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "test-pv",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pv: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pv",
				},
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{
							Driver: "test-driver",
						},
					},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "test-pvc",
					},
				},
			},
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
			},
			wantSnapshot: true,
			wantError:    false,
		},
		{
			name: "Returns false when snapshotVolumes is false",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "default",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "test-pv",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pv: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pv",
				},
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{
							Driver: "test-driver",
						},
					},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "test-pvc",
					},
				},
			},
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupSpec{
					SnapshotVolumes: boolPtr(false),
				},
			},
			wantSnapshot: false,
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with PV and PVC
			client := velerotest.NewFakeControllerRuntimeClient(t, tt.pv, tt.pvc)

			// Convert PVC to unstructured
			pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tt.pvc)
			require.NoError(t, err)
			unstructuredPVC := &unstructured.Unstructured{Object: pvcMap}

			logger := logrus.New()

			// Call the function under test - this is the wrapper for third-party plugins
			result, err := ShouldPerformSnapshotWithBackup(
				unstructuredPVC,
				kuberesource.PersistentVolumeClaims,
				*tt.backup,
				client,
				logger,
			)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantSnapshot, result)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestShouldPerformSnapshotWithVolumeHelper(t *testing.T) {
	tests := []struct {
		name         string
		pvc          *corev1api.PersistentVolumeClaim
		pv           *corev1api.PersistentVolume
		backup       *velerov1api.Backup
		wantSnapshot bool
		wantError    bool
	}{
		{
			name: "Returns true with nil VolumeHelper when snapshotVolumes not set",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "default",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "test-pv",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pv: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pv",
				},
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{
							Driver: "test-driver",
						},
					},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "test-pvc",
					},
				},
			},
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
			},
			wantSnapshot: true,
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with PV
			client := velerotest.NewFakeControllerRuntimeClient(t, tt.pv, tt.pvc)

			// Convert PVC to unstructured
			pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tt.pvc)
			require.NoError(t, err)
			unstructuredPVC := &unstructured.Unstructured{Object: pvcMap}

			logger := logrus.New()

			// Call the function under test with nil VolumeHelper
			// This exercises the fallback path that creates a new VolumeHelper per call
			result, err := ShouldPerformSnapshotWithVolumeHelper(
				unstructuredPVC,
				kuberesource.PersistentVolumeClaims,
				*tt.backup,
				client,
				logger,
				nil, // Pass nil for VolumeHelper - exercises fallback path
			)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantSnapshot, result)
			}
		})
	}
}

// TestShouldPerformSnapshotWithNonNilVolumeHelper tests the ShouldPerformSnapshotWithVolumeHelper
// function when a pre-created VolumeHelper is passed. This exercises the cached path used
// by BIA plugins for better performance.
func TestShouldPerformSnapshotWithNonNilVolumeHelper(t *testing.T) {
	pvc := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pvc",
			Namespace: "default",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "test-pv",
		},
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimBound,
		},
	}

	pv := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pv",
		},
		Spec: corev1api.PersistentVolumeSpec{
			PersistentVolumeSource: corev1api.PersistentVolumeSource{
				CSI: &corev1api.CSIPersistentVolumeSource{
					Driver: "test-driver",
				},
			},
			ClaimRef: &corev1api.ObjectReference{
				Namespace: "default",
				Name:      "test-pvc",
			},
		},
	}

	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backup",
			Namespace: "velero",
		},
		Spec: velerov1api.BackupSpec{
			IncludedNamespaces: []string{"default"},
		},
	}

	// Create fake client with PV and PVC
	client := velerotest.NewFakeControllerRuntimeClient(t, pv, pvc)

	logger := logrus.New()

	// Create VolumeHelper using the internal function with namespace caching
	vh, err := volumehelper.NewVolumeHelperImplWithNamespaces(
		nil, // no resource policies for this test
		nil, // snapshotVolumes not set
		logger,
		client,
		false, // defaultVolumesToFSBackup
		true,  // backupExcludePVC
		[]string{"default"},
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, vh)

	// Convert PVC to unstructured
	pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvc)
	require.NoError(t, err)
	unstructuredPVC := &unstructured.Unstructured{Object: pvcMap}

	// Call with non-nil VolumeHelper - exercises the cached path
	result, err := ShouldPerformSnapshotWithVolumeHelper(
		unstructuredPVC,
		kuberesource.PersistentVolumeClaims,
		*backup,
		client,
		logger,
		vh, // Pass non-nil VolumeHelper - exercises cached path
	)

	require.NoError(t, err)
	require.True(t, result, "Should return true for snapshot when snapshotVolumes not set")
}
