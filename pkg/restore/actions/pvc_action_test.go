/*
Copyright 2020 the Velero contributors.

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

package actions

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// TestPVCActionExecute runs the PVCAction's Execute
// method and validates that the item's PVC is modified (or not) as expected.
// Validation is done by comparing the result of the Execute method to the test case's
// desired result.
func TestPVCActionExecute(t *testing.T) {
	tests := []struct {
		name    string
		pvc     *corev1api.PersistentVolumeClaim
		want    *corev1api.PersistentVolumeClaim
		wantErr error
	}{
		{
			name: "a persistent volume claim with no annotation",
			pvc:  builder.ForPersistentVolumeClaim("source-ns", "pvc-1").Result(),
			want: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").Result(),
		},
		{
			name: "a persistent volume claim with selected-node annotation",
			pvc: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").
				ObjectMeta(
					builder.WithAnnotations("volume.kubernetes.io/selected-node", "source-node"),
				).Result(),
			want: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").ObjectMeta(builder.WithAnnotationsMap(map[string]string{})).Result(),
		},
		{
			name: "a persistent volume claim with other annotation",
			pvc: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").
				ObjectMeta(
					builder.WithAnnotations("other-anno-1", "other-value-1", "other-anno-2", "other-value-2"),
				).Result(),
			want: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").ObjectMeta(
				builder.WithAnnotations("other-anno-1", "other-value-1", "other-anno-2", "other-value-2"),
			).Result(),
		},
		{
			name: "a persistent volume claim with other annotation and selected-node annotation",
			pvc: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").
				ObjectMeta(
					builder.WithAnnotations("other-anno", "other-value", "volume.kubernetes.io/selected-node", "source-node"),
				).Result(),
			want: builder.ForPersistentVolumeClaim("source-ns", "pvc-1").ObjectMeta(
				builder.WithAnnotations("other-anno", "other-value"),
			).Result(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := NewPVCAction(
				velerotest.NewLogger(),
				nil,
			)

			// set up test data
			unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvc)
			require.NoError(t, err)

			input := &velero.RestoreItemActionExecuteInput{
				Item: &unstructured.Unstructured{
					Object: unstructuredMap,
				},
				ItemFromBackup: &unstructured.Unstructured{
					Object: unstructuredMap,
				},
			}

			// execute method under test
			res, err := a.Execute(input)

			// validate for both error and non-error cases
			switch {
			case tc.wantErr != nil:
				require.EqualError(t, err, tc.wantErr.Error())
			default:
				fmt.Printf("got +%v\n", res.UpdatedItem)
				require.NoError(t, err)

				wantUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.want)
				fmt.Printf("expected +%v\n", wantUnstructured)
				require.NoError(t, err)

				assert.Equal(t, &unstructured.Unstructured{Object: wantUnstructured}, res.UpdatedItem)
			}
		})
	}
}

func TestAddPVFromPVCActionExecute(t *testing.T) {
	tests := []struct {
		name           string
		itemFromBackup *corev1api.PersistentVolumeClaim
		want           []velero.ResourceIdentifier
		pvbs           []runtime.Object
		wantVolumeName string
	}{
		{
			name: "bound PVC with volume name returns associated PV",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "bound-pv",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			want: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.PersistentVolumes,
					Name:          "bound-pv",
				},
			},
			wantVolumeName: "bound-pv",
		},
		{
			name: "unbound PVC with volume name does not return any additional items",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "pending-pv",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimPending,
				},
			},
			want:           nil,
			wantVolumeName: "pending-pv",
		},
		{
			name: "bound PVC without volume name does not return any additional items",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			want:           nil,
			wantVolumeName: "",
		},
		{
			name: "bound PVC with volume name and matching PVB resets volume name and does not return additional items",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "bound-pv",
					DataSource: &corev1api.TypedLocalObjectReference{
						Name: "some-ds",
					},
					DataSourceRef: &corev1api.TypedObjectReference{
						Name: "some-ds",
					},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pvbs: []runtime.Object{
				builder.ForPodVolumeBackup("ns-1", "pvb-1").
					PodNamespace("ns-1").
					Phase(velerov1api.PodVolumeBackupPhaseCompleted).
					SnapshotID("snap-1").
					ObjectMeta(builder.WithLabels(
						velerov1api.BackupNameLabel, "backup-1",
						velerov1api.PVCUIDLabel, "uid-1",
					), builder.WithAnnotations("velero.io/pvc-name", "pvc-1")).Result(),
			},
			want:           nil,
			wantVolumeName: "",
		},
		{
			name: "bound PVC with volume name and PVB missing SnapshotID does not reset volume name and returns additional items",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "bound-pv",
					DataSource: &corev1api.TypedLocalObjectReference{
						Name: "some-ds",
					},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pvbs: []runtime.Object{
				builder.ForPodVolumeBackup("ns-1", "pvb-1").
					PodNamespace("ns-1").
					Phase(velerov1api.PodVolumeBackupPhaseCompleted).
					SnapshotID("").
					ObjectMeta(builder.WithLabels(
						velerov1api.BackupNameLabel, "backup-1",
						velerov1api.PVCUIDLabel, "uid-1",
					), builder.WithAnnotations("velero.io/pvc-name", "pvc-1")).Result(),
			},
			want: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.PersistentVolumes,
					Name:          "bound-pv",
				},
			},
			wantVolumeName: "bound-pv",
		},
		{
			name: "bound PVC with volume name and PVB with phase Failed does not reset volume name and returns additional items",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "bound-pv",
					DataSource: &corev1api.TypedLocalObjectReference{
						Name: "some-ds",
					},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pvbs: []runtime.Object{
				builder.ForPodVolumeBackup("ns-1", "pvb-1").
					PodNamespace("ns-1").
					Phase(velerov1api.PodVolumeBackupPhaseFailed).
					SnapshotID("snap-1").
					ObjectMeta(builder.WithLabels(
						velerov1api.BackupNameLabel, "backup-1",
						velerov1api.PVCUIDLabel, "uid-1",
					), builder.WithAnnotations("velero.io/pvc-name", "pvc-1")).Result(),
			},
			want: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.PersistentVolumes,
					Name:          "bound-pv",
				},
			},
			wantVolumeName: "bound-pv",
		},
		{
			name: "defensive nil input for restore does not panic when crClient != nil",
			itemFromBackup: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pvc-1",
					Namespace: "ns-1",
					UID:       "uid-1",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "bound-pv",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			pvbs: []runtime.Object{},
			want: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.PersistentVolumes,
					Name:          "bound-pv",
				},
			},
			wantVolumeName: "bound-pv",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			itemFromBackupData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.itemFromBackup)
			require.NoError(t, err)

			itemData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.itemFromBackup)
			require.NoError(t, err)
			// item should have no status
			delete(itemData, "status")

			crClient := velerotest.NewFakeControllerRuntimeClient(t, test.pvbs...)
			action := NewPVCAction(
				velerotest.NewLogger(),
				crClient,
			)

			restoreObj := builder.ForRestore("ns-1", "restore-1").Backup("backup-1").Result()
			if test.name == "defensive nil input for restore does not panic when crClient != nil" {
				restoreObj = nil
			}
			input := &velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: itemData},
				ItemFromBackup: &unstructured.Unstructured{Object: itemFromBackupData},
				Restore:        restoreObj,
			}

			res, err := action.Execute(input)
			require.NoError(t, err)

			assert.Equal(t, test.want, res.AdditionalItems)

			var updatedPVC corev1api.PersistentVolumeClaim
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &updatedPVC)
			require.NoError(t, err)
			assert.Equal(t, test.wantVolumeName, updatedPVC.Spec.VolumeName)
			if test.wantVolumeName == "" && len(test.pvbs) > 0 {
				assert.Nil(t, updatedPVC.Spec.DataSource)
				assert.Nil(t, updatedPVC.Spec.DataSourceRef)
			}
		})
	}
}

func TestRemovePVCAnnotations(t *testing.T) {
	testCases := []struct {
		name                string
		pvc                 corev1api.PersistentVolumeClaim
		removeAnnotations   []string
		expectedAnnotations map[string]string
	}{
		{
			name: "should preserve all existing annotations",
			pvc: corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"ann1": "ann1-val",
						"ann2": "ann2-val",
						"ann3": "ann3-val",
						"ann4": "ann4-val",
					},
				},
			},
			removeAnnotations: []string{},
			expectedAnnotations: map[string]string{
				"ann1": "ann1-val",
				"ann2": "ann2-val",
				"ann3": "ann3-val",
				"ann4": "ann4-val",
			},
		},
		{
			name: "should remove all existing annotations",
			pvc: corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"ann1": "ann1-val",
						"ann2": "ann2-val",
						"ann3": "ann3-val",
						"ann4": "ann4-val",
					},
				},
			},
			removeAnnotations:   []string{"ann1", "ann2", "ann3", "ann4"},
			expectedAnnotations: map[string]string{},
		},
		{
			name: "should preserve some existing annotations",
			pvc: corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"ann1": "ann1-val",
						"ann2": "ann2-val",
						"ann3": "ann3-val",
						"ann4": "ann4-val",
						"ann5": "ann5-val",
						"ann6": "ann6-val",
						"ann7": "ann7-val",
						"ann8": "ann8-val",
					},
				},
			},
			removeAnnotations: []string{"ann1", "ann2", "ann3", "ann4"},
			expectedAnnotations: map[string]string{
				"ann5": "ann5-val",
				"ann6": "ann6-val",
				"ann7": "ann7-val",
				"ann8": "ann8-val",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			removePVCAnnotations(&tc.pvc, tc.removeAnnotations)
			assert.Equal(t, tc.expectedAnnotations, tc.pvc.Annotations)
		})
	}
}
