/*
Copyright 2017 the Velero contributors.

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

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	v1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestBackupPVAction(t *testing.T) {
	tests := []struct {
		name            string
		pvc             *corev1api.PersistentVolumeClaim
		pods            []*corev1api.Pod
		expectedErr     error
		expectedRelated []velero.ResourceIdentifier
	}{
		{
			name:            "Test no volumeName",
			pvc:             builder.ForPersistentVolumeClaim("velero", "testPVC").Phase(corev1api.ClaimBound).Result(),
			expectedErr:     nil,
			expectedRelated: nil,
		},
		{
			name:            "Test empty volumeName",
			pvc:             builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("").Phase(corev1api.ClaimBound).Result(),
			expectedErr:     nil,
			expectedRelated: nil,
		},
		{
			name:            "Test no status phase",
			pvc:             builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Result(),
			expectedErr:     nil,
			expectedRelated: nil,
		},
		{
			name:            "Test pending status phase",
			pvc:             builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimPending).Result(),
			expectedErr:     nil,
			expectedRelated: nil,
		},
		{
			name:            "Test lost status phase",
			pvc:             builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimLost).Result(),
			expectedErr:     nil,
			expectedRelated: nil,
		},
		{
			name:        "Test with volume",
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).Result(),
			expectedErr: nil,
			expectedRelated: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PersistentVolumes, Name: "testPV"},
			},
		},
		{
			name: "Test with volume and one running pod",
			pvc:  builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).Result(),
			pods: []*corev1api.Pod{
				builder.ForPod("velero", "testPod1").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).NodeName("velero").Phase(corev1api.PodRunning).Result(),
			},
			expectedErr: nil,
			expectedRelated: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PersistentVolumes, Name: "testPV"},
				{GroupResource: kuberesource.Pods, Namespace: "velero", Name: "testPod1"},
			},
		},
		{
			name: "Test with volume and multiple running pods",
			pvc:  builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).Result(),
			pods: []*corev1api.Pod{
				builder.ForPod("velero", "testPod1").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).NodeName("velero").Phase(corev1api.PodRunning).Result(),
				builder.ForPod("velero", "testPod2").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).NodeName("velero").Phase(corev1api.PodRunning).Result(),
				builder.ForPod("velero", "testPod3").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).NodeName("velero").Phase(corev1api.PodRunning).Result(),
			},
			expectedErr: nil,
			expectedRelated: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PersistentVolumes, Name: "testPV"},
				{GroupResource: kuberesource.Pods, Namespace: "velero", Name: "testPod1"},
				{GroupResource: kuberesource.Pods, Namespace: "velero", Name: "testPod2"},
				{GroupResource: kuberesource.Pods, Namespace: "velero", Name: "testPod3"},
			},
		},
		{
			name: "Test with volume and multiple running pods, some not running",
			pvc:  builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).Result(),
			pods: []*corev1api.Pod{
				builder.ForPod("velero", "testPod1").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).NodeName("velero").Phase(corev1api.PodSucceeded).Result(),
				builder.ForPod("velero", "testPod2").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).NodeName("velero").Phase(corev1api.PodRunning).Result(),
				builder.ForPod("velero", "testPod3").Volumes(builder.ForVolume("testPVC").PersistentVolumeClaimSource("testPVC").Result()).Phase(corev1api.PodRunning).Result(),
			},
			expectedErr: nil,
			expectedRelated: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PersistentVolumes, Name: "testPV"},
				{GroupResource: kuberesource.Pods, Namespace: "velero", Name: "testPod2"},
			},
		},
		{
			name: "Test with PVC grouping via VGS label",
			pvc:  builder.ForPersistentVolumeClaim("velero", "testPVC-1").ObjectMeta(builder.WithLabels("velero.io/group", "db")).VolumeName("testPV-1").Phase(corev1api.ClaimBound).Result(),
			pods: []*corev1api.Pod{
				builder.ForPod("velero", "testPod-1").
					Volumes(builder.ForVolume("testPV-1").PersistentVolumeClaimSource("testPVC-1").Result()).
					NodeName("node").
					Phase(corev1api.PodRunning).Result(),
			},
			expectedErr: nil,
			expectedRelated: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PersistentVolumes, Name: "testPV-1"},
				{GroupResource: kuberesource.Pods, Namespace: "velero", Name: "testPod-1"},
				{GroupResource: kuberesource.PersistentVolumeClaims, Namespace: "velero", Name: "groupedPVC"},
			},
		},
	}

	backup := &v1.Backup{}
	logger := logrus.New()

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewPVCAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			f := &factorymocks.Factory{}
			f.On("KubebuilderClient").Return(crClient, nil)
			plugin := NewPVCAction(f)
			i, err := plugin(logger)
			require.NoError(t, err)
			a := i.(*PVCAction)

			if tc.pvc != nil {
				require.NoError(t, crClient.Create(t.Context(), tc.pvc))
			}
			for _, pod := range tc.pods {
				require.NoError(t, crClient.Create(t.Context(), pod))
			}

			if tc.name == "Test with PVC grouping via VGS label" {
				groupedPVC := builder.ForPersistentVolumeClaim("velero", "groupedPVC").ObjectMeta(builder.WithLabels("velero.io/group", "db")).VolumeName("groupedPV").Phase(corev1api.ClaimBound).Result()
				require.NoError(t, crClient.Create(t.Context(), groupedPVC))
				backup.Spec.VolumeGroupSnapshotLabelKey = "velero.io/group"
			}

			pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&tc.pvc)
			require.NoError(t, err)

			relatedItems, err := a.GetRelatedItems(&unstructured.Unstructured{Object: pvcMap}, backup)
			if tc.expectedErr != nil {
				require.EqualError(t, err, tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.expectedRelated, relatedItems)
		})
	}
}

// Test_getGroupedPVCs verifies the PVC grouping logic for VolumeGroupSnapshots.
// This ensures only same-namespace PVCs with the same label key and value are included.
func Test_getGroupedPVCs(t *testing.T) {
	tests := []struct {
		name            string
		labelKey        string
		groupValue      string
		existingPVCs    []*corev1api.PersistentVolumeClaim
		targetPVC       *corev1api.PersistentVolumeClaim
		expectedRelated []velero.ResourceIdentifier
		expectError     bool
	}{
		{
			name:        "No label key in spec",
			labelKey:    "",
			targetPVC:   builder.ForPersistentVolumeClaim("ns", "pvc-1").Result(),
			expectError: false,
		},
		{
			name:        "No group value",
			labelKey:    "velero.io/group",
			groupValue:  "",
			targetPVC:   builder.ForPersistentVolumeClaim("ns", "pvc-1").Result(),
			expectError: false,
		},
		{
			name:        "Target PVC does not have the label",
			labelKey:    "velero.io/group",
			targetPVC:   builder.ForPersistentVolumeClaim("ns", "pvc-1").Result(),
			expectError: false,
		},
		{
			name:       "Target PVC has label, but no group matches",
			labelKey:   "velero.io/group",
			groupValue: "group-1",
			targetPVC:  builder.ForPersistentVolumeClaim("ns", "pvc-1").ObjectMeta(builder.WithLabels("velero.io/group", "group-1")).Result(),
			existingPVCs: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").ObjectMeta(builder.WithLabels("velero.io/group", "group-1")).Result(),
			},
			expectError:     false,
			expectedRelated: nil,
		},
		{
			name:       "Multiple PVCs in the same group",
			labelKey:   "velero.io/group",
			groupValue: "group-1",
			targetPVC:  builder.ForPersistentVolumeClaim("ns", "pvc-1").ObjectMeta(builder.WithLabels("velero.io/group", "group-1")).Result(),
			existingPVCs: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").ObjectMeta(builder.WithLabels("velero.io/group", "group-1")).Result(),
				builder.ForPersistentVolumeClaim("ns", "pvc-2").ObjectMeta(builder.WithLabels("velero.io/group", "group-1")).Result(),
				builder.ForPersistentVolumeClaim("ns", "pvc-3").ObjectMeta(builder.WithLabels("velero.io/group", "group-1")).Result(),
			},
			expectError: false,
			expectedRelated: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PersistentVolumeClaims, Namespace: "ns", Name: "pvc-2"},
				{GroupResource: kuberesource.PersistentVolumeClaims, Namespace: "ns", Name: "pvc-3"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			for _, pvc := range tc.existingPVCs {
				require.NoError(t, crClient.Create(t.Context(), pvc))
			}

			logger := logrus.New()
			a := &PVCAction{
				log:      logger,
				crClient: crClient,
			}

			backup := builder.ForBackup("ns", "bkp").VolumeGroupSnapshotLabelKey(tc.labelKey).Result()

			related, err := a.getGroupedPVCs(t.Context(), tc.targetPVC, backup)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.ElementsMatch(t, tc.expectedRelated, related)
		})
	}
}
