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

package output

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

func TestDescribeRestoreProgressInSF(t *testing.T) {
	testcases := []struct {
		name   string
		input  *velerov1api.Restore
		expect map[string]any
	}{
		{
			name:   "nil progress — nothing added",
			input:  builder.ForRestore("velero", "r1").Result(),
			expect: map[string]any{},
		},
		{
			name: "in-progress phase shows estimated labels",
			input: func() *velerov1api.Restore {
				r := builder.ForRestore("velero", "r2").Phase(velerov1api.RestorePhaseInProgress).Result()
				r.Status.Progress = &velerov1api.RestoreProgress{TotalItems: 100, ItemsRestored: 50}
				return r
			}(),
			expect: map[string]any{
				"progress": map[string]any{
					"estimatedTotalItemsToBeRestored": 100,
					"itemsRestoredSoFar":              50,
				},
			},
		},
		{
			name: "completed phase shows final labels",
			input: func() *velerov1api.Restore {
				r := builder.ForRestore("velero", "r3").Phase(velerov1api.RestorePhaseCompleted).Result()
				r.Status.Progress = &velerov1api.RestoreProgress{TotalItems: 80, ItemsRestored: 80}
				return r
			}(),
			expect: map[string]any{
				"progress": map[string]any{
					"totalItemsToBeRestored": 80,
					"itemsRestored":          80,
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeRestoreProgressInSF(sd, tc.input)
			assert.Equal(tt, tc.expect, sd.output)
		})
	}
}

func TestDescribeRestoreTimestampsInSF(t *testing.T) {
	t1 := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 1, 10, 13, 0, 0, 0, time.UTC)
	mt1 := metav1.NewTime(t1)
	mt2 := metav1.NewTime(t2)

	testcases := []struct {
		name   string
		input  *velerov1api.Restore
		expect map[string]any
	}{
		{
			name:  "nil timestamps show <n/a>",
			input: builder.ForRestore("velero", "r1").Result(),
			expect: map[string]any{
				"timestamps": map[string]any{
					"started":   "<n/a>",
					"completed": "<n/a>",
				},
			},
		},
		{
			name: "both timestamps set",
			input: func() *velerov1api.Restore {
				r := builder.ForRestore("velero", "r2").Result()
				r.Status.StartTimestamp = &mt1
				r.Status.CompletionTimestamp = &mt2
				return r
			}(),
			expect: map[string]any{
				"timestamps": map[string]any{
					"started":   mt1.String(),
					"completed": mt2.String(),
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeRestoreTimestampsInSF(sd, tc.input)
			assert.Equal(tt, tc.expect, sd.output)
		})
	}
}

func TestDescribeRestoreSpecInSF(t *testing.T) {
	testcases := []struct {
		name   string
		spec   velerov1api.RestoreSpec
		expect map[string]any
	}{
		{
			name: "minimal spec",
			spec: velerov1api.RestoreSpec{
				BackupName: "backup-1",
			},
			expect: map[string]any{
				"spec": map[string]any{
					"backupName": "backup-1",
					"namespaces": map[string]any{
						"included": "all namespaces found in the backup",
						"excluded": emptyDisplay,
					},
					"resources": map[string]string{
						"included":      "*",
						"excluded":      emptyDisplay,
						"clusterScoped": "auto",
					},
					"namespaceMappings":        emptyDisplay,
					"labelSelector":            emptyDisplay,
					"orLabelSelectors":         emptyDisplay,
					"restorePVs":               "auto",
					"existingResourcePolicy":   emptyDisplay,
					"existingVolumeDataPolicy": emptyDisplay,
					"itemOperationTimeout":     "0s",
					"preserveNodePorts":        "auto",
				},
			},
		},
		{
			name: "included namespaces wildcard treated as all",
			spec: velerov1api.RestoreSpec{
				BackupName:               "backup-2",
				IncludedNamespaces:       []string{"*"},
				ExcludedNamespaces:       []string{"kube-system"},
				IncludedResources:        []string{"pods", "configmaps"},
				ExcludedResources:        []string{"secrets"},
				ExistingResourcePolicy:   velerov1api.ResourcePolicyTypeUpdate,
				ExistingVolumeDataPolicy: velerov1api.VolumeDataPolicyTypeFull,
			},
			expect: map[string]any{
				"spec": map[string]any{
					"backupName": "backup-2",
					"namespaces": map[string]any{
						"included": "all namespaces found in the backup",
						"excluded": "kube-system",
					},
					"resources": map[string]string{
						"included":      "pods, configmaps",
						"excluded":      "secrets",
						"clusterScoped": "auto",
					},
					"namespaceMappings":        emptyDisplay,
					"labelSelector":            emptyDisplay,
					"orLabelSelectors":         emptyDisplay,
					"restorePVs":               "auto",
					"existingResourcePolicy":   string(velerov1api.ResourcePolicyTypeUpdate),
					"existingVolumeDataPolicy": string(velerov1api.VolumeDataPolicyTypeFull),
					"itemOperationTimeout":     "0s",
					"preserveNodePorts":        "auto",
				},
			},
		},
		{
			name: "spec with resource modifier and uploader config",
			spec: velerov1api.RestoreSpec{
				BackupName: "backup-3",
				ResourceModifier: &corev1api.TypedLocalObjectReference{
					Kind: "ConfigMap",
					Name: "my-modifier",
				},
				UploaderConfig: &velerov1api.UploaderConfigForRestore{
					WriteSparseFiles:      boolptr.True(),
					ParallelFilesDownload: 4,
				},
			},
			expect: map[string]any{
				"spec": map[string]any{
					"backupName": "backup-3",
					"namespaces": map[string]any{
						"included": "all namespaces found in the backup",
						"excluded": emptyDisplay,
					},
					"resources": map[string]string{
						"included":      "*",
						"excluded":      emptyDisplay,
						"clusterScoped": "auto",
					},
					"namespaceMappings":        emptyDisplay,
					"labelSelector":            emptyDisplay,
					"orLabelSelectors":         emptyDisplay,
					"restorePVs":               "auto",
					"existingResourcePolicy":   emptyDisplay,
					"existingVolumeDataPolicy": emptyDisplay,
					"itemOperationTimeout":     "0s",
					"preserveNodePorts":        "auto",
					"resourceModifier": map[string]any{
						"type": "ConfigMap",
						"name": "my-modifier",
					},
					"uploaderConfig": map[string]any{
						"writeSparseFiles":      true,
						"parallelFilesDownload": 4,
					},
				},
			},
		},
		{
			name: "namespaces, mappings, selectors, resource policy and flags",
			spec: velerov1api.RestoreSpec{
				BackupName:              "backup-4",
				IncludedNamespaces:      []string{"ns-a", "ns-b"},
				NamespaceMapping:        map[string]string{"ns-a": "ns-a-new"},
				LabelSelector:           &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}},
				OrLabelSelectors:        []*metav1.LabelSelector{{MatchLabels: map[string]string{"env": "prod"}}, {MatchLabels: map[string]string{"env": "stage"}}},
				IncludeClusterResources: boolptr.True(),
				RestorePVs:              boolptr.True(),
				PreserveNodePorts:       boolptr.False(),
				ResourcePolicy: &corev1api.TypedLocalObjectReference{
					Kind: "configmap",
					Name: "volume-policy",
				},
				UploaderConfig: &velerov1api.UploaderConfigForRestore{
					WriteSparseFiles: boolptr.False(),
				},
			},
			expect: map[string]any{
				"spec": map[string]any{
					"backupName": "backup-4",
					"namespaces": map[string]any{
						"included": "ns-a, ns-b",
						"excluded": emptyDisplay,
					},
					"resources": map[string]string{
						"included":      "*",
						"excluded":      emptyDisplay,
						"clusterScoped": "included",
					},
					"namespaceMappings":        map[string]string{"ns-a": "ns-a-new"},
					"labelSelector":            "app=nginx",
					"orLabelSelectors":         "env=prod or env=stage",
					"restorePVs":               "true",
					"existingResourcePolicy":   emptyDisplay,
					"existingVolumeDataPolicy": emptyDisplay,
					"itemOperationTimeout":     "0s",
					"preserveNodePorts":        "false",
					"resourcePolicy": map[string]any{
						"type": "configmap",
						"name": "volume-policy",
					},
					"uploaderConfig": map[string]any{},
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeRestoreSpecInSF(sd, tc.spec)
			assert.Equal(tt, tc.expect, sd.output)
		})
	}
}

func TestDescribePodVolumeRestoresInSF(t *testing.T) {
	pvr1 := builder.ForPodVolumeRestore("velero", "pvr-1").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeRestorePhaseCompleted).
		Volume("vol-1").
		PodName("pod-1").
		PodNamespace("ns-1").Result()

	pvr2 := builder.ForPodVolumeRestore("velero", "pvr-2").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeRestorePhaseCompleted).
		Volume("vol-2").
		PodName("pod-2").
		PodNamespace("ns-1").Result()

	pvr3 := builder.ForPodVolumeRestore("velero", "pvr-3").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeRestorePhaseFailed).
		Volume("vol-3").
		PodName("pod-3").
		PodNamespace("ns-1").Result()

	testcases := []struct {
		name     string
		restores []velerov1api.PodVolumeRestore
		details  bool
		expect   map[string]any
	}{
		{
			name:     "empty list",
			restores: []velerov1api.PodVolumeRestore{},
			details:  false,
			expect: map[string]any{
				"podVolumeRestores": "<none included>",
			},
		},
		{
			name:     "2 completed, no details",
			restores: []velerov1api.PodVolumeRestore{*pvr1, *pvr2},
			details:  false,
			expect: map[string]any{
				"podVolumeRestores": map[string]any{
					"uploaderType": "kopia",
					"Completed":    2,
				},
			},
		},
		{
			name:     "2 completed with details",
			restores: []velerov1api.PodVolumeRestore{*pvr1, *pvr2},
			details:  true,
			expect: map[string]any{
				"podVolumeRestores": map[string]any{
					"uploaderType": "kopia",
					"Completed": []map[string]string{
						{"ns-1/pod-1": "vol-1"},
						{"ns-1/pod-2": "vol-2"},
					},
				},
			},
		},
		{
			name:     "completed and failed, no details",
			restores: []velerov1api.PodVolumeRestore{*pvr1, *pvr2, *pvr3},
			details:  false,
			expect: map[string]any{
				"podVolumeRestores": map[string]any{
					"uploaderType": "kopia",
					"Completed":    2,
					"Failed":       1,
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describePodVolumeRestoresInSF(sd, tc.restores, tc.details)
			assert.Equal(tt, tc.expect, sd.output)
		})
	}
}

func TestDescribeRestoreCSISnapshotsInSF_NoData(t *testing.T) {
	testcases := []struct {
		name             string
		inputVolInfoList []volume.RestoreVolumeInfo
		details          bool
		expect           map[string]any
	}{
		{
			name:             "no CSI entries — none included",
			inputVolInfoList: []volume.RestoreVolumeInfo{},
			details:          false,
			expect: map[string]any{
				"csiSnapshotRestores": "<none included>",
			},
		},
		{
			name: "only native snapshot entries — none included",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod: volume.NativeSnapshot,
					PVCName:       "pvc-1",
					PVCNamespace:  "ns-1",
				},
			},
			details: false,
			expect: map[string]any{
				"csiSnapshotRestores": "<none included>",
			},
		},
		{
			name: "CSI snapshot, no details",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod: volume.CSISnapshot,
					PVCName:       "pvc-1",
					PVCNamespace:  "ns-1",
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						VSCName:        "vsc-1",
						SnapshotHandle: "snap-handle-1",
						Driver:         "csi.test.driver",
					},
				},
			},
			details: false,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-1/pvc-1": map[string]any{
						"snapshot": "specify --details for more information",
					},
				},
			},
		},
		{
			name: "CSI snapshot, with details",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod: volume.CSISnapshot,
					PVCName:       "pvc-2",
					PVCNamespace:  "ns-2",
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						VSCName:        "vsc-2",
						SnapshotHandle: "snap-handle-2",
						Driver:         "csi.test.driver",
					},
				},
			},
			details: true,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-2/pvc-2": map[string]any{
						"snapshot": map[string]any{
							"snapshotContentName": "vsc-2",
							"storageSnapshotID":   "snap-handle-2",
							"csiDriver":           "csi.test.driver",
						},
					},
				},
			},
		},
		{
			name: "data movement entry, with details",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod:     volume.CSISnapshot,
					SnapshotDataMoved: true,
					PVCName:           "pvc-3",
					PVCNamespace:      "ns-3",
					SnapshotDataMovementInfo: &volume.RestoreSnapshotDataMovementInfo{
						OperationID:     "op-3",
						DataMover:       "velero",
						UploaderType:    "kopia",
						Size:            1234,
						IncrementalSize: ptr.To(int64(500)),
						RestoreType:     "Incremental",
					},
				},
			},
			details: true,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-3/pvc-3": map[string]any{
						"dataMovement": map[string]any{
							"operationID":     "op-3",
							"dataMover":       "velero",
							"uploaderType":    "kopia",
							"size":            int64(1234),
							"incrementalSize": int64(500),
							"restoreType":     "Incremental",
						},
					},
				},
			},
		},
		{
			name: "data movement entry, no details",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod:     volume.CSISnapshot,
					SnapshotDataMoved: true,
					PVCName:           "pvc-3",
					PVCNamespace:      "ns-3",
					SnapshotDataMovementInfo: &volume.RestoreSnapshotDataMovementInfo{
						OperationID:  "op-3",
						DataMover:    "velero",
						UploaderType: "kopia",
					},
				},
			},
			details: false,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-3/pvc-3": map[string]any{
						"dataMovement": "specify --details for more information",
					},
				},
			},
		},
		{
			name: "CSI snapshot with details and nil CSISnapshotInfo",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod:   volume.CSISnapshot,
					PVCName:         "pvc-4",
					PVCNamespace:    "ns-4",
					CSISnapshotInfo: nil,
				},
			},
			details: true,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-4/pvc-4": map[string]any{
						"snapshot": "<CSI snapshot info not found>",
					},
				},
			},
		},
		{
			name: "data movement with details and nil SnapshotDataMovementInfo",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					RestoreMethod:            volume.CSISnapshot,
					SnapshotDataMoved:        true,
					PVCName:                  "pvc-5",
					PVCNamespace:             "ns-5",
					SnapshotDataMovementInfo: nil,
				},
			},
			details: true,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-5/pvc-5": map[string]any{
						"dataMovement": "<snapshot data movement info not found>",
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeCSISnapshotsRestoresInSF(sd, tc.inputVolInfoList, tc.details)
			assert.Equal(tt, tc.expect, sd.output)
		})
	}
}

func TestDescribeCSISnapshotsRestoresFromReader(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		describeCSISnapshotsRestoresFromReader(sd, strings.NewReader("not-json"), false)
		got, ok := sd.output["csiSnapshotRestores"].(string)
		require.True(t, ok)
		assert.Contains(t, got, "<error reading restore volume info:")
	})

	t.Run("valid json", func(t *testing.T) {
		volInfo := []volume.RestoreVolumeInfo{
			{
				RestoreMethod: volume.CSISnapshot,
				PVCName:       "pvc-1",
				PVCNamespace:  "ns-1",
				CSISnapshotInfo: &volume.CSISnapshotInfo{
					VSCName:        "vsc-1",
					SnapshotHandle: "snap-handle-1",
					Driver:         "csi.test.driver",
				},
			},
		}
		data, err := json.Marshal(volInfo)
		require.NoError(t, err)

		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		describeCSISnapshotsRestoresFromReader(sd, bytes.NewReader(data), false)
		assert.Equal(t, map[string]any{
			"csiSnapshotRestores": map[string]any{
				"ns-1/pvc-1": map[string]any{
					"snapshot": "specify --details for more information",
				},
			},
		}, sd.output)
	})
}

func TestDescribeRestoreItemOperationsInSF_NoDownload(t *testing.T) {
	kbClient := test.NewFakeControllerRuntimeClient(t)
	testcases := []struct {
		name   string
		status velerov1api.RestoreStatus
		expect map[string]any
	}{
		{
			name:   "zero operations — nothing added",
			status: velerov1api.RestoreStatus{},
			expect: map[string]any{},
		},
		{
			name: "some operations, no details",
			status: velerov1api.RestoreStatus{
				RestoreItemOperationsAttempted: 5,
				RestoreItemOperationsCompleted: 4,
				RestoreItemOperationsFailed:    1,
			},
			expect: map[string]any{
				"restoreItemOperations": map[string]any{
					"attempted": 5,
					"completed": 4,
					"failed":    1,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			restore := builder.ForRestore("velero", "r1").Result()
			restore.Status = tc.status

			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeRestoreItemOperationsInSF(context.Background(), kbClient, sd, restore, false, false, "")
			assert.Equal(tt, tc.expect, sd.output)
		})
	}
}

func TestDescribeRestoreItemOperationsInSF_DownloadError(t *testing.T) {
	kbClient := test.NewFakeControllerRuntimeClient(t)
	restore := builder.ForRestore("velero", "r1").Result()
	restore.Status.RestoreItemOperationsAttempted = 2
	restore.Status.RestoreItemOperationsCompleted = 1
	restore.Status.RestoreItemOperationsFailed = 1

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sd := &StructuredDescriber{output: make(map[string]any), format: ""}
	describeRestoreItemOperationsInSF(ctx, kbClient, sd, restore, true, false, "")

	ops, ok := sd.output["restoreItemOperations"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 2, ops["attempted"])
	assert.Equal(t, 1, ops["completed"])
	assert.Equal(t, 1, ops["failed"])
	_, hasErr := ops["errorGettingOperations"]
	assert.True(t, hasErr)
}

func TestDescribeRestoreItemOperationInSF(t *testing.T) {
	t1 := time.Date(2023, 6, 26, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2023, 6, 25, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2023, 6, 24, 0, 0, 0, 0, time.UTC)

	input := builder.ForRestoreOperation().
		RestoreName("restore-1").
		OperationID("op-1").
		RestoreItemAction("action-1").
		ResourceIdentifier("group", "rs-type", "ns", "rs-name").
		Status(*builder.ForOperationStatus().
			Phase(itemoperation.OperationPhaseFailed).
			Error("operation error").
			Progress(50, 100, "bytes").
			Description("operation description").
			Created(t3).
			Started(t2).
			Updated(t1).
			Result()).Result()

	got := describeRestoreItemOperationInSF(input)
	assert.Equal(t, "operation error", got["error"])
	assert.Equal(t, "op-1", got["operationID"])
	assert.Equal(t, "action-1", got["restoreItemActionPlugin"])
	assert.Equal(t, itemoperation.OperationPhaseFailed, got["phase"])
	assert.Equal(t, "operation description", got["progressDescription"])
	assert.Equal(t, t3.String(), got["created"])
	assert.Equal(t, t2.String(), got["started"])
	assert.Equal(t, t1.String(), got["updated"])
	assert.Equal(t, map[string]any{
		"completed": int64(50),
		"total":     int64(100),
		"units":     "bytes",
	}, got["progress"])
}

func TestDescribeRestoreItemOperationsFromReader(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		opsInfo := map[string]any{"attempted": 1}
		describeRestoreItemOperationsFromReader(sd, opsInfo, strings.NewReader("not-json"))
		got, ok := sd.output["restoreItemOperations"].(map[string]any)
		require.True(t, ok)
		_, hasErr := got["errorReadingOperations"]
		assert.True(t, hasErr)
	})

	t.Run("valid json", func(t *testing.T) {
		op := builder.ForRestoreOperation().
			RestoreName("restore-1").
			OperationID("op-1").
			RestoreItemAction("action-1").
			ResourceIdentifier("group", "rs-type", "ns", "rs-name").
			Status(*builder.ForOperationStatus().Phase(itemoperation.OperationPhaseCompleted).Result()).
			Result()
		data, err := json.Marshal([]*itemoperation.RestoreOperation{op})
		require.NoError(t, err)

		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		opsInfo := map[string]any{"attempted": 1, "completed": 1, "failed": 0}
		describeRestoreItemOperationsFromReader(sd, opsInfo, bytes.NewReader(data))

		got, ok := sd.output["restoreItemOperations"].(map[string]any)
		require.True(t, ok)
		ops, ok := got["operations"].([]map[string]any)
		require.True(t, ok)
		require.Len(t, ops, 1)
		assert.Equal(t, "op-1", ops[0]["operationID"])
	})
}

func TestDescribeResourceModifierInSF(t *testing.T) {
	input := &corev1api.TypedLocalObjectReference{
		Kind: "ConfigMap",
		Name: "my-modifier",
	}
	expect := map[string]any{
		"type": "ConfigMap",
		"name": "my-modifier",
	}
	assert.Equal(t, expect, describeResourceModifierInSF(input))
}

func TestDescribeRestoreResultsFromReader(t *testing.T) {
	restoreBoth := builder.ForRestore("velero", "r1").Result()
	restoreBoth.Status.Warnings = 2
	restoreBoth.Status.Errors = 1

	t.Run("invalid json", func(t *testing.T) {
		warnings, errs := make(map[string]any), make(map[string]any)
		describeRestoreResultsFromReader(warnings, errs, strings.NewReader("not-json"), restoreBoth)
		_, hasWarn := warnings["errorDecodingWarnings"]
		_, hasErr := errs["errorDecodingErrors"]
		assert.True(t, hasWarn)
		assert.True(t, hasErr)
	})

	t.Run("valid json", func(t *testing.T) {
		payload := map[string]results.Result{
			"warnings": {
				Velero:  []string{"w1"},
				Cluster: []string{"c1"},
				Namespaces: map[string][]string{
					"ns-1": {"n1"},
				},
			},
			"errors": {
				Velero: []string{"e1"},
			},
		}
		data, err := json.Marshal(payload)
		require.NoError(t, err)

		warnings, errs := make(map[string]any), make(map[string]any)
		describeRestoreResultsFromReader(warnings, errs, bytes.NewReader(data), restoreBoth)
		assert.Equal(t, []string{"w1"}, warnings["velero"])
		assert.Equal(t, []string{"c1"}, warnings["cluster"])
		assert.Equal(t, map[string][]string{"ns-1": {"n1"}}, warnings["namespace"])
		assert.Equal(t, []string{"e1"}, errs["velero"])
	})

	t.Run("warnings only decode error", func(t *testing.T) {
		restore := builder.ForRestore("velero", "r2").Result()
		restore.Status.Warnings = 1
		warnings, errs := make(map[string]any), make(map[string]any)
		describeRestoreResultsFromReader(warnings, errs, strings.NewReader("not-json"), restore)
		_, hasWarn := warnings["errorDecodingWarnings"]
		assert.True(t, hasWarn)
		assert.Empty(t, errs)
	})

	t.Run("errors only decode error", func(t *testing.T) {
		restore := builder.ForRestore("velero", "r3").Result()
		restore.Status.Errors = 1
		warnings, errs := make(map[string]any), make(map[string]any)
		describeRestoreResultsFromReader(warnings, errs, strings.NewReader("not-json"), restore)
		_, hasErr := errs["errorDecodingErrors"]
		assert.True(t, hasErr)
		assert.Empty(t, warnings)
	})
}

func TestDescribeRestoreResultsInSF(t *testing.T) {
	kbClient := test.NewFakeControllerRuntimeClient(t)

	t.Run("no warnings or errors", func(t *testing.T) {
		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		restore := builder.ForRestore("velero", "r1").Result()
		describeRestoreResultsInSF(context.Background(), kbClient, sd, restore, false, "")
		assert.Empty(t, sd.output)
	})

	t.Run("download error", func(t *testing.T) {
		restore := builder.ForRestore("velero", "r1").Result()
		restore.Status.Warnings = 1
		restore.Status.Errors = 1

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		describeRestoreResultsInSF(ctx, kbClient, sd, restore, false, "")

		warnings, ok := sd.output["warnings"].(map[string]any)
		require.True(t, ok)
		_, hasWarn := warnings["errorGettingWarnings"]
		assert.True(t, hasWarn)

		errs, ok := sd.output["errors"].(map[string]any)
		require.True(t, ok)
		_, hasErr := errs["errorGettingErrors"]
		assert.True(t, hasErr)
	})

	t.Run("download error warnings only", func(t *testing.T) {
		restore := builder.ForRestore("velero", "r1").Result()
		restore.Status.Warnings = 1
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		describeRestoreResultsInSF(ctx, kbClient, sd, restore, false, "")
		_, hasWarn := sd.output["warnings"]
		_, hasErr := sd.output["errors"]
		assert.True(t, hasWarn)
		assert.False(t, hasErr)
	})

	t.Run("download error errors only", func(t *testing.T) {
		restore := builder.ForRestore("velero", "r1").Result()
		restore.Status.Errors = 1
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		describeRestoreResultsInSF(ctx, kbClient, sd, restore, false, "")
		_, hasWarn := sd.output["warnings"]
		_, hasErr := sd.output["errors"]
		assert.False(t, hasWarn)
		assert.True(t, hasErr)
	})
}

func TestDescribeRestoreResourceListFromReader(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		describeRestoreResourceListFromReader(sd, strings.NewReader("not-json"))
		got, ok := sd.output["resourceList"].(string)
		require.True(t, ok)
		assert.Contains(t, got, "<error reading restore resource list:")
	})

	t.Run("valid json", func(t *testing.T) {
		sd := &StructuredDescriber{output: make(map[string]any), format: ""}
		payload := map[string][]string{"v1/Pod": {"ns/pod-1"}}
		data, err := json.Marshal(payload)
		require.NoError(t, err)
		describeRestoreResourceListFromReader(sd, bytes.NewReader(data))
		assert.Equal(t, payload, sd.output["resourceList"])
	})
}

func TestDescribeRestoreResourceListInSF_DownloadError(t *testing.T) {
	kbClient := test.NewFakeControllerRuntimeClient(t)
	restore := builder.ForRestore("velero", "r1").Result()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sd := &StructuredDescriber{output: make(map[string]any), format: ""}
	describeRestoreResourceListInSF(ctx, kbClient, sd, restore, false, "")
	got, ok := sd.output["resourceList"].(string)
	require.True(t, ok)
	assert.Contains(t, got, "<error getting restore resource list:")
}

func TestDescribeRestoreCSISnapshotsInSF_DownloadError(t *testing.T) {
	kbClient := test.NewFakeControllerRuntimeClient(t)
	restore := builder.ForRestore("velero", "r1").Result()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sd := &StructuredDescriber{output: make(map[string]any), format: ""}
	describeRestoreCSISnapshotsInSF(ctx, kbClient, sd, restore, false, false, "")
	got, ok := sd.output["csiSnapshotRestores"].(string)
	require.True(t, ok)
	assert.Contains(t, got, "<error getting restore volume info:")
}

func TestDescribeRestoreInSF(t *testing.T) {
	kbClient := test.NewFakeControllerRuntimeClient(t)
	started := metav1.NewTime(time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC))
	completed := metav1.NewTime(time.Date(2024, 1, 10, 13, 0, 0, 0, time.UTC))
	deletedAt := metav1.NewTime(time.Date(2024, 1, 10, 14, 0, 0, 0, time.UTC))

	pvr := builder.ForPodVolumeRestore("velero", "pvr-1").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeRestorePhaseCompleted).
		Volume("vol-1").
		PodName("pod-1").
		PodNamespace("ns-1").Result()

	restore := builder.ForRestore("velero", "restore-1").
		Backup("backup-1").
		Phase(velerov1api.RestorePhaseCompleted).
		ObjectMeta(builder.WithLabels("app", "velero"), builder.WithAnnotations("a", "b")).
		Result()
	restore.DeletionTimestamp = &deletedAt
	restore.Status.StartTimestamp = &started
	restore.Status.CompletionTimestamp = &completed
	restore.Status.Progress = &velerov1api.RestoreProgress{TotalItems: 10, ItemsRestored: 10}
	restore.Status.ValidationErrors = []string{"invalid include"}
	restore.Status.Warnings = 1
	restore.Status.Errors = 1
	restore.Status.RestoreItemOperationsAttempted = 2
	restore.Status.RestoreItemOperationsCompleted = 2
	restore.Status.HookStatus = &velerov1api.HookStatus{HooksAttempted: 3, HooksFailed: 1}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := DescribeRestoreInSF(ctx, kbClient, restore, []velerov1api.PodVolumeRestore{*pvr}, true, false, "", "json")

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	assert.Equal(t, "Completed (Deleting)", parsed["phase"])
	assert.Contains(t, parsed, "metadata")
	assert.Contains(t, parsed, "progress")
	assert.Contains(t, parsed, "timestamps")
	assert.Contains(t, parsed, "spec")
	assert.Contains(t, parsed, "podVolumeRestores")
	assert.Contains(t, parsed, "hookStatus")
	assert.Equal(t, []any{"invalid include"}, parsed["validationErrors"])

	t.Run("empty phase defaults to New", func(t *testing.T) {
		r := builder.ForRestore("velero", "restore-2").Result()
		out := DescribeRestoreInSF(ctx, kbClient, r, nil, false, false, "", "json")
		require.Contains(t, out, `"phase": "New"`)
	})
}
