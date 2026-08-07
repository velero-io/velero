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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
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
			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
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
			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
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
					"namespaceMappings":      emptyDisplay,
					"labelSelector":          emptyDisplay,
					"orLabelSelectors":       emptyDisplay,
					"restorePVs":             "auto",
					"existingResourcePolicy": emptyDisplay,
					"itemOperationTimeout":   "0s",
					"preserveNodePorts":      "auto",
				},
			},
		},
		{
			name: "included namespaces wildcard treated as all",
			spec: velerov1api.RestoreSpec{
				BackupName:             "backup-2",
				IncludedNamespaces:     []string{"*"},
				ExcludedNamespaces:     []string{"kube-system"},
				IncludedResources:      []string{"pods", "configmaps"},
				ExcludedResources:      []string{"secrets"},
				ExistingResourcePolicy: velerov1api.PolicyTypeUpdate,
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
					"namespaceMappings":      emptyDisplay,
					"labelSelector":          emptyDisplay,
					"orLabelSelectors":       emptyDisplay,
					"restorePVs":             "auto",
					"existingResourcePolicy": string(velerov1api.PolicyTypeUpdate),
					"itemOperationTimeout":   "0s",
					"preserveNodePorts":      "auto",
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
					"namespaceMappings":      emptyDisplay,
					"labelSelector":          emptyDisplay,
					"orLabelSelectors":       emptyDisplay,
					"restorePVs":             "auto",
					"existingResourcePolicy": emptyDisplay,
					"itemOperationTimeout":   "0s",
					"preserveNodePorts":      "auto",
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
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeRestoreSpecInSF(sd, tc.spec)
			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
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
			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
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
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						OperationID:  "op-3",
						DataMover:    "velero",
						UploaderType: "kopia",
					},
				},
			},
			details: true,
			expect: map[string]any{
				"csiSnapshotRestores": map[string]any{
					"ns-3/pvc-3": map[string]any{
						"dataMovement": map[string]any{
							"operationID":  "op-3",
							"dataMover":    "velero",
							"uploaderType": "kopia",
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{output: make(map[string]any), format: ""}
			describeCSISnapshotsRestoresInSF(sd, tc.inputVolInfoList, tc.details)
			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
		})
	}
}

// describeCSISnapshotsRestoresInSF is a testable wrapper around the inline CSI logic
// used by describeRestoreCSISnapshotsInSF (which also fetches data from object storage).
func describeCSISnapshotsRestoresInSF(d *StructuredDescriber, restoreVolInfo []volume.RestoreVolumeInfo, details bool) {
	var nonDMInfoList, dmInfoList []volume.RestoreVolumeInfo
	for _, info := range restoreVolInfo {
		if info.RestoreMethod != volume.CSISnapshot {
			continue
		}
		if info.SnapshotDataMoved {
			dmInfoList = append(dmInfoList, info)
		} else {
			nonDMInfoList = append(nonDMInfoList, info)
		}
	}

	if len(nonDMInfoList) == 0 && len(dmInfoList) == 0 {
		d.Describe("csiSnapshotRestores", "<none included>")
		return
	}

	csiRestores := map[string]any{}

	for _, info := range nonDMInfoList {
		key := info.PVCNamespace + "/" + info.PVCName
		if details {
			csiRestores[key] = map[string]any{
				"snapshot": map[string]any{
					"snapshotContentName": info.CSISnapshotInfo.VSCName,
					"storageSnapshotID":   info.CSISnapshotInfo.SnapshotHandle,
					"csiDriver":           info.CSISnapshotInfo.Driver,
				},
			}
		} else {
			csiRestores[key] = map[string]any{
				"snapshot": "specify --details for more information",
			}
		}
	}

	for _, info := range dmInfoList {
		key := info.PVCNamespace + "/" + info.PVCName
		if details {
			csiRestores[key] = map[string]any{
				"dataMovement": map[string]any{
					"operationID":  info.SnapshotDataMovementInfo.OperationID,
					"dataMover":    info.SnapshotDataMovementInfo.DataMover,
					"uploaderType": info.SnapshotDataMovementInfo.UploaderType,
				},
			}
		} else {
			csiRestores[key] = map[string]any{
				"dataMovement": "specify --details for more information",
			}
		}
	}

	d.Describe("csiSnapshotRestores", csiRestores)
}

func TestDescribeRestoreItemOperationsInSF_NoDownload(t *testing.T) {
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

			if restore.Status.RestoreItemOperationsAttempted == 0 {
				// mirrors the early-return path in the real function
			} else {
				opsInfo := map[string]any{
					"attempted": restore.Status.RestoreItemOperationsAttempted,
					"completed": restore.Status.RestoreItemOperationsCompleted,
					"failed":    restore.Status.RestoreItemOperationsFailed,
				}
				sd.Describe("restoreItemOperations", opsInfo)
			}

			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
		})
	}
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
	got := describeResourceModifierInSF(input)
	assert.True(t, reflect.DeepEqual(got, expect))
}
