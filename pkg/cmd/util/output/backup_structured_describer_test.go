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
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

func TestDescribeBackupInSF(t *testing.T) {
	sd := &StructuredDescriber{
		output: make(map[string]any),
		format: "",
	}
	backupBuilder1 := builder.ForBackup("test-ns", "test-backup")
	backupBuilder1.IncludedNamespaces("inc-ns-1", "inc-ns-2").
		ExcludedNamespaces("exc-ns-1", "exc-ns-2").
		IncludedResources("inc-res-1", "inc-res-2").
		ExcludedResources("exc-res-1", "exc-res-2").
		StorageLocation("backup-location").
		TTL(72 * time.Hour).
		CSISnapshotTimeout(10 * time.Minute).
		DataMover("mover").
		Hooks(velerov1api.BackupHooks{
			Resources: []velerov1api.BackupResourceHookSpec{
				{
					Name: "hook-1",
					PreHooks: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "hook-container-1",
								Command:   []string{"pre"},
								OnError:   velerov1api.HookErrorModeContinue,
							},
						},
					},
					PostHooks: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "hook-container-1",
								Command:   []string{"post"},
								OnError:   velerov1api.HookErrorModeContinue,
							},
						},
					},
					IncludedNamespaces: []string{"hook-inc-ns-1", "hook-inc-ns-2"},
					ExcludedNamespaces: []string{"hook-exc-ns-1", "hook-exc-ns-2"},
					IncludedResources:  []string{"hook-inc-res-1", "hook-inc-res-2"},
					ExcludedResources:  []string{"hook-exc-res-1", "hook-exc-res-2"},
				},
			},
		})

	expect1 := map[string]any{
		"spec": map[string]any{
			"namespaces": map[string]any{
				"included": "inc-ns-1, inc-ns-2",
				"excluded": "exc-ns-1, exc-ns-2",
			},
			"resources": map[string]string{
				"included":      "inc-res-1, inc-res-2",
				"excluded":      "exc-res-1, exc-res-2",
				"clusterScoped": "auto",
			},
			"dataMover":               "mover",
			"labelSelector":           emptyDisplay,
			"storageLocation":         "backup-location",
			"veleroNativeSnapshotPVs": "auto",
			"TTL":                     "72h0m0s",
			"CSISnapshotTimeout":      "10m0s",
			"veleroSnapshotMoveData":  "auto",
			"hooks": map[string]any{
				"resources": map[string]any{
					"hook-1": map[string]any{
						"labelSelector": emptyDisplay,
						"namespaces": map[string]string{
							"included": "hook-inc-ns-1, hook-inc-ns-2",
							"excluded": "hook-exc-ns-1, hook-exc-ns-2",
						},
						"preExecHook": []map[string]any{
							{
								"container": "hook-container-1",
								"command":   "pre",
								"onError:":  velerov1api.HookErrorModeContinue,
								"timeout":   "0s",
							},
						},
						"postExecHook": []map[string]any{
							{
								"container": "hook-container-1",
								"command":   "post",
								"onError:":  velerov1api.HookErrorModeContinue,
								"timeout":   "0s",
							},
						},
						"resources": map[string]string{
							"included": "hook-inc-res-1, hook-inc-res-2",
							"excluded": "hook-exc-res-1, hook-exc-res-2",
						},
					},
				},
			},
		},
	}
	DescribeBackupSpecInSF(sd, backupBuilder1.Result().Spec)
	assert.True(t, reflect.DeepEqual(sd.output, expect1))

	backupBuilder2 := builder.ForBackup("test-ns-2", "test-backup-2").
		StorageLocation("backup-location").
		OrderedResources(map[string]string{
			"kind1": "rs1-1, rs1-2",
			"kind2": "rs2-1, rs2-2",
		}).Hooks(velerov1api.BackupHooks{
		Resources: []velerov1api.BackupResourceHookSpec{
			{
				Name: "hook-1",
				PreHooks: []velerov1api.BackupResourceHook{
					{
						Exec: &velerov1api.ExecHook{
							Container: "hook-container-1",
							Command:   []string{"pre"},
							OnError:   velerov1api.HookErrorModeContinue,
						},
					},
				},
				PostHooks: []velerov1api.BackupResourceHook{
					{
						Exec: &velerov1api.ExecHook{
							Container: "hook-container-1",
							Command:   []string{"post"},
							OnError:   velerov1api.HookErrorModeContinue,
						},
					},
				},
			},
		},
	})

	expect2 := map[string]any{
		"spec": map[string]any{
			"namespaces": map[string]any{
				"included": "*",
				"excluded": emptyDisplay,
			},
			"resources": map[string]string{
				"included":      "*",
				"excluded":      emptyDisplay,
				"clusterScoped": "auto",
			},
			"dataMover":               emptyDisplay,
			"labelSelector":           emptyDisplay,
			"storageLocation":         "backup-location",
			"veleroNativeSnapshotPVs": "auto",
			"TTL":                     "0s",
			"CSISnapshotTimeout":      "0s",
			"veleroSnapshotMoveData":  "auto",
			"hooks": map[string]any{
				"resources": map[string]any{
					"hook-1": map[string]any{
						"labelSelector": emptyDisplay,
						"namespaces": map[string]string{
							"included": "*",
							"excluded": emptyDisplay,
						},
						"preExecHook": []map[string]any{
							{
								"container": "hook-container-1",
								"command":   "pre",
								"onError:":  velerov1api.HookErrorModeContinue,
								"timeout":   "0s",
							},
						},
						"postExecHook": []map[string]any{
							{
								"container": "hook-container-1",
								"command":   "post",
								"onError:":  velerov1api.HookErrorModeContinue,
								"timeout":   "0s",
							},
						},
						"resources": map[string]string{
							"included": "*",
							"excluded": emptyDisplay,
						},
					},
				},
			},
			"orderedResources": map[string]string{
				"kind1": "rs1-1, rs1-2",
				"kind2": "rs2-1, rs2-2",
			},
		},
	}
	DescribeBackupSpecInSF(sd, backupBuilder2.Result().Spec)
	assert.True(t, reflect.DeepEqual(sd.output, expect2))
}

func TestDescribePodVolumeBackupsInSF(t *testing.T) {
	pvbBuilder1 := builder.ForPodVolumeBackup("test-ns1", "test-pvb1")
	pvb1 := pvbBuilder1.BackupStorageLocation("backup-location").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseCompleted).
		BackupStorageLocation("bsl-1").
		Volume("vol-1").
		PodName("pod-1").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-1").Result()

	pvbBuilder2 := builder.ForPodVolumeBackup("test-ns1", "test-pvb2")
	pvb2 := pvbBuilder2.BackupStorageLocation("backup-location").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseCompleted).
		BackupStorageLocation("bsl-1").
		Volume("vol-2").
		PodName("pod-2").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-2").Result()

	pvb3 := builder.ForPodVolumeBackup("test-ns1", "test-pvb3").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseFailed).
		BackupStorageLocation("bsl-1").
		Volume("vol-3").
		PodName("pod-3").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-3").Result()
	pvb4 := builder.ForPodVolumeBackup("test-ns1", "test-pvb4").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseCanceled).
		BackupStorageLocation("bsl-1").
		Volume("vol-4").
		PodName("pod-4").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-4").Result()
	pvb5 := builder.ForPodVolumeBackup("test-ns1", "test-pvb5").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseInProgress).
		BackupStorageLocation("bsl-1").
		Volume("vol-5").
		PodName("pod-5").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-5").Result()
	pvb6 := builder.ForPodVolumeBackup("test-ns1", "test-pvb6").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseCanceling).
		BackupStorageLocation("bsl-1").
		Volume("vol-6").
		PodName("pod-6").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-6").Result()
	pvb7 := builder.ForPodVolumeBackup("test-ns1", "test-pvb7").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhasePrepared).
		BackupStorageLocation("bsl-1").
		Volume("vol-7").
		PodName("pod-7").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-7").Result()
	pvb8 := builder.ForPodVolumeBackup("test-ns1", "test-pvb6").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseAccepted).
		BackupStorageLocation("bsl-1").
		Volume("vol-8").
		PodName("pod-8").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-8").Result()

	testcases := []struct {
		name         string
		inputPVBList []velerov1api.PodVolumeBackup
		inputDetails bool
		expect       map[string]any
	}{
		{
			name:         "empty list",
			inputPVBList: []velerov1api.PodVolumeBackup{},
			inputDetails: false,
			expect:       map[string]any{"podVolumeBackups": "<none included>"},
		},
		{
			name:         "2 completed pvbs",
			inputPVBList: []velerov1api.PodVolumeBackup{*pvb1, *pvb2},
			inputDetails: true,
			expect: map[string]any{
				"podVolumeBackups": map[string]any{
					"podVolumeBackupsDetails": map[string]any{
						"Completed": []map[string]string{
							{"pod-ns-1/pod-1": "vol-1"},
							{"pod-ns-1/pod-2": "vol-2"},
						},
					},
					"uploderType": "kopia",
				},
			},
		},
		{
			name:         "all phases",
			inputPVBList: []velerov1api.PodVolumeBackup{*pvb1, *pvb2, *pvb3, *pvb4, *pvb5, *pvb6, *pvb7, *pvb8},
			inputDetails: true,
			expect: map[string]any{
				"podVolumeBackups": map[string]any{
					"podVolumeBackupsDetails": map[string]any{
						"Completed": []map[string]string{
							{"pod-ns-1/pod-1": "vol-1"},
							{"pod-ns-1/pod-2": "vol-2"},
						},
						"Failed": []map[string]string{
							{"pod-ns-1/pod-3": "vol-3"},
						},
						"Canceled": []map[string]string{
							{"pod-ns-1/pod-4": "vol-4"},
						},
						"In Progress": []map[string]string{
							{"pod-ns-1/pod-5": "vol-5"},
						},
						"Canceling": []map[string]string{
							{"pod-ns-1/pod-6": "vol-6"},
						},
						"Prepared": []map[string]string{
							{"pod-ns-1/pod-7": "vol-7"},
						},
						"Accepted": []map[string]string{
							{"pod-ns-1/pod-8": "vol-8"},
						},
					},
					"uploderType": "kopia",
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			output := make(map[string]any)
			describePodVolumeBackupsInSF(tc.inputPVBList, tc.inputDetails, output)
			assert.True(tt, reflect.DeepEqual(output, tc.expect))
		})
	}
}

func TestDescribeNativeSnapshotsInSF(t *testing.T) {
	testcases := []struct {
		name         string
		volumeInfo   []*volume.BackupVolumeInfo
		inputDetails bool
		expect       map[string]any
	}{
		{
			name: "no details",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod: volume.NativeSnapshot,
					PVName:       "pv-1",
					NativeSnapshotInfo: &volume.NativeSnapshotInfo{
						SnapshotHandle: "snapshot-1",
						VolumeType:     "ebs",
						VolumeAZ:       "us-east-2",
						IOPS:           "1000 mbps",
					},
				},
			},
			expect: map[string]any{
				"nativeSnapshots": map[string]any{
					"pv-1": "specify --details for more information",
				},
			},
		},
		{
			name: "details",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod: volume.NativeSnapshot,
					PVName:       "pv-1",
					Result:       volume.VolumeResultSucceeded,
					NativeSnapshotInfo: &volume.NativeSnapshotInfo{
						SnapshotHandle: "snapshot-1",
						VolumeType:     "ebs",
						VolumeAZ:       "us-east-2",
						IOPS:           "1000 mbps",
					},
				},
			},
			inputDetails: true,
			expect: map[string]any{
				"nativeSnapshots": map[string]any{
					"pv-1": map[string]string{
						"snapshotID":       "snapshot-1",
						"type":             "ebs",
						"availabilityZone": "us-east-2",
						"IOPS":             "1000 mbps",
						"result":           "succeeded",
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			output := make(map[string]any)
			describeNativeSnapshotsInSF(tc.inputDetails, tc.volumeInfo, output)
			assert.True(tt, reflect.DeepEqual(output, tc.expect))
		})
	}
}

func TestDescribeCSISnapshotsInSF(t *testing.T) {
	testcases := []struct {
		name             string
		volumeInfo       []*volume.BackupVolumeInfo
		inputDetails     bool
		expect           map[string]any
		legacyInfoSource bool
	}{
		{
			name:       "empty info, not legacy",
			volumeInfo: []*volume.BackupVolumeInfo{},
			expect: map[string]any{
				"csiSnapshots": "<none included>",
			},
		},
		{
			name:             "empty info, legacy",
			volumeInfo:       []*volume.BackupVolumeInfo{},
			legacyInfoSource: true,
			expect: map[string]any{
				"csiSnapshots": "<none included or not detectable>",
			},
		},
		{
			name: "no details, local snapshot",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod:          volume.CSISnapshot,
					PVCNamespace:          "pvc-ns-1",
					PVCName:               "pvc-1",
					PreserveLocalSnapshot: true,
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						SnapshotHandle: "snapshot-1",
						Size:           1024,
						Driver:         "fake-driver",
						VSCName:        "vsc-1",
						OperationID:    "fake-operation-1",
					},
				},
			},
			expect: map[string]any{
				"csiSnapshots": map[string]any{
					"pvc-ns-1/pvc-1": map[string]any{
						"snapshot": "included, specify --details for more information",
					},
				},
			},
		},
		{
			name: "details, local snapshot",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod:          volume.CSISnapshot,
					PVCNamespace:          "pvc-ns-2",
					PVCName:               "pvc-2",
					PreserveLocalSnapshot: true,
					Result:                volume.VolumeResultSucceeded,
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						SnapshotHandle: "snapshot-2",
						Size:           1024,
						Driver:         "fake-driver",
						VSCName:        "vsc-2",
						OperationID:    "fake-operation-2",
					},
				},
			},
			inputDetails: true,
			expect: map[string]any{
				"csiSnapshots": map[string]any{
					"pvc-ns-2/pvc-2": map[string]any{
						"snapshot": map[string]any{
							"operationID":         "fake-operation-2",
							"snapshotContentName": "vsc-2",
							"storageSnapshotID":   "snapshot-2",
							"snapshotSize(bytes)": int64(1024),
							"csiDriver":           "fake-driver",
							"result":              "succeeded",
						},
					},
				},
			},
		},
		{
			name: "no details, data movement",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod:      volume.CSISnapshot,
					PVCNamespace:      "pvc-ns-3",
					PVCName:           "pvc-3",
					SnapshotDataMoved: true,
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover:      "velero",
						UploaderType:   "fake-uploader",
						SnapshotHandle: "fake-repo-id-3",
						OperationID:    "fake-operation-3",
					},
				},
			},
			expect: map[string]any{
				"csiSnapshots": map[string]any{
					"pvc-ns-3/pvc-3": map[string]any{
						"dataMovement": "included, specify --details for more information",
					},
				},
			},
		},
		{
			name: "details, data movement",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod:      volume.CSISnapshot,
					PVCNamespace:      "pvc-ns-4",
					PVCName:           "pvc-4",
					SnapshotDataMoved: true,
					Result:            volume.VolumeResultSucceeded,
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover:      "velero",
						UploaderType:   "fake-uploader",
						SnapshotHandle: "fake-repo-id-4",
						OperationID:    "fake-operation-4",
					},
				},
			},
			inputDetails: true,
			expect: map[string]any{
				"csiSnapshots": map[string]any{
					"pvc-ns-4/pvc-4": map[string]any{
						"dataMovement": map[string]any{
							"operationID":  "fake-operation-4",
							"dataMover":    "velero",
							"uploaderType": "fake-uploader",
							"result":       "succeeded",
						},
					},
				},
			},
		},
		{
			name: "details, data movement, data mover is empty",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod:      volume.CSISnapshot,
					PVCNamespace:      "pvc-ns-4",
					Result:            volume.VolumeResultFailed,
					PVCName:           "pvc-4",
					SnapshotDataMoved: true,
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						UploaderType:   "fake-uploader",
						SnapshotHandle: "fake-repo-id-4",
						OperationID:    "fake-operation-4",
					},
				},
			},
			inputDetails: true,
			expect: map[string]any{
				"csiSnapshots": map[string]any{
					"pvc-ns-4/pvc-4": map[string]any{
						"dataMovement": map[string]any{
							"operationID":  "fake-operation-4",
							"dataMover":    "velero",
							"uploaderType": "fake-uploader",
							"result":       "failed",
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			output := make(map[string]any)
			describeCSISnapshotsInSF(tc.inputDetails, tc.volumeInfo, output, tc.legacyInfoSource)
			assert.True(tt, reflect.DeepEqual(output, tc.expect))
		})
	}
}

func TestDescribeResourcePoliciesInSF(t *testing.T) {
	input := &corev1api.TypedLocalObjectReference{
		Kind: "configmap",
		Name: "resource-policy-1",
	}
	expect := map[string]any{
		"resourcePolicies": map[string]any{
			"type": "configmap",
			"name": "resource-policy-1",
		},
	}
	sd := &StructuredDescriber{
		output: make(map[string]any),
		format: "",
	}
	DescribeResourcePoliciesInSF(sd, input)
	assert.True(t, reflect.DeepEqual(sd.output, expect))
}

func TestDescribeGlobalVolumePolicyInSF(t *testing.T) {
	// No annotation: nothing is added to the output.
	sd := &StructuredDescriber{output: make(map[string]any), format: ""}
	DescribeGlobalVolumePolicyInSF(sd, builder.ForBackup("velero", "b").Result())
	assert.Empty(t, sd.output)

	// Annotation present: the ConfigMap name is surfaced.
	sd = &StructuredDescriber{output: make(map[string]any), format: ""}
	backup := builder.ForBackup("velero", "b").
		ObjectMeta(builder.WithAnnotations(velerov1api.GlobalBackupVolumePolicyConfigMapAnnotation, "global-volume-policy")).
		Result()
	DescribeGlobalVolumePolicyInSF(sd, backup)
	expectGlobal := map[string]any{
		"globalVolumePolicies": map[string]any{
			"type": "configmap",
			"name": "global-volume-policy",
		},
	}
	assert.True(t, reflect.DeepEqual(sd.output, expectGlobal))
}

func TestDescribeBackupResultInSF(t *testing.T) {
	input := results.Result{
		Velero:  []string{"msg-1", "msg-2"},
		Cluster: []string{"cluster-1", "cluster-2"},
		Namespaces: map[string][]string{
			"ns-1": {"ns-1-msg-1", "ns-1-msg-2"},
		},
	}
	got := map[string]any{}
	expect := map[string]any{
		"velero":  []string{"msg-1", "msg-2"},
		"cluster": []string{"cluster-1", "cluster-2"},
		"namespace": map[string][]string{
			"ns-1": {"ns-1-msg-1", "ns-1-msg-2"},
		},
	}
	describeResultInSF(got, input)
	assert.True(t, reflect.DeepEqual(got, expect))
}

func TestDescribeDeleteBackupRequestsInSF(t *testing.T) {
	t1, err1 := time.Parse("2006-Jan-02", "2023-Jun-26")
	require.NoError(t, err1)
	dbr1 := builder.ForDeleteBackupRequest("velero", "dbr1").
		ObjectMeta(builder.WithCreationTimestamp(t1)).
		BackupName("bak-1").
		Phase(velerov1api.DeleteBackupRequestPhaseProcessed).
		Errors("some error").Result()
	t2, err2 := time.Parse("2006-Jan-02", "2023-Jun-25")
	require.NoError(t, err2)
	dbr2 := builder.ForDeleteBackupRequest("velero", "dbr2").
		ObjectMeta(builder.WithCreationTimestamp(t2)).
		BackupName("bak-2").
		Phase(velerov1api.DeleteBackupRequestPhaseInProgress).Result()

	testcases := []struct {
		name   string
		input  []velerov1api.DeleteBackupRequest
		expect map[string]any
	}{
		{
			name:  "empty list",
			input: []velerov1api.DeleteBackupRequest{},
			expect: map[string]any{
				"deletionAttempts": map[string]any{
					"deleteBackupRequests": []map[string]any{},
				},
			},
		},
		{
			name:  "list with one failed and one in-progress request",
			input: []velerov1api.DeleteBackupRequest{*dbr1, *dbr2},
			expect: map[string]any{
				"deletionAttempts": map[string]any{
					"failed": int(1),
					"deleteBackupRequests": []map[string]any{
						{
							"creationTimestamp": t1.String(),
							"phase":             velerov1api.DeleteBackupRequestPhaseProcessed,
							"errors": []string{
								"some error",
							},
						},
						{
							"creationTimestamp": t2.String(),
							"phase":             velerov1api.DeleteBackupRequestPhaseInProgress,
						},
					},
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			sd := &StructuredDescriber{
				output: make(map[string]any),
				format: "",
			}
			DescribeDeleteBackupRequestsInSF(sd, tc.input)
			assert.True(tt, reflect.DeepEqual(sd.output, tc.expect))
		})
	}
}

func TestDescribeFineGrainedFilterPoliciesInSF(t *testing.T) {
	yamlData := `
version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["StorageClass"]
    labelSelector: {"app": "velero"}
  - kinds: ["ClusterRole"]
    orLabelSelectors:
    - {"app": "velero"}
    - {"app": "test"}
    names: ["role1"]
    excludedNames: ["role2"]
namespacedFilterPolicies:
- namespaces: ["ns1", "ns2"]
  resourceFilters:
  - kinds: ["Pod", "ConfigMap"]
    labelSelector: {"app": "velero"}
  - kinds: ["*"]
`
	cm := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "velero",
		},
		Data: map[string]string{
			"policy.yaml": yamlData,
		},
	}

	client := fake.NewClientBuilder().WithRuntimeObjects(cm).Build()

	backup := builder.ForBackup("velero", "test-backup").
		ResourcePolicies("test-policy").Result()

	sd := &StructuredDescriber{
		output: make(map[string]any),
		format: "",
	}

	DescribeFineGrainedFilterPoliciesInSF(context.Background(), client, sd, backup)

	expect := map[string]any{
		"clusterScopedFilterPolicy": map[string]any{
			"resourceFilters": []map[string]any{
				{
					"kinds":         []string{"StorageClass"},
					"labelSelector": map[string]string{"app": "velero"},
				},
				{
					"kinds": []string{"ClusterRole"},
					"orLabelSelectors": []map[string]string{
						{"app": "velero"},
						{"app": "test"},
					},
					"names":         []string{"role1"},
					"excludedNames": []string{"role2"},
				},
			},
		},
		"namespacedFilterPolicies": []map[string]any{
			{
				"namespace": "ns1",
				"resourceFilters": []map[string]any{
					{
						"kinds":         []string{"Pod", "ConfigMap"},
						"labelSelector": map[string]string{"app": "velero"},
					},
					{
						"kinds":      []string{},
						"isCatchAll": true,
					},
				},
			},
			{
				"namespace": "ns2",
				"resourceFilters": []map[string]any{
					{
						"kinds":         []string{"Pod", "ConfigMap"},
						"labelSelector": map[string]string{"app": "velero"},
					},
					{
						"kinds":      []string{},
						"isCatchAll": true,
					},
				},
			},
		},
	}

	assert.True(t, reflect.DeepEqual(sd.output, expect))
}
