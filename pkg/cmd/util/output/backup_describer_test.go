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
	"testing"
	"text/tabwriter"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
)

func TestDescribeUploaderConfig(t *testing.T) {
	input := builder.ForBackup("test-ns", "test-backup-1").ParallelFilesUpload(10).Result().Spec
	d := &Describer{
		Prefix: "",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 2, ' ', 0)
	DescribeUploaderConfigForBackup(d, input)
	d.out.Flush()
	expect := `Uploader config:
  Parallel files upload:  10
`
	assert.Equal(t, expect, d.buf.String())
}

func TestDescribeResourcePolicies(t *testing.T) {
	input := &corev1api.TypedLocalObjectReference{
		Kind: "configmap",
		Name: "test-resource-policy",
	}
	d := &Describer{
		Prefix: "",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 2, ' ', 0)
	DescribeResourcePolicies(d, input)
	d.out.Flush()
	expect := `Resource policies:
  Type:  configmap
  Name:  test-resource-policy
`
	assert.Equal(t, expect, d.buf.String())
}

func TestDescribeGlobalVolumePolicy(t *testing.T) {
	newDescriber := func() *Describer {
		d := &Describer{out: &tabwriter.Writer{}, buf: &bytes.Buffer{}}
		d.out.Init(d.buf, 0, 8, 2, ' ', 0)
		return d
	}

	// No annotation: nothing is printed.
	d := newDescriber()
	DescribeGlobalVolumePolicy(d, builder.ForBackup("velero", "b").Result())
	d.out.Flush()
	assert.Empty(t, d.buf.String())

	// Annotation present: ConfigMap name is surfaced.
	d = newDescriber()
	backup := builder.ForBackup("velero", "b").
		ObjectMeta(builder.WithAnnotations(velerov1api.GlobalBackupVolumePolicyConfigMapAnnotation, "global-volume-policy")).
		Result()
	DescribeGlobalVolumePolicy(d, backup)
	d.out.Flush()
	expect := `
Global volume policies:
  Type:  configmap
  Name:  global-volume-policy
`
	assert.Equal(t, expect, d.buf.String())
}

func TestDescribeBackupSpec(t *testing.T) {
	input1 := builder.ForBackup("test-ns", "test-backup-1").
		IncludedNamespaces("inc-ns-1", "inc-ns-2").
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
		}).Result().Spec

	expect1 := `Namespaces:
  Included:  inc-ns-1, inc-ns-2
  Excluded:  exc-ns-1, exc-ns-2

Resources:
  Included:        inc-res-1, inc-res-2
  Excluded:        exc-res-1, exc-res-2
  Cluster-scoped:  auto

Label selector:  <none>

Or label selector:  <none>

Storage Location:  backup-location

Velero-Native Snapshot PVs:  auto
Snapshot Move Data:          auto
Data Mover:                  mover

TTL:  72h0m0s

CSISnapshotTimeout:    10m0s
ItemOperationTimeout:  0s

Hooks:
  Resources:
    hook-1:
      Namespaces:
        Included:  hook-inc-ns-1, hook-inc-ns-2
        Excluded:  hook-exc-ns-1, hook-exc-ns-2

      Resources:
        Included:  hook-inc-res-1, hook-inc-res-2
        Excluded:  hook-exc-res-1, hook-exc-res-2

      Label selector:  <none>

      Pre Exec Hook:
        Container:  hook-container-1
        Command:    pre
        On Error:   Continue
        Timeout:    0s

      Post Exec Hook:
        Container:  hook-container-1
        Command:    post
        On Error:   Continue
        Timeout:    0s
`

	input2 := builder.ForBackup("test-ns", "test-backup-2").
		IncludedNamespaces("inc-ns-1", "inc-ns-2").
		ExcludedNamespaces("exc-ns-1", "exc-ns-2").
		IncludedClusterScopedResources("inc-cluster-res-1", "inc-cluster-res-2").
		IncludedNamespaceScopedResources("inc-ns-res-1", "inc-ns-res-2").
		ExcludedClusterScopedResources("exc-cluster-res-1", "exc-cluster-res-2").
		ExcludedNamespaceScopedResources("exc-ns-res-1", "exc-ns-res-2").
		StorageLocation("backup-location").
		TTL(72 * time.Hour).
		CSISnapshotTimeout(10 * time.Minute).
		DataMover("mover").
		Result().Spec

	expect2 := `Namespaces:
  Included:  inc-ns-1, inc-ns-2
  Excluded:  exc-ns-1, exc-ns-2

Resources:
  Included cluster-scoped:    inc-cluster-res-1, inc-cluster-res-2
  Excluded cluster-scoped:    exc-cluster-res-1, exc-cluster-res-2
  Included namespace-scoped:  inc-ns-res-1, inc-ns-res-2
  Excluded namespace-scoped:  exc-ns-res-1, exc-ns-res-2

Label selector:  <none>

Or label selector:  <none>

Storage Location:  backup-location

Velero-Native Snapshot PVs:  auto
Snapshot Move Data:          auto
Data Mover:                  mover

TTL:  72h0m0s

CSISnapshotTimeout:    10m0s
ItemOperationTimeout:  0s

Hooks:  <none>
`

	input3 := builder.ForBackup("test-ns", "test-backup-3").
		StorageLocation("backup-location").
		OrderedResources(map[string]string{
			"kind1": "rs1-1, rs1-2",
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
	}).Result().Spec

	expect3 := `Namespaces:
  Included:  *
  Excluded:  <none>

Resources:
  Included cluster-scoped:    <none>
  Excluded cluster-scoped:    <none>
  Included namespace-scoped:  *
  Excluded namespace-scoped:  <none>

Label selector:  <none>

Or label selector:  <none>

Storage Location:  backup-location

Velero-Native Snapshot PVs:  auto
Snapshot Move Data:          auto
Data Mover:                  velero

TTL:  0s

CSISnapshotTimeout:    0s
ItemOperationTimeout:  0s

Hooks:
  Resources:
    hook-1:
      Namespaces:
        Included:  *
        Excluded:  <none>

      Resources:
        Included:  *
        Excluded:  <none>

      Label selector:  <none>

      Pre Exec Hook:
        Container:  hook-container-1
        Command:    pre
        On Error:   Continue
        Timeout:    0s

      Post Exec Hook:
        Container:  hook-container-1
        Command:    post
        On Error:   Continue
        Timeout:    0s

OrderedResources:
  kind1: rs1-1, rs1-2
`
	input4 := builder.ForBackup("test-ns", "test-backup-4").
		DefaultVolumesToFsBackup(true).
		StorageLocation("backup-location").
		Result().Spec

	expect4 := `Namespaces:
  Included:  *
  Excluded:  <none>

Resources:
  Included cluster-scoped:    <none>
  Excluded cluster-scoped:    <none>
  Included namespace-scoped:  *
  Excluded namespace-scoped:  <none>

Label selector:  <none>

Or label selector:  <none>

Storage Location:  backup-location

Velero-Native Snapshot PVs:    auto
File System Backup (Default):  true
Snapshot Move Data:            auto
Data Mover:                    velero

TTL:  0s

CSISnapshotTimeout:    0s
ItemOperationTimeout:  0s

Hooks:  <none>
`

	input5 := builder.ForBackup("test-ns", "test-backup-5").
		DefaultVolumesToFsBackup(false).
		StorageLocation("backup-location").
		Result().Spec

	expect5 := `Namespaces:
  Included:  *
  Excluded:  <none>

Resources:
  Included cluster-scoped:    <none>
  Excluded cluster-scoped:    <none>
  Included namespace-scoped:  *
  Excluded namespace-scoped:  <none>

Label selector:  <none>

Or label selector:  <none>

Storage Location:  backup-location

Velero-Native Snapshot PVs:    auto
File System Backup (Default):  false
Snapshot Move Data:            auto
Data Mover:                    velero

TTL:  0s

CSISnapshotTimeout:    0s
ItemOperationTimeout:  0s

Hooks:  <none>
`

	testcases := []struct {
		name   string
		input  velerov1api.BackupSpec
		expect string
	}{
		{
			name:   "old resource filter with hooks",
			input:  input1,
			expect: expect1,
		},
		{
			name:   "new resource filter",
			input:  input2,
			expect: expect2,
		},
		{
			name:   "old resource filter with hooks and ordered resources",
			input:  input3,
			expect: expect3,
		},
		{
			name:   "DefaultVolumesToFsBackup is true",
			input:  input4,
			expect: expect4,
		},
		{
			name:   "DefaultVolumesToFsBackup is false",
			input:  input5,
			expect: expect5,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			DescribeBackupSpec(d, tc.input)
			d.out.Flush()
			assert.Equal(tt, tc.expect, d.buf.String())
		})
	}
}

func TestDescribeNativeSnapshots(t *testing.T) {
	testcases := []struct {
		name         string
		volumeInfo   []*volume.BackupVolumeInfo
		inputDetails bool
		expect       string
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
			expect: `  Velero-Native Snapshots:
    pv-1: specify --details for more information
`,
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
			expect: `  Velero-Native Snapshots:
    pv-1:
      Snapshot ID:        snapshot-1
      Type:               ebs
      Availability Zone:  us-east-2
      IOPS:               1000 mbps
      Result:             succeeded
`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			describeNativeSnapshots(d, tc.inputDetails, tc.volumeInfo)
			d.out.Flush()
			assert.Equal(t, tc.expect, d.buf.String())
		})
	}
}

func TestCSISnapshots(t *testing.T) {
	testcases := []struct {
		name             string
		volumeInfo       []*volume.BackupVolumeInfo
		inputDetails     bool
		expect           string
		legacyInfoSource bool
	}{
		{
			name:       "empty info, not legacy",
			volumeInfo: []*volume.BackupVolumeInfo{},
			expect: `  CSI Snapshots: <none included>
`,
		},
		{
			name:             "empty info, legacy",
			volumeInfo:       []*volume.BackupVolumeInfo{},
			legacyInfoSource: true,
			expect: `  CSI Snapshots: <none included or not detectable>
`,
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
			expect: `  CSI Snapshots:
    pvc-ns-1/pvc-1:
      Snapshot: included, specify --details for more information
`,
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
			expect: `  CSI Snapshots:
    pvc-ns-2/pvc-2:
      Snapshot:
        Operation ID: fake-operation-2
        Snapshot Content Name: vsc-2
        Storage Snapshot ID: snapshot-2
        Snapshot Size (bytes): 1024
        CSI Driver: fake-driver
        Result: succeeded
`,
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
			expect: `  CSI Snapshots:
    pvc-ns-3/pvc-3:
      Data Movement: included, specify --details for more information
`,
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
			expect: `  CSI Snapshots:
    pvc-ns-4/pvc-4:
      Data Movement:
        Operation ID: fake-operation-4
        Data Mover: velero
        Uploader Type: fake-uploader
        Moved data Size (bytes): 0
        Result: succeeded
`,
		},
		{
			name: "details, data movement, data mover is empty",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					BackupMethod:      volume.CSISnapshot,
					PVCNamespace:      "pvc-ns-5",
					PVCName:           "pvc-5",
					Result:            volume.VolumeResultFailed,
					SnapshotDataMoved: true,
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						UploaderType:    "fake-uploader",
						SnapshotHandle:  "fake-repo-id-5",
						OperationID:     "fake-operation-5",
						Size:            100,
						IncrementalSize: 50,
						Phase:           velerov2alpha1.DataUploadPhaseFailed,
					},
				},
			},
			inputDetails: true,
			expect: `  CSI Snapshots:
    pvc-ns-5/pvc-5:
      Data Movement:
        Operation ID: fake-operation-5
        Data Mover: velero
        Uploader Type: fake-uploader
        Moved data Size (bytes): 100
        Incremental data Size (bytes): 50
        Result: failed
`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			describeCSISnapshots(d, tc.inputDetails, tc.volumeInfo, tc.legacyInfoSource)
			d.out.Flush()
			assert.Equal(t, tc.expect, d.buf.String())
		})
	}
}

func TestDescribePodVolumeBackups(t *testing.T) {
	pvb1 := builder.ForPodVolumeBackup("test-ns", "test-pvb1").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeBackupPhaseCompleted).
		BackupStorageLocation("bsl-1").
		Volume("vol-1").
		PodName("pod-1").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-1").Result()
	pvb2 := builder.ForPodVolumeBackup("test-ns1", "test-pvb2").
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
		expect       string
	}{
		{
			name:         "empty list",
			inputPVBList: []velerov1api.PodVolumeBackup{},
			inputDetails: true,
			expect: `  Pod Volume Backups: <none included>
`,
		},
		{
			name:         "2 completed pvbs no details",
			inputPVBList: []velerov1api.PodVolumeBackup{*pvb1, *pvb2},
			inputDetails: false,
			expect: `  Pod Volume Backups - kopia (specify --details for more information):
    Completed:  2
`,
		},
		{
			name:         "2 completed pvbs with details",
			inputPVBList: []velerov1api.PodVolumeBackup{*pvb1, *pvb2},
			inputDetails: true,
			expect: `  Pod Volume Backups - kopia:
    Completed:
      pod-ns-1/pod-1: vol-1
      pod-ns-1/pod-2: vol-2
`,
		},
		{
			name:         "all phases with details",
			inputPVBList: []velerov1api.PodVolumeBackup{*pvb1, *pvb2, *pvb3, *pvb4, *pvb5, *pvb6, *pvb7, *pvb8},
			inputDetails: true,
			expect: `  Pod Volume Backups - kopia:
    Completed:
      pod-ns-1/pod-1: vol-1
      pod-ns-1/pod-2: vol-2
    Failed:
      pod-ns-1/pod-3: vol-3
    Canceled:
      pod-ns-1/pod-4: vol-4
    In Progress:
      pod-ns-1/pod-5: vol-5
    Canceling:
      pod-ns-1/pod-6: vol-6
    Prepared:
      pod-ns-1/pod-7: vol-7
    Accepted:
      pod-ns-1/pod-8: vol-8
`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			describePodVolumeBackups(d, tc.inputDetails, tc.inputPVBList)
			d.out.Flush()
			assert.Equal(tt, tc.expect, d.buf.String())
		})
	}
}

func TestDescribeDeleteBackupRequests(t *testing.T) {
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
		expect string
	}{
		{
			name:  "empty list",
			input: []velerov1api.DeleteBackupRequest{},
			expect: `Deletion Attempts:
`,
		},
		{
			name:  "list with one failed and one in-progress request",
			input: []velerov1api.DeleteBackupRequest{*dbr1, *dbr2},
			expect: `Deletion Attempts (1 failed):
  2023-06-26 00:00:00 +0000 UTC: Processed
  Errors:
    some error

  2023-06-25 00:00:00 +0000 UTC: InProgress
`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			DescribeDeleteBackupRequests(d, tc.input)
			d.out.Flush()
			assert.Equal(tt, tc.expect, d.buf.String())
		})
	}
}

func TestDescribeBackupItemOperation(t *testing.T) {
	t1, err1 := time.Parse("2006-Jan-02", "2023-Jun-26")
	require.NoError(t, err1)
	t2, err2 := time.Parse("2006-Jan-02", "2023-Jun-25")
	require.NoError(t, err2)
	t3, err3 := time.Parse("2006-Jan-02", "2023-Jun-24")
	require.NoError(t, err3)
	input := builder.ForBackupOperation().
		BackupName("backup-1").
		OperationID("op-1").
		BackupItemAction("action-1").
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
	expected := `  Operation for rs-type.group ns/rs-name:
    Backup Item Action Plugin:  action-1
    Operation ID:               op-1
    Phase:                      Failed
    Operation Error:            operation error
    Progress:                   50 of 100 complete (bytes)
    Progress description:       operation description
    Created:                    2023-06-24 00:00:00 +0000 UTC
    Started:                    2023-06-25 00:00:00 +0000 UTC
    Updated:                    2023-06-26 00:00:00 +0000 UTC
`
	d := &Describer{
		Prefix: "",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 2, ' ', 0)
	describeBackupItemOperation(d, input)
	d.out.Flush()
	assert.Equal(t, expected, d.buf.String())
}

func TestDescribeFineGrainedFilterPolicies(t *testing.T) {
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

	d := &Describer{
		Prefix: "",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 2, ' ', 0)

	DescribeFineGrainedFilterPolicies(context.Background(), client, d, backup)
	d.out.Flush()

	expected := `
Cluster Scoped Filter Policy:
  Resource Filters:
    StorageClass:
      Label selector:     app=velero
      Included names:     <none>
      Excluded names:     <none>
    ClusterRole:
      OR label selectors: [app=velero, app=test]
      Included names:     [role1]
      Excluded names:     [role2]

Namespace-Scoped Filter Policies:
  ns1:
    Resource Filters:
      Pod, ConfigMap:
        Label selector:     app=velero
        Included names:     <none>
        Excluded names:     <none>
      <catch-all> (all other kinds):
        Label selector:     <none>
        Included names:     <none>
        Excluded names:     <none>
  ns2:
    Resource Filters:
      Pod, ConfigMap:
        Label selector:     app=velero
        Included names:     <none>
        Excluded names:     <none>
      <catch-all> (all other kinds):
        Label selector:     <none>
        Included names:     <none>
        Excluded names:     <none>
`
	assert.Equal(t, expected, d.buf.String())
}
