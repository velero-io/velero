package output

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

func TestDescribeResult(t *testing.T) {
	testcases := []struct {
		name        string
		inputName   string
		inputResult results.Result
		expect      string
	}{
		{
			name:      "result without ns warns",
			inputName: "restore-1",
			inputResult: results.Result{
				Velero:     []string{"velero-msg-1", "velero-msg-2"},
				Cluster:    []string{"cluster-msg-1", "cluster-msg-2"},
				Namespaces: map[string][]string{},
			},
			expect: `restore-1:
  Velero:   velero-msg-1
            velero-msg-2
  Cluster:  cluster-msg-1
            cluster-msg-2
  Namespaces: <none>
`,
		},
		{
			name:      "result with ns warns",
			inputName: "restore-2",
			inputResult: results.Result{
				Velero:  []string{"velero-msg-1", "velero-msg-2"},
				Cluster: []string{"cluster-msg-1", "cluster-msg-2"},
				Namespaces: map[string][]string{
					"ns-1": {"ns-1-warn-1", "ns-1-warn-2"},
				},
			},
			expect: `restore-2:
  Velero:   velero-msg-1
            velero-msg-2
  Cluster:  cluster-msg-1
            cluster-msg-2
  Namespaces:
    ns-1:  ns-1-warn-1
           ns-1-warn-2
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
			describeResult(d, tc.inputName, tc.inputResult)
			d.out.Flush()
			assert.Equal(tt, tc.expect, d.buf.String())
		})
	}
}

func TestDescribeRestoreItemOperation(t *testing.T) {
	t1, err1 := time.Parse("2006-Jan-02", "2023-Jun-26")
	require.NoError(t, err1)
	t2, err2 := time.Parse("2006-Jan-02", "2023-Jun-25")
	require.NoError(t, err2)
	t3, err3 := time.Parse("2006-Jan-02", "2023-Jun-24")
	require.NoError(t, err3)
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
	expected := `  Operation for rs-type.group ns/rs-name:
    Restore Item Action Plugin:  action-1
    Operation ID:                op-1
    Phase:                       Failed
    Operation Error:             operation error
    Progress:                    50 of 100 complete (bytes)
    Progress description:        operation description
    Created:                     2023-06-24 00:00:00 +0000 UTC
    Started:                     2023-06-25 00:00:00 +0000 UTC
    Updated:                     2023-06-26 00:00:00 +0000 UTC
`
	d := &Describer{
		Prefix: "",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 2, ' ', 0)
	describeRestoreItemOperation(d, input)
	d.out.Flush()
	assert.Equal(t, expected, d.buf.String())
}

func TestDescribePodVolumeRestores(t *testing.T) {
	pvr1 := builder.ForPodVolumeRestore("velero", "pvr-1").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeRestorePhaseCompleted).
		BackupStorageLocation("bsl-1").
		Volume("vol-1").
		PodName("pod-1").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-1").Result()
	pvr2 := builder.ForPodVolumeRestore("velero", "pvr-2").
		UploaderType("kopia").
		Phase(velerov1api.PodVolumeRestorePhaseCompleted).
		BackupStorageLocation("bsl-1").
		Volume("vol-2").
		PodName("pod-2").
		PodNamespace("pod-ns-1").
		SnapshotID("snap-2").Result()

	testcases := []struct {
		name         string
		inputPVRList []velerov1api.PodVolumeRestore
		inputDetails bool
		expect       string
	}{
		{
			name:         "empty list",
			inputPVRList: []velerov1api.PodVolumeRestore{},
			inputDetails: true,
			expect:       ``,
		},
		{
			name:         "2 completed pvrs no details",
			inputPVRList: []velerov1api.PodVolumeRestore{*pvr1, *pvr2},
			inputDetails: false,
			expect: `kopia Restores (specify --details for more information):
  Completed:  2
`,
		},
		{
			name:         "2 completed pvrs with details",
			inputPVRList: []velerov1api.PodVolumeRestore{*pvr1, *pvr2},
			inputDetails: true,
			expect: `kopia Restores:
  Completed:
    pod-ns-1/pod-1: vol-1
    pod-ns-1/pod-2: vol-2
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
			describePodVolumeRestores(d, tc.inputPVRList, tc.inputDetails)
			d.out.Flush()
			assert.Equal(tt, tc.expect, d.buf.String())
		})
	}
}
func TestDescribeUploaderConfigForRestore(t *testing.T) {
	cases := []struct {
		name     string
		spec     velerov1api.RestoreSpec
		expected string
	}{
		{
			name:     "UploaderConfigNil",
			spec:     velerov1api.RestoreSpec{}, // Create a RestoreSpec with nil UploaderConfig
			expected: "",
		},
		{
			name: "test",
			spec: velerov1api.RestoreSpec{
				UploaderConfig: &velerov1api.UploaderConfigForRestore{
					WriteSparseFiles:      boolptr.True(),
					ParallelFilesDownload: 4,
				},
			},
			expected: "\nUploader config:\n  Write Sparse Files:  true\n  Parallel Restore:    4\n",
		},
		{
			name: "WriteSparseFiles test",
			spec: velerov1api.RestoreSpec{
				UploaderConfig: &velerov1api.UploaderConfigForRestore{
					WriteSparseFiles: boolptr.True(),
				},
			},
			expected: "\nUploader config:\n  Write Sparse Files:  true\n",
		},
		{
			name: "ParallelFilesDownload test",
			spec: velerov1api.RestoreSpec{
				UploaderConfig: &velerov1api.UploaderConfigForRestore{
					ParallelFilesDownload: 4,
				},
			},
			expected: "\nUploader config:\n  Parallel Restore:  4\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			describeUploaderConfigForRestore(d, tc.spec)
			d.out.Flush()
			assert.Equal(t, tc.expected, d.buf.String(), "Output should match expected")
		})
	}
}

func TestDescribeCSISnapshotsRestore(t *testing.T) {
	cases := []struct {
		name             string
		inputVolInfoList []volume.RestoreVolumeInfo
		inputDetail      bool
		expect           string
	}{
		{
			name:             "empty list",
			inputVolInfoList: []volume.RestoreVolumeInfo{},
			inputDetail:      true,
			expect: `
CSI Snapshot Restores: <none included>
`,
		},
		{
			name: "list with non CSI snapshot",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					PVCName:       "pvc-2",
					PVCNamespace:  "ns-2",
					PVName:        "pv-2",
					RestoreMethod: volume.NativeSnapshot,
					NativeSnapshotInfo: &volume.NativeSnapshotInfo{
						SnapshotHandle: "snap-1",
					},
				},
			},
			inputDetail: true,
			expect: `
CSI Snapshot Restores: <none included>
`,
		},
		{
			name: "CSI restore without data movement, detailed",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					PVCName:       "pvc-1",
					PVCNamespace:  "ns-1",
					PVName:        "pv-1",
					RestoreMethod: volume.CSISnapshot,
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						SnapshotHandle: "snapshot-handle-1",
						Size:           1234,
						Driver:         "csi.test.driver",
						VSCName:        "content-1",
					},
				},
			},
			inputDetail: true,
			expect: `
CSI Snapshot Restores:
  ns-1/pvc-1:
    Snapshot:
      Snapshot Content Name: content-1
      Storage Snapshot ID: snapshot-handle-1
      CSI Driver: csi.test.driver
`,
		},
		{
			name: "CSI restore with data movement, detailed",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					PVCName:           "pvc-3",
					PVCNamespace:      "ns-3",
					PVName:            "pv-3",
					RestoreMethod:     volume.CSISnapshot,
					SnapshotDataMoved: true,
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
			inputDetail: true,
			expect: `
CSI Snapshot Restores:
  ns-3/pvc-3:
    Data Movement:
      Operation ID: op-3
      Data Mover: velero
      Uploader Type: kopia
      Restore Type: Incremental
      Restored data Size (bytes): 1234
      Incremental data Size (bytes): 500
`,
		},
		{
			name: "vol info with different entries, without details",
			inputVolInfoList: []volume.RestoreVolumeInfo{
				{
					PVCName:           "pvc-3",
					PVCNamespace:      "ns-3",
					PVName:            "pv-3",
					RestoreMethod:     volume.CSISnapshot,
					SnapshotDataMoved: true,
					SnapshotDataMovementInfo: &volume.RestoreSnapshotDataMovementInfo{
						OperationID:  "op-3",
						DataMover:    "velero",
						UploaderType: "kopia",
						Size:         1234,
					},
				},
				{
					PVCName:       "pvc-2",
					PVCNamespace:  "ns-2",
					PVName:        "pv-2",
					RestoreMethod: volume.NativeSnapshot,
					NativeSnapshotInfo: &volume.NativeSnapshotInfo{
						SnapshotHandle: "snap-1",
					},
				},
				{
					PVCName:       "pvc-1",
					PVCNamespace:  "ns-1",
					PVName:        "pv-1",
					RestoreMethod: volume.CSISnapshot,
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						SnapshotHandle: "snapshot-handle-1",
						Size:           1234,
						Driver:         "csi.test.driver",
						VSCName:        "content-1",
					},
				},
			},
			inputDetail: false,
			expect: `
CSI Snapshot Restores:
  ns-1/pvc-1:
    Snapshot: specify --details for more information
  ns-3/pvc-3:
    Data Movement: specify --details for more information
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Describer{
				Prefix: "",
				out:    &tabwriter.Writer{},
				buf:    &bytes.Buffer{},
			}
			d.out.Init(d.buf, 0, 8, 2, ' ', 0)
			describeCSISnapshotsRestores(d, tc.inputVolInfoList, tc.inputDetail)
			d.out.Flush()
			assert.Equal(t, tc.expect, d.buf.String())
		})
	}
}

func TestDescribeResourceModifier(t *testing.T) {
	d := &Describer{
		Prefix: "",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}

	d.out.Init(d.buf, 0, 8, 2, ' ', 0)

	DescribeResourceModifier(d, &corev1api.TypedLocalObjectReference{
		APIGroup: &corev1api.SchemeGroupVersion.Group,
		Kind:     "ConfigMap",
		Name:     "resourceModifier",
	})
	d.out.Flush()

	expectOutput := `Resource modifier:
  Type:  ConfigMap
  Name:  resourceModifier
`

	fmt.Println(d.buf.String())
	require.Equal(t, expectOutput, d.buf.String())
}

func TestDescribeRestore(t *testing.T) {
	kbClient := velerotest.NewFakeControllerRuntimeClient(t)
	restore := builder.ForRestore("velero", "test-restore").
		Backup("test-backup").
		ExistingResourcePolicy(string(velerov1api.ResourcePolicyTypeUpdate)).
		ExistingVolumeDataPolicy(string(velerov1api.VolumeDataPolicyTypeFull)).
		Result()

	out := DescribeRestore(context.Background(), kbClient, restore, nil, false, false, "")
	assert.Contains(t, out, "Existing Resource Policy:      update")
	assert.Contains(t, out, "Existing Volume Data Policy:   full")
}
