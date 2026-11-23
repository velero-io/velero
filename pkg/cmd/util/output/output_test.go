package output

import (
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"

	"testing"
)

func TestBindFlags(t *testing.T) {
	cmd := &cobra.Command{}
	BindFlags(cmd.Flags())
	assert.NotNil(t, cmd.Flags().Lookup("output"))
	assert.NotNil(t, cmd.Flags().Lookup("label-columns"))
	assert.NotNil(t, cmd.Flags().Lookup("show-labels"))
	assert.Nil(t, cmd.Flags().Lookup("not-exist"))
}

func TestBindFlagsSimple(t *testing.T) {
	cmd := &cobra.Command{}
	BindFlagsSimple(cmd.Flags())
	assert.NotNil(t, cmd.Flags().Lookup("output"))
	assert.Nil(t, cmd.Flags().Lookup("label-columns"))
	assert.Nil(t, cmd.Flags().Lookup("show-labels"))
}

func TestClearOutputFlagDefault(t *testing.T) {
	cmd := &cobra.Command{}
	ClearOutputFlagDefault(cmd)
	assert.Nil(t, cmd.Flags().Lookup("output"))
	BindFlags(cmd.Flags())
	cmd.Flags().Set("output", "json")
	ClearOutputFlagDefault(cmd)
	assert.Empty(t, cmd.Flags().Lookup("output").Value.String())
}

func cmdWithFormat(use string, format string) *cobra.Command {
	cmd := &cobra.Command{
		Use: use,
	}
	BindFlags(cmd.Flags())
	cmd.Flags().Set("output", format)
	return cmd
}

func TestValidateFlags(t *testing.T) {
	testcases := []struct {
		name   string
		input  *cobra.Command
		hasErr bool
	}{
		{
			name:   "unknown format",
			input:  cmdWithFormat("whatever", "unknown"),
			hasErr: true,
		},
		{
			name:   "json format",
			input:  cmdWithFormat("whatever", "json"),
			hasErr: false,
		},
		{
			name:   "yaml format",
			input:  cmdWithFormat("whatever", "yaml"),
			hasErr: false,
		},
		{
			name:   "empty format",
			input:  cmdWithFormat("whatever", ""),
			hasErr: false,
		},
		{
			name:   "install with table format",
			input:  cmdWithFormat("install", "table"),
			hasErr: true,
		},
		{
			name:   "other with table format",
			input:  cmdWithFormat("other", "table"),
			hasErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFlags(tc.input)
			if tc.hasErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrintWithFormat(t *testing.T) {
	testcases := []struct {
		name  string
		input struct {
			cmd *cobra.Command
			obj runtime.Object
		}
		hasErr  bool
		printed bool
	}{
		{
			name: "empty format",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", ""),
			},
			hasErr:  false,
			printed: false,
		},
		{
			name: "json format backup",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "json"),
				obj: &velerov1.Backup{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.Backup{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "json format backup list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "json"),
				obj: &velerov1.BackupList{
					Items: []velerov1.Backup{
						{},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.BackupList{
					Items: []velerov1.Backup{
						{},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.Backup{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format restore list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.RestoreList{
					Items: []velerov1.Restore{
						{},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format restore",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.Restore{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format schedule list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.ScheduleList{
					Items: []velerov1.Schedule{
						{},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format schedule",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.Schedule{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup repository list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.BackupRepositoryList{
					Items: []velerov1.BackupRepository{
						{},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup repository",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.BackupRepository{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup location list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.BackupStorageLocationList{
					Items: []velerov1.BackupStorageLocation{
						{
							Spec: velerov1.BackupStorageLocationSpec{
								Provider: "aws",
								StorageType: velerov1.StorageType{
									ObjectStorage: &velerov1.ObjectStorageLocation{
										Bucket: "bucket",
									},
								},
							},
						},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format backup location",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.BackupStorageLocation{
					Spec: velerov1.BackupStorageLocationSpec{
						Provider: "aws",
						StorageType: velerov1.StorageType{
							ObjectStorage: &velerov1.ObjectStorageLocation{
								Bucket: "bucket",
							},
						},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format volume snapshot location list",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.VolumeSnapshotLocationList{
					Items: []velerov1.VolumeSnapshotLocation{
						{},
					},
				},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format volume snapshot location",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.VolumeSnapshotLocation{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format volume snapshot location",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.VolumeSnapshotLocation{},
			},
			hasErr:  false,
			printed: true,
		},
		{
			name: "table format plugin list via server status",
			input: struct {
				cmd *cobra.Command
				obj runtime.Object
			}{
				cmd: cmdWithFormat("describe", "table"),
				obj: &velerov1.ServerStatusRequest{},
			},
			hasErr:  false,
			printed: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := PrintWithFormat(tc.input.cmd, tc.input.obj)
			if tc.hasErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.printed, p)
		})
	}
}
