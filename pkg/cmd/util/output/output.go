/*
Copyright 2017, 2020 the Velero contributors.

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
	"fmt"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/util/encode"
)

const (
	downloadRequestTimeout = 30 * time.Second
	emptyDisplay           = "<none>"
	defaultDataMover       = "velero"
)

// BindFlags defines a set of output-specific flags within the provided
// FlagSet.
func BindFlags(flags *pflag.FlagSet) {
	flags.StringP("output", "o", "table", "Output display format. For create commands, display the object but do not send it to the server. Valid formats are 'table', 'json', and 'yaml'. 'table' is not valid for the install command.")
	labelColumns := flag.NewStringArray()
	flags.VarP(&labelColumns, "label-columns", "L", "Accepts a comma separated list of labels that are going to be presented as columns. Names are case-sensitive. You can also use multiple flag options like -L label1 -L label2...")
	flags.Bool("show-labels", false, "Show labels in the last column")
}

// BindFlagsSimple defines the output format flag only.
func BindFlagsSimple(flags *pflag.FlagSet) {
	flags.StringP("output", "o", "table", "Output display format. For create commands, display the object but do not send it to the server. Valid formats are 'table', 'json', and 'yaml'. 'table' is not valid for the install command.")
}

// ClearOutputFlagDefault sets the current and default value
// of the "output" flag to the empty string.
func ClearOutputFlagDefault(cmd *cobra.Command) {
	f := cmd.Flag("output")
	if f == nil {
		return
	}
	f.DefValue = ""
	if err := f.Value.Set(""); err != nil {
		fmt.Printf("error clear the default value of output flag: %s\n", err.Error())
	}
}

// GetOutputFlagValue returns the value of the "output" flag
// in the provided command, or the zero value if not present.
func GetOutputFlagValue(cmd *cobra.Command) string {
	return flag.GetOptionalStringFlag(cmd, "output")
}

// GetLabelColumnsValues returns the value of the "label-columns" flag
// in the provided command, or the zero value if not present.
func GetLabelColumnsValues(cmd *cobra.Command) []string {
	return flag.GetOptionalStringArrayFlag(cmd, "label-columns")
}

// GetShowLabelsValue returns the value of the "show-labels" flag
// in the provided command, or the zero value if not present.
func GetShowLabelsValue(cmd *cobra.Command) bool {
	return flag.GetOptionalBoolFlag(cmd, "show-labels")
}

// ValidateFlags returns an error if any of the output-related flags
// were specified with invalid values, or nil otherwise.
func ValidateFlags(cmd *cobra.Command) error {
	if err := validateOutputFlag(cmd); err != nil {
		return err
	}
	return nil
}

func validateOutputFlag(cmd *cobra.Command) error {
	output := GetOutputFlagValue(cmd)
	switch output {
	case "", "json", "yaml":
	case "table":
		if cmd.Name() == "install" {
			return errors.New("'table' format is not supported with 'install' command")
		}
	default:
		return errors.Errorf("invalid output format %q - valid values are 'table', 'json', and 'yaml'", output)
	}
	return nil
}

// PrintWithFormat prints the provided object in the format specified by
// the command's flags.
func PrintWithFormat(c *cobra.Command, obj runtime.Object) (bool, error) {
	format := GetOutputFlagValue(c)
	if format == "" {
		return false, nil
	}

	switch format {
	case "table":
		return printTable(c, obj)
	case "json", "yaml":
		return printEncoded(obj, format)
	}

	return false, errors.Errorf("unsupported output format %q; valid values are 'table', 'json', and 'yaml'", format)
}

func printEncoded(obj runtime.Object, format string) (bool, error) {
	// assume we're printing obj
	toPrint := obj

	if meta.IsListType(obj) {
		list, _ := meta.ExtractList(obj)
		if len(list) == 1 {
			// if obj was a list and there was only 1 item, just print that 1 instead of a list
			toPrint = list[0]
		}
	}

	encoded, err := encode.Encode(toPrint, format)
	if err != nil {
		return false, err
	}

	fmt.Println(string(encoded))

	return true, nil
}

func printTable(cmd *cobra.Command, obj runtime.Object) (bool, error) {
	// 1. generate table
	var table *metav1.Table

	switch objType := obj.(type) {
	case *velerov1api.Backup:
		table = &metav1.Table{
			ColumnDefinitions: backupColumns,
			Rows:              printBackup(objType),
		}
	case *velerov1api.BackupList:
		table = &metav1.Table{
			ColumnDefinitions: backupColumns,
			Rows:              printBackupList(objType),
		}
	case *velerov1api.Restore:
		table = &metav1.Table{
			ColumnDefinitions: restoreColumns,
			Rows:              printRestore(objType),
		}
	case *velerov1api.RestoreList:
		table = &metav1.Table{
			ColumnDefinitions: restoreColumns,
			Rows:              printRestoreList(objType),
		}
	case *velerov1api.Schedule:
		table = &metav1.Table{
			ColumnDefinitions: scheduleColumns,
			Rows:              printSchedule(objType),
		}
	case *velerov1api.ScheduleList:
		table = &metav1.Table{
			ColumnDefinitions: scheduleColumns,
			Rows:              printScheduleList(objType),
		}
	case *velerov1api.BackupRepository:
		table = &metav1.Table{
			ColumnDefinitions: backupRepoColumns,
			Rows:              printBackupRepo(objType),
		}
	case *velerov1api.BackupRepositoryList:
		table = &metav1.Table{
			ColumnDefinitions: backupRepoColumns,
			Rows:              printBackupRepoList(objType),
		}
	case *velerov1api.BackupStorageLocation:
		table = &metav1.Table{
			ColumnDefinitions: backupStorageLocationColumns,
			Rows:              printBackupStorageLocation(objType),
		}
	case *velerov1api.BackupStorageLocationList:
		table = &metav1.Table{
			ColumnDefinitions: backupStorageLocationColumns,
			Rows:              printBackupStorageLocationList(objType),
		}
	case *velerov1api.VolumeSnapshotLocation:
		table = &metav1.Table{
			ColumnDefinitions: volumeSnapshotLocationColumns,
			Rows:              printVolumeSnapshotLocation(objType),
		}
	case *velerov1api.VolumeSnapshotLocationList:
		table = &metav1.Table{
			ColumnDefinitions: volumeSnapshotLocationColumns,
			Rows:              printVolumeSnapshotLocationList(objType),
		}
	case *velerov1api.ServerStatusRequest:
		table = &metav1.Table{
			ColumnDefinitions: pluginColumns,
			Rows:              printPluginList(objType),
		}
	default:
		return false, errors.Errorf("type %T is not supported", obj)
	}

	// 2. print table
	tablePrinter, err := NewPrinter(cmd)
	if err != nil {
		return false, err
	}

	err = tablePrinter.PrintObj(table, os.Stdout)
	if err != nil {
		return false, err
	}

	return true, nil
}

// NewPrinter returns a printer for doing human-readable table printing of
// Velero objects.
func NewPrinter(cmd *cobra.Command) (printers.ResourcePrinter, error) {
	options := printers.PrintOptions{
		ShowLabels:   GetShowLabelsValue(cmd),
		ColumnLabels: GetLabelColumnsValues(cmd),
	}

	printer := printers.NewTablePrinter(options)

	return printer, nil
}
