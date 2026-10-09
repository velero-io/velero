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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

var (
	restoreColumns = []metav1.TableColumnDefinition{
		// name needs Type and Format defined for the decorator to identify it:
		// https://github.com/kubernetes/kubernetes/blob/v1.15.3/pkg/printers/tableprinter.go#L204
		{Name: "Name", Type: "string", Format: "name"},
		{Name: "Backup"},
		{Name: "Status"},
		{Name: "Started"},
		{Name: "Completed"},
		{Name: "Errors"},
		{Name: "Warnings"},
		{Name: "Created"},
		{Name: "Selector"},
	}
)

func printRestoreList(list *v1.RestoreList) []metav1.TableRow {
	rows := make([]metav1.TableRow, 0, len(list.Items))

	for i := range list.Items {
		rows = append(rows, printRestore(&list.Items[i])...)
	}
	return rows
}

func printRestore(restore *v1.Restore) []metav1.TableRow {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: restore},
	}

	status := restore.Status.Phase
	if status == "" {
		status = v1.RestorePhaseNew
	}

	row.Cells = append(row.Cells,
		restore.Name,
		restore.Spec.BackupName,
		status,
		formatTimestamp(restore.Status.StartTimestamp),
		formatTimestamp(restore.Status.CompletionTimestamp),
		restore.Status.Errors,
		restore.Status.Warnings,
		restore.CreationTimestamp.Time,
		metav1.FormatLabelSelector(restore.Spec.LabelSelector),
	)

	return []metav1.TableRow{row}
}
