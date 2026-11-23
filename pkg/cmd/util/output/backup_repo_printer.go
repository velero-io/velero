/*
Copyright 2018, 2020 the Velero contributors.

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

	v1 "github.com/velero-io/velero/pkg/apis/velero/v1"
)

var (
	backupRepoColumns = []metav1.TableColumnDefinition{
		// name needs Type and Format defined for the decorator to identify it:
		// https://github.com/kubernetes/kubernetes/blob/v1.15.3/pkg/printers/tableprinter.go#L204
		{Name: "Name", Type: "string", Format: "name"},
		{Name: "Status"},
		{Name: "Last Maintenance"},
	}
)

func printBackupRepoList(list *v1.BackupRepositoryList) []metav1.TableRow {
	rows := make([]metav1.TableRow, 0, len(list.Items))

	for i := range list.Items {
		rows = append(rows, printBackupRepo(&list.Items[i])...)
	}
	return rows
}

func printBackupRepo(repo *v1.BackupRepository) []metav1.TableRow {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: repo},
	}

	status := repo.Status.Phase
	if status == "" {
		status = v1.BackupRepositoryPhaseNew
	}

	var lastMaintenance string
	if repo.Status.LastMaintenanceTime == nil || repo.Status.LastMaintenanceTime.IsZero() {
		lastMaintenance = "<never>"
	} else {
		lastMaintenance = repo.Status.LastMaintenanceTime.String()
	}

	row.Cells = append(row.Cells,
		repo.Name,
		status,
		lastMaintenance,
	)

	return []metav1.TableRow{row}
}
