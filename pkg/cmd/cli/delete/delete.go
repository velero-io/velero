/*
Copyright 2020 the Velero contributors.

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

package delete

import (
	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd/cli/backup"
	"github.com/velero-io/velero/pkg/cmd/cli/backuplocation"
	"github.com/velero-io/velero/pkg/cmd/cli/restore"
	"github.com/velero-io/velero/pkg/cmd/cli/schedule"
)

func NewCommand(f client.Factory) *cobra.Command {
	c := &cobra.Command{
		Use:   "delete",
		Short: "Delete velero resources",
		Long:  "Delete velero resources",
	}

	backupCommand := backup.NewDeleteCommand(f, "backup")
	backupCommand.Aliases = []string{"backups"}

	backuplocationCommand := backuplocation.NewDeleteCommand(f, "backup-location")
	backuplocationCommand.Aliases = []string{"backup-locations"}

	restoreCommand := restore.NewDeleteCommand(f, "restore")
	restoreCommand.Aliases = []string{"restores"}

	scheduleCommand := schedule.NewDeleteCommand(f, "schedule")
	scheduleCommand.Aliases = []string{"schedules"}

	c.AddCommand(
		backupCommand,
		backuplocationCommand,
		restoreCommand,
		scheduleCommand,
	)

	return c
}
