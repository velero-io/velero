/*
Copyright 2017 the Velero contributors.

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

package describe

import (
	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd/cli/backup"
	"github.com/velero-io/velero/pkg/cmd/cli/restore"
	"github.com/velero-io/velero/pkg/cmd/cli/schedule"
)

func NewCommand(f client.Factory) *cobra.Command {
	c := &cobra.Command{
		Use:   "describe",
		Short: "Describe velero resources",
		Long:  "Describe velero resources",
	}

	backupCommand := backup.NewDescribeCommand(f, "backups")
	backupCommand.Aliases = []string{"backup"}

	scheduleCommand := schedule.NewDescribeCommand(f, "schedules")
	scheduleCommand.Aliases = []string{"schedule"}

	restoreCommand := restore.NewDescribeCommand(f, "restores")
	restoreCommand.Aliases = []string{"restore"}

	c.AddCommand(
		backupCommand,
		scheduleCommand,
		restoreCommand,
	)

	return c
}
