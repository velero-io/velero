/*
Copyright The Velero Contributors.

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

package schedule

import (
	"github.com/spf13/cobra"

	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
)

// NewUnpauseCommand creates the command for unpause
func NewUnpauseCommand(f client.Factory, use string) *cobra.Command {
	o := cli.NewSelectOptions("pause", "schedule")
	pauseOpts := NewPauseOptions()
	c := &cobra.Command{
		Use:   use,
		Short: "Unpause schedules",
		Example: `  # Unpause a schedule named "schedule-1".
  velero schedule unpause schedule-1

  # Unpause schedules named "schedule-1" and "schedule-2".
  velero schedule unpause schedule-1 schedule-2

  # Unpause all schedules labeled with "foo=bar".
  velero schedule unpause --selector foo=bar

  # Unpause all schedules.
  velero schedule unpause --all`,
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args))
			cmd.CheckError(o.Validate())
			cmd.CheckError(runPause(f, o, false, pauseOpts.SkipOptions.SkipImmediately.Value))
		},
	}

	c.ValidArgsFunction = cli.CompleteScheduleNames(f)
	o.BindFlags(c.Flags())
	pauseOpts.BindFlags(c.Flags())

	return c
}
