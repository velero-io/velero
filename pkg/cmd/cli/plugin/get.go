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

package plugin

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd"
	"github.com/velero-io/velero/pkg/cmd/cli/serverstatus"
	"github.com/velero-io/velero/pkg/cmd/util/output"
)

func NewGetCommand(f client.Factory, use string) *cobra.Command {
	timeout := 5 * time.Second

	c := &cobra.Command{
		Use:   use,
		Short: "Get information for all plugins on the velero server",
		Run: func(c *cobra.Command, args []string) {
			err := output.ValidateFlags(c)
			cmd.CheckError(err)

			kbClient, err := f.KubebuilderClient()
			cmd.CheckError(err)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			serverStatusGetter := &serverstatus.DefaultServerStatusGetter{
				Namespace: f.Namespace(),
				Context:   ctx,
			}

			serverStatus, err := serverStatusGetter.GetServerStatus(kbClient)
			if err != nil {
				fmt.Fprintf(os.Stdout, "<error getting plugin information: %s>\n", err)
				return
			}

			_, err = output.PrintWithFormat(c, serverStatus)
			cmd.CheckError(err)
		},
	}

	c.Flags().DurationVar(&timeout, "timeout", timeout, "Maximum time to wait for plugin information to be reported. Default is 5 seconds.")
	output.BindFlagsSimple(c.Flags())

	return c
}
