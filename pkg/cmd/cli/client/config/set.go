/*
Copyright 2018 the Velero contributors.

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

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd"
)

func NewSetCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "set KEY=VALUE [KEY=VALUE]...",
		Short: "Set client configuration file values",
		Args:  cobra.MinimumNArgs(1),
		Run: func(c *cobra.Command, args []string) {
			config, err := client.LoadConfig()
			cmd.CheckError(err)

			for _, arg := range args {
				pair := strings.Split(arg, "=")
				if len(pair) != 2 {
					fmt.Fprintf(os.Stderr, "WARNING: invalid KEY=VALUE: %q\n", arg)
					continue
				}
				key, value := pair[0], pair[1]

				if value == "" {
					delete(config, key)
				} else {
					config[key] = value
				}
			}

			cmd.CheckError(client.SaveConfig(config))
		},
	}

	return c
}
