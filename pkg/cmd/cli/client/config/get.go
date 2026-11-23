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
	"sort"

	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/cmd"
)

func NewGetCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "get [KEY 1] [KEY 2] [...]",
		Short: "Get client configuration file values",
		Run: func(c *cobra.Command, args []string) {
			config, err := client.LoadConfig()
			cmd.CheckError(err)

			if len(args) == 0 {
				keys := make([]string, 0, len(config))
				for key := range config {
					keys = append(keys, key)
				}

				sort.Strings(keys)

				for _, key := range keys {
					fmt.Printf("%s: %s\n", key, config[key])
				}
			} else {
				for _, key := range args {
					value, found := config[key]
					if !found {
						value = "<NOT SET>"
					}
					fmt.Printf("%s: %s\n", key, value)
				}
			}
		},
	}

	return c
}
