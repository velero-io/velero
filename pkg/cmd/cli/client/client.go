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

package client

import (
	"github.com/spf13/cobra"

	"github.com/vmware-tanzu/velero/pkg/cmd/cli/client/config"
)

func NewCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "client",
		Short: "Velero client related commands",
	}

	c.AddCommand(
		config.NewCommand(),
	)

	return c
}
