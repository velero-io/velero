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

package backuplocation

import (
	"github.com/spf13/cobra"

	"github.com/velero-io/velero/pkg/client"
)

func NewCommand(f client.Factory) *cobra.Command {
	c := &cobra.Command{
		Use:   "backup-location",
		Short: "Work with backup storage locations",
		Long:  "Work with backup storage locations",
	}

	c.AddCommand(
		NewCreateCommand(f, "create"),
		NewDeleteCommand(f, "delete"),
		NewGetCommand(f, "get"),
		NewSetCommand(f, "set"),
	)

	return c
}
