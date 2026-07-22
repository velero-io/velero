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
	"context"

	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
)

func NewGetCommand(f client.Factory, use string) *cobra.Command {
	var listOptions metav1.ListOptions
	var showDefaultOnly bool

	c := &cobra.Command{
		Use:   use,
		Short: "Get backup storage locations",
		Run: func(c *cobra.Command, args []string) {
			err := output.ValidateFlags(c)
			cmd.CheckError(err)

			kbClient, err := f.KubebuilderClient()
			cmd.CheckError(err)

			locations := new(velerov1api.BackupStorageLocationList)
			if len(args) > 0 {
				for _, name := range args {
					location := &velerov1api.BackupStorageLocation{}
					err = kbClient.Get(context.Background(), kbclient.ObjectKey{
						Namespace: f.Namespace(),
						Name:      name,
					}, location)
					cmd.CheckError(err)

					if showDefaultOnly {
						if location.Spec.Default {
							locations.Items = append(locations.Items, *location)
							break
						}
					} else {
						locations.Items = append(locations.Items, *location)
					}
				}
			} else {
				err := kbClient.List(context.Background(), locations, &kbclient.ListOptions{
					Namespace: f.Namespace(),
					Raw:       &listOptions,
				})
				cmd.CheckError(err)

				if showDefaultOnly {
					for i := 0; i < len(locations.Items); i++ {
						if locations.Items[i].Spec.Default {
							continue
						}
						if i != len(locations.Items)-1 {
							copy(locations.Items[i:], locations.Items[i+1:])
							i = i - 1
						}
						locations.Items = locations.Items[:len(locations.Items)-1]
					}
				}
			}

			_, err = output.PrintWithFormat(c, locations)
			cmd.CheckError(err)
		},
	}

	c.ValidArgsFunction = cli.CompleteBackupStorageLocationNames(f)
	c.Flags().BoolVar(&showDefaultOnly, "default", false, "Displays the current default backup storage location.")
	c.Flags().StringVarP(&listOptions.LabelSelector, "selector", "l", listOptions.LabelSelector, "Only show items matching this label selector.")

	output.BindFlags(c.Flags())

	return c
}
