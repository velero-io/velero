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

package restore

import (
	"context"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
)

func NewGetCommand(f client.Factory, use string) *cobra.Command {
	var listOptions metav1.ListOptions

	c := &cobra.Command{
		Use:   use,
		Short: "Get restores",
		Run: func(c *cobra.Command, args []string) {
			err := output.ValidateFlags(c)
			cmd.CheckError(err)

			kbClient, err := f.KubebuilderClient()
			cmd.CheckError(err)

			restores := new(api.RestoreList)
			if len(args) > 0 {
				for _, name := range args {
					restore := new(api.Restore)
					err := kbClient.Get(context.TODO(), controllerclient.ObjectKey{Namespace: f.Namespace(), Name: name}, restore)
					cmd.CheckError(err)
					restores.Items = append(restores.Items, *restore)
				}
			} else {
				parsedSelector, err := labels.Parse(listOptions.LabelSelector)
				cmd.CheckError(err)

				err = kbClient.List(context.TODO(), restores, &controllerclient.ListOptions{LabelSelector: parsedSelector, Namespace: f.Namespace()})
				cmd.CheckError(err)
			}

			// Append "(Deleting)" to phase if deletionTimestamp is marked.
			for i := range restores.Items {
				if !restores.Items[i].DeletionTimestamp.IsZero() {
					restores.Items[i].Status.Phase += " (Deleting)"
				}
			}

			if printed, err := output.PrintWithFormat(c, restores); printed || err != nil {
				cmd.CheckError(err)
				return
			}

			_, err = output.PrintWithFormat(c, restores)
			cmd.CheckError(err)
		},
	}

	c.ValidArgsFunction = cli.CompleteRestoreNames(f)
	c.Flags().StringVarP(&listOptions.LabelSelector, "selector", "l", listOptions.LabelSelector, "Only show items matching this label selector.")

	output.BindFlags(c.Flags())

	return c
}
