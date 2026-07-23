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

package schedule

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
)

func NewDescribeCommand(f client.Factory, use string) *cobra.Command {
	var listOptions metav1.ListOptions

	c := &cobra.Command{
		Use:   use + " [NAME1] [NAME2] [NAME...]",
		Short: "Describe schedules",
		Run: func(c *cobra.Command, args []string) {
			crClient, err := f.KubebuilderClient()
			cmd.CheckError(err)

			schedules := new(v1.ScheduleList)
			if len(args) > 0 {
				for _, name := range args {
					schedule := new(v1.Schedule)
					err := crClient.Get(context.TODO(), ctrlclient.ObjectKey{Namespace: f.Namespace(), Name: name}, schedule)
					cmd.CheckError(err)
					schedules.Items = append(schedules.Items, *schedule)
				}
			} else {
				selector := labels.NewSelector()
				if listOptions.LabelSelector != "" {
					selector, err = labels.Parse(listOptions.LabelSelector)
					cmd.CheckError(err)
				}
				err = crClient.List(context.TODO(), schedules, &ctrlclient.ListOptions{LabelSelector: selector})
				cmd.CheckError(err)
			}

			first := true
			for i := range schedules.Items {
				s := output.DescribeSchedule(&schedules.Items[i])
				if first {
					first = false
					fmt.Print(s)
				} else {
					fmt.Printf("\n\n%s", s)
				}
			}
			cmd.CheckError(err)
		},
	}

	c.ValidArgsFunction = cli.CompleteScheduleNames(f)
	c.Flags().StringVarP(&listOptions.LabelSelector, "selector", "l", listOptions.LabelSelector, "Only show items matching this label selector.")

	return c
}
