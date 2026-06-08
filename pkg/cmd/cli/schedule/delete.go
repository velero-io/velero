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

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/confirm"
)

// NewDeleteCommand creates and returns a new cobra command for deleting schedules.
func NewDeleteCommand(f client.Factory, use string) *cobra.Command {
	o := cli.NewDeleteOptions("schedule")

	c := &cobra.Command{
		Use:   fmt.Sprintf("%s [NAMES]", use),
		Short: "Delete schedules",
		Example: `  # Delete a schedule named "schedule-1".
  velero schedule delete schedule-1

  # Delete a schedule named "schedule-1" without prompting for confirmation.
  velero schedule delete schedule-1 --confirm

  # Delete schedules named "schedule-1" and "schedule-2".
  velero schedule delete schedule-1 schedule-2

  # Delete all schedules labeled with "foo=bar".
  velero schedule delete --selector foo=bar

  # Delete all schedules.
  velero schedule delete --all`,
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(f, args))
			cmd.CheckError(o.Validate(c, f, args))
			cmd.CheckError(Run(o))
		},
	}

	c.ValidArgsFunction = cli.CompleteScheduleNames(f)
	o.BindFlags(c.Flags())
	return c
}

// Run performs the deletion of schedules.
func Run(o *cli.DeleteOptions) error {
	if !o.Confirm && !confirm.GetConfirmation() {
		return nil
	}
	var (
		schedules []*velerov1api.Schedule
		errs      []error
	)
	switch {
	case len(o.Names) > 0:
		for _, name := range o.Names {
			schedule := new(velerov1api.Schedule)
			err := o.Client.Get(context.TODO(), controllerclient.ObjectKey{Namespace: o.Namespace, Name: name}, schedule)
			if err != nil {
				errs = append(errs, errors.WithStack(err))
				continue
			}
			schedules = append(schedules, schedule)
		}
	default:
		selector := labels.Everything()
		if o.Selector.LabelSelector != nil {
			convertedSelector, err := metav1.LabelSelectorAsSelector(o.Selector.LabelSelector)
			if err != nil {
				return errors.WithStack(err)
			}
			selector = convertedSelector
		}
		scheduleList := new(velerov1api.ScheduleList)
		err := o.Client.List(context.TODO(), scheduleList, &controllerclient.ListOptions{
			Namespace:     o.Namespace,
			LabelSelector: selector,
		})
		if err != nil {
			errs = append(errs, errors.WithStack(err))
		}

		for i := range scheduleList.Items {
			schedules = append(schedules, &scheduleList.Items[i])
		}
	}
	if len(schedules) == 0 {
		fmt.Println("No schedules found")
		return nil
	}

	for _, s := range schedules {
		err := o.Client.Delete(context.TODO(), s, &controllerclient.DeleteOptions{})
		if err != nil {
			errs = append(errs, errors.WithStack(err))
			continue
		}
		fmt.Printf("Schedule deleted: %v\n", s.Name)
	}
	return kubeerrs.NewAggregate(errs)
}
