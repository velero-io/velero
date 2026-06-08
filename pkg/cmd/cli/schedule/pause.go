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
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
)

// NewPauseCommand creates the command for pause
func NewPauseCommand(f client.Factory, use string) *cobra.Command {
	o := cli.NewSelectOptions("pause", "schedule")
	pauseOpts := NewPauseOptions()

	c := &cobra.Command{
		Use:   use,
		Short: "Pause schedules",
		Example: `  # Pause a schedule named "schedule-1".
  velero schedule pause schedule-1

  # Pause schedules named "schedule-1" and "schedule-2".
  velero schedule pause schedule-1 schedule-2

  # Pause all schedules labeled with "foo=bar".
  velero schedule pause --selector foo=bar

  # Pause all schedules.
  velero schedule pause --all`,
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args))
			cmd.CheckError(o.Validate())
			cmd.CheckError(runPause(f, o, true, pauseOpts.SkipOptions.SkipImmediately.Value))
		},
	}

	c.ValidArgsFunction = cli.CompleteScheduleNames(f)
	o.BindFlags(c.Flags())
	pauseOpts.BindFlags(c.Flags())

	return c
}

type PauseOptions struct {
	SkipOptions *SkipOptions
}

func NewPauseOptions() *PauseOptions {
	return &PauseOptions{
		SkipOptions: NewSkipOptions(),
	}
}

func (o *PauseOptions) BindFlags(flags *pflag.FlagSet) {
	o.SkipOptions.BindFlags(flags)
}

func runPause(f client.Factory, o *cli.SelectOptions, paused bool, skipImmediately *bool) error {
	crClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}

	var (
		schedules []*velerov1api.Schedule
		errs      []error
	)
	switch {
	case len(o.Names) > 0:
		for _, name := range o.Names {
			schedule := new(velerov1api.Schedule)
			err := crClient.Get(context.TODO(), ctrlclient.ObjectKey{Name: name, Namespace: f.Namespace()}, schedule)
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
		res := new(velerov1api.ScheduleList)
		err := crClient.List(context.TODO(), res, &ctrlclient.ListOptions{
			LabelSelector: selector,
		})
		if err != nil {
			errs = append(errs, errors.WithStack(err))
		}

		for i := range res.Items {
			schedules = append(schedules, &res.Items[i])
		}
	}
	if len(schedules) == 0 {
		fmt.Println("No schedules found")
		return nil
	}

	msg := "paused"
	if !paused {
		msg = "unpaused"
	}
	for _, schedule := range schedules {
		if schedule.Spec.Paused == paused {
			fmt.Printf("Schedule %s is already %s, skip\n", schedule.Name, msg)
			continue
		}
		schedule.Spec.Paused = paused
		schedule.Spec.SkipImmediately = skipImmediately
		if err := crClient.Update(context.TODO(), schedule); err != nil {
			return errors.Wrapf(err, "failed to update schedule %s", schedule.Name)
		}
		fmt.Printf("Schedule %s %s successfully\n", schedule.Name, msg)
	}
	return kubeerrs.NewAggregate(errs)
}
