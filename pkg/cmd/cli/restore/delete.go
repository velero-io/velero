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

// NewDeleteCommand creates and returns a new cobra command for deleting restores.
func NewDeleteCommand(f client.Factory, use string) *cobra.Command {
	o := cli.NewDeleteOptions("restore")

	c := &cobra.Command{
		Use:   fmt.Sprintf("%s [NAMES]", use),
		Short: "Delete restores",
		Example: `  # Delete a restore named "restore-1".
  velero restore delete restore-1

  # Delete a restore named "restore-1" without prompting for confirmation.
  velero restore delete restore-1 --confirm

  # Delete restores named "restore-1" and "restore-2".
  velero restore delete restore-1 restore-2

  # Delete all restores labeled with "foo=bar".
  velero restore delete --selector foo=bar
	
  # Delete all restores.
  velero restore delete --all`,
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(f, args))
			cmd.CheckError(o.Validate(c, f, args))
			cmd.CheckError(Run(o))
		},
	}
	c.ValidArgsFunction = cli.CompleteRestoreNames(f)
	o.BindFlags(c.Flags())
	return c
}

// Run performs the deletion of restore(s).
func Run(o *cli.DeleteOptions) error {
	if !o.Confirm && !confirm.GetConfirmation() {
		return nil
	}
	var (
		restores []*velerov1api.Restore
		errs     []error
	)

	switch {
	case len(o.Names) > 0:
		for _, name := range o.Names {
			restore := new(velerov1api.Restore)
			err := o.Client.Get(context.TODO(), controllerclient.ObjectKey{Namespace: o.Namespace, Name: name}, restore)
			if err != nil {
				errs = append(errs, errors.WithStack(err))
				continue
			}
			restores = append(restores, restore)
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
		restoreList := new(velerov1api.RestoreList)
		err := o.Client.List(context.TODO(), restoreList, &controllerclient.ListOptions{
			Namespace:     o.Namespace,
			LabelSelector: selector,
		})
		if err != nil {
			errs = append(errs, errors.WithStack(err))
		}

		for i := range restoreList.Items {
			restores = append(restores, &restoreList.Items[i])
		}
	}

	if len(errs) > 0 {
		fmt.Println("errs: ", errs)
		return kubeerrs.NewAggregate(errs)
	}

	if len(restores) == 0 {
		fmt.Println("No restores found")
		return nil
	}
	for _, r := range restores {
		err := o.Client.Delete(context.TODO(), r, &controllerclient.DeleteOptions{})
		if err != nil {
			errs = append(errs, errors.WithStack(err))
			continue
		}
		fmt.Printf("Request to delete restore %q submitted successfully.\nThe restore will be fully deleted after all associated data (restore files in object storage) are removed.\n", r.Name)
	}
	return kubeerrs.NewAggregate(errs)
}
