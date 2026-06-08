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

package backup

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
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/confirm"
	"github.com/vmware-tanzu/velero/pkg/label"
)

// NewDeleteCommand creates a new command that deletes a backup.
func NewDeleteCommand(f client.Factory, use string) *cobra.Command {
	o := cli.NewDeleteOptions("backup")

	c := &cobra.Command{
		Use:   fmt.Sprintf("%s [NAMES]", use),
		Short: "Delete backups",
		Example: `  # Delete a backup named "backup-1".
  velero backup delete backup-1

  # Delete a backup named "backup-1" without prompting for confirmation.
  velero backup delete backup-1 --confirm

  # Delete backups named "backup-1" and "backup-2".
  velero backup delete backup-1 backup-2

  # Delete all backups triggered by schedule "schedule-1".
  velero backup delete --selector velero.io/schedule-name=schedule-1
 
  # Delete all backups.
  velero backup delete --all`,
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(f, args))
			cmd.CheckError(o.Validate(c, f, args))
			cmd.CheckError(Run(o))
		},
	}

	c.ValidArgsFunction = cli.CompleteBackupNames(f)
	o.BindFlags(c.Flags())

	return c
}

// Run performs the delete backup operation.
func Run(o *cli.DeleteOptions) error {
	if !o.Confirm && !confirm.GetConfirmation() {
		// Don't do anything unless we get confirmation
		return nil
	}

	var (
		backups []*velerov1api.Backup
		errs    []error
	)

	// get the list of backups to delete
	switch {
	case len(o.Names) > 0:
		for _, name := range o.Names {
			backup := new(velerov1api.Backup)
			err := o.Client.Get(context.TODO(), controllerclient.ObjectKey{Namespace: o.Namespace, Name: name}, backup)
			if err != nil {
				errs = append(errs, errors.WithStack(err))
				continue
			}

			backups = append(backups, backup)
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

		backupList := new(velerov1api.BackupList)
		err := o.Client.List(context.TODO(), backupList, &controllerclient.ListOptions{LabelSelector: selector, Namespace: o.Namespace})
		if err != nil {
			return errors.WithStack(err)
		}
		for i := range backupList.Items {
			backups = append(backups, &backupList.Items[i])
		}
	}

	if len(backups) == 0 {
		fmt.Println("No backups found")
		return nil
	}

	// create a backup deletion request for each
	for _, b := range backups {
		deleteRequest := builder.ForDeleteBackupRequest(o.Namespace, "").BackupName(b.Name).
			ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, label.GetValidName(b.Name),
				velerov1api.BackupUIDLabel, string(b.UID)), builder.WithGenerateName(b.Name+"-")).Result()

		if err := client.CreateRetryGenerateName(o.Client, context.TODO(), deleteRequest); err != nil {
			errs = append(errs, err)
			continue
		}

		fmt.Printf("Request to delete backup %q submitted successfully.\nThe backup will be fully deleted after all associated data (disk snapshots, backup files, restores) are removed.\n", b.Name)
	}

	return kubeerrs.NewAggregate(errs)
}
