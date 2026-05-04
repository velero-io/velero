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
	"github.com/spf13/pflag"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/backup"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
)

func NewCreateCommand(f client.Factory, use string) *cobra.Command {
	o := NewCreateOptions()

	c := &cobra.Command{
		Use:   use + " NAME --schedule",
		Short: "Create a schedule",
		Long: `The --schedule flag is required, in cron notation, using UTC time:

| Character Position | Character Period | Acceptable Values |
| -------------------|:----------------:| -----------------:|
| 1                  | Minute           | 0-59,*            |
| 2                  | Hour             | 0-23,*            |
| 3                  | Day of Month     | 1-31,*            |
| 4                  | Month            | 1-12,*            |
| 5                  | Day of Week      | 0-6,*             |

The schedule can also be expressed using "@every <duration>" syntax. The duration
can be specified using a combination of seconds (s), minutes (m), and hours (h), for
example: "@every 2h30m".`,

		Example: `  # Create a backup every 6 hours.
  velero create schedule NAME --schedule="0 */6 * * *"

  # Create a backup every 6 hours with the @every notation.
  velero create schedule NAME --schedule="@every 6h"

  # Create a daily backup of the web namespace.
  velero create schedule NAME --schedule="@every 24h" --include-namespaces web

  # Create a weekly backup, each living for 90 days (2160 hours).
  velero create schedule NAME --schedule="@every 168h" --ttl 2160h0m0s`,
		Args: cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args, f))
			cmd.CheckError(o.Validate(c, args, f))
			cmd.CheckError(o.Run(c, f))
		},
	}

	o.BindFlags(c.Flags())
	output.BindFlags(c.Flags())
	output.ClearOutputFlagDefault(c)

	return c
}

type CreateOptions struct {
	BackupOptions              *backup.CreateOptions
	SkipOptions                *SkipOptions
	Schedule                   string
	UseOwnerReferencesInBackup bool
	Paused                     bool
}

func NewCreateOptions() *CreateOptions {
	return &CreateOptions{
		BackupOptions: backup.NewCreateOptions(),
		SkipOptions:   NewSkipOptions(),
	}
}

func (o *CreateOptions) BindFlags(flags *pflag.FlagSet) {
	o.BackupOptions.BindFlags(flags)
	o.SkipOptions.BindFlags(flags)
	flags.StringVar(&o.Schedule, "schedule", o.Schedule, "A cron expression specifying a recurring schedule for this backup to run")
	flags.BoolVar(&o.UseOwnerReferencesInBackup, "use-owner-references-in-backup", o.UseOwnerReferencesInBackup, "Specifies whether to use OwnerReferences on backups created by this Schedule. Notice: if set to true, when schedule is deleted, backups will be deleted too.")
	flags.BoolVar(&o.Paused, "paused", o.Paused, "Specifies whether the newly created schedule is paused or not.")
}

func (o *CreateOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if len(o.Schedule) == 0 {
		return errors.New("--schedule is required")
	}

	return o.BackupOptions.Validate(c, args, f)
}

func (o *CreateOptions) Complete(args []string, f client.Factory) error {
	return o.BackupOptions.Complete(args, f)
}

func (o *CreateOptions) Run(c *cobra.Command, f client.Factory) error {
	var orders map[string]string

	crClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}

	if len(o.BackupOptions.OrderedResources) > 0 {
		orders, err = backup.ParseOrderedResources(o.BackupOptions.OrderedResources)
		if err != nil {
			return err
		}
	}

	schedule := &api.Schedule{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.Namespace(),
			Name:      o.BackupOptions.Name,
			Labels:    o.BackupOptions.Labels.Data(),
		},
		Spec: api.ScheduleSpec{
			Template: api.BackupSpec{
				IncludedNamespaces:               o.BackupOptions.IncludeNamespaces,
				ExcludedNamespaces:               o.BackupOptions.ExcludeNamespaces,
				IncludedResources:                o.BackupOptions.IncludeResources,
				ExcludedResources:                o.BackupOptions.ExcludeResources,
				IncludedClusterScopedResources:   o.BackupOptions.IncludeClusterScopedResources,
				ExcludedClusterScopedResources:   o.BackupOptions.ExcludeClusterScopedResources,
				IncludedNamespaceScopedResources: o.BackupOptions.IncludeNamespaceScopedResources,
				ExcludedNamespaceScopedResources: o.BackupOptions.ExcludeNamespaceScopedResources,
				IncludeClusterResources:          o.BackupOptions.IncludeClusterResources.Value,
				LabelSelector:                    o.BackupOptions.Selector.LabelSelector,
				OrLabelSelectors:                 o.BackupOptions.OrSelector.OrLabelSelectors,
				SnapshotVolumes:                  o.BackupOptions.SnapshotVolumes.Value,
				TTL:                              metav1.Duration{Duration: o.BackupOptions.TTL},
				StorageLocation:                  o.BackupOptions.StorageLocation,
				VolumeSnapshotLocations:          o.BackupOptions.SnapshotLocations,
				DefaultVolumesToFsBackup:         o.BackupOptions.DefaultVolumesToFsBackup.Value,
				OrderedResources:                 orders,
				CSISnapshotTimeout:               metav1.Duration{Duration: o.BackupOptions.CSISnapshotTimeout},
				CSISnapshotErrorTimeout:          metav1.Duration{Duration: o.BackupOptions.CSISnapshotErrorTimeout},
				ItemOperationTimeout:             metav1.Duration{Duration: o.BackupOptions.ItemOperationTimeout},
				DataMover:                        o.BackupOptions.DataMover,
				SnapshotMoveData:                 o.BackupOptions.SnapshotMoveData.Value,
			},
			Schedule:                   o.Schedule,
			UseOwnerReferencesInBackup: &o.UseOwnerReferencesInBackup,
			Paused:                     o.Paused,
			SkipImmediately:            o.SkipOptions.SkipImmediately.Value,
		},
	}

	if o.BackupOptions.ResPoliciesConfigmap != "" {
		schedule.Spec.Template.ResourcePolicy = &corev1api.TypedLocalObjectReference{Kind: resourcepolicies.ConfigmapRefType, Name: o.BackupOptions.ResPoliciesConfigmap}
	}

	if o.BackupOptions.ParallelFilesUpload > 0 {
		schedule.Spec.Template.UploaderConfig = &api.UploaderConfigForBackup{
			ParallelFilesUpload: o.BackupOptions.ParallelFilesUpload,
		}
	}

	if printed, err := output.PrintWithFormat(c, schedule); printed || err != nil {
		return err
	}

	err = crClient.Create(context.TODO(), schedule)
	if err != nil {
		return err
	}

	fmt.Printf("Schedule %q created successfully.\n", schedule.Name)
	return nil
}
