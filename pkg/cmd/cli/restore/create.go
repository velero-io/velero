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
	"sort"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/resourcemodifiers"
	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/velero/restore"
)

func NewCreateCommand(f client.Factory, use string) *cobra.Command {
	o := NewCreateOptions()

	c := &cobra.Command{
		Use:   use + " [RESTORE_NAME] [--from-backup BACKUP_NAME | --from-schedule SCHEDULE_NAME]",
		Short: "Create a restore",
		Example: `  # Create a restore named "restore-1" from backup "backup-1".
  velero restore create restore-1 --from-backup backup-1

  # Create a restore with a default name ("backup-1-<timestamp>") from backup "backup-1".
  velero restore create --from-backup backup-1
 
  # Create a restore from the latest successful backup triggered by schedule "schedule-1".
  velero restore create --from-schedule schedule-1

  # Create a restore from the latest successful OR partially-failed backup triggered by schedule "schedule-1".
  velero restore create --from-schedule schedule-1 --allow-partially-failed

  # Create a restore for only persistentvolumeclaims and persistentvolumes within a backup.
  velero restore create --from-backup backup-2 --include-resources persistentvolumeclaims,persistentvolumes`,
		Args: cobra.MaximumNArgs(1),
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
	BackupName                string
	ScheduleName              string
	RestoreName               string
	RestoreVolumes            flag.OptionalBool
	PreserveNodePorts         flag.OptionalBool
	Labels                    flag.Map
	Annotations               flag.Map
	IncludeNamespaces         flag.StringArray
	ExcludeNamespaces         flag.StringArray
	ExistingResourcePolicy    string
	IncludeResources          flag.StringArray
	ExcludeResources          flag.StringArray
	StatusIncludeResources    flag.StringArray
	StatusExcludeResources    flag.StringArray
	NamespaceMappings         flag.Map
	Selector                  flag.LabelSelector
	OrSelector                flag.OrLabelSelector
	IncludeClusterResources   flag.OptionalBool
	Wait                      bool
	AllowPartiallyFailed      flag.OptionalBool
	ItemOperationTimeout      time.Duration
	ResourceModifierConfigMap string
	WriteSparseFiles          flag.OptionalBool
	ParallelFilesDownload     int
	client                    kbclient.WithWatch
}

func NewCreateOptions() *CreateOptions {
	return &CreateOptions{
		Labels:                  flag.NewMap(),
		Annotations:             flag.NewMap(),
		IncludeNamespaces:       flag.NewStringArray("*"),
		NamespaceMappings:       flag.NewMap().WithEntryDelimiter(',').WithKeyValueDelimiter(':'),
		RestoreVolumes:          flag.NewOptionalBool(nil),
		PreserveNodePorts:       flag.NewOptionalBool(nil),
		IncludeClusterResources: flag.NewOptionalBool(nil),
		WriteSparseFiles:        flag.NewOptionalBool(nil),
	}
}

func (o *CreateOptions) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.BackupName, "from-backup", "", "Backup to restore from")
	flags.StringVar(&o.ScheduleName, "from-schedule", "", "Schedule to restore from")
	flags.Var(&o.IncludeNamespaces, "include-namespaces", "Namespaces to include in the restore (use '*' for all namespaces)")
	flags.Var(&o.ExcludeNamespaces, "exclude-namespaces", "Namespaces to exclude from the restore.")
	flags.Var(&o.NamespaceMappings, "namespace-mappings", "Namespace mappings from name in the backup to desired restored name in the form src1:dst1,src2:dst2,...")
	flags.Var(&o.Labels, "labels", "Labels to apply to the restore.")
	flags.Var(&o.Annotations, "annotations", "Annotations to apply to the restore.")
	flags.Var(&o.IncludeResources, "include-resources", "Resources to include in the restore, formatted as resource.group, such as storageclasses.storage.k8s.io (use '*' for all resources).")
	flags.Var(&o.ExcludeResources, "exclude-resources", "Resources to exclude from the restore, formatted as resource.group, such as storageclasses.storage.k8s.io.")
	flags.StringVar(&o.ExistingResourcePolicy, "existing-resource-policy", "", "Restore Policy to be used during the restore workflow, can be - none or update")
	flags.Var(&o.StatusIncludeResources, "status-include-resources", "Resources to include in the restore status, formatted as resource.group, such as storageclasses.storage.k8s.io.")
	flags.Var(&o.StatusExcludeResources, "status-exclude-resources", "Resources to exclude from the restore status, formatted as resource.group, such as storageclasses.storage.k8s.io.")
	flags.VarP(&o.Selector, "selector", "l", "Only restore resources matching this label selector.")
	flags.Var(&o.OrSelector, "or-selector", "Restore resources matching at least one of the label selector from the list. Label selectors should be separated by ' or '. For example, foo=bar or app=nginx")
	flags.DurationVar(&o.ItemOperationTimeout, "item-operation-timeout", o.ItemOperationTimeout, "How long to wait for async plugin operations before timeout.")
	f := flags.VarPF(&o.RestoreVolumes, "restore-volumes", "", "Whether to restore volumes from snapshots.")
	// this allows the user to just specify "--restore-volumes" as shorthand for "--restore-volumes=true"
	// like a normal bool flag
	f.NoOptDefVal = cmd.TRUE

	f = flags.VarPF(&o.PreserveNodePorts, "preserve-nodeports", "", "Whether to preserve nodeports of Services when restoring.")
	// this allows the user to just specify "--preserve-nodeports" as shorthand for "--preserve-nodeports=true"
	// like a normal bool flag
	f.NoOptDefVal = cmd.TRUE

	f = flags.VarPF(&o.IncludeClusterResources, "include-cluster-resources", "", "Include cluster-scoped resources in the restore.")
	f.NoOptDefVal = cmd.TRUE

	f = flags.VarPF(&o.AllowPartiallyFailed, "allow-partially-failed", "", "If using --from-schedule, whether to consider PartiallyFailed backups when looking for the most recent one. This flag has no effect if not using --from-schedule.")
	f.NoOptDefVal = cmd.TRUE

	flags.BoolVarP(&o.Wait, "wait", "w", o.Wait, "Wait for the operation to complete.")

	flags.StringVar(&o.ResourceModifierConfigMap, "resource-modifier-configmap", "", "Reference to the resource modifier configmap that restore will use")

	f = flags.VarPF(&o.WriteSparseFiles, "write-sparse-files", "", "Whether to write sparse files during restoring volumes")
	f.NoOptDefVal = cmd.TRUE

	flags.IntVar(&o.ParallelFilesDownload, "parallel-files-download", 0, "The number of restore operations to run in parallel. If set to 0, the default parallelism will be the number of CPUs for the node that node agent pod is running.")
}

func (o *CreateOptions) Complete(args []string, f client.Factory) error {
	if len(args) == 1 {
		o.RestoreName = args[0]
	} else {
		sourceName := o.BackupName
		if o.ScheduleName != "" {
			sourceName = o.ScheduleName
		}

		o.RestoreName = fmt.Sprintf("%s-%s", sourceName, time.Now().Format("20060102150405"))
	}

	client, err := f.KubebuilderWatchClient()
	if err != nil {
		return err
	}
	o.client = client

	return nil
}

func (o *CreateOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if o.BackupName != "" && o.ScheduleName != "" {
		return errors.New("either a backup or schedule must be specified, but not both")
	}

	if o.BackupName == "" && o.ScheduleName == "" {
		return errors.New("either a backup or schedule must be specified, but not both")
	}

	if err := output.ValidateFlags(c); err != nil {
		return err
	}

	if o.client == nil {
		// This should never happen
		return errors.New("Velero client is not set; unable to proceed")
	}

	if o.Selector.LabelSelector != nil && o.OrSelector.OrLabelSelectors != nil {
		return errors.New("either a 'selector' or an 'or-selector' can be specified, but not both")
	}

	if len(o.ExistingResourcePolicy) > 0 && !restore.IsResourcePolicyValid(o.ExistingResourcePolicy) {
		return errors.New("existing-resource-policy has invalid value, it accepts only none, update as value")
	}

	if o.ParallelFilesDownload < 0 {
		return errors.New("parallel-files-download cannot be negative")
	}

	switch {
	case o.BackupName != "":
		backup := new(api.Backup)
		if err := o.client.Get(context.TODO(), kbclient.ObjectKey{Namespace: f.Namespace(), Name: o.BackupName}, backup); err != nil {
			return err
		}
	case o.ScheduleName != "":
		backupList := new(api.BackupList)
		err := o.client.List(context.TODO(), backupList, &kbclient.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{api.ScheduleNameLabel: label.GetValidName(o.ScheduleName)}),
			Namespace:     f.Namespace(),
		})
		if err != nil {
			return err
		}
		if len(backupList.Items) == 0 {
			return errors.Errorf("No backups found for the schedule %s", o.ScheduleName)
		}
	}

	return nil
}

// mostRecentBackup returns the backup with the most recent start timestamp that has a phase that's
// in the provided list of allowed phases.
func mostRecentBackup(backups []api.Backup, allowedPhases ...api.BackupPhase) *api.Backup {
	// sort the backups in descending order of start time (i.e. most recent to least recent)
	sort.Slice(backups, func(i, j int) bool {
		// Use .After() because we want descending sort.

		var iStartTime, jStartTime time.Time
		if backups[i].Status.StartTimestamp != nil {
			iStartTime = backups[i].Status.StartTimestamp.Time
		}
		if backups[j].Status.StartTimestamp != nil {
			jStartTime = backups[j].Status.StartTimestamp.Time
		}
		return iStartTime.After(jStartTime)
	})

	// create a map of the allowed phases for easy lookup below
	phases := map[api.BackupPhase]struct{}{}
	for _, phase := range allowedPhases {
		phases[phase] = struct{}{}
	}

	var res *api.Backup
	for i, backup := range backups {
		// if the backup's phase is one of the allowable ones, record
		// the backup and break the loop so we can return it
		if _, ok := phases[backup.Status.Phase]; ok {
			res = &backups[i]
			break
		}
	}

	return res
}

func (o *CreateOptions) Run(c *cobra.Command, f client.Factory) error {
	if o.client == nil {
		// This should never happen
		return errors.New("Velero client is not set; unable to proceed")
	}

	// if --allow-partially-failed was specified, look up the most recent Completed or
	// PartiallyFailed backup for the provided schedule, and use that specific backup
	// to restore from.
	if o.ScheduleName != "" && boolptr.IsSetToTrue(o.AllowPartiallyFailed.Value) {
		backupList := new(api.BackupList)
		err := o.client.List(context.TODO(), backupList, &kbclient.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{api.ScheduleNameLabel: label.GetValidName(o.ScheduleName)}),
			Namespace:     f.Namespace(),
		})
		if err != nil {
			return err
		}

		// if we find a Completed or PartiallyFailed backup for the schedule, restore specifically from that backup. If we don't
		// find one, proceed as-is -- the Velero server will handle validation.
		if backup := mostRecentBackup(backupList.Items, api.BackupPhaseCompleted, api.BackupPhasePartiallyFailed); backup != nil {
			// TODO(sk): this is kind of a hack -- we should revisit this and probably
			// move this logic to the server side or otherwise solve this problem.
			o.BackupName = backup.Name
			o.ScheduleName = ""
		}
	}

	var resModifiers *corev1api.TypedLocalObjectReference

	if o.ResourceModifierConfigMap != "" {
		resModifiers = &corev1api.TypedLocalObjectReference{
			// Group for core API is ""
			APIGroup: &corev1api.SchemeGroupVersion.Group,
			Kind:     resourcemodifiers.ConfigmapRefType,
			Name:     o.ResourceModifierConfigMap,
		}
	}

	restore := &api.Restore{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   f.Namespace(),
			Name:        o.RestoreName,
			Labels:      o.Labels.Data(),
			Annotations: o.Annotations.Data(),
		},
		Spec: api.RestoreSpec{
			BackupName:              o.BackupName,
			ScheduleName:            o.ScheduleName,
			IncludedNamespaces:      o.IncludeNamespaces,
			ExcludedNamespaces:      o.ExcludeNamespaces,
			IncludedResources:       o.IncludeResources,
			ExcludedResources:       o.ExcludeResources,
			ExistingResourcePolicy:  api.PolicyType(o.ExistingResourcePolicy),
			NamespaceMapping:        o.NamespaceMappings.Data(),
			LabelSelector:           o.Selector.LabelSelector,
			OrLabelSelectors:        o.OrSelector.OrLabelSelectors,
			RestorePVs:              o.RestoreVolumes.Value,
			PreserveNodePorts:       o.PreserveNodePorts.Value,
			IncludeClusterResources: o.IncludeClusterResources.Value,
			ResourceModifier:        resModifiers,
			ItemOperationTimeout: metav1.Duration{
				Duration: o.ItemOperationTimeout,
			},
			UploaderConfig: &api.UploaderConfigForRestore{
				WriteSparseFiles:      o.WriteSparseFiles.Value,
				ParallelFilesDownload: o.ParallelFilesDownload,
			},
		},
	}

	if len([]string(o.StatusIncludeResources)) > 0 {
		restore.Spec.RestoreStatus = &api.RestoreStatusSpec{
			IncludedResources: o.StatusIncludeResources,
			ExcludedResources: o.StatusExcludeResources,
		}
	}

	if printed, err := output.PrintWithFormat(c, restore); printed || err != nil {
		return err
	}

	var updates chan *api.Restore
	if o.Wait {
		stop := make(chan struct{})
		defer close(stop)

		updates = make(chan *api.Restore)

		lw := kube.InternalLW{
			Client:     o.client,
			Namespace:  f.Namespace(),
			ObjectList: new(api.RestoreList),
		}
		restoreInformer := cache.NewSharedInformer(&lw, &api.Restore{}, time.Second)

		_, _ = restoreInformer.AddEventHandler(
			cache.FilteringResourceEventHandler{
				FilterFunc: func(obj any) bool {
					restore, ok := obj.(*api.Restore)
					if !ok {
						return false
					}
					return restore.Name == o.RestoreName
				},
				Handler: cache.ResourceEventHandlerFuncs{
					UpdateFunc: func(_, obj any) {
						restore, ok := obj.(*api.Restore)
						if !ok {
							return
						}
						updates <- restore
					},
					DeleteFunc: func(obj any) {
						restore, ok := obj.(*api.Restore)
						if !ok {
							return
						}
						updates <- restore
					},
				},
			},
		)
		go restoreInformer.Run(stop)
	}

	err := o.client.Create(context.TODO(), restore, &kbclient.CreateOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("Restore request %q submitted successfully.\n", restore.Name)
	if o.Wait {
		fmt.Println("Waiting for restore to complete. You may safely press ctrl-c to stop waiting - your restore will continue in the background.")
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				fmt.Print(".")
			case restore, ok := <-updates:
				if !ok {
					fmt.Println("\nError waiting: unable to watch restores.")
					return nil
				}

				if restore.Status.Phase == api.RestorePhaseFailedValidation || restore.Status.Phase == api.RestorePhaseCompleted ||
					restore.Status.Phase == api.RestorePhasePartiallyFailed || restore.Status.Phase == api.RestorePhaseFailed {
					fmt.Printf("\nRestore completed with status: %s. You may check for more information using the commands `velero restore describe %s` and `velero restore logs %s`.\n", restore.Status.Phase, restore.Name, restore.Name)
					return nil
				}
			}
		}
	}

	// Not waiting

	fmt.Printf("Run `velero restore describe %s` or `velero restore logs %s` for more details.\n", restore.Name, restore.Name)

	return nil
}
