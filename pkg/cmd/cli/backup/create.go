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

package backup

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/cache"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func NewCreateCommand(f client.Factory, use string) *cobra.Command {
	o := NewCreateOptions()

	c := &cobra.Command{
		Use:   use + " NAME",
		Short: "Create a backup",
		Args:  cobra.MaximumNArgs(1),
		Run: func(c *cobra.Command, args []string) {
			cmd.CheckError(o.Complete(args, f))
			cmd.CheckError(o.Validate(c, args, f))
			cmd.CheckError(o.Run(c, f))
		},
		Example: `  # Create a backup containing all resources.
  velero backup create backup1

  # Create a backup including only the nginx namespace.
  velero backup create nginx-backup --include-namespaces nginx

  # Create a backup excluding the velero and default namespaces.
  velero backup create backup2 --exclude-namespaces velero,default

  # Create a backup based on a schedule named daily-backup.
  velero backup create --from-schedule daily-backup

  # View the YAML for a backup that doesn't snapshot volumes, without sending it to the server.
  velero backup create backup3 --snapshot-volumes=false -o yaml

  # Wait for a backup to complete before returning from the command.
  velero backup create backup4 --wait`,
	}

	o.BindFlags(c.Flags())
	o.BindWait(c.Flags())
	o.BindFromSchedule(c.Flags())
	output.BindFlags(c.Flags())
	output.ClearOutputFlagDefault(c)

	return c
}

type CreateOptions struct {
	Name                            string
	TTL                             time.Duration
	SnapshotVolumes                 flag.OptionalBool
	SnapshotMoveData                flag.OptionalBool
	DataMover                       string
	DefaultVolumesToFsBackup        flag.OptionalBool
	IncludeNamespaces               flag.StringArray
	ExcludeNamespaces               flag.StringArray
	IncludeResources                flag.StringArray
	ExcludeResources                flag.StringArray
	IncludeClusterScopedResources   flag.StringArray
	ExcludeClusterScopedResources   flag.StringArray
	IncludeNamespaceScopedResources flag.StringArray
	ExcludeNamespaceScopedResources flag.StringArray
	Labels                          flag.Map
	Annotations                     flag.Map
	Selector                        flag.LabelSelector
	OrSelector                      flag.OrLabelSelector
	IncludeClusterResources         flag.OptionalBool
	Wait                            bool
	StorageLocation                 string
	SnapshotLocations               []string
	FromSchedule                    string
	OrderedResources                string
	CSISnapshotTimeout              time.Duration
	CSISnapshotErrorTimeout         time.Duration
	ItemOperationTimeout            time.Duration
	ResPoliciesConfigmap            string
	client                          kbclient.WithWatch
	ParallelFilesUpload             int
}

func NewCreateOptions() *CreateOptions {
	return &CreateOptions{
		IncludeNamespaces:       flag.NewStringArray("*"),
		Labels:                  flag.NewMap(),
		Annotations:             flag.NewMap(),
		SnapshotVolumes:         flag.NewOptionalBool(nil),
		IncludeClusterResources: flag.NewOptionalBool(nil),
	}
}

func (o *CreateOptions) BindFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&o.TTL, "ttl", o.TTL, "How long before the backup can be garbage collected.")
	flags.Var(&o.IncludeNamespaces, "include-namespaces", "Namespaces to include in the backup (use '*' for all namespaces).")
	flags.Var(&o.ExcludeNamespaces, "exclude-namespaces", "Namespaces to exclude from the backup.")
	flags.Var(&o.IncludeResources, "include-resources", "Resources to include in the backup, formatted as resource.group, such as storageclasses.storage.k8s.io (use '*' for all resources). Cannot work with include-cluster-scoped-resources, exclude-cluster-scoped-resources, include-namespace-scoped-resources and exclude-namespace-scoped-resources.")
	flags.Var(&o.ExcludeResources, "exclude-resources", "Resources to exclude from the backup, formatted as resource.group, such as storageclasses.storage.k8s.io. Cannot work with include-cluster-scoped-resources, exclude-cluster-scoped-resources, include-namespace-scoped-resources and exclude-namespace-scoped-resources.")
	flags.Var(&o.IncludeClusterScopedResources, "include-cluster-scoped-resources", "Cluster-scoped resources to include in the backup, formatted as resource.group, such as storageclasses.storage.k8s.io(use '*' for all resources). Cannot work with include-resources, exclude-resources and include-cluster-resources.")
	flags.Var(&o.ExcludeClusterScopedResources, "exclude-cluster-scoped-resources", "Cluster-scoped resources to exclude from the backup, formatted as resource.group, such as storageclasses.storage.k8s.io(use '*' for all resources). Cannot work with include-resources, exclude-resources and include-cluster-resources.")
	flags.Var(&o.IncludeNamespaceScopedResources, "include-namespace-scoped-resources", "Namespaced resources to include in the backup, formatted as resource.group, such as deployments.apps(use '*' for all resources). Cannot work with include-resources, exclude-resources and include-cluster-resources.")
	flags.Var(&o.ExcludeNamespaceScopedResources, "exclude-namespace-scoped-resources", "Namespaced resources to exclude from the backup, formatted as resource.group, such as deployments.apps(use '*' for all resources). Cannot work with include-resources, exclude-resources and include-cluster-resources.")
	flags.Var(&o.Labels, "labels", "Labels to apply to the backup.")
	flags.Var(&o.Annotations, "annotations", "Annotations to apply to the backup.")
	flags.StringVar(&o.StorageLocation, "storage-location", "", "Location in which to store the backup.")
	flags.StringSliceVar(&o.SnapshotLocations, "volume-snapshot-locations", o.SnapshotLocations, "List of locations (at most one per provider) where volume snapshots should be stored.")
	flags.VarP(&o.Selector, "selector", "l", "Only back up resources matching this label selector.")
	flags.Var(&o.OrSelector, "or-selector", "Backup resources matching at least one of the label selector from the list. Label selectors should be separated by ' or '. For example, foo=bar or app=nginx")
	flags.StringVar(&o.OrderedResources, "ordered-resources", "", "Mapping Kinds to an ordered list of specific resources of that Kind.  Resource names are separated by commas and their names are in format 'namespace/resourcename'. For cluster scope resource, simply use resource name. Key-value pairs in the mapping are separated by semi-colon.  Example: 'pods=ns1/pod1,ns1/pod2;persistentvolumeclaims=ns1/pvc4,ns1/pvc8'.  Optional.")
	flags.DurationVar(&o.CSISnapshotTimeout, "csi-snapshot-timeout", o.CSISnapshotTimeout, "How long to wait for CSI snapshot creation before timeout.")
	flags.DurationVar(&o.CSISnapshotErrorTimeout, "csi-snapshot-error-timeout", o.CSISnapshotErrorTimeout, "How long to tolerate persistent errors in a CSI VolumeSnapshot or VolumeSnapshotContent status before failing the backup.")
	flags.DurationVar(&o.ItemOperationTimeout, "item-operation-timeout", o.ItemOperationTimeout, "How long to wait for async plugin operations before timeout.")
	f := flags.VarPF(&o.SnapshotVolumes, "snapshot-volumes", "", "Take snapshots of PersistentVolumes as part of the backup. If the parameter is not set, it is treated as setting to 'true'.")
	// this allows the user to just specify "--snapshot-volumes" as shorthand for "--snapshot-volumes=true"
	// like a normal bool flag
	f.NoOptDefVal = cmd.TRUE

	f = flags.VarPF(&o.SnapshotMoveData, "snapshot-move-data", "", "Specify whether snapshot data should be moved")
	f.NoOptDefVal = cmd.TRUE

	f = flags.VarPF(&o.IncludeClusterResources, "include-cluster-resources", "", "Include cluster-scoped resources in the backup. Cannot work with include-cluster-scoped-resources, exclude-cluster-scoped-resources, include-namespace-scoped-resources and exclude-namespace-scoped-resources.")
	f.NoOptDefVal = cmd.TRUE

	f = flags.VarPF(&o.DefaultVolumesToFsBackup, "default-volumes-to-fs-backup", "", "Use pod volume file system backup by default for volumes")
	f.NoOptDefVal = cmd.TRUE

	flags.StringVar(&o.ResPoliciesConfigmap, "resource-policies-configmap", "", "Reference to the resource policies configmap that backup should use")
	flags.StringVar(&o.DataMover, "data-mover", "", "Specify the data mover to be used by the backup. If the parameter is not set or set as 'velero', the built-in data mover will be used")
	flags.IntVar(&o.ParallelFilesUpload, "parallel-files-upload", 0, "Number of files uploads simultaneously when running a backup. This is only applicable for the kopia uploader")
}

// BindWait binds the wait flag separately so it is not called by other create
// commands that reuse CreateOptions's BindFlags method.
func (o *CreateOptions) BindWait(flags *pflag.FlagSet) {
	flags.BoolVarP(&o.Wait, "wait", "w", o.Wait, "Wait for the operation to complete.")
}

// BindFromSchedule binds the from-schedule flag separately so it is not called
// by other create commands that reuse CreateOptions's BindFlags method.
func (o *CreateOptions) BindFromSchedule(flags *pflag.FlagSet) {
	flags.StringVar(&o.FromSchedule, "from-schedule", "", "Create a backup from the template of an existing schedule. Cannot be used with any other filters. Backup name is optional if used.")
}

func (o *CreateOptions) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if err := output.ValidateFlags(c); err != nil {
		return err
	}

	if o.Selector.LabelSelector != nil && o.OrSelector.OrLabelSelectors != nil {
		return fmt.Errorf("either a 'selector' or an 'or-selector' can be specified, but not both")
	}

	// Ensure if FromSchedule is set, it has a non-empty value
	if err := o.validateFromScheduleFlag(c); err != nil {
		return err
	}

	// Ensure that unless FromSchedule is set, args contains a backup name
	if o.FromSchedule == "" && len(args) != 1 {
		return fmt.Errorf("a backup name is required, unless you are creating based on a schedule")
	}

	errs := collections.ValidateNamespaceIncludesExcludes(o.IncludeNamespaces, o.ExcludeNamespaces)
	if len(errs) > 0 {
		return kubeerrs.NewAggregate(errs)
	}

	if o.oldAndNewFilterParametersUsedTogether() {
		return fmt.Errorf("include-resources, exclude-resources and include-cluster-resources are old filter parameters.\n" +
			"include-cluster-scoped-resources, exclude-cluster-scoped-resources, include-namespace-scoped-resources and exclude-namespace-scoped-resources are new filter parameters.\n" +
			"They cannot be used together")
	}

	if o.StorageLocation != "" {
		location := &velerov1api.BackupStorageLocation{}
		if err := o.client.Get(context.Background(), kbclient.ObjectKey{
			Namespace: f.Namespace(),
			Name:      o.StorageLocation,
		}, location); err != nil {
			return err
		}
	}

	for _, loc := range o.SnapshotLocations {
		snapshotLocation := new(velerov1api.VolumeSnapshotLocation)
		if err := o.client.Get(context.Background(), kbclient.ObjectKey{Namespace: f.Namespace(), Name: loc}, snapshotLocation); err != nil {
			return err
		}
	}

	return nil
}

func (o *CreateOptions) validateFromScheduleFlag(c *cobra.Command) error {
	trimmed := strings.TrimSpace(o.FromSchedule)
	if c.Flags().Changed("from-schedule") && trimmed == "" {
		return fmt.Errorf("flag must have a non-empty value: --from-schedule")
	}

	// Assign the trimmed value back
	o.FromSchedule = trimmed
	return nil
}

func (o *CreateOptions) Complete(args []string, f client.Factory) error {
	// If an explicit name is specified, use that name
	if len(args) > 0 {
		o.Name = args[0]
	}
	client, err := f.KubebuilderWatchClient()
	if err != nil {
		return err
	}
	o.client = client
	return nil
}

func (o *CreateOptions) Run(c *cobra.Command, f client.Factory) error {
	backup, err := o.BuildBackup(f.Namespace())
	if err != nil {
		return err
	}

	if printed, err := output.PrintWithFormat(c, backup); printed || err != nil {
		return err
	}

	if o.FromSchedule != "" {
		fmt.Println("Creating backup from schedule, all other filters are ignored.")
	}

	var updates chan *velerov1api.Backup
	if o.Wait {
		stop := make(chan struct{})
		defer close(stop)

		updates = make(chan *velerov1api.Backup)

		lw := kube.InternalLW{
			Client:     o.client,
			Namespace:  f.Namespace(),
			ObjectList: new(velerov1api.BackupList),
		}
		backupInformer := cache.NewSharedInformer(&lw, &velerov1api.Backup{}, time.Second)
		_, _ = backupInformer.AddEventHandler(
			cache.FilteringResourceEventHandler{
				FilterFunc: func(obj any) bool {
					backup, ok := obj.(*velerov1api.Backup)

					if !ok {
						return false
					}
					return backup.Name == o.Name
				},
				Handler: cache.ResourceEventHandlerFuncs{
					UpdateFunc: func(_, obj any) {
						backup, ok := obj.(*velerov1api.Backup)
						if !ok {
							return
						}
						updates <- backup
					},
					DeleteFunc: func(obj any) {
						backup, ok := obj.(*velerov1api.Backup)
						if !ok {
							return
						}
						updates <- backup
					},
				},
			},
		)

		go backupInformer.Run(stop)
	}

	err = o.client.Create(context.TODO(), backup, &kbclient.CreateOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("Backup request %q submitted successfully.\n", backup.Name)
	if o.Wait {
		fmt.Println("Waiting for backup to complete. You may safely press ctrl-c to stop waiting - your backup will continue in the background.")
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				fmt.Print(".")
			case backup, ok := <-updates:
				if !ok {
					fmt.Println("\nError waiting: unable to watch backups.")
					return nil
				}

				if backup.Status.Phase == velerov1api.BackupPhaseFailedValidation || backup.Status.Phase == velerov1api.BackupPhaseCompleted ||
					backup.Status.Phase == velerov1api.BackupPhasePartiallyFailed || backup.Status.Phase == velerov1api.BackupPhaseFailed {
					fmt.Printf("\nBackup completed with status: %s. You may check for more information using the commands `velero backup describe %s` and `velero backup logs %s`.\n", backup.Status.Phase, backup.Name, backup.Name)
					return nil
				}
			}
		}
	}

	// Not waiting

	fmt.Printf("Run `velero backup describe %s` or `velero backup logs %s` for more details.\n", backup.Name, backup.Name)

	return nil
}

// ParseOrderedResources converts to map of Kinds to an ordered list of specific resources of that Kind.
// Resource names in the list are in format 'namespace/resourcename' and separated by commas.
// Key-value pairs in the mapping are separated by semi-colon.
// Ex: 'pods=ns1/pod1,ns1/pod2;persistentvolumeclaims=ns1/pvc4,ns1/pvc8'.
func ParseOrderedResources(orderMapStr string) (map[string]string, error) {
	entries := strings.Split(orderMapStr, ";")
	if len(entries) == 0 {
		return nil, fmt.Errorf("invalid OrderedResources '%s'", orderMapStr)
	}
	orderedResources := make(map[string]string)
	for _, entry := range entries {
		kv := strings.Split(entry, "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid OrderedResources '%s'", entry)
		}
		kind := strings.TrimSpace(kv[0])
		order := strings.TrimSpace(kv[1])
		orderedResources[kind] = order
	}
	return orderedResources, nil
}

func (o *CreateOptions) BuildBackup(namespace string) (*velerov1api.Backup, error) {
	var backupBuilder *builder.BackupBuilder

	if o.FromSchedule != "" {
		schedule := new(velerov1api.Schedule)
		err := o.client.Get(context.TODO(), kbclient.ObjectKey{Namespace: namespace, Name: o.FromSchedule}, schedule)
		if err != nil {
			return nil, err
		}
		if o.Name == "" {
			o.Name = schedule.TimestampedName(time.Now().UTC())
		}
		backupBuilder = builder.ForBackup(namespace, o.Name).
			FromSchedule(schedule)
	} else {
		backupBuilder = builder.ForBackup(namespace, o.Name).
			IncludedNamespaces(o.IncludeNamespaces...).
			ExcludedNamespaces(o.ExcludeNamespaces...).
			IncludedResources(o.IncludeResources...).
			ExcludedResources(o.ExcludeResources...).
			IncludedClusterScopedResources(o.IncludeClusterScopedResources...).
			ExcludedClusterScopedResources(o.ExcludeClusterScopedResources...).
			IncludedNamespaceScopedResources(o.IncludeNamespaceScopedResources...).
			ExcludedNamespaceScopedResources(o.ExcludeNamespaceScopedResources...).
			LabelSelector(o.Selector.LabelSelector).
			OrLabelSelector(o.OrSelector.OrLabelSelectors).
			TTL(o.TTL).
			StorageLocation(o.StorageLocation).
			VolumeSnapshotLocations(o.SnapshotLocations...).
			CSISnapshotTimeout(o.CSISnapshotTimeout).
			CSISnapshotErrorTimeout(o.CSISnapshotErrorTimeout).
			ItemOperationTimeout(o.ItemOperationTimeout).
			DataMover(o.DataMover)
		if len(o.OrderedResources) > 0 {
			orders, err := ParseOrderedResources(o.OrderedResources)
			if err != nil {
				return nil, err
			}
			backupBuilder.OrderedResources(orders)
		}

		if o.SnapshotVolumes.Value != nil {
			backupBuilder.SnapshotVolumes(*o.SnapshotVolumes.Value)
		}
		if o.SnapshotMoveData.Value != nil {
			backupBuilder.SnapshotMoveData(*o.SnapshotMoveData.Value)
		}
		if o.IncludeClusterResources.Value != nil {
			backupBuilder.IncludeClusterResources(*o.IncludeClusterResources.Value)
		}
		if o.DefaultVolumesToFsBackup.Value != nil {
			backupBuilder.DefaultVolumesToFsBackup(*o.DefaultVolumesToFsBackup.Value)
		}
		if o.ResPoliciesConfigmap != "" {
			backupBuilder.ResourcePolicies(o.ResPoliciesConfigmap)
		}
		if o.ParallelFilesUpload > 0 {
			backupBuilder.ParallelFilesUpload(o.ParallelFilesUpload)
		}
	}

	backup := backupBuilder.ObjectMeta(builder.WithLabelsMap(o.Labels.Data()), builder.WithAnnotationsMap(o.Annotations.Data())).Result()
	return backup, nil
}

func (o *CreateOptions) oldAndNewFilterParametersUsedTogether() bool {
	haveOldResourceFilterParameters := len(o.IncludeResources) > 0 ||
		len(o.ExcludeResources) > 0 ||
		o.IncludeClusterResources.Value != nil
	haveNewResourceFilterParameters := len(o.IncludeClusterScopedResources) > 0 ||
		(len(o.ExcludeClusterScopedResources) > 0) ||
		(len(o.IncludeNamespaceScopedResources) > 0) ||
		(len(o.ExcludeNamespaceScopedResources) > 0)

	return haveOldResourceFilterParameters && haveNewResourceFilterParameters
}
