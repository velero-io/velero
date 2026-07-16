/*
Copyright the Velero contributors.

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

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/internal/velero"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/output"
	"github.com/vmware-tanzu/velero/pkg/install"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

// Options collects all the options for installing Velero into a Kubernetes cluster.
type Options struct {
	Namespace                       string
	Image                           string
	BucketName                      string
	Prefix                          string
	ProviderName                    string
	PodAnnotations                  flag.Map
	PodLabels                       flag.Map
	ServiceAccountAnnotations       flag.Map
	ServiceAccountName              string
	VeleroPodCPURequest             string
	VeleroPodMemRequest             string
	VeleroPodCPULimit               string
	VeleroPodMemLimit               string
	NodeAgentPodCPURequest          string
	NodeAgentPodMemRequest          string
	NodeAgentPodCPULimit            string
	NodeAgentPodMemLimit            string
	RestoreOnly                     bool
	SecretFile                      string
	NoSecret                        bool
	DryRun                          bool
	BackupStorageConfig             flag.Map
	VolumeSnapshotConfig            flag.Map
	UseNodeAgent                    bool
	UseNodeAgentWindows             bool
	PrivilegedNodeAgent             bool
	Wait                            bool
	UseVolumeSnapshots              bool
	DefaultRepoMaintenanceFrequency time.Duration
	GarbageCollectionFrequency      time.Duration
	PodVolumeOperationTimeout       time.Duration
	Plugins                         flag.StringArray
	NoDefaultBackupLocation         bool
	CRDsOnly                        bool
	CACertFile                      string
	Features                        string
	DefaultVolumesToFsBackup        bool
	UploaderType                    string
	DefaultSnapshotMoveData         bool
	CSISnapshotEarlyFrequentPolling bool
	DisableInformerCache            bool
	ScheduleSkipImmediately         bool
	PodResources                    kubeutil.PodResources
	KeepLatestMaintenanceJobs       int
	BackupRepoConfigMap             string
	RepoMaintenanceJobConfigMap     string
	NodeAgentConfigMap              string
	ItemBlockWorkerCount            int
	ConcurrentBackups               int
	NodeAgentDisableHostPath        bool
	kubeletRootDir                  string
	Apply                           bool
	ServerPriorityClassName         string
	NodeAgentPriorityClassName      string
}

// BindFlags adds command line values to the options struct.
func (o *Options) BindFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.ProviderName, "provider", o.ProviderName, "Provider name for backup and volume storage")
	flags.StringVar(&o.BucketName, "bucket", o.BucketName, "Name of the object storage bucket where backups should be stored")
	flags.StringVar(&o.SecretFile, "secret-file", o.SecretFile, "File containing credentials for backup and volume provider. If not specified, --no-secret must be used for confirmation. Optional.")
	flags.BoolVar(&o.NoSecret, "no-secret", o.NoSecret, "Flag indicating if a secret should be created. Must be used as confirmation if --secret-file is not provided. Optional.")
	flags.BoolVar(&o.Apply, "apply", o.Apply, "Flag indicating if resources should be applied instead of created. This can be used for updating existing resources.")
	flags.BoolVar(&o.NoDefaultBackupLocation, "no-default-backup-location", o.NoDefaultBackupLocation, "Flag indicating if a default backup location should be created. Must be used as confirmation if --bucket or --provider are not provided. Optional.")
	flags.StringVar(&o.Image, "image", o.Image, "Image to use for the Velero and node agent pods. Optional.")
	flags.StringVar(&o.Prefix, "prefix", o.Prefix, "Prefix under which all Velero data should be stored within the bucket. Optional.")
	flags.Var(&o.PodAnnotations, "pod-annotations", "Annotations to add to the Velero and node agent pods. Optional. Format is key1=value1,key2=value2")
	flags.Var(&o.PodLabels, "pod-labels", "Labels to add to the Velero and node agent pods. Optional. Format is key1=value1,key2=value2")
	flags.Var(&o.ServiceAccountAnnotations, "sa-annotations", "Annotations to add to the Velero ServiceAccount. Add iam.gke.io/gcp-service-account=[GSA_NAME]@[PROJECT_NAME].iam.gserviceaccount.com for workload identity. Optional. Format is key1=value1,key2=value2")
	flags.StringVar(&o.ServiceAccountName, "service-account-name", o.ServiceAccountName, "ServiceAccountName to be set to the Velero and node agent pods, it should be created before the installation, and the user also needs to create the rolebinding for it."+
		"  Optional, if this attribute is set, the default service account 'velero' will not be created, and the flag --sa-annotations will be disregarded.")
	flags.StringVar(&o.VeleroPodCPURequest, "velero-pod-cpu-request", o.VeleroPodCPURequest, `CPU request for Velero pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.VeleroPodMemRequest, "velero-pod-mem-request", o.VeleroPodMemRequest, `Memory request for Velero pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.VeleroPodCPULimit, "velero-pod-cpu-limit", o.VeleroPodCPULimit, `CPU limit for Velero pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.VeleroPodMemLimit, "velero-pod-mem-limit", o.VeleroPodMemLimit, `Memory limit for Velero pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.NodeAgentPodCPURequest, "node-agent-pod-cpu-request", o.NodeAgentPodCPURequest, `CPU request for node-agent pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.NodeAgentPodMemRequest, "node-agent-pod-mem-request", o.NodeAgentPodMemRequest, `Memory request for node-agent pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.NodeAgentPodCPULimit, "node-agent-pod-cpu-limit", o.NodeAgentPodCPULimit, `CPU limit for node-agent pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.NodeAgentPodMemLimit, "node-agent-pod-mem-limit", o.NodeAgentPodMemLimit, `Memory limit for node-agent pod. A value of "0" is treated as unbounded. Optional.`)
	flags.StringVar(&o.kubeletRootDir, "kubelet-root-dir", o.kubeletRootDir, `Kubelet root directory for the node agent. Optional.`)

	flags.Var(&o.BackupStorageConfig, "backup-location-config", "Configuration to use for the backup storage location. Format is key1=value1,key2=value2")
	flags.Var(&o.VolumeSnapshotConfig, "snapshot-location-config", "Configuration to use for the volume snapshot location. Format is key1=value1,key2=value2")
	flags.BoolVar(&o.UseVolumeSnapshots, "use-volume-snapshots", o.UseVolumeSnapshots, "Whether or not to create snapshot location automatically. Set to false if you do not plan to create volume snapshots via a storage provider.")
	flags.BoolVar(&o.RestoreOnly, "restore-only", o.RestoreOnly, "Run the server in restore-only mode. Optional.")
	flags.BoolVar(&o.DryRun, "dry-run", o.DryRun, "Generate resources, but don't send them to the cluster. Use with -o. Optional.")
	flags.BoolVar(&o.UseNodeAgent, "use-node-agent", o.UseNodeAgent, "Create Velero node-agent daemonset. Optional. Velero node-agent hosts and associates Velero modules that need to run in one or more Linux nodes.")
	flags.BoolVar(&o.UseNodeAgentWindows, "use-node-agent-windows", o.UseNodeAgentWindows, "Create Velero node-agent-windows daemonset. Optional. Velero node-agent-windows hosts and associates Velero modules that need to run in one or more Windows nodes.")
	flags.BoolVar(&o.PrivilegedNodeAgent, "privileged-node-agent", o.PrivilegedNodeAgent, "Use privileged mode for the node agent. Optional. Required to backup block devices.")
	flags.BoolVar(&o.Wait, "wait", o.Wait, "Wait for Velero deployment to be ready. Optional.")
	flags.DurationVar(&o.DefaultRepoMaintenanceFrequency, "default-repo-maintain-frequency", o.DefaultRepoMaintenanceFrequency, "How often 'maintain' is run for backup repositories by default. Optional.")
	flags.DurationVar(&o.GarbageCollectionFrequency, "garbage-collection-frequency", o.GarbageCollectionFrequency, "How often the garbage collection runs for expired backups.(default 1h)")
	flags.DurationVar(&o.PodVolumeOperationTimeout, "pod-volume-operation-timeout", o.PodVolumeOperationTimeout, "How long to wait for pod volume operations to complete before timing out(default 4h). Optional.")
	flags.Var(&o.Plugins, "plugins", "Plugin container images to install into the Velero Deployment")
	flags.BoolVar(&o.CRDsOnly, "crds-only", o.CRDsOnly, "Only generate CustomResourceDefinition resources. Useful for updating CRDs for an existing Velero install.")
	flags.StringVar(&o.CACertFile, "cacert", o.CACertFile, "File containing a certificate bundle to use when verifying TLS connections to the object store. Optional.")
	flags.StringVar(&o.Features, "features", o.Features, "Comma separated list of Velero feature flags to be set on the Velero deployment and the node-agent daemonset, if node-agent is enabled")
	flags.BoolVar(&o.DefaultVolumesToFsBackup, "default-volumes-to-fs-backup", o.DefaultVolumesToFsBackup, "Bool flag to configure Velero server to use pod volume file system backup by default for all volumes on all backups. Optional.")
	flags.StringVar(&o.UploaderType, "uploader-type", o.UploaderType, fmt.Sprintf("The type of uploader to transfer the data of pod volumes, supported value: '%s'", uploader.KopiaType))
	flags.BoolVar(&o.DefaultSnapshotMoveData, "default-snapshot-move-data", o.DefaultSnapshotMoveData, "Bool flag to configure Velero server to move data by default for all snapshots supporting data movement. Optional.")
	flags.BoolVar(&o.CSISnapshotEarlyFrequentPolling, "csi-snapshot-early-frequent-polling", o.CSISnapshotEarlyFrequentPolling, "Bool flag to configure Velero server to use early frequent polling by default for all CSI snapshots. Optional.")
	flags.BoolVar(&o.DisableInformerCache, "disable-informer-cache", o.DisableInformerCache, "Disable informer cache for Get calls on restore. With this enabled, it will speed up restore in cases where there are backup resources which already exist in the cluster, but for very large clusters this will increase velero memory usage. Default is false (don't disable). Optional.")
	flags.BoolVar(&o.ScheduleSkipImmediately, "schedule-skip-immediately", o.ScheduleSkipImmediately, "Skip the first scheduled backup immediately after creating a schedule. Default is false (don't skip).")
	flags.BoolVar(&o.NodeAgentDisableHostPath, "node-agent-disable-host-path", o.NodeAgentDisableHostPath, "Don't mount the pod volume host path to node-agent. Optional. Pod volume host path mount is required by fs-backup but could be disabled for other backup methods.")

	flags.IntVar(
		&o.KeepLatestMaintenanceJobs,
		"keep-latest-maintenance-jobs",
		o.KeepLatestMaintenanceJobs,
		"Number of latest maintenance jobs to keep each repository. Optional.",
	)
	flags.StringVar(
		&o.PodResources.CPURequest,
		"maintenance-job-cpu-request",
		o.PodResources.CPURequest,
		"CPU request for maintenance jobs. Default is no limit.",
	)
	flags.StringVar(
		&o.PodResources.MemoryRequest,
		"maintenance-job-mem-request",
		o.PodResources.MemoryRequest,
		"Memory request for maintenance jobs. Default is no limit.",
	)
	flags.StringVar(
		&o.PodResources.CPULimit,
		"maintenance-job-cpu-limit",
		o.PodResources.CPULimit,
		"CPU limit for maintenance jobs. Default is no limit.",
	)
	flags.StringVar(
		&o.PodResources.MemoryLimit,
		"maintenance-job-mem-limit",
		o.PodResources.MemoryLimit,
		"Memory limit for maintenance jobs. Default is no limit.",
	)
	flags.StringVar(
		&o.BackupRepoConfigMap,
		"backup-repository-configmap",
		o.BackupRepoConfigMap,
		"The name of configMap containing backup repository configurations.",
	)
	flags.StringVar(
		&o.RepoMaintenanceJobConfigMap,
		"repo-maintenance-job-configmap",
		o.RepoMaintenanceJobConfigMap,
		"The name of ConfigMap containing repository maintenance Job configurations.",
	)
	flags.StringVar(
		&o.NodeAgentConfigMap,
		"node-agent-configmap",
		o.NodeAgentConfigMap,
		"The name of ConfigMap containing node-agent configurations.",
	)
	flags.IntVar(
		&o.ItemBlockWorkerCount,
		"item-block-worker-count",
		o.ItemBlockWorkerCount,
		"Number of worker threads to process ItemBlocks. Default is one. Optional.",
	)
	flags.IntVar(
		&o.ConcurrentBackups,
		"concurrent-backups",
		o.ConcurrentBackups,
		"Number of backups to process concurrently. Default is one. Optional.",
	)
	flags.StringVar(
		&o.ServerPriorityClassName,
		"server-priority-class-name",
		o.ServerPriorityClassName,
		"Priority class name for the Velero server deployment. Optional.",
	)
	flags.StringVar(
		&o.NodeAgentPriorityClassName,
		"node-agent-priority-class-name",
		o.NodeAgentPriorityClassName,
		"Priority class name for the node agent daemonset. Optional.",
	)
}

// NewInstallOptions instantiates a new, default InstallOptions struct.
func NewInstallOptions() *Options {
	return &Options{
		Namespace:                 velerov1api.DefaultNamespace,
		Image:                     velero.DefaultVeleroImage(),
		BackupStorageConfig:       flag.NewMap(),
		VolumeSnapshotConfig:      flag.NewMap(),
		PodAnnotations:            flag.NewMap(),
		PodLabels:                 flag.NewMap(),
		ServiceAccountAnnotations: flag.NewMap(),
		VeleroPodCPURequest:       install.DefaultVeleroPodCPURequest,
		VeleroPodMemRequest:       install.DefaultVeleroPodMemRequest,
		VeleroPodCPULimit:         install.DefaultVeleroPodCPULimit,
		VeleroPodMemLimit:         install.DefaultVeleroPodMemLimit,
		NodeAgentPodCPURequest:    install.DefaultNodeAgentPodCPURequest,
		NodeAgentPodMemRequest:    install.DefaultNodeAgentPodMemRequest,
		NodeAgentPodCPULimit:      install.DefaultNodeAgentPodCPULimit,
		NodeAgentPodMemLimit:      install.DefaultNodeAgentPodMemLimit,
		// Default to creating a VSL unless we're told otherwise
		UseVolumeSnapshots:              true,
		NoDefaultBackupLocation:         false,
		CRDsOnly:                        false,
		DefaultVolumesToFsBackup:        false,
		UploaderType:                    uploader.KopiaType,
		DefaultSnapshotMoveData:         false,
		CSISnapshotEarlyFrequentPolling: false,
		DisableInformerCache:            false,
		ScheduleSkipImmediately:         false,
		kubeletRootDir:                  install.DefaultKubeletRootDir,
		NodeAgentDisableHostPath:        false,
	}
}

// AsVeleroOptions translates the values provided at the command line into values used to instantiate Kubernetes resources
func (o *Options) AsVeleroOptions() (*install.VeleroOptions, error) {
	var secretData []byte
	if o.SecretFile != "" && !o.NoSecret {
		realPath, err := filepath.Abs(o.SecretFile)
		if err != nil {
			return nil, err
		}
		secretData, err = os.ReadFile(realPath)
		if err != nil {
			return nil, err
		}
	}
	var caCertData []byte
	if o.CACertFile != "" {
		realPath, err := filepath.Abs(o.CACertFile)
		if err != nil {
			return nil, err
		}
		caCertData, err = os.ReadFile(realPath)
		if err != nil {
			return nil, err
		}
	}
	veleroPodResources, err := kubeutil.ParseCPUAndMemoryResources(
		o.VeleroPodCPURequest,
		o.VeleroPodMemRequest,
		o.VeleroPodCPULimit,
		o.VeleroPodMemLimit,
	)
	if err != nil {
		return nil, err
	}
	nodeAgentPodResources, err := kubeutil.ParseCPUAndMemoryResources(
		o.NodeAgentPodCPURequest,
		o.NodeAgentPodMemRequest,
		o.NodeAgentPodCPULimit,
		o.NodeAgentPodMemLimit,
	)
	if err != nil {
		return nil, err
	}

	return &install.VeleroOptions{
		Namespace:                       o.Namespace,
		Image:                           o.Image,
		ProviderName:                    o.ProviderName,
		Bucket:                          o.BucketName,
		Prefix:                          o.Prefix,
		PodAnnotations:                  o.PodAnnotations.Data(),
		PodLabels:                       o.PodLabels.Data(),
		ServiceAccountAnnotations:       o.ServiceAccountAnnotations.Data(),
		ServiceAccountName:              o.ServiceAccountName,
		VeleroPodResources:              veleroPodResources,
		NodeAgentPodResources:           nodeAgentPodResources,
		SecretData:                      secretData,
		RestoreOnly:                     o.RestoreOnly,
		UseNodeAgent:                    o.UseNodeAgent,
		UseNodeAgentWindows:             o.UseNodeAgentWindows,
		PrivilegedNodeAgent:             o.PrivilegedNodeAgent,
		UseVolumeSnapshots:              o.UseVolumeSnapshots,
		BSLConfig:                       o.BackupStorageConfig.Data(),
		VSLConfig:                       o.VolumeSnapshotConfig.Data(),
		DefaultRepoMaintenanceFrequency: o.DefaultRepoMaintenanceFrequency,
		GarbageCollectionFrequency:      o.GarbageCollectionFrequency,
		PodVolumeOperationTimeout:       o.PodVolumeOperationTimeout,
		Plugins:                         o.Plugins,
		NoDefaultBackupLocation:         o.NoDefaultBackupLocation,
		CACertData:                      caCertData,
		Features:                        strings.Split(o.Features, ","),
		DefaultVolumesToFsBackup:        o.DefaultVolumesToFsBackup,
		UploaderType:                    o.UploaderType,
		DefaultSnapshotMoveData:         o.DefaultSnapshotMoveData,
		CSISnapshotEarlyFrequentPolling: o.CSISnapshotEarlyFrequentPolling,
		DisableInformerCache:            o.DisableInformerCache,
		ScheduleSkipImmediately:         o.ScheduleSkipImmediately,
		PodResources:                    o.PodResources,
		KeepLatestMaintenanceJobs:       o.KeepLatestMaintenanceJobs,
		BackupRepoConfigMap:             o.BackupRepoConfigMap,
		RepoMaintenanceJobConfigMap:     o.RepoMaintenanceJobConfigMap,
		NodeAgentConfigMap:              o.NodeAgentConfigMap,
		ItemBlockWorkerCount:            o.ItemBlockWorkerCount,
		ConcurrentBackups:               o.ConcurrentBackups,
		KubeletRootDir:                  o.kubeletRootDir,
		NodeAgentDisableHostPath:        o.NodeAgentDisableHostPath,
		ServerPriorityClassName:         o.ServerPriorityClassName,
		NodeAgentPriorityClassName:      o.NodeAgentPriorityClassName,
	}, nil
}

// NewCommand creates a cobra command.
func NewCommand(f client.Factory) *cobra.Command {
	o := NewInstallOptions()
	c := &cobra.Command{
		Use:   "install",
		Short: "Install Velero",
		Long: `Install Velero onto a Kubernetes cluster using the supplied provider information, such as
the provider's name, a bucket name, and a file containing the credentials to access that bucket.
A prefix within the bucket and configuration for the backup store location may also be supplied.
Additionally, volume snapshot information for the same provider may be supplied.

All required CustomResourceDefinitions will be installed to the server, as well as the
Velero Deployment and associated node-agent DaemonSet.

The provided secret data will be created in a Secret named 'cloud-credentials'.

All namespaced resources will be placed in the 'velero' namespace by default. 

The '--namespace' flag can be used to specify a different namespace to install into.

Use '--wait' to wait for the Velero Deployment to be ready before proceeding.

Use '-o yaml' or '-o json' with '--dry-run' to output all generated resources as text instead of sending the resources to the server.
This is useful as a starting point for more customized installations.
		`,
		Example: `  # velero install --provider gcp --plugins velero/velero-plugin-for-gcp:v1.0.0 --bucket mybucket --secret-file ./gcp-service-account.json

  # velero install --provider aws --plugins velero/velero-plugin-for-aws:v1.0.0 --bucket backups --secret-file ./aws-iam-creds --backup-location-config region=us-east-2 --snapshot-location-config region=us-east-2

  # velero install --provider aws --plugins velero/velero-plugin-for-aws:v1.0.0 --bucket backups --secret-file ./aws-iam-creds --backup-location-config region=us-east-2 --snapshot-location-config region=us-east-2 --use-node-agent

  # velero install --provider gcp --plugins velero/velero-plugin-for-gcp:v1.0.0 --bucket gcp-backups --secret-file ./gcp-creds.json --wait

  # velero install --provider aws --plugins velero/velero-plugin-for-aws:v1.0.0 --bucket backups --backup-location-config region=us-west-2 --snapshot-location-config region=us-west-2 --no-secret --pod-annotations iam.amazonaws.com/role=arn:aws:iam::<AWS_ACCOUNT_ID>:role/<VELERO_ROLE_NAME>

  # velero install --provider gcp --plugins velero/velero-plugin-for-gcp:v1.0.0 --bucket gcp-backups --secret-file ./gcp-creds.json --velero-pod-cpu-request=1000m --velero-pod-cpu-limit=5000m --velero-pod-mem-request=512Mi --velero-pod-mem-limit=1024Mi

  # velero install --provider gcp --plugins velero/velero-plugin-for-gcp:v1.0.0 --bucket gcp-backups --secret-file ./gcp-creds.json --node-agent-pod-cpu-request=1000m --node-agent-pod-cpu-limit=5000m --node-agent-pod-mem-request=512Mi --node-agent-pod-mem-limit=1024Mi

  # velero install --provider azure --plugins velero/velero-plugin-for-microsoft-azure:v1.0.0 --bucket $BLOB_CONTAINER --secret-file ./credentials-velero --backup-location-config resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,storageAccount=$AZURE_STORAGE_ACCOUNT_ID[,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID] --snapshot-location-config apiTimeout=<YOUR_TIMEOUT>[,resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID]`,
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

// Run executes a command in the context of the provided arguments.
func (o *Options) Run(c *cobra.Command, f client.Factory) error {
	var resources *unstructured.UnstructuredList
	if o.CRDsOnly {
		resources = install.AllCRDs()
	} else {
		vo, err := o.AsVeleroOptions()
		if err != nil {
			return err
		}

		resources = install.AllResources(vo)
	}

	if _, err := output.PrintWithFormat(c, resources); err != nil {
		return err
	}

	if o.DryRun {
		return nil
	}
	dynamicClient, err := f.DynamicClient()
	if err != nil {
		return err
	}
	dynamicFactory := client.NewDynamicFactory(dynamicClient)

	kbClient, err := f.KubebuilderClient()
	if err != nil {
		return err
	}

	errorMsg := fmt.Sprintf("\n\nError installing Velero. Use `kubectl logs deploy/velero -n %s` to check the deploy logs", o.Namespace)

	err = install.Install(dynamicFactory, kbClient, resources, os.Stdout, o.Apply)
	if err != nil {
		return errors.Wrap(err, errorMsg)
	}

	if o.Wait {
		fmt.Println("Waiting for Velero deployment to be ready.")
		if _, err = install.DeploymentIsReady(dynamicFactory, o.Namespace); err != nil {
			return errors.Wrap(err, errorMsg)
		}

		if o.UseNodeAgent {
			fmt.Println("Waiting for node-agent daemonset to be ready.")
			if _, err = install.NodeAgentIsReady(dynamicFactory, o.Namespace); err != nil {
				return errors.Wrap(err, errorMsg)
			}
		}

		if o.UseNodeAgentWindows {
			fmt.Println("Waiting for node-agent-windows daemonset to be ready.")
			if _, err = install.NodeAgentWindowsIsReady(dynamicFactory, o.Namespace); err != nil {
				return errors.Wrap(err, errorMsg)
			}
		}
	}
	if o.SecretFile == "" {
		fmt.Printf("\nNo secret file was specified, no Secret created.\n\n")
	}

	if o.NoDefaultBackupLocation {
		fmt.Printf("\nNo bucket and provider were specified, no default backup storage location created.\n\n")
	}

	fmt.Printf("Velero is installed! ⛵ Use 'kubectl logs deployment/velero -n %s' to view the status.\n", o.Namespace)
	return nil
}

// Complete completes options for a command.
func (o *Options) Complete(args []string, f client.Factory) error {
	o.Namespace = f.Namespace()
	return nil
}

// Validate validates options provided to a command.
func (o *Options) Validate(c *cobra.Command, args []string, f client.Factory) error {
	if err := output.ValidateFlags(c); err != nil {
		return err
	}

	// If we're only installing CRDs, we can skip the rest of the validation.
	if o.CRDsOnly {
		return nil
	}

	if msg, err := uploader.ValidateUploaderType(o.UploaderType); err != nil {
		return err
	} else if msg != "" {
		fmt.Printf("⚠️  %s\n", msg)
	}

	// Our main 3 providers don't support bucket names starting with a dash, and a bucket name starting with one
	// can indicate that an environment variable was left blank.
	// This case will help catch that error
	if strings.HasPrefix(o.BucketName, "-") {
		return errors.Errorf("Bucket names cannot begin with a dash. Bucket name was: %s", o.BucketName)
	}

	if o.NoDefaultBackupLocation {
		if o.BucketName != "" {
			return errors.New("Cannot use both --bucket and --no-default-backup-location at the same time")
		}

		if o.Prefix != "" {
			return errors.New("Cannot use both --prefix and --no-default-backup-location at the same time")
		}

		if o.BackupStorageConfig.String() != "" {
			return errors.New("Cannot use both --backup-location-config and --no-default-backup-location at the same time")
		}
	} else {
		if o.ProviderName == "" {
			return errors.New("--provider is required")
		}

		if o.BucketName == "" {
			return errors.New("--bucket is required")
		}
	}

	if o.UseVolumeSnapshots {
		if o.ProviderName == "" {
			return errors.New("--provider is required when --use-volume-snapshots is set to true")
		}
	} else {
		if o.VolumeSnapshotConfig.String() != "" {
			return errors.New("--snapshot-location-config must be empty when --use-volume-snapshots=false")
		}
	}

	if o.NoDefaultBackupLocation && !o.UseVolumeSnapshots {
		if o.ProviderName != "" {
			return errors.New("--provider must be empty when using --no-default-backup-location and --use-volume-snapshots=false")
		}
	} else {
		if len(o.Plugins) == 0 {
			return errors.New("--plugins flag is required")
		}
	}

	if o.DefaultVolumesToFsBackup && !o.UseNodeAgent {
		return errors.New("--use-node-agent is required when using --default-volumes-to-fs-backup")
	}

	switch {
	case o.SecretFile == "" && !o.NoSecret:
		return errors.New("One of --secret-file or --no-secret is required")
	case o.SecretFile != "" && o.NoSecret:
		return errors.New("Cannot use both --secret-file and --no-secret")
	}

	if o.DefaultRepoMaintenanceFrequency < 0 {
		return errors.New("--default-repo-maintain-frequency must be non-negative")
	}

	if o.GarbageCollectionFrequency < 0 {
		return errors.New("--garbage-collection-frequency must be non-negative")
	}

	if o.PodVolumeOperationTimeout < 0 {
		return errors.New("--pod-volume-operation-timeout must be non-negative")
	}

	crClient, err := f.KubebuilderClient()
	if err != nil {
		return fmt.Errorf("fail to create go-client %w", err)
	}

	if len(o.NodeAgentConfigMap) > 0 {
		if err := kubeutil.VerifyJSONConfigs(c.Context(), o.Namespace, crClient, o.NodeAgentConfigMap, &velerotypes.NodeAgentConfigs{}); err != nil {
			return fmt.Errorf("--node-agent-configmap specified ConfigMap %s is invalid: %w", o.NodeAgentConfigMap, err)
		}
	}

	if len(o.RepoMaintenanceJobConfigMap) > 0 {
		if err := kubeutil.VerifyJSONConfigs(c.Context(), o.Namespace, crClient, o.RepoMaintenanceJobConfigMap, &velerotypes.JobConfigs{}); err != nil {
			return fmt.Errorf("--repo-maintenance-job-configmap specified ConfigMap %s is invalid: %w", o.RepoMaintenanceJobConfigMap, err)
		}
	}

	if len(o.BackupRepoConfigMap) > 0 {
		config := make(map[string]any)
		if err := kubeutil.VerifyJSONConfigs(c.Context(), o.Namespace, crClient, o.BackupRepoConfigMap, &config); err != nil {
			return fmt.Errorf("--backup-repository-configmap specified ConfigMap %s is invalid: %w", o.BackupRepoConfigMap, err)
		}
	}

	return nil
}
