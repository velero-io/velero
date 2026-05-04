package config

import (
	"fmt"
	"strings"
	"time"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/constant"
	podvolumeconfigs "github.com/vmware-tanzu/velero/pkg/podvolume/configs"
	"github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

const (
	// the port where prometheus metrics are exposed
	defaultMetricsAddress = ":8085"

	defaultBackupSyncPeriod           = time.Minute
	defaultStoreValidationFrequency   = time.Minute
	defaultPodVolumeOperationTimeout  = 240 * time.Minute
	defaultResourceTerminatingTimeout = 10 * time.Minute

	// server's client default qps and burst
	defaultClientQPS      float32 = 100.0
	defaultClientBurst    int     = 100
	defaultClientPageSize int     = 500

	defaultProfilerAddress = "localhost:6060"

	// the default TTL for a backup
	defaultBackupTTL = 30 * 24 * time.Hour

	defaultCSISnapshotTimeout      = 10 * time.Minute
	defaultCSISnapshotErrorTimeout = 10 * time.Minute
	defaultItemOperationTimeout    = 4 * time.Hour

	resourceTimeout = 10 * time.Minute

	defaultMaxConcurrentK8SConnections = 30
	defaultDisableInformerCache        = false

	DefaultItemBlockWorkerCount = 1
	DefaultConcurrentBackups    = 1
)

var (
	// DisableableControllers is a list of controllers that can be disabled
	DisableableControllers = []string{
		constant.ControllerBackupQueue,
		constant.ControllerBackup,
		constant.ControllerBackupOperations,
		constant.ControllerBackupDeletion,
		constant.ControllerBackupFinalizer,
		constant.ControllerBackupSync,
		constant.ControllerDownloadRequest,
		constant.ControllerGarbageCollection,
		constant.ControllerBackupRepo,
		constant.ControllerRestore,
		constant.ControllerRestoreOperations,
		constant.ControllerSchedule,
		constant.ControllerServerStatusRequest,
		constant.ControllerRestoreFinalizer,
	}

	/*
		High priorities:
		  - Custom Resource Definitions come before Custom Resource so that they can be
		    restored with their corresponding CRD.
		  - Namespaces go second because all namespaced resources depend on them.
		  - Storage Classes are needed to create PVs and PVCs correctly.
		  - VolumeSnapshotClasses  are needed to provision volumes using volumesnapshots
		  - VolumeSnapshotContents are needed as they contain the handle to the volume snapshot in the
		    storage provider
		  - VolumeSnapshots are needed to create PVCs using the VolumeSnapshot as their data source.
		  - DataUploads need to restore before PVC for Snapshot DataMover to work, because PVC needs the DataUploadResults to create DataDownloads.
		  - PVs go before PVCs because PVCs depend on them.
		  - PVCs go before pods or controllers so they can be mounted as volumes.
		  - Service accounts go before secrets so service account token secrets can be filled automatically.
		  - Secrets and ConfigMaps go before pods or controllers so they can be mounted
		    as volumes.
		  - Limit ranges go before pods or controllers so pods can use them.
		  - Pods go before controllers so they can be explicitly restored and potentially
		    have pod volume restores run before controllers adopt the pods.
		  - Replica sets go before deployments/other controllers so they can be explicitly
		    restored and be adopted by controllers.
		  - CAPI ClusterClasses go before Clusters.
		  - Endpoints go before Services so no new Endpoints will be created
		  - Services go before Clusters so they can be adopted by AKO-operator and no new Services will be created
		    for the same clusters

		Low priorities:
		  - Tanzu ClusterBootstraps go last as it can reference any other kind of resources.
		  - ClusterBootstraps go before CAPI Clusters otherwise a new default ClusterBootstrap object is created for the cluster
		  - CAPI Clusters come before ClusterResourceSets because failing to do so means the CAPI controller-manager will panic.
		    Both Clusters and ClusterResourceSets need to come before ClusterResourceSetBinding in order to properly restore workload clusters.
		    See https://github.com/kubernetes-sigs/cluster-api/issues/4105
		  - apps.kappctrl.k14s.io and packageinstalls.packaging.carvel.dev go after workloads(pod/replicaset/etc.), otherwise the controller may
		    creates new workloads before restoring them
	*/
	defaultRestorePriorities = types.Priorities{
		HighPriorities: []string{
			"customresourcedefinitions",
			"namespaces",
			"storageclasses",
			"volumesnapshotclass.snapshot.storage.k8s.io",
			"volumesnapshotcontents.snapshot.storage.k8s.io",
			"volumesnapshots.snapshot.storage.k8s.io",
			"datauploads.velero.io",
			"persistentvolumes",
			"persistentvolumeclaims",
			"clusterroles",
			"roles",
			"serviceaccounts",
			"clusterrolebindings",
			"rolebindings",
			"secrets",
			"configmaps",
			"limitranges",
			"priorityclasses",
			"pods",
			// we fully qualify replicasets.apps because prior to Kubernetes 1.16, replicasets also
			// existed in the extensions API group, but we back up replicasets from "apps" so we want
			// to ensure that we prioritize restoring from "apps" too, since this is how they're stored
			// in the backup.
			"replicasets.apps",
			"clusterclasses.cluster.x-k8s.io",
			"endpoints",
			"services",
		},
		LowPriorities: []string{
			"clusterbootstraps.run.tanzu.vmware.com",
			"clusters.cluster.x-k8s.io",
			"clusterresourcesets.addons.cluster.x-k8s.io",
			"apps.kappctrl.k14s.io",
			"packageinstalls.packaging.carvel.dev",
		},
	}
)

type Config struct {
	PluginDir                      string
	MetricsAddress                 string
	DefaultBackupLocation          string // TODO(2.0) Deprecate defaultBackupLocation
	BackupSyncPeriod               time.Duration
	PodVolumeOperationTimeout      time.Duration
	ResourceTerminatingTimeout     time.Duration
	DefaultBackupTTL               time.Duration
	DefaultVGSLabelKey             string
	StoreValidationFrequency       time.Duration
	DefaultCSISnapshotTimeout      time.Duration
	DefaultCSISnapshotErrorTimeout time.Duration
	DefaultItemOperationTimeout    time.Duration
	ResourceTimeout                time.Duration
	RestoreResourcePriorities      types.Priorities
	DefaultVolumeSnapshotLocations flag.Map
	RestoreOnly                    bool
	DisabledControllers            []string
	ClientQPS                      float32
	ClientBurst                    int
	ClientPageSize                 int
	ProfilerAddress                string
	LogLevel                       *logging.LevelFlag
	LogFormat                      *logging.FormatFlag
	RepoMaintenanceFrequency       time.Duration
	GarbageCollectionFrequency     time.Duration
	ItemOperationSyncFrequency     time.Duration
	DefaultVolumesToFsBackup       bool
	UploaderType                   string
	MaxConcurrentK8SConnections    int
	DefaultSnapshotMoveData        bool
	DisableInformerCache           bool
	ScheduleSkipImmediately        bool
	CredentialsDirectory           string
	BackupRepoConfig               string
	RepoMaintenanceJobConfig       string
	ItemBlockWorkerCount           int
	ConcurrentBackups              int
}

func GetDefaultConfig() *Config {
	config := &Config{
		PluginDir:                      "/plugins",
		MetricsAddress:                 defaultMetricsAddress,
		DefaultBackupLocation:          "default",
		DefaultVolumeSnapshotLocations: flag.NewMap().WithKeyValueDelimiter(':'),
		BackupSyncPeriod:               defaultBackupSyncPeriod,
		DefaultBackupTTL:               defaultBackupTTL,
		DefaultVGSLabelKey:             velerov1api.DefaultVGSLabelKey,
		DefaultCSISnapshotTimeout:      defaultCSISnapshotTimeout,
		DefaultCSISnapshotErrorTimeout: defaultCSISnapshotErrorTimeout,
		DefaultItemOperationTimeout:    defaultItemOperationTimeout,
		ResourceTimeout:                resourceTimeout,
		StoreValidationFrequency:       defaultStoreValidationFrequency,
		PodVolumeOperationTimeout:      defaultPodVolumeOperationTimeout,
		RestoreResourcePriorities:      defaultRestorePriorities,
		ClientQPS:                      defaultClientQPS,
		ClientBurst:                    defaultClientBurst,
		ClientPageSize:                 defaultClientPageSize,
		ProfilerAddress:                defaultProfilerAddress,
		ResourceTerminatingTimeout:     defaultResourceTerminatingTimeout,
		LogLevel:                       logging.LogLevelFlag(logrus.InfoLevel),
		LogFormat:                      logging.NewFormatFlag(),
		DefaultVolumesToFsBackup:       podvolumeconfigs.DefaultVolumesToFsBackup,
		UploaderType:                   uploader.KopiaType,
		MaxConcurrentK8SConnections:    defaultMaxConcurrentK8SConnections,
		DefaultSnapshotMoveData:        false,
		DisableInformerCache:           defaultDisableInformerCache,
		ScheduleSkipImmediately:        false,
		CredentialsDirectory:           credentials.DefaultStoreDirectory(),
		ItemBlockWorkerCount:           DefaultItemBlockWorkerCount,
		ConcurrentBackups:              DefaultConcurrentBackups,
	}

	return config
}

func (c *Config) BindFlags(flags *pflag.FlagSet) {
	flags.Var(c.LogLevel, "log-level", fmt.Sprintf("The level at which to log. Valid values are %s.", strings.Join(c.LogLevel.AllowedValues(), ", ")))
	flags.Var(c.LogFormat, "log-format", fmt.Sprintf("The format for log output. Valid values are %s.", strings.Join(c.LogFormat.AllowedValues(), ", ")))
	flags.StringVar(&c.PluginDir, "plugin-dir", c.PluginDir, "Directory containing Velero plugins")
	flags.StringVar(&c.MetricsAddress, "metrics-address", c.MetricsAddress, "The address to expose prometheus metrics")
	flags.DurationVar(&c.BackupSyncPeriod, "backup-sync-period", c.BackupSyncPeriod, "How often to ensure all Velero backups in object storage exist as Backup API objects in the cluster. This is the default sync period if none is explicitly specified for a backup storage location.")
	flags.DurationVar(&c.PodVolumeOperationTimeout, "fs-backup-timeout", c.PodVolumeOperationTimeout, "How long pod volume file system backups/restores should be allowed to run before timing out.")
	flags.BoolVar(&c.RestoreOnly, "restore-only", c.RestoreOnly, "Run in a mode where only restores are allowed; backups, schedules, and garbage-collection are all disabled. DEPRECATED: this flag will be removed in v2.0. Use read-only backup storage locations instead.")
	flags.StringSliceVar(&c.DisabledControllers, "disable-controllers", c.DisabledControllers, fmt.Sprintf("List of controllers to disable on startup. Valid values are %s", strings.Join(DisableableControllers, ",")))
	flags.Var(&c.RestoreResourcePriorities, "restore-resource-priorities", "Desired order of resource restores, the priority list contains two parts which are split by \"-\" element. The resources before \"-\" element are restored first as high priorities, the resources after \"-\" element are restored last as low priorities, and any resource not in the list will be restored alphabetically between the high and low priorities.")
	flags.StringVar(&c.DefaultBackupLocation, "default-backup-storage-location", c.DefaultBackupLocation, "Name of the default backup storage location. DEPRECATED: this flag will be removed in v2.0. Use \"velero backup-location set --default\" instead.")
	flags.DurationVar(&c.StoreValidationFrequency, "store-validation-frequency", c.StoreValidationFrequency, "How often to verify if the storage is valid. Optional. Set this to `0s` to disable sync. Default 1 minute.")
	flags.Float32Var(&c.ClientQPS, "client-qps", c.ClientQPS, "Maximum number of requests per second by the server to the Kubernetes API once the burst limit has been reached.")
	flags.IntVar(&c.ClientBurst, "client-burst", c.ClientBurst, "Maximum number of requests by the server to the Kubernetes API in a short period of time.")
	flags.IntVar(&c.ClientPageSize, "client-page-size", c.ClientPageSize, "Page size of requests by the server to the Kubernetes API when listing objects during a backup. Set to 0 to disable paging.")
	flags.StringVar(&c.ProfilerAddress, "profiler-address", c.ProfilerAddress, "The address to expose the pprof profiler.")
	flags.DurationVar(&c.ResourceTerminatingTimeout, "terminating-resource-timeout", c.ResourceTerminatingTimeout, "How long to wait on persistent volumes and namespaces to terminate during a restore before timing out.")
	flags.DurationVar(&c.DefaultBackupTTL, "default-backup-ttl", c.DefaultBackupTTL, "How long to wait by default before backups can be garbage collected.")
	flags.StringVar(&c.DefaultVGSLabelKey, "volume-group-snapshot-label-key", c.DefaultVGSLabelKey, "Label key for grouping PVCs into VolumeGroupSnapshot. Default value is 'velero.io/volume-group'")
	flags.DurationVar(&c.RepoMaintenanceFrequency, "default-repo-maintain-frequency", c.RepoMaintenanceFrequency, "How often 'maintain' is run for backup repositories by default.")
	flags.DurationVar(&c.GarbageCollectionFrequency, "garbage-collection-frequency", c.GarbageCollectionFrequency, "How often garbage collection is run for expired backups.")
	flags.DurationVar(&c.ItemOperationSyncFrequency, "item-operation-sync-frequency", c.ItemOperationSyncFrequency, "How often to check status on backup/restore operations after backup/restore processing. Default is 10 seconds")
	flags.BoolVar(&c.DefaultVolumesToFsBackup, "default-volumes-to-fs-backup", c.DefaultVolumesToFsBackup, "Backup all volumes with pod volume file system backup by default.")
	flags.StringVar(&c.UploaderType, "uploader-type", c.UploaderType, "Type of uploader to handle the transfer of data of pod volumes")
	flags.DurationVar(&c.DefaultItemOperationTimeout, "default-item-operation-timeout", c.DefaultItemOperationTimeout, "How long to wait on asynchronous BackupItemActions and RestoreItemActions to complete before timing out. Default is 4 hours")
	flags.DurationVar(&c.DefaultCSISnapshotErrorTimeout, "default-csi-snapshot-error-timeout", c.DefaultCSISnapshotErrorTimeout, "How long to tolerate persistent errors in a CSI VolumeSnapshot or VolumeSnapshotContent status before failing the backup. Default is 10 minutes.")
	flags.DurationVar(&c.ResourceTimeout, "resource-timeout", c.ResourceTimeout, "How long to wait for resource processes which are not covered by other specific timeout parameters. Default is 10 minutes.")
	flags.IntVar(&c.MaxConcurrentK8SConnections, "max-concurrent-k8s-connections", c.MaxConcurrentK8SConnections, "Max concurrent connections number that Velero can create with kube-apiserver. Default is 30.")
	flags.BoolVar(&c.DefaultSnapshotMoveData, "default-snapshot-move-data", c.DefaultSnapshotMoveData, "Move data by default for all snapshots supporting data movement.")
	flags.BoolVar(&c.DisableInformerCache, "disable-informer-cache", c.DisableInformerCache, "Disable informer cache for Get calls on restore. With this enabled, it will speed up restore in cases where there are backup resources which already exist in the cluster, but for very large clusters this will increase velero memory usage. Default is false (don't disable).")
	flags.BoolVar(&c.ScheduleSkipImmediately, "schedule-skip-immediately", c.ScheduleSkipImmediately, "Skip the first scheduled backup immediately after creating a schedule. Default is false (don't skip).")
	flags.Var(&c.DefaultVolumeSnapshotLocations, "default-volume-snapshot-locations", "List of unique volume providers and default volume snapshot location (provider1:location-01,provider2:location-02,...)")

	flags.StringVar(
		&c.BackupRepoConfig,
		"backup-repository-configmap",
		c.BackupRepoConfig,
		"The name of ConfigMap containing backup repository configurations.",
	)
	flags.StringVar(
		&c.RepoMaintenanceJobConfig,
		"repo-maintenance-job-configmap",
		c.RepoMaintenanceJobConfig,
		"The name of ConfigMap containing repository maintenance Job configurations.",
	)
	flags.IntVar(
		&c.ItemBlockWorkerCount,
		"item-block-worker-count",
		c.ItemBlockWorkerCount,
		"Number of worker threads to process ItemBlocks. Default is one. Optional.",
	)
	flags.IntVar(
		&c.ConcurrentBackups,
		"concurrent-backups",
		c.ConcurrentBackups,
		"Number of backups to process concurrently. Default is one. Optional.",
	)
}
