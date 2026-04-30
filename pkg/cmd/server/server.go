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

package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"reflect"
	"strings"
	"time"

	logrusr "github.com/bombsimon/logrusr/v3"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	snapshotv1client "github.com/kubernetes-csi/external-snapshotter/client/v4/clientset/versioned"
	snapshotv1informers "github.com/kubernetes-csi/external-snapshotter/client/v4/informers/externalversions"
	snapshotv1listers "github.com/kubernetes-csi/external-snapshotter/client/v4/listers/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/backup"
	"github.com/vmware-tanzu/velero/pkg/buildinfo"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/signals"
	"github.com/vmware-tanzu/velero/pkg/controller"
	velerodiscovery "github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/features"
	clientset "github.com/vmware-tanzu/velero/pkg/generated/clientset/versioned"
	"github.com/vmware-tanzu/velero/pkg/itemoperationmap"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/podexec"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/repository"
	repokey "github.com/vmware-tanzu/velero/pkg/repository/keys"
	"github.com/vmware-tanzu/velero/pkg/restore"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
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
	defaultClientQPS      float32 = 20.0
	defaultClientBurst    int     = 30
	defaultClientPageSize int     = 500

	defaultProfilerAddress = "localhost:6060"

	// the default TTL for a backup
	defaultBackupTTL = 30 * 24 * time.Hour

	defaultCSISnapshotTimeout   = 10 * time.Minute
	defaultItemOperationTimeout = 4 * time.Hour

	resourceTimeout = 10 * time.Minute

	// defaultCredentialsDirectory is the path on disk where credential
	// files will be written to
	defaultCredentialsDirectory = "/tmp/credentials"

	defaultMaxConcurrentK8SConnections = 30
	defaultDisableInformerCache        = false
)

type serverConfig struct {
	// TODO(2.0) Deprecate defaultBackupLocation
	pluginDir, metricsAddress, defaultBackupLocation                        string
	backupSyncPeriod, podVolumeOperationTimeout, resourceTerminatingTimeout time.Duration
	defaultBackupTTL, storeValidationFrequency, defaultCSISnapshotTimeout   time.Duration
	defaultItemOperationTimeout, resourceTimeout                            time.Duration
	restoreResourcePriorities                                               restore.Priorities
	defaultVolumeSnapshotLocations                                          map[string]string
	restoreOnly                                                             bool
	disabledControllers                                                     []string
	clientQPS                                                               float32
	clientBurst                                                             int
	clientPageSize                                                          int
	profilerAddress                                                         string
	formatFlag                                                              *logging.FormatFlag
	repoMaintenanceFrequency                                                time.Duration
	garbageCollectionFrequency                                              time.Duration
	itemOperationSyncFrequency                                              time.Duration
	defaultVolumesToFsBackup                                                bool
	uploaderType                                                            string
	maxConcurrentK8SConnections                                             int
	defaultSnapshotMoveData                                                 bool
	disableInformerCache                                                    bool
}

func NewCommand(f client.Factory) *cobra.Command {
	var (
		volumeSnapshotLocations = flag.NewMap().WithKeyValueDelimiter(':')
		logLevelFlag            = logging.LogLevelFlag(logrus.InfoLevel)
		config                  = serverConfig{
			pluginDir:                      "/plugins",
			metricsAddress:                 defaultMetricsAddress,
			defaultBackupLocation:          "default",
			defaultVolumeSnapshotLocations: make(map[string]string),
			backupSyncPeriod:               defaultBackupSyncPeriod,
			defaultBackupTTL:               defaultBackupTTL,
			defaultCSISnapshotTimeout:      defaultCSISnapshotTimeout,
			defaultItemOperationTimeout:    defaultItemOperationTimeout,
			resourceTimeout:                resourceTimeout,
			storeValidationFrequency:       defaultStoreValidationFrequency,
			podVolumeOperationTimeout:      defaultPodVolumeOperationTimeout,
			restoreResourcePriorities:      defaultRestorePriorities,
			clientQPS:                      defaultClientQPS,
			clientBurst:                    defaultClientBurst,
			clientPageSize:                 defaultClientPageSize,
			profilerAddress:                defaultProfilerAddress,
			resourceTerminatingTimeout:     defaultResourceTerminatingTimeout,
			formatFlag:                     logging.NewFormatFlag(),
			defaultVolumesToFsBackup:       podvolume.DefaultVolumesToFsBackup,
			uploaderType:                   uploader.ResticType,
			maxConcurrentK8SConnections:    defaultMaxConcurrentK8SConnections,
			defaultSnapshotMoveData:        false,
			disableInformerCache:           defaultDisableInformerCache,
		}
	)

	var command = &cobra.Command{
		Use:    "server",
		Short:  "Run the velero server",
		Long:   "Run the velero server",
		Hidden: true,
		Run: func(c *cobra.Command, args []string) {
			// go-plugin uses log.Println to log when it's waiting for all plugin processes to complete so we need to
			// set its output to stdout.
			log.SetOutput(os.Stdout)

			logLevel := logLevelFlag.Parse()
			format := config.formatFlag.Parse()

			// Make sure we log to stdout so cloud log dashboards don't show this as an error.
			logrus.SetOutput(os.Stdout)

			// Velero's DefaultLogger logs to stdout, so all is good there.
			logger := logging.DefaultLogger(logLevel, format)

			logger.Infof("setting log-level to %s", strings.ToUpper(logLevel.String()))

			logger.Infof("Starting Velero server %s (%s)", buildinfo.Version, buildinfo.FormattedGitSHA())
			if len(features.All()) > 0 {
				logger.Infof("%d feature flags enabled %s", len(features.All()), features.All())
			} else {
				logger.Info("No feature flags enabled")
			}

			if volumeSnapshotLocations.Data() != nil {
				config.defaultVolumeSnapshotLocations = volumeSnapshotLocations.Data()
			}

			f.SetBasename(fmt.Sprintf("%s-%s", c.Parent().Name(), c.Name()))

			s, err := newServer(f, config, logger)
			cmd.CheckError(err)

			cmd.CheckError(s.run())
		},
	}

	command.Flags().Var(logLevelFlag, "log-level", fmt.Sprintf("The level at which to log. Valid values are %s.", strings.Join(logLevelFlag.AllowedValues(), ", ")))
	command.Flags().Var(config.formatFlag, "log-format", fmt.Sprintf("The format for log output. Valid values are %s.", strings.Join(config.formatFlag.AllowedValues(), ", ")))
	command.Flags().StringVar(&config.pluginDir, "plugin-dir", config.pluginDir, "Directory containing Velero plugins")
	command.Flags().StringVar(&config.metricsAddress, "metrics-address", config.metricsAddress, "The address to expose prometheus metrics")
	command.Flags().DurationVar(&config.backupSyncPeriod, "backup-sync-period", config.backupSyncPeriod, "How often to ensure all Velero backups in object storage exist as Backup API objects in the cluster. This is the default sync period if none is explicitly specified for a backup storage location.")
	command.Flags().DurationVar(&config.podVolumeOperationTimeout, "fs-backup-timeout", config.podVolumeOperationTimeout, "How long pod volume file system backups/restores should be allowed to run before timing out.")
	command.Flags().BoolVar(&config.restoreOnly, "restore-only", config.restoreOnly, "Run in a mode where only restores are allowed; backups, schedules, and garbage-collection are all disabled. DEPRECATED: this flag will be removed in v2.0. Use read-only backup storage locations instead.")
	command.Flags().StringSliceVar(&config.disabledControllers, "disable-controllers", config.disabledControllers, fmt.Sprintf("List of controllers to disable on startup. Valid values are %s", strings.Join(controller.DisableableControllers, ",")))
	command.Flags().Var(&config.restoreResourcePriorities, "restore-resource-priorities", "Desired order of resource restores, the priority list contains two parts which are split by \"-\" element. The resources before \"-\" element are restored first as high priorities, the resources after \"-\" element are restored last as low priorities, and any resource not in the list will be restored alphabetically between the high and low priorities.")
	command.Flags().StringVar(&config.defaultBackupLocation, "default-backup-storage-location", config.defaultBackupLocation, "Name of the default backup storage location. DEPRECATED: this flag will be removed in v2.0. Use \"velero backup-location set --default\" instead.")
	command.Flags().DurationVar(&config.storeValidationFrequency, "store-validation-frequency", config.storeValidationFrequency, "How often to verify if the storage is valid. Optional. Set this to `0s` to disable sync. Default 1 minute.")
	command.Flags().Var(&volumeSnapshotLocations, "default-volume-snapshot-locations", "List of unique volume providers and default volume snapshot location (provider1:location-01,provider2:location-02,...)")
	command.Flags().Float32Var(&config.clientQPS, "client-qps", config.clientQPS, "Maximum number of requests per second by the server to the Kubernetes API once the burst limit has been reached.")
	command.Flags().IntVar(&config.clientBurst, "client-burst", config.clientBurst, "Maximum number of requests by the server to the Kubernetes API in a short period of time.")
	command.Flags().IntVar(&config.clientPageSize, "client-page-size", config.clientPageSize, "Page size of requests by the server to the Kubernetes API when listing objects during a backup. Set to 0 to disable paging.")
	command.Flags().StringVar(&config.profilerAddress, "profiler-address", config.profilerAddress, "The address to expose the pprof profiler.")
	command.Flags().DurationVar(&config.resourceTerminatingTimeout, "terminating-resource-timeout", config.resourceTerminatingTimeout, "How long to wait on persistent volumes and namespaces to terminate during a restore before timing out.")
	command.Flags().DurationVar(&config.defaultBackupTTL, "default-backup-ttl", config.defaultBackupTTL, "How long to wait by default before backups can be garbage collected.")
	command.Flags().DurationVar(&config.repoMaintenanceFrequency, "default-repo-maintain-frequency", config.repoMaintenanceFrequency, "How often 'maintain' is run for backup repositories by default.")
	command.Flags().DurationVar(&config.garbageCollectionFrequency, "garbage-collection-frequency", config.garbageCollectionFrequency, "How often garbage collection is run for expired backups.")
	command.Flags().DurationVar(&config.itemOperationSyncFrequency, "item-operation-sync-frequency", config.itemOperationSyncFrequency, "How often to check status on backup/restore operations after backup/restore processing. Default is 10 seconds")
	command.Flags().BoolVar(&config.defaultVolumesToFsBackup, "default-volumes-to-fs-backup", config.defaultVolumesToFsBackup, "Backup all volumes with pod volume file system backup by default.")
	command.Flags().StringVar(&config.uploaderType, "uploader-type", config.uploaderType, "Type of uploader to handle the transfer of data of pod volumes")
	command.Flags().DurationVar(&config.defaultItemOperationTimeout, "default-item-operation-timeout", config.defaultItemOperationTimeout, "How long to wait on asynchronous BackupItemActions and RestoreItemActions to complete before timing out. Default is 4 hours")
	command.Flags().DurationVar(&config.resourceTimeout, "resource-timeout", config.resourceTimeout, "How long to wait for resource processes which are not covered by other specific timeout parameters. Default is 10 minutes.")
	command.Flags().IntVar(&config.maxConcurrentK8SConnections, "max-concurrent-k8s-connections", config.maxConcurrentK8SConnections, "Max concurrent connections number that Velero can create with kube-apiserver. Default is 30.")
	command.Flags().BoolVar(&config.defaultSnapshotMoveData, "default-snapshot-move-data", config.defaultSnapshotMoveData, "Move data by default for all snapshots supporting data movement.")
	command.Flags().BoolVar(&config.disableInformerCache, "disable-informer-cache", config.disableInformerCache, "Disable informer cache for Get calls on restore. WIth this enabled, it will speed up restore in cases where there are backup resources which already exist in the cluster, but for very large clusters this will increase velero memory usage. Default is false (don't disable).")

	return command
}

type server struct {
	namespace             string
	metricsAddress        string
	kubeClientConfig      *rest.Config
	kubeClient            kubernetes.Interface
	veleroClient          clientset.Interface
	discoveryClient       discovery.DiscoveryInterface
	discoveryHelper       velerodiscovery.Helper
	dynamicClient         dynamic.Interface
	csiSnapshotClient     *snapshotv1client.Clientset
	csiSnapshotLister     snapshotv1listers.VolumeSnapshotLister
	ctx                   context.Context
	cancelFunc            context.CancelFunc
	logger                logrus.FieldLogger
	logLevel              logrus.Level
	pluginRegistry        process.Registry
	repoManager           repository.Manager
	repoLocker            *repository.RepoLocker
	repoEnsurer           *repository.Ensurer
	metrics               *metrics.ServerMetrics
	config                serverConfig
	mgr                   manager.Manager
	credentialFileStore   credentials.FileStore
	credentialSecretStore credentials.SecretStore
}

func newServer(f client.Factory, config serverConfig, logger *logrus.Logger) (*server, error) {
	if err := uploader.ValidateUploaderType(config.uploaderType); err != nil {
		return nil, err
	}

	if config.clientQPS < 0.0 {
		return nil, errors.New("client-qps must be positive")
	}
	f.SetClientQPS(config.clientQPS)

	if config.clientBurst <= 0 {
		return nil, errors.New("client-burst must be positive")
	}
	f.SetClientBurst(config.clientBurst)

	if config.clientPageSize < 0 {
		return nil, errors.New("client-page-size must not be negative")
	}

	kubeClient, err := f.KubeClient()
	if err != nil {
		return nil, err
	}

	veleroClient, err := f.Client()
	if err != nil {
		return nil, err
	}

	dynamicClient, err := f.DynamicClient()
	if err != nil {
		return nil, err
	}

	pluginRegistry := process.NewRegistry(config.pluginDir, logger, logger.Level)
	if err := pluginRegistry.DiscoverPlugins(); err != nil {
		return nil, err
	}

	// cancelFunc is not deferred here because if it was, then ctx would immediately
	// be canceled once this function exited, making it useless to any informers using later.
	// That, in turn, causes the velero server to halt when the first informer tries to use it.
	// Therefore, we must explicitly call it on the error paths in this function.
	ctx, cancelFunc := context.WithCancel(context.Background())

	clientConfig, err := f.ClientConfig()
	if err != nil {
		cancelFunc()
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := velerov1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}
	if err := velerov2alpha1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}
	if err := corev1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}
	if err := snapshotv1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}

	ctrl.SetLogger(logrusr.New(logger))

	mgr, err := ctrl.NewManager(clientConfig, ctrl.Options{
		Scheme:    scheme,
		Namespace: f.Namespace(),
	})
	if err != nil {
		cancelFunc()
		return nil, err
	}

	credentialFileStore, err := credentials.NewNamespacedFileStore(
		mgr.GetClient(),
		f.Namespace(),
		defaultCredentialsDirectory,
		filesystem.NewFileSystem(),
	)
	if err != nil {
		cancelFunc()
		return nil, err
	}

	credentialSecretStore, err := credentials.NewNamespacedSecretStore(mgr.GetClient(), f.Namespace())
	if err != nil {
		cancelFunc()
		return nil, err
	}

	s := &server{
		namespace:             f.Namespace(),
		metricsAddress:        config.metricsAddress,
		kubeClientConfig:      clientConfig,
		kubeClient:            kubeClient,
		veleroClient:          veleroClient,
		discoveryClient:       veleroClient.Discovery(),
		dynamicClient:         dynamicClient,
		ctx:                   ctx,
		cancelFunc:            cancelFunc,
		logger:                logger,
		logLevel:              logger.Level,
		pluginRegistry:        pluginRegistry,
		config:                config,
		mgr:                   mgr,
		credentialFileStore:   credentialFileStore,
		credentialSecretStore: credentialSecretStore,
	}

	// Setup CSI snapshot client and lister
	var csiSnapClient *snapshotv1client.Clientset
	if features.IsEnabled(velerov1api.CSIFeatureFlag) {
		csiSnapClient, err = snapshotv1client.NewForConfig(clientConfig)
		if err != nil {
			cancelFunc()
			return nil, err
		}
		s.csiSnapshotClient = csiSnapClient

		s.csiSnapshotLister, err = s.getCSIVolumeSnapshotListers()
		if err != nil {
			cancelFunc()
			return nil, err
		}
	}

	return s, nil
}

func (s *server) run() error {
	signals.CancelOnShutdown(s.cancelFunc, s.logger)

	if s.config.profilerAddress != "" {
		go s.runProfiler()
	}

	// Since s.namespace, which specifies where backups/restores/schedules/etc. should live,
	// *could* be different from the namespace where the Velero server pod runs, check to make
	// sure it exists, and fail fast if it doesn't.
	if err := s.namespaceExists(s.namespace); err != nil {
		return err
	}

	if err := s.initDiscoveryHelper(); err != nil {
		return err
	}

	if err := s.veleroResourcesExist(); err != nil {
		return err
	}

	s.checkNodeAgent()

	if err := s.initRepoManager(); err != nil {
		return err
	}

	markInProgressCRsFailed(s.ctx, s.mgr.GetConfig(), s.mgr.GetScheme(), s.namespace, s.logger)

	if err := s.runControllers(s.config.defaultVolumeSnapshotLocations); err != nil {
		return err
	}

	return nil
}

// namespaceExists returns nil if namespace can be successfully
// gotten from the Kubernetes API, or an error otherwise.
func (s *server) namespaceExists(namespace string) error {
	s.logger.WithField("namespace", namespace).Info("Checking existence of namespace.")

	if _, err := s.kubeClient.CoreV1().Namespaces().Get(s.ctx, namespace, metav1.GetOptions{}); err != nil {
		return errors.WithStack(err)
	}

	s.logger.WithField("namespace", namespace).Info("Namespace exists")
	return nil
}

// initDiscoveryHelper instantiates the server's discovery helper and spawns a
// goroutine to call Refresh() every 5 minutes.
func (s *server) initDiscoveryHelper() error {
	discoveryHelper, err := velerodiscovery.NewHelper(s.discoveryClient, s.logger)
	if err != nil {
		return err
	}
	s.discoveryHelper = discoveryHelper

	go wait.Until(
		func() {
			if err := discoveryHelper.Refresh(); err != nil {
				s.logger.WithError(err).Error("Error refreshing discovery")
			}
		},
		5*time.Minute,
		s.ctx.Done(),
	)

	return nil
}

// veleroResourcesExist checks for the existence of each Velero CRD via discovery
// and returns an error if any of them don't exist.
func (s *server) veleroResourcesExist() error {
	s.logger.Info("Checking existence of Velero custom resource definitions")

	// add more group versions whenever available
	gvResources := map[string]sets.String{
		velerov1api.SchemeGroupVersion.String():       velerov1api.CustomResourceKinds(),
		velerov2alpha1api.SchemeGroupVersion.String(): velerov2alpha1api.CustomResourceKinds(),
	}

	for _, lst := range s.discoveryHelper.Resources() {
		if resources, found := gvResources[lst.GroupVersion]; found {
			for _, resource := range lst.APIResources {
				s.logger.WithField("kind", resource.Kind).Info("Found custom resource")
				resources.Delete(resource.Kind)
			}
		}
	}

	var errs []error
	for gv, resources := range gvResources {
		for kind := range resources {
			errs = append(errs, errors.Errorf("custom resource %s not found in Velero API group %s", kind, gv))
		}
	}

	if len(errs) > 0 {
		errs = append(errs, errors.New("Velero custom resources not found - apply config/crd/v1/bases/*.yaml,config/crd/v2alpha1/bases*.yaml, to update the custom resource definitions"))
		return kubeerrs.NewAggregate(errs)
	}

	s.logger.Info("All Velero custom resource definitions exist")
	return nil
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
  - Secrets and config maps go before pods or controllers so they can be mounted
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
*/
var defaultRestorePriorities = restore.Priorities{
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
		"serviceaccounts",
		"secrets",
		"configmaps",
		"limitranges",
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
	},
}

func (s *server) checkNodeAgent() {
	// warn if node agent does not exist
	if err := nodeagent.IsRunning(s.ctx, s.kubeClient, s.namespace); err == nodeagent.ErrDaemonSetNotFound {
		s.logger.Warn("Velero node agent not found; pod volume backups/restores will not work until it's created")
	} else if err != nil {
		s.logger.WithError(errors.WithStack(err)).Warn("Error checking for existence of velero node agent")
	}
}

func (s *server) initRepoManager() error {
	// ensure the repo key secret is set up
	if err := repokey.EnsureCommonRepositoryKey(s.kubeClient.CoreV1(), s.namespace); err != nil {
		return err
	}

	s.repoLocker = repository.NewRepoLocker()
	s.repoEnsurer = repository.NewEnsurer(s.mgr.GetClient(), s.logger, s.config.resourceTimeout)

	s.repoManager = repository.NewManager(s.namespace, s.mgr.GetClient(), s.repoLocker, s.repoEnsurer, s.credentialFileStore, s.credentialSecretStore, s.logger)

	return nil
}

func (s *server) getCSIVolumeSnapshotListers() (vsLister snapshotv1listers.VolumeSnapshotLister, err error) {
	_, err = s.discoveryClient.ServerResourcesForGroupVersion(snapshotv1api.SchemeGroupVersion.String())
	switch {
	case apierrors.IsNotFound(err):
		// CSI is enabled, but the required CRDs aren't installed, so halt.
		s.logger.Warnf("The '%s' feature flag was specified, but CSI API group [%s] was not found.", velerov1api.CSIFeatureFlag, snapshotv1api.SchemeGroupVersion.String())
		err = nil
	case err == nil:
		wrapper := NewCSIInformerFactoryWrapper(s.csiSnapshotClient)

		s.logger.Debug("Creating CSI listers")
		// Access the wrapped factory directly here since we've already done the feature flag check above to know it's safe.
		vsLister = wrapper.factory.Snapshot().V1().VolumeSnapshots().Lister()

		// start the informers & and wait for the caches to sync
		wrapper.Start(s.ctx.Done())
		s.logger.Info("Waiting for informer caches to sync")
		csiCacheSyncResults := wrapper.WaitForCacheSync(s.ctx.Done())
		s.logger.Info("Done waiting for informer caches to sync")

		for informer, synced := range csiCacheSyncResults {
			if !synced {
				err = errors.Errorf("cache was not synced for informer %v", informer)
				return vsLister, err
			}
			s.logger.WithField("informer", informer).Info("Informer cache synced")
		}
	case err != nil:
		s.logger.Errorf("fail to find snapshot v1 schema: %s", err)
	}

	return vsLister, err
}

func (s *server) runControllers(defaultVolumeSnapshotLocations map[string]string) error {
	s.logger.Info("Starting controllers")

	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		s.logger.Infof("Starting metric server at address [%s]", s.metricsAddress)
		server := &http.Server{
			Addr:              s.metricsAddress,
			Handler:           metricsMux,
			ReadHeaderTimeout: 3 * time.Second,
		}
		if err := server.ListenAndServe(); err != nil {
			s.logger.Fatalf("Failed to start metric server at [%s]: %v", s.metricsAddress, err)
		}
	}()
	s.metrics = metrics.NewServerMetrics()
	s.metrics.RegisterAllMetrics()
	// Initialize manual backup metrics
	s.metrics.InitSchedule("")

	newPluginManager := func(logger logrus.FieldLogger) clientmgmt.Manager {
		return clientmgmt.NewManager(logger, s.logLevel, s.pluginRegistry)
	}

	backupStoreGetter := persistence.NewObjectBackupStoreGetter(s.credentialFileStore)

	backupTracker := controller.NewBackupTracker()

	// By far, PodVolumeBackup, PodVolumeRestore, BackupStorageLocation controllers
	// are not included in --disable-controllers list.
	// This is because of PVB and PVR are used by node agent DaemonSet,
	// and BSL controller is mandatory for Velero to work.
	// Note: all runtime type controllers that can be disabled are grouped separately, below:
	enabledRuntimeControllers := map[string]struct{}{
		controller.Backup:              {},
		controller.BackupDeletion:      {},
		controller.BackupFinalizer:     {},
		controller.BackupOperations:    {},
		controller.BackupRepo:          {},
		controller.BackupSync:          {},
		controller.DownloadRequest:     {},
		controller.GarbageCollection:   {},
		controller.Restore:             {},
		controller.RestoreOperations:   {},
		controller.Schedule:            {},
		controller.ServerStatusRequest: {},
	}

	if s.config.restoreOnly {
		s.logger.Info("Restore only mode - not starting the backup, schedule, delete-backup, or GC controllers")
		s.config.disabledControllers = append(s.config.disabledControllers,
			controller.Backup,
			controller.BackupDeletion,
			controller.BackupFinalizer,
			controller.BackupOperations,
			controller.GarbageCollection,
			controller.Schedule,
		)
	}

	// Remove disabled controllers so they are not initialized. If a match is not found we want
	// to halt the system so the user knows this operation was not possible.
	if err := removeControllers(s.config.disabledControllers, enabledRuntimeControllers, s.logger); err != nil {
		log.Fatal(err, "unable to disable a controller")
	}

	// Enable BSL controller. No need to check whether it's enabled or not.
	bslr := controller.NewBackupStorageLocationReconciler(
		s.ctx,
		s.mgr.GetClient(),
		s.mgr.GetScheme(),
		storage.DefaultBackupLocationInfo{
			StorageLocation:           s.config.defaultBackupLocation,
			ServerValidationFrequency: s.config.storeValidationFrequency,
		},
		newPluginManager,
		backupStoreGetter,
		s.logger,
	)
	if err := bslr.SetupWithManager(s.mgr); err != nil {
		s.logger.Fatal(err, "unable to create controller", "controller", controller.BackupStorageLocation)
	}

	if _, ok := enabledRuntimeControllers[controller.Backup]; ok {
		backupper, err := backup.NewKubernetesBackupper(
			s.mgr.GetClient(),
			s.discoveryHelper,
			client.NewDynamicFactory(s.dynamicClient),
			podexec.NewPodCommandExecutor(s.kubeClientConfig, s.kubeClient.CoreV1().RESTClient()),
			podvolume.NewBackupperFactory(
				s.repoLocker,
				s.repoEnsurer,
				s.veleroClient,
				s.kubeClient.CoreV1(),
				s.kubeClient.CoreV1(),
				s.kubeClient.CoreV1(),
				s.logger,
			),
			s.config.podVolumeOperationTimeout,
			s.config.defaultVolumesToFsBackup,
			s.config.clientPageSize,
			s.config.uploaderType,
		)
		cmd.CheckError(err)
		if err := controller.NewBackupReconciler(
			s.ctx,
			s.discoveryHelper,
			backupper,
			s.logger,
			s.logLevel,
			newPluginManager,
			backupTracker,
			s.mgr.GetClient(),
			s.config.defaultBackupLocation,
			s.config.defaultVolumesToFsBackup,
			s.config.defaultBackupTTL,
			s.config.defaultCSISnapshotTimeout,
			s.config.resourceTimeout,
			s.config.defaultItemOperationTimeout,
			defaultVolumeSnapshotLocations,
			s.metrics,
			backupStoreGetter,
			s.config.formatFlag.Parse(),
			s.csiSnapshotLister,
			s.credentialFileStore,
			s.config.maxConcurrentK8SConnections,
			s.config.defaultSnapshotMoveData,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.Backup)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.BackupDeletion]; ok {
		if err := controller.NewBackupDeletionReconciler(
			s.logger,
			s.mgr.GetClient(),
			backupTracker,
			s.repoManager,
			s.metrics,
			s.discoveryHelper,
			newPluginManager,
			backupStoreGetter,
			s.credentialFileStore,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.BackupDeletion)
		}
	}

	backupOpsMap := itemoperationmap.NewBackupItemOperationsMap()
	if _, ok := enabledRuntimeControllers[controller.BackupOperations]; ok {
		r := controller.NewBackupOperationsReconciler(
			s.logger,
			s.mgr.GetClient(),
			s.config.itemOperationSyncFrequency,
			newPluginManager,
			backupStoreGetter,
			s.metrics,
			backupOpsMap,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.BackupOperations)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.BackupFinalizer]; ok {
		backupper, err := backup.NewKubernetesBackupper(
			s.mgr.GetClient(),
			s.discoveryHelper,
			client.NewDynamicFactory(s.dynamicClient),
			podexec.NewPodCommandExecutor(s.kubeClientConfig, s.kubeClient.CoreV1().RESTClient()),
			podvolume.NewBackupperFactory(
				s.repoLocker,
				s.repoEnsurer,
				s.veleroClient,
				s.kubeClient.CoreV1(),
				s.kubeClient.CoreV1(),
				s.kubeClient.CoreV1(),
				s.logger,
			),
			s.config.podVolumeOperationTimeout,
			s.config.defaultVolumesToFsBackup,
			s.config.clientPageSize,
			s.config.uploaderType,
		)
		cmd.CheckError(err)
		r := controller.NewBackupFinalizerReconciler(
			s.mgr.GetClient(),
			clock.RealClock{},
			backupper,
			newPluginManager,
			backupTracker,
			backupStoreGetter,
			s.logger,
			s.metrics,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.BackupFinalizer)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.BackupRepo]; ok {
		if err := controller.NewBackupRepoReconciler(s.namespace, s.logger, s.mgr.GetClient(), s.config.repoMaintenanceFrequency, s.repoManager).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.BackupRepo)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.BackupSync]; ok {
		syncPeriod := s.config.backupSyncPeriod
		if syncPeriod <= 0 {
			syncPeriod = time.Minute
		}

		backupSyncReconciler := controller.NewBackupSyncReconciler(
			s.mgr.GetClient(),
			s.namespace,
			syncPeriod,
			newPluginManager,
			backupStoreGetter,
			s.logger,
		)
		if err := backupSyncReconciler.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, " unable to create controller ", "controller ", controller.BackupSync)
		}
	}

	restoreOpsMap := itemoperationmap.NewRestoreItemOperationsMap()
	if _, ok := enabledRuntimeControllers[controller.RestoreOperations]; ok {
		r := controller.NewRestoreOperationsReconciler(
			s.logger,
			s.namespace,
			s.mgr.GetClient(),
			s.config.itemOperationSyncFrequency,
			newPluginManager,
			backupStoreGetter,
			s.metrics,
			restoreOpsMap,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.RestoreOperations)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.DownloadRequest]; ok {
		r := controller.NewDownloadRequestReconciler(
			s.mgr.GetClient(),
			clock.RealClock{},
			newPluginManager,
			backupStoreGetter,
			s.logger,
			backupOpsMap,
			restoreOpsMap,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.DownloadRequest)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.GarbageCollection]; ok {
		r := controller.NewGCReconciler(s.logger, s.mgr.GetClient(), s.config.garbageCollectionFrequency)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.GarbageCollection)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.Restore]; ok {
		restorer, err := restore.NewKubernetesRestorer(
			s.discoveryHelper,
			client.NewDynamicFactory(s.dynamicClient),
			s.config.restoreResourcePriorities,
			s.kubeClient.CoreV1().Namespaces(),
			podvolume.NewRestorerFactory(
				s.repoLocker,
				s.repoEnsurer,
				s.veleroClient,
				s.kubeClient.CoreV1(),
				s.kubeClient.CoreV1(),
				s.kubeClient,
				s.logger,
			),
			s.config.podVolumeOperationTimeout,
			s.config.resourceTerminatingTimeout,
			s.config.resourceTimeout,
			s.logger,
			podexec.NewPodCommandExecutor(s.kubeClientConfig, s.kubeClient.CoreV1().RESTClient()),
			s.kubeClient.CoreV1().RESTClient(),
			s.credentialFileStore,
			s.mgr.GetClient(),
		)

		cmd.CheckError(err)

		r := controller.NewRestoreReconciler(
			s.ctx,
			s.namespace,
			restorer,
			s.mgr.GetClient(),
			s.logger,
			s.logLevel,
			newPluginManager,
			backupStoreGetter,
			s.metrics,
			s.config.formatFlag.Parse(),
			s.config.defaultItemOperationTimeout,
			s.config.disableInformerCache,
		)

		if err = r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "fail to create controller", "controller", controller.Restore)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.Schedule]; ok {
		if err := controller.NewScheduleReconciler(s.namespace, s.logger, s.mgr.GetClient(), s.metrics).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.Schedule)
		}
	}

	if _, ok := enabledRuntimeControllers[controller.ServerStatusRequest]; ok {
		if err := controller.NewServerStatusRequestReconciler(
			s.ctx,
			s.mgr.GetClient(),
			s.pluginRegistry,
			clock.RealClock{},
			s.logger,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", controller.ServerStatusRequest)
		}
	}

	s.logger.Info("Server starting...")

	if err := s.mgr.Start(s.ctx); err != nil {
		s.logger.Fatal("Problem starting manager", err)
	}
	return nil
}

// removeControllers will remove any controller listed to be disabled from the list
// of controllers to be initialized. It will check the runtime controllers. If a match
// wasn't found and it returns an error.
func removeControllers(disabledControllers []string, enabledRuntimeControllers map[string]struct{}, logger logrus.FieldLogger) error {
	for _, controllerName := range disabledControllers {
		if _, ok := enabledRuntimeControllers[controllerName]; ok {
			logger.Infof("Disabling controller: %s", controllerName)
			delete(enabledRuntimeControllers, controllerName)
		} else {
			msg := fmt.Sprintf("Invalid value for --disable-controllers flag provided: %s. Valid values are: %s", controllerName, strings.Join(controller.DisableableControllers, ","))
			return errors.New(msg)
		}
	}
	return nil
}

func (s *server) runProfiler() {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Addr:              s.config.profilerAddress,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		s.logger.WithError(errors.WithStack(err)).Error("error running profiler http server")
	}
}

// CSIInformerFactoryWrapper is a proxy around the CSI SharedInformerFactory that checks the CSI feature flag before performing operations.
type CSIInformerFactoryWrapper struct {
	factory snapshotv1informers.SharedInformerFactory
}

func NewCSIInformerFactoryWrapper(c snapshotv1client.Interface) *CSIInformerFactoryWrapper {
	// If no namespace is specified, all namespaces are watched.
	// This is desirable for VolumeSnapshots, as we want to query for all VolumeSnapshots across all namespaces using this informer
	w := &CSIInformerFactoryWrapper{}

	if features.IsEnabled(velerov1api.CSIFeatureFlag) {
		w.factory = snapshotv1informers.NewSharedInformerFactoryWithOptions(c, 0)
	}
	return w
}

// Start proxies the Start call to the CSI SharedInformerFactory.
func (w *CSIInformerFactoryWrapper) Start(stopCh <-chan struct{}) {
	if features.IsEnabled(velerov1api.CSIFeatureFlag) {
		w.factory.Start(stopCh)
	}
}

// WaitForCacheSync proxies the WaitForCacheSync call to the CSI SharedInformerFactory.
func (w *CSIInformerFactoryWrapper) WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool {
	if features.IsEnabled(velerov1api.CSIFeatureFlag) {
		return w.factory.WaitForCacheSync(stopCh)
	}
	return nil
}

// if there is a restarting during the reconciling of backups/restores/etc, these CRs may be stuck in progress status
// markInProgressCRsFailed tries to mark the in progress CRs as failed when starting the server to avoid the issue
func markInProgressCRsFailed(ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme, namespace string, log logrus.FieldLogger) {
	// the function is called before starting the controller manager, the embedded client isn't ready to use, so create a new one here
	client, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to create client")
		return
	}

	markInProgressBackupsFailed(ctx, client, namespace, log)

	markInProgressRestoresFailed(ctx, client, namespace, log)
}

func markInProgressBackupsFailed(ctx context.Context, client ctrlclient.Client, namespace string, log logrus.FieldLogger) {
	backups := &velerov1api.BackupList{}
	if err := client.List(ctx, backups, &ctrlclient.MatchingFields{"metadata.namespace": namespace}); err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to list backups")
		return
	}

	for i, backup := range backups.Items {
		if backup.Status.Phase != velerov1api.BackupPhaseInProgress {
			log.Debugf("the status of backup %q is %q, skip", backup.GetName(), backup.Status.Phase)
			continue
		}
		updated := backup.DeepCopy()
		updated.Status.Phase = velerov1api.BackupPhaseFailed
		updated.Status.FailureReason = fmt.Sprintf("found a backup with status %q during the server starting, mark it as %q", backup.Status.Phase, updated.Status.Phase)
		updated.Status.CompletionTimestamp = &metav1.Time{Time: time.Now()}
		if err := client.Patch(ctx, updated, ctrlclient.MergeFrom(&backups.Items[i])); err != nil {
			log.WithError(errors.WithStack(err)).Errorf("failed to patch backup %q", backup.GetName())
			continue
		}
		log.WithField("backup", backup.GetName()).Warn(updated.Status.FailureReason)
		markDataUploadsCancel(ctx, client, backup, log)
	}
}

func markInProgressRestoresFailed(ctx context.Context, client ctrlclient.Client, namespace string, log logrus.FieldLogger) {
	restores := &velerov1api.RestoreList{}
	if err := client.List(ctx, restores, &ctrlclient.MatchingFields{"metadata.namespace": namespace}); err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to list restores")
		return
	}
	for i, restore := range restores.Items {
		if restore.Status.Phase != velerov1api.RestorePhaseInProgress {
			log.Debugf("the status of restore %q is %q, skip", restore.GetName(), restore.Status.Phase)
			continue
		}
		updated := restore.DeepCopy()
		updated.Status.Phase = velerov1api.RestorePhaseFailed
		updated.Status.FailureReason = fmt.Sprintf("found a restore with status %q during the server starting, mark it as %q", restore.Status.Phase, updated.Status.Phase)
		updated.Status.CompletionTimestamp = &metav1.Time{Time: time.Now()}
		if err := client.Patch(ctx, updated, ctrlclient.MergeFrom(&restores.Items[i])); err != nil {
			log.WithError(errors.WithStack(err)).Errorf("failed to patch restore %q", restore.GetName())
			continue
		}
		log.WithField("restore", restore.GetName()).Warn(updated.Status.FailureReason)
		markDataDownloadsCancel(ctx, client, restore, log)
	}
}

func markDataUploadsCancel(ctx context.Context, client ctrlclient.Client, backup velerov1api.Backup, log logrus.FieldLogger) {
	dataUploads := &velerov2alpha1api.DataUploadList{}

	if err := client.List(ctx, dataUploads, &ctrlclient.MatchingFields{"metadata.namespace": backup.GetNamespace()}, &ctrlclient.MatchingLabels{velerov1api.BackupUIDLabel: string(backup.GetUID())}); err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to list dataUploads")
		return
	}

	for i := range dataUploads.Items {
		du := dataUploads.Items[i]
		if du.Status.Phase == velerov2alpha1api.DataUploadPhaseAccepted ||
			du.Status.Phase == velerov2alpha1api.DataUploadPhasePrepared ||
			du.Status.Phase == velerov2alpha1api.DataUploadPhaseInProgress ||
			du.Status.Phase == velerov2alpha1api.DataUploadPhaseNew ||
			du.Status.Phase == "" {
			err := controller.UpdateDataUploadWithRetry(ctx, client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log.WithField("dataupload", du.Name),
				func(dataUpload *velerov2alpha1api.DataUpload) {
					dataUpload.Spec.Cancel = true
					dataUpload.Status.Message = fmt.Sprintf("found a dataupload with status %q during the velero server starting, mark it as cancel", du.Status.Phase)
				})

			if err != nil {
				log.WithError(errors.WithStack(err)).Errorf("failed to mark dataupload %q cancel", du.GetName())
				continue
			}
			log.WithField("dataupload", du.GetName()).Warn(du.Status.Message)
		}
	}
}

func markDataDownloadsCancel(ctx context.Context, client ctrlclient.Client, restore velerov1api.Restore, log logrus.FieldLogger) {
	dataDownloads := &velerov2alpha1api.DataDownloadList{}

	if err := client.List(ctx, dataDownloads, &ctrlclient.MatchingFields{"metadata.namespace": restore.GetNamespace()}, &ctrlclient.MatchingLabels{velerov1api.RestoreUIDLabel: string(restore.GetUID())}); err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to list dataDownloads")
		return
	}

	for i := range dataDownloads.Items {
		dd := dataDownloads.Items[i]
		if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseAccepted ||
			dd.Status.Phase == velerov2alpha1api.DataDownloadPhasePrepared ||
			dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseInProgress ||
			dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseNew ||
			dd.Status.Phase == "" {
			err := controller.UpdateDataDownloadWithRetry(ctx, client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log.WithField("datadownload", dd.Name),
				func(dataDownload *velerov2alpha1api.DataDownload) {
					dataDownload.Spec.Cancel = true
					dataDownload.Status.Message = fmt.Sprintf("found a datadownload with status %q during the velero server starting, mark it as cancel", dd.Status.Phase)
				})

			if err != nil {
				log.WithError(errors.WithStack(err)).Errorf("failed to mark dataupload %q cancel", dd.GetName())
				continue
			}
			log.WithField("datadownload", dd.GetName()).Warn(dd.Status.Message)
		}
	}
}
