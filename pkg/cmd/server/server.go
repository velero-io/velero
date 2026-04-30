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
	"strings"
	"time"

	logrusr "github.com/bombsimon/logrusr/v3"
	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	appsv1api "k8s.io/api/apps/v1"
	batchv1api "k8s.io/api/batch/v1"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/hook"
	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/backup"
	"github.com/vmware-tanzu/velero/pkg/buildinfo"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/server/config"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/signals"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/controller"
	velerodiscovery "github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/features"
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
	repomanager "github.com/vmware-tanzu/velero/pkg/repository/manager"
	"github.com/vmware-tanzu/velero/pkg/restore"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

func NewCommand(f client.Factory) *cobra.Command {
	config := config.GetDefaultConfig()

	var command = &cobra.Command{
		Use:    "server",
		Short:  "Run the velero server",
		Long:   "Run the velero server",
		Hidden: true,
		Run: func(c *cobra.Command, args []string) {
			// go-plugin uses log.Println to log when it's waiting for all plugin processes to complete so we need to
			// set its output to stdout.
			log.SetOutput(os.Stdout)

			logLevel := config.LogLevel.Parse()
			format := config.LogFormat.Parse()

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

			f.SetBasename(fmt.Sprintf("%s-%s", c.Parent().Name(), c.Name()))

			s, err := newServer(f, config, logger)
			cmd.CheckError(err)

			cmd.CheckError(s.run())
		},
	}

	config.BindFlags(command.Flags())

	return command
}

type server struct {
	namespace        string
	metricsAddress   string
	kubeClientConfig *rest.Config
	kubeClient       kubernetes.Interface
	discoveryClient  discovery.AggregatedDiscoveryInterface
	discoveryHelper  velerodiscovery.Helper
	dynamicClient    dynamic.Interface
	// controller-runtime client. the difference from the controller-manager's client
	// is that the controller-manager's client is limited to list namespaced-scoped
	// resources in the namespace where Velero is installed, or the cluster-scoped
	// resources. The crClient doesn't have the limitation.
	crClient              ctrlclient.Client
	ctx                   context.Context
	cancelFunc            context.CancelFunc
	logger                logrus.FieldLogger
	logLevel              logrus.Level
	pluginRegistry        process.Registry
	repoManager           repomanager.Manager
	repoLocker            *repository.RepoLocker
	repoEnsurer           *repository.Ensurer
	metrics               *metrics.ServerMetrics
	config                *config.Config
	mgr                   manager.Manager
	credentialFileStore   credentials.FileStore
	credentialSecretStore credentials.SecretStore
}

func newServer(f client.Factory, config *config.Config, logger *logrus.Logger) (*server, error) {
	if msg, err := uploader.ValidateUploaderType(config.UploaderType); err != nil {
		return nil, err
	} else if msg != "" {
		logger.Warn(msg)
	}

	if config.ClientQPS < 0.0 {
		return nil, errors.New("client-qps must be positive")
	}
	f.SetClientQPS(config.ClientQPS)

	if config.ClientBurst <= 0 {
		return nil, errors.New("client-burst must be positive")
	}
	f.SetClientBurst(config.ClientBurst)

	if config.ClientPageSize < 0 {
		return nil, errors.New("client-page-size must not be negative")
	}

	kubeClient, err := f.KubeClient()
	if err != nil {
		return nil, err
	}

	dynamicClient, err := f.DynamicClient()
	if err != nil {
		return nil, err
	}

	crClient, err := f.KubebuilderClient()
	if err != nil {
		return nil, err
	}

	pluginRegistry := process.NewRegistry(config.PluginDir, logger, logger.Level)
	if err := pluginRegistry.DiscoverPlugins(); err != nil {
		return nil, err
	}

	// cancelFunc is not deferred here because if it was, then ctx would immediately
	// be canceled once this function exited, making it useless to any informers using later.
	// That, in turn, causes the velero server to halt when the first informer tries to use it.
	// Therefore, we must explicitly call it on the error paths in this function.
	ctx, cancelFunc := context.WithCancel(context.Background())

	if len(config.BackupRepoConfig) > 0 {
		repoConfig := make(map[string]any)
		if err := kube.VerifyJSONConfigs(ctx, f.Namespace(), crClient, config.BackupRepoConfig, &repoConfig); err != nil {
			cancelFunc()
			return nil, err
		}
	}

	if len(config.RepoMaintenanceJobConfig) > 0 {
		if err := kube.VerifyJSONConfigs(ctx, f.Namespace(), crClient, config.RepoMaintenanceJobConfig, &velerotypes.JobConfigs{}); err != nil {
			cancelFunc()
			return nil, err
		}
	}

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
	if err := volumegroupsnapshotv1beta2.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}
	if err := batchv1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}
	if err := appsv1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, err
	}

	ctrl.SetLogger(logrusr.New(logger))
	klog.SetLogger(logrusr.New(logger)) // klog.Logger is used by k8s.io/client-go

	var mgr manager.Manager
	retry := 10
	for {
		mgr, err = ctrl.NewManager(clientConfig, ctrl.Options{
			Scheme: scheme,
			Cache: cache.Options{
				DefaultNamespaces: map[string]cache.Config{
					f.Namespace(): {},
				},
			},
		})
		if err == nil {
			break
		}

		retry--
		if retry == 0 {
			break
		}

		logger.WithError(err).Warn("Failed to create controller manager, need retry")

		time.Sleep(time.Second)
	}

	if err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error creating controller manager")
	}

	credentialFileStore, err := credentials.NewNamespacedFileStore(
		mgr.GetClient(),
		f.Namespace(),
		config.CredentialsDirectory,
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

	var discoveryClient discovery.AggregatedDiscoveryInterface
	if discoveryClient, err = f.DiscoveryClient(); err != nil {
		cancelFunc()
		return nil, err
	}

	s := &server{
		namespace:             f.Namespace(),
		metricsAddress:        config.MetricsAddress,
		kubeClientConfig:      clientConfig,
		kubeClient:            kubeClient,
		discoveryClient:       discoveryClient,
		dynamicClient:         dynamicClient,
		crClient:              crClient,
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

	return s, nil
}

func (s *server) run() error {
	signals.CancelOnShutdown(s.cancelFunc, s.logger)

	if s.config.ProfilerAddress != "" {
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

	if err := s.setupBeforeControllerRun(); err != nil {
		return err
	}

	if err := s.runControllers(s.config.DefaultVolumeSnapshotLocations.Data()); err != nil {
		return err
	}

	return nil
}

// setupBeforeControllerRun do any setup that needs to happen before the controllers are started.
func (s *server) setupBeforeControllerRun() error {
	client, err := ctrlclient.New(s.mgr.GetConfig(), ctrlclient.Options{Scheme: s.mgr.GetScheme()})
	// the function is called before starting the controller manager, the embedded client isn't ready to use, so create a new one here
	if err != nil {
		return errors.WithStack(err)
	}

	markInProgressCRsFailed(s.ctx, client, s.namespace, s.logger)

	if err := setDefaultBackupLocation(s.ctx, client, s.namespace, s.config.DefaultBackupLocation, s.logger); err != nil {
		return err
	}
	return nil
}

// setDefaultBackupLocation set the BSL that matches the "velero server --default-backup-storage-location"
func setDefaultBackupLocation(ctx context.Context, client ctrlclient.Client, namespace, defaultBackupLocation string, logger logrus.FieldLogger) error {
	if defaultBackupLocation == "" {
		logger.Debug("No default backup storage location specified. Velero will not automatically select a backup storage location for new backups.")
		return nil
	}

	backupLocation := &velerov1api.BackupStorageLocation{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: defaultBackupLocation}, backupLocation); err != nil {
		if apierrors.IsNotFound(err) {
			logger.WithField("backupStorageLocation", defaultBackupLocation).WithError(err).Warn("Failed to set default backup storage location at server start")
			return nil
		} else {
			return errors.WithStack(err)
		}
	}

	if !backupLocation.Spec.Default {
		backupLocation.Spec.Default = true
		if err := client.Update(ctx, backupLocation); err != nil {
			return errors.WithStack(err)
		}

		logger.WithField("backupStorageLocation", defaultBackupLocation).Info("Set backup storage location as default")
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
	gvResources := map[string]sets.Set[string]{
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

func (s *server) checkNodeAgent() {
	// warn if node agent does not exist
	if kube.WithLinuxNode(s.ctx, s.crClient, s.logger) {
		if err := nodeagent.IsRunningOnLinux(s.ctx, s.kubeClient, s.namespace); err == nodeagent.ErrDaemonSetNotFound {
			s.logger.Warn("Velero node agent not found for linux nodes; pod volume backups/restores and data mover backups/restores will not work until it's created")
		} else if err != nil {
			s.logger.WithError(errors.WithStack(err)).Warn("Error checking for existence of velero node agent for linux nodes")
		}
	}

	if kube.WithWindowsNode(s.ctx, s.crClient, s.logger) {
		if err := nodeagent.IsRunningOnWindows(s.ctx, s.kubeClient, s.namespace); err == nodeagent.ErrDaemonSetNotFound {
			s.logger.Warn("Velero node agent not found for Windows nodes; pod volume backups/restores and data mover backups/restores will not work until it's created")
		} else if err != nil {
			s.logger.WithError(errors.WithStack(err)).Warn("Error checking for existence of velero node agent for Windows nodes")
		}
	}
}

func (s *server) initRepoManager() error {
	// ensure the repo key secret is set up
	if err := repokey.EnsureCommonRepositoryKey(s.kubeClient.CoreV1(), s.namespace); err != nil {
		return err
	}

	s.repoLocker = repository.NewRepoLocker()
	s.repoEnsurer = repository.NewEnsurer(s.mgr.GetClient(), s.logger, s.config.ResourceTimeout)

	s.repoManager = repomanager.NewManager(
		s.namespace,
		s.mgr.GetClient(),
		s.repoLocker,
		s.credentialFileStore,
		s.credentialSecretStore,
		s.logger,
	)

	return nil
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

	backupStoreGetter := persistence.NewObjectBackupStoreGetterWithSecretStore(s.credentialFileStore, s.credentialSecretStore)

	backupTracker := controller.NewBackupTracker()

	// By far, PodVolumeBackup, PodVolumeRestore, BackupStorageLocation controllers
	// are not included in --disable-controllers list.
	// This is because of PVB and PVR are used by node agent DaemonSet,
	// and BSL controller is mandatory for Velero to work.
	// Note: all runtime type controllers that can be disabled are grouped separately, below:
	enabledRuntimeControllers := map[string]struct{}{
		constant.ControllerBackup:              {},
		constant.ControllerBackupDeletion:      {},
		constant.ControllerBackupFinalizer:     {},
		constant.ControllerBackupOperations:    {},
		constant.ControllerBackupRepo:          {},
		constant.ControllerBackupSync:          {},
		constant.ControllerDownloadRequest:     {},
		constant.ControllerGarbageCollection:   {},
		constant.ControllerRestore:             {},
		constant.ControllerRestoreOperations:   {},
		constant.ControllerSchedule:            {},
		constant.ControllerServerStatusRequest: {},
		constant.ControllerRestoreFinalizer:    {},
		constant.ControllerBackupQueue:         {},
	}

	if s.config.RestoreOnly {
		s.logger.Info("Restore only mode - not starting the backup, schedule, delete-backup, or GC controllers")
		s.config.DisabledControllers = append(s.config.DisabledControllers,
			constant.ControllerBackup,
			constant.ControllerBackupDeletion,
			constant.ControllerBackupFinalizer,
			constant.ControllerBackupOperations,
			constant.ControllerGarbageCollection,
			constant.ControllerSchedule,
		)
	}

	// Remove disabled controllers so they are not initialized. If a match is not found we want
	// to halt the system so the user knows this operation was not possible.
	if err := removeControllers(s.config.DisabledControllers, enabledRuntimeControllers, s.logger); err != nil {
		log.Fatal(err, "unable to disable a controller")
	}

	// Enable BSL controller. No need to check whether it's enabled or not.
	bslr := controller.NewBackupStorageLocationReconciler(
		s.ctx,
		s.mgr.GetClient(),
		storage.DefaultBackupLocationInfo{
			StorageLocation:           s.config.DefaultBackupLocation,
			ServerValidationFrequency: s.config.StoreValidationFrequency,
		},
		newPluginManager,
		backupStoreGetter,
		s.metrics,
		s.logger,
	)
	if err := bslr.SetupWithManager(s.mgr); err != nil {
		s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackupStorageLocation)
	}

	pvbInformer, err := s.mgr.GetCache().GetInformer(s.ctx, &velerov1api.PodVolumeBackup{})
	if err != nil {
		s.logger.Fatal(err, "fail to get controller-runtime informer from manager for PVB")
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerBackup]; ok {
		backupper, err := backup.NewKubernetesBackupper(
			s.crClient,
			s.discoveryHelper,
			client.NewDynamicFactory(s.dynamicClient),
			podexec.NewPodCommandExecutor(s.kubeClientConfig, s.kubeClient.CoreV1().RESTClient()),
			podvolume.NewBackupperFactory(
				s.repoLocker,
				s.repoEnsurer,
				s.crClient,
				pvbInformer,
				s.logger,
			),
			s.config.PodVolumeOperationTimeout,
			s.config.DefaultVolumesToFsBackup,
			s.config.ClientPageSize,
			s.config.UploaderType,
			newPluginManager,
			backupStoreGetter,
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
			s.config.DefaultBackupLocation,
			s.config.DefaultVolumesToFsBackup,
			s.config.DefaultBackupTTL,
			s.config.DefaultVGSLabelKey,
			s.config.DefaultCSISnapshotTimeout,
			s.config.ResourceTimeout,
			s.config.DefaultItemOperationTimeout,
			defaultVolumeSnapshotLocations,
			s.metrics,
			backupStoreGetter,
			s.config.LogFormat.Parse(),
			s.credentialFileStore,
			s.config.MaxConcurrentK8SConnections,
			s.config.DefaultSnapshotMoveData,
			s.config.ItemBlockWorkerCount,
			s.config.ConcurrentBackups,
			s.crClient,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackup)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerBackupDeletion]; ok {
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
			s.repoEnsurer,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackupDeletion)
		}
	}

	backupOpsMap := itemoperationmap.NewBackupItemOperationsMap()
	if _, ok := enabledRuntimeControllers[constant.ControllerBackupOperations]; ok {
		r := controller.NewBackupOperationsReconciler(
			s.logger,
			s.mgr.GetClient(),
			s.config.ItemOperationSyncFrequency,
			newPluginManager,
			backupStoreGetter,
			s.metrics,
			backupOpsMap,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackupOperations)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerBackupFinalizer]; ok {
		backupper, err := backup.NewKubernetesBackupper(
			s.mgr.GetClient(),
			s.discoveryHelper,
			client.NewDynamicFactory(s.dynamicClient),
			podexec.NewPodCommandExecutor(s.kubeClientConfig, s.kubeClient.CoreV1().RESTClient()),
			podvolume.NewBackupperFactory(
				s.repoLocker,
				s.repoEnsurer,
				s.crClient,
				pvbInformer,
				s.logger,
			),
			s.config.PodVolumeOperationTimeout,
			s.config.DefaultVolumesToFsBackup,
			s.config.ClientPageSize,
			s.config.UploaderType,
			newPluginManager,
			backupStoreGetter,
		)
		cmd.CheckError(err)
		r := controller.NewBackupFinalizerReconciler(
			s.mgr.GetClient(),
			s.crClient,
			clock.RealClock{},
			backupper,
			newPluginManager,
			backupTracker,
			backupStoreGetter,
			s.logger,
			s.metrics,
			s.config.ResourceTimeout,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackupFinalizer)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerBackupRepo]; ok {
		if err := controller.NewBackupRepoReconciler(
			s.namespace,
			s.logger,
			s.mgr.GetClient(),
			s.repoManager,
			s.config.RepoMaintenanceFrequency,
			s.config.BackupRepoConfig,
			s.config.RepoMaintenanceJobConfig,
			s.logLevel,
			s.config.LogFormat,
			s.metrics,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackupRepo)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerBackupSync]; ok {
		syncPeriod := s.config.BackupSyncPeriod
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
			s.logger.Fatal(err, " unable to create controller ", "controller ", constant.ControllerBackupSync)
		}
	}

	restoreOpsMap := itemoperationmap.NewRestoreItemOperationsMap()
	if _, ok := enabledRuntimeControllers[constant.ControllerRestoreOperations]; ok {
		r := controller.NewRestoreOperationsReconciler(
			s.logger,
			s.namespace,
			s.mgr.GetClient(),
			s.config.ItemOperationSyncFrequency,
			newPluginManager,
			backupStoreGetter,
			s.metrics,
			restoreOpsMap,
		)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerRestoreOperations)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerDownloadRequest]; ok {
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
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerDownloadRequest)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerGarbageCollection]; ok {
		r := controller.NewGCReconciler(s.logger, s.mgr.GetClient(), s.config.GarbageCollectionFrequency)
		if err := r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerGarbageCollection)
		}
	}

	pvrInformer, err := s.mgr.GetCache().GetInformer(s.ctx, &velerov1api.PodVolumeRestore{})
	if err != nil {
		s.logger.Fatal(err, "fail to get controller-runtime informer from manager for PVR")
	}

	multiHookTracker := hook.NewMultiHookTracker()

	if _, ok := enabledRuntimeControllers[constant.ControllerRestore]; ok {
		restorer, err := restore.NewKubernetesRestorer(
			s.discoveryHelper,
			client.NewDynamicFactory(s.dynamicClient),
			s.config.RestoreResourcePriorities,
			s.kubeClient.CoreV1().Namespaces(),
			podvolume.NewRestorerFactory(
				s.repoLocker,
				s.repoEnsurer,
				s.kubeClient,
				s.crClient,
				pvrInformer,
				s.logger,
			),
			s.config.PodVolumeOperationTimeout,
			s.config.ResourceTerminatingTimeout,
			s.config.ResourceTimeout,
			s.logger,
			podexec.NewPodCommandExecutor(s.kubeClientConfig, s.kubeClient.CoreV1().RESTClient()),
			s.kubeClient.CoreV1().RESTClient(),
			s.credentialFileStore,
			s.mgr.GetClient(),
			multiHookTracker,
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
			s.config.LogFormat.Parse(),
			s.config.DefaultItemOperationTimeout,
			s.config.DisableInformerCache,
			s.crClient,
			s.config.ResourceTimeout,
		)

		if err = r.SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "fail to create controller", "controller", constant.ControllerRestore)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerSchedule]; ok {
		if err := controller.NewScheduleReconciler(s.namespace, s.logger, s.mgr.GetClient(), s.metrics, s.config.ScheduleSkipImmediately).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerSchedule)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerServerStatusRequest]; ok {
		if err := controller.NewServerStatusRequestReconciler(
			s.ctx,
			s.mgr.GetClient(),
			s.pluginRegistry,
			clock.RealClock{},
			s.logger,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerServerStatusRequest)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerRestoreFinalizer]; ok {
		if err := controller.NewRestoreFinalizerReconciler(
			s.logger,
			s.namespace,
			s.mgr.GetClient(),
			newPluginManager,
			backupStoreGetter,
			s.metrics,
			s.crClient,
			multiHookTracker,
			s.config.ResourceTimeout,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerRestoreFinalizer)
		}
	}

	if _, ok := enabledRuntimeControllers[constant.ControllerBackupQueue]; ok {
		if err := controller.NewBackupQueueReconciler(
			s.mgr.GetClient(),
			s.mgr.GetScheme(),
			s.logger,
			s.config.ConcurrentBackups,
			backupTracker,
		).SetupWithManager(s.mgr); err != nil {
			s.logger.Fatal(err, "unable to create controller", "controller", constant.ControllerBackupQueue)
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
			msg := fmt.Sprintf("Invalid value for --disable-controllers flag provided: %s. Valid values are: %s", controllerName, strings.Join(config.DisableableControllers, ","))
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
		Addr:              s.config.ProfilerAddress,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		s.logger.WithError(errors.WithStack(err)).Error("error running profiler http server")
	}
}

// if there is a restarting during the reconciling of backups/restores/etc, these CRs may be stuck in progress status
// markInProgressCRsFailed tries to mark the in progress CRs as failed when starting the server to avoid the issue
func markInProgressCRsFailed(ctx context.Context, client ctrlclient.Client, namespace string, log logrus.FieldLogger) {
	markInProgressBackupsFailed(ctx, client, namespace, log)

	markInProgressRestoresFailed(ctx, client, namespace, log)
}

func markInProgressBackupsFailed(ctx context.Context, client ctrlclient.Client, namespace string, log logrus.FieldLogger) {
	backups := &velerov1api.BackupList{}
	if err := client.List(ctx, backups, &ctrlclient.ListOptions{Namespace: namespace}); err != nil {
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
		markPodVolumeBackupsCancel(ctx, client, backup, log)
	}
}

func markInProgressRestoresFailed(ctx context.Context, client ctrlclient.Client, namespace string, log logrus.FieldLogger) {
	restores := &velerov1api.RestoreList{}
	if err := client.List(ctx, restores, &ctrlclient.ListOptions{Namespace: namespace}); err != nil {
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
		markPodVolumeRestoresCancel(ctx, client, restore, log)
	}
}

func markDataUploadsCancel(ctx context.Context, client ctrlclient.Client, backup velerov1api.Backup, log logrus.FieldLogger) {
	dataUploads := &velerov2alpha1api.DataUploadList{}

	if err := client.List(ctx, dataUploads, &ctrlclient.ListOptions{
		Namespace: backup.GetNamespace(),
		LabelSelector: labels.Set(map[string]string{
			velerov1api.BackupUIDLabel: string(backup.GetUID()),
		}).AsSelector(),
	}); err != nil {
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
				func(dataUpload *velerov2alpha1api.DataUpload) bool {
					if dataUpload.Spec.Cancel {
						return false
					}

					dataUpload.Spec.Cancel = true
					dataUpload.Status.Message = fmt.Sprintf("Dataupload is in status %q during the velero server starting, mark it as cancel", du.Status.Phase)

					return true
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

	if err := client.List(ctx, dataDownloads, &ctrlclient.ListOptions{
		Namespace: restore.GetNamespace(),
		LabelSelector: labels.Set(map[string]string{
			velerov1api.RestoreUIDLabel: string(restore.GetUID()),
		}).AsSelector(),
	}); err != nil {
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
				func(dataDownload *velerov2alpha1api.DataDownload) bool {
					if dataDownload.Spec.Cancel {
						return false
					}

					dataDownload.Spec.Cancel = true
					dataDownload.Status.Message = fmt.Sprintf("Datadownload is in status %q during the velero server starting, mark it as cancel", dd.Status.Phase)

					return true
				})

			if err != nil {
				log.WithError(errors.WithStack(err)).Errorf("failed to mark datadownload %q cancel", dd.GetName())
				continue
			}
			log.WithField("datadownload", dd.GetName()).Warn(dd.Status.Message)
		}
	}
}

func markPodVolumeBackupsCancel(ctx context.Context, client ctrlclient.Client, backup velerov1api.Backup, log logrus.FieldLogger) {
	pvbs := &velerov1api.PodVolumeBackupList{}

	if err := client.List(ctx, pvbs, &ctrlclient.ListOptions{
		Namespace: backup.GetNamespace(),
		LabelSelector: labels.Set(map[string]string{
			velerov1api.BackupUIDLabel: string(backup.GetUID()),
		}).AsSelector(),
	}); err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to list PVBs")
		return
	}

	for i := range pvbs.Items {
		pvb := pvbs.Items[i]
		if pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseAccepted ||
			pvb.Status.Phase == velerov1api.PodVolumeBackupPhasePrepared ||
			pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseInProgress ||
			pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseNew ||
			pvb.Status.Phase == "" {
			err := controller.UpdatePVBWithRetry(ctx, client, types.NamespacedName{Namespace: pvb.Namespace, Name: pvb.Name}, log.WithField("PVB", pvb.Name),
				func(pvb *velerov1api.PodVolumeBackup) bool {
					if pvb.Spec.Cancel {
						return false
					}

					pvb.Spec.Cancel = true
					pvb.Status.Message = fmt.Sprintf("PVB is in status %q during the velero server starting, mark it as cancel", pvb.Status.Phase)

					return true
				})

			if err != nil {
				log.WithError(errors.WithStack(err)).Errorf("failed to mark PVB %q cancel", pvb.GetName())
				continue
			}
			log.WithField("PVB is mark for cancel due to server restart", pvb.GetName()).Warn(pvb.Status.Message)
		}
	}
}

func markPodVolumeRestoresCancel(ctx context.Context, client ctrlclient.Client, restore velerov1api.Restore, log logrus.FieldLogger) {
	pvrs := &velerov1api.PodVolumeRestoreList{}

	if err := client.List(ctx, pvrs, &ctrlclient.ListOptions{
		Namespace: restore.GetNamespace(),
		LabelSelector: labels.Set(map[string]string{
			velerov1api.RestoreUIDLabel: string(restore.GetUID()),
		}).AsSelector(),
	}); err != nil {
		log.WithError(errors.WithStack(err)).Error("failed to list PVRs")
		return
	}

	for i := range pvrs.Items {
		pvr := pvrs.Items[i]
		if _, err := uploader.ValidateUploaderType(pvr.Spec.UploaderType); err != nil {
			log.WithField("PVR", pvr.Name).Warnf("invalid uploader type %s, skip marking cancel for this PVR", pvr.Spec.UploaderType)
			continue
		}

		if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseAccepted ||
			pvr.Status.Phase == velerov1api.PodVolumeRestorePhasePrepared ||
			pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseInProgress ||
			pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseNew ||
			pvr.Status.Phase == "" {
			err := controller.UpdatePVRWithRetry(ctx, client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log.WithField("PVR", pvr.Name),
				func(pvr *velerov1api.PodVolumeRestore) bool {
					if pvr.Spec.Cancel {
						return false
					}

					pvr.Spec.Cancel = true
					pvr.Status.Message = fmt.Sprintf("PVR is in status %q during the velero server starting, mark it as cancel", pvr.Status.Phase)

					return true
				})

			if err != nil {
				log.WithError(errors.WithStack(err)).Errorf("failed to mark PVR %q cancel", pvr.GetName())
				continue
			}
			log.WithField("PVR is mark for cancel due to server restart", pvr.GetName()).Warn(pvr.Status.Message)
		}
	}
}
