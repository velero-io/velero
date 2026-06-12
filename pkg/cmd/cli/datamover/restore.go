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

package datamover

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bombsimon/logrusr/v3"
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/buildinfo"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/signals"
	"github.com/vmware-tanzu/velero/pkg/datamover"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/logging"

	ctlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type dataMoverRestoreConfig struct {
	volumePath      string
	volumeMode      string
	ddName          string
	cacheDir        string
	resourceTimeout time.Duration
}

func NewRestoreCommand(f client.Factory) *cobra.Command {
	logLevelFlag := logging.LogLevelFlag(logrus.InfoLevel)
	formatFlag := logging.NewFormatFlag()

	config := dataMoverRestoreConfig{}

	command := &cobra.Command{
		Use:    "restore",
		Short:  "Run the velero data-mover restore",
		Long:   "Run the velero data-mover restore",
		Hidden: true,
		Run: func(c *cobra.Command, args []string) {
			logLevel := logLevelFlag.Parse()
			logrus.Infof("Setting log-level to %s", strings.ToUpper(logLevel.String()))

			logger := logging.DefaultLogger(logLevel, formatFlag.Parse())
			logger.Infof("Starting Velero data-mover restore %s (%s)", buildinfo.Version, buildinfo.FormattedGitSHA())

			f.SetBasename(fmt.Sprintf("%s-%s", c.Parent().Name(), c.Name()))
			s, err := newdataMoverRestore(logger, f, config)
			if err != nil {
				kube.ExitPodWithMessage(logger, false, "Failed to create data mover restore, %v", err)
			}

			s.run()
		},
	}

	command.Flags().Var(logLevelFlag, "log-level", fmt.Sprintf("The level at which to log. Valid values are %s.", strings.Join(logLevelFlag.AllowedValues(), ", ")))
	command.Flags().Var(formatFlag, "log-format", fmt.Sprintf("The format for log output. Valid values are %s.", strings.Join(formatFlag.AllowedValues(), ", ")))
	command.Flags().StringVar(&config.volumePath, "volume-path", config.volumePath, "The full path of the volume to be restored")
	command.Flags().StringVar(&config.volumeMode, "volume-mode", config.volumeMode, "The mode of the volume to be restored")
	command.Flags().StringVar(&config.ddName, "data-download", config.ddName, "The data download name")
	command.Flags().StringVar(&config.cacheDir, "cache-volume-path", config.cacheDir, "The full path of the cache volume")
	command.Flags().DurationVar(&config.resourceTimeout, "resource-timeout", config.resourceTimeout, "How long to wait for resource processes which are not covered by other specific timeout parameters.")

	_ = command.MarkFlagRequired("volume-path")
	_ = command.MarkFlagRequired("volume-mode")
	_ = command.MarkFlagRequired("data-download")
	_ = command.MarkFlagRequired("resource-timeout")

	return command
}

type dataMoverRestore struct {
	logger      logrus.FieldLogger
	ctx         context.Context
	cancelFunc  context.CancelFunc
	client      ctlclient.Client
	cache       ctlcache.Cache
	namespace   string
	nodeName    string
	config      dataMoverRestoreConfig
	kubeClient  kubernetes.Interface
	dataPathMgr *datapath.Manager
}

func newdataMoverRestore(logger logrus.FieldLogger, factory client.Factory, config dataMoverRestoreConfig) (*dataMoverRestore, error) {
	ctx, cancelFunc := context.WithCancel(context.Background())

	clientConfig, err := factory.ClientConfig()
	if err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to create client config")
	}

	ctrl.SetLogger(logrusr.New(logger))
	klog.SetLogger(logrusr.New(logger)) // klog.Logger is used by k8s.io/client-go

	scheme := runtime.NewScheme()
	if err := velerov1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to add velero v1 scheme")
	}

	if err := velerov2alpha1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to add velero v2alpha1 scheme")
	}

	if err := corev1api.AddToScheme(scheme); err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to add core v1 scheme")
	}

	nodeName := os.Getenv("NODE_NAME")

	// use a field selector to filter to only pods scheduled on this node.
	cacheOption := ctlcache.Options{
		Scheme: scheme,
		ByObject: map[ctlclient.Object]ctlcache.ByObject{
			&corev1api.Pod{}: {
				Field: fields.Set{"spec.nodeName": nodeName}.AsSelector(),
			},
			&velerov2alpha1api.DataDownload{}: {
				Field: fields.Set{"metadata.namespace": factory.Namespace()}.AsSelector(),
			},
		},
	}

	cli, err := ctlclient.New(clientConfig, ctlclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to create client")
	}

	var cache ctlcache.Cache
	retry := 10
	for {
		cache, err = ctlcache.New(clientConfig, cacheOption)
		if err == nil {
			break
		}

		retry--
		if retry == 0 {
			break
		}

		logger.WithError(err).Warn("Failed to create client cache, need retry")

		time.Sleep(time.Second)
	}

	if err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to create client cache")
	}

	s := &dataMoverRestore{
		logger:     logger,
		ctx:        ctx,
		cancelFunc: cancelFunc,
		client:     cli,
		cache:      cache,
		config:     config,
		namespace:  factory.Namespace(),
		nodeName:   nodeName,
	}

	s.kubeClient, err = factory.KubeClient()
	if err != nil {
		cancelFunc()
		return nil, errors.Wrap(err, "error to create kube client")
	}

	s.dataPathMgr = datapath.NewManager(1)

	return s, nil
}

var funcCreateDataPathRestore = (*dataMoverRestore).createDataPathService

func (s *dataMoverRestore) run() {
	signals.CancelOnShutdown(s.cancelFunc, s.logger)
	go func() {
		if err := s.cache.Start(s.ctx); err != nil {
			s.logger.WithError(err).Warn("error starting cache")
		}
	}()

	s.runDataPath()
}

func (s *dataMoverRestore) runDataPath() {
	s.logger.Infof("Starting micro service in node %s for dd %s", s.nodeName, s.config.ddName)

	dpService, err := funcCreateDataPathRestore(s)
	if err != nil {
		s.cancelFunc()
		funcExitWithMessage(s.logger, false, "Failed to create data path service for DataDownload %s: %v", s.config.ddName, err)
		return
	}

	s.logger.Infof("Starting data path service %s", s.config.ddName)

	err = dpService.Init()
	if err != nil {
		dpService.Shutdown()
		s.cancelFunc()
		funcExitWithMessage(s.logger, false, "Failed to init data path service for DataDownload %s: %v", s.config.ddName, err)
		return
	}

	result, err := dpService.RunCancelableDataPath(s.ctx)
	if err != nil {
		dpService.Shutdown()
		s.cancelFunc()
		funcExitWithMessage(s.logger, false, "Failed to run data path service for DataDownload %s: %v", s.config.ddName, err)
		return
	}

	s.logger.WithField("dd", s.config.ddName).Info("Data path service completed")

	dpService.Shutdown()

	s.logger.WithField("dd", s.config.ddName).Info("Data path service is shut down")

	s.cancelFunc()

	funcExitWithMessage(s.logger, true, result)
}

func (s *dataMoverRestore) createDataPathService() (dataPathService, error) {
	credentialFileStore, err := funcNewCredentialFileStore(
		s.client,
		s.namespace,
		credentials.DefaultStoreDirectory(),
		filesystem.NewFileSystem(),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "error to create credential file store")
	}

	credSecretStore, err := funcNewCredentialSecretStore(s.client, s.namespace)
	if err != nil {
		return nil, errors.Wrapf(err, "error to create credential secret store")
	}

	credGetter := &credentials.CredentialGetter{FromFile: credentialFileStore, FromSecret: credSecretStore}

	duInformer, err := s.cache.GetInformer(s.ctx, &velerov2alpha1api.DataDownload{})
	if err != nil {
		return nil, errors.Wrap(err, "error to get controller-runtime informer from manager")
	}

	repoEnsurer := repository.NewEnsurer(s.client, s.logger, s.config.resourceTimeout)

	return datamover.NewRestoreMicroService(s.ctx, s.client, s.kubeClient, s.config.ddName, s.namespace, s.nodeName, datapath.AccessPoint{
		ByPath:  s.config.volumePath,
		VolMode: uploader.PersistentVolumeMode(s.config.volumeMode),
	}, s.dataPathMgr, repoEnsurer, credGetter, duInformer, s.config.cacheDir, s.logger), nil
}
