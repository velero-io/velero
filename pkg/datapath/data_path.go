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

package datapath

import (
	"context"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository"
	repokey "github.com/vmware-tanzu/velero/pkg/repository/keys"
	repoProvider "github.com/vmware-tanzu/velero/pkg/repository/provider"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/uploader/provider"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

// InitParam define the input param for data path init
type InitParam struct {
	BSLName           string
	SourceNamespace   string
	UploaderType      string
	RepositoryType    string
	RepoIdentifier    string
	RepositoryEnsurer *repository.Ensurer
	CredentialGetter  *credentials.CredentialGetter
	Filesystem        filesystem.Interface
	CacheDir          string
}

// BackupStartParam define the input param for backup start
type BackupStartParam struct {
	RealSource     string
	ParentSnapshot string
	ForceFull      bool
	Tags           map[string]string
}

type generalDataPath struct {
	ctx            context.Context
	cancel         context.CancelFunc
	backupRepo     *velerov1api.BackupRepository
	uploaderProv   provider.Provider
	log            logrus.FieldLogger
	client         client.Client
	backupLocation *velerov1api.BackupStorageLocation
	namespace      string
	initialized    bool
	callbacks      Callbacks
	jobName        string
	requestorType  string
	wgDataPath     sync.WaitGroup
	dataPathLock   sync.Mutex
}

func newGeneralDataPath(jobName string, requestorType string, client client.Client, namespace string, callbacks Callbacks, log logrus.FieldLogger) AsyncBR {
	dp := &generalDataPath{
		jobName:       jobName,
		requestorType: requestorType,
		client:        client,
		namespace:     namespace,
		callbacks:     callbacks,
		wgDataPath:    sync.WaitGroup{},
		log:           log,
	}

	return dp
}

func (dp *generalDataPath) Init(ctx context.Context, param any) error {
	initParam := param.(*InitParam)

	var err error
	defer func() {
		if err != nil {
			dp.Close(ctx)
		}
	}()

	dp.ctx, dp.cancel = context.WithCancel(ctx)

	backupLocation := &velerov1api.BackupStorageLocation{}
	if err = dp.client.Get(ctx, client.ObjectKey{
		Namespace: dp.namespace,
		Name:      initParam.BSLName,
	}, backupLocation); err != nil {
		return errors.Wrapf(err, "error getting backup storage location %s", initParam.BSLName)
	}

	dp.backupLocation = backupLocation

	dp.backupRepo, err = initParam.RepositoryEnsurer.EnsureRepo(ctx, dp.namespace, initParam.SourceNamespace, initParam.BSLName, initParam.RepositoryType)
	if err != nil {
		return errors.Wrapf(err, "error to ensure backup repository %s-%s-%s", initParam.BSLName, initParam.SourceNamespace, initParam.RepositoryType)
	}

	err = dp.boostRepoConnect(ctx, initParam.RepositoryType, initParam.CredentialGetter, initParam.CacheDir)
	if err != nil {
		return errors.Wrapf(err, "error to boost backup repository connection %s-%s-%s", initParam.BSLName, initParam.SourceNamespace, initParam.RepositoryType)
	}

	dp.uploaderProv, err = provider.NewUploaderProvider(ctx, dp.client, initParam.UploaderType, dp.requestorType, initParam.RepoIdentifier,
		dp.backupLocation, dp.backupRepo, initParam.CredentialGetter, repokey.RepoKeySelector(), dp.log)
	if err != nil {
		return errors.Wrapf(err, "error creating uploader %s", initParam.UploaderType)
	}

	dp.initialized = true

	dp.log.WithFields(
		logrus.Fields{
			"jobName":          dp.jobName,
			"bsl":              initParam.BSLName,
			"source namespace": initParam.SourceNamespace,
			"uploader":         initParam.UploaderType,
			"repository":       initParam.RepositoryType,
		}).Info("Data path is initialized")

	return nil
}

func (dp *generalDataPath) Close(ctx context.Context) {
	if dp.cancel != nil {
		dp.cancel()
	}

	dp.log.WithField("user", dp.jobName).Info("Closing data path")

	dp.wgDataPath.Wait()

	dp.close(ctx)

	dp.log.WithField("user", dp.jobName).Info("Data path is closed")
}

func (dp *generalDataPath) close(ctx context.Context) {
	dp.dataPathLock.Lock()
	defer dp.dataPathLock.Unlock()

	if dp.uploaderProv != nil {
		if err := dp.uploaderProv.Close(ctx); err != nil {
			dp.log.Errorf("failed to close uploader provider with error %v", err)
		}

		dp.uploaderProv = nil
	}
}

func (dp *generalDataPath) StartBackup(source AccessPoint, uploaderConfig map[string]string, param any) error {
	if !dp.initialized {
		return errors.New("file system data path is not initialized")
	}

	dp.wgDataPath.Add(1)

	backupParam := param.(*BackupStartParam)

	go func() {
		dp.log.Info("Start data path backup")

		defer func() {
			dp.close(context.Background())
			dp.wgDataPath.Done()
		}()

		snapshotID, emptySnapshot, totalBytes, incrementalBytes, err := dp.uploaderProv.RunBackup(dp.ctx, source.ByPath, backupParam.RealSource, backupParam.Tags, backupParam.ForceFull,
			backupParam.ParentSnapshot, provider.CBTParam{}, source.VolMode, uploaderConfig, dp)

		if err == provider.ErrorCanceled {
			dp.callbacks.OnCancelled(context.Background(), dp.namespace, dp.jobName)
		} else if err != nil {
			dataPathErr := DataPathError{
				snapshotID: snapshotID,
				err:        err,
			}
			dp.callbacks.OnFailed(context.Background(), dp.namespace, dp.jobName, dataPathErr)
		} else {
			dp.callbacks.OnCompleted(context.Background(), dp.namespace, dp.jobName, Result{Backup: BackupResult{snapshotID, emptySnapshot, source, totalBytes, incrementalBytes}})
		}
	}()

	return nil
}

func (dp *generalDataPath) StartRestore(snapshotID string, target AccessPoint, uploaderConfigs map[string]string) error {
	if !dp.initialized {
		return errors.New("data path is not initialized")
	}

	dp.wgDataPath.Add(1)

	go func() {
		dp.log.Info("Start data path restore")

		defer func() {
			dp.close(context.Background())
			dp.wgDataPath.Done()
		}()

		totalBytes, err := dp.uploaderProv.RunRestore(dp.ctx, snapshotID, target.ByPath, target.VolMode, uploaderConfigs, dp)

		if err == provider.ErrorCanceled {
			dp.callbacks.OnCancelled(context.Background(), dp.namespace, dp.jobName)
		} else if err != nil {
			dataPathErr := DataPathError{
				snapshotID: snapshotID,
				err:        err,
			}
			dp.callbacks.OnFailed(context.Background(), dp.namespace, dp.jobName, dataPathErr)
		} else {
			dp.callbacks.OnCompleted(context.Background(), dp.namespace, dp.jobName, Result{Restore: RestoreResult{Target: target, TotalBytes: totalBytes}})
		}
	}()

	return nil
}

// UpdateProgress which implement ProgressUpdater interface to update progress status
func (dp *generalDataPath) UpdateProgress(p *uploader.Progress) {
	if dp.callbacks.OnProgress != nil {
		dp.callbacks.OnProgress(context.Background(), dp.namespace, dp.jobName, &uploader.Progress{TotalBytes: p.TotalBytes, BytesDone: p.BytesDone})
	}
}

func (dp *generalDataPath) Cancel() {
	dp.cancel()
	dp.log.WithField("user", dp.jobName).Info("FileSystemBR is canceled")
}

func (dp *generalDataPath) boostRepoConnect(ctx context.Context, repositoryType string, credentialGetter *credentials.CredentialGetter, cacheDir string) error {
	if repositoryType == velerov1api.BackupRepositoryTypeKopia {
		if err := repoProvider.NewUnifiedRepoProvider(*credentialGetter, repositoryType, dp.log).BoostRepoConnect(ctx, repoProvider.RepoParam{BackupLocation: dp.backupLocation, BackupRepo: dp.backupRepo, CacheDir: cacheDir}); err != nil {
			return err
		}

		return nil
	}

	return errors.Errorf("error getting provider for repo %s", repositoryType)
}
