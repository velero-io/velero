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
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/kube"

	cachetool "k8s.io/client-go/tools/cache"
)

// RestoreMicroService process data mover restores inside the restore pod
type RestoreMicroService struct {
	ctx              context.Context
	client           client.Client
	kubeClient       kubernetes.Interface
	repoEnsurer      *repository.Ensurer
	credentialGetter *credentials.CredentialGetter
	logger           logrus.FieldLogger
	dataPathMgr      *datapath.Manager
	eventRecorder    kube.EventRecorder

	namespace        string
	dataDownloadName string
	dataDownload     *velerov2alpha1api.DataDownload
	sourceTargetPath datapath.AccessPoint

	resultSignal chan dataPathResult

	ddInformer cache.Informer
	ddHandler  cachetool.ResourceEventHandlerRegistration
	nodeName   string
	cacheDir   string
}

func NewRestoreMicroService(ctx context.Context, client client.Client, kubeClient kubernetes.Interface, dataDownloadName string, namespace string, nodeName string,
	sourceTargetPath datapath.AccessPoint, dataPathMgr *datapath.Manager, repoEnsurer *repository.Ensurer, cred *credentials.CredentialGetter,
	ddInformer cache.Informer, cacheDir string, log logrus.FieldLogger) *RestoreMicroService {
	return &RestoreMicroService{
		ctx:              ctx,
		client:           client,
		kubeClient:       kubeClient,
		credentialGetter: cred,
		logger:           log,
		repoEnsurer:      repoEnsurer,
		dataPathMgr:      dataPathMgr,
		namespace:        namespace,
		dataDownloadName: dataDownloadName,
		sourceTargetPath: sourceTargetPath,
		nodeName:         nodeName,
		resultSignal:     make(chan dataPathResult),
		ddInformer:       ddInformer,
		cacheDir:         cacheDir,
	}
}

func (r *RestoreMicroService) Init() error {
	r.eventRecorder = kube.NewEventRecorder(r.kubeClient, r.client.Scheme(), r.dataDownloadName, r.nodeName, r.logger)

	handler, err := r.ddInformer.AddEventHandler(
		cachetool.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj any, newObj any) {
				oldDd := oldObj.(*velerov2alpha1api.DataDownload)
				newDd := newObj.(*velerov2alpha1api.DataDownload)

				if newDd.Name != r.dataDownloadName {
					return
				}

				if newDd.Status.Phase != velerov2alpha1api.DataDownloadPhaseInProgress {
					return
				}

				if newDd.Spec.Cancel && !oldDd.Spec.Cancel {
					r.cancelDataDownload(newDd)
				}
			},
		},
	)

	if err != nil {
		return errors.Wrap(err, "error adding dd handler")
	}

	r.ddHandler = handler

	return err
}

func (r *RestoreMicroService) RunCancelableDataPath(ctx context.Context) (string, error) {
	log := r.logger.WithFields(logrus.Fields{
		"datadownload": r.dataDownloadName,
	})

	dd := &velerov2alpha1api.DataDownload{}
	err := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		err := r.client.Get(ctx, types.NamespacedName{
			Namespace: r.namespace,
			Name:      r.dataDownloadName,
		}, dd)
		if apierrors.IsNotFound(err) {
			return false, nil
		}

		if err != nil {
			return true, errors.Wrapf(err, "error to get dd %s", r.dataDownloadName)
		}

		if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseInProgress {
			return true, nil
		} else {
			return false, nil
		}
	})
	if err != nil {
		log.WithError(err).Error("Failed to wait dd")
		return "", errors.Wrap(err, "error waiting for dd")
	}

	r.dataDownload = dd

	log.Info("Run cancelable dataDownload")

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataDownloadCompleted,
		OnFailed:    r.OnDataDownloadFailed,
		OnCancelled: r.OnDataDownloadCancelled,
		OnProgress:  r.OnDataDownloadProgress,
	}

	dp, err := r.dataPathMgr.CreateGenericDataPath(dd.Name, dataUploadDownloadRequestor, ctx, r.client, dd.Namespace, callbacks, log)
	if err != nil {
		return "", errors.Wrap(err, "error to create data path")
	}

	log.Debug("Found volume path")
	if err := dp.Init(ctx,
		&datapath.InitParam{
			BSLName:           dd.Spec.BackupStorageLocation,
			SourceNamespace:   dd.Spec.SourceNamespace,
			UploaderType:      GetUploaderType(dd.Spec.DataMover),
			RepositoryType:    velerov1api.BackupRepositoryTypeKopia,
			RepoIdentifier:    "",
			RepositoryEnsurer: r.repoEnsurer,
			CredentialGetter:  r.credentialGetter,
			CacheDir:          r.cacheDir,
		}); err != nil {
		return "", errors.Wrap(err, "error to initialize data path")
	}
	log.Info("fs init")

	if err := dp.StartRestore(dd.Spec.SnapshotID, r.sourceTargetPath, dd.Spec.DataMoverConfig); err != nil {
		return "", errors.Wrap(err, "error starting data path restore")
	}

	log.Info("Async fs restore data path started")
	r.eventRecorder.Event(dd, false, datapath.EventReasonStarted, "Data path for %s started", dd.Name)

	result := ""
	select {
	case <-ctx.Done():
		err = errors.New("timed out waiting for fs restore to complete")
		break
	case res := <-r.resultSignal:
		err = res.err
		result = res.result
		break
	}

	if err != nil {
		log.WithError(err).Error("Async fs restore was not completed")
	}

	r.eventRecorder.EndingEvent(dd, false, datapath.EventReasonStopped, "Data path for %s stopped", dd.Name)

	return result, err
}

func (r *RestoreMicroService) Shutdown() {
	r.eventRecorder.Shutdown()
	r.closeDataPath(r.ctx, r.dataDownloadName)

	if r.ddHandler != nil {
		if err := r.ddInformer.RemoveEventHandler(r.ddHandler); err != nil {
			r.logger.WithError(err).Warn("Failed to remove pod handler")
		}
	}
}

func (r *RestoreMicroService) OnDataDownloadCompleted(ctx context.Context, namespace string, ddName string, result datapath.Result) {
	log := r.logger.WithField("datadownload", ddName)

	restoreBytes, err := funcMarshal(result.Restore)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal restore result %v", result.Restore)
		r.resultSignal <- dataPathResult{
			err: errors.Wrapf(err, "Failed to marshal restore result %v", result.Restore),
		}
	} else {
		r.eventRecorder.Event(r.dataDownload, false, datapath.EventReasonCompleted, string(restoreBytes))
		r.resultSignal <- dataPathResult{
			result: string(restoreBytes),
		}
	}

	log.Info("Async fs restore data path completed")
}

func (r *RestoreMicroService) OnDataDownloadFailed(ctx context.Context, namespace string, ddName string, err error) {
	log := r.logger.WithField("datadownload", ddName)
	log.WithError(err).Error("Async fs restore data path failed")

	r.eventRecorder.Event(r.dataDownload, false, datapath.EventReasonFailed, "Data path for data download %s failed, error %v", r.dataDownloadName, err)
	r.resultSignal <- dataPathResult{
		err: errors.Wrapf(err, "Data path for data download %s failed", r.dataDownloadName),
	}
}

func (r *RestoreMicroService) OnDataDownloadCancelled(ctx context.Context, namespace string, ddName string) {
	log := r.logger.WithField("datadownload", ddName)
	log.Warn("Async fs restore data path canceled")

	r.eventRecorder.Event(r.dataDownload, false, datapath.EventReasonCancelled, "Data path for data download %s canceled", ddName)
	r.resultSignal <- dataPathResult{
		err: errors.New(datapath.ErrCancelled),
	}
}

func (r *RestoreMicroService) OnDataDownloadProgress(ctx context.Context, namespace string, ddName string, progress *uploader.Progress) {
	log := r.logger.WithFields(logrus.Fields{
		"datadownload": ddName,
	})

	progressBytes, err := funcMarshal(progress)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal progress %v", progress)
		return
	}

	r.eventRecorder.Event(r.dataDownload, false, datapath.EventReasonProgress, string(progressBytes))
}

func (r *RestoreMicroService) closeDataPath(ctx context.Context, ddName string) {
	fsRestore := r.dataPathMgr.GetAsyncBR(ddName)
	if fsRestore != nil {
		fsRestore.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(ddName)
}

func (r *RestoreMicroService) cancelDataDownload(dd *velerov2alpha1api.DataDownload) {
	r.logger.WithField("DataDownload", dd.Name).Info("Data download is being canceled")

	r.eventRecorder.Event(dd, false, datapath.EventReasonCancelling, "Canceling for data download %s", dd.Name)

	fsBackup := r.dataPathMgr.GetAsyncBR(dd.Name)
	if fsBackup == nil {
		r.OnDataDownloadCancelled(r.ctx, dd.GetNamespace(), dd.GetName())
		r.eventRecorder.EndingEvent(dd, false, datapath.EventReasonStopped, "Data path for %s exited without start", dd.Name)
	} else {
		fsBackup.Cancel()
	}
}
