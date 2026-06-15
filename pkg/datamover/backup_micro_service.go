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
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cachetool "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/kube"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	dataUploadDownloadRequestor = "snapshot-data-upload-download"
)

// BackupMicroService process data mover backups inside the backup pod
type BackupMicroService struct {
	ctx              context.Context
	client           client.Client
	kubeClient       kubernetes.Interface
	repoEnsurer      *repository.Ensurer
	credentialGetter *credentials.CredentialGetter
	logger           logrus.FieldLogger
	dataPathMgr      *datapath.Manager
	eventRecorder    kube.EventRecorder

	namespace        string
	dataUploadName   string
	dataUpload       *velerov2alpha1api.DataUpload
	sourceTargetPath datapath.AccessPoint

	resultSignal chan dataPathResult

	duInformer cache.Informer
	duHandler  cachetool.ResourceEventHandlerRegistration
	nodeName   string
}

type dataPathResult struct {
	err    error
	result string
}

func NewBackupMicroService(ctx context.Context, client client.Client, kubeClient kubernetes.Interface, dataUploadName string, namespace string, nodeName string,
	sourceTargetPath datapath.AccessPoint, dataPathMgr *datapath.Manager, repoEnsurer *repository.Ensurer, cred *credentials.CredentialGetter,
	duInformer cache.Informer, log logrus.FieldLogger) *BackupMicroService {
	return &BackupMicroService{
		ctx:              ctx,
		client:           client,
		kubeClient:       kubeClient,
		credentialGetter: cred,
		logger:           log,
		repoEnsurer:      repoEnsurer,
		dataPathMgr:      dataPathMgr,
		namespace:        namespace,
		dataUploadName:   dataUploadName,
		sourceTargetPath: sourceTargetPath,
		nodeName:         nodeName,
		resultSignal:     make(chan dataPathResult),
		duInformer:       duInformer,
	}
}

func (r *BackupMicroService) Init() error {
	r.eventRecorder = kube.NewEventRecorder(r.kubeClient, r.client.Scheme(), r.dataUploadName, r.nodeName, r.logger)

	handler, err := r.duInformer.AddEventHandler(
		cachetool.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj any, newObj any) {
				oldDu := oldObj.(*velerov2alpha1api.DataUpload)
				newDu := newObj.(*velerov2alpha1api.DataUpload)

				if newDu.Name != r.dataUploadName {
					return
				}

				if newDu.Status.Phase != velerov2alpha1api.DataUploadPhaseInProgress {
					return
				}

				if newDu.Spec.Cancel && !oldDu.Spec.Cancel {
					r.cancelDataUpload(newDu)
				}
			},
		},
	)

	if err != nil {
		return errors.Wrap(err, "error adding du handler")
	}

	r.duHandler = handler

	return err
}

func (r *BackupMicroService) RunCancelableDataPath(ctx context.Context) (string, error) {
	log := r.logger.WithFields(logrus.Fields{
		"dataupload": r.dataUploadName,
	})

	du := &velerov2alpha1api.DataUpload{}
	err := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		err := r.client.Get(ctx, types.NamespacedName{
			Namespace: r.namespace,
			Name:      r.dataUploadName,
		}, du)

		if apierrors.IsNotFound(err) {
			return false, nil
		}

		if err != nil {
			return true, errors.Wrapf(err, "error to get du %s", r.dataUploadName)
		}

		if du.Status.Phase == velerov2alpha1api.DataUploadPhaseInProgress {
			return true, nil
		} else {
			return false, nil
		}
	})

	if err != nil {
		log.WithError(err).Error("Failed to wait du")
		return "", errors.Wrap(err, "error waiting for du")
	}

	r.dataUpload = du

	log.Info("Run cancelable dataUpload")

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataUploadCompleted,
		OnFailed:    r.OnDataUploadFailed,
		OnCancelled: r.OnDataUploadCancelled,
		OnProgress:  r.OnDataUploadProgress,
	}

	dp, err := r.dataPathMgr.CreateGenericDataPath(du.Name, dataUploadDownloadRequestor, ctx, r.client, du.Namespace, callbacks, log)
	if err != nil {
		return "", errors.Wrap(err, "error to create data path")
	}

	log.Debug("Async fs br created")

	if err := dp.Init(ctx, &datapath.InitParam{
		BSLName:           du.Spec.BackupStorageLocation,
		SourceNamespace:   du.Spec.SourceNamespace,
		UploaderType:      GetUploaderType(du.Spec.DataMover),
		RepositoryType:    velerov1api.BackupRepositoryTypeKopia,
		RepoIdentifier:    "",
		RepositoryEnsurer: r.repoEnsurer,
		CredentialGetter:  r.credentialGetter,
	}); err != nil {
		return "", errors.Wrap(err, "error to initialize data path")
	}

	log.Info("Async fs br init")

	tags := map[string]string{
		velerov1api.AsyncOperationIDLabel: du.Labels[velerov1api.AsyncOperationIDLabel],
	}

	if err := dp.StartBackup(r.sourceTargetPath, du.Spec.DataMoverConfig, &datapath.BackupStartParam{
		RealSource:     GetRealSource(du.Spec.SourceNamespace, du.Spec.SourcePVC),
		ParentSnapshot: "",
		ForceFull:      false,
		Tags:           tags,
	}); err != nil {
		return "", errors.Wrap(err, "error starting data path backup")
	}

	log.Info("Async fs backup data path started")
	r.eventRecorder.Event(du, false, datapath.EventReasonStarted, "Data path for %s started", du.Name)

	result := ""
	select {
	case <-ctx.Done():
		err = errors.New("timed out waiting for fs backup to complete")
		break
	case res := <-r.resultSignal:
		err = res.err
		result = res.result
		break
	}

	if err != nil {
		log.WithError(err).Error("Async fs backup was not completed")
	}

	r.eventRecorder.EndingEvent(du, false, datapath.EventReasonStopped, "Data path for %s stopped", du.Name)

	return result, err
}

func (r *BackupMicroService) Shutdown() {
	r.eventRecorder.Shutdown()
	r.closeDataPath(r.ctx, r.dataUploadName)

	if r.duHandler != nil {
		if err := r.duInformer.RemoveEventHandler(r.duHandler); err != nil {
			r.logger.WithError(err).Warn("Failed to remove pod handler")
		}
	}
}

var funcMarshal = json.Marshal

func (r *BackupMicroService) OnDataUploadCompleted(ctx context.Context, namespace string, duName string, result datapath.Result) {
	log := r.logger.WithField("dataupload", duName)

	backupBytes, err := funcMarshal(result.Backup)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal backup result %v", result.Backup)
		r.resultSignal <- dataPathResult{
			err: errors.Wrapf(err, "Failed to marshal backup result %v", result.Backup),
		}
	} else {
		r.eventRecorder.Event(r.dataUpload, false, datapath.EventReasonCompleted, string(backupBytes))
		r.resultSignal <- dataPathResult{
			result: string(backupBytes),
		}
	}

	log.Info("Async fs backup completed")
}

func (r *BackupMicroService) OnDataUploadFailed(ctx context.Context, namespace string, duName string, err error) {
	log := r.logger.WithField("dataupload", duName)
	log.WithError(err).Error("Async fs backup data path failed")

	r.eventRecorder.Event(r.dataUpload, false, datapath.EventReasonFailed, "Data path for data upload %s failed, error %v", r.dataUploadName, err)
	r.resultSignal <- dataPathResult{
		err: errors.Wrapf(err, "Data path for data upload %s failed", r.dataUploadName),
	}
}

func (r *BackupMicroService) OnDataUploadCancelled(ctx context.Context, namespace string, duName string) {
	log := r.logger.WithField("dataupload", duName)
	log.Warn("Async fs backup data path canceled")

	r.eventRecorder.Event(r.dataUpload, false, datapath.EventReasonCancelled, "Data path for data upload %s canceled", duName)
	r.resultSignal <- dataPathResult{
		err: errors.New(datapath.ErrCancelled),
	}
}

func (r *BackupMicroService) OnDataUploadProgress(ctx context.Context, namespace string, duName string, progress *uploader.Progress) {
	log := r.logger.WithFields(logrus.Fields{
		"dataupload": duName,
	})

	progressBytes, err := funcMarshal(progress)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal progress %v", progress)
		return
	}

	r.eventRecorder.Event(r.dataUpload, false, datapath.EventReasonProgress, string(progressBytes))
}

func (r *BackupMicroService) closeDataPath(ctx context.Context, duName string) {
	fsBackup := r.dataPathMgr.GetAsyncBR(duName)
	if fsBackup != nil {
		fsBackup.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(duName)
}

func (r *BackupMicroService) cancelDataUpload(du *velerov2alpha1api.DataUpload) {
	r.logger.WithField("DataUpload", du.Name).Info("Data upload is being canceled")

	r.eventRecorder.Event(du, false, datapath.EventReasonCancelling, "Canceling for data upload %s", du.Name)

	fsBackup := r.dataPathMgr.GetAsyncBR(du.Name)
	if fsBackup == nil {
		r.OnDataUploadCancelled(r.ctx, du.GetNamespace(), du.GetName())
		r.eventRecorder.EndingEvent(du, false, datapath.EventReasonStopped, "Data path for %s exited without start", du.Name)
	} else {
		fsBackup.Cancel()
	}
}
