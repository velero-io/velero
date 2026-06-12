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

package podvolume

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
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/kube"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	podVolumeRequestor = "snapshot-pod-volume"
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
	pvbName          string
	pvb              *velerov1api.PodVolumeBackup
	sourceTargetPath datapath.AccessPoint

	resultSignal chan dataPathResult

	pvbInformer cache.Informer
	pvbHandler  cachetool.ResourceEventHandlerRegistration
	nodeName    string
}

type dataPathResult struct {
	err    error
	result string
}

func NewBackupMicroService(ctx context.Context, client client.Client, kubeClient kubernetes.Interface, pvbName string, namespace string, nodeName string,
	sourceTargetPath datapath.AccessPoint, dataPathMgr *datapath.Manager, repoEnsurer *repository.Ensurer, cred *credentials.CredentialGetter,
	pvbInformer cache.Informer, log logrus.FieldLogger) *BackupMicroService {
	return &BackupMicroService{
		ctx:              ctx,
		client:           client,
		kubeClient:       kubeClient,
		credentialGetter: cred,
		logger:           log,
		repoEnsurer:      repoEnsurer,
		dataPathMgr:      dataPathMgr,
		namespace:        namespace,
		pvbName:          pvbName,
		sourceTargetPath: sourceTargetPath,
		nodeName:         nodeName,
		resultSignal:     make(chan dataPathResult),
		pvbInformer:      pvbInformer,
	}
}

func (r *BackupMicroService) Init() error {
	r.eventRecorder = kube.NewEventRecorder(r.kubeClient, r.client.Scheme(), r.pvbName, r.nodeName, r.logger)

	handler, err := r.pvbInformer.AddEventHandler(
		cachetool.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj any, newObj any) {
				oldPvb := oldObj.(*velerov1api.PodVolumeBackup)
				newPvb := newObj.(*velerov1api.PodVolumeBackup)

				if newPvb.Name != r.pvbName {
					return
				}

				if newPvb.Status.Phase != velerov1api.PodVolumeBackupPhaseInProgress {
					return
				}

				if newPvb.Spec.Cancel && !oldPvb.Spec.Cancel {
					r.cancelPodVolumeBackup(newPvb)
				}
			},
		},
	)

	if err != nil {
		return errors.Wrap(err, "error adding PVB handler")
	}

	r.pvbHandler = handler

	return err
}

func (r *BackupMicroService) RunCancelableDataPath(ctx context.Context) (string, error) {
	log := r.logger.WithFields(logrus.Fields{
		"PVB": r.pvbName,
	})

	pvb := &velerov1api.PodVolumeBackup{}
	err := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		err := r.client.Get(ctx, types.NamespacedName{
			Namespace: r.namespace,
			Name:      r.pvbName,
		}, pvb)

		if apierrors.IsNotFound(err) {
			return false, nil
		}

		if err != nil {
			return true, errors.Wrapf(err, "error to get PVB %s", r.pvbName)
		}

		if pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseInProgress {
			return true, nil
		} else {
			return false, nil
		}
	})

	if err != nil {
		log.WithError(err).Error("Failed to wait PVB")
		return "", errors.Wrap(err, "error waiting for PVB")
	}

	r.pvb = pvb

	log.Info("Run cancelable PVB")

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataPathCompleted,
		OnFailed:    r.OnDataPathFailed,
		OnCancelled: r.OnDataPathCancelled,
		OnProgress:  r.OnDataPathProgress,
	}

	fsBackup, err := r.dataPathMgr.CreateFileSystemBR(pvb.Name, podVolumeRequestor, ctx, r.client, pvb.Namespace, callbacks, log)
	if err != nil {
		return "", errors.Wrap(err, "error to create data path")
	}

	log.Debug("Async fs br created")

	if err := fsBackup.Init(ctx, &datapath.FSBRInitParam{
		BSLName:           pvb.Spec.BackupStorageLocation,
		SourceNamespace:   pvb.Spec.Pod.Namespace,
		UploaderType:      pvb.Spec.UploaderType,
		RepositoryType:    velerov1api.BackupRepositoryTypeKopia,
		RepoIdentifier:    "",
		RepositoryEnsurer: r.repoEnsurer,
		CredentialGetter:  r.credentialGetter,
	}); err != nil {
		return "", errors.Wrap(err, "error to initialize data path")
	}

	log.Info("Async fs br init")

	tags := map[string]string{}

	if err := fsBackup.StartBackup(r.sourceTargetPath, pvb.Spec.UploaderSettings, &datapath.FSBRStartParam{
		RealSource:     GetRealSource(pvb),
		ParentSnapshot: "",
		ForceFull:      false,
		Tags:           tags,
	}); err != nil {
		return "", errors.Wrap(err, "error starting data path backup")
	}

	log.Info("Async fs backup data path started")
	r.eventRecorder.Event(pvb, false, datapath.EventReasonStarted, "Data path for %s started", pvb.Name)

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

	r.eventRecorder.EndingEvent(pvb, false, datapath.EventReasonStopped, "Data path for %s stopped", pvb.Name)

	return result, err
}

func (r *BackupMicroService) Shutdown() {
	r.eventRecorder.Shutdown()
	r.closeDataPath(r.ctx, r.pvbName)

	if r.pvbHandler != nil {
		if err := r.pvbInformer.RemoveEventHandler(r.pvbHandler); err != nil {
			r.logger.WithError(err).Warn("Failed to remove pod handler")
		}
	}
}

var funcMarshal = json.Marshal

func (r *BackupMicroService) OnDataPathCompleted(ctx context.Context, namespace string, pvbName string, result datapath.Result) {
	log := r.logger.WithField("PVB", pvbName)

	backupBytes, err := funcMarshal(result.Backup)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal backup result %v", result.Backup)
		r.resultSignal <- dataPathResult{
			err: errors.Wrapf(err, "Failed to marshal backup result %v", result.Backup),
		}
	} else {
		r.eventRecorder.Event(r.pvb, false, datapath.EventReasonCompleted, string(backupBytes))
		r.resultSignal <- dataPathResult{
			result: string(backupBytes),
		}
	}

	log.Info("Async fs backup completed")
}

func (r *BackupMicroService) OnDataPathFailed(ctx context.Context, namespace string, pvbName string, err error) {
	log := r.logger.WithField("PVB", pvbName)
	log.WithError(err).Error("Async fs backup data path failed")

	r.eventRecorder.Event(r.pvb, false, datapath.EventReasonFailed, "Data path for PVB %s failed, error %v", r.pvbName, err)
	r.resultSignal <- dataPathResult{
		err: errors.Wrapf(err, "Data path for PVB %s failed", r.pvbName),
	}
}

func (r *BackupMicroService) OnDataPathCancelled(ctx context.Context, namespace string, pvbName string) {
	log := r.logger.WithField("PVB", pvbName)
	log.Warn("Async fs backup data path canceled")

	r.eventRecorder.Event(r.pvb, false, datapath.EventReasonCancelled, "Data path for PVB %s canceled", pvbName)
	r.resultSignal <- dataPathResult{
		err: errors.New(datapath.ErrCancelled),
	}
}

func (r *BackupMicroService) OnDataPathProgress(ctx context.Context, namespace string, pvbName string, progress *uploader.Progress) {
	log := r.logger.WithFields(logrus.Fields{
		"PVB": pvbName,
	})

	progressBytes, err := funcMarshal(progress)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal progress %v", progress)
		return
	}

	r.eventRecorder.Event(r.pvb, false, datapath.EventReasonProgress, string(progressBytes))
}

func (r *BackupMicroService) closeDataPath(ctx context.Context, duName string) {
	fsBackup := r.dataPathMgr.GetAsyncBR(duName)
	if fsBackup != nil {
		fsBackup.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(duName)
}

func (r *BackupMicroService) cancelPodVolumeBackup(pvb *velerov1api.PodVolumeBackup) {
	r.logger.WithField("PVB", pvb.Name).Info("PVB is being canceled")

	r.eventRecorder.Event(pvb, false, datapath.EventReasonCancelling, "Canceling for PVB %s", pvb.Name)

	fsBackup := r.dataPathMgr.GetAsyncBR(pvb.Name)
	if fsBackup == nil {
		r.OnDataPathCancelled(r.ctx, pvb.GetNamespace(), pvb.GetName())
		r.eventRecorder.EndingEvent(pvb, false, datapath.EventReasonStopped, "Data path for %s exited without start", pvb.Name)
	} else {
		fsBackup.Cancel()
	}
}
