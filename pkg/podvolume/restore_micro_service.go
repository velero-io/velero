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
	"fmt"
	"os"
	"path/filepath"
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
	pvrName          string
	pvr              *velerov1api.PodVolumeRestore
	sourceTargetPath datapath.AccessPoint

	resultSignal chan dataPathResult

	pvrInformer cache.Informer
	pvrHandler  cachetool.ResourceEventHandlerRegistration
	nodeName    string
	cacheDir    string
}

func NewRestoreMicroService(ctx context.Context, client client.Client, kubeClient kubernetes.Interface, pvrName string, namespace string, nodeName string,
	sourceTargetPath datapath.AccessPoint, dataPathMgr *datapath.Manager, repoEnsurer *repository.Ensurer, cred *credentials.CredentialGetter,
	pvrInformer cache.Informer, cacheDir string, log logrus.FieldLogger) *RestoreMicroService {
	return &RestoreMicroService{
		ctx:              ctx,
		client:           client,
		kubeClient:       kubeClient,
		credentialGetter: cred,
		logger:           log,
		repoEnsurer:      repoEnsurer,
		dataPathMgr:      dataPathMgr,
		namespace:        namespace,
		pvrName:          pvrName,
		sourceTargetPath: sourceTargetPath,
		nodeName:         nodeName,
		resultSignal:     make(chan dataPathResult),
		pvrInformer:      pvrInformer,
		cacheDir:         cacheDir,
	}
}

func (r *RestoreMicroService) Init() error {
	r.eventRecorder = kube.NewEventRecorder(r.kubeClient, r.client.Scheme(), r.pvrName, r.nodeName, r.logger)

	handler, err := r.pvrInformer.AddEventHandler(
		cachetool.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj any, newObj any) {
				oldPvr := oldObj.(*velerov1api.PodVolumeRestore)
				newPvr := newObj.(*velerov1api.PodVolumeRestore)

				if newPvr.Name != r.pvrName {
					return
				}

				if newPvr.Status.Phase != velerov1api.PodVolumeRestorePhaseInProgress {
					return
				}

				if newPvr.Spec.Cancel && !oldPvr.Spec.Cancel {
					r.cancelPodVolumeRestore(newPvr)
				}
			},
		},
	)

	if err != nil {
		return errors.Wrap(err, "error adding PVR handler")
	}

	r.pvrHandler = handler

	return err
}

func (r *RestoreMicroService) RunCancelableDataPath(ctx context.Context) (string, error) {
	log := r.logger.WithFields(logrus.Fields{
		"PVR": r.pvrName,
	})

	pvr := &velerov1api.PodVolumeRestore{}
	err := wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		err := r.client.Get(ctx, types.NamespacedName{
			Namespace: r.namespace,
			Name:      r.pvrName,
		}, pvr)
		if apierrors.IsNotFound(err) {
			return false, nil
		}

		if err != nil {
			return true, errors.Wrapf(err, "error to get PVR %s", r.pvrName)
		}

		if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseInProgress {
			return true, nil
		} else {
			return false, nil
		}
	})
	if err != nil {
		log.WithError(err).Error("Failed to wait PVR")
		return "", errors.Wrap(err, "error waiting for PVR")
	}

	r.pvr = pvr

	log.Info("Run cancelable PVR")

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnPvrCompleted,
		OnFailed:    r.OnPvrFailed,
		OnCancelled: r.OnPvrCancelled,
		OnProgress:  r.OnPvrProgress,
	}

	fsRestore, err := r.dataPathMgr.CreateFileSystemBR(pvr.Name, podVolumeRequestor, ctx, r.client, pvr.Namespace, callbacks, log)
	if err != nil {
		return "", errors.Wrap(err, "error to create data path")
	}

	log.Debug("Async fs br created")

	if err := fsRestore.Init(ctx,
		&datapath.FSBRInitParam{
			BSLName:           pvr.Spec.BackupStorageLocation,
			SourceNamespace:   pvr.Spec.SourceNamespace,
			UploaderType:      pvr.Spec.UploaderType,
			RepositoryType:    velerov1api.BackupRepositoryTypeKopia,
			RepoIdentifier:    "",
			RepositoryEnsurer: r.repoEnsurer,
			CredentialGetter:  r.credentialGetter,
			CacheDir:          r.cacheDir,
		}); err != nil {
		return "", errors.Wrap(err, "error to initialize data path")
	}

	log.Info("Async fs br init")

	if err := fsRestore.StartRestore(pvr.Spec.SnapshotID, r.sourceTargetPath, pvr.Spec.UploaderSettings); err != nil {
		return "", errors.Wrap(err, "error starting data path restore")
	}

	log.Info("Async fs restore data path started")
	r.eventRecorder.Event(pvr, false, datapath.EventReasonStarted, "Data path for %s started", pvr.Name)

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

	r.eventRecorder.EndingEvent(pvr, false, datapath.EventReasonStopped, "Data path for %s stopped", pvr.Name)

	return result, err
}

func (r *RestoreMicroService) Shutdown() {
	r.eventRecorder.Shutdown()
	r.closeDataPath(r.ctx, r.pvrName)

	if r.pvrHandler != nil {
		if err := r.pvrInformer.RemoveEventHandler(r.pvrHandler); err != nil {
			r.logger.WithError(err).Warn("Failed to remove pod handler")
		}
	}
}

var funcWriteCompletionMark = writeCompletionMark

func (r *RestoreMicroService) OnPvrCompleted(ctx context.Context, namespace string, pvrName string, result datapath.Result) {
	log := r.logger.WithField("PVR", pvrName)

	err := funcWriteCompletionMark(r.pvr, result.Restore, log)
	if err != nil {
		log.WithError(err).Warnf("Failed to write completion mark, restored pod may failed to start")
	}

	restoreBytes, err := funcMarshal(result.Restore)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal restore result %v", result.Restore)
		r.recordPvrFailed(fmt.Sprintf("error marshaling restore result %v", result.Restore), err)
	} else {
		r.eventRecorder.Event(r.pvr, false, datapath.EventReasonCompleted, string(restoreBytes))
		r.resultSignal <- dataPathResult{
			result: string(restoreBytes),
		}
	}

	log.Info("Async fs restore data path completed")
}

func (r *RestoreMicroService) recordPvrFailed(msg string, err error) {
	evtMsg := fmt.Sprintf("%s, error %v", msg, err)
	r.eventRecorder.Event(r.pvr, false, datapath.EventReasonFailed, evtMsg)
	r.resultSignal <- dataPathResult{
		err: errors.Wrap(err, msg),
	}
}

func (r *RestoreMicroService) OnPvrFailed(ctx context.Context, namespace string, pvrName string, err error) {
	log := r.logger.WithField("PVR", pvrName)
	log.WithError(err).Error("Async fs restore data path failed")

	r.recordPvrFailed(fmt.Sprintf("Data path for PVR %s failed", pvrName), err)
}

func (r *RestoreMicroService) OnPvrCancelled(ctx context.Context, namespace string, pvrName string) {
	log := r.logger.WithField("PVR", pvrName)
	log.Warn("Async fs restore data path canceled")

	r.eventRecorder.Event(r.pvr, false, datapath.EventReasonCancelled, "Data path for PVR %s canceled", pvrName)
	r.resultSignal <- dataPathResult{
		err: errors.New(datapath.ErrCancelled),
	}
}

func (r *RestoreMicroService) OnPvrProgress(ctx context.Context, namespace string, pvrName string, progress *uploader.Progress) {
	log := r.logger.WithFields(logrus.Fields{
		"PVR": pvrName,
	})

	progressBytes, err := funcMarshal(progress)
	if err != nil {
		log.WithError(err).Errorf("Failed to marshal progress %v", progress)
		return
	}

	r.eventRecorder.Event(r.pvr, false, datapath.EventReasonProgress, string(progressBytes))
}

func (r *RestoreMicroService) closeDataPath(ctx context.Context, pvrName string) {
	fsRestore := r.dataPathMgr.GetAsyncBR(pvrName)
	if fsRestore != nil {
		fsRestore.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(pvrName)
}

func (r *RestoreMicroService) cancelPodVolumeRestore(pvr *velerov1api.PodVolumeRestore) {
	r.logger.WithField("PVR", pvr.Name).Info("PVR is being canceled")

	r.eventRecorder.Event(pvr, false, datapath.EventReasonCancelling, "Canceling for PVR %s", pvr.Name)

	fsBackup := r.dataPathMgr.GetAsyncBR(pvr.Name)
	if fsBackup == nil {
		r.OnPvrCancelled(r.ctx, pvr.GetNamespace(), pvr.GetName())
		r.eventRecorder.EndingEvent(pvr, false, datapath.EventReasonStopped, "Data path for %s exited without start", pvr.Name)
	} else {
		fsBackup.Cancel()
	}
}

var funcRemoveAll = os.RemoveAll
var funcMkdirAll = os.MkdirAll
var funcWriteFile = os.WriteFile

func writeCompletionMark(pvr *velerov1api.PodVolumeRestore, result datapath.RestoreResult, log logrus.FieldLogger) error {
	volumePath := result.Target.ByPath
	if volumePath == "" {
		return errors.New("target volume is empty in restore result")
	}

	// Remove the .velero directory from the restored volume (it may contain done files from previous restores
	// of this volume, which we don't want to carry over). If this fails for any reason, log and continue, since
	// this is non-essential cleanup (the done files are named based on restore UID and the init container looks
	// for the one specific to the restore being executed).
	if err := funcRemoveAll(filepath.Join(volumePath, ".velero")); err != nil {
		log.WithError(err).Warnf("Failed to remove .velero directory from directory %s", volumePath)
	}

	if len(pvr.OwnerReferences) == 0 {
		return errors.New("error finding restore UID")
	}

	restoreUID := pvr.OwnerReferences[0].UID

	// Create the .velero directory within the volume dir so we can write a done file
	// for this restore.
	if err := funcMkdirAll(filepath.Join(volumePath, ".velero"), 0755); err != nil {
		return errors.Wrapf(err, "error creating .velero directory for done file")
	}

	// Write a done file with name=<restore-uid> into the just-created .velero dir
	// within the volume. The velero init container on the pod is waiting
	// for this file to exist in each restored volume before completing.
	if err := funcWriteFile(filepath.Join(volumePath, ".velero", string(restoreUID)), nil, 0644); err != nil {
		return errors.Wrapf(err, "error writing done file")
	}

	return nil
}
