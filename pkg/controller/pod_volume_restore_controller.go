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

package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/vmware-tanzu/velero/internal/credentials"
	veleroapishared "github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/restorehelper"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

func NewPodVolumeRestoreReconciler(client client.Client, ensurer *repository.Ensurer,
	credentialGetter *credentials.CredentialGetter, logger logrus.FieldLogger) *PodVolumeRestoreReconciler {
	return &PodVolumeRestoreReconciler{
		Client:            client,
		logger:            logger.WithField("controller", "PodVolumeRestore"),
		repositoryEnsurer: ensurer,
		credentialGetter:  credentialGetter,
		fileSystem:        filesystem.NewFileSystem(),
		clock:             &clocks.RealClock{},
		dataPathMgr:       datapath.NewManager(1),
	}
}

type PodVolumeRestoreReconciler struct {
	client.Client
	logger            logrus.FieldLogger
	repositoryEnsurer *repository.Ensurer
	credentialGetter  *credentials.CredentialGetter
	fileSystem        filesystem.Interface
	clock             clocks.WithTickerAndDelayedExecution
	dataPathMgr       *datapath.Manager
}

// +kubebuilder:rbac:groups=velero.io,resources=podvolumerestores,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=podvolumerestores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumes,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumerclaims,verbs=get

func (c *PodVolumeRestoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.logger.WithField("PodVolumeRestore", req.String())

	pvr := &velerov1api.PodVolumeRestore{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: req.Name}, pvr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warn("PodVolumeRestore not found, skip")
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("Unable to get the PodVolumeRestore")
		return ctrl.Result{}, err
	}
	log = log.WithField("pod", fmt.Sprintf("%s/%s", pvr.Spec.Pod.Namespace, pvr.Spec.Pod.Name))
	if len(pvr.OwnerReferences) == 1 {
		log = log.WithField("restore", fmt.Sprintf("%s/%s", pvr.Namespace, pvr.OwnerReferences[0].Name))
	}

	shouldProcess, pod, err := c.shouldProcess(ctx, log, pvr)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !shouldProcess {
		return ctrl.Result{}, nil
	}

	initContainerIndex := getInitContainerIndex(pod)
	if initContainerIndex > 0 {
		log.Warnf(`Init containers before the %s container may cause issues
		          if they interfere with volumes being restored: %s index %d`, restorehelper.WaitInitContainer, restorehelper.WaitInitContainer, initContainerIndex)
	}

	log.Info("Restore starting")

	callbacks := datapath.Callbacks{
		OnCompleted: c.OnDataPathCompleted,
		OnFailed:    c.OnDataPathFailed,
		OnCancelled: c.OnDataPathCancelled,
		OnProgress:  c.OnDataPathProgress,
	}

	fsRestore, err := c.dataPathMgr.CreateFileSystemBR(pvr.Name, pVBRRequestor, ctx, c.Client, pvr.Namespace, callbacks, log)
	if err != nil {
		if err == datapath.ConcurrentLimitExceed {
			return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, nil
		} else {
			return c.errorOut(ctx, pvr, err, "error to create data path", log)
		}
	}

	original := pvr.DeepCopy()
	pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseInProgress
	pvr.Status.StartTimestamp = &metav1.Time{Time: c.clock.Now()}
	if err = c.Patch(ctx, pvr, client.MergeFrom(original)); err != nil {
		return c.errorOut(ctx, pvr, err, "error to update status to in progress", log)
	}

	volumePath, err := exposer.GetPodVolumeHostPath(ctx, pod, pvr.Spec.Volume, c.Client, c.fileSystem, log)
	if err != nil {
		return c.errorOut(ctx, pvr, err, "error exposing host path for pod volume", log)
	}

	log.WithField("path", volumePath.ByPath).Debugf("Found host path")

	if err := fsRestore.Init(ctx, pvr.Spec.BackupStorageLocation, pvr.Spec.SourceNamespace, pvr.Spec.UploaderType,
		podvolume.GetPvrRepositoryType(pvr), pvr.Spec.RepoIdentifier, c.repositoryEnsurer, c.credentialGetter); err != nil {
		return c.errorOut(ctx, pvr, err, "error to initialize data path", log)
	}

	if err := fsRestore.StartRestore(pvr.Spec.SnapshotID, volumePath); err != nil {
		return c.errorOut(ctx, pvr, err, "error starting data path restore", log)
	}

	log.WithField("path", volumePath.ByPath).Info("Async fs restore data path started")

	return ctrl.Result{}, nil
}

func (c *PodVolumeRestoreReconciler) errorOut(ctx context.Context, pvr *velerov1api.PodVolumeRestore, err error, msg string, log logrus.FieldLogger) (ctrl.Result, error) {
	c.closeDataPath(ctx, pvr.Name)
	_ = UpdatePVRStatusToFailed(ctx, c.Client, pvr, errors.WithMessage(err, msg).Error(), c.clock.Now(), log)
	return ctrl.Result{}, err
}

func UpdatePVRStatusToFailed(ctx context.Context, c client.Client, pvb *velerov1api.PodVolumeRestore, errString string, time time.Time, log logrus.FieldLogger) error {
	original := pvb.DeepCopy()
	pvb.Status.Phase = velerov1api.PodVolumeRestorePhaseFailed
	pvb.Status.Message = errString
	pvb.Status.CompletionTimestamp = &metav1.Time{Time: time}

	err := c.Patch(ctx, pvb, client.MergeFrom(original))
	if err != nil {
		log.WithError(err).Error("error updating PodVolumeRestore status")
	}

	return err
}

func (c *PodVolumeRestoreReconciler) shouldProcess(ctx context.Context, log logrus.FieldLogger, pvr *velerov1api.PodVolumeRestore) (bool, *corev1api.Pod, error) {
	if !isPVRNew(pvr) {
		log.Debug("PodVolumeRestore is not new, skip")
		return false, nil, nil
	}

	// we filter the pods during the initialization of cache, if we can get a pod here, the pod must be in the same node with the controller
	// so we don't need to compare the node anymore
	pod := &corev1api.Pod{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: pvr.Spec.Pod.Namespace, Name: pvr.Spec.Pod.Name}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Debug("Pod not found on this node, skip")
			return false, nil, nil
		}
		log.WithError(err).Error("Unable to get pod")
		return false, nil, err
	}

	if !isInitContainerRunning(pod) {
		log.Debug("Pod is not running restore-wait init container, skip")
		return false, nil, nil
	}

	return true, pod, nil
}

func (c *PodVolumeRestoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// The pod may not being scheduled at the point when its PVRs are initially reconciled.
	// By watching the pods, we can trigger the PVR reconciliation again once the pod is finally scheduled on the node.
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.PodVolumeRestore{}).
		Watches(&source.Kind{Type: &corev1api.Pod{}}, handler.EnqueueRequestsFromMapFunc(c.findVolumeRestoresForPod)).
		Complete(c)
}

func (c *PodVolumeRestoreReconciler) findVolumeRestoresForPod(pod client.Object) []reconcile.Request {
	list := &velerov1api.PodVolumeRestoreList{}
	options := &client.ListOptions{
		LabelSelector: labels.Set(map[string]string{
			velerov1api.PodUIDLabel: string(pod.GetUID()),
		}).AsSelector(),
	}
	if err := c.List(context.TODO(), list, options); err != nil {
		c.logger.WithField("pod", fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())).WithError(err).
			Error("unable to list PodVolumeRestores")
		return []reconcile.Request{}
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i, item := range list.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			},
		}
	}
	return requests
}

func isPVRNew(pvr *velerov1api.PodVolumeRestore) bool {
	return pvr.Status.Phase == "" || pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseNew
}

func isInitContainerRunning(pod *corev1api.Pod) bool {
	// Pod volume wait container can be anywhere in the list of init containers, but must be running.
	i := getInitContainerIndex(pod)
	return i >= 0 &&
		len(pod.Status.InitContainerStatuses)-1 >= i &&
		pod.Status.InitContainerStatuses[i].State.Running != nil
}

func getInitContainerIndex(pod *corev1api.Pod) int {
	// Pod volume wait container can be anywhere in the list of init containers so locate it.
	for i, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name == restorehelper.WaitInitContainer {
			return i
		}
	}

	return -1
}

func (c *PodVolumeRestoreReconciler) OnDataPathCompleted(ctx context.Context, namespace string, pvrName string, result datapath.Result) {
	defer c.closeDataPath(ctx, pvrName)

	log := c.logger.WithField("pvr", pvrName)

	log.WithField("PVR", pvrName).Info("Async fs restore data path completed")

	var pvr velerov1api.PodVolumeRestore
	if err := c.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); err != nil {
		log.WithError(err).Warn("Failed to get PVR on completion")
		return
	}

	volumePath := result.Restore.Target.ByPath
	if volumePath == "" {
		_, _ = c.errorOut(ctx, &pvr, errors.New("path is empty"), "invalid restore target", log)
		return
	}

	// Remove the .velero directory from the restored volume (it may contain done files from previous restores
	// of this volume, which we don't want to carry over). If this fails for any reason, log and continue, since
	// this is non-essential cleanup (the done files are named based on restore UID and the init container looks
	// for the one specific to the restore being executed).
	if err := os.RemoveAll(filepath.Join(volumePath, ".velero")); err != nil {
		log.WithError(err).Warnf("error removing .velero directory from directory %s", volumePath)
	}

	var restoreUID types.UID
	for _, owner := range pvr.OwnerReferences {
		if boolptr.IsSetToTrue(owner.Controller) {
			restoreUID = owner.UID
			break
		}
	}

	// Create the .velero directory within the volume dir so we can write a done file
	// for this restore.
	if err := os.MkdirAll(filepath.Join(volumePath, ".velero"), 0755); err != nil {
		_, _ = c.errorOut(ctx, &pvr, err, "error creating .velero directory for done file", log)
		return
	}

	// Write a done file with name=<restore-uid> into the just-created .velero dir
	// within the volume. The velero init container on the pod is waiting
	// for this file to exist in each restored volume before completing.
	if err := os.WriteFile(filepath.Join(volumePath, ".velero", string(restoreUID)), nil, 0644); err != nil { //nolint:gosec
		_, _ = c.errorOut(ctx, &pvr, err, "error writing done file", log)
		return
	}

	original := pvr.DeepCopy()
	pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseCompleted
	pvr.Status.CompletionTimestamp = &metav1.Time{Time: c.clock.Now()}
	if err := c.Patch(ctx, &pvr, client.MergeFrom(original)); err != nil {
		log.WithError(err).Error("error updating PodVolumeRestore status")
	}

	log.Info("Restore completed")
}

func (c *PodVolumeRestoreReconciler) OnDataPathFailed(ctx context.Context, namespace string, pvrName string, err error) {
	defer c.closeDataPath(ctx, pvrName)

	log := c.logger.WithField("pvr", pvrName)

	log.WithError(err).Error("Async fs restore data path failed")

	var pvr velerov1api.PodVolumeRestore
	if getErr := c.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVR on failure")
	} else {
		_, _ = c.errorOut(ctx, &pvr, err, "data path restore failed", log)
	}
}

func (c *PodVolumeRestoreReconciler) OnDataPathCancelled(ctx context.Context, namespace string, pvrName string) {
	defer c.closeDataPath(ctx, pvrName)

	log := c.logger.WithField("pvr", pvrName)

	log.Warn("Async fs restore data path canceled")

	var pvr velerov1api.PodVolumeRestore
	if getErr := c.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVR on cancel")
	} else {
		_, _ = c.errorOut(ctx, &pvr, errors.New("PVR is canceled"), "data path restore canceled", log)
	}
}

func (c *PodVolumeRestoreReconciler) OnDataPathProgress(ctx context.Context, namespace string, pvrName string, progress *uploader.Progress) {
	log := c.logger.WithField("pvr", pvrName)

	var pvr velerov1api.PodVolumeRestore
	if err := c.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); err != nil {
		log.WithError(err).Warn("Failed to get PVB on progress")
		return
	}

	original := pvr.DeepCopy()
	pvr.Status.Progress = veleroapishared.DataMoveOperationProgress{TotalBytes: progress.TotalBytes, BytesDone: progress.BytesDone}

	if err := c.Patch(ctx, &pvr, client.MergeFrom(original)); err != nil {
		log.WithError(err).Error("Failed to update progress")
	}
}

func (c *PodVolumeRestoreReconciler) closeDataPath(ctx context.Context, pvbName string) {
	fsRestore := c.dataPathMgr.GetAsyncBR(pvbName)
	if fsRestore != nil {
		fsRestore.Close(ctx)
	}

	c.dataPathMgr.RemoveAsyncBR(pvbName)
}
