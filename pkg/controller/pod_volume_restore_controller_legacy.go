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

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func InitLegacyPodVolumeRestoreReconciler(client client.Client, mgr manager.Manager, kubeClient kubernetes.Interface, dataPathMgr *datapath.Manager, namespace string,
	resourceTimeout time.Duration, logger logrus.FieldLogger) error {
	log := logger.WithField("controller", "PodVolumeRestoreLegacy")

	credentialFileStore, err := credentials.NewNamespacedFileStore(client, namespace, credentials.DefaultStoreDirectory(), filesystem.NewFileSystem())
	if err != nil {
		return errors.Wrapf(err, "error creating credentials file store")
	}

	credSecretStore, err := credentials.NewNamespacedSecretStore(client, namespace)
	if err != nil {
		return errors.Wrapf(err, "error creating secret file store")
	}

	credentialGetter := &credentials.CredentialGetter{FromFile: credentialFileStore, FromSecret: credSecretStore}
	ensurer := repository.NewEnsurer(client, log, resourceTimeout)

	reconciler := &PodVolumeRestoreReconcilerLegacy{
		Client:            client,
		kubeClient:        kubeClient,
		logger:            log,
		repositoryEnsurer: ensurer,
		credentialGetter:  credentialGetter,
		fileSystem:        filesystem.NewFileSystem(),
		clock:             &clocks.RealClock{},
		dataPathMgr:       dataPathMgr,
	}

	if err = reconciler.SetupWithManager(mgr); err != nil {
		return errors.Wrapf(err, "error setup controller manager")
	}

	return nil
}

type PodVolumeRestoreReconcilerLegacy struct {
	client.Client
	kubeClient        kubernetes.Interface
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

func (c *PodVolumeRestoreReconcilerLegacy) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.logger.WithField("PodVolumeRestore", req.NamespacedName.String())
	log.Info("Reconciling PVR by legacy controller")

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

	shouldProcess, pod, err := shouldProcess(ctx, c.Client, log, pvr)
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
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		} else {
			return c.errorOut(ctx, pvr, err, "error to create data path", log)
		}
	}

	original := pvr.DeepCopy()
	pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseInProgress
	pvr.Status.StartTimestamp = &metav1.Time{Time: c.clock.Now()}
	if err = c.Patch(ctx, pvr, client.MergeFrom(original)); err != nil {
		c.closeDataPath(ctx, pvr.Name)
		return c.errorOut(ctx, pvr, err, "error to update status to in progress", log)
	}

	volumePath, err := exposer.GetPodVolumeHostPath(ctx, pod, pvr.Spec.Volume, c.kubeClient, c.fileSystem, log)
	if err != nil {
		c.closeDataPath(ctx, pvr.Name)
		return c.errorOut(ctx, pvr, err, "error exposing host path for pod volume", log)
	}

	log.WithField("path", volumePath.ByPath).Debugf("Found host path")

	if err := fsRestore.Init(ctx, &datapath.FSBRInitParam{
		BSLName:           pvr.Spec.BackupStorageLocation,
		SourceNamespace:   pvr.Spec.SourceNamespace,
		UploaderType:      pvr.Spec.UploaderType,
		RepositoryType:    podvolume.GetPvrRepositoryType(pvr),
		RepoIdentifier:    pvr.Spec.RepoIdentifier,
		RepositoryEnsurer: c.repositoryEnsurer,
		CredentialGetter:  c.credentialGetter,
	}); err != nil {
		c.closeDataPath(ctx, pvr.Name)
		return c.errorOut(ctx, pvr, err, "error to initialize data path", log)
	}

	if err := fsRestore.StartRestore(pvr.Spec.SnapshotID, volumePath, pvr.Spec.UploaderSettings); err != nil {
		c.closeDataPath(ctx, pvr.Name)
		return c.errorOut(ctx, pvr, err, "error starting data path restore", log)
	}

	log.WithField("path", volumePath.ByPath).Info("Async fs restore data path started")

	return ctrl.Result{}, nil
}

func (c *PodVolumeRestoreReconcilerLegacy) errorOut(ctx context.Context, pvr *velerov1api.PodVolumeRestore, err error, msg string, log logrus.FieldLogger) (ctrl.Result, error) {
	_ = UpdatePVRStatusToFailed(ctx, c.Client, pvr, err, msg, c.clock.Now(), log)
	return ctrl.Result{}, err
}

func (c *PodVolumeRestoreReconcilerLegacy) SetupWithManager(mgr ctrl.Manager) error {
	// The pod may not being scheduled at the point when its PVRs are initially reconciled.
	// By watching the pods, we can trigger the PVR reconciliation again once the pod is finally scheduled on the node.
	pred := kube.NewAllEventPredicate(func(obj client.Object) bool {
		pvr := obj.(*velerov1api.PodVolumeRestore)
		return IsLegacyPVR(pvr)
	})

	return ctrl.NewControllerManagedBy(mgr).Named("podvolumerestorelegacy").
		For(&velerov1api.PodVolumeRestore{}, builder.WithPredicates(pred)).
		Watches(&corev1api.Pod{}, handler.EnqueueRequestsFromMapFunc(c.findVolumeRestoresForPod)).
		Complete(c)
}

func (c *PodVolumeRestoreReconcilerLegacy) findVolumeRestoresForPod(ctx context.Context, pod client.Object) []reconcile.Request {
	list := &velerov1api.PodVolumeRestoreList{}
	options := &client.ListOptions{
		LabelSelector: labels.Set(map[string]string{
			velerov1api.PodUIDLabel: string(pod.GetUID()),
		}).AsSelector(),
	}
	if err := c.Client.List(context.TODO(), list, options); err != nil {
		c.logger.WithField("pod", fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())).WithError(err).
			Error("unable to list PodVolumeRestores")
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}
	for _, item := range list.Items {
		if !IsLegacyPVR(&item) {
			continue
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			},
		})
	}
	return requests
}

func (c *PodVolumeRestoreReconcilerLegacy) OnDataPathCompleted(ctx context.Context, namespace string, pvrName string, result datapath.Result) {
	defer c.dataPathMgr.RemoveAsyncBR(pvrName)

	log := c.logger.WithField("pvr", pvrName)

	log.WithField("PVR", pvrName).Info("Async fs restore data path completed")

	var pvr velerov1api.PodVolumeRestore
	if err := c.Client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); err != nil {
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
	if err := os.WriteFile(filepath.Join(volumePath, ".velero", string(restoreUID)), nil, 0644); err != nil { //nolint:gosec // Internal usage. No need to check.
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

func (c *PodVolumeRestoreReconcilerLegacy) OnDataPathFailed(ctx context.Context, namespace string, pvrName string, err error) {
	defer c.dataPathMgr.RemoveAsyncBR(pvrName)

	log := c.logger.WithField("pvr", pvrName)

	log.WithError(err).Error("Async fs restore data path failed")

	var pvr velerov1api.PodVolumeRestore
	if getErr := c.Client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVR on failure")
	} else {
		_, _ = c.errorOut(ctx, &pvr, err, "data path restore failed", log)
	}
}

func (c *PodVolumeRestoreReconcilerLegacy) OnDataPathCancelled(ctx context.Context, namespace string, pvrName string) {
	defer c.dataPathMgr.RemoveAsyncBR(pvrName)

	log := c.logger.WithField("pvr", pvrName)

	log.Warn("Async fs restore data path canceled")

	var pvr velerov1api.PodVolumeRestore
	if getErr := c.Client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVR on cancel")
	} else {
		_, _ = c.errorOut(ctx, &pvr, errors.New("PVR is canceled"), "data path restore canceled", log)
	}
}

func (c *PodVolumeRestoreReconcilerLegacy) OnDataPathProgress(ctx context.Context, namespace string, pvrName string, progress *uploader.Progress) {
	log := c.logger.WithField("pvr", pvrName)

	var pvr velerov1api.PodVolumeRestore
	if err := c.Client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); err != nil {
		log.WithError(err).Warn("Failed to get PVB on progress")
		return
	}

	original := pvr.DeepCopy()
	pvr.Status.Progress = veleroapishared.DataMoveOperationProgress{TotalBytes: progress.TotalBytes, BytesDone: progress.BytesDone}

	if err := c.Client.Patch(ctx, &pvr, client.MergeFrom(original)); err != nil {
		log.WithError(err).Error("Failed to update progress")
	}
}

func (c *PodVolumeRestoreReconcilerLegacy) closeDataPath(ctx context.Context, pvbName string) {
	fsRestore := c.dataPathMgr.GetAsyncBR(pvbName)
	if fsRestore != nil {
		fsRestore.Close(ctx)
	}

	c.dataPathMgr.RemoveAsyncBR(pvbName)
}

func IsLegacyPVR(pvr *velerov1api.PodVolumeRestore) bool {
	return pvr.Spec.UploaderType == uploader.ResticType
}
