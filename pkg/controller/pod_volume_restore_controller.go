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
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	veleroapishared "github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	repository "github.com/vmware-tanzu/velero/pkg/repository/manager"
	"github.com/vmware-tanzu/velero/pkg/restorehelper"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func NewPodVolumeRestoreReconciler(
	client client.Client,
	mgr manager.Manager,
	kubeClient kubernetes.Interface,
	dataPathMgr *datapath.Manager,
	counter *exposer.VgdpCounter,
	nodeName string,
	preparingTimeout time.Duration,
	resourceTimeout time.Duration,
	backupRepoConfigs map[string]string,
	cacheVolumeConfigs *velerotypes.CachePVC,
	podResources corev1api.ResourceRequirements,
	logger logrus.FieldLogger,
	dataMovePriorityClass string,
	privileged bool,
	repoConfigMgr repository.ConfigManager,
	podLabels map[string]string,
	podAnnotations map[string]string,
) *PodVolumeRestoreReconciler {
	return &PodVolumeRestoreReconciler{
		client:                client,
		mgr:                   mgr,
		kubeClient:            kubeClient,
		logger:                logger.WithField("controller", "PodVolumeRestore"),
		nodeName:              nodeName,
		clock:                 &clocks.RealClock{},
		podResources:          podResources,
		backupRepoConfigs:     backupRepoConfigs,
		cacheVolumeConfigs:    cacheVolumeConfigs,
		dataPathMgr:           dataPathMgr,
		vgdpCounter:           counter,
		preparingTimeout:      preparingTimeout,
		resourceTimeout:       resourceTimeout,
		exposer:               exposer.NewPodVolumeExposer(kubeClient, logger),
		cancelledPVR:          make(map[string]time.Time),
		dataMovePriorityClass: dataMovePriorityClass,
		privileged:            privileged,
		repoConfigMgr:         repoConfigMgr,
		podLabels:             podLabels,
		podAnnotations:        podAnnotations,
	}
}

type PodVolumeRestoreReconciler struct {
	client                client.Client
	mgr                   manager.Manager
	kubeClient            kubernetes.Interface
	logger                logrus.FieldLogger
	nodeName              string
	clock                 clocks.WithTickerAndDelayedExecution
	podResources          corev1api.ResourceRequirements
	backupRepoConfigs     map[string]string
	cacheVolumeConfigs    *velerotypes.CachePVC
	exposer               exposer.PodVolumeExposer
	dataPathMgr           *datapath.Manager
	vgdpCounter           *exposer.VgdpCounter
	preparingTimeout      time.Duration
	resourceTimeout       time.Duration
	cancelledPVR          map[string]time.Time
	dataMovePriorityClass string
	privileged            bool
	repoConfigMgr         repository.ConfigManager
	podLabels             map[string]string
	podAnnotations        map[string]string
}

// +kubebuilder:rbac:groups=velero.io,resources=podvolumerestores,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=podvolumerestores/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumes,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumerclaims,verbs=get

func (r *PodVolumeRestoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithField("PodVolumeRestore", req.NamespacedName.String())
	log.Info("Reconciling PVR by advanced controller")

	pvr := &velerov1api.PodVolumeRestore{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: req.Name}, pvr); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warn("PVR not found, skip")
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("Unable to get the PVR")
		return ctrl.Result{}, err
	}

	log = log.WithField("pod", fmt.Sprintf("%s/%s", pvr.Spec.Pod.Namespace, pvr.Spec.Pod.Name))
	if len(pvr.OwnerReferences) == 1 {
		log = log.WithField("restore", fmt.Sprintf("%s/%s", pvr.Namespace, pvr.OwnerReferences[0].Name))
	}

	// Logic for clear resources when pvr been deleted
	if !isPVRInFinalState(pvr) {
		if !controllerutil.ContainsFinalizer(pvr, PodVolumeFinalizer) {
			if err := UpdatePVRWithRetry(ctx, r.client, req.NamespacedName, log, func(pvr *velerov1api.PodVolumeRestore) bool {
				if controllerutil.ContainsFinalizer(pvr, PodVolumeFinalizer) {
					return false
				}

				controllerutil.AddFinalizer(pvr, PodVolumeFinalizer)

				return true
			}); err != nil {
				log.WithError(err).Errorf("failed to add finalizer for PVR %s/%s", pvr.Namespace, pvr.Name)
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		if !pvr.DeletionTimestamp.IsZero() {
			if !pvr.Spec.Cancel {
				log.Warnf("Cancel PVR under phase %s because it is being deleted", pvr.Status.Phase)

				if err := UpdatePVRWithRetry(ctx, r.client, req.NamespacedName, log, func(pvr *velerov1api.PodVolumeRestore) bool {
					if pvr.Spec.Cancel {
						return false
					}

					pvr.Spec.Cancel = true
					pvr.Status.Message = "Cancel PVR because it is being deleted"

					return true
				}); err != nil {
					log.WithError(err).Errorf("failed to set cancel flag for PVR %s/%s", pvr.Namespace, pvr.Name)
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, nil
			}
		}
	} else {
		delete(r.cancelledPVR, pvr.Name)

		if controllerutil.ContainsFinalizer(pvr, PodVolumeFinalizer) {
			if err := UpdatePVRWithRetry(ctx, r.client, req.NamespacedName, log, func(pvr *velerov1api.PodVolumeRestore) bool {
				if !controllerutil.ContainsFinalizer(pvr, PodVolumeFinalizer) {
					return false
				}

				controllerutil.RemoveFinalizer(pvr, PodVolumeFinalizer)

				return true
			}); err != nil {
				log.WithError(err).Error("error to remove finalizer")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}
	}

	if pvr.Spec.Cancel {
		if spotted, found := r.cancelledPVR[pvr.Name]; !found {
			r.cancelledPVR[pvr.Name] = r.clock.Now()
		} else {
			delay := cancelDelayOthers
			if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseInProgress {
				delay = cancelDelayInProgress
			}

			if time.Since(spotted) > delay {
				log.Infof("PVR %s is canceled in Phase %s but not handled in rasonable time", pvr.GetName(), pvr.Status.Phase)
				if r.tryCancelPodVolumeRestore(ctx, pvr, "") {
					delete(r.cancelledPVR, pvr.Name)
				}

				return ctrl.Result{}, nil
			}
		}
	}

	if pvr.Status.Phase == "" || pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseNew {
		if pvr.Spec.Cancel {
			log.Infof("PVR %s is canceled in Phase %s", pvr.GetName(), pvr.Status.Phase)
			_ = r.tryCancelPodVolumeRestore(ctx, pvr, "")

			return ctrl.Result{}, nil
		}

		shouldProcess, pod, err := shouldProcess(ctx, r.client, log, pvr)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !shouldProcess {
			return ctrl.Result{}, nil
		}

		if r.vgdpCounter != nil && r.vgdpCounter.IsConstrained(ctx, r.logger) {
			log.Debug("Data path initiation is constrained, requeue later")
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}

		log.Info("Accepting PVR")

		if err := r.acceptPodVolumeRestore(ctx, pvr); err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error accepting PVR %s", pvr.Name)
		}

		initContainerIndex := getInitContainerIndex(pod)
		if initContainerIndex > 0 {
			log.Warnf(`Init containers before the %s container may cause issues
					  if they interfere with volumes being restored: %s index %d`, restorehelper.WaitInitContainer, restorehelper.WaitInitContainer, initContainerIndex)
		}

		log.Info("Exposing PVR")

		exposeParam := r.setupExposeParam(pvr)
		if err := r.exposer.Expose(ctx, getPVROwnerObject(pvr), exposeParam); err != nil {
			return r.errorOut(ctx, pvr, err, "error to expose PVR", log)
		}

		log.Info("PVR is exposed")

		return ctrl.Result{}, nil
	} else if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseAccepted {
		if peekErr := r.exposer.PeekExposed(ctx, getPVROwnerObject(pvr)); peekErr != nil {
			log.Errorf("Cancel PVR %s/%s because of expose error %s", pvr.Namespace, pvr.Name, peekErr)

			diags := strings.Split(r.exposer.DiagnoseExpose(ctx, getPVROwnerObject(pvr)), "\n")
			for _, diag := range diags {
				log.Warnf("[Diagnose PVR expose]%s", diag)
			}

			_ = r.tryCancelPodVolumeRestore(ctx, pvr, fmt.Sprintf("found a PVR %s/%s with expose error: %s. mark it as cancel", pvr.Namespace, pvr.Name, peekErr))
		} else if pvr.Status.AcceptedTimestamp != nil {
			if time.Since(pvr.Status.AcceptedTimestamp.Time) >= r.preparingTimeout {
				r.onPrepareTimeout(ctx, pvr)
			}
		}

		return ctrl.Result{}, nil
	} else if pvr.Status.Phase == velerov1api.PodVolumeRestorePhasePrepared {
		log.Infof("PVR is prepared and should be processed by %s (%s)", pvr.Status.Node, r.nodeName)

		if pvr.Status.Node != r.nodeName {
			return ctrl.Result{}, nil
		}

		if pvr.Spec.Cancel {
			log.Info("Prepared PVR is being canceled")
			r.OnDataPathCancelled(ctx, pvr.GetNamespace(), pvr.GetName())
			return ctrl.Result{}, nil
		}

		asyncBR := r.dataPathMgr.GetAsyncBR(pvr.Name)
		if asyncBR != nil {
			log.Info("Cancellable data path is already started")
			return ctrl.Result{}, nil
		}

		res, err := r.exposer.GetExposed(ctx, getPVROwnerObject(pvr), r.client, r.nodeName, r.resourceTimeout)
		if err != nil {
			return r.errorOut(ctx, pvr, err, "exposed PVR is not ready", log)
		} else if res == nil {
			return r.errorOut(ctx, pvr, errors.New("no expose result is available for the current node"), "exposed PVR is not ready", log)
		}

		log.Info("Exposed PVR is ready and creating data path routine")

		callbacks := datapath.Callbacks{
			OnCompleted: r.OnDataPathCompleted,
			OnFailed:    r.OnDataPathFailed,
			OnCancelled: r.OnDataPathCancelled,
			OnProgress:  r.OnDataPathProgress,
		}

		asyncBR, err = r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, r.kubeClient, r.mgr, datapath.TaskTypeRestore,
			pvr.Name, pvr.Namespace, res.ByPod.HostingPod.Name, res.ByPod.HostingContainer, pvr.Name, callbacks, false, log)
		if err != nil {
			if err == datapath.ConcurrentLimitExceed {
				log.Debug("Data path instance is concurrent limited requeue later")
				return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
			} else {
				return r.errorOut(ctx, pvr, err, "error to create data path", log)
			}
		}

		if err := r.initCancelableDataPath(ctx, asyncBR, res, log); err != nil {
			log.WithError(err).Errorf("Failed to init cancelable data path for %s", pvr.Name)

			r.closeDataPath(ctx, pvr.Name)
			return r.errorOut(ctx, pvr, err, "error initializing data path", log)
		}

		terminated := false
		if err := UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log, func(pvr *velerov1api.PodVolumeRestore) bool {
			if isPVRInFinalState(pvr) {
				terminated = true
				return false
			}

			pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseInProgress
			pvr.Status.StartTimestamp = &metav1.Time{Time: r.clock.Now()}

			delete(pvr.Labels, exposer.ExposeOnGoingLabel)

			return true
		}); err != nil {
			log.WithError(err).Warnf("Failed to update PVR %s to InProgress, will data path close and retry", pvr.Name)

			r.closeDataPath(ctx, pvr.Name)
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}

		if terminated {
			log.Warnf("PVR %s is terminated during transition from prepared", pvr.Name)
			r.closeDataPath(ctx, pvr.Name)
			return ctrl.Result{}, nil
		}

		log.Info("PVR is marked as in progress")

		if err := r.startCancelableDataPath(asyncBR, pvr, res, log); err != nil {
			log.WithError(err).Errorf("Failed to start cancelable data path for %s", pvr.Name)
			r.closeDataPath(ctx, pvr.Name)

			return r.errorOut(ctx, pvr, err, "error starting data path", log)
		}

		return ctrl.Result{}, nil
	} else if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseInProgress {
		if pvr.Spec.Cancel {
			if pvr.Status.Node != r.nodeName {
				return ctrl.Result{}, nil
			}

			log.Info("PVR is being canceled")

			asyncBR := r.dataPathMgr.GetAsyncBR(pvr.Name)
			if asyncBR == nil {
				r.OnDataPathCancelled(ctx, pvr.GetNamespace(), pvr.GetName())
				return ctrl.Result{}, nil
			}

			// Update status to Canceling
			if err := UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log, func(pvr *velerov1api.PodVolumeRestore) bool {
				if isPVRInFinalState(pvr) {
					log.Warnf("PVR %s is terminated, abort setting it to canceling", pvr.Name)
					return false
				}

				pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseCanceling
				return true
			}); err != nil {
				log.WithError(err).Error("error updating PVR into canceling status")
				return ctrl.Result{}, err
			}

			asyncBR.Cancel()
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *PodVolumeRestoreReconciler) acceptPodVolumeRestore(ctx context.Context, pvr *velerov1api.PodVolumeRestore) error {
	return UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, r.logger, func(pvr *velerov1api.PodVolumeRestore) bool {
		pvr.Status.AcceptedTimestamp = &metav1.Time{Time: r.clock.Now()}
		pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseAccepted
		pvr.Status.Node = r.nodeName

		if pvr.Labels == nil {
			pvr.Labels = make(map[string]string)
		}
		pvr.Labels[exposer.ExposeOnGoingLabel] = "true"

		return true
	})
}

func (r *PodVolumeRestoreReconciler) tryCancelPodVolumeRestore(ctx context.Context, pvr *velerov1api.PodVolumeRestore, message string) bool {
	log := r.logger.WithField("PVR", pvr.Name)
	succeeded, err := funcExclusiveUpdatePodVolumeRestore(ctx, r.client, pvr, func(pvr *velerov1api.PodVolumeRestore) {
		pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseCanceled
		if pvr.Status.StartTimestamp.IsZero() {
			pvr.Status.StartTimestamp = &metav1.Time{Time: r.clock.Now()}
		}
		pvr.Status.CompletionTimestamp = &metav1.Time{Time: r.clock.Now()}

		if message != "" {
			pvr.Status.Message = message
		}

		delete(pvr.Labels, exposer.ExposeOnGoingLabel)
	})

	if err != nil {
		log.WithError(err).Error("error updating PVR status")
		return false
	} else if !succeeded {
		log.Warn("conflict in updating PVR status and will try it again later")
		return false
	}

	r.exposer.CleanUp(ctx, getPVROwnerObject(pvr))

	log.Warn("PVR is canceled")

	return true
}

var funcExclusiveUpdatePodVolumeRestore = exclusiveUpdatePodVolumeRestore

func exclusiveUpdatePodVolumeRestore(ctx context.Context, cli client.Client, pvr *velerov1api.PodVolumeRestore,
	updateFunc func(*velerov1api.PodVolumeRestore)) (bool, error) {
	updateFunc(pvr)

	err := cli.Update(ctx, pvr)
	if err == nil {
		return true, nil
	}

	// warn we won't rollback pvr values in memory when error
	if apierrors.IsConflict(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (r *PodVolumeRestoreReconciler) onPrepareTimeout(ctx context.Context, pvr *velerov1api.PodVolumeRestore) {
	log := r.logger.WithField("PVR", pvr.Name)

	log.Info("Timeout happened for preparing PVR")

	succeeded, err := funcExclusiveUpdatePodVolumeRestore(ctx, r.client, pvr, func(pvr *velerov1api.PodVolumeRestore) {
		pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseFailed
		pvr.Status.Message = "timeout on preparing PVR"

		delete(pvr.Labels, exposer.ExposeOnGoingLabel)
	})

	if err != nil {
		log.WithError(err).Warn("Failed to update PVR")
		return
	}

	if !succeeded {
		log.Warn("PVR has been updated by others")
		return
	}

	diags := strings.Split(r.exposer.DiagnoseExpose(ctx, getPVROwnerObject(pvr)), "\n")
	for _, diag := range diags {
		log.Warnf("[Diagnose PVR expose]%s", diag)
	}

	r.exposer.CleanUp(ctx, getPVROwnerObject(pvr))

	log.Info("PVR has been cleaned up")
}

func (r *PodVolumeRestoreReconciler) initCancelableDataPath(ctx context.Context, asyncBR datapath.AsyncBR, res *exposer.ExposeResult, log logrus.FieldLogger) error {
	log.Info("Init cancelable PVR")

	if err := asyncBR.Init(ctx, nil); err != nil {
		return errors.Wrap(err, "error initializing asyncBR")
	}

	log.Infof("async data path init for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)

	return nil
}

func (r *PodVolumeRestoreReconciler) startCancelableDataPath(asyncBR datapath.AsyncBR, pvr *velerov1api.PodVolumeRestore, res *exposer.ExposeResult, log logrus.FieldLogger) error {
	log.Info("Start cancelable PVR")

	if err := asyncBR.StartRestore(pvr.Spec.SnapshotID, datapath.AccessPoint{
		ByPath: res.ByPod.VolumeName,
	}, pvr.Spec.UploaderSettings); err != nil {
		return errors.Wrapf(err, "error starting async restore for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)
	}

	log.Infof("Async restore started for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)
	return nil
}

func (r *PodVolumeRestoreReconciler) errorOut(ctx context.Context, pvr *velerov1api.PodVolumeRestore, err error, msg string, log logrus.FieldLogger) (ctrl.Result, error) {
	r.exposer.CleanUp(ctx, getPVROwnerObject(pvr))

	return ctrl.Result{}, UpdatePVRStatusToFailed(ctx, r.client, pvr, err, msg, r.clock.Now(), log)
}

func UpdatePVRStatusToFailed(ctx context.Context, c client.Client, pvr *velerov1api.PodVolumeRestore, err error, msg string, time time.Time, log logrus.FieldLogger) error {
	log.Info("update PVR status to Failed")

	if patchErr := UpdatePVRWithRetry(context.Background(), c, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log,
		func(pvr *velerov1api.PodVolumeRestore) bool {
			if isPVRInFinalState(pvr) {
				return false
			}

			pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseFailed
			pvr.Status.Message = errors.WithMessage(err, msg).Error()
			pvr.Status.CompletionTimestamp = &metav1.Time{Time: time}

			delete(pvr.Labels, exposer.ExposeOnGoingLabel)

			return true
		}); patchErr != nil {
		log.WithError(patchErr).Warn("error updating PVR status")
	}

	return err
}

func shouldProcess(ctx context.Context, client client.Client, log logrus.FieldLogger, pvr *velerov1api.PodVolumeRestore) (bool, *corev1api.Pod, error) {
	if !isPVRNew(pvr) {
		log.Debug("PVR is not new, skip")
		return false, nil, nil
	}

	// we filter the pods during the initialization of cache, if we can get a pod here, the pod must be in the same node with the controller
	// so we don't need to compare the node anymore
	pod := &corev1api.Pod{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: pvr.Spec.Pod.Namespace, Name: pvr.Spec.Pod.Name}, pod); err != nil {
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

func (r *PodVolumeRestoreReconciler) closeDataPath(ctx context.Context, pvrName string) {
	asyncBR := r.dataPathMgr.GetAsyncBR(pvrName)
	if asyncBR != nil {
		asyncBR.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(pvrName)
}

func (r *PodVolumeRestoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		pvr := object.(*velerov1api.PodVolumeRestore)
		if _, err := uploader.ValidateUploaderType(pvr.Spec.UploaderType); err != nil {
			return false
		}

		if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseAccepted {
			return true
		}

		if pvr.Spec.Cancel && !isPVRInFinalState(pvr) {
			return true
		}

		if isPVRInFinalState(pvr) && !pvr.DeletionTimestamp.IsZero() {
			return true
		}

		return false
	})

	s := kube.NewPeriodicalEnqueueSource(r.logger.WithField("controller", constant.ControllerPodVolumeRestore), r.client, &velerov1api.PodVolumeRestoreList{}, preparingMonitorFrequency, kube.PeriodicalEnqueueSourceOption{
		Predicates: []predicate.Predicate{gp},
	})

	pred := kube.NewAllEventPredicate(func(obj client.Object) bool {
		pvr := obj.(*velerov1api.PodVolumeRestore)
		_, err := uploader.ValidateUploaderType(pvr.Spec.UploaderType)
		return err == nil
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.PodVolumeRestore{}, builder.WithPredicates(pred)).
		WatchesRawSource(s).
		Watches(&corev1api.Pod{}, handler.EnqueueRequestsFromMapFunc(r.findPVRForTargetPod)).
		Watches(&corev1api.Pod{}, kube.EnqueueRequestsFromMapUpdateFunc(r.findPVRForRestorePod),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(ue event.UpdateEvent) bool {
					newObj := ue.ObjectNew.(*corev1api.Pod)

					if _, ok := newObj.Labels[velerov1api.PVRLabel]; !ok {
						return false
					}

					if newObj.Spec.NodeName == "" {
						return false
					}

					return true
				},
				CreateFunc: func(event.CreateEvent) bool {
					return false
				},
				DeleteFunc: func(de event.DeleteEvent) bool {
					return false
				},
				GenericFunc: func(ge event.GenericEvent) bool {
					return false
				},
			})).
		Complete(r)
}

func (r *PodVolumeRestoreReconciler) findPVRForTargetPod(ctx context.Context, pod client.Object) []reconcile.Request {
	list := &velerov1api.PodVolumeRestoreList{}
	options := &client.ListOptions{
		LabelSelector: labels.Set(map[string]string{
			velerov1api.PodUIDLabel: string(pod.GetUID()),
		}).AsSelector(),
	}
	if err := r.client.List(context.TODO(), list, options); err != nil {
		r.logger.WithField("pod", fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())).WithError(err).
			Error("unable to list PodVolumeRestores")
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}
	for _, item := range list.Items {
		if _, err := uploader.ValidateUploaderType(item.Spec.UploaderType); err != nil {
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

func (r *PodVolumeRestoreReconciler) findPVRForRestorePod(ctx context.Context, podObj client.Object) []reconcile.Request {
	pod := podObj.(*corev1api.Pod)
	pvr, err := findPVRByRestorePod(r.client, *pod)

	log := r.logger.WithField("pod", pod.Name)
	if err != nil {
		log.WithError(err).Error("unable to get PVR")
		return []reconcile.Request{}
	} else if pvr == nil {
		log.Error("get empty PVR")
		return []reconcile.Request{}
	}
	log = log.WithFields(logrus.Fields{
		"PVR": pvr.Name,
	})

	if _, err := uploader.ValidateUploaderType(pvr.Spec.UploaderType); err != nil {
		log.WithField("uploaderType", pvr.Spec.UploaderType).Debug("skip PVR with invalid uploader type")
		return []reconcile.Request{}
	}

	if pvr.Status.Phase != velerov1api.PodVolumeRestorePhaseAccepted {
		return []reconcile.Request{}
	}

	if pod.Status.Phase == corev1api.PodRunning {
		log.Info("Preparing PVR")

		if err = UpdatePVRWithRetry(context.Background(), r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log,
			func(pvr *velerov1api.PodVolumeRestore) bool {
				if isPVRInFinalState(pvr) {
					log.Warnf("PVR %s is terminated, abort setting it to prepared", pvr.Name)
					return false
				}

				pvr.Status.Phase = velerov1api.PodVolumeRestorePhasePrepared
				return true
			}); err != nil {
			log.WithError(err).Warn("failed to update PVR, prepare will halt for this PVR")
			return []reconcile.Request{}
		}
	} else if unrecoverable, reason := kube.IsPodUnrecoverable(pod, log); unrecoverable {
		err := UpdatePVRWithRetry(context.Background(), r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log,
			func(pvr *velerov1api.PodVolumeRestore) bool {
				if pvr.Spec.Cancel {
					return false
				}

				pvr.Spec.Cancel = true
				pvr.Status.Message = fmt.Sprintf("Cancel PVR because the exposing pod %s/%s is in abnormal status for reason %s", pod.Namespace, pod.Name, reason)

				return true
			})

		if err != nil {
			log.WithError(err).Warn("failed to cancel PVR, and it will wait for prepare timeout")
			return []reconcile.Request{}
		}

		log.Infof("Exposed pod is in abnormal status(reason %s) and PVR is marked as cancel", reason)
	} else {
		return []reconcile.Request{}
	}

	request := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: pvr.Namespace,
			Name:      pvr.Name,
		},
	}
	return []reconcile.Request{request}
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

func (r *PodVolumeRestoreReconciler) OnDataPathCompleted(ctx context.Context, namespace string, pvrName string, result datapath.Result) {
	defer r.dataPathMgr.RemoveAsyncBR(pvrName)

	log := r.logger.WithField("PVR", pvrName)

	log.WithField("PVR", pvrName).WithField("result", result.Restore).Info("Async fs restore data path completed")

	var pvr velerov1api.PodVolumeRestore
	if err := r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); err != nil {
		log.WithError(err).Warn("Failed to get PVR on completion")
		return
	}

	log.Info("Cleaning up exposed environment")
	r.exposer.CleanUp(ctx, getPVROwnerObject(&pvr))

	if err := UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log, func(pvr *velerov1api.PodVolumeRestore) bool {
		if isPVRInFinalState(pvr) {
			return false
		}

		pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseCompleted
		pvr.Status.CompletionTimestamp = &metav1.Time{Time: r.clock.Now()}

		delete(pvr.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); err != nil {
		log.WithError(err).Error("error updating PVR status")
	} else {
		log.Info("Restore completed")
	}
}

func (r *PodVolumeRestoreReconciler) OnDataPathFailed(ctx context.Context, namespace string, pvrName string, err error) {
	defer r.dataPathMgr.RemoveAsyncBR(pvrName)

	log := r.logger.WithField("PVR", pvrName)

	log.WithError(err).Error("Async fs restore data path failed")

	var pvr velerov1api.PodVolumeRestore
	if getErr := r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVR on failure")
	} else {
		_, _ = r.errorOut(ctx, &pvr, err, "data path restore failed", log)
	}
}

func (r *PodVolumeRestoreReconciler) OnDataPathCancelled(ctx context.Context, namespace string, pvrName string) {
	defer r.dataPathMgr.RemoveAsyncBR(pvrName)

	log := r.logger.WithField("PVR", pvrName)

	log.Warn("Async fs restore data path canceled")

	var pvr velerov1api.PodVolumeRestore
	if getErr := r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, &pvr); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVR on cancel")
		return
	}
	// cleans up any objects generated during the snapshot expose
	r.exposer.CleanUp(ctx, getPVROwnerObject(&pvr))

	if err := UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, log, func(pvr *velerov1api.PodVolumeRestore) bool {
		if isPVRInFinalState(pvr) {
			return false
		}

		pvr.Status.Phase = velerov1api.PodVolumeRestorePhaseCanceled
		if pvr.Status.StartTimestamp.IsZero() {
			pvr.Status.StartTimestamp = &metav1.Time{Time: r.clock.Now()}
		}
		pvr.Status.CompletionTimestamp = &metav1.Time{Time: r.clock.Now()}

		delete(pvr.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); err != nil {
		log.WithError(err).Error("error updating PVR status on cancel")
	} else {
		delete(r.cancelledPVR, pvr.Name)
	}
}

func (r *PodVolumeRestoreReconciler) OnDataPathProgress(ctx context.Context, namespace string, pvrName string, progress *uploader.Progress) {
	log := r.logger.WithField("PVR", pvrName)

	if err := UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: namespace, Name: pvrName}, log, func(pvr *velerov1api.PodVolumeRestore) bool {
		pvr.Status.Progress = veleroapishared.DataMoveOperationProgress{TotalBytes: progress.TotalBytes, BytesDone: progress.BytesDone}
		return true
	}); err != nil {
		log.WithError(err).Error("Failed to update progress")
	}
}

func (r *PodVolumeRestoreReconciler) setupExposeParam(pvr *velerov1api.PodVolumeRestore) exposer.PodVolumeExposeParam {
	log := r.logger.WithField("PVR", pvr.Name)

	nodeOS, err := kube.GetNodeOS(context.Background(), pvr.Status.Node, r.kubeClient.CoreV1())
	if err != nil {
		log.WithError(err).Warnf("Failed to get nodeOS for node %s, use linux node-agent for hosting pod labels, annotations and tolerations", pvr.Status.Node)
	}

	hostingPodLabels := map[string]string{velerov1api.PVRLabel: pvr.Name}
	if len(r.podLabels) > 0 {
		for k, v := range r.podLabels {
			hostingPodLabels[k] = v
		}
	} else {
		for _, k := range util.ThirdPartyLabels {
			if v, err := nodeagent.GetLabelValue(context.Background(), r.kubeClient, pvr.Namespace, k, nodeOS); err != nil {
				if err != nodeagent.ErrNodeAgentLabelNotFound {
					log.WithError(err).Warnf("Failed to check node-agent label, skip adding host pod label %s", k)
				}
			} else {
				hostingPodLabels[k] = v
			}
		}
	}

	hostingPodAnnotation := map[string]string{}
	if len(r.podAnnotations) > 0 {
		for k, v := range r.podAnnotations {
			hostingPodAnnotation[k] = v
		}
	} else {
		for _, k := range util.ThirdPartyAnnotations {
			if v, err := nodeagent.GetAnnotationValue(context.Background(), r.kubeClient, pvr.Namespace, k, nodeOS); err != nil {
				if err != nodeagent.ErrNodeAgentAnnotationNotFound {
					log.WithError(err).Warnf("Failed to check node-agent annotation, skip adding host pod annotation %s", k)
				}
			} else {
				hostingPodAnnotation[k] = v
			}
		}
	}

	hostingPodTolerations := []corev1api.Toleration{}
	for _, k := range util.ThirdPartyTolerations {
		if v, err := nodeagent.GetToleration(context.Background(), r.kubeClient, pvr.Namespace, k, nodeOS); err != nil {
			if err != nodeagent.ErrNodeAgentTolerationNotFound {
				log.WithError(err).Warnf("Failed to check node-agent toleration, skip adding host pod toleration %s", k)
			}
		} else {
			hostingPodTolerations = append(hostingPodTolerations, *v)
		}
	}

	var cacheVolume *exposer.CacheConfigs
	if r.cacheVolumeConfigs != nil {
		if limit, err := r.repoConfigMgr.ClientSideCacheLimit(velerov1api.BackupRepositoryTypeKopia, r.backupRepoConfigs); err != nil {
			log.WithError(err).Warnf("Failed to get client side cache limit for repo type %s from configs %v", velerov1api.BackupRepositoryTypeKopia, r.backupRepoConfigs)
		} else {
			cacheVolume = &exposer.CacheConfigs{
				Limit:             limit,
				StorageClass:      r.cacheVolumeConfigs.StorageClass,
				ResidentThreshold: r.cacheVolumeConfigs.ResidentThresholdInMB << 20,
			}
		}
	}

	return exposer.PodVolumeExposeParam{
		Type:                  exposer.PodVolumeExposeTypeRestore,
		ClientNamespace:       pvr.Spec.Pod.Namespace,
		ClientPodName:         pvr.Spec.Pod.Name,
		ClientPodVolume:       pvr.Spec.Volume,
		HostingPodLabels:      hostingPodLabels,
		HostingPodAnnotations: hostingPodAnnotation,
		HostingPodTolerations: hostingPodTolerations,
		OperationTimeout:      r.resourceTimeout,
		Resources:             r.podResources,
		RestoreSize:           pvr.Spec.SnapshotSize,
		CacheVolume:           cacheVolume,
		// Priority class name for the data mover pod, retrieved from node-agent-configmap
		PriorityClassName: r.dataMovePriorityClass,
		Privileged:        r.privileged,
	}
}

func getPVROwnerObject(pvr *velerov1api.PodVolumeRestore) corev1api.ObjectReference {
	return corev1api.ObjectReference{
		Kind:       pvr.Kind,
		Namespace:  pvr.Namespace,
		Name:       pvr.Name,
		UID:        pvr.UID,
		APIVersion: pvr.APIVersion,
	}
}

func findPVRByRestorePod(client client.Client, pod corev1api.Pod) (*velerov1api.PodVolumeRestore, error) {
	if label, exist := pod.Labels[velerov1api.PVRLabel]; exist {
		pvr := &velerov1api.PodVolumeRestore{}
		err := client.Get(context.Background(), types.NamespacedName{
			Namespace: pod.Namespace,
			Name:      label,
		}, pvr)

		if err != nil {
			return nil, errors.Wrapf(err, "error to find PVR by pod %s/%s", pod.Namespace, pod.Name)
		}
		return pvr, nil
	}
	return nil, nil
}

func isPVRInFinalState(pvr *velerov1api.PodVolumeRestore) bool {
	return pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseFailed ||
		pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseCanceled ||
		pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseCompleted
}

func UpdatePVRWithRetry(ctx context.Context, client client.Client, namespacedName types.NamespacedName, log logrus.FieldLogger, updateFunc func(*velerov1api.PodVolumeRestore) bool) error {
	return wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (bool, error) {
		pvr := &velerov1api.PodVolumeRestore{}
		if err := client.Get(ctx, namespacedName, pvr); err != nil {
			return false, errors.Wrap(err, "getting PVR")
		}

		if updateFunc(pvr) {
			err := client.Update(ctx, pvr)
			if err != nil {
				if apierrors.IsConflict(err) {
					log.Debugf("failed to update PVR for %s/%s and will retry it", pvr.Namespace, pvr.Name)
					return false, nil
				} else {
					return false, errors.Wrapf(err, "error updating PVR %s/%s", pvr.Namespace, pvr.Name)
				}
			}
		}

		return true, nil
	})
}

var funcResumeCancellablePVR = (*PodVolumeRestoreReconciler).resumeCancellableDataPath

func (r *PodVolumeRestoreReconciler) AttemptPVRResume(ctx context.Context, logger *logrus.Entry, ns string) error {
	pvrs := &velerov1api.PodVolumeRestoreList{}
	if err := r.client.List(ctx, pvrs, &client.ListOptions{Namespace: ns}); err != nil {
		r.logger.WithError(errors.WithStack(err)).Error("failed to list PVRs")
		return errors.Wrapf(err, "error to list PVRs")
	}

	for i := range pvrs.Items {
		pvr := &pvrs.Items[i]
		if _, err := uploader.ValidateUploaderType(pvr.Spec.UploaderType); err != nil {
			continue
		}

		if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseInProgress {
			if pvr.Status.Node != r.nodeName {
				logger.WithField("PVR", pvr.Name).WithField("current node", r.nodeName).Infof("PVR should be resumed by another node %s", pvr.Status.Node)
				continue
			}

			err := funcResumeCancellablePVR(r, ctx, pvr, logger)
			if err == nil {
				logger.WithField("PVR", pvr.Name).WithField("current node", r.nodeName).Info("Completed to resume in progress PVR")
				continue
			}

			logger.WithField("PVR", pvr.GetName()).WithError(err).Warn("Failed to resume data path for PVR, have to cancel it")

			resumeErr := err
			err = UpdatePVRWithRetry(ctx, r.client, types.NamespacedName{Namespace: pvr.Namespace, Name: pvr.Name}, logger.WithField("PVR", pvr.Name),
				func(pvr *velerov1api.PodVolumeRestore) bool {
					if pvr.Spec.Cancel {
						return false
					}

					pvr.Spec.Cancel = true
					pvr.Status.Message = fmt.Sprintf("Resume InProgress PVR failed with error %v, mark it as cancel", resumeErr)

					return true
				})
			if err != nil {
				logger.WithField("PVR", pvr.GetName()).WithError(errors.WithStack(err)).Error("Failed to trigger PVR cancel")
			}
		} else if !isPVRInFinalState(pvr) {
			logger.WithField("PVR", pvr.GetName()).Infof("find a PVR with status %s", pvr.Status.Phase)
		}
	}

	return nil
}

func (r *PodVolumeRestoreReconciler) resumeCancellableDataPath(ctx context.Context, pvr *velerov1api.PodVolumeRestore, log logrus.FieldLogger) error {
	log.Info("Resume cancelable PVR")

	res, err := r.exposer.GetExposed(ctx, getPVROwnerObject(pvr), r.client, r.nodeName, r.resourceTimeout)
	if err != nil {
		return errors.Wrapf(err, "error to get exposed PVR %s", pvr.Name)
	}

	if res == nil {
		return errors.Errorf("no expose result is available for the current node for PVR %s", pvr.Name)
	}

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataPathCompleted,
		OnFailed:    r.OnDataPathFailed,
		OnCancelled: r.OnDataPathCancelled,
		OnProgress:  r.OnDataPathProgress,
	}

	asyncBR, err := r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, r.kubeClient, r.mgr, datapath.TaskTypeRestore, pvr.Name, pvr.Namespace, res.ByPod.HostingPod.Name, res.ByPod.HostingContainer, pvr.Name, callbacks, true, log)
	if err != nil {
		return errors.Wrapf(err, "error to create asyncBR watcher for PVR %s", pvr.Name)
	}

	resumeComplete := false
	defer func() {
		if !resumeComplete {
			r.closeDataPath(ctx, pvr.Name)
		}
	}()

	if err := asyncBR.Init(ctx, nil); err != nil {
		return errors.Wrapf(err, "error to init asyncBR watcher for PVR %s", pvr.Name)
	}

	if err := asyncBR.StartRestore(pvr.Spec.SnapshotID, datapath.AccessPoint{
		ByPath: res.ByPod.VolumeName,
	}, pvr.Spec.UploaderSettings); err != nil {
		return errors.Wrapf(err, "error to resume asyncBR watcher for PVR %s", pvr.Name)
	}

	resumeComplete = true

	log.Infof("asyncBR is resumed for PVR %s", pvr.Name)

	return nil
}
