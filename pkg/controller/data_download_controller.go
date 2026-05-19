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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	datamover "github.com/vmware-tanzu/velero/pkg/datamover"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	repository "github.com/vmware-tanzu/velero/pkg/repository/manager"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// DataDownloadReconciler reconciles a DataDownload object
type DataDownloadReconciler struct {
	client                client.Client
	kubeClient            kubernetes.Interface
	mgr                   manager.Manager
	logger                logrus.FieldLogger
	Clock                 clock.WithTickerAndDelayedExecution
	restoreExposer        exposer.GenericRestoreExposer
	nodeName              string
	dataPathMgr           *datapath.Manager
	vgdpCounter           *exposer.VgdpCounter
	loadAffinity          []*kube.LoadAffinity
	restorePVCConfig      velerotypes.RestorePVC
	backupRepoConfigs     map[string]string
	cacheVolumeConfigs    *velerotypes.CachePVC
	podResources          corev1api.ResourceRequirements
	preparingTimeout      time.Duration
	metrics               *metrics.ServerMetrics
	cancelledDataDownload map[string]time.Time
	dataMovePriorityClass string
	repoConfigMgr         repository.ConfigManager
	podLabels             map[string]string
	podAnnotations        map[string]string
}

func NewDataDownloadReconciler(
	client client.Client,
	mgr manager.Manager,
	kubeClient kubernetes.Interface,
	dataPathMgr *datapath.Manager,
	counter *exposer.VgdpCounter,
	loadAffinity []*kube.LoadAffinity,
	restorePVCConfig velerotypes.RestorePVC,
	backupRepoConfigs map[string]string,
	cacheVolumeConfigs *velerotypes.CachePVC,
	podResources corev1api.ResourceRequirements,
	nodeName string,
	preparingTimeout time.Duration,
	logger logrus.FieldLogger,
	metrics *metrics.ServerMetrics,
	dataMovePriorityClass string,
	repoConfigMgr repository.ConfigManager,
	podLabels map[string]string,
	podAnnotations map[string]string,
) *DataDownloadReconciler {
	return &DataDownloadReconciler{
		client:                client,
		kubeClient:            kubeClient,
		mgr:                   mgr,
		logger:                logger.WithField("controller", "DataDownload"),
		Clock:                 &clock.RealClock{},
		nodeName:              nodeName,
		restoreExposer:        exposer.NewGenericRestoreExposer(kubeClient, logger),
		restorePVCConfig:      restorePVCConfig,
		backupRepoConfigs:     backupRepoConfigs,
		cacheVolumeConfigs:    cacheVolumeConfigs,
		dataPathMgr:           dataPathMgr,
		vgdpCounter:           counter,
		loadAffinity:          loadAffinity,
		podResources:          podResources,
		preparingTimeout:      preparingTimeout,
		metrics:               metrics,
		cancelledDataDownload: make(map[string]time.Time),
		dataMovePriorityClass: dataMovePriorityClass,
		repoConfigMgr:         repoConfigMgr,
		podLabels:             podLabels,
		podAnnotations:        podAnnotations,
	}
}

// +kubebuilder:rbac:groups=velero.io,resources=datadownloads,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=datadownloads/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumes,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumerclaims,verbs=get

func (r *DataDownloadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithFields(logrus.Fields{
		"controller":   "datadownload",
		"datadownload": req.NamespacedName,
	})

	log.Infof("Reconcile %s", req.Name)

	dd := &velerov2alpha1api.DataDownload{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: req.Name}, dd); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warn("DataDownload not found, skip")
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("Unable to get the DataDownload")
		return ctrl.Result{}, err
	}

	if !datamover.IsBuiltInUploader(dd.Spec.DataMover) {
		log.WithField("data mover", dd.Spec.DataMover).Info("it is not one built-in data mover which is not supported by Velero")
		return ctrl.Result{}, nil
	}

	// Logic for clear resources when datadownload been deleted
	if !isDataDownloadInFinalState(dd) {
		if !controllerutil.ContainsFinalizer(dd, DataUploadDownloadFinalizer) {
			if err := UpdateDataDownloadWithRetry(ctx, r.client, req.NamespacedName, log, func(dd *velerov2alpha1api.DataDownload) bool {
				if controllerutil.ContainsFinalizer(dd, DataUploadDownloadFinalizer) {
					return false
				}

				controllerutil.AddFinalizer(dd, DataUploadDownloadFinalizer)

				return true
			}); err != nil {
				log.WithError(err).Errorf("failed to add finalizer for dd %s/%s", dd.Namespace, dd.Name)
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		if !dd.DeletionTimestamp.IsZero() {
			if !dd.Spec.Cancel {
				// when delete cr we need to clear up internal resources created by Velero, here we use the cancel mechanism
				// to help clear up resources instead of clear them directly in case of some conflict with Expose action
				log.Warnf("Cancel dd under phase %s because it is being deleted", dd.Status.Phase)

				if err := UpdateDataDownloadWithRetry(ctx, r.client, req.NamespacedName, log, func(dataDownload *velerov2alpha1api.DataDownload) bool {
					if dataDownload.Spec.Cancel {
						return false
					}

					dataDownload.Spec.Cancel = true
					dataDownload.Status.Message = "Cancel datadownload because it is being deleted"

					return true
				}); err != nil {
					log.WithError(err).Errorf("failed to set cancel flag for dd %s/%s", dd.Namespace, dd.Name)
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, nil
			}
		}
	} else {
		delete(r.cancelledDataDownload, dd.Name)

		// put the finalizer remove action here for all cr will goes to the final status, we could check finalizer and do remove action in final status
		// instead of intermediate state.
		// remove finalizer no matter whether the cr is being deleted or not for it is no longer needed when internal resources are all cleaned up
		// also in final status cr won't block the direct delete of the velero namespace
		if controllerutil.ContainsFinalizer(dd, DataUploadDownloadFinalizer) {
			if err := UpdateDataDownloadWithRetry(ctx, r.client, req.NamespacedName, log, func(dd *velerov2alpha1api.DataDownload) bool {
				if !controllerutil.ContainsFinalizer(dd, DataUploadDownloadFinalizer) {
					return false
				}

				controllerutil.RemoveFinalizer(dd, DataUploadDownloadFinalizer)

				return true
			}); err != nil {
				log.WithError(err).Error("error to remove finalizer")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}
	}

	if dd.Spec.Cancel {
		if spotted, found := r.cancelledDataDownload[dd.Name]; !found {
			r.cancelledDataDownload[dd.Name] = r.Clock.Now()
		} else {
			delay := cancelDelayOthers
			if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseInProgress {
				delay = cancelDelayInProgress
			}

			if time.Since(spotted) > delay {
				log.Infof("Data download %s is canceled in Phase %s but not handled in rasonable time", dd.GetName(), dd.Status.Phase)
				if r.tryCancelDataDownload(ctx, dd, "") {
					delete(r.cancelledDataDownload, dd.Name)
				}

				return ctrl.Result{}, nil
			}
		}
	}

	if dd.Status.Phase == "" || dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseNew {
		if dd.Spec.Cancel {
			log.Debugf("Data download is canceled in Phase %s", dd.Status.Phase)

			r.tryCancelDataDownload(ctx, dd, "")

			return ctrl.Result{}, nil
		}

		if r.vgdpCounter != nil && r.vgdpCounter.IsConstrained(ctx, r.logger) {
			log.Debug("Data path initiation is constrained, requeue later")
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}

		if _, err := r.getTargetPVC(ctx, dd); err != nil {
			log.WithField("error", err).Debugf("Cannot find target PVC for DataDownload yet. Retry later.")
			return ctrl.Result{Requeue: true}, nil
		}

		log.Info("Data download starting")

		accepted, err := r.acceptDataDownload(ctx, dd)
		if err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error accepting the data download %s", dd.Name)
		}

		if !accepted {
			log.Debug("Data download is not accepted")
			return ctrl.Result{}, nil
		}

		log.Info("Data download is accepted")

		exposeParam, err := r.setupExposeParam(dd)
		if err != nil {
			return r.errorOut(ctx, dd, err, "failed to set exposer parameters", log)
		}

		// Expose() will trigger to create one pod whose volume is restored by a given volume snapshot,
		// but the pod maybe is not in the same node of the current controller, so we need to return it here.
		// And then only the controller who is in the same node could do the rest work.
		err = r.restoreExposer.Expose(ctx, getDataDownloadOwnerObject(dd), exposeParam)
		if err != nil {
			return r.errorOut(ctx, dd, err, "error to expose snapshot", log)
		}
		log.Info("Restore is exposed")

		return ctrl.Result{}, nil
	} else if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseAccepted {
		if peekErr := r.restoreExposer.PeekExposed(ctx, getDataDownloadOwnerObject(dd)); peekErr != nil {
			log.Errorf("Cancel dd %s/%s because of expose error %s", dd.Namespace, dd.Name, peekErr)

			diags := strings.Split(r.restoreExposer.DiagnoseExpose(ctx, getDataDownloadOwnerObject(dd)), "\n")
			for _, diag := range diags {
				log.Warnf("[Diagnose DD expose]%s", diag)
			}

			r.tryCancelDataDownload(ctx, dd, fmt.Sprintf("found a datadownload %s/%s with expose error: %s. mark it as cancel", dd.Namespace, dd.Name, peekErr))
		} else if dd.Status.AcceptedTimestamp != nil {
			if time.Since(dd.Status.AcceptedTimestamp.Time) >= r.preparingTimeout {
				r.onPrepareTimeout(ctx, dd)
			}
		}

		return ctrl.Result{}, nil
	} else if dd.Status.Phase == velerov2alpha1api.DataDownloadPhasePrepared {
		log.Infof("Data download is prepared and should be processed by %s (%s)", dd.Status.Node, r.nodeName)

		if dd.Status.Node != r.nodeName {
			return ctrl.Result{}, nil
		}

		if dd.Spec.Cancel {
			log.Debugf("Data download is been canceled %s in Phase %s", dd.GetName(), dd.Status.Phase)
			r.OnDataDownloadCancelled(ctx, dd.GetNamespace(), dd.GetName())
			return ctrl.Result{}, nil
		}

		asyncBR := r.dataPathMgr.GetAsyncBR(dd.Name)

		if asyncBR != nil {
			log.Info("Cancellable data path is already started")
			return ctrl.Result{}, nil
		}

		result, err := r.restoreExposer.GetExposed(ctx, getDataDownloadOwnerObject(dd), r.client, r.nodeName, dd.Spec.OperationTimeout.Duration)
		if err != nil {
			return r.errorOut(ctx, dd, err, "restore exposer is not ready", log)
		} else if result == nil {
			return r.errorOut(ctx, dd, errors.New("no expose result is available for the current node"), "exposed snapshot is not ready", log)
		}

		log.Info("Restore PVC is ready and creating data path routine")

		// Need to first create file system BR and get data path instance then update data download status
		callbacks := datapath.Callbacks{
			OnCompleted: r.OnDataDownloadCompleted,
			OnFailed:    r.OnDataDownloadFailed,
			OnCancelled: r.OnDataDownloadCancelled,
			OnProgress:  r.OnDataDownloadProgress,
		}

		asyncBR, err = r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, r.kubeClient, r.mgr, datapath.TaskTypeRestore,
			dd.Name, dd.Namespace, result.ByPod.HostingPod.Name, result.ByPod.HostingContainer, dd.Name, callbacks, false, log)
		if err != nil {
			if err == datapath.ConcurrentLimitExceed {
				log.Debug("Data path instance is concurrent limited requeue later")
				return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
			} else {
				return r.errorOut(ctx, dd, err, "error to create data path", log)
			}
		}

		if err := r.initCancelableDataPath(ctx, asyncBR, result, log); err != nil {
			log.WithError(err).Errorf("Failed to init cancelable data path for %s", dd.Name)

			r.closeDataPath(ctx, dd.Name)
			return r.errorOut(ctx, dd, err, "error initializing data path", log)
		}

		// Update status to InProgress
		terminated := false
		if err := UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log, func(dd *velerov2alpha1api.DataDownload) bool {
			if isDataDownloadInFinalState(dd) {
				terminated = true
				return false
			}

			dd.Status.Phase = velerov2alpha1api.DataDownloadPhaseInProgress
			dd.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}

			delete(dd.Labels, exposer.ExposeOnGoingLabel)

			return true
		}); err != nil {
			log.WithError(err).Warnf("Failed to update datadownload %s to InProgress, will data path close and retry", dd.Name)

			r.closeDataPath(ctx, dd.Name)
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}

		if terminated {
			log.Warnf("datadownload %s is terminated during transition from prepared", dd.Name)
			r.closeDataPath(ctx, dd.Name)
			return ctrl.Result{}, nil
		}

		log.Info("Data download is marked as in progress")

		if err := r.startCancelableDataPath(asyncBR, dd, result, log); err != nil {
			log.WithError(err).Errorf("Failed to start cancelable data path for %s", dd.Name)

			r.closeDataPath(ctx, dd.Name)
			return r.errorOut(ctx, dd, err, "error starting data path", log)
		}

		return ctrl.Result{}, nil
	} else if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseInProgress {
		if dd.Spec.Cancel {
			if dd.Status.Node != r.nodeName {
				return ctrl.Result{}, nil
			}

			log.Info("In progress data download is being canceled")

			asyncBR := r.dataPathMgr.GetAsyncBR(dd.Name)
			if asyncBR == nil {
				r.OnDataDownloadCancelled(ctx, dd.GetNamespace(), dd.GetName())
				return ctrl.Result{}, nil
			}

			// Update status to Canceling.
			if err := UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log, func(dd *velerov2alpha1api.DataDownload) bool {
				if isDataDownloadInFinalState(dd) {
					log.Warnf("datadownload %s is terminated, abort setting it to canceling", dd.Name)
					return false
				}

				dd.Status.Phase = velerov2alpha1api.DataDownloadPhaseCanceling
				return true
			}); err != nil {
				log.WithError(err).Error("error updating data download into canceling status")
				return ctrl.Result{}, err
			}

			asyncBR.Cancel()
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *DataDownloadReconciler) initCancelableDataPath(ctx context.Context, asyncBR datapath.AsyncBR, res *exposer.ExposeResult, log logrus.FieldLogger) error {
	log.Info("Init cancelable dataDownload")

	if err := asyncBR.Init(ctx, nil); err != nil {
		return errors.Wrap(err, "error initializing asyncBR")
	}

	log.Infof("async restore init for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)

	return nil
}

func (r *DataDownloadReconciler) startCancelableDataPath(asyncBR datapath.AsyncBR, dd *velerov2alpha1api.DataDownload, res *exposer.ExposeResult, log logrus.FieldLogger) error {
	log.Info("Start cancelable dataDownload")

	if err := asyncBR.StartRestore(dd.Spec.SnapshotID, datapath.AccessPoint{
		ByPath: res.ByPod.VolumeName,
	}, dd.Spec.DataMoverConfig); err != nil {
		return errors.Wrapf(err, "error starting async restore for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)
	}

	log.Infof("Async restore started for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)
	return nil
}

func (r *DataDownloadReconciler) OnDataDownloadCompleted(ctx context.Context, namespace string, ddName string, result datapath.Result) {
	defer r.dataPathMgr.RemoveAsyncBR(ddName)

	log := r.logger.WithField("datadownload", ddName)
	log.Info("Async fs restore data path completed")

	var dd velerov2alpha1api.DataDownload
	if err := r.client.Get(ctx, types.NamespacedName{Name: ddName, Namespace: namespace}, &dd); err != nil {
		log.WithError(err).Warn("Failed to get datadownload on completion")
		return
	}

	objRef := getDataDownloadOwnerObject(&dd)
	err := r.restoreExposer.RebindVolume(ctx, objRef, dd.Spec.TargetVolume.PVC, dd.Spec.TargetVolume.Namespace, dd.Spec.OperationTimeout.Duration)
	if err != nil {
		log.WithError(err).Error("Failed to rebind PV to target PVC on completion")
		return
	}

	log.Info("Cleaning up exposed environment")
	r.restoreExposer.CleanUp(ctx, objRef)

	if err := UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log, func(dd *velerov2alpha1api.DataDownload) bool {
		if isDataDownloadInFinalState(dd) {
			return false
		}

		dd.Status.Phase = velerov2alpha1api.DataDownloadPhaseCompleted
		dd.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		delete(dd.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); err != nil {
		log.WithError(err).Error("error updating data download status")
	} else {
		log.Infof("Data download is marked as %s", dd.Status.Phase)
		r.metrics.RegisterDataDownloadSuccess(r.nodeName)
	}
}

func (r *DataDownloadReconciler) OnDataDownloadFailed(ctx context.Context, namespace string, ddName string, err error) {
	defer r.dataPathMgr.RemoveAsyncBR(ddName)

	log := r.logger.WithField("datadownload", ddName)

	log.WithError(err).Error("Async fs restore data path failed")

	var dd velerov2alpha1api.DataDownload
	if getErr := r.client.Get(ctx, types.NamespacedName{Name: ddName, Namespace: namespace}, &dd); getErr != nil {
		log.WithError(getErr).Warn("Failed to get data download on failure")
	} else {
		_, _ = r.errorOut(ctx, &dd, err, "data path restore failed", log)
	}
}

func (r *DataDownloadReconciler) OnDataDownloadCancelled(ctx context.Context, namespace string, ddName string) {
	defer r.dataPathMgr.RemoveAsyncBR(ddName)

	log := r.logger.WithField("datadownload", ddName)

	log.Warn("Async fs backup data path canceled")

	var dd velerov2alpha1api.DataDownload
	if getErr := r.client.Get(ctx, types.NamespacedName{Name: ddName, Namespace: namespace}, &dd); getErr != nil {
		log.WithError(getErr).Warn("Failed to get datadownload on cancel")
		return
	}
	// cleans up any objects generated during the snapshot expose
	r.restoreExposer.CleanUp(ctx, getDataDownloadOwnerObject(&dd))

	if err := UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log, func(dd *velerov2alpha1api.DataDownload) bool {
		if isDataDownloadInFinalState(dd) {
			return false
		}

		dd.Status.Phase = velerov2alpha1api.DataDownloadPhaseCanceled
		if dd.Status.StartTimestamp.IsZero() {
			dd.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}
		}
		dd.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		delete(dd.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); err != nil {
		log.WithError(err).Error("error updating data download status")
	} else {
		r.metrics.RegisterDataDownloadCancel(r.nodeName)
		delete(r.cancelledDataDownload, dd.Name)
	}
}

func (r *DataDownloadReconciler) tryCancelDataDownload(ctx context.Context, dd *velerov2alpha1api.DataDownload, message string) bool {
	log := r.logger.WithField("datadownload", dd.Name)
	succeeded, err := funcExclusiveUpdateDataDownload(ctx, r.client, dd, func(dataDownload *velerov2alpha1api.DataDownload) {
		dataDownload.Status.Phase = velerov2alpha1api.DataDownloadPhaseCanceled
		if dataDownload.Status.StartTimestamp.IsZero() {
			dataDownload.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}
		}
		dataDownload.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		if message != "" {
			dataDownload.Status.Message = message
		}

		delete(dataDownload.Labels, exposer.ExposeOnGoingLabel)
	})

	if err != nil {
		log.WithError(err).Error("error updating datadownload status")
		return false
	} else if !succeeded {
		log.Warn("conflict in updating datadownload status and will try it again later")
		return false
	}

	// success update
	r.metrics.RegisterDataDownloadCancel(r.nodeName)
	r.restoreExposer.CleanUp(ctx, getDataDownloadOwnerObject(dd))

	log.Warn("data download is canceled")

	return true
}

func (r *DataDownloadReconciler) OnDataDownloadProgress(ctx context.Context, namespace string, ddName string, progress *uploader.Progress) {
	log := r.logger.WithField("datadownload", ddName)

	if err := UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: namespace, Name: ddName}, log, func(dd *velerov2alpha1api.DataDownload) bool {
		dd.Status.Progress = shared.DataMoveOperationProgress{TotalBytes: progress.TotalBytes, BytesDone: progress.BytesDone}
		return true
	}); err != nil {
		log.WithError(err).Error("Failed to update progress")
	}
}

// SetupWithManager registers the DataDownload controller.
// The fresh new DataDownload CR first created will trigger to create one pod (long time, maybe failure or unknown status) by one of the datadownload controllers
// then the request will get out of the Reconcile queue immediately by not blocking others' CR handling, in order to finish the rest data download process we need to
// re-enqueue the previous related request once the related pod is in running status to keep going on the rest logic. and below logic will avoid handling the unwanted
// pod status and also avoid block others CR handling
func (r *DataDownloadReconciler) SetupWithManager(mgr ctrl.Manager) error {
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		dd := object.(*velerov2alpha1api.DataDownload)
		if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseAccepted {
			return true
		}

		if dd.Spec.Cancel && !isDataDownloadInFinalState(dd) {
			return true
		}

		if isDataDownloadInFinalState(dd) && !dd.DeletionTimestamp.IsZero() {
			return true
		}

		return false
	})
	s := kube.NewPeriodicalEnqueueSource(r.logger.WithField("controller", constant.ControllerDataDownload), r.client, &velerov2alpha1api.DataDownloadList{}, preparingMonitorFrequency, kube.PeriodicalEnqueueSourceOption{
		Predicates: []predicate.Predicate{gp},
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov2alpha1api.DataDownload{}).
		WatchesRawSource(s).
		Watches(&corev1api.Pod{}, kube.EnqueueRequestsFromMapUpdateFunc(r.findSnapshotRestoreForPod),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(ue event.UpdateEvent) bool {
					newObj := ue.ObjectNew.(*corev1api.Pod)

					if _, ok := newObj.Labels[velerov1api.DataDownloadLabel]; !ok {
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

func (r *DataDownloadReconciler) findSnapshotRestoreForPod(ctx context.Context, podObj client.Object) []reconcile.Request {
	pod := podObj.(*corev1api.Pod)
	dd, err := findDataDownloadByPod(r.client, *pod)

	log := r.logger.WithField("pod", pod.Name)
	if err != nil {
		log.WithError(err).Error("unable to get DataDownload")
		return []reconcile.Request{}
	} else if dd == nil {
		log.Error("get empty DataDownload")
		return []reconcile.Request{}
	}
	log = log.WithFields(logrus.Fields{
		"Dataddownload": dd.Name,
	})

	if dd.Status.Phase != velerov2alpha1api.DataDownloadPhaseAccepted {
		return []reconcile.Request{}
	}

	if pod.Status.Phase == corev1api.PodRunning {
		log.Info("Preparing data download")
		if err = UpdateDataDownloadWithRetry(context.Background(), r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log,
			func(dd *velerov2alpha1api.DataDownload) bool {
				if isDataDownloadInFinalState(dd) {
					log.Warnf("datadownload %s is terminated, abort setting it to prepared", dd.Name)
					return false
				}

				r.prepareDataDownload(dd)
				return true
			}); err != nil {
			log.WithError(err).Warn("failed to update dataudownload, prepare will halt for this dataudownload")
			return []reconcile.Request{}
		}
	} else if unrecoverable, reason := kube.IsPodUnrecoverable(pod, log); unrecoverable {
		err := UpdateDataDownloadWithRetry(context.Background(), r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, r.logger.WithField("datadownlad", dd.Name),
			func(dataDownload *velerov2alpha1api.DataDownload) bool {
				if dataDownload.Spec.Cancel {
					return false
				}

				dataDownload.Spec.Cancel = true
				dataDownload.Status.Message = fmt.Sprintf("Cancel datadownload because the exposing pod %s/%s is in abnormal status for reason %s", pod.Namespace, pod.Name, reason)

				return true
			})

		if err != nil {
			log.WithError(err).Warn("failed to cancel datadownload, and it will wait for prepare timeout")
			return []reconcile.Request{}
		}
		log.Infof("Exposed pod is in abnormal status(reason %s) and datadownload is marked as cancel", reason)
	} else {
		return []reconcile.Request{}
	}

	request := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: dd.Namespace,
			Name:      dd.Name,
		},
	}
	return []reconcile.Request{request}
}

func (r *DataDownloadReconciler) prepareDataDownload(ssb *velerov2alpha1api.DataDownload) {
	ssb.Status.Phase = velerov2alpha1api.DataDownloadPhasePrepared
	ssb.Status.Node = r.nodeName
}

func (r *DataDownloadReconciler) errorOut(ctx context.Context, dd *velerov2alpha1api.DataDownload, err error, msg string, log logrus.FieldLogger) (ctrl.Result, error) {
	if r.restoreExposer != nil {
		r.restoreExposer.CleanUp(ctx, getDataDownloadOwnerObject(dd))
	}
	return ctrl.Result{}, r.updateStatusToFailed(ctx, dd, err, msg, log)
}

func (r *DataDownloadReconciler) updateStatusToFailed(ctx context.Context, dd *velerov2alpha1api.DataDownload, err error, msg string, log logrus.FieldLogger) error {
	log.Info("update data download status to Failed")

	if patchErr := UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, log, func(dd *velerov2alpha1api.DataDownload) bool {
		if isDataDownloadInFinalState(dd) {
			return false
		}

		dd.Status.Phase = velerov2alpha1api.DataDownloadPhaseFailed
		dd.Status.Message = errors.WithMessage(err, msg).Error()
		dd.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		delete(dd.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); patchErr != nil {
		log.WithError(patchErr).Error("error updating DataDownload status")
	} else {
		r.metrics.RegisterDataDownloadFailure(r.nodeName)
	}

	return err
}

func (r *DataDownloadReconciler) acceptDataDownload(ctx context.Context, dd *velerov2alpha1api.DataDownload) (bool, error) {
	r.logger.Infof("Accepting data download %s", dd.Name)

	// For all data download controller in each node-agent will try to update download CR, and only one controller will success,
	// and the success one could handle later logic

	updated := dd.DeepCopy()

	updateFunc := func(datadownload *velerov2alpha1api.DataDownload) {
		datadownload.Status.Phase = velerov2alpha1api.DataDownloadPhaseAccepted
		datadownload.Status.AcceptedByNode = r.nodeName
		datadownload.Status.AcceptedTimestamp = &metav1.Time{Time: r.Clock.Now()}

		if datadownload.Labels == nil {
			datadownload.Labels = make(map[string]string)
		}
		datadownload.Labels[exposer.ExposeOnGoingLabel] = "true"
	}

	succeeded, err := funcExclusiveUpdateDataDownload(ctx, r.client, updated, updateFunc)

	if err != nil {
		return false, err
	}

	if succeeded {
		updateFunc(dd) // If update success, it's need to update du values in memory
		r.logger.WithField("DataDownload", dd.Name).Infof("This datadownload has been accepted by %s", r.nodeName)
		return true, nil
	}

	r.logger.WithField("DataDownload", dd.Name).Info("This datadownload has been accepted by others")
	return false, nil
}

func (r *DataDownloadReconciler) onPrepareTimeout(ctx context.Context, dd *velerov2alpha1api.DataDownload) {
	log := r.logger.WithField("DataDownload", dd.Name)

	log.Info("Timeout happened for preparing datadownload")
	succeeded, err := funcExclusiveUpdateDataDownload(ctx, r.client, dd, func(dd *velerov2alpha1api.DataDownload) {
		dd.Status.Phase = velerov2alpha1api.DataDownloadPhaseFailed
		dd.Status.Message = "timeout on preparing data download"

		delete(dd.Labels, exposer.ExposeOnGoingLabel)
	})

	if err != nil {
		log.WithError(err).Warn("Failed to update datadownload")
		return
	}

	if !succeeded {
		log.Warn("Datadownload has been updated by others")
		return
	}

	diags := strings.Split(r.restoreExposer.DiagnoseExpose(ctx, getDataDownloadOwnerObject(dd)), "\n")
	for _, diag := range diags {
		log.Warnf("[Diagnose DD expose]%s", diag)
	}

	r.restoreExposer.CleanUp(ctx, getDataDownloadOwnerObject(dd))

	log.Info("Datadownload has been cleaned up")

	r.metrics.RegisterDataDownloadFailure(r.nodeName)
}

var funcExclusiveUpdateDataDownload = exclusiveUpdateDataDownload

func exclusiveUpdateDataDownload(ctx context.Context, cli client.Client, dd *velerov2alpha1api.DataDownload,
	updateFunc func(*velerov2alpha1api.DataDownload)) (bool, error) {
	updateFunc(dd)

	err := cli.Update(ctx, dd)

	if err == nil {
		return true, nil
	}
	// it won't rollback dd in memory when error
	if apierrors.IsConflict(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (r *DataDownloadReconciler) getTargetPVC(ctx context.Context, dd *velerov2alpha1api.DataDownload) (*corev1api.PersistentVolumeClaim, error) {
	return r.kubeClient.CoreV1().PersistentVolumeClaims(dd.Spec.TargetVolume.Namespace).Get(ctx, dd.Spec.TargetVolume.PVC, metav1.GetOptions{})
}

func (r *DataDownloadReconciler) closeDataPath(ctx context.Context, ddName string) {
	asyncBR := r.dataPathMgr.GetAsyncBR(ddName)
	if asyncBR != nil {
		asyncBR.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(ddName)
}

func (r *DataDownloadReconciler) setupExposeParam(dd *velerov2alpha1api.DataDownload) (exposer.GenericRestoreExposeParam, error) {
	log := r.logger.WithField("datadownload", dd.Name)

	nodeOS := string(dd.Spec.NodeOS)
	if nodeOS == "" {
		log.Info("nodeOS is empty in DD, fallback to linux")
		nodeOS = kube.NodeOSLinux
	}

	if err := kube.HasNodeWithOS(context.Background(), nodeOS, r.kubeClient.CoreV1()); err != nil {
		return exposer.GenericRestoreExposeParam{}, errors.Wrapf(err, "no appropriate node to run datadownload %s/%s", dd.Namespace, dd.Name)
	}

	hostingPodLabels := map[string]string{velerov1api.DataDownloadLabel: dd.Name}
	if len(r.podLabels) > 0 {
		for k, v := range r.podLabels {
			hostingPodLabels[k] = v
		}
	} else {
		for _, k := range util.ThirdPartyLabels {
			if v, err := nodeagent.GetLabelValue(context.Background(), r.kubeClient, dd.Namespace, k, nodeOS); err != nil {
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
			if v, err := nodeagent.GetAnnotationValue(context.Background(), r.kubeClient, dd.Namespace, k, nodeOS); err != nil {
				if err != nodeagent.ErrNodeAgentAnnotationNotFound {
					log.WithError(err).Warnf("Failed to check node-agent annotation, skip adding host pod annotation %s", k)
				}
			} else {
				hostingPodAnnotation[k] = v
			}
		}
	}

	hostingPodTolerations, err := nodeagent.GetTolerations(context.Background(), r.kubeClient, dd.Namespace, nodeOS)
	if err != nil {
		log.WithError(err).Warn("Failed to get node-agent tolerations, hosting pod will have no tolerations")
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

	return exposer.GenericRestoreExposeParam{
		TargetPVCName:         dd.Spec.TargetVolume.PVC,
		TargetNamespace:       dd.Spec.TargetVolume.Namespace,
		HostingPodLabels:      hostingPodLabels,
		HostingPodAnnotations: hostingPodAnnotation,
		HostingPodTolerations: hostingPodTolerations,
		Resources:             r.podResources,
		OperationTimeout:      dd.Spec.OperationTimeout.Duration,
		ExposeTimeout:         r.preparingTimeout,
		NodeOS:                nodeOS,
		RestorePVCConfig:      r.restorePVCConfig,
		LoadAffinity:          r.loadAffinity,
		PriorityClassName:     r.dataMovePriorityClass,
		RestoreSize:           dd.Spec.SnapshotSize,
		CacheVolume:           cacheVolume,
	}, nil
}

func getDataDownloadOwnerObject(dd *velerov2alpha1api.DataDownload) corev1api.ObjectReference {
	return corev1api.ObjectReference{
		Kind:       dd.Kind,
		Namespace:  dd.Namespace,
		Name:       dd.Name,
		UID:        dd.UID,
		APIVersion: dd.APIVersion,
	}
}

func findDataDownloadByPod(client client.Client, pod corev1api.Pod) (*velerov2alpha1api.DataDownload, error) {
	if label, exist := pod.Labels[velerov1api.DataDownloadLabel]; exist {
		dd := &velerov2alpha1api.DataDownload{}
		err := client.Get(context.Background(), types.NamespacedName{
			Namespace: pod.Namespace,
			Name:      label,
		}, dd)

		if err != nil {
			return nil, errors.Wrapf(err, "error to find DataDownload by pod %s/%s", pod.Namespace, pod.Name)
		}
		return dd, nil
	}

	return nil, nil
}

func isDataDownloadInFinalState(dd *velerov2alpha1api.DataDownload) bool {
	return dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseFailed ||
		dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseCanceled ||
		dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseCompleted
}

func UpdateDataDownloadWithRetry(ctx context.Context, client client.Client, namespacedName types.NamespacedName, log logrus.FieldLogger, updateFunc func(*velerov2alpha1api.DataDownload) bool) error {
	return wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		dd := &velerov2alpha1api.DataDownload{}
		if err := client.Get(ctx, namespacedName, dd); err != nil {
			return false, errors.Wrap(err, "getting DataDownload")
		}

		if updateFunc(dd) {
			err := client.Update(ctx, dd)
			if err != nil {
				if apierrors.IsConflict(err) {
					log.Debugf("failed to update datadownload for %s/%s and will retry it", dd.Namespace, dd.Name)
					return false, nil
				} else {
					return false, errors.Wrapf(err, "error updating datadownload %s/%s", dd.Namespace, dd.Name)
				}
			}
		}

		return true, nil
	})
}

var funcResumeCancellableDataRestore = (*DataDownloadReconciler).resumeCancellableDataPath

func (r *DataDownloadReconciler) AttemptDataDownloadResume(ctx context.Context, logger *logrus.Entry, ns string) error {
	dataDownloads := &velerov2alpha1api.DataDownloadList{}
	if err := r.client.List(ctx, dataDownloads, &client.ListOptions{Namespace: ns}); err != nil {
		r.logger.WithError(errors.WithStack(err)).Error("failed to list datadownloads")
		return errors.Wrapf(err, "error to list datadownloads")
	}

	for i := range dataDownloads.Items {
		dd := &dataDownloads.Items[i]
		if dd.Status.Phase == velerov2alpha1api.DataDownloadPhaseInProgress {
			if dd.Status.Node != r.nodeName {
				logger.WithField("dd", dd.Name).WithField("current node", r.nodeName).Infof("DD should be resumed by another node %s", dd.Status.Node)
				continue
			}

			err := funcResumeCancellableDataRestore(r, ctx, dd, logger)
			if err == nil {
				logger.WithField("dd", dd.Name).WithField("current node", r.nodeName).Info("Completed to resume in progress DD")
				continue
			}

			logger.WithField("datadownload", dd.GetName()).WithError(err).Warn("Failed to resume data path for dd, have to cancel it")

			resumeErr := err
			err = UpdateDataDownloadWithRetry(ctx, r.client, types.NamespacedName{Namespace: dd.Namespace, Name: dd.Name}, logger.WithField("datadownload", dd.Name),
				func(dataDownload *velerov2alpha1api.DataDownload) bool {
					if dataDownload.Spec.Cancel {
						return false
					}

					dataDownload.Spec.Cancel = true
					dataDownload.Status.Message = fmt.Sprintf("Resume InProgress datadownload failed with error %v, mark it as cancel", resumeErr)

					return true
				})
			if err != nil {
				logger.WithError(errors.WithStack(err)).WithError(errors.WithStack(err)).Error("Failed to trigger datadownload cancel")
			}
		} else if !isDataDownloadInFinalState(dd) {
			// the Prepared CR could be still handled by datadownload controller after node-agent restart
			// the accepted CR may also suvived from node-agent restart as long as the intermediate objects are all done
			logger.WithField("datadownload", dd.GetName()).Infof("find a datadownload with status %s", dd.Status.Phase)
		}
	}

	return nil
}

func (r *DataDownloadReconciler) resumeCancellableDataPath(ctx context.Context, dd *velerov2alpha1api.DataDownload, log logrus.FieldLogger) error {
	log.Info("Resume cancelable dataDownload")

	res, err := r.restoreExposer.GetExposed(ctx, getDataDownloadOwnerObject(dd), r.client, r.nodeName, dd.Spec.OperationTimeout.Duration)
	if err != nil {
		return errors.Wrapf(err, "error to get exposed volume for dd %s", dd.Name)
	}

	if res == nil {
		return errors.Errorf("expose info missed for dd %s", dd.Name)
	}

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataDownloadCompleted,
		OnFailed:    r.OnDataDownloadFailed,
		OnCancelled: r.OnDataDownloadCancelled,
		OnProgress:  r.OnDataDownloadProgress,
	}

	asyncBR, err := r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, r.kubeClient, r.mgr, datapath.TaskTypeRestore, dd.Name, dd.Namespace, res.ByPod.HostingPod.Name, res.ByPod.HostingContainer, dd.Name, callbacks, true, log)
	if err != nil {
		return errors.Wrapf(err, "error to create asyncBR watcher for dd %s", dd.Name)
	}

	resumeComplete := false
	defer func() {
		if !resumeComplete {
			r.closeDataPath(ctx, dd.Name)
		}
	}()

	if err := asyncBR.Init(ctx, nil); err != nil {
		return errors.Wrapf(err, "error to init asyncBR watcher for dd %s", dd.Name)
	}

	if err := asyncBR.StartRestore(dd.Spec.SnapshotID, datapath.AccessPoint{
		ByPath: res.ByPod.VolumeName,
	}, nil); err != nil {
		return errors.Wrapf(err, "error to resume asyncBR watcher for dd %s", dd.Name)
	}

	resumeComplete = true

	log.Infof("asyncBR is resumed for dd %s", dd.Name)

	return nil
}
