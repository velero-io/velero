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

	snapshotter "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/typed/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clocks "k8s.io/utils/clock"
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
	"github.com/vmware-tanzu/velero/pkg/datamover"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	dataUploadDownloadRequestor = "snapshot-data-upload-download"
	DataUploadDownloadFinalizer = "velero.io/data-upload-download-finalizer"
	preparingMonitorFrequency   = time.Minute
	cancelDelayInProgress       = time.Hour
	cancelDelayOthers           = time.Minute * 5
)

// DataUploadReconciler reconciles a DataUpload object
type DataUploadReconciler struct {
	client                client.Client
	kubeClient            kubernetes.Interface
	csiSnapshotClient     snapshotter.SnapshotV1Interface
	mgr                   manager.Manager
	Clock                 clocks.WithTickerAndDelayedExecution
	nodeName              string
	logger                logrus.FieldLogger
	snapshotExposerList   map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer
	dataPathMgr           *datapath.Manager
	vgdpCounter           *exposer.VgdpCounter
	loadAffinity          []*kube.LoadAffinity
	backupPVCConfig       map[string]velerotypes.BackupPVC
	podResources          corev1api.ResourceRequirements
	preparingTimeout      time.Duration
	metrics               *metrics.ServerMetrics
	cancelledDataUpload   map[string]time.Time
	dataMovePriorityClass string
	podLabels             map[string]string
	podAnnotations        map[string]string
}

func NewDataUploadReconciler(
	client client.Client,
	mgr manager.Manager,
	kubeClient kubernetes.Interface,
	csiSnapshotClient snapshotter.SnapshotV1Interface,
	dataPathMgr *datapath.Manager,
	counter *exposer.VgdpCounter,
	loadAffinity []*kube.LoadAffinity,
	backupPVCConfig map[string]velerotypes.BackupPVC,
	podResources corev1api.ResourceRequirements,
	clock clocks.WithTickerAndDelayedExecution,
	nodeName string,
	preparingTimeout time.Duration,
	log logrus.FieldLogger,
	metrics *metrics.ServerMetrics,
	dataMovePriorityClass string,
	podLabels map[string]string,
	podAnnotations map[string]string,
) *DataUploadReconciler {
	return &DataUploadReconciler{
		client:            client,
		mgr:               mgr,
		kubeClient:        kubeClient,
		csiSnapshotClient: csiSnapshotClient,
		Clock:             clock,
		nodeName:          nodeName,
		logger:            log,
		snapshotExposerList: map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{
			velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(
				kubeClient,
				csiSnapshotClient,
				log,
			),
		},
		dataPathMgr:           dataPathMgr,
		vgdpCounter:           counter,
		loadAffinity:          loadAffinity,
		backupPVCConfig:       backupPVCConfig,
		podResources:          podResources,
		preparingTimeout:      preparingTimeout,
		metrics:               metrics,
		cancelledDataUpload:   make(map[string]time.Time),
		dataMovePriorityClass: dataMovePriorityClass,
		podLabels:             podLabels,
		podAnnotations:        podAnnotations,
	}
}

// +kubebuilder:rbac:groups=velero.io,resources=datauploads,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=datauploads/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumes,verbs=get
// +kubebuilder:rbac:groups="",resources=persistentvolumerclaims,verbs=get

func (r *DataUploadReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithFields(logrus.Fields{
		"controller": "dataupload",
		"dataupload": req.NamespacedName,
	})
	log.Infof("Reconcile %s", req.Name)
	du := &velerov2alpha1api.DataUpload{}
	if err := r.client.Get(ctx, req.NamespacedName, du); err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("Unable to find DataUpload")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err, "getting DataUpload")
	}

	if !datamover.IsBuiltInUploader(du.Spec.DataMover) {
		log.WithField("Data mover", du.Spec.DataMover).Debug("it is not one built-in data mover which is not supported by Velero")
		return ctrl.Result{}, nil
	}

	// Logic for clear resources when dataupload been deleted
	if !isDataUploadInFinalState(du) {
		if !controllerutil.ContainsFinalizer(du, DataUploadDownloadFinalizer) {
			if err := UpdateDataUploadWithRetry(ctx, r.client, req.NamespacedName, log, func(dataUpload *velerov2alpha1api.DataUpload) bool {
				if controllerutil.ContainsFinalizer(dataUpload, DataUploadDownloadFinalizer) {
					return false
				}

				controllerutil.AddFinalizer(dataUpload, DataUploadDownloadFinalizer)

				return true
			}); err != nil {
				log.WithError(err).Errorf("failed to add finalizer for du %s/%s", du.Namespace, du.Name)
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		if !du.DeletionTimestamp.IsZero() {
			if !du.Spec.Cancel {
				// when delete cr we need to clear up internal resources created by Velero, here we use the cancel mechanism
				// to help clear up resources instead of clear them directly in case of some conflict with Expose action
				log.Warnf("Cancel du under phase %s because it is being deleted", du.Status.Phase)

				if err := UpdateDataUploadWithRetry(ctx, r.client, req.NamespacedName, log, func(dataUpload *velerov2alpha1api.DataUpload) bool {
					if dataUpload.Spec.Cancel {
						return false
					}

					dataUpload.Spec.Cancel = true
					dataUpload.Status.Message = "Cancel dataupload because it is being deleted"

					return true
				}); err != nil {
					log.WithError(err).Errorf("failed to set cancel flag for du %s/%s", du.Namespace, du.Name)
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, nil
			}
		}
	} else {
		delete(r.cancelledDataUpload, du.Name)

		// put the finalizer remove action here for all cr will goes to the final status, we could check finalizer and do remove action in final status
		// instead of intermediate state.
		// remove finalizer no matter whether the cr is being deleted or not for it is no longer needed when internal resources are all cleaned up
		// also in final status cr won't block the direct delete of the velero namespace
		if controllerutil.ContainsFinalizer(du, DataUploadDownloadFinalizer) {
			if err := UpdateDataUploadWithRetry(ctx, r.client, req.NamespacedName, log, func(du *velerov2alpha1api.DataUpload) bool {
				if !controllerutil.ContainsFinalizer(du, DataUploadDownloadFinalizer) {
					return false
				}

				controllerutil.RemoveFinalizer(du, DataUploadDownloadFinalizer)

				return true
			}); err != nil {
				log.WithError(err).Error("error to remove finalizer")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}
	}

	if du.Spec.Cancel {
		if spotted, found := r.cancelledDataUpload[du.Name]; !found {
			r.cancelledDataUpload[du.Name] = r.Clock.Now()
		} else {
			delay := cancelDelayOthers
			if du.Status.Phase == velerov2alpha1api.DataUploadPhaseInProgress {
				delay = cancelDelayInProgress
			}

			if time.Since(spotted) > delay {
				log.Infof("Data upload %s is canceled in Phase %s but not handled in reasonable time", du.GetName(), du.Status.Phase)
				if r.tryCancelDataUpload(ctx, du, "") {
					delete(r.cancelledDataUpload, du.Name)
				}

				return ctrl.Result{}, nil
			}
		}
	}

	ep, ok := r.snapshotExposerList[du.Spec.SnapshotType]
	if !ok {
		return r.errorOut(ctx, du, errors.Errorf("%s type of snapshot exposer is not exist", du.Spec.SnapshotType), "not exist type of exposer", log)
	}

	if du.Status.Phase == "" || du.Status.Phase == velerov2alpha1api.DataUploadPhaseNew {
		if du.Spec.Cancel {
			log.Debugf("Data upload is canceled in Phase %s", du.Status.Phase)

			r.tryCancelDataUpload(ctx, du, "")

			return ctrl.Result{}, nil
		}

		if r.vgdpCounter != nil && r.vgdpCounter.IsConstrained(ctx, r.logger) {
			log.Debug("Data path initiation is constrained, requeue later")
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}

		log.Info("Data upload starting")

		accepted, err := r.acceptDataUpload(ctx, du)
		if err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error accepting the data upload %s", du.Name)
		}

		if !accepted {
			log.Debug("Data upload is not accepted")
			return ctrl.Result{}, nil
		}

		log.Info("Data upload is accepted")

		exposeParam, err := r.setupExposeParam(du)
		if err != nil {
			return r.errorOut(ctx, du, err, "failed to set exposer parameters", log)
		}

		// Expose() will trigger to create one pod whose volume is restored by a given volume snapshot,
		// but the pod maybe is not in the same node of the current controller, so we need to return it here.
		// And then only the controller who is in the same node could do the rest work.
		if err := ep.Expose(ctx, getOwnerObject(du), exposeParam); err != nil {
			return r.errorOut(ctx, du, err, "error exposing snapshot", log)
		}

		log.Info("Snapshot is exposed")

		return ctrl.Result{}, nil
	} else if du.Status.Phase == velerov2alpha1api.DataUploadPhaseAccepted {
		if peekErr := ep.PeekExposed(ctx, getOwnerObject(du)); peekErr != nil {
			log.Errorf("Cancel du %s/%s because of expose error %s", du.Namespace, du.Name, peekErr)

			diags := strings.Split(ep.DiagnoseExpose(ctx, getOwnerObject(du)), "\n")
			for _, diag := range diags {
				log.Warnf("[Diagnose DU expose]%s", diag)
			}

			r.tryCancelDataUpload(ctx, du, fmt.Sprintf("found a du %s/%s with expose error: %s. mark it as cancel", du.Namespace, du.Name, peekErr))
		} else if du.Status.AcceptedTimestamp != nil {
			if time.Since(du.Status.AcceptedTimestamp.Time) >= r.preparingTimeout {
				r.onPrepareTimeout(ctx, du)
			}
		}

		return ctrl.Result{}, nil
	} else if du.Status.Phase == velerov2alpha1api.DataUploadPhasePrepared {
		log.Infof("Data upload is prepared and should be processed by %s (%s)", du.Status.Node, r.nodeName)

		if du.Status.Node != r.nodeName {
			return ctrl.Result{}, nil
		}

		if du.Spec.Cancel {
			log.Info("Prepared data upload is being canceled")
			r.OnDataUploadCancelled(ctx, du.GetNamespace(), du.GetName())
			return ctrl.Result{}, nil
		}

		asyncBR := r.dataPathMgr.GetAsyncBR(du.Name)
		if asyncBR != nil {
			log.Info("Cancellable data path is already started")
			return ctrl.Result{}, nil
		}
		waitExposePara := r.setupWaitExposePara(du)
		res, err := ep.GetExposed(ctx, getOwnerObject(du), du.Spec.OperationTimeout.Duration, waitExposePara)
		if err != nil {
			return r.errorOut(ctx, du, err, "exposed snapshot is not ready", log)
		} else if res == nil {
			return r.errorOut(ctx, du, errors.New("no expose result is available for the current node"), "exposed snapshot is not ready", log)
		}

		if res.ByPod.NodeOS == nil {
			return r.errorOut(ctx, du, errors.New("unsupported ambiguous node OS"), "invalid expose result", log)
		}

		log.Info("Exposed snapshot is ready and creating data path routine")

		// Need to first create file system BR and get data path instance then update data upload status
		callbacks := datapath.Callbacks{
			OnCompleted: r.OnDataUploadCompleted,
			OnFailed:    r.OnDataUploadFailed,
			OnCancelled: r.OnDataUploadCancelled,
			OnProgress:  r.OnDataUploadProgress,
		}

		asyncBR, err = r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, r.kubeClient, r.mgr, datapath.TaskTypeBackup,
			du.Name, du.Namespace, res.ByPod.HostingPod.Name, res.ByPod.HostingContainer, du.Name, callbacks, false, log)
		if err != nil {
			if err == datapath.ConcurrentLimitExceed {
				log.Debug("Data path instance is concurrent limited requeue later")
				return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
			} else {
				return r.errorOut(ctx, du, err, "error to create data path", log)
			}
		}

		if err := r.initCancelableDataPath(ctx, asyncBR, res, log); err != nil {
			log.WithError(err).Errorf("Failed to init cancelable data path for %s", du.Name)

			r.closeDataPath(ctx, du.Name)
			return r.errorOut(ctx, du, err, "error initializing data path", log)
		}

		// Update status to InProgress
		terminated := false
		if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(du *velerov2alpha1api.DataUpload) bool {
			if isDataUploadInFinalState(du) {
				terminated = true
				return false
			}

			du.Status.Phase = velerov2alpha1api.DataUploadPhaseInProgress
			du.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}
			du.Status.NodeOS = velerov2alpha1api.NodeOS(*res.ByPod.NodeOS)

			delete(du.Labels, exposer.ExposeOnGoingLabel)

			return true
		}); err != nil {
			log.WithError(err).Warnf("Failed to update dataupload %s to InProgress, will data path close and retry", du.Name)

			r.closeDataPath(ctx, du.Name)
			return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5}, nil
		}

		if terminated {
			log.Warnf("dataupload %s is terminated during transition from prepared", du.Name)
			r.closeDataPath(ctx, du.Name)
			return ctrl.Result{}, nil
		}

		log.Info("Data upload is marked as in progress")

		if err := r.startCancelableDataPath(asyncBR, du, res, log); err != nil {
			log.WithError(err).Errorf("Failed to start cancelable data path for %s", du.Name)
			r.closeDataPath(ctx, du.Name)

			return r.errorOut(ctx, du, err, "error starting data path", log)
		}

		return ctrl.Result{}, nil
	} else if du.Status.Phase == velerov2alpha1api.DataUploadPhaseInProgress {
		if du.Spec.Cancel {
			if du.Status.Node != r.nodeName {
				return ctrl.Result{}, nil
			}

			log.Info("In progress data upload is being canceled")

			asyncBR := r.dataPathMgr.GetAsyncBR(du.Name)
			if asyncBR == nil {
				r.OnDataUploadCancelled(ctx, du.GetNamespace(), du.GetName())
				return ctrl.Result{}, nil
			}

			// Update status to Canceling
			if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(du *velerov2alpha1api.DataUpload) bool {
				if isDataUploadInFinalState(du) {
					log.Warnf("dataupload %s is terminated, abort setting it to canceling", du.Name)
					return false
				}

				du.Status.Phase = velerov2alpha1api.DataUploadPhaseCanceling
				return true
			}); err != nil {
				log.WithError(err).Error("error updating data upload into canceling status")
				return ctrl.Result{}, err
			}

			asyncBR.Cancel()
			return ctrl.Result{}, nil
		}
	}

	return ctrl.Result{}, nil
}

func (r *DataUploadReconciler) initCancelableDataPath(ctx context.Context, asyncBR datapath.AsyncBR, res *exposer.ExposeResult, log logrus.FieldLogger) error {
	log.Info("Init cancelable dataUpload")

	if err := asyncBR.Init(ctx, nil); err != nil {
		return errors.Wrap(err, "error initializing asyncBR")
	}

	log.Infof("async backup init for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)

	return nil
}

func (r *DataUploadReconciler) startCancelableDataPath(asyncBR datapath.AsyncBR, du *velerov2alpha1api.DataUpload, res *exposer.ExposeResult, log logrus.FieldLogger) error {
	log.Info("Start cancelable dataUpload")

	if err := asyncBR.StartBackup(datapath.AccessPoint{
		ByPath: res.ByPod.VolumeName,
	}, du.Spec.DataMoverConfig, nil); err != nil {
		return errors.Wrapf(err, "error starting async backup for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)
	}

	log.Infof("Async backup started for pod %s, volume %s", res.ByPod.HostingPod.Name, res.ByPod.VolumeName)
	return nil
}

func (r *DataUploadReconciler) OnDataUploadCompleted(ctx context.Context, namespace string, duName string, result datapath.Result) {
	defer r.dataPathMgr.RemoveAsyncBR(duName)

	log := r.logger.WithField("dataupload", duName)

	log.Info("Async fs backup data path completed")

	var du velerov2alpha1api.DataUpload
	if err := r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, &du); err != nil {
		log.WithError(err).Warn("Failed to get dataupload on completion")
		return
	}

	// cleans up any objects generated during the snapshot expose
	ep, ok := r.snapshotExposerList[du.Spec.SnapshotType]
	if !ok {
		log.WithError(fmt.Errorf("%v type of snapshot exposer is not exist", du.Spec.SnapshotType)).
			Warn("Failed to clean up resources on completion")
	} else {
		var volumeSnapshotName string
		if du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI { // Other exposer should have another condition
			volumeSnapshotName = du.Spec.CSISnapshot.VolumeSnapshot
		}
		ep.CleanUp(ctx, getOwnerObject(&du), volumeSnapshotName, du.Spec.SourceNamespace)
	}

	// Update status to Completed with path & snapshot ID.
	if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(du *velerov2alpha1api.DataUpload) bool {
		if isDataUploadInFinalState(du) {
			return false
		}

		du.Status.Path = result.Backup.Source.ByPath
		du.Status.Phase = velerov2alpha1api.DataUploadPhaseCompleted
		du.Status.SnapshotID = result.Backup.SnapshotID
		du.Status.IncrementalBytes = result.Backup.IncrementalBytes
		du.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}
		if result.Backup.EmptySnapshot {
			du.Status.Message = "volume was empty so no data was upload"
		}

		delete(du.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); err != nil {
		log.WithError(err).Error("error updating DataUpload status")
	} else {
		log.Info("Data upload completed")
		r.metrics.RegisterDataUploadSuccess(r.nodeName)
	}
}

func (r *DataUploadReconciler) OnDataUploadFailed(ctx context.Context, namespace, duName string, err error) {
	defer r.dataPathMgr.RemoveAsyncBR(duName)

	log := r.logger.WithField("dataupload", duName)

	log.WithError(err).Error("Async fs backup data path failed")

	var du velerov2alpha1api.DataUpload
	if getErr := r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, &du); getErr != nil {
		log.WithError(getErr).Warn("Failed to get dataupload on failure")
	} else {
		_, _ = r.errorOut(ctx, &du, err, "data path backup failed", log)
	}
}

func (r *DataUploadReconciler) OnDataUploadCancelled(ctx context.Context, namespace string, duName string) {
	defer r.dataPathMgr.RemoveAsyncBR(duName)

	log := r.logger.WithField("dataupload", duName)

	log.Warn("Async fs backup data path canceled")

	du := &velerov2alpha1api.DataUpload{}
	if getErr := r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, du); getErr != nil {
		log.WithError(getErr).Warn("Failed to get dataupload on cancel")
		return
	}
	// cleans up any objects generated during the snapshot expose
	r.cleanUp(ctx, du, log)

	if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(du *velerov2alpha1api.DataUpload) bool {
		if isDataUploadInFinalState(du) {
			return false
		}

		du.Status.Phase = velerov2alpha1api.DataUploadPhaseCanceled
		if du.Status.StartTimestamp.IsZero() {
			du.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}
		}
		du.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		delete(du.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); err != nil {
		log.WithError(err).Error("error updating DataUpload status")
	} else {
		r.metrics.RegisterDataUploadCancel(r.nodeName)
		delete(r.cancelledDataUpload, du.Name)
	}
}

func (r *DataUploadReconciler) tryCancelDataUpload(ctx context.Context, du *velerov2alpha1api.DataUpload, message string) bool {
	log := r.logger.WithField("dataupload", du.Name)
	succeeded, err := funcExclusiveUpdateDataUpload(ctx, r.client, du, func(dataUpload *velerov2alpha1api.DataUpload) {
		dataUpload.Status.Phase = velerov2alpha1api.DataUploadPhaseCanceled
		if dataUpload.Status.StartTimestamp.IsZero() {
			dataUpload.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}
		}
		dataUpload.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		if message != "" {
			dataUpload.Status.Message = message
		}

		delete(dataUpload.Labels, exposer.ExposeOnGoingLabel)
	})

	if err != nil {
		log.WithError(err).Error("error updating dataupload status")
		return false
	} else if !succeeded {
		log.Warn("conflict in updating dataupload status and will try it again later")
		return false
	}

	// success update
	r.metrics.RegisterDataUploadCancel(r.nodeName)
	// cleans up any objects generated during the snapshot expose
	r.cleanUp(ctx, du, log)

	log.Warn("data upload is canceled")

	return true
}

func (r *DataUploadReconciler) cleanUp(ctx context.Context, du *velerov2alpha1api.DataUpload, log logrus.FieldLogger) {
	ep, ok := r.snapshotExposerList[du.Spec.SnapshotType]
	if !ok {
		log.WithError(fmt.Errorf("%v type of snapshot exposer is not exist", du.Spec.SnapshotType)).
			Warn("Failed to clean up resources on canceled")
	} else {
		var volumeSnapshotName string
		if du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI { // Other exposer should have another condition
			volumeSnapshotName = du.Spec.CSISnapshot.VolumeSnapshot
		}
		ep.CleanUp(ctx, getOwnerObject(du), volumeSnapshotName, du.Spec.SourceNamespace)
	}
}

func (r *DataUploadReconciler) OnDataUploadProgress(ctx context.Context, namespace string, duName string, progress *uploader.Progress) {
	log := r.logger.WithField("dataupload", duName)

	if err := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: namespace, Name: duName}, log, func(du *velerov2alpha1api.DataUpload) bool {
		du.Status.Progress = shared.DataMoveOperationProgress{TotalBytes: progress.TotalBytes, BytesDone: progress.BytesDone}
		return true
	}); err != nil {
		log.WithError(err).Error("Failed to update progress")
	}
}

// SetupWithManager registers the DataUpload controller.
// The fresh new DataUpload CR first created will trigger to create one pod (long time, maybe failure or unknown status) by one of the dataupload controllers
// then the request will get out of the Reconcile queue immediately by not blocking others' CR handling, in order to finish the rest data upload process we need to
// re-enqueue the previous related request once the related pod is in running status to keep going on the rest logic. and below logic will avoid handling the unwanted
// pod status and also avoid block others CR handling
func (r *DataUploadReconciler) SetupWithManager(mgr ctrl.Manager) error {
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		du := object.(*velerov2alpha1api.DataUpload)
		if du.Status.Phase == velerov2alpha1api.DataUploadPhaseAccepted {
			return true
		}

		if du.Spec.Cancel && !isDataUploadInFinalState(du) {
			return true
		}

		if isDataUploadInFinalState(du) && !du.DeletionTimestamp.IsZero() {
			return true
		}

		return false
	})
	s := kube.NewPeriodicalEnqueueSource(r.logger.WithField("controller", constant.ControllerDataUpload), r.client, &velerov2alpha1api.DataUploadList{}, preparingMonitorFrequency, kube.PeriodicalEnqueueSourceOption{
		Predicates: []predicate.Predicate{gp},
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov2alpha1api.DataUpload{}).
		WatchesRawSource(s).
		Watches(&corev1api.Pod{}, kube.EnqueueRequestsFromMapUpdateFunc(r.findDataUploadForPod),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(ue event.UpdateEvent) bool {
					newObj := ue.ObjectNew.(*corev1api.Pod)

					if _, ok := newObj.Labels[velerov1api.DataUploadLabel]; !ok {
						return false
					}

					if newObj.Spec.NodeName != r.nodeName {
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

func (r *DataUploadReconciler) findDataUploadForPod(ctx context.Context, podObj client.Object) []reconcile.Request {
	pod := podObj.(*corev1api.Pod)
	du, err := findDataUploadByPod(r.client, *pod)
	log := r.logger.WithFields(logrus.Fields{
		"Backup pod": pod.Name,
	})

	if err != nil {
		log.WithError(err).Error("unable to get dataupload")
		return []reconcile.Request{}
	} else if du == nil {
		log.Error("get empty DataUpload")
		return []reconcile.Request{}
	}
	log = log.WithFields(logrus.Fields{
		"Datadupload": du.Name,
	})

	if du.Status.Phase != velerov2alpha1api.DataUploadPhaseAccepted {
		return []reconcile.Request{}
	}

	if pod.Status.Phase == corev1api.PodRunning {
		log.Info("Preparing dataupload")
		if err = UpdateDataUploadWithRetry(context.Background(), r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log,
			func(du *velerov2alpha1api.DataUpload) bool {
				if isDataUploadInFinalState(du) {
					log.Warnf("dataupload %s is terminated, abort setting it to prepared", du.Name)
					return false
				}

				r.prepareDataUpload(du)
				return true
			}); err != nil {
			log.WithError(err).Warn("failed to update dataupload, prepare will halt for this dataupload")
			return []reconcile.Request{}
		}
	} else if unrecoverable, reason := kube.IsPodUnrecoverable(pod, log); unrecoverable { // let the abnormal backup pod failed early
		err := UpdateDataUploadWithRetry(context.Background(), r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, r.logger.WithField("dataupload", du.Name),
			func(dataUpload *velerov2alpha1api.DataUpload) bool {
				if dataUpload.Spec.Cancel {
					return false
				}

				dataUpload.Spec.Cancel = true
				dataUpload.Status.Message = fmt.Sprintf("Cancel dataupload because the exposing pod %s/%s is in abnormal status for reason %s", pod.Namespace, pod.Name, reason)

				return true
			})

		if err != nil {
			log.WithError(err).Warn("failed to cancel dataupload, and it will wait for prepare timeout")
			return []reconcile.Request{}
		}
		log.Infof("Exposed pod is in abnormal status(reason %s) and dataupload is marked as cancel", reason)
	} else {
		return []reconcile.Request{}
	}

	request := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: du.Namespace,
			Name:      du.Name,
		},
	}
	return []reconcile.Request{request}
}

func (r *DataUploadReconciler) prepareDataUpload(du *velerov2alpha1api.DataUpload) {
	du.Status.Phase = velerov2alpha1api.DataUploadPhasePrepared
	du.Status.Node = r.nodeName
}

func (r *DataUploadReconciler) errorOut(ctx context.Context, du *velerov2alpha1api.DataUpload, err error, msg string, log logrus.FieldLogger) (ctrl.Result, error) {
	if se, ok := r.snapshotExposerList[du.Spec.SnapshotType]; ok {
		var volumeSnapshotName string
		if du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI { // Other exposer should have another condition
			volumeSnapshotName = du.Spec.CSISnapshot.VolumeSnapshot
		}
		se.CleanUp(ctx, getOwnerObject(du), volumeSnapshotName, du.Spec.SourceNamespace)
	} else {
		log.Errorf("failed to clean up exposed snapshot could not find %s snapshot exposer", du.Spec.SnapshotType)
	}

	return ctrl.Result{}, r.updateStatusToFailed(ctx, du, err, msg, log)
}

func (r *DataUploadReconciler) updateStatusToFailed(ctx context.Context, du *velerov2alpha1api.DataUpload, err error, msg string, log logrus.FieldLogger) error {
	log.Info("update data upload status to Failed")

	if patchErr := UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, log, func(du *velerov2alpha1api.DataUpload) bool {
		if isDataUploadInFinalState(du) {
			return false
		}

		du.Status.Phase = velerov2alpha1api.DataUploadPhaseFailed
		du.Status.Message = errors.WithMessage(err, msg).Error()
		if du.Status.StartTimestamp.IsZero() {
			du.Status.StartTimestamp = &metav1.Time{Time: r.Clock.Now()}
		}

		if dataPathError, ok := err.(datapath.DataPathError); ok {
			du.Status.SnapshotID = dataPathError.GetSnapshotID()
		}
		du.Status.CompletionTimestamp = &metav1.Time{Time: r.Clock.Now()}

		delete(du.Labels, exposer.ExposeOnGoingLabel)

		return true
	}); patchErr != nil {
		log.WithError(patchErr).Error("error updating DataUpload status")
	} else {
		r.metrics.RegisterDataUploadFailure(r.nodeName)
	}

	return err
}

func (r *DataUploadReconciler) acceptDataUpload(ctx context.Context, du *velerov2alpha1api.DataUpload) (bool, error) {
	r.logger.Infof("Accepting data upload %s", du.Name)

	// For all data upload controller in each node-agent will try to update dataupload CR, and only one controller will success,
	// and the success one could handle later logic
	updated := du.DeepCopy()

	updateFunc := func(dataUpload *velerov2alpha1api.DataUpload) {
		dataUpload.Status.Phase = velerov2alpha1api.DataUploadPhaseAccepted
		dataUpload.Status.AcceptedByNode = r.nodeName
		dataUpload.Status.AcceptedTimestamp = &metav1.Time{Time: r.Clock.Now()}

		if dataUpload.Labels == nil {
			dataUpload.Labels = make(map[string]string)
		}
		dataUpload.Labels[exposer.ExposeOnGoingLabel] = "true"
	}

	succeeded, err := funcExclusiveUpdateDataUpload(ctx, r.client, updated, updateFunc)

	if err != nil {
		return false, err
	}

	if succeeded {
		updateFunc(du) // If update success, it's need to update du values in memory
		r.logger.WithField("Dataupload", du.Name).Infof("This datauplod has been accepted by %s", r.nodeName)
		return true, nil
	}

	r.logger.WithField("Dataupload", du.Name).Info("This datauplod has been accepted by others")
	return false, nil
}

func (r *DataUploadReconciler) onPrepareTimeout(ctx context.Context, du *velerov2alpha1api.DataUpload) {
	log := r.logger.WithField("Dataupload", du.Name)

	log.Info("Timeout happened for preparing dataupload")

	succeeded, err := funcExclusiveUpdateDataUpload(ctx, r.client, du, func(du *velerov2alpha1api.DataUpload) {
		du.Status.Phase = velerov2alpha1api.DataUploadPhaseFailed
		du.Status.Message = "timeout on preparing data upload"

		delete(du.Labels, exposer.ExposeOnGoingLabel)
	})

	if err != nil {
		log.WithError(err).Warn("Failed to update dataupload")
		return
	}

	if !succeeded {
		log.Warn("Dataupload has been updated by others")
		return
	}

	ep, ok := r.snapshotExposerList[du.Spec.SnapshotType]
	if !ok {
		log.WithError(fmt.Errorf("%v type of snapshot exposer is not exist", du.Spec.SnapshotType)).
			Warn("Failed to clean up resources on canceled")
	} else {
		var volumeSnapshotName string
		if du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI { // Other exposer should have another condition
			volumeSnapshotName = du.Spec.CSISnapshot.VolumeSnapshot
		}

		diags := strings.Split(ep.DiagnoseExpose(ctx, getOwnerObject(du)), "\n")
		for _, diag := range diags {
			log.Warnf("[Diagnose DU expose]%s", diag)
		}

		ep.CleanUp(ctx, getOwnerObject(du), volumeSnapshotName, du.Spec.SourceNamespace)

		log.Info("Dataupload has been cleaned up")
	}

	r.metrics.RegisterDataUploadFailure(r.nodeName)
}

var funcExclusiveUpdateDataUpload = exclusiveUpdateDataUpload

func exclusiveUpdateDataUpload(ctx context.Context, cli client.Client, du *velerov2alpha1api.DataUpload,
	updateFunc func(*velerov2alpha1api.DataUpload)) (bool, error) {
	updateFunc(du)

	err := cli.Update(ctx, du)
	if err == nil {
		return true, nil
	}

	// warn we won't rollback du values in memory when error
	if apierrors.IsConflict(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (r *DataUploadReconciler) closeDataPath(ctx context.Context, duName string) {
	asyncBR := r.dataPathMgr.GetAsyncBR(duName)
	if asyncBR != nil {
		asyncBR.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(duName)
}

func (r *DataUploadReconciler) setupExposeParam(du *velerov2alpha1api.DataUpload) (any, error) {
	log := r.logger.WithField("dataupload", du.Name)

	if du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI {
		pvc := &corev1api.PersistentVolumeClaim{}
		err := r.client.Get(context.Background(), types.NamespacedName{
			Namespace: du.Spec.SourceNamespace,
			Name:      du.Spec.SourcePVC,
		}, pvc)

		if err != nil {
			return nil, errors.Wrapf(err, "failed to get PVC %s/%s", du.Spec.SourceNamespace, du.Spec.SourcePVC)
		}

		pv := &corev1api.PersistentVolume{}
		if err := r.client.Get(context.Background(), types.NamespacedName{
			Name: pvc.Spec.VolumeName,
		}, pv); err != nil {
			return nil, errors.Wrapf(err, "failed to get source PV %s", pvc.Spec.VolumeName)
		}

		nodeOS := kube.GetPVCAttachingNodeOS(pvc, r.kubeClient.CoreV1(), r.kubeClient.StorageV1(), log)

		if err := kube.HasNodeWithOS(context.Background(), nodeOS, r.kubeClient.CoreV1()); err != nil {
			return nil, errors.Wrapf(err, "no appropriate node to run data upload for PVC %s/%s", du.Spec.SourceNamespace, du.Spec.SourcePVC)
		}

		accessMode := exposer.AccessModeFileSystem
		if pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode == corev1api.PersistentVolumeBlock {
			accessMode = exposer.AccessModeBlock
		}

		hostingPodLabels := map[string]string{velerov1api.DataUploadLabel: du.Name}
		if len(r.podLabels) > 0 {
			for k, v := range r.podLabels {
				hostingPodLabels[k] = v
			}
		} else {
			for _, k := range util.ThirdPartyLabels {
				if v, err := nodeagent.GetLabelValue(context.Background(), r.kubeClient, du.Namespace, k, nodeOS); err != nil {
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
				if v, err := nodeagent.GetAnnotationValue(context.Background(), r.kubeClient, du.Namespace, k, nodeOS); err != nil {
					if err != nodeagent.ErrNodeAgentAnnotationNotFound {
						log.WithError(err).Warnf("Failed to check node-agent annotation, skip adding host pod annotation %s", k)
					}
				} else {
					hostingPodAnnotation[k] = v
				}
			}
		}

		hostingPodTolerations, err := nodeagent.GetTolerations(context.Background(), r.kubeClient, du.Namespace, nodeOS)
		if err != nil {
			log.WithError(err).Warn("Failed to get node-agent tolerations, hosting pod will have no tolerations")
		}

		return &exposer.CSISnapshotExposeParam{
			SnapshotName:          du.Spec.CSISnapshot.VolumeSnapshot,
			SourceNamespace:       du.Spec.SourceNamespace,
			SourcePVCName:         pvc.Name,
			SourcePVName:          pv.Name,
			StorageClass:          du.Spec.CSISnapshot.StorageClass,
			HostingPodLabels:      hostingPodLabels,
			HostingPodAnnotations: hostingPodAnnotation,
			HostingPodTolerations: hostingPodTolerations,
			AccessMode:            accessMode,
			OperationTimeout:      du.Spec.OperationTimeout.Duration,
			ExposeTimeout:         r.preparingTimeout,
			VolumeSize:            pvc.Spec.Resources.Requests[corev1api.ResourceStorage],
			Affinity:              r.loadAffinity,
			BackupPVCConfig:       r.backupPVCConfig,
			Resources:             r.podResources,
			NodeOS:                nodeOS,
			PriorityClassName:     r.dataMovePriorityClass,
		}, nil
	}

	return nil, nil
}

func (r *DataUploadReconciler) setupWaitExposePara(du *velerov2alpha1api.DataUpload) any {
	if du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI {
		return &exposer.CSISnapshotExposeWaitParam{
			NodeClient: r.client,
			NodeName:   r.nodeName,
		}
	}
	return nil
}

func getOwnerObject(du *velerov2alpha1api.DataUpload) corev1api.ObjectReference {
	return corev1api.ObjectReference{
		Kind:       du.Kind,
		Namespace:  du.Namespace,
		Name:       du.Name,
		UID:        du.UID,
		APIVersion: du.APIVersion,
	}
}

func findDataUploadByPod(client client.Client, pod corev1api.Pod) (*velerov2alpha1api.DataUpload, error) {
	if label, exist := pod.Labels[velerov1api.DataUploadLabel]; exist {
		du := &velerov2alpha1api.DataUpload{}
		err := client.Get(context.Background(), types.NamespacedName{
			Namespace: pod.Namespace,
			Name:      label,
		}, du)

		if err != nil {
			return nil, errors.Wrapf(err, "error to find DataUpload by pod %s/%s", pod.Namespace, pod.Name)
		}
		return du, nil
	}
	return nil, nil
}

func isDataUploadInFinalState(du *velerov2alpha1api.DataUpload) bool {
	return du.Status.Phase == velerov2alpha1api.DataUploadPhaseFailed ||
		du.Status.Phase == velerov2alpha1api.DataUploadPhaseCanceled ||
		du.Status.Phase == velerov2alpha1api.DataUploadPhaseCompleted
}

func UpdateDataUploadWithRetry(ctx context.Context, client client.Client, namespacedName types.NamespacedName, log logrus.FieldLogger, updateFunc func(*velerov2alpha1api.DataUpload) bool) error {
	return wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		du := &velerov2alpha1api.DataUpload{}
		if err := client.Get(ctx, namespacedName, du); err != nil {
			return false, errors.Wrap(err, "getting DataUpload")
		}

		if updateFunc(du) {
			err := client.Update(ctx, du)
			if err != nil {
				if apierrors.IsConflict(err) {
					log.Debugf("failed to update dataupload for %s/%s and will retry it", du.Namespace, du.Name)
					return false, nil
				} else {
					return false, errors.Wrapf(err, "error updating dataupload with error %s/%s", du.Namespace, du.Name)
				}
			}
		}

		return true, nil
	})
}

var funcResumeCancellableDataBackup = (*DataUploadReconciler).resumeCancellableDataPath

func (r *DataUploadReconciler) AttemptDataUploadResume(ctx context.Context, logger *logrus.Entry, ns string) error {
	dataUploads := &velerov2alpha1api.DataUploadList{}
	if err := r.client.List(ctx, dataUploads, &client.ListOptions{Namespace: ns}); err != nil {
		r.logger.WithError(errors.WithStack(err)).Error("failed to list datauploads")
		return errors.Wrapf(err, "error to list datauploads")
	}

	for i := range dataUploads.Items {
		du := &dataUploads.Items[i]
		if du.Status.Phase == velerov2alpha1api.DataUploadPhaseInProgress {
			if du.Status.Node != r.nodeName {
				logger.WithField("du", du.Name).WithField("current node", r.nodeName).Infof("DU should be resumed by another node %s", du.Status.Node)
				continue
			}

			err := funcResumeCancellableDataBackup(r, ctx, du, logger)
			if err == nil {
				logger.WithField("du", du.Name).WithField("current node", r.nodeName).Info("Completed to resume in progress DU")
				continue
			}

			logger.WithField("dataupload", du.GetName()).WithError(err).Warn("Failed to resume data path for du, have to cancel it")

			resumeErr := err
			err = UpdateDataUploadWithRetry(ctx, r.client, types.NamespacedName{Namespace: du.Namespace, Name: du.Name}, logger.WithField("dataupload", du.Name),
				func(dataUpload *velerov2alpha1api.DataUpload) bool {
					if dataUpload.Spec.Cancel {
						return false
					}

					dataUpload.Spec.Cancel = true
					dataUpload.Status.Message = fmt.Sprintf("Resume InProgress dataupload failed with error %v, mark it as cancel", resumeErr)

					return true
				})
			if err != nil {
				logger.WithField("dataupload", du.GetName()).WithError(errors.WithStack(err)).Error("Failed to trigger dataupload cancel")
			}
		} else if !isDataUploadInFinalState(du) {
			// the Prepared CR could be still handled by dataupload controller after node-agent restart
			// the accepted CR may also suvived from node-agent restart as long as the intermediate objects are all done
			logger.WithField("dataupload", du.GetName()).Infof("find a dataupload with status %s", du.Status.Phase)
		}
	}

	return nil
}

func (r *DataUploadReconciler) resumeCancellableDataPath(ctx context.Context, du *velerov2alpha1api.DataUpload, log logrus.FieldLogger) error {
	log.Info("Resume cancelable dataUpload")

	ep, ok := r.snapshotExposerList[du.Spec.SnapshotType]
	if !ok {
		return errors.Errorf("error to find exposer for du %s", du.Name)
	}

	waitExposePara := r.setupWaitExposePara(du)
	res, err := ep.GetExposed(ctx, getOwnerObject(du), du.Spec.OperationTimeout.Duration, waitExposePara)
	if err != nil {
		return errors.Wrapf(err, "error to get exposed snapshot for du %s", du.Name)
	}

	if res == nil {
		return errors.Errorf("expose info missed for du %s", du.Name)
	}

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataUploadCompleted,
		OnFailed:    r.OnDataUploadFailed,
		OnCancelled: r.OnDataUploadCancelled,
		OnProgress:  r.OnDataUploadProgress,
	}

	asyncBR, err := r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, r.kubeClient, r.mgr, datapath.TaskTypeBackup, du.Name, du.Namespace, res.ByPod.HostingPod.Name, res.ByPod.HostingContainer, du.Name, callbacks, true, log)
	if err != nil {
		return errors.Wrapf(err, "error to create asyncBR watcher for du %s", du.Name)
	}

	resumeComplete := false
	defer func() {
		if !resumeComplete {
			r.closeDataPath(ctx, du.Name)
		}
	}()

	if err := asyncBR.Init(ctx, nil); err != nil {
		return errors.Wrapf(err, "error to init asyncBR watcher for du %s", du.Name)
	}

	if err := asyncBR.StartBackup(datapath.AccessPoint{
		ByPath: res.ByPod.VolumeName,
	}, du.Spec.DataMoverConfig, nil); err != nil {
		return errors.Wrapf(err, "error to resume asyncBR watcher for du %s", du.Name)
	}

	resumeComplete = true

	log.Infof("asyncBR is resumed for du %s", du.Name)

	return nil
}
