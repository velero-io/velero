/*
Copyright the Velero contributors.

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
	"sync"
	"time"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/hook"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

type restoreFinalizerReconciler struct {
	client.Client
	namespace         string
	logger            logrus.FieldLogger
	newPluginManager  func(logger logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter persistence.ObjectBackupStoreGetter
	metrics           *metrics.ServerMetrics
	clock             clock.WithTickerAndDelayedExecution
	crClient          client.Client
	multiHookTracker  *hook.MultiHookTracker
	resourceTimeout   time.Duration
}

func NewRestoreFinalizerReconciler(
	logger logrus.FieldLogger,
	namespace string,
	client client.Client,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	metrics *metrics.ServerMetrics,
	crClient client.Client,
	multiHookTracker *hook.MultiHookTracker,
	resourceTimeout time.Duration,
) *restoreFinalizerReconciler {
	return &restoreFinalizerReconciler{
		Client:            client,
		logger:            logger,
		namespace:         namespace,
		newPluginManager:  newPluginManager,
		backupStoreGetter: backupStoreGetter,
		metrics:           metrics,
		clock:             &clock.RealClock{},
		crClient:          crClient,
		multiHookTracker:  multiHookTracker,
		resourceTimeout:   resourceTimeout,
	}
}

func (r *restoreFinalizerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Restore{}).
		Named(constant.ControllerRestoreFinalizer).
		Complete(r)
}

// +kubebuilder:rbac:groups=velero.io,resources=restores,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=velero.io,resources=restores/status,verbs=get
func (r *restoreFinalizerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithField("restore finalizer", req.String())
	log.Debug("restoreFinalizerReconciler getting restore")

	original := &velerov1api.Restore{}
	if err := r.Get(ctx, req.NamespacedName, original); err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Error("restore not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrapf(err, "error getting restore %s", req.String())
	}
	restore := original.DeepCopy()
	log.Debugf("restore: %s", restore.Name)

	log = r.logger.WithFields(
		logrus.Fields{
			"restore": req.String(),
		},
	)

	switch restore.Status.Phase {
	case velerov1api.RestorePhaseFinalizing, velerov1api.RestorePhaseFinalizingPartiallyFailed:
	default:
		log.Debug("Restore is not awaiting finalization, skipping")
		return ctrl.Result{}, nil
	}

	info, err := fetchBackupInfoInternal(r.Client, r.namespace, restore.Spec.BackupName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Error("not found backup, skip")
			if err2 := r.finishProcessing(velerov1api.RestorePhasePartiallyFailed, restore, original); err2 != nil {
				log.WithError(err2).Error("error updating restore's final status")
				return ctrl.Result{}, errors.Wrap(err2, "error updating restore's final status")
			}
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("error getting backup info")
		return ctrl.Result{}, errors.Wrap(err, "error getting backup info")
	}

	pluginManager := r.newPluginManager(r.logger)
	defer pluginManager.CleanupClients()
	backupStore, err := r.backupStoreGetter.Get(info.location, pluginManager, r.logger)
	if err != nil {
		log.WithError(err).Error("error getting backup store")
		return ctrl.Result{}, errors.Wrap(err, "error getting backup store")
	}

	volumeInfo, err := backupStore.GetBackupVolumeInfos(restore.Spec.BackupName)
	if err != nil {
		log.WithError(err).Errorf("error getting volumeInfo for backup %s", restore.Spec.BackupName)
		return ctrl.Result{}, errors.Wrap(err, "error getting volumeInfo")
	}

	restoredResourceList, err := backupStore.GetRestoredResourceList(restore.Name)
	if err != nil {
		log.WithError(err).Error("error getting restoredResourceList")
		return ctrl.Result{}, errors.Wrap(err, "error getting restoredResourceList")
	}

	restoredPVCList := volume.RestoredPVCFromRestoredResourceList(restoredResourceList)

	restoreItemOperations, err := backupStore.GetRestoreItemOperations(restore.Name)
	if err != nil {
		log.WithError(err).Error("error getting itemOperationList")
		return ctrl.Result{}, errors.Wrap(err, "error getting itemOperationList")
	}

	finalizerCtx := &finalizerContext{
		logger:           log,
		restore:          restore,
		crClient:         r.crClient,
		volumeInfo:       volumeInfo,
		restoredPVCList:  restoredPVCList,
		multiHookTracker: r.multiHookTracker,
		resourceTimeout:  r.resourceTimeout,
		restoreItemOperationList: restoreItemOperationList{
			items: restoreItemOperations,
		},
	}
	warnings, errs := finalizerCtx.execute()

	warningCnt := len(warnings.Velero) + len(warnings.Cluster)
	for _, w := range warnings.Namespaces {
		warningCnt += len(w)
	}
	errCnt := len(errs.Velero) + len(errs.Cluster)
	for _, e := range errs.Namespaces {
		errCnt += len(e)
	}
	restore.Status.Warnings += warningCnt
	restore.Status.Errors += errCnt

	if !errs.IsEmpty() {
		restore.Status.Phase = velerov1api.RestorePhaseFinalizingPartiallyFailed
	}

	if warningCnt > 0 || errCnt > 0 {
		err := r.updateResults(backupStore, restore, &warnings, &errs)
		if err != nil {
			log.WithError(err).Error("error updating results")
			return ctrl.Result{}, errors.Wrap(err, "error updating results")
		}
	}

	finalPhase := velerov1api.RestorePhaseCompleted
	if restore.Status.Phase == velerov1api.RestorePhaseFinalizingPartiallyFailed {
		finalPhase = velerov1api.RestorePhasePartiallyFailed
	}
	log.Infof("Marking restore %s", finalPhase)

	if err := r.finishProcessing(finalPhase, restore, original); err != nil {
		log.WithError(err).Error("error updating restore's final status")
		return ctrl.Result{}, errors.Wrap(err, "error updating restore's final status")
	}

	return ctrl.Result{}, nil
}

func (r *restoreFinalizerReconciler) updateResults(backupStore persistence.BackupStore, restore *velerov1api.Restore, newWarnings *results.Result, newErrs *results.Result) error {
	originResults, err := backupStore.GetRestoreResults(restore.Name)
	if err != nil {
		return errors.Wrap(err, "error getting restore results")
	}
	warnings := originResults["warnings"]
	errs := originResults["errors"]
	warnings.Merge(newWarnings)
	errs.Merge(newErrs)

	m := map[string]results.Result{
		"warnings": warnings,
		"errors":   errs,
	}
	if err := putResults(restore, m, backupStore); err != nil {
		return errors.Wrap(err, "error putting restore results")
	}

	return nil
}

func (r *restoreFinalizerReconciler) finishProcessing(restorePhase velerov1api.RestorePhase, restore *velerov1api.Restore, original *velerov1api.Restore) error {
	if restorePhase == velerov1api.RestorePhasePartiallyFailed {
		restore.Status.Phase = velerov1api.RestorePhasePartiallyFailed
		r.metrics.RegisterRestorePartialFailure(restore.Spec.ScheduleName)
	} else {
		restore.Status.Phase = velerov1api.RestorePhaseCompleted
		r.metrics.RegisterRestoreSuccess(restore.Spec.ScheduleName)
	}
	restore.Status.CompletionTimestamp = &metav1.Time{Time: r.clock.Now()}
	// retry `Finalizing`/`FinalizingPartiallyFailed` to
	// - `Completed`
	// - `PartiallyFailed`
	return kubeutil.PatchResourceWithRetriesOnErrors(r.resourceTimeout, original, restore, r.Client)
}

type restoreItemOperationList struct {
	items []*itemoperation.RestoreOperation
}

func (r *restoreItemOperationList) selectByResource(group, resource, ns, name string) []*itemoperation.RestoreOperation {
	var res []*itemoperation.RestoreOperation
	rid := velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{
			Group:    group,
			Resource: resource,
		},
		Namespace: ns,
		Name:      name,
	}
	for _, item := range r.items {
		if item != nil && item.Spec.ResourceIdentifier == rid {
			res = append(res, item)
		}
	}
	return res
}

// SelectByPVC filters the restore item operation list by PVC namespace and name.
func (r *restoreItemOperationList) SelectByPVC(ns, name string) []*itemoperation.RestoreOperation {
	return r.selectByResource("", "persistentvolumeclaims", ns, name)
}

// finalizerContext includes all the dependencies required by finalization tasks and
// a function execute() to orderly implement task logic.
type finalizerContext struct {
	logger                   logrus.FieldLogger
	restore                  *velerov1api.Restore
	crClient                 client.Client
	volumeInfo               []*volume.BackupVolumeInfo
	restoredPVCList          map[string]struct{}
	restoreItemOperationList restoreItemOperationList
	multiHookTracker         *hook.MultiHookTracker
	resourceTimeout          time.Duration
}

func (ctx *finalizerContext) execute() (results.Result, results.Result) {
	warnings, errs := results.Result{}, results.Result{}

	// implement finalization tasks
	pdpErrs := ctx.patchDynamicPVWithVolumeInfo()
	errs.Merge(&pdpErrs)

	vgscWarnings := ctx.cleanupStubVGSC()
	warnings.Merge(&vgscWarnings)

	rehErrs := ctx.WaitRestoreExecHook()
	errs.Merge(&rehErrs)

	return warnings, errs
}

// patchDynamicPV patches newly dynamically provisioned PV using volume info
// in order to restore custom settings that would otherwise be lost during dynamic PV recreation.
func (ctx *finalizerContext) patchDynamicPVWithVolumeInfo() (errs results.Result) {
	ctx.logger.Info("patching newly dynamically provisioned PV starts")

	var pvWaitGroup sync.WaitGroup
	var resultLock sync.Mutex

	maxConcurrency := 3
	semaphore := make(chan struct{}, maxConcurrency)

	for _, volumeItem := range ctx.volumeInfo {
		if (volumeItem.BackupMethod == volume.PodVolumeBackup || volumeItem.BackupMethod == volume.CSISnapshot) && volumeItem.PVInfo != nil {
			// Determine restored PVC namespace
			restoredNamespace := volumeItem.PVCNamespace
			if remapped, ok := ctx.restore.Spec.NamespaceMapping[restoredNamespace]; ok {
				restoredNamespace = remapped
			}

			// Check if PVC was restored in previous phase
			pvcKey := fmt.Sprintf("%s/%s", restoredNamespace, volumeItem.PVCName)
			if _, restored := ctx.restoredPVCList[pvcKey]; !restored {
				continue
			}

			pvWaitGroup.Add(1)
			go func(volInfo volume.BackupVolumeInfo, restoredNamespace string) {
				defer pvWaitGroup.Done()

				semaphore <- struct{}{}

				log := ctx.logger.WithField("PVC", volInfo.PVCName).WithField("PVCNamespace", restoredNamespace)
				log.Debug("patching dynamic PV is in progress")

				err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, ctx.resourceTimeout, true, func(context.Context) (bool, error) {
					// wait for PVC to be bound
					pvc := &corev1api.PersistentVolumeClaim{}
					err := ctx.crClient.Get(context.Background(), client.ObjectKey{Name: volInfo.PVCName, Namespace: restoredNamespace}, pvc)
					if apierrors.IsNotFound(err) {
						log.Debug("error not finding PVC")
						return false, nil
					}
					if err != nil {
						return false, err
					}

					// Check whether the async operation to populate the PVC is successful.  If it's not, will skip patching the PV, instead of waiting.
					operations := ctx.restoreItemOperationList.SelectByPVC(pvc.Namespace, pvc.Name)
					for _, op := range operations {
						if op.Spec.RestoreItemAction == constant.PluginCSIPVCRestoreRIA &&
							op.Status.Phase != itemoperation.OperationPhaseCompleted {
							log.Warnf("skipping PV patch, because the operation to restore the PVC is not completed, "+
								"operation: %s, phase: %s", op.Spec.OperationID, op.Status.Phase)
							return true, nil
						}
					}

					// We are handling a common but specific scenario where a PVC is in a pending state and uses a storage class with
					// VolumeBindingMode set to WaitForFirstConsumer. In this case, the PV patch step is skipped to avoid
					// failures due to the PVC not being bound, which could cause a timeout and result in a failed restore.
					if pvc.Status.Phase == corev1api.ClaimPending {
						// check if storage class used has VolumeBindingMode as WaitForFirstConsumer
						scName := *pvc.Spec.StorageClassName
						sc := &storagev1api.StorageClass{}
						err = ctx.crClient.Get(context.Background(), client.ObjectKey{Name: scName}, sc)

						if err != nil {
							errs.Add(restoredNamespace, err)
							return false, err
						}
						// skip PV patch step for this scenario
						// because pvc would not be bound and the PV patch step would fail due to timeout thus failing the restore
						if *sc.VolumeBindingMode == storagev1api.VolumeBindingWaitForFirstConsumer {
							log.Warnf("skipping PV patch to restore custom reclaim policy, if any: StorageClass %s used by PVC %s has VolumeBindingMode set to WaitForFirstConsumer, and the PVC is also in a pending state", scName, pvc.Name)
							return true, nil
						}
					}

					if pvc.Status.Phase != corev1api.ClaimBound || pvc.Spec.VolumeName == "" {
						log.Debugf("PVC: %s not ready", pvc.Name)
						return false, nil
					}

					// wait for PV to be bound
					pvName := pvc.Spec.VolumeName
					pv := &corev1api.PersistentVolume{}
					err = ctx.crClient.Get(context.Background(), client.ObjectKey{Name: pvName}, pv)
					if apierrors.IsNotFound(err) {
						log.Debugf("error not finding PV: %s", pvName)
						return false, nil
					}
					if err != nil {
						return false, err
					}

					if pv.Spec.ClaimRef == nil || pv.Status.Phase != corev1api.VolumeBound {
						log.Debugf("PV: %s not ready", pvName)
						return false, nil
					}

					// validate PV
					if pv.Spec.ClaimRef.Name != pvc.Name || pv.Spec.ClaimRef.Namespace != restoredNamespace {
						return false, fmt.Errorf("PV was bound by unexpected PVC, unexpected PVC: %s/%s, expected PVC: %s/%s",
							pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name, restoredNamespace, pvc.Name)
					}

					// patch PV's reclaim policy and label using the corresponding data stored in volume info
					if needPatch(pv, volInfo.PVInfo) {
						updatedPV := pv.DeepCopy()
						updatedPV.Labels = volInfo.PVInfo.Labels
						updatedPV.Spec.PersistentVolumeReclaimPolicy = corev1api.PersistentVolumeReclaimPolicy(volInfo.PVInfo.ReclaimPolicy)
						if err := kubeutil.PatchResource(pv, updatedPV, ctx.crClient); err != nil {
							return false, err
						}
						log.Infof("newly dynamically provisioned PV:%s has been patched using volume info", pvName)
					}

					return true, nil
				})

				if err != nil {
					err = fmt.Errorf("fail to patch dynamic PV, err: %s, PVC: %s, PV: %s", err, volInfo.PVCName, volInfo.PVName)
					ctx.logger.WithError(errors.WithStack((err))).Error("err patching dynamic PV using volume info")
					resultLock.Lock()
					defer resultLock.Unlock()
					errs.Add(restoredNamespace, err)
				}

				<-semaphore
			}(*volumeItem, restoredNamespace)
		}
	}

	pvWaitGroup.Wait()
	ctx.logger.Info("patching newly dynamically provisioned PV ends")

	return errs
}

// cleanupStubVGSC deletes stub VolumeGroupSnapshotContent objects that were
// created during restore to satisfy CSI controller validation. These stubs are
// labeled with velero.io/restore-name for identification.
// Before deleting each VGSC, it waits for all related VolumeSnapshotContents
// to become ReadyToUse, since the CSI controller needs the VGSC during VSC reconciliation.
func (ctx *finalizerContext) cleanupStubVGSC() (warnings results.Result) {
	ctx.logger.Info("cleaning up stub VolumeGroupSnapshotContents")

	vgscList := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentList{}
	err := ctx.crClient.List(
		context.Background(),
		vgscList,
		client.MatchingLabels{velerov1api.RestoreNameLabel: ctx.restore.Name},
	)
	if err != nil {
		// If the CRD is not installed, listing will fail. This is expected
		// on clusters without VolumeGroupSnapshot support, so treat as warning.
		ctx.logger.WithError(err).Warn("failed to list stub VolumeGroupSnapshotContents, skipping cleanup")
		warnings.Add("cluster", errors.Wrap(err, "failed to list stub VolumeGroupSnapshotContents"))
		return warnings
	}

	if len(vgscList.Items) == 0 {
		ctx.logger.Info("no stub VolumeGroupSnapshotContents to clean up")
		return warnings
	}

	for i := range vgscList.Items {
		vgsc := &vgscList.Items[i]
		log := ctx.logger.WithField("vgsc", vgsc.Name)

		// Collect the snapshot handles associated with this VGSC
		snapshotHandles := map[string]bool{}
		if vgsc.Spec.Source.GroupSnapshotHandles != nil {
			for _, h := range vgsc.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles {
				snapshotHandles[h] = true
			}
		}

		if len(snapshotHandles) > 0 {
			// Wait for related VSCs to become ReadyToUse before deleting the VGSC
			log.Infof("waiting for %d related VolumeSnapshotContents to become ReadyToUse", len(snapshotHandles))
			err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, ctx.resourceTimeout, true, func(context.Context) (bool, error) {
				vscList := &snapshotv1api.VolumeSnapshotContentList{}
				if err := ctx.crClient.List(context.Background(), vscList, client.MatchingLabels{velerov1api.RestoreNameLabel: ctx.restore.Name}); err != nil {
					log.WithError(err).Warn("failed to list VolumeSnapshotContents")
					return false, nil
				}

				for j := range vscList.Items {
					vsc := &vscList.Items[j]
					if vsc.Spec.Source.SnapshotHandle == nil {
						continue
					}
					if !snapshotHandles[*vsc.Spec.Source.SnapshotHandle] {
						continue
					}
					// This VSC is related to our VGSC
					if vsc.Status == nil || !boolptr.IsSetToTrue(vsc.Status.ReadyToUse) {
						log.Debugf("VolumeSnapshotContent %s not yet ReadyToUse", vsc.Name)
						return false, nil
					}
				}
				return true, nil
			})
			if err != nil {
				log.WithError(err).Warn("timed out waiting for related VolumeSnapshotContents to become ReadyToUse, proceeding with VGSC deletion")
				warnings.Add("cluster", errors.Wrapf(err, "timed out waiting for VSCs related to VGSC %s", vgsc.Name))
			}
		}

		log.Info("deleting stub VolumeGroupSnapshotContent")
		if err := ctx.crClient.Delete(context.Background(), vgsc); err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("stub VolumeGroupSnapshotContent already deleted")
				continue
			}
			log.WithError(err).Warn("failed to delete stub VolumeGroupSnapshotContent")
			warnings.Add("cluster", errors.Wrapf(err, "failed to delete stub VolumeGroupSnapshotContent %s", vgsc.Name))
		} else {
			log.Info("deleted stub VolumeGroupSnapshotContent")
		}
	}

	return warnings
}

func needPatch(newPV *corev1api.PersistentVolume, pvInfo *volume.PVInfo) bool {
	if newPV.Spec.PersistentVolumeReclaimPolicy != corev1api.PersistentVolumeReclaimPolicy(pvInfo.ReclaimPolicy) {
		return true
	}

	newPVLabels, pvLabels := newPV.Labels, pvInfo.Labels
	for k, v := range pvLabels {
		if _, ok := newPVLabels[k]; !ok {
			return true
		}
		if newPVLabels[k] != v {
			return true
		}
	}

	return false
}

// WaitRestoreExecHook waits for restore exec hooks to finish then update the hook execution results
func (ctx *finalizerContext) WaitRestoreExecHook() (errs results.Result) {
	log := ctx.logger.WithField("restore", ctx.restore.Name)
	log.Info("Waiting for restore exec hooks starts")

	// wait for restore exec hooks to finish
	err := wait.PollUntilContextCancel(context.Background(), 1*time.Second, true, func(context.Context) (bool, error) {
		attempted, failed := ctx.multiHookTracker.Stat(ctx.restore.Name)
		log.Debugf("Checking the progress of hooks execution: attempted=%d, failed=%d", attempted, failed)
		if ctx.multiHookTracker.IsComplete(ctx.restore.Name) {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		errs.Add(ctx.restore.Namespace, err)
		return errs
	}
	log.Info("Done waiting for restore exec hooks starts")

	for _, ei := range ctx.multiHookTracker.HookErrs(ctx.restore.Name) {
		errs.Add(ei.Namespace, ei.Err)
	}

	// update hooks execution status
	updated := ctx.restore.DeepCopy()
	if updated.Status.HookStatus == nil {
		updated.Status.HookStatus = &velerov1api.HookStatus{}
	}
	updated.Status.HookStatus.HooksAttempted, updated.Status.HookStatus.HooksFailed = ctx.multiHookTracker.Stat(ctx.restore.Name)
	log.Debugf("hookAttempted: %d, hookFailed: %d", updated.Status.HookStatus.HooksAttempted, updated.Status.HookStatus.HooksFailed)

	if err := kubeutil.PatchResource(ctx.restore, updated, ctx.crClient); err != nil {
		log.WithError(errors.WithStack((err))).Error("Updating restore status")
		errs.Add(ctx.restore.Namespace, err)
	}

	// delete the hook data for this restore
	ctx.multiHookTracker.Delete(ctx.restore.Name)

	return errs
}
