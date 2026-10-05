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
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/itemoperationmap"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	defaultRestoreOperationsFrequency = 10 * time.Second
)

type restoreOperationsReconciler struct {
	client.Client
	namespace         string
	logger            logrus.FieldLogger
	clock             clocks.WithTickerAndDelayedExecution
	frequency         time.Duration
	itemOperationsMap *itemoperationmap.RestoreItemOperationsMap
	newPluginManager  func(logger logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter persistence.ObjectBackupStoreGetter
	metrics           *metrics.ServerMetrics
}

func NewRestoreOperationsReconciler(
	logger logrus.FieldLogger,
	namespace string,
	client client.Client,
	frequency time.Duration,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	metrics *metrics.ServerMetrics,
	itemOperationsMap *itemoperationmap.RestoreItemOperationsMap,
) *restoreOperationsReconciler {
	abor := &restoreOperationsReconciler{
		Client:            client,
		logger:            logger,
		namespace:         namespace,
		clock:             clocks.RealClock{},
		frequency:         frequency,
		itemOperationsMap: itemOperationsMap,
		newPluginManager:  newPluginManager,
		backupStoreGetter: backupStoreGetter,
		metrics:           metrics,
	}
	if abor.frequency <= 0 {
		abor.frequency = defaultRestoreOperationsFrequency
	}
	return abor
}

func (r *restoreOperationsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		restore := object.(*velerov1api.Restore)
		return (restore.Status.Phase == velerov1api.RestorePhaseWaitingForPluginOperations ||
			restore.Status.Phase == velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed)
	})
	s := kube.NewPeriodicalEnqueueSource(r.logger.WithField("controller", constant.ControllerRestoreOperations), mgr.GetClient(), &velerov1api.RestoreList{}, r.frequency, kube.PeriodicalEnqueueSourceOption{
		Predicates: []predicate.Predicate{gp},
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Restore{}, builder.WithPredicates(kube.FalsePredicate{})).
		WatchesRawSource(s).
		Named(constant.ControllerRestoreOperations).
		Complete(r)
}

// +kubebuilder:rbac:groups=velero.io,resources=restores,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=velero.io,resources=restores/status,verbs=get

func (r *restoreOperationsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithField("restore operations for restore", req.String())
	log.Debug("restoreOperationsReconciler getting restore")

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
	case velerov1api.RestorePhaseWaitingForPluginOperations, velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed:
		// only process restores waiting for plugin operations to complete
	default:
		log.Debug("Restore has no ongoing plugin operations, skipping")
		return ctrl.Result{}, nil
	}

	info, err := r.fetchBackupInfo(restore.Spec.BackupName)
	if err != nil {
		log.Warnf("Cannot check progress on Restore operations because backup info is unavailable %s; marking restore FinalizingPartiallyFailed", err.Error())
		restore.Status.Phase = velerov1api.RestorePhaseFinalizingPartiallyFailed
		err2 := r.updateRestoreAndOperationsJSON(ctx, original, restore, nil, &itemoperationmap.OperationsForRestore{ErrsSinceUpdate: []string{err.Error()}}, false, false)
		if err2 != nil {
			log.WithError(err2).Error("error updating Restore")
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting backup info")
	}

	pluginManager := r.newPluginManager(r.logger)
	defer pluginManager.CleanupClients()
	backupStore, err := r.backupStoreGetter.Get(info.location, pluginManager, r.logger)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error getting backup store")
	}

	operations, err := r.itemOperationsMap.GetOperationsForRestore(backupStore, restore.Name)
	if err != nil {
		err2 := r.updateRestoreAndOperationsJSON(ctx, original, restore, backupStore, &itemoperationmap.OperationsForRestore{ErrsSinceUpdate: []string{err.Error()}}, false, false)
		if err2 != nil {
			return ctrl.Result{}, errors.Wrap(err2, "error updating Restore")
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting restore operations")
	}
	stillInProgress, changes, opsCompleted, opsFailed, errs := getRestoreItemOperationProgress(restore, pluginManager, operations.Operations)
	// if len(errs)>0, need to update restore errors and error log
	operations.ErrsSinceUpdate = append(operations.ErrsSinceUpdate, errs...)
	restore.Status.Errors += len(operations.ErrsSinceUpdate)
	completionChanges := false
	if restore.Status.RestoreItemOperationsCompleted != opsCompleted || restore.Status.RestoreItemOperationsFailed != opsFailed {
		completionChanges = true
		restore.Status.RestoreItemOperationsCompleted = opsCompleted
		restore.Status.RestoreItemOperationsFailed = opsFailed
	}
	if changes {
		operations.ChangesSinceUpdate = true
	}

	if len(operations.ErrsSinceUpdate) > 0 {
		restore.Status.Phase = velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed
	}

	// if stillInProgress is false, restore moves to terminal phase and needs update
	// if operations.ErrsSinceUpdate is not empty, then restore phase needs to change to
	// RestorePhaseWaitingForPluginOperationsPartiallyFailed and needs update
	// If the only changes are incremental progress, then no write is necessary, progress can remain in memory
	if !stillInProgress {
		if restore.Status.Phase == velerov1api.RestorePhaseWaitingForPluginOperations {
			log.Infof("Marking restore %s Finalizing", restore.Name)
			restore.Status.Phase = velerov1api.RestorePhaseFinalizing
		} else {
			log.Infof("Marking restore %s FinalizingPartiallyFailed", restore.Name)
			restore.Status.Phase = velerov1api.RestorePhaseFinalizingPartiallyFailed
		}
	}
	err = r.updateRestoreAndOperationsJSON(ctx, original, restore, backupStore, operations, changes, completionChanges)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error updating Restore")
	}
	return ctrl.Result{}, nil
}

// fetchBackupInfo checks the backup lister for a backup that matches the given name. If it doesn't
// find it, it returns an error.
func (r *restoreOperationsReconciler) fetchBackupInfo(backupName string) (backupInfo, error) {
	return fetchBackupInfoInternal(r.Client, r.namespace, backupName)
}

func (r *restoreOperationsReconciler) updateRestoreAndOperationsJSON(
	ctx context.Context,
	original, restore *velerov1api.Restore,
	backupStore persistence.BackupStore,
	operations *itemoperationmap.OperationsForRestore,
	changes bool,
	completionChanges bool) error {
	if len(operations.ErrsSinceUpdate) > 0 {
		// FIXME: download/upload results
		r.logger.WithField("restore", restore.Name).Infof("Restore has %d errors", len(operations.ErrsSinceUpdate))
	}
	removeIfComplete := true
	defer func() {
		// remove local operations list if complete
		if removeIfComplete && (restore.Status.Phase == velerov1api.RestorePhaseFinalizing ||
			restore.Status.Phase == velerov1api.RestorePhaseFinalizingPartiallyFailed) {
			r.itemOperationsMap.DeleteOperationsForRestore(restore.Name)
		} else if changes {
			r.itemOperationsMap.PutOperationsForRestore(operations, restore.Name)
		}
	}()

	// update restore and upload progress if errs or complete
	if len(operations.ErrsSinceUpdate) > 0 ||
		restore.Status.Phase == velerov1api.RestorePhaseFinalizing ||
		restore.Status.Phase == velerov1api.RestorePhaseFinalizingPartiallyFailed {
		// update file store
		if backupStore != nil {
			if err := r.itemOperationsMap.UploadProgressAndPutOperationsForRestore(backupStore, operations, restore.Name); err != nil {
				removeIfComplete = false
				return err
			}
		}
		// update restore
		err := r.Client.Patch(ctx, restore, client.MergeFrom(original))
		if err != nil {
			removeIfComplete = false
			return errors.Wrapf(err, "error updating Restore %s", restore.Name)
		}
	} else if completionChanges {
		// If restore is still incomplete and no new errors are found but there are some new operations
		// completed, patch restore to reflect new completion numbers, but don't upload detailed json file
		err := r.Client.Patch(ctx, restore, client.MergeFrom(original))
		if err != nil {
			return errors.Wrapf(err, "error updating Restore %s", restore.Name)
		}
	}
	return nil
}

func getRestoreItemOperationProgress(
	restore *velerov1api.Restore,
	pluginManager clientmgmt.Manager,
	operationsList []*itemoperation.RestoreOperation) (bool, bool, int, int, []string) {
	inProgressOperations := false
	changes := false
	var errs []string
	var completedCount, failedCount int

	for _, operation := range operationsList {
		if operation.Status.Phase == itemoperation.OperationPhaseNew ||
			operation.Status.Phase == itemoperation.OperationPhaseInProgress {
			ria, err := pluginManager.GetRestoreItemActionV2(operation.Spec.RestoreItemAction)
			if err != nil {
				operation.Status.Phase = itemoperation.OperationPhaseFailed
				operation.Status.Error = err.Error()
				errs = append(errs, err.Error())
				changes = true
				failedCount++
				continue
			}
			operationProgress, err := ria.Progress(operation.Spec.OperationID, restore)
			if err != nil {
				operation.Status.Phase = itemoperation.OperationPhaseFailed
				operation.Status.Error = err.Error()
				errs = append(errs, err.Error())
				changes = true
				failedCount++
				continue
			}
			if operation.Status.NCompleted != operationProgress.NCompleted {
				operation.Status.NCompleted = operationProgress.NCompleted
				changes = true
			}
			if operation.Status.NTotal != operationProgress.NTotal {
				operation.Status.NTotal = operationProgress.NTotal
				changes = true
			}
			if operation.Status.OperationUnits != operationProgress.OperationUnits {
				operation.Status.OperationUnits = operationProgress.OperationUnits
				changes = true
			}
			if operation.Status.Description != operationProgress.Description {
				operation.Status.Description = operationProgress.Description
				changes = true
			}
			started := metav1.NewTime(operationProgress.Started)
			if operation.Status.Started == nil && !operationProgress.Started.IsZero() ||
				operation.Status.Started != nil && *(operation.Status.Started) != started {
				operation.Status.Started = &started
				changes = true
			}
			updated := metav1.NewTime(operationProgress.Updated)
			if operation.Status.Updated == nil && !operationProgress.Updated.IsZero() ||
				operation.Status.Updated != nil && *(operation.Status.Updated) != updated {
				operation.Status.Updated = &updated
				changes = true
			}

			if operationProgress.Completed {
				if operationProgress.Err != "" {
					operation.Status.Phase = itemoperation.OperationPhaseFailed
					operation.Status.Error = operationProgress.Err
					errs = append(errs, operationProgress.Err)
					changes = true
					failedCount++
					continue
				}
				operation.Status.Phase = itemoperation.OperationPhaseCompleted
				changes = true
				completedCount++
				continue
			}
			// cancel operation if past timeout period
			if operation.Status.Created.Time.Add(restore.Spec.ItemOperationTimeout.Duration).Before(time.Now()) {
				_ = ria.Cancel(operation.Spec.OperationID, restore)
				operation.Status.Phase = itemoperation.OperationPhaseFailed
				operation.Status.Error = "Asynchronous action timed out"
				errs = append(errs, operation.Status.Error)
				changes = true
				failedCount++
				continue
			}
			if operation.Status.Phase == itemoperation.OperationPhaseNew &&
				operation.Status.Started != nil {
				operation.Status.Phase = itemoperation.OperationPhaseInProgress
				changes = true
			}
			// if we reach this point, the operation is still running
			inProgressOperations = true
		} else if operation.Status.Phase == itemoperation.OperationPhaseCompleted {
			completedCount++
		} else if operation.Status.Phase == itemoperation.OperationPhaseFailed {
			failedCount++
		}
	}
	return inProgressOperations, changes, completedCount, failedCount, errs
}
