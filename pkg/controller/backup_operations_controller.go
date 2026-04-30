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
	"bytes"
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/itemoperationmap"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/util/encode"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	defaultBackupOperationsFrequency = 10 * time.Second
)

type backupOperationsReconciler struct {
	client.Client
	logger            logrus.FieldLogger
	clock             clocks.WithTickerAndDelayedExecution
	frequency         time.Duration
	itemOperationsMap *itemoperationmap.BackupItemOperationsMap
	newPluginManager  func(logger logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter persistence.ObjectBackupStoreGetter
	metrics           *metrics.ServerMetrics
}

func NewBackupOperationsReconciler(
	logger logrus.FieldLogger,
	client client.Client,
	frequency time.Duration,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	metrics *metrics.ServerMetrics,
	itemOperationsMap *itemoperationmap.BackupItemOperationsMap,
) *backupOperationsReconciler {
	abor := &backupOperationsReconciler{
		Client:            client,
		logger:            logger,
		clock:             clocks.RealClock{},
		frequency:         frequency,
		itemOperationsMap: itemOperationsMap,
		newPluginManager:  newPluginManager,
		backupStoreGetter: backupStoreGetter,
		metrics:           metrics,
	}
	if abor.frequency <= 0 {
		abor.frequency = defaultBackupOperationsFrequency
	}
	return abor
}

func (c *backupOperationsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	s := kube.NewPeriodicalEnqueueSource(c.logger, mgr.GetClient(), &velerov1api.BackupList{}, c.frequency, kube.PeriodicalEnqueueSourceOption{})
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		backup := object.(*velerov1api.Backup)
		return (backup.Status.Phase == velerov1api.BackupPhaseWaitingForPluginOperations ||
			backup.Status.Phase == velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed)
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Backup{}, builder.WithPredicates(kube.FalsePredicate{})).
		Watches(s, nil, builder.WithPredicates(gp)).
		Complete(c)
}

// +kubebuilder:rbac:groups=velero.io,resources=backups,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=velero.io,resources=backups/status,verbs=get
// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations,verbs=get

func (c *backupOperationsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.logger.WithField("backup operations for backup", req.String())
	log.Debug("backupOperationsReconciler getting backup")

	original := &velerov1api.Backup{}
	if err := c.Get(ctx, req.NamespacedName, original); err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Error("backup not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrapf(err, "error getting backup %s", req.String())
	}
	backup := original.DeepCopy()
	log.Debugf("backup: %s", backup.Name)

	log = c.logger.WithFields(
		logrus.Fields{
			"backup": req.String(),
		},
	)

	switch backup.Status.Phase {
	case velerov1api.BackupPhaseWaitingForPluginOperations, velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed:
		// only process backups waiting for plugin operations to complete
	default:
		log.Debug("Backup has no ongoing plugin operations, skipping")
		return ctrl.Result{}, nil
	}

	loc := &velerov1api.BackupStorageLocation{}
	if err := c.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      backup.Spec.StorageLocation,
	}, loc); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warnf("Cannot check progress on Backup operations because backup storage location %s does not exist; marking backup PartiallyFailed", backup.Spec.StorageLocation)
			backup.Status.Phase = velerov1api.BackupPhasePartiallyFailed
		} else {
			log.Warnf("Cannot check progress on Backup operations because backup storage location %s could not be retrieved: %s; marking backup PartiallyFailed", backup.Spec.StorageLocation, err.Error())
			backup.Status.Phase = velerov1api.BackupPhasePartiallyFailed
		}
		err2 := c.updateBackupAndOperationsJSON(ctx, original, backup, nil, &itemoperationmap.OperationsForBackup{ErrsSinceUpdate: []string{err.Error()}}, false, false)
		if err2 != nil {
			log.WithError(err2).Error("error updating Backup")
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting backup storage location")
	}

	if loc.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly {
		log.Infof("Cannot check progress on Backup operations because backup storage location %s is currently in read-only mode; marking backup PartiallyFailed", loc.Name)
		backup.Status.Phase = velerov1api.BackupPhasePartiallyFailed

		err := c.updateBackupAndOperationsJSON(ctx, original, backup, nil, &itemoperationmap.OperationsForBackup{ErrsSinceUpdate: []string{"BSL is read-only"}}, false, false)
		if err != nil {
			log.WithError(err).Error("error updating Backup")
		}
		return ctrl.Result{}, nil
	}

	pluginManager := c.newPluginManager(c.logger)
	defer pluginManager.CleanupClients()
	backupStore, err := c.backupStoreGetter.Get(loc, pluginManager, c.logger)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error getting backup store")
	}

	operations, err := c.itemOperationsMap.GetOperationsForBackup(backupStore, backup.Name)
	if err != nil {
		err2 := c.updateBackupAndOperationsJSON(ctx, original, backup, backupStore, &itemoperationmap.OperationsForBackup{ErrsSinceUpdate: []string{err.Error()}}, false, false)
		if err2 != nil {
			return ctrl.Result{}, errors.Wrap(err2, "error updating Backup")
		}
		return ctrl.Result{}, errors.Wrap(err, "error getting backup operations")
	}
	stillInProgress, changes, opsCompleted, opsFailed, errs := getBackupItemOperationProgress(backup, pluginManager, operations.Operations)
	// if len(errs)>0, need to update backup errors and error log
	operations.ErrsSinceUpdate = append(operations.ErrsSinceUpdate, errs...)
	backup.Status.Errors += len(operations.ErrsSinceUpdate)
	completionChanges := false
	if backup.Status.BackupItemOperationsCompleted != opsCompleted || backup.Status.BackupItemOperationsFailed != opsFailed {
		completionChanges = true
		backup.Status.BackupItemOperationsCompleted = opsCompleted
		backup.Status.BackupItemOperationsFailed = opsFailed
	}
	if changes {
		operations.ChangesSinceUpdate = true
	}

	if len(operations.ErrsSinceUpdate) > 0 {
		backup.Status.Phase = velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed
	}

	// if stillInProgress is false, backup moves to finalize phase and needs update
	// if operations.ErrsSinceUpdate is not empty, then backup phase needs to change to
	// BackupPhaseWaitingForPluginOperationsPartiallyFailed and needs update
	// If the only changes are incremental progress, then no write is necessary, progress can remain in memory
	if !stillInProgress {
		if backup.Status.Phase == velerov1api.BackupPhaseWaitingForPluginOperations {
			log.Infof("Marking backup %s Finalizing", backup.Name)
			backup.Status.Phase = velerov1api.BackupPhaseFinalizing
		} else {
			log.Infof("Marking backup %s FinalizingPartiallyFailed", backup.Name)
			backup.Status.Phase = velerov1api.BackupPhaseFinalizingPartiallyFailed
		}
	}
	err = c.updateBackupAndOperationsJSON(ctx, original, backup, backupStore, operations, changes, completionChanges)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "error updating Backup")
	}
	return ctrl.Result{}, nil
}

func (c *backupOperationsReconciler) updateBackupAndOperationsJSON(
	ctx context.Context,
	original, backup *velerov1api.Backup,
	backupStore persistence.BackupStore,
	operations *itemoperationmap.OperationsForBackup,
	changes bool,
	completionChanges bool) error {
	backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]

	if len(operations.ErrsSinceUpdate) > 0 {
		c.metrics.RegisterBackupItemsErrorsGauge(backupScheduleName, backup.Status.Errors)
		// FIXME: download/upload results once https://github.com/vmware-tanzu/velero/pull/5576 is merged
	}
	removeIfComplete := true
	defer func() {
		// remove local operations list if complete
		if removeIfComplete && (backup.Status.Phase == velerov1api.BackupPhaseCompleted ||
			backup.Status.Phase == velerov1api.BackupPhasePartiallyFailed ||
			backup.Status.Phase == velerov1api.BackupPhaseFinalizing ||
			backup.Status.Phase == velerov1api.BackupPhaseFinalizingPartiallyFailed) {
			c.itemOperationsMap.DeleteOperationsForBackup(backup.Name)
		} else if changes {
			c.itemOperationsMap.PutOperationsForBackup(operations, backup.Name)
		}
	}()

	// update backup and upload progress if errs or complete
	if len(operations.ErrsSinceUpdate) > 0 ||
		backup.Status.Phase == velerov1api.BackupPhaseCompleted ||
		backup.Status.Phase == velerov1api.BackupPhasePartiallyFailed ||
		backup.Status.Phase == velerov1api.BackupPhaseFinalizing ||
		backup.Status.Phase == velerov1api.BackupPhaseFinalizingPartiallyFailed {
		// update file store
		if backupStore != nil {
			backupJSON := new(bytes.Buffer)
			if err := encode.To(backup, "json", backupJSON); err != nil {
				removeIfComplete = false
				return errors.Wrap(err, "error encoding backup json")
			}
			err := backupStore.PutBackupMetadata(backup.Name, backupJSON)
			if err != nil {
				removeIfComplete = false
				return errors.Wrap(err, "error uploading backup json")
			}
			if err := c.itemOperationsMap.UploadProgressAndPutOperationsForBackup(backupStore, operations, backup.Name); err != nil {
				removeIfComplete = false
				return err
			}
		}
		// update backup
		err := c.Patch(ctx, backup, client.MergeFrom(original))
		if err != nil {
			removeIfComplete = false
			return errors.Wrapf(err, "error updating Backup %s", backup.Name)
		}
	} else if completionChanges {
		// If backup is still incomplete and no new errors are found but there are some new operations
		// completed, patch backup to reflect new completion numbers, but don't upload detailed json file
		err := c.Patch(ctx, backup, client.MergeFrom(original))
		if err != nil {
			return errors.Wrapf(err, "error updating Backup %s", backup.Name)
		}
	}
	return nil
}

// check progress of backupItemOperations
// return: inProgressOperations, changes, completedCount, failedCount, errs
func getBackupItemOperationProgress(
	backup *velerov1api.Backup,
	pluginManager clientmgmt.Manager,
	operationsList []*itemoperation.BackupOperation) (bool, bool, int, int, []string) {
	inProgressOperations := false
	changes := false
	var errs []string
	var completedCount, failedCount int

	for _, operation := range operationsList {
		if operation.Status.Phase == itemoperation.OperationPhaseNew ||
			operation.Status.Phase == itemoperation.OperationPhaseInProgress {
			bia, err := pluginManager.GetBackupItemActionV2(operation.Spec.BackupItemAction)
			if err != nil {
				operation.Status.Phase = itemoperation.OperationPhaseFailed
				operation.Status.Error = err.Error()
				errs = append(errs, err.Error())
				changes = true
				failedCount++
				continue
			}
			operationProgress, err := bia.Progress(operation.Spec.OperationID, backup)
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
			if operation.Status.Created.Time.Add(backup.Spec.ItemOperationTimeout.Duration).Before(time.Now()) {
				_ = bia.Cancel(operation.Spec.OperationID, backup)
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
