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
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/storage"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	pkgbackup "github.com/vmware-tanzu/velero/pkg/backup"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
	"github.com/vmware-tanzu/velero/pkg/util/encode"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
	"github.com/vmware-tanzu/velero/pkg/util/results"
	veleroutil "github.com/vmware-tanzu/velero/pkg/util/velero"
)

const (
	backupResyncPeriod = time.Minute
)

var autoExcludeNamespaceScopedResources = []string{
	// CSI VolumeSnapshot and VolumeSnapshotContent are intermediate resources.
	// Velero only handle the VS and VSC created during backup,
	// not during resource collecting.
	"volumesnapshots.snapshot.storage.k8s.io",
}

var autoExcludeClusterScopedResources = []string{
	// CSI VolumeSnapshot and VolumeSnapshotContent are intermediate resources.
	// Velero only handle the VS and VSC created during backup,
	// not during resource collecting.
	"volumesnapshotcontents.snapshot.storage.k8s.io",
}

type backupReconciler struct {
	ctx                            context.Context
	logger                         logrus.FieldLogger
	discoveryHelper                discovery.Helper
	backupper                      pkgbackup.Backupper
	kbClient                       kbclient.Client
	clock                          clock.WithTickerAndDelayedExecution
	backupLogLevel                 logrus.Level
	newPluginManager               func(logrus.FieldLogger) clientmgmt.Manager
	backupTracker                  BackupTracker
	defaultBackupLocation          string
	defaultVolumesToFsBackup       bool
	defaultBackupTTL               time.Duration
	defaultVGSLabelKey             string
	defaultCSISnapshotTimeout      time.Duration
	defaultCSISnapshotErrorTimeout time.Duration
	resourceTimeout                time.Duration
	defaultItemOperationTimeout    time.Duration
	defaultSnapshotLocations       map[string]string
	metrics                        *metrics.ServerMetrics
	backupStoreGetter              persistence.ObjectBackupStoreGetter
	formatFlag                     logging.Format
	credentialFileStore            credentials.FileStore
	maxConcurrentK8SConnections    int
	defaultSnapshotMoveData        bool
	globalCRClient                 kbclient.Client
	itemBlockWorkerCount           int
	concurrentBackups              int
}

func NewBackupReconciler(
	ctx context.Context,
	discoveryHelper discovery.Helper,
	backupper pkgbackup.Backupper,
	logger logrus.FieldLogger,
	backupLogLevel logrus.Level,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupTracker BackupTracker,
	kbClient kbclient.Client,
	defaultBackupLocation string,
	defaultVolumesToFsBackup bool,
	defaultBackupTTL time.Duration,
	defaultVGSLabelKey string,
	defaultCSISnapshotTimeout time.Duration,
	defaultCSISnapshotErrorTimeout time.Duration,
	resourceTimeout time.Duration,
	defaultItemOperationTimeout time.Duration,
	defaultSnapshotLocations map[string]string,
	metrics *metrics.ServerMetrics,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	formatFlag logging.Format,
	credentialStore credentials.FileStore,
	maxConcurrentK8SConnections int,
	defaultSnapshotMoveData bool,
	itemBlockWorkerCount int,
	concurrentBackups int,
	globalCRClient kbclient.Client,
) *backupReconciler {
	b := &backupReconciler{
		ctx:                            ctx,
		discoveryHelper:                discoveryHelper,
		backupper:                      backupper,
		clock:                          &clock.RealClock{},
		logger:                         logger,
		backupLogLevel:                 backupLogLevel,
		newPluginManager:               newPluginManager,
		backupTracker:                  backupTracker,
		kbClient:                       kbClient,
		defaultBackupLocation:          defaultBackupLocation,
		defaultVolumesToFsBackup:       defaultVolumesToFsBackup,
		defaultBackupTTL:               defaultBackupTTL,
		defaultVGSLabelKey:             defaultVGSLabelKey,
		defaultCSISnapshotTimeout:      defaultCSISnapshotTimeout,
		defaultCSISnapshotErrorTimeout: defaultCSISnapshotErrorTimeout,
		resourceTimeout:                resourceTimeout,
		defaultItemOperationTimeout:    defaultItemOperationTimeout,
		defaultSnapshotLocations:       defaultSnapshotLocations,
		metrics:                        metrics,
		backupStoreGetter:              backupStoreGetter,
		formatFlag:                     formatFlag,
		credentialFileStore:            credentialStore,
		maxConcurrentK8SConnections:    maxConcurrentK8SConnections,
		defaultSnapshotMoveData:        defaultSnapshotMoveData,
		itemBlockWorkerCount:           itemBlockWorkerCount,
		concurrentBackups:              max(concurrentBackups, 1),
		globalCRClient:                 globalCRClient,
	}
	b.updateTotalBackupMetric()
	return b
}

func (b *backupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Backup{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(ue event.UpdateEvent) bool {
				backup := ue.ObjectNew.(*velerov1api.Backup)
				return backup.Status.Phase == velerov1api.BackupPhaseReadyToStart
			},
			CreateFunc: func(ce event.CreateEvent) bool {
				return false
			},
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
			GenericFunc: func(ge event.GenericEvent) bool {
				return false
			},
		})).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: b.concurrentBackups,
		}).
		Named(constant.ControllerBackup).
		Complete(b)
}

func (b *backupReconciler) updateTotalBackupMetric() {
	go func() {
		// Wait for 5 seconds to let controller-runtime to setup k8s clients.
		time.Sleep(5 * time.Second)

		wait.Until(
			func() {
				// recompute backup_total metric
				backups := &velerov1api.BackupList{}
				err := b.kbClient.List(context.Background(), backups, &kbclient.ListOptions{LabelSelector: labels.Everything()})
				if err != nil {
					b.logger.Error(err, "Error computing backup_total metric")
				} else {
					b.metrics.SetBackupTotal(int64(len(backups.Items)))
				}

				// recompute backup_last_successful_timestamp metric for each
				// schedule (including the empty schedule, i.e. ad-hoc backups)
				for schedule, timestamp := range getLastSuccessBySchedule(backups.Items) {
					b.metrics.SetBackupLastSuccessfulTimestamp(schedule, timestamp)
				}
			},
			backupResyncPeriod,
			b.ctx.Done(),
		)
	}()
}

// getLastSuccessBySchedule finds the most recent completed backup for each schedule
// and returns a map of schedule name -> completion time of the most recent completed
// backup. This map includes an entry for ad-hoc/non-scheduled backups, where the key
// is the empty string.
func getLastSuccessBySchedule(backups []velerov1api.Backup) map[string]time.Time {
	lastSuccessBySchedule := map[string]time.Time{}
	for _, backup := range backups {
		if backup.Status.Phase != velerov1api.BackupPhaseCompleted {
			continue
		}
		if backup.Status.CompletionTimestamp == nil {
			continue
		}

		schedule := backup.Labels[velerov1api.ScheduleNameLabel]
		timestamp := backup.Status.CompletionTimestamp.Time

		if timestamp.After(lastSuccessBySchedule[schedule]) {
			lastSuccessBySchedule[schedule] = timestamp
		}
	}

	return lastSuccessBySchedule
}

func (b *backupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := b.logger.WithFields(logrus.Fields{
		"controller":    constant.ControllerBackup,
		"backuprequest": req.String(),
	})

	log.Debug("Getting backup")

	original := &velerov1api.Backup{}
	err := b.kbClient.Get(ctx, req.NamespacedName, original)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("backup not found")
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("error getting backup")
		return ctrl.Result{}, err
	}

	// Double-check we have the correct phase. In the unlikely event that multiple controller
	// instances are running, it's possible for controller A to succeed in changing the phase to
	// InProgress, while controller B's attempt to patch the phase fails. When controller B
	// reprocesses the same backup, it will either show up as New (informer hasn't seen the update
	// yet) or as InProgress. In the former case, the patch attempt will fail again, until the
	// informer sees the update. In the latter case, after the informer has seen the update to
	// InProgress, we still need this check so we can return nil to indicate we've finished processing
	// this key (even though it was a no-op).
	switch original.Status.Phase {
	case velerov1api.BackupPhaseReadyToStart:
		// only process ReadytToStart backups
	default:
		b.logger.WithFields(logrus.Fields{
			"backup": kubeutil.NamespaceAndName(original),
			"phase":  original.Status.Phase,
		}).Debug("Backup is not handled")
		return ctrl.Result{}, nil
	}

	log.Debug("Preparing backup request")
	request := b.prepareBackupRequest(ctx, original, log)
	// delete worker pool after reconcile
	defer request.StopWorkerPool()
	if len(request.Status.ValidationErrors) > 0 {
		request.Status.Phase = velerov1api.BackupPhaseFailedValidation
	} else {
		request.Status.Phase = velerov1api.BackupPhaseInProgress
		request.Status.StartTimestamp = &metav1.Time{Time: b.clock.Now()}
	}

	// update status to
	// BackupPhaseFailedValidation
	// BackupPhaseInProgress
	// if patch fail, backup can reconcile again as phase would still be "" or New
	if err := kubeutil.PatchResource(original, request.Backup, b.kbClient); err != nil {
		return ctrl.Result{}, errors.Wrapf(err, "error updating Backup status to %s", request.Status.Phase)
	}

	backupScheduleName := request.GetLabels()[velerov1api.ScheduleNameLabel]

	b.backupTracker.Add(request.Namespace, request.Name)
	defer func() {
		switch request.Status.Phase {
		case velerov1api.BackupPhaseCompleted, velerov1api.BackupPhasePartiallyFailed, velerov1api.BackupPhaseFailed, velerov1api.BackupPhaseFailedValidation:
			b.backupTracker.Delete(request.Namespace, request.Name)
		case velerov1api.BackupPhaseWaitingForPluginOperations, velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed, velerov1api.BackupPhaseFinalizing, velerov1api.BackupPhaseFinalizingPartiallyFailed:
			b.backupTracker.AddPostProcessing(request.Namespace, request.Name)
		}
	}()

	if request.Status.Phase == velerov1api.BackupPhaseFailedValidation {
		log.Debug("failed to validate backup status")
		b.metrics.RegisterBackupValidationFailure(backupScheduleName)
		b.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusFailure)

		return ctrl.Result{}, nil
	}

	// store ref to just-updated item for creating patch
	original = request.Backup.DeepCopy()

	log.Debug("Running backup")

	b.metrics.RegisterBackupAttempt(backupScheduleName)

	// execution & upload of backup
	if err := b.runBackup(request); err != nil {
		// even though runBackup sets the backup's phase prior
		// to uploading artifacts to object storage, we have to
		// check for an error again here and update the phase if
		// one is found, because there could've been an error
		// while uploading artifacts to object storage, which would
		// result in the backup being Failed.
		log.WithError(err).Error("backup failed")
		request.Status.Phase = velerov1api.BackupPhaseFailed
		request.Status.FailureReason = err.Error()
	}

	switch request.Status.Phase {
	case velerov1api.BackupPhaseCompleted:
		b.metrics.RegisterBackupSuccess(backupScheduleName)
		b.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusSucc)
	case velerov1api.BackupPhasePartiallyFailed:
		b.metrics.RegisterBackupPartialFailure(backupScheduleName)
		b.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusFailure)
	case velerov1api.BackupPhaseFailed:
		b.metrics.RegisterBackupFailed(backupScheduleName)
		b.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusFailure)
	case velerov1api.BackupPhaseFailedValidation:
		b.metrics.RegisterBackupValidationFailure(backupScheduleName)
		b.metrics.RegisterBackupLastStatus(backupScheduleName, metrics.BackupLastStatusFailure)
	}
	log.Info("Updating backup's status")
	// Phases were updated in runBackup()
	// This patch with retry update Phase from InProgress to
	// BackupPhaseWaitingForPluginOperations -> backup_operations_controller.go will now reconcile
	// BackupPhaseWaitingForPluginOperationsPartiallyFailed -> backup_operations_controller.go will now reconcile
	// BackupPhaseFinalizing -> backup_finalizer_controller.go will now reconcile
	// BackupPhaseFinalizingPartiallyFailed -> backup_finalizer_controller.go will now reconcile
	// BackupPhaseFailed
	if err := kubeutil.PatchResourceWithRetriesOnErrors(b.resourceTimeout, original, request.Backup, b.kbClient); err != nil {
		log.WithError(err).Errorf("error updating backup's status from %v to %v", original.Status.Phase, request.Backup.Status.Phase)
	}
	return ctrl.Result{}, nil
}

func (b *backupReconciler) prepareBackupRequest(ctx context.Context, backup *velerov1api.Backup, logger logrus.FieldLogger) *pkgbackup.Request {
	request := &pkgbackup.Request{
		Backup:           backup.DeepCopy(), // don't modify items in the cache
		SkippedPVTracker: pkgbackup.NewSkipPVTracker(),
		BackedUpItems:    pkgbackup.NewBackedUpItemsMap(),
		WorkerPool:       pkgbackup.StartItemBlockWorkerPool(ctx, b.itemBlockWorkerCount, logger),
	}
	request.VolumesInformation.Init()

	// set backup major version - deprecated, use Status.FormatVersion
	request.Status.Version = pkgbackup.BackupVersion

	// set backup major, minor, and patch version
	request.Status.FormatVersion = pkgbackup.BackupFormatVersion

	if request.Spec.TTL.Duration == 0 {
		// set default backup TTL
		request.Spec.TTL.Duration = b.defaultBackupTTL
	}

	if len(request.Spec.VolumeGroupSnapshotLabelKey) == 0 {
		request.Spec.VolumeGroupSnapshotLabelKey = b.defaultVGSLabelKey
	}

	if request.Spec.CSISnapshotTimeout.Duration == 0 {
		// set default CSI VolumeSnapshot timeout
		request.Spec.CSISnapshotTimeout.Duration = b.defaultCSISnapshotTimeout
	}

	if request.Spec.CSISnapshotErrorTimeout.Duration == 0 {
		// set default CSI VolumeSnapshot error timeout
		request.Spec.CSISnapshotErrorTimeout.Duration = b.defaultCSISnapshotErrorTimeout
	}

	if request.Spec.ItemOperationTimeout.Duration == 0 {
		// set default item operation timeout
		request.Spec.ItemOperationTimeout.Duration = b.defaultItemOperationTimeout
	}

	// calculate expiration
	request.Status.Expiration = &metav1.Time{Time: b.clock.Now().Add(request.Spec.TTL.Duration)}

	// TODO: After we drop the support for backup v1 CR.  Remove this code block after DefaultVolumesToRestic is removed from CRD
	// For now, for CRs created by old versions, we need to respect the DefaultVolumesToRestic value if it is set true
	if boolptr.IsSetToTrue(request.Spec.DefaultVolumesToRestic) {
		logger.Warn("DefaultVolumesToRestic field will be deprecated, use DefaultVolumesToFsBackup instead. Automatically remap it to DefaultVolumesToFsBackup")
		request.Spec.DefaultVolumesToFsBackup = request.Spec.DefaultVolumesToRestic
	}

	if request.Spec.DefaultVolumesToFsBackup == nil {
		request.Spec.DefaultVolumesToFsBackup = &b.defaultVolumesToFsBackup
	}

	if request.Spec.SnapshotMoveData == nil {
		request.Spec.SnapshotMoveData = &b.defaultSnapshotMoveData
	}

	// find which storage location to use
	var serverSpecified bool
	if request.Spec.StorageLocation == "" {
		// when the user doesn't specify a location, use the server default unless there is an existing BSL marked as default
		// TODO(2.0) b.defaultBackupLocation will be deprecated
		request.Spec.StorageLocation = b.defaultBackupLocation

		locationList, err := storage.ListBackupStorageLocations(context.Background(), b.kbClient, request.Namespace)
		if err == nil {
			for _, location := range locationList.Items {
				if location.Spec.Default {
					request.Spec.StorageLocation = location.Name
					break
				}
			}
		}
		serverSpecified = true
	}

	// get the storage location, and store the BackupStorageLocation API obj on the request
	storageLocation := &velerov1api.BackupStorageLocation{}
	if err := b.kbClient.Get(context.Background(), kbclient.ObjectKey{
		Namespace: request.Namespace,
		Name:      request.Spec.StorageLocation,
	}, storageLocation); err != nil {
		if apierrors.IsNotFound(err) {
			if serverSpecified {
				// TODO(2.0) remove this. For now, without mentioning "server default" it could be confusing trying to grasp where the default came from.
				request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("an existing backup storage location was not specified at backup creation time and the server default %s does not exist. Please address this issue (see `velero backup-location -h` for options) and create a new backup. Error: %v", request.Spec.StorageLocation, err))
			} else {
				request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("an existing backup storage location was not specified at backup creation time and the default %s was not found. Please address this issue (see `velero backup-location -h` for options) and create a new backup. Error: %v", request.Spec.StorageLocation, err))
			}
		} else {
			request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("error getting backup storage location: %v", err))
		}
	} else {
		request.StorageLocation = storageLocation

		if request.StorageLocation.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly {
			request.Status.ValidationErrors = append(request.Status.ValidationErrors,
				fmt.Sprintf("backup can't be created because backup storage location %s is currently in read-only mode", request.StorageLocation.Name))
		}

		if !veleroutil.BSLIsAvailable(*request.StorageLocation) {
			request.Status.ValidationErrors = append(
				request.Status.ValidationErrors,
				fmt.Sprintf("backup can't be created because BackupStorageLocation %s is in Unavailable status.", request.StorageLocation.Name),
			)
		}
	}

	// add the storage location as a label for easy filtering later.
	if request.Labels == nil {
		request.Labels = make(map[string]string)
	}
	request.Labels[velerov1api.StorageLocationLabel] = label.GetValidName(request.Spec.StorageLocation)

	// validate and get the backup's VolumeSnapshotLocations, and store the
	// VolumeSnapshotLocation API objs on the request
	if locs, errs := b.validateAndGetSnapshotLocations(request.Backup); len(errs) > 0 {
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, errs...)
	} else {
		request.Spec.VolumeSnapshotLocations = nil
		for _, loc := range locs {
			request.Spec.VolumeSnapshotLocations = append(request.Spec.VolumeSnapshotLocations, loc.Name)
			request.SnapshotLocations = append(request.SnapshotLocations, loc)
		}
	}

	// Getting all information of cluster version - useful for future skip-level migration
	if request.Annotations == nil {
		request.Annotations = make(map[string]string)
	}
	request.Annotations[velerov1api.SourceClusterK8sGitVersionAnnotation] = b.discoveryHelper.ServerVersion().String()
	request.Annotations[velerov1api.SourceClusterK8sMajorVersionAnnotation] = b.discoveryHelper.ServerVersion().Major
	request.Annotations[velerov1api.SourceClusterK8sMinorVersionAnnotation] = b.discoveryHelper.ServerVersion().Minor
	request.Annotations[velerov1api.ResourceTimeoutAnnotation] = b.resourceTimeout.String()

	// Add namespaces with label velero.io/exclude-from-backup=true into request.Spec.ExcludedNamespaces
	// Essentially, adding the label velero.io/exclude-from-backup=true to a namespace would be equivalent to setting spec.ExcludedNamespaces
	namespaces := corev1api.NamespaceList{}
	if err := b.kbClient.List(context.Background(), &namespaces, kbclient.MatchingLabels{velerov1api.ExcludeFromBackupLabel: "true"}); err == nil {
		for _, ns := range namespaces.Items {
			request.Spec.ExcludedNamespaces = append(request.Spec.ExcludedNamespaces, ns.Name)
		}
	} else {
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("error getting namespace list: %v", err))
	}

	// validate whether Included/Excluded resources and IncludedClusterResource are mixed with
	// Included/Excluded cluster-scoped/namespace-scoped resources.
	if oldAndNewFilterParametersUsedTogether(request.Spec) {
		validatedError := fmt.Sprintf("include-resources, exclude-resources and include-cluster-resources are old filter parameters.\n" +
			"include-cluster-scoped-resources, exclude-cluster-scoped-resources, include-namespace-scoped-resources and exclude-namespace-scoped-resources are new filter parameters.\n" +
			"They cannot be used together")
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, validatedError)
	}

	if collections.UseOldResourceFilters(request.Spec) {
		// validate the included/excluded resources
		ieErr := collections.ValidateIncludesExcludes(request.Spec.IncludedResources, request.Spec.ExcludedResources)
		if len(ieErr) > 0 {
			for _, err := range ieErr {
				request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("Invalid included/excluded resource lists: %v", err))
			}
		} else {
			request.Spec.IncludedResources, request.Spec.ExcludedResources =
				modifyResourceIncludeExclude(
					request.Spec.IncludedResources,
					request.Spec.ExcludedResources,
					append(autoExcludeNamespaceScopedResources, autoExcludeClusterScopedResources...),
				)
		}
	} else {
		// validate the cluster-scoped included/excluded resources
		clusterErr := collections.ValidateScopedIncludesExcludes(request.Spec.IncludedClusterScopedResources, request.Spec.ExcludedClusterScopedResources)
		if len(clusterErr) > 0 {
			for _, err := range clusterErr {
				request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("Invalid cluster-scoped included/excluded resource lists: %s", err))
			}
		} else {
			request.Spec.IncludedClusterScopedResources, request.Spec.ExcludedClusterScopedResources =
				modifyResourceIncludeExclude(
					request.Spec.IncludedClusterScopedResources,
					request.Spec.ExcludedClusterScopedResources,
					autoExcludeClusterScopedResources,
				)
		}

		// validate the namespace-scoped included/excluded resources
		namespaceErr := collections.ValidateScopedIncludesExcludes(request.Spec.IncludedNamespaceScopedResources, request.Spec.ExcludedNamespaceScopedResources)
		if len(namespaceErr) > 0 {
			for _, err := range namespaceErr {
				request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("Invalid namespace-scoped included/excluded resource lists: %s", err))
			}
		} else {
			request.Spec.IncludedNamespaceScopedResources, request.Spec.ExcludedNamespaceScopedResources =
				modifyResourceIncludeExclude(
					request.Spec.IncludedNamespaceScopedResources,
					request.Spec.ExcludedNamespaceScopedResources,
					autoExcludeNamespaceScopedResources,
				)
		}
	}

	// Empty IncludedNamespaces means "include all namespaces". Normalize
	// to ["*"] so that downstream wildcard expansion does not collapse
	// an empty-includes + wildcard-excludes combination into "back up nothing".
	if len(request.Spec.IncludedNamespaces) == 0 {
		request.Spec.IncludedNamespaces = []string{"*"}
	}

	// validate the included/excluded namespaces
	for _, err := range collections.ValidateNamespaceIncludesExcludes(request.Spec.IncludedNamespaces, request.Spec.ExcludedNamespaces) {
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, fmt.Sprintf("Invalid included/excluded namespace lists: %v", err))
	}

	// validate that only one exists orLabelSelector or just labelSelector (singular)
	if request.Spec.OrLabelSelectors != nil && request.Spec.LabelSelector != nil {
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, "encountered labelSelector as well as orLabelSelectors in backup spec, only one can be specified")
	}

	resourcePolicies, err := resourcepolicies.GetResourcePoliciesFromBackup(*request.Backup, b.kbClient, logger)
	if err != nil {
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, err.Error())
	}
	if resourcePolicies != nil && resourcePolicies.GetIncludeExcludePolicy() != nil && collections.UseOldResourceFilters(request.Spec) {
		request.Status.ValidationErrors = append(request.Status.ValidationErrors, "include-resources, exclude-resources and include-cluster-resources are old filter parameters.\n"+
			"They cannot be used with include-exclude policies.")
	}
	request.ResPolicies = resourcePolicies
	return request
}

// validateAndGetSnapshotLocations gets a collection of VolumeSnapshotLocation objects that
// this backup will use (returned as a map of provider name -> VSL), and ensures:
//   - each location name in .spec.volumeSnapshotLocations exists as a location
//   - exactly 1 location per provider
//   - a given provider's default location name is added to .spec.volumeSnapshotLocations if one
//     is not explicitly specified for the provider (if there's only one location for the provider,
//     it will automatically be used)
//
// if backup has snapshotVolume disabled then it returns empty VSL
func (b *backupReconciler) validateAndGetSnapshotLocations(backup *velerov1api.Backup) (map[string]*velerov1api.VolumeSnapshotLocation, []string) {
	errors := []string{}
	providerLocations := make(map[string]*velerov1api.VolumeSnapshotLocation)

	for _, locationName := range backup.Spec.VolumeSnapshotLocations {
		// validate each locationName exists as a VolumeSnapshotLocation
		location := &velerov1api.VolumeSnapshotLocation{}
		if err := b.kbClient.Get(context.Background(), kbclient.ObjectKey{Namespace: backup.Namespace, Name: locationName}, location); err != nil {
			if apierrors.IsNotFound(err) {
				errors = append(errors, fmt.Sprintf("a VolumeSnapshotLocation CRD for the location %s with the name specified in the backup spec needs to be created before this snapshot can be executed. Error: %v", locationName, err))
			} else {
				errors = append(errors, fmt.Sprintf("error getting volume snapshot location named %s: %v", locationName, err))
			}
			continue
		}

		// ensure we end up with exactly 1 location *per provider*
		if providerLocation, ok := providerLocations[location.Spec.Provider]; ok {
			// if > 1 location name per provider as in ["aws-us-east-1" | "aws-us-west-1"] (same provider, multiple names)
			if providerLocation.Name != locationName {
				errors = append(errors, fmt.Sprintf("more than one VolumeSnapshotLocation name specified for provider %s: %s; unexpected name was %s", location.Spec.Provider, locationName, providerLocation.Name))
				continue
			}
		} else {
			// keep track of all valid existing locations, per provider
			providerLocations[location.Spec.Provider] = location
		}
	}

	if len(errors) > 0 {
		return nil, errors
	}
	volumeSnapshotLocations := &velerov1api.VolumeSnapshotLocationList{}
	err := b.kbClient.List(context.Background(), volumeSnapshotLocations, &kbclient.ListOptions{Namespace: backup.Namespace, LabelSelector: labels.Everything()})
	if err != nil {
		errors = append(errors, fmt.Sprintf("error listing volume snapshot locations: %v", err))
		return nil, errors
	}

	// build a map of provider->list of all locations for the provider
	allProviderLocations := make(map[string][]*velerov1api.VolumeSnapshotLocation)
	for i := range volumeSnapshotLocations.Items {
		loc := volumeSnapshotLocations.Items[i]
		allProviderLocations[loc.Spec.Provider] = append(allProviderLocations[loc.Spec.Provider], &loc)
	}

	// go through each provider and make sure we have/can get a VSL
	// for it
	for provider, locations := range allProviderLocations {
		if _, ok := providerLocations[provider]; ok {
			// backup's spec had a location named for this provider
			continue
		}

		if len(locations) > 1 {
			// more than one possible location for the provider: check
			// the defaults
			defaultLocation := b.defaultSnapshotLocations[provider]
			if defaultLocation == "" {
				errors = append(errors, fmt.Sprintf("provider %s has more than one possible volume snapshot location, and none were specified explicitly or as a default", provider))
				continue
			}
			location := &velerov1api.VolumeSnapshotLocation{}
			if err := b.kbClient.Get(context.Background(), kbclient.ObjectKey{Namespace: backup.Namespace, Name: defaultLocation}, location); err != nil {
				errors = append(errors, fmt.Sprintf("error getting volume snapshot location named %s: %v", defaultLocation, err))
				continue
			}

			providerLocations[provider] = location
			continue
		}

		// exactly one location for the provider: use it
		providerLocations[provider] = locations[0]
	}

	if len(errors) > 0 {
		return nil, errors
	}

	// add credential to config for each location
	for _, location := range providerLocations {
		err = volume.UpdateVolumeSnapshotLocationWithCredentialConfig(location, b.credentialFileStore)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error adding credentials to volume snapshot location named %s: %v", location.Name, err))
			continue
		}
	}

	if len(errors) > 0 {
		return nil, errors
	}

	return providerLocations, nil
}

// runBackup runs and uploads a validated backup. Any error returned from this function
// causes the backup to be Failed; if no error is returned, the backup's status's Errors
// field is checked to see if the backup was a partial failure.

func (b *backupReconciler) runBackup(backup *pkgbackup.Request) error {
	b.logger.WithField(constant.ControllerBackup, kubeutil.NamespaceAndName(backup)).Info("Setting up backup log")

	// Log the backup to both a backup log file and to stdout. This will help see what happened if the upload of the
	// backup log failed for whatever reason.
	logCounter := logging.NewLogHook()
	backupLog, err := logging.NewTempFileLogger(b.backupLogLevel, b.formatFlag, logCounter, logrus.Fields{constant.ControllerBackup: kubeutil.NamespaceAndName(backup)})
	if err != nil {
		return errors.Wrap(err, "error creating dual mode logger for backup")
	}
	defer backupLog.Dispose(b.logger.WithField(constant.ControllerBackup, kubeutil.NamespaceAndName(backup)))

	backupLog.Info("Setting up backup temp file")
	backupFile, err := os.CreateTemp("", "")
	if err != nil {
		return errors.Wrap(err, "error creating temp file for backup")
	}
	defer closeAndRemoveFile(backupFile, backupLog)

	backupLog.Info("Setting up plugin manager")
	pluginManager := b.newPluginManager(backupLog)
	defer pluginManager.CleanupClients()

	backupLog.Info("Getting backup item actions")
	actions, err := pluginManager.GetBackupItemActionsV2()
	if err != nil {
		return err
	}
	backupLog.Info("Getting ItemBlock actions")
	ibActions, err := pluginManager.GetItemBlockActions()
	if err != nil {
		return err
	}
	backupLog.Info("Setting up backup store to check for backup existence")
	backupStore, err := b.backupStoreGetter.Get(backup.StorageLocation, pluginManager, backupLog)
	if err != nil {
		return err
	}

	exists, err := backupStore.BackupExists(backup.StorageLocation.Spec.StorageType.ObjectStorage.Bucket, backup.Name)
	if exists || err != nil {
		backup.Status.Phase = velerov1api.BackupPhaseFailed
		backup.Status.CompletionTimestamp = &metav1.Time{Time: b.clock.Now()}
		if err != nil {
			return errors.Wrapf(err, "error checking if backup already exists in object storage")
		}
		return errors.Errorf("backup already exists in object storage")
	}

	backupItemActionsResolver := framework.NewBackupItemActionResolverV2(actions)
	itemBlockActionResolver := framework.NewItemBlockActionResolver(ibActions)

	var fatalErrs []error
	if err := b.backupper.BackupWithResolvers(backupLog, backup, backupFile, backupItemActionsResolver, itemBlockActionResolver, pluginManager); err != nil {
		fatalErrs = append(fatalErrs, err)
	}

	// native snapshots phase will either be failed or completed right away
	// https://github.com/vmware-tanzu/velero/blob/de3ea52f0cc478e99efa7b9524c7f353514261a4/pkg/backup/item_backupper.go#L632-L639
	backup.Status.VolumeSnapshotsAttempted = len(backup.VolumeSnapshots.Get())
	for _, snap := range backup.VolumeSnapshots.Get() {
		if snap.Status.Phase == volume.SnapshotPhaseCompleted {
			backup.Status.VolumeSnapshotsCompleted++
		}
	}
	volumeSnapshots, volumeSnapshotContents, volumeSnapshotClasses := pkgbackup.GetBackupCSIResources(b.kbClient, b.globalCRClient, backup.Backup, backupLog)
	// Update CSIVolumeSnapshotsAttempted
	backup.Status.CSIVolumeSnapshotsAttempted = len(volumeSnapshots)

	// Iterate over backup item operations and update progress.
	// Any errors on operations at this point should be added to backup errors.
	// If any operations are still not complete, then back will not be set to
	// Completed yet.
	inProgressOperations, _, opsCompleted, opsFailed, errs := getBackupItemOperationProgress(backup.Backup, pluginManager, *backup.GetItemOperationsList())
	if len(errs) > 0 {
		for _, err := range errs {
			backupLog.Error(err)
		}
	}

	backup.Status.BackupItemOperationsAttempted = len(*backup.GetItemOperationsList())
	backup.Status.BackupItemOperationsCompleted = opsCompleted
	backup.Status.BackupItemOperationsFailed = opsFailed

	backup.Status.Warnings = logCounter.GetCount(logrus.WarnLevel)
	backup.Status.Errors = logCounter.GetCount(logrus.ErrorLevel)

	backupWarnings := logCounter.GetEntries(logrus.WarnLevel)
	backupErrors := logCounter.GetEntries(logrus.ErrorLevel)
	results := map[string]results.Result{
		"warnings": backupWarnings,
		"errors":   backupErrors,
	}

	backupLog.DoneForPersist(b.logger.WithField(constant.ControllerBackup, kubeutil.NamespaceAndName(backup)))

	// Assign finalize phase as close to end as possible so that any errors
	// logged to backupLog are captured. This is done before uploading the
	// artifacts to object storage so that the JSON representation of the
	// backup in object storage has the terminal phase set.
	switch {
	case len(fatalErrs) > 0:
		backup.Status.Phase = velerov1api.BackupPhaseFailed
	case logCounter.GetCount(logrus.ErrorLevel) > 0:
		if inProgressOperations {
			backup.Status.Phase = velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed
		} else {
			backup.Status.Phase = velerov1api.BackupPhaseFinalizingPartiallyFailed
		}
	default:
		if inProgressOperations {
			backup.Status.Phase = velerov1api.BackupPhaseWaitingForPluginOperations
		} else {
			backup.Status.Phase = velerov1api.BackupPhaseFinalizing
		}
	}
	// Mark completion timestamp before serializing and uploading.
	// Otherwise, the JSON file in object storage has a CompletionTimestamp of 'null'.
	if backup.Status.Phase == velerov1api.BackupPhaseFailed ||
		backup.Status.Phase == velerov1api.BackupPhasePartiallyFailed ||
		backup.Status.Phase == velerov1api.BackupPhaseCompleted {
		backup.Status.CompletionTimestamp = &metav1.Time{Time: b.clock.Now()}
	}
	recordBackupMetrics(backupLog, backup.Backup, backupFile, b.metrics, false)

	// re-instantiate the backup store because credentials could have changed since the original
	// instantiation, if this was a long-running backup
	backupLog.Info("Setting up backup store to persist the backup")
	backupStore, err = b.backupStoreGetter.Get(backup.StorageLocation, pluginManager, backupLog)
	if err != nil {
		return err
	}

	if logFile, err := backupLog.GetPersistFile(); err != nil {
		fatalErrs = append(fatalErrs, errors.Wrap(err, "error getting backup log file"))
	} else {
		if errs := persistBackup(backup, backupFile, logFile, backupStore, volumeSnapshots, volumeSnapshotContents, volumeSnapshotClasses, results, b.globalCRClient, backupLog); len(errs) > 0 {
			fatalErrs = append(fatalErrs, errs...)
		}
	}
	b.logger.WithField(constant.ControllerBackup, kubeutil.NamespaceAndName(backup)).Infof("Initial backup processing complete, moving to %s", backup.Status.Phase)

	// if we return a non-nil error, the calling function will update
	// the backup's phase to Failed.
	return kerrors.NewAggregate(fatalErrs)
}

func recordBackupMetrics(log logrus.FieldLogger, backup *velerov1api.Backup, backupFile *os.File, serverMetrics *metrics.ServerMetrics, finalize bool) {
	backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]

	if backupFile != nil {
		var backupSizeBytes int64
		if backupFileStat, err := backupFile.Stat(); err != nil {
			log.WithError(errors.WithStack(err)).Error("Error getting backup file info")
		} else {
			backupSizeBytes = backupFileStat.Size()
		}
		serverMetrics.SetBackupTarballSizeBytesGauge(backupScheduleName, backupSizeBytes)
	}

	if backup.Status.CompletionTimestamp != nil {
		backupDuration := backup.Status.CompletionTimestamp.Time.Sub(backup.Status.StartTimestamp.Time)
		backupDurationSeconds := float64(backupDuration / time.Second)
		serverMetrics.RegisterBackupDuration(backupScheduleName, backupDurationSeconds)
	}

	if !finalize {
		serverMetrics.RegisterVolumeSnapshotAttempts(backupScheduleName, backup.Status.VolumeSnapshotsAttempted)
		serverMetrics.RegisterVolumeSnapshotSuccesses(backupScheduleName, backup.Status.VolumeSnapshotsCompleted)
		serverMetrics.RegisterVolumeSnapshotFailures(backupScheduleName, backup.Status.VolumeSnapshotsAttempted-backup.Status.VolumeSnapshotsCompleted)

		if features.IsEnabled(velerov1api.CSIFeatureFlag) {
			serverMetrics.RegisterCSISnapshotAttempts(backupScheduleName, backup.Name, backup.Status.CSIVolumeSnapshotsAttempted)
		}

		if backup.Status.Progress != nil {
			serverMetrics.RegisterBackupItemsTotalGauge(backupScheduleName, backup.Status.Progress.TotalItems)
		}
		serverMetrics.RegisterBackupItemsErrorsGauge(backupScheduleName, backup.Status.Errors)

		if backup.Status.Warnings > 0 {
			serverMetrics.RegisterBackupWarning(backupScheduleName)
		}
	} else if features.IsEnabled(velerov1api.CSIFeatureFlag) {
		serverMetrics.RegisterCSISnapshotSuccesses(backupScheduleName, backup.Name, backup.Status.CSIVolumeSnapshotsCompleted)
		serverMetrics.RegisterCSISnapshotFailures(backupScheduleName, backup.Name, backup.Status.CSIVolumeSnapshotsAttempted-backup.Status.CSIVolumeSnapshotsCompleted)
	}
}

func persistBackup(backup *pkgbackup.Request,
	backupContents, backupLog *os.File,
	backupStore persistence.BackupStore,
	csiVolumeSnapshots []snapshotv1api.VolumeSnapshot,
	csiVolumeSnapshotContents []snapshotv1api.VolumeSnapshotContent,
	csiVolumeSnapshotClasses []snapshotv1api.VolumeSnapshotClass,
	results map[string]results.Result,
	crClient kbclient.Client,
	logger logrus.FieldLogger,
) []error {
	persistErrs := []error{}
	backupJSON := new(bytes.Buffer)

	if err := encode.To(backup.Backup, "json", backupJSON); err != nil {
		persistErrs = append(persistErrs, errors.Wrap(err, "error encoding backup"))
	}

	// Velero-native volume snapshots (as opposed to CSI ones)
	nativeVolumeSnapshots, errs := encode.ToJSONGzip(backup.VolumeSnapshots.Get(), "native volumesnapshots list")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	var backupItemOperations *bytes.Buffer
	backupItemOperations, errs = encode.ToJSONGzip(backup.GetItemOperationsList(), "backup item operations list")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	podVolumeBackups, errs := encode.ToJSONGzip(backup.PodVolumeBackups, "pod volume backups list")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	csiSnapshotClassesJSON, errs := encode.ToJSONGzip(csiVolumeSnapshotClasses, "csi volume snapshot classes list")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	backupResourceList, errs := encode.ToJSONGzip(backup.BackupResourceList(), "backup resources list")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	backupResult, errs := encode.ToJSONGzip(results, "backup results")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	backup.FillVolumesInformation()

	volumeInfoJSON, errs := encode.ToJSONGzip(backup.VolumesInformation.Result(
		csiVolumeSnapshots,
		csiVolumeSnapshotContents,
		csiVolumeSnapshotClasses,
		crClient,
		logger,
	), "backup volumes information")
	if errs != nil {
		persistErrs = append(persistErrs, errs...)
	}

	if len(persistErrs) > 0 {
		// Don't upload the JSON files or backup tarball if encoding to json fails.
		backupJSON = nil
		backupContents = nil
		nativeVolumeSnapshots = nil
		backupItemOperations = nil
		backupResourceList = nil
		csiSnapshotClassesJSON = nil
		backupResult = nil
		volumeInfoJSON = nil
	}

	backupInfo := persistence.BackupInfo{
		Name:                     backup.Name,
		Metadata:                 backupJSON,
		Contents:                 backupContents,
		Log:                      backupLog,
		BackupResults:            backupResult,
		PodVolumeBackups:         podVolumeBackups,
		VolumeSnapshots:          nativeVolumeSnapshots,
		BackupItemOperations:     backupItemOperations,
		BackupResourceList:       backupResourceList,
		CSIVolumeSnapshotClasses: csiSnapshotClassesJSON,
		BackupVolumeInfo:         volumeInfoJSON,
	}
	if err := backupStore.PutBackup(backupInfo); err != nil {
		persistErrs = append(persistErrs, err)
	}

	return persistErrs
}

func closeAndRemoveFile(file *os.File, log logrus.FieldLogger) {
	if file == nil {
		log.Debug("Skipping removal of file due to nil file pointer")
		return
	}
	if err := file.Close(); err != nil {
		log.WithError(err).WithField("file", file.Name()).Error("error closing file")
	}
	if err := os.Remove(file.Name()); err != nil {
		log.WithError(err).WithField("file", file.Name()).Error("error removing file")
	}
}

func oldAndNewFilterParametersUsedTogether(backupSpec velerov1api.BackupSpec) bool {
	haveOldResourceFilterParameters := len(backupSpec.IncludedResources) > 0 ||
		(len(backupSpec.ExcludedResources) > 0) ||
		(backupSpec.IncludeClusterResources != nil)
	haveNewResourceFilterParameters := len(backupSpec.IncludedClusterScopedResources) > 0 ||
		(len(backupSpec.ExcludedClusterScopedResources) > 0) ||
		(len(backupSpec.IncludedNamespaceScopedResources) > 0) ||
		(len(backupSpec.ExcludedNamespaceScopedResources) > 0)

	return haveOldResourceFilterParameters && haveNewResourceFilterParameters
}

func modifyResourceIncludeExclude(include, exclude, addedExclude []string) (modifiedInclude, modifiedExclude []string) {
	modifiedInclude = include
	modifiedExclude = exclude

	excludeStrSet := sets.NewString(exclude...)
	for _, ex := range addedExclude {
		if !excludeStrSet.Has(ex) {
			modifiedExclude = append(modifiedExclude, ex)
		}
	}

	for _, exElem := range modifiedExclude {
		for inIndex, inElem := range modifiedInclude {
			if inElem == exElem {
				modifiedInclude = slices.Delete(modifiedInclude, inIndex, inIndex+1)
			}
		}
	}

	return modifiedInclude, modifiedExclude
}
