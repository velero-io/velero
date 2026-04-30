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
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	veleroapishared "github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

const pVBRRequestor string = "pod-volume-backup-restore"

// NewPodVolumeBackupReconciler creates the PodVolumeBackupReconciler instance
func NewPodVolumeBackupReconciler(client client.Client, ensurer *repository.Ensurer, credentialGetter *credentials.CredentialGetter,
	nodeName string, scheme *runtime.Scheme, metrics *metrics.ServerMetrics, logger logrus.FieldLogger) *PodVolumeBackupReconciler {
	return &PodVolumeBackupReconciler{
		Client:            client,
		logger:            logger.WithField("controller", "PodVolumeBackup"),
		repositoryEnsurer: ensurer,
		credentialGetter:  credentialGetter,
		nodeName:          nodeName,
		fileSystem:        filesystem.NewFileSystem(),
		clock:             &clocks.RealClock{},
		scheme:            scheme,
		metrics:           metrics,
		dataPathMgr:       datapath.NewManager(1),
	}
}

// PodVolumeBackupReconciler reconciles a PodVolumeBackup object
type PodVolumeBackupReconciler struct {
	client.Client
	scheme            *runtime.Scheme
	clock             clocks.WithTickerAndDelayedExecution
	metrics           *metrics.ServerMetrics
	credentialGetter  *credentials.CredentialGetter
	repositoryEnsurer *repository.Ensurer
	nodeName          string
	fileSystem        filesystem.Interface
	logger            logrus.FieldLogger
	dataPathMgr       *datapath.Manager
}

// +kubebuilder:rbac:groups=velero.io,resources=podvolumebackups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=podvolumebackups/status,verbs=get;update;patch

func (r *PodVolumeBackupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithFields(logrus.Fields{
		"controller":      "podvolumebackup",
		"podvolumebackup": req.NamespacedName,
	})

	var pvb velerov1api.PodVolumeBackup
	if err := r.Get(ctx, req.NamespacedName, &pvb); err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("Unable to find PodVolumeBackup")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err, "getting PodVolumeBackup")
	}
	if len(pvb.OwnerReferences) == 1 {
		log = log.WithField(
			"backup",
			fmt.Sprintf("%s/%s", req.Namespace, pvb.OwnerReferences[0].Name),
		)
	}

	// Only process items for this node.
	if pvb.Spec.Node != r.nodeName {
		return ctrl.Result{}, nil
	}

	switch pvb.Status.Phase {
	case "", velerov1api.PodVolumeBackupPhaseNew:
		// Only process new items.
	default:
		log.Debug("PodVolumeBackup is not new, not processing")
		return ctrl.Result{}, nil
	}

	log.Info("PodVolumeBackup starting")

	callbacks := datapath.Callbacks{
		OnCompleted: r.OnDataPathCompleted,
		OnFailed:    r.OnDataPathFailed,
		OnCancelled: r.OnDataPathCancelled,
		OnProgress:  r.OnDataPathProgress,
	}

	fsBackup, err := r.dataPathMgr.CreateFileSystemBR(pvb.Name, pVBRRequestor, ctx, r.Client, pvb.Namespace, callbacks, log)
	if err != nil {
		if err == datapath.ConcurrentLimitExceed {
			return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, nil
		} else {
			return r.errorOut(ctx, &pvb, err, "error to create data path", log)
		}
	}

	r.metrics.RegisterPodVolumeBackupEnqueue(r.nodeName)

	// Update status to InProgress.
	original := pvb.DeepCopy()
	pvb.Status.Phase = velerov1api.PodVolumeBackupPhaseInProgress
	pvb.Status.StartTimestamp = &metav1.Time{Time: r.clock.Now()}
	if err := r.Patch(ctx, &pvb, client.MergeFrom(original)); err != nil {
		return r.errorOut(ctx, &pvb, err, "error updating PodVolumeBackup status", log)
	}

	var pod corev1.Pod
	podNamespacedName := client.ObjectKey{
		Namespace: pvb.Spec.Pod.Namespace,
		Name:      pvb.Spec.Pod.Name,
	}
	if err := r.Get(ctx, podNamespacedName, &pod); err != nil {
		return r.errorOut(ctx, &pvb, err, fmt.Sprintf("getting pod %s/%s", pvb.Spec.Pod.Namespace, pvb.Spec.Pod.Name), log)
	}

	path, err := exposer.GetPodVolumeHostPath(ctx, &pod, pvb.Spec.Volume, r.Client, r.fileSystem, log)
	if err != nil {
		return r.errorOut(ctx, &pvb, err, "error exposing host path for pod volume", log)
	}

	log.WithField("path", path.ByPath).Debugf("Found host path")

	if err := fsBackup.Init(ctx, pvb.Spec.BackupStorageLocation, pvb.Spec.Pod.Namespace, pvb.Spec.UploaderType,
		podvolume.GetPvbRepositoryType(&pvb), pvb.Spec.RepoIdentifier, r.repositoryEnsurer, r.credentialGetter); err != nil {
		return r.errorOut(ctx, &pvb, err, "error to initialize data path", log)
	}

	// If this is a PVC, look for the most recent completed pod volume backup for it and get
	// its snapshot ID to do new backup based on it. Without this,
	// if the pod using the PVC (and therefore the directory path under /host_pods/) has
	// changed since the PVC's last backup, for backup, it will not be able to identify a suitable
	// parent snapshot to use, and will have to do a full rescan of the contents of the PVC.
	var parentSnapshotID string
	if pvcUID, ok := pvb.Labels[velerov1api.PVCUIDLabel]; ok {
		parentSnapshotID = r.getParentSnapshot(ctx, log, pvcUID, &pvb)
		if parentSnapshotID == "" {
			log.Info("No parent snapshot found for PVC, not based on parent snapshot for this backup")
		} else {
			log.WithField("parentSnapshotID", parentSnapshotID).Info("Based on parent snapshot for this backup")
		}
	}

	if err := fsBackup.StartBackup(path, "", parentSnapshotID, false, pvb.Spec.Tags); err != nil {
		return r.errorOut(ctx, &pvb, err, "error starting data path backup", log)
	}

	log.WithField("path", path.ByPath).Info("Async fs backup data path started")

	return ctrl.Result{}, nil
}

func (r *PodVolumeBackupReconciler) OnDataPathCompleted(ctx context.Context, namespace string, pvbName string, result datapath.Result) {
	defer r.closeDataPath(ctx, pvbName)

	log := r.logger.WithField("pvb", pvbName)

	log.WithField("PVB", pvbName).Info("Async fs backup data path completed")

	var pvb velerov1api.PodVolumeBackup
	if err := r.Get(ctx, types.NamespacedName{Name: pvbName, Namespace: namespace}, &pvb); err != nil {
		log.WithError(err).Warn("Failed to get PVB on completion")
		return
	}

	// Update status to Completed with path & snapshot ID.
	original := pvb.DeepCopy()
	pvb.Status.Path = result.Backup.Source.ByPath
	pvb.Status.Phase = velerov1api.PodVolumeBackupPhaseCompleted
	pvb.Status.SnapshotID = result.Backup.SnapshotID
	pvb.Status.CompletionTimestamp = &metav1.Time{Time: r.clock.Now()}
	if result.Backup.EmptySnapshot {
		pvb.Status.Message = "volume was empty so no snapshot was taken"
	}

	if err := r.Patch(ctx, &pvb, client.MergeFrom(original)); err != nil {
		log.WithError(err).Error("error updating PodVolumeBackup status")
	}

	latencyDuration := pvb.Status.CompletionTimestamp.Sub(pvb.Status.StartTimestamp.Time)
	latencySeconds := float64(latencyDuration / time.Second)
	backupName := fmt.Sprintf("%s/%s", pvb.Namespace, pvb.OwnerReferences[0].Name)
	generateOpName := fmt.Sprintf("%s-%s-%s-%s-backup", pvb.Name, pvb.Spec.BackupStorageLocation, pvb.Spec.Pod.Namespace, pvb.Spec.UploaderType)
	r.metrics.ObservePodVolumeOpLatency(r.nodeName, pvb.Name, generateOpName, backupName, latencySeconds)
	r.metrics.RegisterPodVolumeOpLatencyGauge(r.nodeName, pvb.Name, generateOpName, backupName, latencySeconds)
	r.metrics.RegisterPodVolumeBackupDequeue(r.nodeName)

	log.Info("PodVolumeBackup completed")
}

func (r *PodVolumeBackupReconciler) OnDataPathFailed(ctx context.Context, namespace string, pvbName string, err error) {
	defer r.closeDataPath(ctx, pvbName)

	log := r.logger.WithField("pvb", pvbName)

	log.WithError(err).Error("Async fs backup data path failed")

	var pvb velerov1api.PodVolumeBackup
	if getErr := r.Get(ctx, types.NamespacedName{Name: pvbName, Namespace: namespace}, &pvb); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVB on failure")
	} else {
		_, _ = r.errorOut(ctx, &pvb, err, "data path backup failed", log)
	}
}

func (r *PodVolumeBackupReconciler) OnDataPathCancelled(ctx context.Context, namespace string, pvbName string) {
	defer r.closeDataPath(ctx, pvbName)

	log := r.logger.WithField("pvb", pvbName)

	log.Warn("Async fs backup data path canceled")

	var pvb velerov1api.PodVolumeBackup
	if getErr := r.Get(ctx, types.NamespacedName{Name: pvbName, Namespace: namespace}, &pvb); getErr != nil {
		log.WithError(getErr).Warn("Failed to get PVB on cancel")
	} else {
		_, _ = r.errorOut(ctx, &pvb, errors.New("PVB is canceled"), "data path backup canceled", log)
	}
}

func (r *PodVolumeBackupReconciler) OnDataPathProgress(ctx context.Context, namespace string, pvbName string, progress *uploader.Progress) {
	log := r.logger.WithField("pvb", pvbName)

	var pvb velerov1api.PodVolumeBackup
	if err := r.Get(ctx, types.NamespacedName{Name: pvbName, Namespace: namespace}, &pvb); err != nil {
		log.WithError(err).Warn("Failed to get PVB on progress")
		return
	}

	original := pvb.DeepCopy()
	pvb.Status.Progress = veleroapishared.DataMoveOperationProgress{TotalBytes: progress.TotalBytes, BytesDone: progress.BytesDone}

	if err := r.Patch(ctx, &pvb, client.MergeFrom(original)); err != nil {
		log.WithError(err).Error("Failed to update progress")
	}
}

// SetupWithManager registers the PVB controller.
func (r *PodVolumeBackupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.PodVolumeBackup{}).
		Complete(r)
}

// getParentSnapshot finds the most recent completed PodVolumeBackup for the
// specified PVC and returns its snapshot ID. Any errors encountered are
// logged but not returned since they do not prevent a backup from proceeding.
func (r *PodVolumeBackupReconciler) getParentSnapshot(ctx context.Context, log logrus.FieldLogger, pvcUID string, podVolumeBackup *velerov1api.PodVolumeBackup) string {
	log = log.WithField("pvcUID", pvcUID)
	log.Infof("Looking for most recent completed PodVolumeBackup for this PVC")

	listOpts := &client.ListOptions{
		Namespace: podVolumeBackup.Namespace,
	}
	matchingLabels := client.MatchingLabels(map[string]string{velerov1api.PVCUIDLabel: pvcUID})
	matchingLabels.ApplyToList(listOpts)

	var pvbList velerov1api.PodVolumeBackupList
	if err := r.List(ctx, &pvbList, listOpts); err != nil {
		log.WithError(errors.WithStack(err)).Error("getting list of podvolumebackups for this PVC")
	}

	// Go through all the podvolumebackups for the PVC and look for the most
	// recent completed one to use as the parent.
	var mostRecentPVB velerov1api.PodVolumeBackup
	for _, pvb := range pvbList.Items {
		if pvb.Spec.UploaderType != podVolumeBackup.Spec.UploaderType {
			continue
		}
		if pvb.Status.Phase != velerov1api.PodVolumeBackupPhaseCompleted {
			continue
		}

		if podVolumeBackup.Spec.BackupStorageLocation != pvb.Spec.BackupStorageLocation {
			// Check the backup storage location is the same as spec in order to
			// support backup to multiple backup-locations. Otherwise, there exists
			// a case that backup volume snapshot to the second location would
			// failed, since the founded parent ID is only valid for the first
			// backup location, not the second backup location. Also, the second
			// backup should not use the first backup parent ID since its for the
			// first backup location only.
			continue
		}

		if mostRecentPVB.Status == (velerov1api.PodVolumeBackupStatus{}) || pvb.Status.StartTimestamp.After(mostRecentPVB.Status.StartTimestamp.Time) {
			mostRecentPVB = pvb
		}
	}

	if mostRecentPVB.Status == (velerov1api.PodVolumeBackupStatus{}) {
		log.Info("No completed PodVolumeBackup found for PVC")
		return ""
	}

	log.WithFields(map[string]interface{}{
		"parentPodVolumeBackup": mostRecentPVB.Name,
		"parentSnapshotID":      mostRecentPVB.Status.SnapshotID,
	}).Info("Found most recent completed PodVolumeBackup for PVC")

	return mostRecentPVB.Status.SnapshotID
}

func (r *PodVolumeBackupReconciler) closeDataPath(ctx context.Context, pvbName string) {
	fsBackup := r.dataPathMgr.GetAsyncBR(pvbName)
	if fsBackup != nil {
		fsBackup.Close(ctx)
	}

	r.dataPathMgr.RemoveAsyncBR(pvbName)
}

func (r *PodVolumeBackupReconciler) errorOut(ctx context.Context, pvb *velerov1api.PodVolumeBackup, err error, msg string, log logrus.FieldLogger) (ctrl.Result, error) {
	r.closeDataPath(ctx, pvb.Name)
	_ = UpdatePVBStatusToFailed(ctx, r.Client, pvb, errors.WithMessage(err, msg).Error(), r.clock.Now(), log)

	return ctrl.Result{}, err
}

func UpdatePVBStatusToFailed(ctx context.Context, c client.Client, pvb *velerov1api.PodVolumeBackup, errString string, time time.Time, log logrus.FieldLogger) error {
	original := pvb.DeepCopy()
	pvb.Status.Phase = velerov1api.PodVolumeBackupPhaseFailed
	pvb.Status.Message = errString
	pvb.Status.CompletionTimestamp = &metav1.Time{Time: time}

	err := c.Patch(ctx, pvb, client.MergeFrom(original))
	if err != nil {
		log.WithError(err).Error("error updating PodVolumeBackup status")
	}

	return err
}
