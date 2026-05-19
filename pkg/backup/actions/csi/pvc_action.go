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

package csi

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"k8s.io/client-go/util/retry"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"k8s.io/apimachinery/pkg/api/resource"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	veleroclient "github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/label"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/utils/volumehelper"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
	uploaderUtil "github.com/vmware-tanzu/velero/pkg/uploader/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	podvolumeutil "github.com/vmware-tanzu/velero/pkg/util/podvolume"
	vhutil "github.com/vmware-tanzu/velero/pkg/util/volumehelper"
)

// TODO: Replace hardcoded VolumeSnapshot finalizer strings with constants from
// "github.com/kubernetes-csi/external-snapshotter/v8/pkg/utils"
// once module/toolchain upgrades are done.
// Finalizer constants
const (
	VolumeSnapshotFinalizerGroupProtection  = "snapshot.storage.kubernetes.io/volumesnapshot-in-group-protection"
	VolumeSnapshotFinalizerSourceProtection = "snapshot.storage.kubernetes.io/volumesnapshot-as-source-protection"
)

// pvcBackupItemAction is a backup item action plugin for Velero.
type pvcBackupItemAction struct {
	log      logrus.FieldLogger
	crClient crclient.Client

	// pvcPodCache provides lazy per-namespace caching of PVC-to-Pod mappings.
	// Since plugin instances are unique per backup (created via newPluginManager and
	// cleaned up via CleanupClients at backup completion), we can safely cache this
	// without mutex or backup UID tracking.
	// This avoids the O(N*M) performance issue when there are many PVCs and pods.
	// See issue #9179 and PR #9226 for details.
	pvcPodCache *podvolumeutil.PVCPodCache
}

// AppliesTo returns information indicating that the PVCBackupItemAction
// should be invoked to backup PVCs.
func (p *pvcBackupItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"persistentvolumeclaims"},
	}, nil
}

func (p *pvcBackupItemAction) validateBackup(backup velerov1api.Backup) (valid bool) {
	if backup.Status.Phase == velerov1api.BackupPhaseFinalizing ||
		backup.Status.Phase == velerov1api.BackupPhaseFinalizingPartiallyFailed {
		p.log.WithFields(
			logrus.Fields{
				"Backup": fmt.Sprintf("%s/%s", backup.Namespace, backup.Name),
				"Phase":  backup.Status.Phase,
			},
		).Debug("Backup is in finalizing phase. Skip this PVC.")
		return false
	}

	return true
}

// ensurePVCPodCacheForNamespace ensures the PVC-to-Pod cache is built for the given namespace.
// This uses lazy per-namespace caching following the pattern from PR #9226.
// Since plugin instances are unique per backup, we can safely cache without mutex or backup UID tracking.
func (p *pvcBackupItemAction) ensurePVCPodCacheForNamespace(ctx context.Context, namespace string) error {
	// Initialize cache if needed
	if p.pvcPodCache == nil {
		p.pvcPodCache = podvolumeutil.NewPVCPodCache()
	}

	// Build cache for namespace if not already done
	if !p.pvcPodCache.IsNamespaceBuilt(namespace) {
		p.log.Debugf("Building PVC-to-Pod cache for namespace %s", namespace)
		if err := p.pvcPodCache.BuildCacheForNamespace(ctx, namespace, p.crClient); err != nil {
			return errors.Wrapf(err, "failed to build PVC-to-Pod cache for namespace %s", namespace)
		}
	}
	return nil
}

// getVolumeHelperWithCache creates a VolumeHelper using the pre-built PVC-to-Pod cache.
// The cache should be ensured for the relevant namespace(s) before calling this.
func (p *pvcBackupItemAction) getVolumeHelperWithCache(backup *velerov1api.Backup) (vhutil.VolumeHelper, error) {
	// Create VolumeHelper with our lazy-built cache
	vh, err := volumehelper.NewVolumeHelperWithCache(
		*backup,
		p.crClient,
		p.log,
		p.pvcPodCache,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create VolumeHelper")
	}
	return vh, nil
}

// getOrCreateVolumeHelper returns a VolumeHelper with lazy per-namespace caching.
// The VolumeHelper uses the pvcPodCache which is populated lazily as namespaces are encountered.
// Callers should use ensurePVCPodCacheForNamespace before calling methods that need
// PVC-to-Pod lookups for a specific namespace.
// Since plugin instances are unique per backup (created via newPluginManager and
// cleaned up via CleanupClients at backup completion), we can safely cache this.
// See issue #9179 and PR #9226 for details.
func (p *pvcBackupItemAction) getOrCreateVolumeHelper(backup *velerov1api.Backup) (vhutil.VolumeHelper, error) {
	// Initialize the PVC-to-Pod cache if needed
	if p.pvcPodCache == nil {
		p.pvcPodCache = podvolumeutil.NewPVCPodCache()
	}

	// Return the VolumeHelper with our lazily-built cache
	// The cache will be populated incrementally as namespaces are encountered
	return p.getVolumeHelperWithCache(backup)
}

func (p *pvcBackupItemAction) validatePVCandPV(
	pvc corev1api.PersistentVolumeClaim,
	item runtime.Unstructured,
) (
	valid bool,
	updateItem runtime.Unstructured,
	err error,
) {
	updateItem = item

	// no storage class: we don't know how to map to a VolumeSnapshotClass
	if pvc.Spec.StorageClassName == nil {
		return false,
			updateItem,
			errors.Errorf(
				"Cannot snapshot PVC %s/%s, PVC has no storage class.",
				pvc.Namespace, pvc.Name)
	}

	p.log.Debugf(
		"Fetching underlying PV for PVC %s",
		fmt.Sprintf("%s/%s", pvc.Namespace, pvc.Name),
	)

	// Do nothing if this is not a CSI provisioned volume
	pv, err := kubeutil.GetPVForPVC(&pvc, p.crClient)
	if err != nil {
		return false, updateItem, errors.WithStack(err)
	}

	if pv.Spec.PersistentVolumeSource.CSI == nil {
		p.log.Infof(
			"Skipping PVC %s/%s, associated PV %s is not a CSI volume",
			pvc.Namespace, pvc.Name, pv.Name)

		kubeutil.AddAnnotations(
			&pvc.ObjectMeta,
			map[string]string{
				velerov1api.SkippedNoCSIPVAnnotation: "true",
			})
		data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pvc)
		updateItem = &unstructured.Unstructured{Object: data}
		return false, updateItem, err
	}

	return true, updateItem, nil
}

func (p *pvcBackupItemAction) createVolumeSnapshot(
	pvc corev1api.PersistentVolumeClaim,
	backup *velerov1api.Backup,
) (
	vs *snapshotv1api.VolumeSnapshot,
	err error,
) {
	p.log.Debugf("Fetching storage class for PV %s", *pvc.Spec.StorageClassName)
	storageClass := new(storagev1api.StorageClass)
	if err := p.crClient.Get(
		context.TODO(), crclient.ObjectKey{Name: *pvc.Spec.StorageClassName},
		storageClass,
	); err != nil {
		return nil, errors.Wrap(err, "error getting storage class")
	}

	p.log.Debugf("Fetching VolumeSnapshotClass for %s", storageClass.Provisioner)
	vsClass, err := csi.GetVolumeSnapshotClass(
		storageClass,
		backup,
		&pvc,
		p.log,
		p.crClient,
	)
	if err != nil {
		return nil, errors.Wrapf(
			err, "failed to get VolumeSnapshotClass for StorageClass %s",
			storageClass.Name,
		)
	}
	p.log.Infof("VolumeSnapshotClass=%s", vsClass.Name)

	vsLabels := map[string]string{}
	for k, v := range pvc.ObjectMeta.Labels {
		vsLabels[k] = v
	}
	vsLabels[velerov1api.BackupNameLabel] = label.GetValidName(backup.Name)

	// Craft the vs object to be created
	vs = &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "velero-" + pvc.Name + "-",
			Namespace:    pvc.Namespace,
			Labels:       vsLabels,
		},
		Spec: snapshotv1api.VolumeSnapshotSpec{
			Source: snapshotv1api.VolumeSnapshotSource{
				PersistentVolumeClaimName: &pvc.Name,
			},
			VolumeSnapshotClassName: &vsClass.Name,
		},
	}

	if err := p.crClient.Create(context.TODO(), vs); err != nil {
		return nil, errors.Wrapf(
			err, "error creating volume snapshot",
		)
	}
	p.log.Infof(
		"Created VolumeSnapshot %s",
		fmt.Sprintf("%s/%s", vs.Namespace, vs.Name),
	)

	return vs, nil
}

// Execute recognizes PVCs backed by volumes provisioned by CSI drivers
// with VolumeSnapshotting capability and creates snapshots of the
// underlying PVs by creating VolumeSnapshot CSI API objects that will
// trigger the CSI driver to perform the snapshot operation on the volume.
func (p *pvcBackupItemAction) Execute(
	item runtime.Unstructured,
	backup *velerov1api.Backup,
) (
	runtime.Unstructured,
	[]velero.ResourceIdentifier,
	string,
	[]velero.ResourceIdentifier,
	error,
) {
	p.log.Info("Starting PVCBackupItemAction")

	if valid := p.validateBackup(*backup); !valid {
		return item, nil, "", nil, nil
	}

	var pvc corev1api.PersistentVolumeClaim
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		item.UnstructuredContent(),
		&pvc,
	); err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}
	if valid, item, err := p.validatePVCandPV(
		pvc,
		item,
	); !valid {
		if err != nil {
			return nil, nil, "", nil, err
		}
		return item, nil, "", nil, nil
	}

	// Ensure PVC-to-Pod cache is built for this namespace (lazy per-namespace caching)
	if err := p.ensurePVCPodCacheForNamespace(context.TODO(), pvc.Namespace); err != nil {
		return nil, nil, "", nil, err
	}

	// Get or create the cached VolumeHelper for this backup
	vh, err := p.getOrCreateVolumeHelper(backup)
	if err != nil {
		return nil, nil, "", nil, err
	}

	shouldSnapshot, err := vh.ShouldPerformSnapshot(
		item,
		kuberesource.PersistentVolumeClaims,
	)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if !shouldSnapshot {
		p.log.Debugf("CSI plugin skip snapshot for PVC %s according to the VolumeHelper setting.",
			pvc.Namespace+"/"+pvc.Name)
		return nil, nil, "", nil, err
	}

	vs, err := p.getVolumeSnapshotReference(context.TODO(), pvc, backup)
	if err != nil {
		return nil, nil, "", nil, err
	}

	// Wait until VS associated VSC snapshot handle created before
	// continue.we later require the vsc restore size
	vsc, err := csi.WaitUntilVSCHandleIsReady(
		vs,
		p.crClient,
		p.log,
		backup.Spec.CSISnapshotTimeout.Duration,
	)
	if err != nil {
		p.log.Errorf("Failed to wait for VolumeSnapshot %s/%s to become ReadyToUse within timeout %v: %s",
			vs.Namespace, vs.Name, backup.Spec.CSISnapshotTimeout.Duration, err.Error())
		csi.CleanupVolumeSnapshot(vs, p.crClient, p.log)
		return nil, nil, "", nil, errors.WithStack(err)
	}

	labels := map[string]string{
		velerov1api.VolumeSnapshotLabel: vs.Name,
		velerov1api.BackupNameLabel:     backup.Name,
	}

	annotations := map[string]string{
		velerov1api.VolumeSnapshotLabel:                 vs.Name,
		velerov1api.MustIncludeAdditionalItemAnnotation: "true",
	}

	var additionalItems []velero.ResourceIdentifier
	operationID := ""
	var itemToUpdate []velero.ResourceIdentifier

	if boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
		operationID = label.GetValidName(
			string(
				velerov1api.AsyncOperationIDPrefixDataUpload,
			) + string(backup.UID) + "." + string(pvc.UID),
		)
		dataUploadLog := p.log.WithFields(logrus.Fields{
			"Source PVC":     fmt.Sprintf("%s/%s", pvc.Namespace, pvc.Name),
			"VolumeSnapshot": fmt.Sprintf("%s/%s", vs.Namespace, vs.Name),
			"Operation ID":   operationID,
			"Backup":         backup.Name,
		})

		dataUploadLog.Info("Starting data upload of backup")

		dataUpload, err := createDataUpload(
			context.Background(),
			backup,
			p.crClient,
			vs,
			&pvc,
			operationID,
			vsc,
		)
		if err != nil {
			dataUploadLog.WithError(err).Error("failed to submit DataUpload")

			// TODO: need to use DeleteVolumeSnapshotIfAny, after data mover
			// adopting the controller-runtime client.
			if deleteErr := p.crClient.Delete(context.TODO(), vs); deleteErr != nil {
				if !apierrors.IsNotFound(deleteErr) {
					dataUploadLog.WithError(deleteErr).Error("fail to delete VolumeSnapshot")
				}
			}

			// Return without modification to not fail the backup,
			// and the above error log makes the backup partially fail.
			return item, nil, "", nil, nil
		} else {
			itemToUpdate = []velero.ResourceIdentifier{
				{
					GroupResource: schema.GroupResource{
						Group:    "velero.io",
						Resource: "datauploads",
					},
					Namespace: dataUpload.Namespace,
					Name:      dataUpload.Name,
				},
			}
			// Set the DataUploadNameLabel, which is used for restore to
			// let CSI plugin check whether it should handle the volume.
			// If volume is CSI migration, PVC doesn't have the annotation.
			annotations[velerov1api.DataUploadNameAnnotation] = dataUpload.Namespace + "/" + dataUpload.Name

			dataUploadLog.Info("DataUpload is submitted successfully.")
		}
	} else {
		setPVCRequestSizeToVSRestoreSize(&pvc, vsc, p.log)

		additionalItems = []velero.ResourceIdentifier{
			{
				GroupResource: kuberesource.VolumeSnapshots,
				Namespace:     vs.Namespace,
				Name:          vs.Name,
			},
		}
	}

	kubeutil.AddAnnotations(&pvc.ObjectMeta, annotations)
	kubeutil.AddLabels(&pvc.ObjectMeta, labels)

	p.log.Infof("Returning from PVCBackupItemAction with %d additionalItems to backup",
		len(additionalItems))
	for _, ai := range additionalItems {
		p.log.Debugf("%s: %s", ai.GroupResource.String(), ai.Name)
	}

	pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pvc)
	if err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}
	return &unstructured.Unstructured{Object: pvcMap},
		additionalItems, operationID, itemToUpdate, nil
}

func (p *pvcBackupItemAction) Name() string {
	return "PVCBackupItemAction"
}

func (p *pvcBackupItemAction) Progress(
	operationID string,
	backup *velerov1api.Backup,
) (velero.OperationProgress, error) {
	progress := velero.OperationProgress{}
	if operationID == "" {
		return progress, biav2.InvalidOperationIDError(operationID)
	}

	dataUpload, err := getDataUpload(context.Background(), p.crClient, backup.Namespace, operationID)
	if err != nil {
		p.log.Errorf(
			"fail to get DataUpload for backup %s/%s by operation ID %s: %s",
			backup.Namespace, backup.Name, operationID, err.Error(),
		)
		return progress, err
	}
	if dataUpload.Status.Phase == velerov2alpha1.DataUploadPhaseNew ||
		dataUpload.Status.Phase == "" {
		p.log.Debugf("DataUpload is still not processed yet. Skip progress update.")
		return progress, nil
	}

	progress.Description = string(dataUpload.Status.Phase)
	progress.OperationUnits = "Bytes"
	progress.NCompleted = dataUpload.Status.Progress.BytesDone
	progress.NTotal = dataUpload.Status.Progress.TotalBytes

	if dataUpload.Status.StartTimestamp != nil {
		progress.Started = dataUpload.Status.StartTimestamp.Time
	}

	if dataUpload.Status.CompletionTimestamp != nil {
		progress.Updated = dataUpload.Status.CompletionTimestamp.Time
	}

	if dataUpload.Status.Phase == velerov2alpha1.DataUploadPhaseCompleted {
		progress.Completed = true
	} else if dataUpload.Status.Phase == velerov2alpha1.DataUploadPhaseFailed {
		progress.Completed = true
		progress.Err = dataUpload.Status.Message
	} else if dataUpload.Status.Phase == velerov2alpha1.DataUploadPhaseCanceled {
		progress.Completed = true
		progress.Err = "DataUpload is canceled"
	}

	return progress, nil
}

func (p *pvcBackupItemAction) Cancel(operationID string, backup *velerov1api.Backup) error {
	if operationID == "" {
		return biav2.InvalidOperationIDError(operationID)
	}

	dataUpload, err := getDataUpload(context.Background(), p.crClient, backup.Namespace, operationID)
	if err != nil {
		p.log.Errorf(
			"fail to get DataUpload for backup %s/%s: %s",
			backup.Namespace, backup.Name, err.Error(),
		)
		return err
	}

	return cancelDataUpload(context.Background(), p.crClient, dataUpload)
}

func newDataUpload(
	backup *velerov1api.Backup,
	vs *snapshotv1api.VolumeSnapshot,
	pvc *corev1api.PersistentVolumeClaim,
	operationID string,
	vsc *snapshotv1api.VolumeSnapshotContent,
) *velerov2alpha1.DataUpload {
	dataUpload := &velerov2alpha1.DataUpload{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
			Kind:       "DataUpload",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    backup.Namespace,
			GenerateName: backup.Name + "-",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: velerov1api.SchemeGroupVersion.String(),
					Kind:       "Backup",
					Name:       backup.Name,
					UID:        backup.UID,
					Controller: boolptr.True(),
				},
			},
			Labels: map[string]string{
				velerov1api.BackupNameLabel:       label.GetValidName(backup.Name),
				velerov1api.BackupUIDLabel:        string(backup.UID),
				velerov1api.PVCUIDLabel:           string(pvc.UID),
				velerov1api.AsyncOperationIDLabel: operationID,
			},
		},
		Spec: velerov2alpha1.DataUploadSpec{
			SnapshotType: velerov2alpha1.SnapshotTypeCSI,
			CSISnapshot: &velerov2alpha1.CSISnapshotSpec{
				VolumeSnapshot: vs.Name,
				StorageClass:   *pvc.Spec.StorageClassName,
				Driver:         vsc.Spec.Driver,
			},
			SourcePVC:             pvc.Name,
			DataMover:             backup.Spec.DataMover,
			BackupStorageLocation: backup.Spec.StorageLocation,
			SourceNamespace:       pvc.Namespace,
			OperationTimeout:      backup.Spec.CSISnapshotTimeout,
		},
	}

	if vs.Spec.VolumeSnapshotClassName != nil {
		dataUpload.Spec.CSISnapshot.SnapshotClass = *vs.Spec.VolumeSnapshotClassName
	}

	if backup.Spec.UploaderConfig != nil &&
		backup.Spec.UploaderConfig.ParallelFilesUpload > 0 {
		dataUpload.Spec.DataMoverConfig = make(map[string]string)
		dataUpload.Spec.DataMoverConfig[uploaderUtil.ParallelFilesUpload] = strconv.Itoa(backup.Spec.UploaderConfig.ParallelFilesUpload)
	}

	return dataUpload
}

func createDataUpload(
	ctx context.Context,
	backup *velerov1api.Backup,
	crClient crclient.Client,
	vs *snapshotv1api.VolumeSnapshot,
	pvc *corev1api.PersistentVolumeClaim,
	operationID string,
	vsc *snapshotv1api.VolumeSnapshotContent,
) (*velerov2alpha1.DataUpload, error) {
	dataUpload := newDataUpload(backup, vs, pvc, operationID, vsc)

	err := crClient.Create(ctx, dataUpload)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create DataUpload CR")
	}

	return dataUpload, err
}

func getDataUpload(
	ctx context.Context,
	crClient crclient.Client,
	namespace string,
	operationID string,
) (*velerov2alpha1.DataUpload, error) {
	dataUploadList := new(velerov2alpha1.DataUploadList)
	err := crClient.List(ctx, dataUploadList, &crclient.ListOptions{
		Namespace: namespace,
		LabelSelector: labels.SelectorFromSet(
			map[string]string{velerov1api.AsyncOperationIDLabel: operationID},
		),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "error to list DataUpload")
	}

	if len(dataUploadList.Items) == 0 {
		return nil, errors.Errorf("not found DataUpload for operationID %s", operationID)
	}

	if len(dataUploadList.Items) > 1 {
		return nil, errors.Errorf("more than one DataUpload found operationID %s", operationID)
	}

	return &dataUploadList.Items[0], nil
}

func cancelDataUpload(
	ctx context.Context,
	crClient crclient.Client,
	dataUpload *velerov2alpha1.DataUpload,
) error {
	updatedDataUpload := dataUpload.DeepCopy()
	updatedDataUpload.Spec.Cancel = true

	err := crClient.Patch(ctx, updatedDataUpload, crclient.MergeFrom(dataUpload))
	if err != nil {
		return errors.Wrap(err, "error patch DataUpload")
	}

	return nil
}

func NewPvcBackupItemAction(f veleroclient.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		return &pvcBackupItemAction{
			log:      logger,
			crClient: crClient,
		}, nil
	}
}

func (p *pvcBackupItemAction) getVolumeSnapshotReference(
	ctx context.Context,
	pvc corev1api.PersistentVolumeClaim,
	backup *velerov1api.Backup,
) (*snapshotv1api.VolumeSnapshot, error) {
	vgsLabelKey := backup.Spec.VolumeGroupSnapshotLabelKey
	group, hasLabel := pvc.Labels[vgsLabelKey]

	if vgsLabelKey != "" && hasLabel && group != "" {
		p.log.Infof("PVC %s/%s is part of VolumeGroupSnapshot group %q via label %q", pvc.Namespace, pvc.Name, group, vgsLabelKey)

		// Try to find an existing VS created via a previous VGS in the current backup
		existingVS, err := p.findExistingVSForBackup(ctx, backup.UID, backup.Name, pvc.Name, pvc.Namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to find existing VolumeSnapshot for PVC %s/%s", pvc.Namespace, pvc.Name)
		}

		if existingVS != nil {
			if existingVS.Status != nil && existingVS.Status.VolumeGroupSnapshotName != nil {
				p.log.Infof("Reusing existing VolumeSnapshot %s for PVC %s", existingVS.Name, pvc.Name)
				return existingVS, nil
			} else {
				return nil, errors.Errorf("found VolumeSnapshot %s for PVC %s, but it was not created via VolumeGroupSnapshot (missing volumeGroupSnapshotName)", existingVS.Name, pvc.Name)
			}
		}

		p.log.Infof("No existing VS found for PVC %s; creating new VGS", pvc.Name)

		// List all PVCs in the VGS group
		groupedPVCs, err := p.listGroupedPVCs(ctx, pvc.Namespace, vgsLabelKey, group)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list PVCs in VolumeGroupSnapshot group %q in namespace %q", group, pvc.Namespace)
		}

		// Ensure PVC-to-Pod cache is built for this namespace (lazy per-namespace caching)
		if err := p.ensurePVCPodCacheForNamespace(ctx, pvc.Namespace); err != nil {
			return nil, errors.Wrapf(err, "failed to build PVC-to-Pod cache for namespace %s", pvc.Namespace)
		}

		// Get the cached VolumeHelper for filtering PVCs by volume policy
		vh, err := p.getOrCreateVolumeHelper(backup)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get VolumeHelper for filtering PVCs in group %q", group)
		}

		// Filter PVCs by volume policy
		filteredPVCs, err := p.filterPVCsByVolumePolicy(groupedPVCs, vh)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to filter PVCs by volume policy for VolumeGroupSnapshot group %q", group)
		}

		// Warn if any PVCs were filtered out
		if len(filteredPVCs) < len(groupedPVCs) {
			for _, originalPVC := range groupedPVCs {
				found := false
				for _, filteredPVC := range filteredPVCs {
					if originalPVC.Name == filteredPVC.Name {
						found = true
						break
					}
				}
				if !found {
					p.log.Warnf("PVC %s/%s has VolumeGroupSnapshot label %s=%s but is excluded by volume policy", originalPVC.Namespace, originalPVC.Name, vgsLabelKey, group)
				}
			}
		}

		// Determine the CSI driver for the grouped PVCs
		driver, err := p.determineCSIDriver(filteredPVCs)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to determine CSI driver for PVCs in VolumeGroupSnapshot group %q", group)
		}
		if driver == "" {
			return nil, errors.New("no csi driver found, failing the backup")
		}

		// Determine the VGSClass to be used for the VGS object to be created
		vgsClass, err := p.determineVGSClass(ctx, driver, backup, &pvc)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to determine VolumeGroupSnapshotClass for CSI driver %q", driver)
		}

		// Create the VGS object
		newVGS, err := p.createVolumeGroupSnapshot(ctx, backup, pvc, vgsLabelKey, group, vgsClass)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create VolumeGroupSnapshot for PVC %s/%s", pvc.Namespace, pvc.Name)
		}

		// Wait for all the VS objects associated with the VGS to have status and VGS Name (VS readiness is checked in legacy flow) and get the PVC-to-VS map
		vsMap, err := p.waitForVGSAssociatedVS(ctx, filteredPVCs, newVGS, backup.Spec.CSISnapshotTimeout.Duration)
		if err != nil {
			return nil, errors.Wrapf(err, "timeout waiting for VolumeSnapshots to have status created via VolumeGroupSnapshot %s", newVGS.Name)
		}

		// Update the VS objects: remove VGS owner references and finalizers; add backup metadata labels.
		err = p.updateVGSCreatedVS(ctx, vsMap, newVGS, backup)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to update VolumeSnapshots created by VolumeGroupSnapshot %s", newVGS.Name)
		}

		// Wait for VGSC binding in the VGS status
		err = p.waitForVGSCBinding(ctx, newVGS, backup.Spec.CSISnapshotTimeout.Duration)
		if err != nil {
			return nil, errors.Wrapf(err, "timeout waiting for VolumeGroupSnapshotContent binding for VolumeGroupSnapshot %s", newVGS.Name)
		}

		// Re-fetch latest VGS to ensure status is populated after VGSC binding
		latestVGS := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
		if err := p.crClient.Get(ctx, crclient.ObjectKeyFromObject(newVGS), latestVGS); err != nil {
			return nil, errors.Wrapf(err, "failed to re-fetch VolumeGroupSnapshot %s after VGSC binding wait", newVGS.Name)
		}

		// Patch the VGSC deletionPolicy to Retain.
		err = p.patchVGSCDeletionPolicy(ctx, latestVGS)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to patch VolumeGroupSnapshotContent Deletion Policy for VolumeGroupSnapshot %s", newVGS.Name)
		}

		// Delete the VGS and VGSC
		err = p.deleteVGSAndVGSC(ctx, latestVGS)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get VolumeSnapshot for PVC %s/%s created by VolumeGroupSnapshot %s", pvc.Namespace, pvc.Name, newVGS.Name)
		}

		// Use the VS that was created for this PVC via VGS.
		vs, found := vsMap[pvc.Name]
		if !found {
			return nil, errors.Wrapf(err, "failed to get VolumeSnapshot for PVC %s/%s created by VolumeGroupSnapshot %s", pvc.Namespace, pvc.Name, newVGS.Name)
		}

		return vs, nil
	}

	// Legacy fallback: create individual VS
	return p.createVolumeSnapshot(pvc, backup)
}

func (p *pvcBackupItemAction) findExistingVSForBackup(
	ctx context.Context,
	backupUID types.UID,
	backupName, pvcName, namespace string,
) (*snapshotv1api.VolumeSnapshot, error) {
	vsList := &snapshotv1api.VolumeSnapshotList{}

	labelSelector := labels.SelectorFromSet(map[string]string{
		velerov1api.BackupNameLabel: label.GetValidName(backupName),
		velerov1api.BackupUIDLabel:  string(backupUID),
	})

	if err := p.crClient.List(ctx, vsList,
		crclient.InNamespace(namespace),
		crclient.MatchingLabelsSelector{Selector: labelSelector},
	); err != nil {
		return nil, errors.Wrap(err, "failed to list VolumeSnapshots with backup labels")
	}

	for _, vs := range vsList.Items {
		if vs.Spec.Source.PersistentVolumeClaimName != nil &&
			*vs.Spec.Source.PersistentVolumeClaimName == pvcName {
			return &vs, nil
		}
	}

	return nil, nil
}

func (p *pvcBackupItemAction) listGroupedPVCs(ctx context.Context, namespace, labelKey, groupValue string) ([]corev1api.PersistentVolumeClaim, error) {
	pvcList := new(corev1api.PersistentVolumeClaimList)
	if err := p.crClient.List(
		ctx,
		pvcList,
		crclient.InNamespace(namespace),
		crclient.MatchingLabels{labelKey: groupValue},
	); err != nil {
		return nil, errors.Wrap(err, "failed to list grouped PVCs")
	}

	return pvcList.Items, nil
}

func (p *pvcBackupItemAction) filterPVCsByVolumePolicy(
	pvcs []corev1api.PersistentVolumeClaim,
	vh vhutil.VolumeHelper,
) ([]corev1api.PersistentVolumeClaim, error) {
	var filteredPVCs []corev1api.PersistentVolumeClaim

	for _, pvc := range pvcs {
		// Convert PVC to unstructured for ShouldPerformSnapshotWithVolumeHelper
		pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pvc)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to convert PVC %s/%s to unstructured", pvc.Namespace, pvc.Name)
		}
		unstructuredPVC := &unstructured.Unstructured{Object: pvcMap}

		// Check if this PVC should be snapshotted according to volume policies
		// Uses the cached VolumeHelper for better performance with many PVCs/pods
		shouldSnapshot, err := vh.ShouldPerformSnapshot(
			unstructuredPVC,
			kuberesource.PersistentVolumeClaims,
		)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to check volume policy for PVC %s/%s", pvc.Namespace, pvc.Name)
		}

		if shouldSnapshot {
			filteredPVCs = append(filteredPVCs, pvc)
		}
	}

	return filteredPVCs, nil
}

func (p *pvcBackupItemAction) determineCSIDriver(
	pvcs []corev1api.PersistentVolumeClaim,
) (string, error) {
	var driver string

	for _, pvc := range pvcs {
		pv, err := kubeutil.GetPVForPVC(&pvc, p.crClient)
		if err != nil {
			return "", err
		}
		if pv.Spec.CSI == nil {
			return "", errors.Errorf("PV %s for PVC %s is not CSI provisioned", pv.Name, pvc.Name)
		}
		current := pv.Spec.CSI.Driver
		if driver == "" {
			driver = current
		} else if driver != current {
			return "", errors.Errorf("found multiple CSI drivers: %s and %s", driver, current)
		}
	}
	return driver, nil
}

func (p *pvcBackupItemAction) determineVGSClass(
	ctx context.Context,
	driver string,
	backup *velerov1api.Backup,
	pvc *corev1api.PersistentVolumeClaim,
) (string, error) {
	// 1. PVC-level override
	if pvc != nil {
		if val, ok := pvc.Annotations[velerov1api.VolumeGroupSnapshotClassAnnotationPVC]; ok && val != "" {
			return val, nil
		}
	}

	// 2. Backup-level override
	key := fmt.Sprintf(velerov1api.VolumeGroupSnapshotClassAnnotationBackupPrefix+"%s", driver)
	if val, ok := backup.Annotations[key]; ok && val != "" {
		return val, nil
	}

	// 3. Fallback to label-based default
	vgsClassList := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotClassList{}
	if err := p.crClient.List(ctx, vgsClassList); err != nil {
		return "", errors.Wrap(err, "failed to list VolumeGroupSnapshotClasses")
	}

	var matched []string
	for _, class := range vgsClassList.Items {
		if class.Driver != driver {
			continue
		}
		if val, ok := class.Labels[velerov1api.VolumeGroupSnapshotClassDefaultLabel]; ok && val == "true" {
			matched = append(matched, class.Name)
		}
	}

	if len(matched) == 1 {
		return matched[0], nil
	} else if len(matched) == 0 {
		return "", errors.Errorf("no VolumeGroupSnapshotClass found for driver %q for PVC %s", driver, pvc.Name)
	} else {
		return "", errors.Errorf("multiple VolumeGroupSnapshotClasses found for driver %q with label velero.io/csi-volumegroupsnapshot-class=true", driver)
	}
}

func (p *pvcBackupItemAction) createVolumeGroupSnapshot(
	ctx context.Context,
	backup *velerov1api.Backup,
	pvc corev1api.PersistentVolumeClaim,
	vgsLabelKey, vgsLabelValue, vgsClassName string,
) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshot, error) {
	vgsLabels := map[string]string{
		velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
		velerov1api.BackupUIDLabel:  string(backup.UID),
		vgsLabelKey:                 vgsLabelValue,
	}

	vgs := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("velero-%s-", vgsLabelValue),
			Namespace:    pvc.Namespace,
			Labels:       vgsLabels,
		},
		Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotSpec{
			VolumeGroupSnapshotClassName: &vgsClassName,
			Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotSource{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						vgsLabelKey: vgsLabelValue,
					},
				},
			},
		},
	}

	if err := p.crClient.Create(ctx, vgs); err != nil {
		return nil, errors.Wrap(err, "failed to create VolumeGroupSnapshot")
	}

	refetchedVGS, err := p.getVGSByLabels(ctx, pvc.Namespace, vgsLabels)
	if err != nil {
		return nil, errors.Wrap(err, "failed to re-fetch VGS after creation")
	}

	p.log.Infof("Re-fetched Created VolumeGroupSnapshot %s/%s for PVC group label %s=%s",
		refetchedVGS.Namespace, refetchedVGS.Name, vgsLabelKey, vgsLabelValue)

	return refetchedVGS, nil
}

func (p *pvcBackupItemAction) waitForVGSAssociatedVS(
	ctx context.Context,
	groupedPVCs []corev1api.PersistentVolumeClaim,
	vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot,
	timeout time.Duration,
) (map[string]*snapshotv1api.VolumeSnapshot, error) {
	expected := len(groupedPVCs)

	vsMap := make(map[string]*snapshotv1api.VolumeSnapshot)

	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (done bool, err error) {
		vsList := &snapshotv1api.VolumeSnapshotList{}
		if err := p.crClient.List(ctx, vsList, crclient.InNamespace(vgs.Namespace)); err != nil {
			return false, err
		}

		vsMap = make(map[string]*snapshotv1api.VolumeSnapshot)

		for _, vs := range vsList.Items {
			if !hasOwnerReference(&vs, vgs) {
				continue
			}
			if vs.Status != nil && vs.Status.VolumeGroupSnapshotName != nil &&
				*vs.Status.VolumeGroupSnapshotName == vgs.Name {
				if vs.Spec.Source.PersistentVolumeClaimName != nil {
					vsMap[*vs.Spec.Source.PersistentVolumeClaimName] = vs.DeepCopy()
				}
			}
		}

		if expected == 0 {
			return false, nil
		}
		if len(vsMap) == expected {
			return true, nil
		}
		return false, nil
	})

	if err != nil {
		return nil, errors.Wrapf(err, "timeout waiting for VolumeSnapshots associated with VGS %s", vgs.Name)
	}

	return vsMap, nil
}

func hasOwnerReference(obj metav1.Object, vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == kuberesource.VGSKind &&
			ref.APIVersion == volumegroupsnapshotv1beta2.GroupName+"/"+volumegroupsnapshotv1beta2.SchemeGroupVersion.Version &&
			ref.UID == vgs.UID {
			return true
		}
	}
	return false
}

func (p *pvcBackupItemAction) updateVGSCreatedVS(
	ctx context.Context,
	vsMap map[string]*snapshotv1api.VolumeSnapshot,
	vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot,
	backup *velerov1api.Backup,
) error {
	for pvcName, vs := range vsMap {
		if vs == nil || vs.Status == nil || vs.Status.VolumeGroupSnapshotName == nil ||
			*vs.Status.VolumeGroupSnapshotName != vgs.Name {
			continue
		}

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// Re-fetch the latest VS to avoid conflict
			latestVS := &snapshotv1api.VolumeSnapshot{}
			if err := p.crClient.Get(ctx, crclient.ObjectKeyFromObject(vs), latestVS); err != nil {
				return errors.Wrapf(err, "failed to get latest VolumeSnapshot %s (PVC %s)", vs.Name, pvcName)
			}

			// Remove VGS owner ref
			if err := controllerutil.RemoveOwnerReference(vgs, latestVS, p.crClient.Scheme()); err != nil {
				return errors.Wrapf(err, "failed to remove VGS owner reference from VS %s", vs.Name)
			}

			// Remove known finalizers
			controllerutil.RemoveFinalizer(latestVS, VolumeSnapshotFinalizerGroupProtection)
			controllerutil.RemoveFinalizer(latestVS, VolumeSnapshotFinalizerSourceProtection)

			// Add Velero labels
			if latestVS.Labels == nil {
				latestVS.Labels = make(map[string]string)
			}
			latestVS.Labels[velerov1api.BackupNameLabel] = backup.Name
			latestVS.Labels[velerov1api.BackupUIDLabel] = string(backup.UID)

			// Attempt to update
			return p.crClient.Update(ctx, latestVS)
		})
		if err != nil {
			return errors.Wrapf(err, "failed to update VS %s (PVC %s) after retrying on conflict", vs.Name, pvcName)
		}
	}

	return nil
}

func (p *pvcBackupItemAction) patchVGSCDeletionPolicy(ctx context.Context, vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot) error {
	if vgs == nil || vgs.Status == nil || vgs.Status.BoundVolumeGroupSnapshotContentName == nil {
		return errors.New("VolumeGroupSnapshotContent name not found in VGS status")
	}

	vgscName := vgs.Status.BoundVolumeGroupSnapshotContentName

	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		vgsc := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
		if err := p.crClient.Get(ctx, crclient.ObjectKey{Name: *vgscName}, vgsc); err != nil {
			return errors.Wrapf(err, "failed to get VolumeGroupSnapshotContent %s for VolumeGroupSnapshot %s/%s", *vgscName, vgs.Namespace, vgs.Name)
		}

		if vgsc.Spec.DeletionPolicy == snapshotv1api.VolumeSnapshotContentDelete {
			p.log.Infof("Patching VGSC %s to Retain deletionPolicy", *vgscName)
			vgsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
			if err := p.crClient.Update(ctx, vgsc); err != nil {
				return errors.Wrapf(err, "failed to update VGSC %s deletionPolicy", *vgscName)
			}
		} else {
			p.log.Infof("VGSC %s already set to deletionPolicy=%s", *vgscName, vgsc.Spec.DeletionPolicy)
		}

		return nil
	})
}

func (p *pvcBackupItemAction) deleteVGSAndVGSC(ctx context.Context, vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot) error {
	if vgs.Status != nil && vgs.Status.BoundVolumeGroupSnapshotContentName != nil {
		vgsc := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{
				Name: *vgs.Status.BoundVolumeGroupSnapshotContentName,
			},
		}
		p.log.Infof("Deleting VolumeGroupSnapshotContent %s", vgsc.Name)
		if err := p.crClient.Delete(ctx, vgsc); err != nil && !apierrors.IsNotFound(err) {
			p.log.Warnf("Failed to delete VolumeGroupSnapshotContent %s: %v", vgsc.Name, err)
			return errors.Wrapf(err, "failed to delete VolumeGroupSnapshotContent %s", vgsc.Name)
		}
	} else {
		p.log.Infof("No BoundVolumeGroupSnapshotContentName set in VolumeGroupSnapshot %s/%s", vgs.Namespace, vgs.Name)
	}

	p.log.Infof("Deleting VolumeGroupSnapshot %s/%s", vgs.Namespace, vgs.Name)
	if err := p.crClient.Delete(ctx, vgs); err != nil && !apierrors.IsNotFound(err) {
		p.log.Warnf("Failed to delete VolumeGroupSnapshot %s/%s: %v", vgs.Namespace, vgs.Name, err)
		return errors.Wrapf(err, "failed to delete VolumeGroupSnapshot %s/%s", vgs.Namespace, vgs.Name)
	}

	return nil
}

func (p *pvcBackupItemAction) waitForVGSCBinding(
	ctx context.Context,
	vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot,
	timeout time.Duration,
) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		vgsRef := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
		if err := p.crClient.Get(ctx, crclient.ObjectKeyFromObject(vgs), vgsRef); err != nil {
			return false, err
		}

		if vgsRef.Status != nil && vgsRef.Status.BoundVolumeGroupSnapshotContentName != nil {
			return true, nil
		}

		return false, nil
	})
}

func (p *pvcBackupItemAction) getVGSByLabels(ctx context.Context, namespace string, labels map[string]string) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshot, error) {
	vgsList := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotList{}
	if err := p.crClient.List(ctx, vgsList,
		crclient.InNamespace(namespace),
		crclient.MatchingLabels(labels),
	); err != nil {
		return nil, errors.Wrap(err, "failed to list VolumeGroupSnapshots by labels")
	}

	if len(vgsList.Items) == 0 {
		return nil, errors.New("no VolumeGroupSnapshot found matching labels")
	}
	if len(vgsList.Items) > 1 {
		return nil, errors.New("multiple VolumeGroupSnapshots found matching labels")
	}

	return &vgsList.Items[0], nil
}

func setPVCRequestSizeToVSRestoreSize(
	pvc *corev1api.PersistentVolumeClaim,
	vsc *snapshotv1api.VolumeSnapshotContent,
	logger logrus.FieldLogger,
) {
	if vsc.Status.RestoreSize != nil {
		logger.Debugf("Patching PVC request size to fit the volumesnapshot restore size %d", vsc.Status.RestoreSize)
		restoreSize := *resource.NewQuantity(*vsc.Status.RestoreSize, resource.BinarySI)

		// It is possible that the volume provider allocated a larger
		// capacity volume than what was requested in the backed up PVC.
		// In this scenario the volumesnapshot of the PVC will end being
		// larger than its requested storage size.  Such a PVC, on restore
		// as-is, will be stuck attempting to use a VolumeSnapshot as a
		// data source for a PVC that is not large enough.
		// To counter that, here we set the storage request on the PVC
		// to the larger of the PVC's storage request and the size of the
		// VolumeSnapshot
		setPVCStorageResourceRequest(pvc, restoreSize, logger)
	}
}

func setPVCStorageResourceRequest(
	pvc *corev1api.PersistentVolumeClaim,
	restoreSize resource.Quantity,
	log logrus.FieldLogger,
) {
	{
		if pvc.Spec.Resources.Requests == nil {
			pvc.Spec.Resources.Requests = corev1api.ResourceList{}
		}

		storageReq, exists := pvc.Spec.Resources.Requests[corev1api.ResourceStorage]
		if !exists || storageReq.Cmp(restoreSize) < 0 {
			pvc.Spec.Resources.Requests[corev1api.ResourceStorage] = restoreSize
			rs := pvc.Spec.Resources.Requests[corev1api.ResourceStorage]
			log.Infof("Resetting storage requests for PVC %s/%s to %s",
				pvc.Namespace, pvc.Name, rs.String())
		}
	}
}
