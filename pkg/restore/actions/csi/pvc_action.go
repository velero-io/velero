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
	"encoding/json"
	"fmt"
	"time"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/client"
	kuberesource "github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/label"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v2"
	uploaderUtil "github.com/vmware-tanzu/velero/pkg/uploader/util"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	AnnSelectedNode          = "volume.kubernetes.io/selected-node"
	GenerateNameRandomLength = 5
)

// pvcRestoreItemAction is a restore item action plugin for Velero
type pvcRestoreItemAction struct {
	log        logrus.FieldLogger
	crClient   crclient.Client
	kubeClient kubernetes.Interface
}

// AppliesTo returns information indicating that the
// PVCCSIRestoreItemAction should be run while restoring PVCs.
func (p *pvcRestoreItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"persistentvolumeclaims"},
		//TODO: add label selector volumeSnapshotLabel
	}, nil
}

// Execute modifies the PVC's spec to use the VolumeSnapshot object as the
// data source ensuring that the newly provisioned volume can be pre-populated
// with data from the VolumeSnapshot.
func (p *pvcRestoreItemAction) Execute(
	input *velero.RestoreItemActionExecuteInput,
) (*velero.RestoreItemActionExecuteOutput, error) {
	var pvc, pvcFromBackup corev1api.PersistentVolumeClaim
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.Item.UnstructuredContent(), &pvc); err != nil {
		return nil, errors.WithStack(err)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.ItemFromBackup.UnstructuredContent(), &pvcFromBackup); err != nil {
		return nil, errors.WithStack(err)
	}

	logger := p.log.WithFields(logrus.Fields{
		"Action":  "PVCCSIRestoreItemAction",
		"PVC":     pvc.Namespace + "/" + pvc.Name,
		"Restore": input.Restore.Namespace + "/" + input.Restore.Name,
	})
	logger.Info("Starting PVCCSIRestoreItemAction for PVC")

	// make sure this RIA only runs for CSI snapshot
	vsName, nameOK := pvcFromBackup.Annotations[velerov1api.VolumeSnapshotLabel]
	if !nameOK {
		logger.Info("Skipping PVCCSIRestoreItemAction for PVC, PVC does not have a CSI VolumeSnapshot.")
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	pvcExists, existingPVC, err := p.isResourceExist(&pvc, *input.Restore)
	if err != nil {
		logger.Error(err)
		return nil, errors.WithStack(err)
	}

	var output *velero.RestoreItemActionExecuteOutput
	if boolptr.IsSetToFalse(input.Restore.Spec.RestorePVs) {
		output, err = p.executeWithoutPVRestore(logger, input, pvcExists, &pvc)
	} else {
		backup := new(velerov1api.Backup)
		if err := p.crClient.Get(context.TODO(), crclient.ObjectKey{Namespace: input.Restore.Namespace, Name: input.Restore.Spec.BackupName}, backup); err != nil {
			return nil, fmt.Errorf("fail to get backup for restore: %s", err.Error())
		}
		if boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
			output, err = p.executeWithDataMove(logger, input, backup, pvcExists, existingPVC, &pvc, &pvcFromBackup)
		} else {
			output, err = p.executeWithoutDataMove(logger, input, pvcExists, &pvc, vsName)
		}
	}
	if err != nil {
		logger.Error(err)
		return nil, errors.WithStack(err)
	}

	logger.Info("Returning from PVCCSIRestoreItemAction for PVC")

	return output, nil
}

func (p *pvcRestoreItemAction) executeWithoutPVRestore(logger *logrus.Entry, input *velero.RestoreItemActionExecuteInput, pvcExists bool, pvc *corev1api.PersistentVolumeClaim) (*velero.RestoreItemActionExecuteOutput, error) {
	if pvcExists {
		logger.Warnf("PVC already exists. Skip restore this PVC.")
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	logger.Info("Restore did not request for PVs to be restored from snapshot")
	pvc.Spec.VolumeName = ""
	pvc.Spec.DataSource = nil
	pvc.Spec.DataSourceRef = nil

	unstructuredPVC, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{Object: unstructuredPVC},
	}, nil
}

func (p *pvcRestoreItemAction) executeWithoutDataMove(logger *logrus.Entry, input *velero.RestoreItemActionExecuteInput, pvcExists bool, pvc *corev1api.PersistentVolumeClaim, vsName string) (*velero.RestoreItemActionExecuteOutput, error) {
	if pvcExists {
		logger.Warnf("PVC already exists. Skip restore this PVC.")
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	//To avoid confilcs, vs and vsc get a new uniq name based in restore UID
	// and vs name old name
	newVSName := util.GenerateSha256FromRestoreUIDAndVsName(string(input.Restore.UID), vsName)

	logger.Debugf("Setting PVC source to VolumeSnapshot new name: %s", newVSName)
	resetPVCSourceToVolumeSnapshot(pvc, newVSName)

	// Force-restore the VolumeSnapshot even when restore resource filters
	// would otherwise exclude it (mirrors backup-side must-include).
	annotations := pvc.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[velerov1api.MustIncludeAdditionalItemRestoreAnnotation] = "true"
	pvc.SetAnnotations(annotations)

	unstructuredPVC, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{Object: unstructuredPVC},
		AdditionalItems: []velero.ResourceIdentifier{
			{
				GroupResource: kuberesource.VolumeSnapshots,
				Name:          vsName,
				Namespace:     pvc.Namespace,
			},
		},
	}, nil
}

func (p *pvcRestoreItemAction) executeWithDataMove(logger *logrus.Entry, input *velero.RestoreItemActionExecuteInput, backup *velerov1api.Backup, pvcExists bool, existingPVC, pvc, pvcFromBackup *corev1api.PersistentVolumeClaim) (*velero.RestoreItemActionExecuteOutput, error) {
	var existingPV *corev1api.PersistentVolume
	var err error
	if pvcExists {
		// If PVC already exists and is not in-place restore, returns early.
		if !input.Restore.IsVolumeDataInplaceRestore() {
			logger.Warnf("PVC already exists and ExistingVolumeDataPolicy is not in-place restore. Skip restore this PVC.")
			return &velero.RestoreItemActionExecuteOutput{
				UpdatedItem: input.Item,
			}, nil
		}

		// the existing PVC should be deleted here rather than in the Exposer, otherwise the target PVC cannot be restored
		existingPV, err = p.prepareForInplaceRestore(context.Background(), logger, pvc, existingPVC, backup.Spec.CSISnapshotTimeout.Duration)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	logger.Info("Start DataMover restore.")

	// If PVC doesn't have a DataUploadNameLabel, which should be created
	// during backup, then CSI cannot handle the volume during to restore,
	// so return early to let Velero tries to fall back to Velero native snapshot.
	if _, ok := pvcFromBackup.Annotations[velerov1api.DataUploadNameAnnotation]; !ok {
		logger.Warnf("PVC doesn't have a DataUpload for data mover. Return.")
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	operationID := label.GetValidName(
		string(velerov1api.AsyncOperationIDPrefixDataDownload) +
			string(input.Restore.UID) + "." + string(pvcFromBackup.UID))

	// If cross-namespace restore is configured, change the namespace
	// for PVC object to be restored
	newNamespace, ok := input.Restore.Spec.NamespaceMapping[pvc.GetNamespace()]
	if !ok {
		// Use original namespace
		newNamespace = pvc.Namespace
	}

	dataDownload, err := restoreFromDataUploadResult(
		context.Background(), input.Restore, backup, pvc, existingPV, newNamespace,
		operationID, p.crClient)
	if err != nil {
		logger.Errorf("Fail to restore from DataUploadResult: %s", err.Error())
		return nil, errors.WithStack(err)
	}
	logger.Infof("DataDownload %s/%s is created successfully.",
		dataDownload.Namespace, dataDownload.Name)

	unstructuredPVC, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{Object: unstructuredPVC},
		OperationID: operationID,
	}, nil
}

func resetPVCSourceToVolumeSnapshot(pvc *corev1api.PersistentVolumeClaim, vsName string) {
	// Restore operation for the PVC will use the VolumeSnapshot as the data source.
	// So clear out the volume name, which is a ref to the PV
	pvc.Spec.VolumeName = ""
	dataSource := &corev1api.TypedLocalObjectReference{
		APIGroup: &snapshotv1api.SchemeGroupVersion.Group,
		Kind:     "VolumeSnapshot",
		Name:     vsName,
	}
	pvc.Spec.DataSource = dataSource
	pvc.Spec.DataSourceRef = nil
}

func (p *pvcRestoreItemAction) Name() string {
	return "PVCRestoreItemAction"
}

func (p *pvcRestoreItemAction) Progress(
	operationID string,
	restore *velerov1api.Restore,
) (velero.OperationProgress, error) {
	progress := velero.OperationProgress{}

	if operationID == "" {
		return progress, riav2.InvalidOperationIDError(operationID)
	}
	logger := p.log.WithFields(logrus.Fields{
		"Action":      "PVCRestoreItemAction",
		"OperationID": operationID,
		"Namespace":   restore.Namespace,
	})

	dataDownload, err := getDataDownload(
		context.Background(),
		restore.Namespace,
		operationID,
		p.crClient,
	)
	if err != nil {
		logger.Errorf("fail to get DataDownload: %s", err.Error())
		return progress, err
	}
	if dataDownload.Status.Phase == velerov2alpha1.DataDownloadPhaseNew ||
		dataDownload.Status.Phase == "" {
		logger.Debugf("DataDownload is still not processed yet. Skip progress update.")
		return progress, nil
	}

	progress.Description = string(dataDownload.Status.Phase)
	progress.OperationUnits = "Bytes"
	progress.NCompleted = dataDownload.Status.Progress.BytesDone
	progress.NTotal = dataDownload.Status.Progress.TotalBytes

	if dataDownload.Status.StartTimestamp != nil {
		progress.Started = dataDownload.Status.StartTimestamp.Time
	}

	if dataDownload.Status.CompletionTimestamp != nil {
		progress.Updated = dataDownload.Status.CompletionTimestamp.Time
	}

	if dataDownload.Status.Phase == velerov2alpha1.DataDownloadPhaseCompleted {
		progress.Completed = true
	} else if dataDownload.Status.Phase == velerov2alpha1.DataDownloadPhaseCanceled {
		progress.Completed = true
		progress.Err = "DataDownload is canceled"
	} else if dataDownload.Status.Phase == velerov2alpha1.DataDownloadPhaseFailed {
		progress.Completed = true
		progress.Err = dataDownload.Status.Message
	}

	return progress, nil
}

func (p *pvcRestoreItemAction) Cancel(
	operationID string, restore *velerov1api.Restore) error {
	if operationID == "" {
		return riav2.InvalidOperationIDError(operationID)
	}
	logger := p.log.WithFields(logrus.Fields{
		"Action":      "PVCRestoreItemAction",
		"OperationID": operationID,
		"Namespace":   restore.Namespace,
	})

	dataDownload, err := getDataDownload(
		context.Background(),
		restore.Namespace,
		operationID,
		p.crClient,
	)
	if err != nil {
		logger.Errorf("fail to get DataDownload: %s", err.Error())
		return err
	}

	err = cancelDataDownload(context.Background(), p.crClient, dataDownload)
	if err != nil {
		logger.Errorf("fail to cancel DataDownload %s: %s", dataDownload.Name, err.Error())
	}
	return err
}

func (p *pvcRestoreItemAction) AreAdditionalItemsReady(
	additionalItems []velero.ResourceIdentifier,
	restore *velerov1api.Restore,
) (bool, error) {
	return true, nil
}

func getDataUploadResult(
	ctx context.Context,
	restore *velerov1api.Restore,
	pvc *corev1api.PersistentVolumeClaim,
	crClient crclient.Client,
) (*velerov2alpha1.DataUploadResult, error) {
	selectorStr := fmt.Sprintf("%s=%s,%s=%s,%s=%s",
		velerov1api.PVCNamespaceNameLabel,
		label.GetValidName(pvc.Namespace+"."+pvc.Name),
		velerov1api.RestoreUIDLabel,
		label.GetValidName(string(restore.UID)),
		velerov1api.ResourceUsageLabel,
		label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)),
	)
	selector, _ := labels.Parse(selectorStr)

	cmList := new(corev1api.ConfigMapList)
	if err := crClient.List(
		ctx,
		cmList,
		&crclient.ListOptions{
			LabelSelector: selector,
			Namespace:     restore.Namespace,
		}); err != nil {
		return nil, errors.Wrapf(err,
			"error to get DataUpload result cm with labels %s", selectorStr)
	}

	if len(cmList.Items) == 0 {
		return nil, errors.Errorf(
			"no DataUpload result cm found with labels %s", selectorStr)
	}

	if len(cmList.Items) > 1 {
		return nil, errors.Errorf(
			"multiple DataUpload result cms found with labels %s", selectorStr)
	}

	jsonBytes, exist := cmList.Items[0].Data[string(restore.UID)]
	if !exist {
		return nil, errors.Errorf(
			"no DataUpload result found with restore key %s, restore %s",
			string(restore.UID), restore.Name)
	}

	result := velerov2alpha1.DataUploadResult{}
	if err := json.Unmarshal([]byte(jsonBytes), &result); err != nil {
		return nil, errors.Errorf(
			"error to unmarshal DataUploadResult, restore UID %s, restore name %s",
			string(restore.UID), restore.Name)
	}

	return &result, nil
}

func getDataDownload(
	ctx context.Context,
	namespace string,
	operationID string,
	crClient crclient.Client,
) (*velerov2alpha1.DataDownload, error) {
	dataDownloadList := new(velerov2alpha1.DataDownloadList)
	err := crClient.List(ctx, dataDownloadList, &crclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			velerov1api.AsyncOperationIDLabel: operationID,
		}),
		Namespace: namespace,
	})
	if err != nil {
		return nil, errors.Wrap(err, "fail to list DataDownload")
	}

	if len(dataDownloadList.Items) == 0 {
		return nil, errors.Errorf("didn't find DataDownload")
	}

	if len(dataDownloadList.Items) > 1 {
		return nil, errors.Errorf("find multiple DataDownloads")
	}

	return &dataDownloadList.Items[0], nil
}

func cancelDataDownload(ctx context.Context, crClient crclient.Client,
	dataDownload *velerov2alpha1.DataDownload) error {
	updatedDataDownload := dataDownload.DeepCopy()
	updatedDataDownload.Spec.Cancel = true

	return crClient.Patch(ctx, updatedDataDownload, crclient.MergeFrom(dataDownload))
}

func newDataDownload(
	restore *velerov1api.Restore,
	backup *velerov1api.Backup,
	dataUploadResult *velerov2alpha1.DataUploadResult,
	pvc *corev1api.PersistentVolumeClaim,
	pv *corev1api.PersistentVolume,
	newNamespace, operationID string,
) *velerov2alpha1.DataDownload {
	pvName := ""
	if pv != nil {
		pvName = pv.Name
	}
	dataDownload := &velerov2alpha1.DataDownload{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
			Kind:       "DataDownload",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    restore.Namespace,
			GenerateName: restore.Name + "-",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: velerov1api.SchemeGroupVersion.String(),
					Kind:       "Restore",
					Name:       restore.Name,
					UID:        restore.UID,
					Controller: boolptr.True(),
				},
			},
			Labels: map[string]string{
				velerov1api.RestoreNameLabel:      label.GetValidName(restore.Name),
				velerov1api.RestoreUIDLabel:       string(restore.UID),
				velerov1api.AsyncOperationIDLabel: operationID,
			},
		},
		Spec: velerov2alpha1.DataDownloadSpec{
			TargetVolume: velerov2alpha1.TargetVolumeSpec{
				PVC:       pvc.Name,
				PV:        pvName,
				Namespace: newNamespace,
				FSType:    dataUploadResult.FSType,
			},
			BackupStorageLocation: dataUploadResult.BackupStorageLocation,
			DataMover:             dataUploadResult.DataMover,
			SnapshotID:            dataUploadResult.SnapshotID,
			SnapshotSize:          dataUploadResult.SnapshotSize,
			SourceNamespace:       dataUploadResult.SourceNamespace,
			OperationTimeout:      backup.Spec.CSISnapshotTimeout,
			NodeOS:                dataUploadResult.NodeOS,
		},
	}
	if restore.Spec.UploaderConfig != nil {
		dataDownload.Spec.DataMoverConfig = uploaderUtil.StoreRestoreConfig(restore.Spec.UploaderConfig)
	}
	if restore.IsVolumeDataInplaceRestore() {
		dataDownload.Spec.RestoreType = string(restore.Spec.ExistingVolumeDataPolicy)
	}
	return dataDownload
}

func restoreFromDataUploadResult(
	ctx context.Context,
	restore *velerov1api.Restore,
	backup *velerov1api.Backup,
	pvc *corev1api.PersistentVolumeClaim,
	pv *corev1api.PersistentVolume,
	newNamespace, operationID string,
	crClient crclient.Client,
) (*velerov2alpha1.DataDownload, error) {
	dataUploadResult, err := getDataUploadResult(ctx, restore, pvc, crClient)
	if err != nil {
		return nil, errors.Wrapf(err, "fail get DataUploadResult for restore: %s",
			restore.Name)
	}
	pvc.Spec.VolumeName = ""
	if pvc.Spec.Selector == nil {
		pvc.Spec.Selector = &metav1.LabelSelector{}
	}
	if pvc.Spec.Selector.MatchLabels == nil {
		pvc.Spec.Selector.MatchLabels = make(map[string]string)
	}
	pvc.Spec.Selector.MatchLabels[velerov1api.DynamicPVRestoreLabel] = label.
		GetValidName(fmt.Sprintf("%s.%s.%s", newNamespace,
			pvc.Name, utilrand.String(GenerateNameRandomLength)))

	dataDownload := newDataDownload(
		restore,
		backup,
		dataUploadResult,
		pvc,
		pv,
		newNamespace,
		operationID,
	)
	err = crClient.Create(ctx, dataDownload)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create DataDownload")
	}

	return dataDownload, nil
}

func (p *pvcRestoreItemAction) isResourceExist(
	pvc *corev1api.PersistentVolumeClaim,
	restore velerov1api.Restore,
) (bool, *corev1api.PersistentVolumeClaim, error) {
	// get target namespace to restore into, if different from source namespace
	targetNamespace := pvc.Namespace
	if target, ok := restore.Spec.NamespaceMapping[pvc.Namespace]; ok {
		targetNamespace = target
	}

	tmpPVC := new(corev1api.PersistentVolumeClaim)
	err := p.crClient.Get(
		context.Background(),
		crclient.ObjectKey{
			Name:      pvc.Name,
			Namespace: targetNamespace,
		},
		tmpPVC,
	)
	if err == nil {
		return true, tmpPVC, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil, nil
	}
	return false, nil, errors.Wrapf(err, "fail to get PVC %s in namespace %s", pvc.Name, targetNamespace)
}

func (p *pvcRestoreItemAction) prepareForInplaceRestore(ctx context.Context, logger *logrus.Entry, targetPVC *corev1api.PersistentVolumeClaim, existingPVC *corev1api.PersistentVolumeClaim, operationTimeout time.Duration) (*corev1api.PersistentVolume, error) {
	if existingPVC.Status.Phase != corev1api.ClaimBound {
		return nil, errors.New("ExistingVolumeDataPolicy is in-place restore, but the existing PVC is not bound.")
	}

	// Capture the "selected-node" annotation from the existing PVC before it is deleted below,
	// and carry it on the target PVC via a Velero-internal carrier annotation. The restore
	// engine translates the carrier back to the Kubernetes "selected-node" annotation after
	// all RestoreItemActions have run, so the recreated target PVC keeps the same scheduling
	// constraint regardless of the order in which RestoreItemActions execute (the generic PVC
	// RIA unconditionally strips the Kubernetes annotation).
	selectedNode, exists := existingPVC.Annotations[kube.KubeAnnSelectedNode]
	if exists {
		logger.Infof("Carrying %q annotation with value %q for target PVC to keep the same selected node as the existing PVC", kube.KubeAnnSelectedNode, selectedNode)
		if targetPVC.Annotations == nil {
			targetPVC.Annotations = map[string]string{}
		}
		targetPVC.Annotations[velerov1api.InplaceRestoreSelectedNodeAnnotation] = selectedNode
	}

	var err error
	logger.Info("ExistingVolumeDataPolicy is in-place restore. Deleting the existing PVC but keep the PV...")
	pv := &corev1api.PersistentVolume{}
	if err = p.crClient.Get(context.Background(), crclient.ObjectKey{Name: existingPVC.Spec.VolumeName}, pv); err != nil {
		return nil, errors.Errorf("Fail to get PV %s: %s", existingPVC.Spec.VolumeName, err.Error())
	}

	// set reclaim policy to retain
	updatedPV, err := kube.SetPVReclaimPolicy(ctx, p.kubeClient.CoreV1(), pv, corev1api.PersistentVolumeReclaimRetain)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to set PV reclaim policy to retain for PV %s", pv.Name)
	}
	if updatedPV != nil {
		pv = updatedPV
	}

	if err = kube.EnsureDeletePVC(ctx, p.kubeClient.CoreV1(), existingPVC.Name, existingPVC.Namespace, operationTimeout); err != nil {
		return nil, errors.Wrapf(err, "fail to delete the existing PVC %s in namespace %s", existingPVC.Name, existingPVC.Namespace)
	}

	logger.Info("Existing PVC deleted")

	return pv, nil
}

func NewPvcRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}

		kubeClient, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		return &pvcRestoreItemAction{
			log:        logger,
			crClient:   crClient,
			kubeClient: kubeClient,
		}, nil
	}
}
