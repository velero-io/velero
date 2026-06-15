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

package volume

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/label"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
)

type Method string

const (
	NativeSnapshot   Method = "NativeSnapshot"
	PodVolumeBackup  Method = "PodVolumeBackup"
	CSISnapshot      Method = "CSISnapshot"
	PodVolumeRestore Method = "PodVolumeRestore"
)

const (
	FieldValueIsUnknown string = "unknown"
	veleroDatamover     string = "velero"
)

type BackupVolumeInfo struct {
	// The PVC's name.
	PVCName string `json:"pvcName,omitempty"`

	// The PVC's namespace
	PVCNamespace string `json:"pvcNamespace,omitempty"`

	// The PV name.
	PVName string `json:"pvName,omitempty"`

	// The way the volume data is backed up. The valid value includes `VeleroNativeSnapshot`, `PodVolumeBackup` and `CSISnapshot`.
	BackupMethod Method `json:"backupMethod,omitempty"`

	// Whether the volume's snapshot data is moved to specified storage.
	SnapshotDataMoved bool `json:"snapshotDataMoved"`

	// Whether the local snapshot is preserved after snapshot is moved.
	// The local snapshot may be a result of CSI snapshot backup(no data movement)
	// or a CSI snapshot data movement plus preserve local snapshot.
	PreserveLocalSnapshot bool `json:"preserveLocalSnapshot"`

	// Whether the Volume is skipped in this backup.
	Skipped bool `json:"skipped"`

	// The reason for the volume is skipped in the backup.
	SkippedReason string `json:"skippedReason,omitempty"`

	// Snapshot starts timestamp.
	StartTimestamp *metav1.Time `json:"startTimestamp,omitempty"`

	// Snapshot completes timestamp.
	CompletionTimestamp *metav1.Time `json:"completionTimestamp,omitempty"`

	// Whether the volume data is backed up successfully.
	Result VolumeResult `json:"result,omitempty"`

	CSISnapshotInfo          *CSISnapshotInfo          `json:"csiSnapshotInfo,omitempty"`
	SnapshotDataMovementInfo *SnapshotDataMovementInfo `json:"snapshotDataMovementInfo,omitempty"`
	NativeSnapshotInfo       *NativeSnapshotInfo       `json:"nativeSnapshotInfo,omitempty"`
	PVBInfo                  *PodVolumeInfo            `json:"pvbInfo,omitempty"`
	PVInfo                   *PVInfo                   `json:"pvInfo,omitempty"`
}

type VolumeResult string

const (
	VolumeResultSucceeded VolumeResult = "succeeded"
	VolumeResultFailed    VolumeResult = "failed"
	//VolumeResultCanceled  VolumeResult = "canceled"
)

type RestoreVolumeInfo struct {
	// The name of the restored PVC
	PVCName string `json:"pvcName,omitempty"`

	// The namespace of the restored PVC
	PVCNamespace string `json:"pvcNamespace,omitempty"`

	// The name of the restored PV, it is possible that in one item there is only PVC or PV info.
	// But if both PVC and PV exist in one item of volume info, they should matched, and if the PV is bound to a PVC,
	// they should coexist in one item.
	PVName string `json:"pvName,omitempty"`

	// The way the volume data is restored.
	RestoreMethod Method `json:"restoreMethod,omitempty"`

	// Whether the volume's data are restored via data movement
	SnapshotDataMoved bool `json:"snapshotDataMoved"`

	CSISnapshotInfo          *CSISnapshotInfo          `json:"csiSnapshotInfo,omitempty"`
	SnapshotDataMovementInfo *SnapshotDataMovementInfo `json:"snapshotDataMovementInfo,omitempty"`
	NativeSnapshotInfo       *NativeSnapshotInfo       `json:"nativeSnapshotInfo,omitempty"`
	PVRInfo                  *PodVolumeInfo            `json:"pvrInfo,omitempty"`
}

// CSISnapshotInfo is used for displaying the CSI snapshot status
type CSISnapshotInfo struct {
	// It's the storage provider's snapshot ID for CSI.
	SnapshotHandle string `json:"snapshotHandle"`

	// The snapshot corresponding volume size.
	Size int64 `json:"size"`

	// The name of the CSI driver.
	Driver string `json:"driver"`

	// The name of the VolumeSnapshotContent.
	VSCName string `json:"vscName"`

	// The Async Operation's ID.
	OperationID string `json:"operationID,omitempty"`

	// The VolumeSnapshot's Status.ReadyToUse value
	ReadyToUse *bool

	// The VolumeGroupSnapshotHandle from VSC status, used to create stub VGSC during restore
	// for CSI drivers that populate this field (e.g., Ceph RBD).
	VolumeGroupSnapshotHandle string `json:"volumeGroupSnapshotHandle,omitempty"`
}

// SnapshotDataMovementInfo is used for displaying the snapshot data mover status.
type SnapshotDataMovementInfo struct {
	// The data mover used by the backup. The valid values are `velero` and ``(equals to `velero`).
	DataMover string `json:"dataMover"`

	// The type of the uploader that uploads the snapshot data. The valid values are `kopia` and `restic`.
	UploaderType string `json:"uploaderType"`

	// The name or ID of the snapshot associated object(SAO).
	// SAO is used to support local snapshots for the snapshot data mover,
	// e.g. it could be a VolumeSnapshot for CSI snapshot data movement.
	RetainedSnapshot string `json:"retainedSnapshot,omitempty"`

	// It's the filesystem repository's snapshot ID.
	SnapshotHandle string `json:"snapshotHandle"`

	// The Async Operation's ID.
	OperationID string `json:"operationID"`

	// Moved snapshot data size.
	Size int64 `json:"size"`

	// Moved snapshot incremental size.
	IncrementalSize int64 `json:"incrementalSize,omitempty"`

	// The DataUpload's Status.Phase value
	Phase velerov2alpha1.DataUploadPhase
}

// NativeSnapshotInfo is used for displaying the Velero native snapshot status.
// A Velero Native Snapshot is a cloud storage snapshot taken by the Velero native
// plugins, e.g. velero-plugin-for-aws, velero-plugin-for-gcp, and
// velero-plugin-for-microsoft-azure.
type NativeSnapshotInfo struct {
	// It's the storage provider's snapshot ID for the Velero-native snapshot.
	SnapshotHandle string `json:"snapshotHandle"`

	// The cloud provider snapshot volume type.
	VolumeType string `json:"volumeType"`

	// The cloud provider snapshot volume's availability zones.
	VolumeAZ string `json:"volumeAZ"`

	// The cloud provider snapshot volume's IOPS.
	IOPS string `json:"iops"`

	// The NativeSnapshot's Status.Phase value
	Phase SnapshotPhase
}

func newNativeSnapshotInfo(s *Snapshot) *NativeSnapshotInfo {
	var iops int64
	if s.Spec.VolumeIOPS != nil {
		iops = *s.Spec.VolumeIOPS
	}
	return &NativeSnapshotInfo{
		SnapshotHandle: s.Status.ProviderSnapshotID,
		VolumeType:     s.Spec.VolumeType,
		VolumeAZ:       s.Spec.VolumeAZ,
		IOPS:           strconv.FormatInt(iops, 10),
		Phase:          s.Status.Phase,
	}
}

// PodVolumeInfo is used for displaying the PodVolumeBackup/PodVolumeRestore snapshot status.
type PodVolumeInfo struct {
	// It's the file-system uploader's snapshot ID for PodVolumeBackup/PodVolumeRestore.
	SnapshotHandle string `json:"snapshotHandle,omitempty"`

	// The snapshot corresponding volume size.
	Size int64 `json:"size,omitempty"`

	// The incremental snapshot size.
	IncrementalSize int64 `json:"incrementalSize,omitempty"`

	// The type of the uploader that uploads the data. The valid values are `kopia` and `restic`.
	UploaderType string `json:"uploaderType"`

	// The PVC's corresponding volume name used by Pod
	// https://github.com/kubernetes/kubernetes/blob/e4b74dd12fa8cb63c174091d5536a10b8ec19d34/pkg/apis/core/types.go#L48
	VolumeName string `json:"volumeName"`

	// The Pod name mounting this PVC.
	PodName string `json:"podName"`

	// The Pod namespace
	PodNamespace string `json:"podNamespace"`

	// The PVB-taken k8s node's name.
	// This field will be empty when the struct is used to represent a podvolumerestore.
	NodeName string `json:"nodeName,omitempty"`

	// The PVB's Status.Phase value
	Phase velerov1api.PodVolumeBackupPhase
}

func newPodVolumeInfoFromPVB(pvb *velerov1api.PodVolumeBackup) *PodVolumeInfo {
	return &PodVolumeInfo{
		SnapshotHandle:  pvb.Status.SnapshotID,
		Size:            pvb.Status.Progress.TotalBytes,
		IncrementalSize: pvb.Status.IncrementalBytes,
		UploaderType:    pvb.Spec.UploaderType,
		VolumeName:      pvb.Spec.Volume,
		PodName:         pvb.Spec.Pod.Name,
		PodNamespace:    pvb.Spec.Pod.Namespace,
		NodeName:        pvb.Spec.Node,
		Phase:           pvb.Status.Phase,
	}
}

func newPodVolumeInfoFromPVR(pvr *velerov1api.PodVolumeRestore) *PodVolumeInfo {
	return &PodVolumeInfo{
		SnapshotHandle: pvr.Spec.SnapshotID,
		Size:           pvr.Status.Progress.TotalBytes,
		UploaderType:   pvr.Spec.UploaderType,
		VolumeName:     pvr.Spec.Volume,
		PodName:        pvr.Spec.Pod.Name,
		PodNamespace:   pvr.Spec.Pod.Namespace,
	}
}

// PVInfo is used to store some PV information modified after creation.
// Those information are lost after PV recreation.
type PVInfo struct {
	// ReclaimPolicy of PV. It could be different from the referenced StorageClass.
	ReclaimPolicy string `json:"reclaimPolicy"`

	// The PV's labels should be kept after recreation.
	Labels map[string]string `json:"labels"`
}

// BackupVolumesInformation contains the information needs by generating
// the backup BackupVolumeInfo array.
type BackupVolumesInformation struct {
	// A map contains the backup-included PV detail content. The key is PV name.
	pvMap       *pvcPvMap
	volumeInfos []*BackupVolumeInfo

	logger                 logrus.FieldLogger
	crClient               kbclient.Client
	volumeSnapshots        []snapshotv1api.VolumeSnapshot
	volumeSnapshotContents []snapshotv1api.VolumeSnapshotContent
	volumeSnapshotClasses  []snapshotv1api.VolumeSnapshotClass
	SkippedPVs             map[string]string
	NativeSnapshots        []*Snapshot
	PodVolumeBackups       []*velerov1api.PodVolumeBackup
	BackupOperations       []*itemoperation.BackupOperation
	BackupName             string
}

type pvcPvInfo struct {
	PVCName      string
	PVCNamespace string
	PV           corev1api.PersistentVolume
}

func (v *BackupVolumesInformation) Init() {
	v.pvMap = &pvcPvMap{
		data: make(map[string]pvcPvInfo),
	}
	v.volumeInfos = make([]*BackupVolumeInfo, 0)
}

func (v *BackupVolumesInformation) InsertPVMap(pv corev1api.PersistentVolume, pvcName, pvcNamespace string) {
	if v.pvMap == nil {
		v.Init()
	}
	v.pvMap.insert(pv, pvcName, pvcNamespace)
}

func (v *BackupVolumesInformation) Result(
	csiVolumeSnapshots []snapshotv1api.VolumeSnapshot,
	csiVolumeSnapshotContents []snapshotv1api.VolumeSnapshotContent,
	csiVolumesnapshotClasses []snapshotv1api.VolumeSnapshotClass,
	crClient kbclient.Client,
	logger logrus.FieldLogger,
) []*BackupVolumeInfo {
	v.logger = logger
	v.crClient = crClient
	v.volumeSnapshots = csiVolumeSnapshots
	v.volumeSnapshotContents = csiVolumeSnapshotContents
	v.volumeSnapshotClasses = csiVolumesnapshotClasses

	v.generateVolumeInfoForSkippedPV()
	v.generateVolumeInfoForVeleroNativeSnapshot()
	v.generateVolumeInfoForCSIVolumeSnapshot()
	v.generateVolumeInfoFromPVB()
	v.generateVolumeInfoFromDataUpload()

	return v.volumeInfos
}

// generateVolumeInfoForSkippedPV generate VolumeInfos for SkippedPV.
func (v *BackupVolumesInformation) generateVolumeInfoForSkippedPV() {
	tmpVolumeInfos := make([]*BackupVolumeInfo, 0)

	for pvName, skippedReason := range v.SkippedPVs {
		if pvcPVInfo := v.pvMap.retrieve(pvName, "", ""); pvcPVInfo != nil {
			volumeInfo := &BackupVolumeInfo{
				PVCName:           pvcPVInfo.PVCName,
				PVCNamespace:      pvcPVInfo.PVCNamespace,
				PVName:            pvName,
				SnapshotDataMoved: false,
				Skipped:           true,
				SkippedReason:     skippedReason,
				PVInfo: &PVInfo{
					ReclaimPolicy: string(pvcPVInfo.PV.Spec.PersistentVolumeReclaimPolicy),
					Labels:        pvcPVInfo.PV.Labels,
				},
			}
			tmpVolumeInfos = append(tmpVolumeInfos, volumeInfo)
		} else {
			v.logger.Warnf("Cannot find info for PV %s", pvName)
			continue
		}
	}

	v.volumeInfos = append(v.volumeInfos, tmpVolumeInfos...)
}

// generateVolumeInfoForVeleroNativeSnapshot generate VolumeInfos for Velero native snapshot
func (v *BackupVolumesInformation) generateVolumeInfoForVeleroNativeSnapshot() {
	tmpVolumeInfos := make([]*BackupVolumeInfo, 0)

	for _, nativeSnapshot := range v.NativeSnapshots {
		if pvcPVInfo := v.pvMap.retrieve(nativeSnapshot.Spec.PersistentVolumeName, "", ""); pvcPVInfo != nil {
			volumeResult := VolumeResultFailed
			if nativeSnapshot.Status.Phase == SnapshotPhaseCompleted {
				volumeResult = VolumeResultSucceeded
			}
			volumeInfo := &BackupVolumeInfo{
				BackupMethod:      NativeSnapshot,
				PVCName:           pvcPVInfo.PVCName,
				PVCNamespace:      pvcPVInfo.PVCNamespace,
				PVName:            pvcPVInfo.PV.Name,
				SnapshotDataMoved: false,
				Skipped:           false,
				// Only set Succeeded to true when the NativeSnapshot's phase is Completed,
				// although NativeSnapshot doesn't check whether the snapshot creation result.
				Result:             volumeResult,
				NativeSnapshotInfo: newNativeSnapshotInfo(nativeSnapshot),
				PVInfo: &PVInfo{
					ReclaimPolicy: string(pvcPVInfo.PV.Spec.PersistentVolumeReclaimPolicy),
					Labels:        pvcPVInfo.PV.Labels,
				},
			}
			tmpVolumeInfos = append(tmpVolumeInfos, volumeInfo)
		} else {
			v.logger.Warnf("cannot find info for PV %s", nativeSnapshot.Spec.PersistentVolumeName)
			continue
		}
	}

	v.volumeInfos = append(v.volumeInfos, tmpVolumeInfos...)
}

// generateVolumeInfoForCSIVolumeSnapshot generate VolumeInfos for CSI VolumeSnapshot
func (v *BackupVolumesInformation) generateVolumeInfoForCSIVolumeSnapshot() {
	tmpVolumeInfos := make([]*BackupVolumeInfo, 0)

	for _, volumeSnapshot := range v.volumeSnapshots {
		var volumeSnapshotContent *snapshotv1api.VolumeSnapshotContent

		// This is protective logic. The passed-in VS should be all related
		// to this backup.
		if volumeSnapshot.Labels[velerov1api.BackupNameLabel] != v.BackupName {
			continue
		}

		if volumeSnapshot.Status == nil || volumeSnapshot.Status.BoundVolumeSnapshotContentName == nil {
			v.logger.Warnf("Cannot fine VolumeSnapshotContent for VolumeSnapshot %s/%s", volumeSnapshot.Namespace, volumeSnapshot.Name)
			continue
		}

		if volumeSnapshot.Spec.Source.PersistentVolumeClaimName == nil {
			v.logger.Warnf("VolumeSnapshot %s/%s doesn't have a source PVC", volumeSnapshot.Namespace, volumeSnapshot.Name)
			continue
		}

		for index := range v.volumeSnapshotContents {
			if *volumeSnapshot.Status.BoundVolumeSnapshotContentName == v.volumeSnapshotContents[index].Name {
				volumeSnapshotContent = &v.volumeSnapshotContents[index]
			}
		}

		if volumeSnapshotContent == nil {
			v.logger.Warnf("fail to get VolumeSnapshotContent for VolumeSnapshot: %s/%s",
				volumeSnapshot.Namespace, volumeSnapshot.Name)
			continue
		}

		var operation itemoperation.BackupOperation
		for _, op := range v.BackupOperations {
			if op.Spec.ResourceIdentifier.GroupResource.String() == kuberesource.VolumeSnapshots.String() &&
				op.Spec.ResourceIdentifier.Name == volumeSnapshot.Name &&
				op.Spec.ResourceIdentifier.Namespace == volumeSnapshot.Namespace {
				operation = *op
			}
		}

		var size int64
		if volumeSnapshot.Status.RestoreSize != nil {
			size = volumeSnapshot.Status.RestoreSize.Value()
		}
		snapshotHandle := ""
		if volumeSnapshotContent.Status.SnapshotHandle != nil {
			snapshotHandle = *volumeSnapshotContent.Status.SnapshotHandle
		}
		volumeGroupSnapshotHandle := ""
		if volumeSnapshotContent.Status != nil && volumeSnapshotContent.Status.VolumeGroupSnapshotHandle != nil {
			volumeGroupSnapshotHandle = *volumeSnapshotContent.Status.VolumeGroupSnapshotHandle
		}
		if pvcPVInfo := v.pvMap.retrieve("", *volumeSnapshot.Spec.Source.PersistentVolumeClaimName, volumeSnapshot.Namespace); pvcPVInfo != nil {
			volumeInfo := &BackupVolumeInfo{
				BackupMethod:          CSISnapshot,
				PVCName:               pvcPVInfo.PVCName,
				PVCNamespace:          pvcPVInfo.PVCNamespace,
				PVName:                pvcPVInfo.PV.Name,
				Skipped:               false,
				SnapshotDataMoved:     false,
				PreserveLocalSnapshot: true,
				CSISnapshotInfo: &CSISnapshotInfo{
					VSCName:                   *volumeSnapshot.Status.BoundVolumeSnapshotContentName,
					Size:                      size,
					Driver:                    volumeSnapshotContent.Spec.Driver,
					SnapshotHandle:            snapshotHandle,
					OperationID:               operation.Spec.OperationID,
					ReadyToUse:                volumeSnapshot.Status.ReadyToUse,
					VolumeGroupSnapshotHandle: volumeGroupSnapshotHandle,
				},
				PVInfo: &PVInfo{
					ReclaimPolicy: string(pvcPVInfo.PV.Spec.PersistentVolumeReclaimPolicy),
					Labels:        pvcPVInfo.PV.Labels,
				},
			}

			if volumeSnapshot.Status.CreationTime != nil {
				volumeInfo.StartTimestamp = volumeSnapshot.Status.CreationTime
			}

			tmpVolumeInfos = append(tmpVolumeInfos, volumeInfo)
		} else {
			v.logger.Warnf("cannot find info for PVC %s/%s", volumeSnapshot.Namespace, volumeSnapshot.Spec.Source.PersistentVolumeClaimName)
			continue
		}
	}

	v.volumeInfos = append(v.volumeInfos, tmpVolumeInfos...)
}

// generateVolumeInfoFromPVB generate BackupVolumeInfo for PVB.
func (v *BackupVolumesInformation) generateVolumeInfoFromPVB() {
	tmpVolumeInfos := make([]*BackupVolumeInfo, 0)
	for _, pvb := range v.PodVolumeBackups {
		volumeInfo := &BackupVolumeInfo{
			BackupMethod:        PodVolumeBackup,
			SnapshotDataMoved:   false,
			Skipped:             false,
			StartTimestamp:      pvb.Status.StartTimestamp,
			CompletionTimestamp: pvb.Status.CompletionTimestamp,
			PVBInfo:             newPodVolumeInfoFromPVB(pvb),
		}

		// Only set Succeeded to true when the PVB's phase is Completed.
		if pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseCompleted {
			volumeInfo.Result = VolumeResultSucceeded
		} else {
			volumeInfo.Result = VolumeResultFailed
		}

		pvcName, err := pvcByPodvolume(context.TODO(), v.crClient, pvb.Spec.Pod.Name, pvb.Spec.Pod.Namespace, pvb.Spec.Volume)
		if err != nil {
			v.logger.WithError(err).Warn("Fail to get PVC from PodVolumeBackup: ", pvb.Name)
			continue
		}
		if pvcName != "" {
			if pvcPVInfo := v.pvMap.retrieve("", pvcName, pvb.Spec.Pod.Namespace); pvcPVInfo != nil {
				volumeInfo.PVCName = pvcPVInfo.PVCName
				volumeInfo.PVCNamespace = pvcPVInfo.PVCNamespace
				volumeInfo.PVName = pvcPVInfo.PV.Name
				volumeInfo.PVInfo = &PVInfo{
					ReclaimPolicy: string(pvcPVInfo.PV.Spec.PersistentVolumeReclaimPolicy),
					Labels:        pvcPVInfo.PV.Labels,
				}
			} else {
				v.logger.Warnf("Cannot find info for PVC %s/%s", pvb.Spec.Pod.Namespace, pvcName)
				continue
			}
		} else {
			v.logger.Debug("The PVB %s doesn't have a corresponding PVC", pvb.Name)
		}
		tmpVolumeInfos = append(tmpVolumeInfos, volumeInfo)
	}
	v.volumeInfos = append(v.volumeInfos, tmpVolumeInfos...)
}

func (v *BackupVolumesInformation) getVolumeSnapshotClasses() (
	[]snapshotv1api.VolumeSnapshotClass,
	error,
) {
	vsClassList := new(snapshotv1api.VolumeSnapshotClassList)
	if err := v.crClient.List(context.TODO(), vsClassList); err != nil {
		v.logger.Warnf("Cannot list VolumeSnapshotClass with error %s.", err.Error())
		return nil, err
	}

	return vsClassList.Items, nil
}

// generateVolumeInfoFromDataUpload generate BackupVolumeInfo for DataUpload.
func (v *BackupVolumesInformation) generateVolumeInfoFromDataUpload() {
	if !features.IsEnabled(velerov1api.CSIFeatureFlag) {
		v.logger.Debug("Skip generating BackupVolumeInfo when the CSI feature is disabled.")
		return
	}

	// Retrieve the operations containing DataUpload.
	duOperationMap := make(map[kbclient.ObjectKey]*itemoperation.BackupOperation)
	for _, operation := range v.BackupOperations {
		if operation.Spec.ResourceIdentifier.GroupResource.String() == kuberesource.PersistentVolumeClaims.String() {
			for _, identifier := range operation.Spec.PostOperationItems {
				if identifier.GroupResource.String() == "datauploads.velero.io" {
					duOperationMap[kbclient.ObjectKey{
						Namespace: identifier.Namespace,
						Name:      identifier.Name,
					}] = operation

					break
				}
			}
		}
	}

	if len(duOperationMap) <= 0 {
		// No DataUpload is found. Return early.
		return
	}

	tmpVolumeInfos := make([]*BackupVolumeInfo, 0)
	for duObjectKey, operation := range duOperationMap {
		dataUpload := new(velerov2alpha1.DataUpload)
		err := v.crClient.Get(
			context.TODO(),
			duObjectKey,
			dataUpload,
		)
		if err != nil {
			v.logger.Warnf("Fail to get DataUpload %s: %s",
				duObjectKey.Namespace+"/"+duObjectKey.Name,
				err.Error(),
			)
			continue
		}

		if pvcPVInfo := v.pvMap.retrieve(
			"",
			operation.Spec.ResourceIdentifier.Name,
			operation.Spec.ResourceIdentifier.Namespace,
		); pvcPVInfo != nil {
			dataMover := veleroDatamover
			if dataUpload.Spec.DataMover != "" {
				dataMover = dataUpload.Spec.DataMover
			}

			volumeInfo := &BackupVolumeInfo{
				BackupMethod:      CSISnapshot,
				PVCName:           pvcPVInfo.PVCName,
				PVCNamespace:      pvcPVInfo.PVCNamespace,
				PVName:            pvcPVInfo.PV.Name,
				SnapshotDataMoved: true,
				Skipped:           false,
				CSISnapshotInfo: &CSISnapshotInfo{
					SnapshotHandle: FieldValueIsUnknown,
					VSCName:        FieldValueIsUnknown,
					OperationID:    FieldValueIsUnknown,
					Driver:         dataUpload.Spec.CSISnapshot.Driver,
				},
				SnapshotDataMovementInfo: &SnapshotDataMovementInfo{
					DataMover:    dataMover,
					UploaderType: velerov1api.BackupRepositoryTypeKopia,
					OperationID:  operation.Spec.OperationID,
					Phase:        dataUpload.Status.Phase,
				},
				PVInfo: &PVInfo{
					ReclaimPolicy: string(pvcPVInfo.PV.Spec.PersistentVolumeReclaimPolicy),
					Labels:        pvcPVInfo.PV.Labels,
				},
			}

			if dataUpload.Status.StartTimestamp != nil {
				volumeInfo.StartTimestamp = dataUpload.Status.StartTimestamp
			}

			tmpVolumeInfos = append(tmpVolumeInfos, volumeInfo)
		} else {
			v.logger.Warnf("Cannot find info for PVC %s/%s", operation.Spec.ResourceIdentifier.Namespace, operation.Spec.ResourceIdentifier.Name)
			continue
		}
	}

	v.volumeInfos = append(v.volumeInfos, tmpVolumeInfos...)
}

type pvcPvMap struct {
	data map[string]pvcPvInfo
}

func (m *pvcPvMap) insert(pv corev1api.PersistentVolume, pvcName, pvcNamespace string) {
	m.data[pv.Name] = pvcPvInfo{
		PVCName:      pvcName,
		PVCNamespace: pvcNamespace,
		PV:           pv,
	}
}

func (m *pvcPvMap) retrieve(pvName, pvcName, pvcNS string) *pvcPvInfo {
	if pvName != "" {
		if info, ok := m.data[pvName]; ok {
			return &info
		}
		return nil
	}

	if pvcNS == "" || pvcName == "" {
		return nil
	}

	for _, info := range m.data {
		if pvcNS == info.PVCNamespace && pvcName == info.PVCName {
			return &info
		}
	}

	return nil
}

func pvcByPodvolume(ctx context.Context, crClient kbclient.Client, podName, podNamespace, volumeName string) (string, error) {
	pod := new(corev1api.Pod)
	err := crClient.Get(ctx, kbclient.ObjectKey{Namespace: podNamespace, Name: podName}, pod)
	if err != nil {
		return "", errors.Wrap(err, "failed to get pod")
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == volumeName && volume.PersistentVolumeClaim != nil {
			return volume.PersistentVolumeClaim.ClaimName, nil
		}
	}
	return "", nil
}

// RestoreVolumeInfoTracker is used to track the volume information during restore.
// It is used to generate the RestoreVolumeInfo array.
type RestoreVolumeInfoTracker struct {
	*sync.Mutex
	restore *velerov1api.Restore
	log     logrus.FieldLogger
	client  kbclient.Client
	pvPvc   *pvcPvMap

	// map of PV name to the NativeSnapshotInfo from which the PV is restored
	pvNativeSnapshotMap map[string]*NativeSnapshotInfo
	// map of PVC object to the CSISnapshot object from which the PV is restored
	// the key is in the form of $pvc-ns/$pvc-name
	pvcCSISnapshotMap map[string]snapshotv1api.VolumeSnapshot
	datadownloadList  *velerov2alpha1.DataDownloadList
	pvrs              []*velerov1api.PodVolumeRestore
}

// Populate data objects in the tracker, which will be used to generate the RestoreVolumeInfo array in Result()
// The input param resourceList should be the final result of the restore.
func (t *RestoreVolumeInfoTracker) Populate(ctx context.Context, restoredResourceList map[string][]string) {
	pvcs := RestoredPVCFromRestoredResourceList(restoredResourceList)
	t.Lock()
	defer t.Unlock()
	for item := range pvcs {
		n := strings.Split(item, "/")
		pvcNS, pvcName := n[0], n[1]
		log := t.log.WithField("namespace", pvcNS).WithField("name", pvcName)
		pvc := &corev1api.PersistentVolumeClaim{}
		if err := t.client.Get(ctx, kbclient.ObjectKey{Namespace: pvcNS, Name: pvcName}, pvc); err != nil {
			log.WithError(err).Error("Failed to get PVC")
			continue
		}
		// Collect the CSI VolumeSnapshot objects referenced by the restored PVCs,
		if pvc.Spec.DataSource != nil && pvc.Spec.DataSource.Kind == "VolumeSnapshot" {
			vs := &snapshotv1api.VolumeSnapshot{}
			if err := t.client.Get(ctx, kbclient.ObjectKey{Namespace: pvcNS, Name: pvc.Spec.DataSource.Name}, vs); err != nil {
				log.WithError(err).Error("Failed to get VolumeSnapshot")
			} else {
				t.pvcCSISnapshotMap[pvc.Namespace+"/"+pvcName] = *vs
			}
		}
		if pvc.Status.Phase == corev1api.ClaimBound && pvc.Spec.VolumeName != "" {
			pv := &corev1api.PersistentVolume{}
			if err := t.client.Get(ctx, kbclient.ObjectKey{Name: pvc.Spec.VolumeName}, pv); err != nil {
				log.WithError(err).Error("Failed to get PV")
			} else {
				t.pvPvc.insert(*pv, pvcName, pvcNS)
			}
		} else {
			log.Warn("PVC is not bound or has no volume name")
			continue
		}
	}
	if err := t.client.List(ctx, t.datadownloadList, &kbclient.ListOptions{
		Namespace:     t.restore.Namespace,
		LabelSelector: label.NewSelectorForRestore(t.restore.Name),
	}); err != nil {
		t.log.WithError(err).Error("Failed to List DataDownloads")
	}
}

// Result generates the RestoreVolumeInfo array, the data should come from the Tracker itself and it should not connect tokkkk API
// server again.
func (t *RestoreVolumeInfoTracker) Result() []*RestoreVolumeInfo {
	volumeInfos := make([]*RestoreVolumeInfo, 0)

	// Generate RestoreVolumeInfo for PVRs
	for _, pvr := range t.pvrs {
		volumeInfo := &RestoreVolumeInfo{
			SnapshotDataMoved: false,
			PVRInfo:           newPodVolumeInfoFromPVR(pvr),
			RestoreMethod:     PodVolumeRestore,
		}
		pvcName, err := pvcByPodvolume(context.TODO(), t.client, pvr.Spec.Pod.Name, pvr.Spec.Pod.Namespace, pvr.Spec.Volume)
		if err != nil {
			t.log.WithError(err).Warn("Fail to get PVC from PodVolumeRestore: ", pvr.Name)
			continue
		}
		if pvcName != "" {
			volumeInfo.PVCName = pvcName
			volumeInfo.PVCNamespace = pvr.Spec.Pod.Namespace
			if pvcPVInfo := t.pvPvc.retrieve("", pvcName, pvr.Spec.Pod.Namespace); pvcPVInfo != nil {
				volumeInfo.PVName = pvcPVInfo.PV.Name
			}
		} else {
			// In this case, the volume is not bound to a PVC and
			// the PVR will not be able to populate into the volume, so we'll skip it
			t.log.Warnf("unable to get PVC for PodVolumeRestore %s/%s, pod: %s/%s, volume: %s",
				pvr.Namespace, pvr.Name, pvr.Spec.Pod.Namespace, pvr.Spec.Pod.Name, pvr.Spec.Volume)
			continue
		}
		volumeInfos = append(volumeInfos, volumeInfo)
	}

	// Generate RestoreVolumeInfo for PVs restored from NativeSnapshots
	for pvName, snapshotInfo := range t.pvNativeSnapshotMap {
		volumeInfo := &RestoreVolumeInfo{
			PVName:             pvName,
			SnapshotDataMoved:  false,
			NativeSnapshotInfo: snapshotInfo,
			RestoreMethod:      NativeSnapshot,
		}
		if pvcPVInfo := t.pvPvc.retrieve(pvName, "", ""); pvcPVInfo != nil {
			volumeInfo.PVCName = pvcPVInfo.PVCName
			volumeInfo.PVCNamespace = pvcPVInfo.PVCNamespace
		}
		volumeInfos = append(volumeInfos, volumeInfo)
	}

	// Generate RestoreVolumeInfo for PVs restored from CSISnapshots
	for pvc, csiSnapshot := range t.pvcCSISnapshotMap {
		n := strings.Split(pvc, "/")
		if len(n) != 2 {
			t.log.Warnf("Invalid PVC key '%s' in the pvc-CSISnapshot map, skip populating it to volume info", pvc)
			continue
		}
		pvcNS, pvcName := n[0], n[1]
		var restoreSize int64
		if csiSnapshot.Status != nil && csiSnapshot.Status.RestoreSize != nil {
			restoreSize = csiSnapshot.Status.RestoreSize.Value()
		}
		vscName := ""
		if csiSnapshot.Spec.Source.VolumeSnapshotContentName != nil {
			vscName = *csiSnapshot.Spec.Source.VolumeSnapshotContentName
		}

		volumeInfo := &RestoreVolumeInfo{
			PVCNamespace:      pvcNS,
			PVCName:           pvcName,
			SnapshotDataMoved: false,
			RestoreMethod:     CSISnapshot,
			CSISnapshotInfo: &CSISnapshotInfo{
				SnapshotHandle: csiSnapshot.Annotations[velerov1api.VolumeSnapshotHandleAnnotation],
				Size:           restoreSize,
				Driver:         csiSnapshot.Annotations[velerov1api.DriverNameAnnotation],
				VSCName:        vscName,
			},
		}
		if pvcPVInfo := t.pvPvc.retrieve("", pvcName, pvcNS); pvcPVInfo != nil {
			volumeInfo.PVName = pvcPVInfo.PV.Name
		}
		volumeInfos = append(volumeInfos, volumeInfo)
	}

	for _, dd := range t.datadownloadList.Items {
		var pvcName, pvcNS, pvName string
		if pvcPVInfo := t.pvPvc.retrieve(dd.Spec.TargetVolume.PV, dd.Spec.TargetVolume.PVC, dd.Spec.TargetVolume.Namespace); pvcPVInfo != nil {
			pvcName = pvcPVInfo.PVCName
			pvcNS = pvcPVInfo.PVCNamespace
			pvName = pvcPVInfo.PV.Name
		} else {
			pvcName = dd.Spec.TargetVolume.PVC
			pvName = dd.Spec.TargetVolume.PV
			pvcNS = dd.Spec.TargetVolume.Namespace
		}
		operationID := dd.Labels[velerov1api.AsyncOperationIDLabel]
		dataMover := veleroDatamover
		if dd.Spec.DataMover != "" {
			dataMover = dd.Spec.DataMover
		}
		volumeInfo := &RestoreVolumeInfo{
			PVName:            pvName,
			PVCNamespace:      pvcNS,
			PVCName:           pvcName,
			SnapshotDataMoved: true,
			// The method will be CSI always no CSI related CRs are created during restore, because
			// the datadownload was initiated in CSI plugin
			// For the same reason, no CSI snapshot info will be populated into volumeInfo
			RestoreMethod: CSISnapshot,
			SnapshotDataMovementInfo: &SnapshotDataMovementInfo{
				DataMover:      dataMover,
				UploaderType:   velerov1api.BackupRepositoryTypeKopia,
				SnapshotHandle: dd.Spec.SnapshotID,
				OperationID:    operationID,
			},
		}

		volumeInfos = append(volumeInfos, volumeInfo)
	}

	return volumeInfos
}

func NewRestoreVolInfoTracker(restore *velerov1api.Restore, logger logrus.FieldLogger, client kbclient.Client) *RestoreVolumeInfoTracker {
	return &RestoreVolumeInfoTracker{
		Mutex:   &sync.Mutex{},
		client:  client,
		log:     logger,
		restore: restore,
		pvPvc: &pvcPvMap{
			data: make(map[string]pvcPvInfo),
		},
		pvNativeSnapshotMap: make(map[string]*NativeSnapshotInfo),
		pvcCSISnapshotMap:   make(map[string]snapshotv1api.VolumeSnapshot),
		datadownloadList:    &velerov2alpha1.DataDownloadList{},
	}
}

func (t *RestoreVolumeInfoTracker) TrackNativeSnapshot(pvName string, snapshotHandle, volumeType, volumeAZ string, iops int64) {
	t.Lock()
	defer t.Unlock()
	t.pvNativeSnapshotMap[pvName] = &NativeSnapshotInfo{
		SnapshotHandle: snapshotHandle,
		VolumeType:     volumeType,
		VolumeAZ:       volumeAZ,
		IOPS:           strconv.FormatInt(iops, 10),
	}
}

func (t *RestoreVolumeInfoTracker) RenamePVForNativeSnapshot(oldName, newName string) {
	t.Lock()
	defer t.Unlock()
	if snapshotInfo, ok := t.pvNativeSnapshotMap[oldName]; ok {
		t.pvNativeSnapshotMap[newName] = snapshotInfo
		delete(t.pvNativeSnapshotMap, oldName)
	}
}

func (t *RestoreVolumeInfoTracker) TrackPodVolume(pvr *velerov1api.PodVolumeRestore) {
	t.Lock()
	defer t.Unlock()
	t.pvrs = append(t.pvrs, pvr)
}
