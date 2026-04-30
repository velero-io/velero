/*
Copyright 2018 the Velero contributors.

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

package v1

const (
	// BackupNameLabel is the label key used to identify a backup by name.
	BackupNameLabel = "velero.io/backup-name"

	// BackupUIDLabel is the label key used to identify a backup by uid.
	BackupUIDLabel = "velero.io/backup-uid"

	// RestoreNameLabel is the label key used to identify a restore by name.
	RestoreNameLabel = "velero.io/restore-name"

	// ScheduleNameLabel is the label key used to identify a schedule by name.
	ScheduleNameLabel = "velero.io/schedule-name"

	// RestoreUIDLabel is the label key used to identify a restore by uid.
	RestoreUIDLabel = "velero.io/restore-uid"

	// PodUIDLabel is the label key used to identify a pod by uid.
	PodUIDLabel = "velero.io/pod-uid"

	// PVCUIDLabel is the label key used to identify a PVC by uid.
	PVCUIDLabel = "velero.io/pvc-uid"

	// PodVolumeOperationTimeoutAnnotation is the annotation key used to apply
	// a backup/restore-specific timeout value for pod volume operations (i.e.
	// pod volume backups/restores).
	PodVolumeOperationTimeoutAnnotation = "velero.io/pod-volume-timeout"

	// StorageLocationLabel is the label key used to identify the storage
	// location of a backup.
	StorageLocationLabel = "velero.io/storage-location"

	// VolumeNamespaceLabel is the label key used to identify which
	// namespace a repository stores backups for.
	VolumeNamespaceLabel = "velero.io/volume-namespace"

	// RepositoryTypeLabel is the label key used to identify the type of a repository
	RepositoryTypeLabel = "velero.io/repository-type"

	// DataUploadLabel is the label key used to identify the dataupload for snapshot backup pod
	DataUploadLabel = "velero.io/data-upload"

	// DataUploadSnapshotInfoLabel is used to identify the configmap that contains the snapshot info of a data upload
	// normally the value of the label should the "true" or "false"
	DataUploadSnapshotInfoLabel = "velero.io/data-upload-snapshot-info"

	// DataDownloadLabel is the label key used to identify the datadownload for snapshot restore pod
	DataDownloadLabel = "velero.io/data-download"

	// SourceClusterK8sVersionAnnotation is the label key used to identify the k8s
	// git version of the backup , i.e. v1.16.4
	SourceClusterK8sGitVersionAnnotation = "velero.io/source-cluster-k8s-gitversion"

	// SourceClusterK8sMajorVersionAnnotation is the label key used to identify the k8s
	// major version of the backup , i.e. 1
	SourceClusterK8sMajorVersionAnnotation = "velero.io/source-cluster-k8s-major-version"

	// SourceClusterK8sMajorVersionAnnotation is the label key used to identify the k8s
	// minor version of the backup , i.e. 16
	SourceClusterK8sMinorVersionAnnotation = "velero.io/source-cluster-k8s-minor-version"

	// ResourceTimeoutAnnotation is the annotation key used to carry the global resource
	// timeout value for backup to plugins.
	ResourceTimeoutAnnotation = "velero.io/resource-timeout"

	// AsyncOperationIDLabel is the label key used to identify the async operation ID
	AsyncOperationIDLabel = "velero.io/async-operation-id"

	// PVCNameLabel is the label key used to identify the PVC's namespace and name.
	// The format is <namespace>/<name>.
	PVCNamespaceNameLabel = "velero.io/pvc-namespace-name"

	// ResourceUsageLabel is the label key to explain the Velero resource usage.
	ResourceUsageLabel = "velero.io/resource-usage"

	// VolumesToBackupAnnotation is the annotation on a pod whose mounted volumes
	// need to be backed up using pod volume backup.
	VolumesToBackupAnnotation = "backup.velero.io/backup-volumes"

	// VolumesToExcludeAnnotation is the annotation on a pod whose mounted volumes
	// should be excluded from pod volume backup.
	VolumesToExcludeAnnotation = "backup.velero.io/backup-volumes-excludes"

	// ExcludeFromBackupLabel is the label to exclude k8s resource from backup,
	// even if the resource contains a matching selector label.
	ExcludeFromBackupLabel = "velero.io/exclude-from-backup"

	// SkipFromBackupAnnotation is the annotation used by internal BackupItemActions
	// to indicate that a resource should be skipped from backup,
	// even if it doesn't have the ExcludeFromBackupLabel.
	// This is used in cases where we want to skip backup of a resource based on some logic in a plugin.
	//
	// Notice: SkipFromBackupAnnotation's priority is higher than MustIncludeAdditionalItemAnnotation.
	// If SkipFromBackupAnnotation is set, the resource will be skipped even if MustIncludeAdditionalItemAnnotation is set.
	SkipFromBackupAnnotation = "velero.io/skip-from-backup"

	// defaultVGSLabelKey is the default label key used to group PVCs under a VolumeGroupSnapshot
	DefaultVGSLabelKey = "velero.io/volume-group"

	// PVBLabel is the label key used to identify the pvb for pvb pod
	PVBLabel = "velero.io/pod-volume-backup"

	// PVRLabel is the label key used to identify the pvb for pvr pod
	PVRLabel = "velero.io/pod-volume-restore"
)

type AsyncOperationIDPrefix string

const (
	AsyncOperationIDPrefixDataDownload AsyncOperationIDPrefix = "dd-"
	AsyncOperationIDPrefixDataUpload   AsyncOperationIDPrefix = "du-"
)

type VeleroResourceUsage string

const (
	VeleroResourceUsageDataUploadResult VeleroResourceUsage = "DataUpload"
)

// CSI related plugin actions' constant variable
const (
	VolumeSnapshotLabel                             = "velero.io/volume-snapshot-name"
	VolumeSnapshotHandleAnnotation                  = "velero.io/csi-volumesnapshot-handle"
	VolumeSnapshotRestoreSize                       = "velero.io/csi-volumesnapshot-restore-size"
	DriverNameAnnotation                            = "velero.io/csi-driver-name"
	VSCDeletionPolicyAnnotation                     = "velero.io/csi-vsc-deletion-policy"
	VolumeGroupSnapshotHandleAnnotation             = "velero.io/csi-volumegroupsnapshot-handle"
	VolumeSnapshotClassSelectorLabel                = "velero.io/csi-volumesnapshot-class"
	VolumeSnapshotClassDriverBackupAnnotationPrefix = "velero.io/csi-volumesnapshot-class"
	VolumeSnapshotClassDriverPVCAnnotation          = "velero.io/csi-volumesnapshot-class"
	VolumeSnapshotClassDriverStorageClassAnnotation = "velero.io/csi-volumesnapshot-class"

	// https://kubernetes.io/zh-cn/docs/concepts/storage/volume-snapshot-classes/
	VolumeSnapshotClassKubernetesAnnotation = "snapshot.storage.kubernetes.io/is-default-class"

	// There is no release w/ these constants exported. Using the strings for now.
	// CSI Annotation volumesnapshotclass
	// https://github.com/kubernetes-csi/external-snapshotter/blob/master/pkg/utils/util.go#L59-L60
	PrefixedListSecretNameAnnotation      = "csi.storage.k8s.io/snapshotter-list-secret-name"      // #nosec G101
	PrefixedListSecretNamespaceAnnotation = "csi.storage.k8s.io/snapshotter-list-secret-namespace" // #nosec G101

	// CSI Annotation volumesnapshotcontents
	PrefixedSecretNameAnnotation      = "csi.storage.k8s.io/snapshotter-secret-name"      // #nosec G101
	PrefixedSecretNamespaceAnnotation = "csi.storage.k8s.io/snapshotter-secret-namespace" // #nosec G101

	// Velero checks this annotation to determine whether to skip resource excluding check.
	MustIncludeAdditionalItemAnnotation = "backup.velero.io/must-include-additional-items"
	// SkippedNoCSIPVAnnotation - Velero checks this annotation on processed PVC to
	// find out if the snapshot was skipped b/c the PV is not provisioned via CSI
	SkippedNoCSIPVAnnotation = "backup.velero.io/skipped-no-csi-pv"

	// DynamicPVRestoreLabel is the label key for dynamic PV restore
	DynamicPVRestoreLabel = "velero.io/dynamic-pv-restore"

	// DataUploadNameAnnotation is the label key for the DataUpload name
	DataUploadNameAnnotation = "velero.io/data-upload-name"

	// Label used on VolumeGroupSnapshotClass to mark it as Velero's default for a CSI driver
	VolumeGroupSnapshotClassDefaultLabel = "velero.io/csi-volumegroupsnapshot-class"

	// Annotation on PVC to override the VGS class to use
	VolumeGroupSnapshotClassAnnotationPVC = "velero.io/csi-volume-group-snapshot-class"

	// Annotation prefix on Backup to override VGS class per CSI driver
	VolumeGroupSnapshotClassAnnotationBackupPrefix = "velero.io/csi-volumegroupsnapshot-class_"
)
