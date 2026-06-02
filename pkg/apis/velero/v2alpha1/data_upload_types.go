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

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
)

// DataUploadSpec is the specification for a DataUpload.
type DataUploadSpec struct {
	// SnapshotType is the type of the snapshot to be backed up.
	SnapshotType SnapshotType `json:"snapshotType"`

	// If SnapshotType is CSI, CSISnapshot provides the information of the CSI snapshot.
	// +optional
	// +nullable
	CSISnapshot *CSISnapshotSpec `json:"csiSnapshot"`

	// SourcePVC is the name of the PVC which the snapshot is taken for.
	SourcePVC string `json:"sourcePVC"`

	// DataMover specifies the data mover to be used by the backup.
	// If DataMover is "" or "velero", the built-in data mover will be used.
	// +optional
	DataMover string `json:"datamover,omitempty"`

	// BackupStorageLocation is the name of the backup storage location
	// where the backup repository is stored.
	BackupStorageLocation string `json:"backupStorageLocation"`

	// SourceNamespace is the original namespace where the volume is backed up from.
	// It is the same namespace for SourcePVC and CSI namespaced objects.
	SourceNamespace string `json:"sourceNamespace"`

	// DataMoverConfig is for data-mover-specific configuration fields.
	// +optional
	// +nullable
	DataMoverConfig map[string]string `json:"dataMoverConfig,omitempty"`

	// Cancel indicates request to cancel the ongoing DataUpload. It can be set
	// when the DataUpload is in InProgress phase
	Cancel bool `json:"cancel,omitempty"`

	// OperationTimeout specifies the time used to wait internal operations,
	// before returning error as timeout.
	OperationTimeout metav1.Duration `json:"operationTimeout"`

	// SnapshotErrorTimeout specifies how long to tolerate persistent errors reported
	// in the source CSI VolumeSnapshot status before failing the data upload, instead
	// of waiting the full OperationTimeout. A zero value disables the early failure.
	// +optional
	SnapshotErrorTimeout metav1.Duration `json:"snapshotErrorTimeout,omitempty"`
}

type SnapshotType string

const (
	SnapshotTypeCSI SnapshotType = "CSI"
)

// CSISnapshotSpec is the specification for a CSI snapshot.
type CSISnapshotSpec struct {
	// VolumeSnapshot is the name of the volume snapshot to be backed up
	VolumeSnapshot string `json:"volumeSnapshot"`

	// StorageClass is the name of the storage class of the PVC that the volume snapshot is created from
	StorageClass string `json:"storageClass"`

	// SnapshotClass is the name of the snapshot class that the volume snapshot is created with
	// +optional
	SnapshotClass string `json:"snapshotClass"`

	// Driver is the driver used by the VolumeSnapshotContent
	// +optional
	Driver string `json:"driver,omitempty"`
}

// DataUploadPhase represents the lifecycle phase of a DataUpload.
// +kubebuilder:validation:Enum=New;Accepted;Prepared;InProgress;Canceling;Canceled;Completed;Failed
type DataUploadPhase string

const (
	DataUploadPhaseNew        DataUploadPhase = "New"
	DataUploadPhaseAccepted   DataUploadPhase = "Accepted"
	DataUploadPhasePrepared   DataUploadPhase = "Prepared"
	DataUploadPhaseInProgress DataUploadPhase = "InProgress"
	DataUploadPhaseCanceling  DataUploadPhase = "Canceling"
	DataUploadPhaseCanceled   DataUploadPhase = "Canceled"
	DataUploadPhaseCompleted  DataUploadPhase = "Completed"
	DataUploadPhaseFailed     DataUploadPhase = "Failed"
)

// NodeOS represents OS of a node.
// +kubebuilder:validation:Enum=auto;linux;windows
type NodeOS string

const (
	NodeOSLinux   NodeOS = "linux"
	NodeOSWindows NodeOS = "windows"
	NodeOSAuto    NodeOS = "auto"
)

// DataUploadStatus is the current status of a DataUpload.
type DataUploadStatus struct {
	// Phase is the current state of the DataUpload.
	// +optional
	Phase DataUploadPhase `json:"phase,omitempty"`

	// Path is the full path of the snapshot volume being backed up.
	// +optional
	Path string `json:"path,omitempty"`

	// SnapshotID is the identifier for the snapshot in the backup repository.
	// +optional
	SnapshotID string `json:"snapshotID,omitempty"`

	// DataMoverResult stores data-mover-specific information as a result of the DataUpload.
	// +optional
	// +nullable
	DataMoverResult *map[string]string `json:"dataMoverResult,omitempty"`

	// Message is a message about the DataUpload's status.
	// +optional
	Message string `json:"message,omitempty"`

	// StartTimestamp records the time a backup was started.
	// Separate from CreationTimestamp, since that value changes
	// on restores.
	// The server's time is used for StartTimestamps
	// +optional
	// +nullable
	StartTimestamp *metav1.Time `json:"startTimestamp,omitempty"`

	// CompletionTimestamp records the time a backup was completed.
	// Completion time is recorded even on failed backups.
	// Completion time is recorded before uploading the backup object.
	// The server's time is used for CompletionTimestamps
	// +optional
	// +nullable
	CompletionTimestamp *metav1.Time `json:"completionTimestamp,omitempty"`

	// Progress holds the total number of bytes of the volume and the current
	// number of backed up bytes. This can be used to display progress information
	// about the backup operation.
	// +optional
	Progress shared.DataMoveOperationProgress `json:"progress,omitempty"`

	// IncrementalBytes holds the number of bytes new or changed since the last backup
	// +optional
	IncrementalBytes int64 `json:"incrementalBytes,omitempty"`

	// Node is name of the node where the DataUpload is processed.
	// +optional
	Node string `json:"node,omitempty"`

	// NodeOS is OS of the node where the DataUpload is processed.
	// +optional
	NodeOS NodeOS `json:"nodeOS,omitempty"`

	// AcceptedByNode is name of the node where the DataUpload is prepared.
	// +optional
	AcceptedByNode string `json:"acceptedByNode,omitempty"`

	// AcceptedTimestamp records the time the DataUpload is to be prepared.
	// The server's time is used for AcceptedTimestamp
	// +optional
	// +nullable
	AcceptedTimestamp *metav1.Time `json:"acceptedTimestamp,omitempty"`
}

// TODO(2.0) After converting all resources to use the runttime-controller client,
// the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="DataUpload status such as New/InProgress"
// +kubebuilder:printcolumn:name="Started",type="date",JSONPath=".status.startTimestamp",description="Time duration since this DataUpload was started"
// +kubebuilder:printcolumn:name="Bytes Done",type="integer",format="int64",JSONPath=".status.progress.bytesDone",description="Completed bytes"
// +kubebuilder:printcolumn:name="Total Bytes",type="integer",format="int64",JSONPath=".status.progress.totalBytes",description="Total bytes"
// +kubebuilder:printcolumn:name="Incremental Bytes",type="integer",format="int64",JSONPath=".status.incrementalBytes",description="Incremental bytes",priority=10
// +kubebuilder:printcolumn:name="Storage Location",type="string",JSONPath=".spec.backupStorageLocation",description="Name of the Backup Storage Location where this backup should be stored"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since this DataUpload was created"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".status.node",description="Name of the node where the DataUpload is processed"

// DataUpload acts as the protocol between data mover plugins and data mover controller for the datamover backup operation
type DataUpload struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec DataUploadSpec `json:"spec,omitempty"`

	// +optional
	Status DataUploadStatus `json:"status,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the k8s:deepcopy marker will no longer be needed and should be removed.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=datauploads,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=datauploads/status,verbs=get;update;patch

// DataUploadList is a list of DataUploads.
type DataUploadList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []DataUpload `json:"items"`
}

// DataUploadResult represents the SnasphotBackup result to be used by DataDownload.
type DataUploadResult struct {
	// BackupStorageLocation is the name of the backup storage location
	// where the backup repository is stored.
	BackupStorageLocation string `json:"backupStorageLocation"`

	// DataMover specifies the data mover used by the DataUpload
	// +optional
	DataMover string `json:"datamover,omitempty"`

	// SnapshotID is the identifier for the snapshot in the backup repository.
	SnapshotID string `json:"snapshotID,omitempty"`

	// SourceNamespace is the original namespace where the volume is backed up from.
	SourceNamespace string `json:"sourceNamespace"`

	// DataMoverResult stores data-mover-specific information as a result of the DataUpload.
	// +optional
	// +nullable
	DataMoverResult *map[string]string `json:"dataMoverResult,omitempty"`

	// NodeOS is OS of the node where the DataUpload is processed.
	// +optional
	NodeOS NodeOS `json:"nodeOS,omitempty"`

	// SnapshotSize is the logical size in Bytes of the snapshot.
	// +optional
	SnapshotSize int64 `json:"snapshotSize,omitempty"`
}
