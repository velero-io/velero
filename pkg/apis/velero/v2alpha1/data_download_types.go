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

// DataDownloadSpec is the specification for a DataDownload.
type DataDownloadSpec struct {
	// TargetVolume is the information of the target PVC and PV.
	TargetVolume TargetVolumeSpec `json:"targetVolume"`

	// BackupStorageLocation is the name of the backup storage location
	// where the backup repository is stored.
	BackupStorageLocation string `json:"backupStorageLocation"`

	// DataMover specifies the data mover to be used by the backup.
	// If DataMover is "" or "velero", the built-in data mover will be used.
	// +optional
	DataMover string `json:"datamover,omitempty"`

	// SnapshotID is the ID of the Velero backup snapshot to be restored from.
	SnapshotID string `json:"snapshotID"`

	// SourceNamespace is the original namespace where the volume is backed up from.
	// It may be different from SourcePVC's namespace if namespace is remapped during restore.
	SourceNamespace string `json:"sourceNamespace"`

	// DataMoverConfig is for data-mover-specific configuration fields.
	// +optional
	DataMoverConfig map[string]string `json:"dataMoverConfig,omitempty"`

	// Cancel indicates request to cancel the ongoing DataDownload. It can be set
	// when the DataDownload is in InProgress phase
	Cancel bool `json:"cancel,omitempty"`

	// OperationTimeout specifies the time used to wait internal operations,
	// before returning error as timeout.
	OperationTimeout metav1.Duration `json:"operationTimeout"`

	// NodeOS is OS of the node where the DataDownload is processed.
	// +optional
	NodeOS NodeOS `json:"nodeOS,omitempty"`

	// SnapshotSize is the logical size in Bytes of the snapshot.
	// +optional
	SnapshotSize int64 `json:"snapshotSize,omitempty"`
}

// TargetVolumeSpec is the specification for a target PVC.
type TargetVolumeSpec struct {
	// PVC is the name of the target PVC that is created by Velero restore
	PVC string `json:"pvc"`

	// PV is the name of the target PV that is created by Velero restore
	PV string `json:"pv"`

	// Namespace is the target namespace
	Namespace string `json:"namespace"`

	// FSType is the file system type of the target volume.
	// +optional
	FSType string `json:"fsType,omitempty"`
}

// DataDownloadPhase represents the lifecycle phase of a DataDownload.
// +kubebuilder:validation:Enum=New;Accepted;Prepared;InProgress;Canceling;Canceled;Completed;Failed
type DataDownloadPhase string

const (
	DataDownloadPhaseNew        DataDownloadPhase = "New"
	DataDownloadPhaseAccepted   DataDownloadPhase = "Accepted"
	DataDownloadPhasePrepared   DataDownloadPhase = "Prepared"
	DataDownloadPhaseInProgress DataDownloadPhase = "InProgress"
	DataDownloadPhaseCanceling  DataDownloadPhase = "Canceling"
	DataDownloadPhaseCanceled   DataDownloadPhase = "Canceled"
	DataDownloadPhaseCompleted  DataDownloadPhase = "Completed"
	DataDownloadPhaseFailed     DataDownloadPhase = "Failed"
)

// DataDownloadStatus is the current status of a DataDownload.
type DataDownloadStatus struct {
	// Phase is the current state of the DataDownload.
	// +optional
	Phase DataDownloadPhase `json:"phase,omitempty"`

	// Message is a message about the DataDownload's status.
	// +optional
	Message string `json:"message,omitempty"`

	// StartTimestamp records the time a restore was started.
	// The server's time is used for StartTimestamps
	// +optional
	// +nullable
	StartTimestamp *metav1.Time `json:"startTimestamp,omitempty"`

	// CompletionTimestamp records the time a restore was completed.
	// Completion time is recorded even on failed restores.
	// The server's time is used for CompletionTimestamps
	// +optional
	// +nullable
	CompletionTimestamp *metav1.Time `json:"completionTimestamp,omitempty"`

	// Progress holds the total number of bytes of the snapshot and the current
	// number of restored bytes. This can be used to display progress information
	// about the restore operation.
	// +optional
	Progress shared.DataMoveOperationProgress `json:"progress,omitempty"`

	// Node is name of the node where the DataDownload is processed.
	// +optional
	Node string `json:"node,omitempty"`

	// Node is name of the node where the DataUpload is prepared.
	// +optional
	AcceptedByNode string `json:"acceptedByNode,omitempty"`

	// AcceptedTimestamp records the time the DataUpload is to be prepared.
	// The server's time is used for AcceptedTimestamp
	// +optional
	// +nullable
	AcceptedTimestamp *metav1.Time `json:"acceptedTimestamp,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client, the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="DataDownload status such as New/InProgress"
// +kubebuilder:printcolumn:name="Started",type="date",JSONPath=".status.startTimestamp",description="Time duration since this DataDownload was started"
// +kubebuilder:printcolumn:name="Bytes Done",type="integer",format="int64",JSONPath=".status.progress.bytesDone",description="Completed bytes"
// +kubebuilder:printcolumn:name="Total Bytes",type="integer",format="int64",JSONPath=".status.progress.totalBytes",description="Total bytes"
// +kubebuilder:printcolumn:name="Storage Location",type="string",JSONPath=".spec.backupStorageLocation",description="Name of the Backup Storage Location where the backup data is stored"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since this DataDownload was created"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".status.node",description="Name of the node where the DataDownload is processed"

// DataDownload acts as the protocol between data mover plugins and data mover controller for the datamover restore operation
type DataDownload struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec DataDownloadSpec `json:"spec,omitempty"`

	// +optional
	Status DataDownloadStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=datadownloads,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=datadownloads/status,verbs=get;update;patch

// DataDownloadList is a list of DataDownloads.
type DataDownloadList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []DataDownload `json:"items"`
}
