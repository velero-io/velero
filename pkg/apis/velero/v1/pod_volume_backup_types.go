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

package v1

import (
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
)

// PodVolumeBackupSpec is the specification for a PodVolumeBackup.
type PodVolumeBackupSpec struct {
	// Node is the name of the node that the Pod is running on.
	Node string `json:"node"`

	// Pod is a reference to the pod containing the volume to be backed up.
	Pod corev1api.ObjectReference `json:"pod"`

	// Volume is the name of the volume within the Pod to be backed
	// up.
	Volume string `json:"volume"`

	// BackupStorageLocation is the name of the backup storage location
	// where the backup repository is stored.
	BackupStorageLocation string `json:"backupStorageLocation"`

	// RepoIdentifier is the backup repository identifier.
	RepoIdentifier string `json:"repoIdentifier"`

	// UploaderType is the type of the uploader to handle the data transfer.
	// +kubebuilder:validation:Enum=kopia;restic;""
	// +optional
	UploaderType string `json:"uploaderType"`

	// Tags are a map of key-value pairs that should be applied to the
	// volume backup as tags.
	// +optional
	Tags map[string]string `json:"tags,omitempty"`

	// UploaderSettings are a map of key-value pairs that should be applied to the
	// uploader configuration.
	// +optional
	// +nullable
	UploaderSettings map[string]string `json:"uploaderSettings,omitempty"`

	// Cancel indicates request to cancel the ongoing PodVolumeBackup. It can be set
	// when the PodVolumeBackup is in InProgress phase
	Cancel bool `json:"cancel,omitempty"`
}

// PodVolumeBackupPhase represents the lifecycle phase of a PodVolumeBackup.
// +kubebuilder:validation:Enum=New;Accepted;Prepared;InProgress;Canceling;Canceled;Completed;Failed
type PodVolumeBackupPhase string

const (
	PodVolumeBackupPhaseNew        PodVolumeBackupPhase = "New"
	PodVolumeBackupPhaseAccepted   PodVolumeBackupPhase = "Accepted"
	PodVolumeBackupPhasePrepared   PodVolumeBackupPhase = "Prepared"
	PodVolumeBackupPhaseInProgress PodVolumeBackupPhase = "InProgress"
	PodVolumeBackupPhaseCanceling  PodVolumeBackupPhase = "Canceling"
	PodVolumeBackupPhaseCanceled   PodVolumeBackupPhase = "Canceled"
	PodVolumeBackupPhaseCompleted  PodVolumeBackupPhase = "Completed"
	PodVolumeBackupPhaseFailed     PodVolumeBackupPhase = "Failed"
)

// PodVolumeBackupStatus is the current status of a PodVolumeBackup.
type PodVolumeBackupStatus struct {
	// Phase is the current state of the PodVolumeBackup.
	// +optional
	Phase PodVolumeBackupPhase `json:"phase,omitempty"`

	// Path is the full path within the controller pod being backed up.
	// +optional
	Path string `json:"path,omitempty"`

	// SnapshotID is the identifier for the snapshot of the pod volume.
	// +optional
	SnapshotID string `json:"snapshotID,omitempty"`

	// Message is a message about the pod volume backup's status.
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

	// AcceptedTimestamp records the time the pod volume backup is to be prepared.
	// The server's time is used for AcceptedTimestamp
	// +optional
	// +nullable
	AcceptedTimestamp *metav1.Time `json:"acceptedTimestamp,omitempty"`
}

// TODO(2.0) After converting all resources to use the runttime-controller client,
// the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="PodVolumeBackup status such as New/InProgress"
// +kubebuilder:printcolumn:name="Started",type="date",JSONPath=".status.startTimestamp",description="Time duration since this PodVolumeBackup was started"
// +kubebuilder:printcolumn:name="Bytes Done",type="integer",format="int64",JSONPath=".status.progress.bytesDone",description="Completed bytes"
// +kubebuilder:printcolumn:name="Total Bytes",type="integer",format="int64",JSONPath=".status.progress.totalBytes",description="Total bytes"
// +kubebuilder:printcolumn:name="Incremental Bytes",type="integer",format="int64",JSONPath=".status.incrementalBytes",description="Incremental bytes",priority=10
// +kubebuilder:printcolumn:name="Storage Location",type="string",JSONPath=".spec.backupStorageLocation",description="Name of the Backup Storage Location where this backup should be stored"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since this PodVolumeBackup was created"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".status.node",description="Name of the node where the PodVolumeBackup is processed"
// +kubebuilder:printcolumn:name="Uploader",type="string",JSONPath=".spec.uploaderType",description="The type of the uploader to handle data transfer"
// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// +kubebuilder:resource:shortName=pvb

type PodVolumeBackup struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec PodVolumeBackupSpec `json:"spec,omitempty"`

	// +optional
	Status PodVolumeBackupStatus `json:"status,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the k8s:deepcopy marker will no longer be needed and should be removed.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=podvolumebackups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=podvolumebackups/status,verbs=get;update;patch

// PodVolumeBackupList is a list of PodVolumeBackups.
type PodVolumeBackupList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PodVolumeBackup `json:"items"`
}
