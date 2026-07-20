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

import (
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
)

// PodVolumeRestoreSpec is the specification for a PodVolumeRestore.
type PodVolumeRestoreSpec struct {
	// Pod is a reference to the pod containing the volume to be restored.
	Pod corev1api.ObjectReference `json:"pod"`

	// Volume is the name of the volume within the Pod to be restored.
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

	// SnapshotID is the ID of the volume snapshot to be restored.
	SnapshotID string `json:"snapshotID"`

	// SourceNamespace is the original namespace for namaspace mapping.
	SourceNamespace string `json:"sourceNamespace"`

	// UploaderSettings are a map of key-value pairs that should be applied to the
	// uploader configuration.
	// +optional
	// +nullable
	UploaderSettings map[string]string `json:"uploaderSettings,omitempty"`

	// Cancel indicates request to cancel the ongoing PodVolumeRestore. It can be set
	// when the PodVolumeRestore is in InProgress phase
	Cancel bool `json:"cancel,omitempty"`

	// SnapshotSize is the logical size in Bytes of the snapshot.
	// +optional
	SnapshotSize int64 `json:"snapshotSize,omitempty"`
}

// PodVolumeRestorePhase represents the lifecycle phase of a PodVolumeRestore.
// +kubebuilder:validation:Enum=New;Accepted;Prepared;InProgress;Canceling;Canceled;Completed;Failed
type PodVolumeRestorePhase string

const (
	PodVolumeRestorePhaseNew        PodVolumeRestorePhase = "New"
	PodVolumeRestorePhaseAccepted   PodVolumeRestorePhase = "Accepted"
	PodVolumeRestorePhasePrepared   PodVolumeRestorePhase = "Prepared"
	PodVolumeRestorePhaseInProgress PodVolumeRestorePhase = "InProgress"
	PodVolumeRestorePhaseCanceling  PodVolumeRestorePhase = "Canceling"
	PodVolumeRestorePhaseCanceled   PodVolumeRestorePhase = "Canceled"
	PodVolumeRestorePhaseCompleted  PodVolumeRestorePhase = "Completed"
	PodVolumeRestorePhaseFailed     PodVolumeRestorePhase = "Failed"
)

// PodVolumeRestoreStatus is the current status of a PodVolumeRestore.
type PodVolumeRestoreStatus struct {
	// Phase is the current state of the PodVolumeRestore.
	// +optional
	Phase PodVolumeRestorePhase `json:"phase,omitempty"`

	// Message is a message about the pod volume restore's status.
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

	// AcceptedTimestamp records the time the pod volume restore is to be prepared.
	// The server's time is used for AcceptedTimestamp
	// +optional
	// +nullable
	AcceptedTimestamp *metav1.Time `json:"acceptedTimestamp,omitempty"`

	// Node is name of the node where the pod volume restore is processed.
	// +optional
	Node string `json:"node,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client, the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="PodVolumeRestore status such as New/InProgress"
// +kubebuilder:printcolumn:name="Started",type="date",JSONPath=".status.startTimestamp",description="Time duration since this PodVolumeRestore was started"
// +kubebuilder:printcolumn:name="Bytes Done",type="integer",format="int64",JSONPath=".status.progress.bytesDone",description="Completed bytes"
// +kubebuilder:printcolumn:name="Total Bytes",type="integer",format="int64",JSONPath=".status.progress.totalBytes",description="Total bytes"
// +kubebuilder:printcolumn:name="Storage Location",type="string",JSONPath=".spec.backupStorageLocation",description="Name of the Backup Storage Location where the backup data is stored"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time duration since this PodVolumeRestore was created"
// +kubebuilder:printcolumn:name="Node",type="string",JSONPath=".status.node",description="Name of the node where the PodVolumeRestore is processed"
// +kubebuilder:printcolumn:name="Uploader Type",type="string",JSONPath=".spec.uploaderType",description="The type of the uploader to handle data transfer"
// +kubebuilder:resource:shortName=pvr

type PodVolumeRestore struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec PodVolumeRestoreSpec `json:"spec,omitempty"`

	// +optional
	Status PodVolumeRestoreStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true

// PodVolumeRestoreList is a list of PodVolumeRestores.
type PodVolumeRestoreList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PodVolumeRestore `json:"items"`
}
