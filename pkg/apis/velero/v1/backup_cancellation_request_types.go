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

package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BackupCancellationRequestSpec is the specification for a request to cancel a backup.
type BackupCancellationRequestSpec struct {
	// BackupName is the name of the backup to cancel.
	BackupName string `json:"backupName"`

	// DeleteBackup, when true, requests deletion after cancellation completes
	// successfully: the request controller creates a DeleteBackupRequest once
	// the backup reaches Canceled. Not applied when the request is Rejected.
	// +optional
	DeleteBackup bool `json:"deleteBackup,omitempty"`
}

// BackupCancellationRequestPhase represents the lifecycle phase of a BackupCancellationRequest.
// +kubebuilder:validation:Enum=New;Accepted;Completed;Rejected
type BackupCancellationRequestPhase string

const (
	// BackupCancellationRequestPhaseNew means the request has been observed, but no
	// phase owner has recorded acceptance on the target Backup yet.
	BackupCancellationRequestPhaseNew BackupCancellationRequestPhase = "New"

	// BackupCancellationRequestPhaseAccepted means a phase owner recorded Canceling
	// on the target Backup; the outcome is authoritative.
	BackupCancellationRequestPhaseAccepted BackupCancellationRequestPhase = "Accepted"

	// BackupCancellationRequestPhaseCompleted means the target Backup reached the
	// terminal Canceled phase.
	BackupCancellationRequestPhaseCompleted BackupCancellationRequestPhase = "Completed"

	// BackupCancellationRequestPhaseRejected means the request could not be honored;
	// Status.Reason distinguishes why.
	BackupCancellationRequestPhaseRejected BackupCancellationRequestPhase = "Rejected"
)

// BackupCancellationRequestRejectedReason explains why a request was Rejected.
// +kubebuilder:validation:Enum=TooLate;AlreadyTerminal;NotFound
type BackupCancellationRequestRejectedReason string

const (
	// BackupCancellationRequestRejectedReasonTooLate means the Backup was still
	// running but past the acceptance boundary (Finalizing*).
	BackupCancellationRequestRejectedReasonTooLate BackupCancellationRequestRejectedReason = "TooLate"

	// BackupCancellationRequestRejectedReasonAlreadyTerminal means the Backup had
	// already reached a terminal phase (Completed, PartiallyFailed, Failed,
	// FailedValidation, or Canceled). Message records the exact phase.
	BackupCancellationRequestRejectedReasonAlreadyTerminal BackupCancellationRequestRejectedReason = "AlreadyTerminal"

	// BackupCancellationRequestRejectedReasonNotFound means no Backup with the
	// requested name existed when the request was bound.
	BackupCancellationRequestRejectedReasonNotFound BackupCancellationRequestRejectedReason = "NotFound"
)

// BackupCancellationRequestStatus is the current status of a BackupCancellationRequest.
type BackupCancellationRequestStatus struct {
	// Phase is the current state of the request.
	// +optional
	Phase BackupCancellationRequestPhase `json:"phase,omitempty"`

	// BackupUID binds the request: it is only acted on for the Backup with this
	// UID, so a later Backup reusing the same name cannot satisfy or be affected
	// by it.
	// +optional
	BackupUID string `json:"backupUID,omitempty"`

	// Reason categorizes a Rejected request.
	// +optional
	Reason BackupCancellationRequestRejectedReason `json:"reason,omitempty"`

	// Message is a human-readable explanation of the current phase (e.g. the
	// exact terminal phase behind an AlreadyTerminal rejection).
	// +optional
	Message string `json:"message,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client, the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="BackupName",type="string",JSONPath=".spec.backupName",description="The name of the backup to be canceled"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="The status of the cancellation request"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.reason",description="The reason a cancellation request was rejected"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:resource:shortName=bcr

// BackupCancellationRequest is a request to cancel an in-progress backup.
type BackupCancellationRequest struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec BackupCancellationRequestSpec `json:"spec,omitempty"`

	// +optional
	Status BackupCancellationRequestStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// BackupCancellationRequestList is a list of BackupCancellationRequests.
type BackupCancellationRequestList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []BackupCancellationRequest `json:"items"`
}
