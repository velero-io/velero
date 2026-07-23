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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackupRepositorySpec is the specification for a BackupRepository.
type BackupRepositorySpec struct {
	// VolumeNamespace is the namespace this backup repository contains
	// pod volume backups for.
	VolumeNamespace string `json:"volumeNamespace"`

	// BackupStorageLocation is the name of the BackupStorageLocation
	// that should contain this repository.
	BackupStorageLocation string `json:"backupStorageLocation"`

	// RepositoryType indicates the type of the backend repository
	// +kubebuilder:validation:Enum=kopia;restic;""
	// +optional
	RepositoryType string `json:"repositoryType"`

	// Deprecated
	// +optional
	ResticIdentifier string `json:"resticIdentifier,omitempty"`

	// MaintenanceFrequency is how often maintenance should be run.
	MaintenanceFrequency metav1.Duration `json:"maintenanceFrequency"`

	// RepositoryConfig is for repository-specific configuration fields.
	// +optional
	// +nullable
	RepositoryConfig map[string]string `json:"repositoryConfig,omitempty"`
}

// BackupRepositoryPhase represents the lifecycle phase of a BackupRepository.
// +kubebuilder:validation:Enum=New;Ready;NotReady
type BackupRepositoryPhase string

const (
	BackupRepositoryPhaseNew      BackupRepositoryPhase = "New"
	BackupRepositoryPhaseReady    BackupRepositoryPhase = "Ready"
	BackupRepositoryPhaseNotReady BackupRepositoryPhase = "NotReady"

	BackupRepositoryTypeKopia string = "kopia"
)

// BackupRepositoryStatus is the current status of a BackupRepository.
type BackupRepositoryStatus struct {
	// Phase is the current state of the BackupRepository.
	// +optional
	Phase BackupRepositoryPhase `json:"phase,omitempty"`

	// Message is a message about the current status of the BackupRepository.
	// +optional
	Message string `json:"message,omitempty"`

	// LastMaintenanceTime is the last time repo maintenance succeeded.
	// +optional
	// +nullable
	LastMaintenanceTime *metav1.Time `json:"lastMaintenanceTime,omitempty"`

	// RecentMaintenance is status of the recent repo maintenance.
	// +optional
	RecentMaintenance []BackupRepositoryMaintenanceStatus `json:"recentMaintenance,omitempty"`
}

// BackupRepositoryMaintenanceResult represents the result of a repo maintenance.
// +kubebuilder:validation:Enum=Succeeded;Failed
type BackupRepositoryMaintenanceResult string

const (
	BackupRepositoryMaintenanceSucceeded BackupRepositoryMaintenanceResult = "Succeeded"
	BackupRepositoryMaintenanceFailed    BackupRepositoryMaintenanceResult = "Failed"
)

type BackupRepositoryMaintenanceStatus struct {
	// Result is the result of the repo maintenance.
	// +optional
	Result BackupRepositoryMaintenanceResult `json:"result,omitempty"`

	// StartTimestamp is the start time of the repo maintenance.
	// +optional
	// +nullable
	StartTimestamp *metav1.Time `json:"startTimestamp,omitempty"`

	// CompleteTimestamp is the completion time of the repo maintenance.
	// +optional
	// +nullable
	CompleteTimestamp *metav1.Time `json:"completeTimestamp,omitempty"`

	// Message is a message about the current status of the repo maintenance.
	// +optional
	Message string `json:"message,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Repository Type",type="string",JSONPath=".spec.repositoryType"
// +kubebuilder:resource:shortName=repo

type BackupRepository struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec BackupRepositorySpec `json:"spec,omitempty"`

	// +optional
	Status BackupRepositoryStatus `json:"status,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the k8s:deepcopy marker will no longer be needed and should be removed.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=backuprepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=backuprepositories/status,verbs=get;update;patch

// BackupRepositoryList is a list of BackupRepositories.
type BackupRepositoryList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []BackupRepository `json:"items"`
}
