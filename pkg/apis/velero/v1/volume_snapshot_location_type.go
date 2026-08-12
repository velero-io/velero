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

import (
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=vsl
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Provider",type="string",JSONPath=".spec.provider",description="Provider is the provider of the volume storage"
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase",description="Volume Snapshot Location status such as Available/Unavailable"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// VolumeSnapshotLocation is a location where Velero stores volume snapshots.
type VolumeSnapshotLocation struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec VolumeSnapshotLocationSpec `json:"spec,omitempty"`

	// +optional
	Status VolumeSnapshotLocationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=volumesnapshotlocations,verbs=get;list;watch;create;update;patch;delete

// VolumeSnapshotLocationList is a list of VolumeSnapshotLocations.
type VolumeSnapshotLocationList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []VolumeSnapshotLocation `json:"items"`
}

// VolumeSnapshotLocationSpec defines the specification for a Velero VolumeSnapshotLocation.
type VolumeSnapshotLocationSpec struct {
	// Provider is the provider of the volume storage.
	Provider string `json:"provider"`

	// Config is for provider-specific configuration fields.
	// +optional
	Config map[string]string `json:"config,omitempty"`

	// Credential contains the credential information intended to be used with this location
	// +optional
	Credential *corev1api.SecretKeySelector `json:"credential,omitempty"`
}

// VolumeSnapshotLocationPhase is the lifecycle phase of a Velero VolumeSnapshotLocation.
// +kubebuilder:validation:Enum=Available;Unavailable
type VolumeSnapshotLocationPhase string

const (
	// VolumeSnapshotLocationPhaseAvailable means the location is available to read and write from.
	VolumeSnapshotLocationPhaseAvailable VolumeSnapshotLocationPhase = "Available"

	// VolumeSnapshotLocationPhaseUnavailable means the location is unavailable to read and write from.
	VolumeSnapshotLocationPhaseUnavailable VolumeSnapshotLocationPhase = "Unavailable"
)

// VolumeSnapshotLocationStatus describes the current status of a Velero VolumeSnapshotLocation.
type VolumeSnapshotLocationStatus struct {
	// +optional
	Phase VolumeSnapshotLocationPhase `json:"phase,omitempty"`
}
