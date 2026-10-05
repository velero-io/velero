/*
Copyright 2020 the Velero contributors.

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

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=ssr
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="The status of the server status request"
// +kubebuilder:printcolumn:name="Server Version",type="string",JSONPath=".status.serverVersion",description="The Velero server version"
// +kubebuilder:printcolumn:name="Processed",type="date",JSONPath=".status.processedTimestamp",description="The time the request was processed by the controller"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ServerStatusRequest is a request to access current status information about
// the Velero server.
type ServerStatusRequest struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec ServerStatusRequestSpec `json:"spec,omitempty"`

	// +optional
	Status ServerStatusRequestStatus `json:"status,omitempty"`
}

// ServerStatusRequestSpec is the specification for a ServerStatusRequest.
type ServerStatusRequestSpec struct {
}

// ServerStatusRequestPhase represents the lifecycle phase of a ServerStatusRequest.
// +kubebuilder:validation:Enum=New;Processed
type ServerStatusRequestPhase string

const (
	// ServerStatusRequestPhaseNew means the ServerStatusRequest has not been processed yet.
	ServerStatusRequestPhaseNew ServerStatusRequestPhase = "New"
	// ServerStatusRequestPhaseProcessed means the ServerStatusRequest has been processed.
	ServerStatusRequestPhaseProcessed ServerStatusRequestPhase = "Processed"
)

// PluginInfo contains attributes of a Velero plugin
type PluginInfo struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// ServerStatusRequestStatus is the current status of a ServerStatusRequest.
type ServerStatusRequestStatus struct {
	// Phase is the current lifecycle phase of the ServerStatusRequest.
	// +optional
	Phase ServerStatusRequestPhase `json:"phase,omitempty"`

	// ProcessedTimestamp is when the ServerStatusRequest was processed
	// by the ServerStatusRequestController.
	// +optional
	// +nullable
	ProcessedTimestamp *metav1.Time `json:"processedTimestamp,omitempty"`

	// ServerVersion is the Velero server version.
	// +optional
	ServerVersion string `json:"serverVersion,omitempty"`

	// Plugins list information about the plugins running on the Velero server
	// +optional
	// +nullable
	Plugins []PluginInfo `json:"plugins,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the k8s:deepcopy marker will no longer be needed and should be removed.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=serverstatusrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=serverstatusrequests/status,verbs=get;update;patch

// ServerStatusRequestList is a list of ServerStatusRequests.
type ServerStatusRequestList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ServerStatusRequest `json:"items"`
}
