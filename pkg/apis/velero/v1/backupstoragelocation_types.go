/*
Copyright 2017, 2020 the Velero contributors.

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
	"errors"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// BackupStorageLocationSpec defines the desired state of a Velero BackupStorageLocation
type BackupStorageLocationSpec struct {
	// Provider is the provider of the backup storage.
	Provider string `json:"provider"`

	// Config is for provider-specific configuration fields.
	// +optional
	Config map[string]string `json:"config,omitempty"`

	// Credential contains the credential information intended to be used with this location
	// +optional
	Credential *corev1api.SecretKeySelector `json:"credential,omitempty"`

	// Worker, when set, runs this BackupStorageLocation's object-store operations in a
	// dedicated worker pod under a distinct identity, instead of in the Velero server
	// process. This allows the location to consume a per-BSL pod/workload identity
	// (e.g. Azure AD Workload Identity, AWS IRSA, GCP Workload Identity).
	// Requires the EnableBSLWorkerIdentity feature flag.
	// +optional
	Worker *BackupStorageLocationWorker `json:"worker,omitempty"`

	StorageType `json:",inline"`

	// Default indicates this location is the default backup storage location.
	// +optional
	Default bool `json:"default,omitempty"`

	// AccessMode defines the permissions for the backup storage location.
	// +optional
	AccessMode BackupStorageLocationAccessMode `json:"accessMode,omitempty"`

	// BackupSyncPeriod defines how frequently to sync backup API objects from object storage. A value of 0 disables sync.
	// +optional
	// +nullable
	BackupSyncPeriod *metav1.Duration `json:"backupSyncPeriod,omitempty"`

	// ValidationFrequency defines how frequently to validate the corresponding object storage. A value of 0 disables validation.
	// +optional
	// +nullable
	ValidationFrequency *metav1.Duration `json:"validationFrequency,omitempty"`
}

// BackupStorageLocationStatus defines the observed state of BackupStorageLocation
type BackupStorageLocationStatus struct {
	// Phase is the current state of the BackupStorageLocation.
	// +optional
	Phase BackupStorageLocationPhase `json:"phase,omitempty"`

	// LastSyncedTime is the last time the contents of the location were synced into
	// the cluster.
	// +optional
	// +nullable
	LastSyncedTime *metav1.Time `json:"lastSyncedTime,omitempty"`

	// LastValidationTime is the last time the backup store location was validated
	// the cluster.
	// +optional
	// +nullable
	LastValidationTime *metav1.Time `json:"lastValidationTime,omitempty"`

	// Message is a message about the backup storage location's status.
	// +optional
	Message string `json:"message,omitempty"`

	// LastSyncedRevision is the value of the `metadata/revision` file in the backup
	// storage location the last time the BSL's contents were synced into the cluster.
	//
	// Deprecated: this field is no longer updated or used for detecting changes to
	// the location's contents and will be removed entirely in v2.0.
	// +optional
	LastSyncedRevision types.UID `json:"lastSyncedRevision,omitempty"`

	// AccessMode is an unused field.
	//
	// Deprecated: there is now an AccessMode field on the Spec and this field
	// will be removed entirely as of v2.0.
	// +optional
	AccessMode BackupStorageLocationAccessMode `json:"accessMode,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=bsl
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase",description="Backup Storage Location status such as Available/Unavailable"
// +kubebuilder:printcolumn:name="Last Validated",type="date",JSONPath=".status.lastValidationTime",description="LastValidationTime is the last time the backup store location was validated"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Default",type="boolean",JSONPath=".spec.default",description="Default backup storage location"

// BackupStorageLocation is a location where Velero stores backup objects
type BackupStorageLocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackupStorageLocationSpec   `json:"spec,omitempty"`
	Status BackupStorageLocationStatus `json:"status,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client,
// the k8s:deepcopy marker will no longer be needed and should be removed.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=backupstoragelocations/status,verbs=get;update;patch

// BackupStorageLocationList contains a list of BackupStorageLocation
type BackupStorageLocationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BackupStorageLocation `json:"items"`
}

// StorageType represents the type of storage that a backup location uses.
// ObjectStorage must be non-nil, since it is currently the only supported StorageType.
type StorageType struct {
	ObjectStorage *ObjectStorageLocation `json:"objectStorage"`
}

// ObjectStorageLocation specifies the settings necessary to connect to a provider's object storage.
type ObjectStorageLocation struct {
	// Bucket is the bucket to use for object storage.
	Bucket string `json:"bucket"`

	// Prefix is the path inside a bucket to use for Velero storage. Optional.
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// CACert defines a CA bundle to use when verifying TLS connections to the provider.
	// Deprecated: Use CACertRef instead.
	// +optional
	CACert []byte `json:"caCert,omitempty"`

	// CACertRef is a reference to a Secret containing the CA certificate bundle to use
	// when verifying TLS connections to the provider. The Secret must be in the same
	// namespace as the BackupStorageLocation.
	// +optional
	CACertRef *corev1api.SecretKeySelector `json:"caCertRef,omitempty"`
}

// BackupStorageLocationWorker configures the dedicated worker pod that runs object-store
// operations for a BackupStorageLocation under a distinct identity.
type BackupStorageLocationWorker struct {
	// ServiceAccountName is the ServiceAccount the worker pod runs as. It must exist in
	// Namespace and carry the desired pod/workload identity.
	ServiceAccountName string `json:"serviceAccountName"`

	// Namespace is the namespace the worker pod runs in. It defaults to the Velero
	// namespace. The ServiceAccount referenced by ServiceAccountName must live in this
	// namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// PodLabels are additional labels applied to the worker pod, e.g.
	// `azure.workload.identity/use: "true"` to opt into a provider's admission webhook.
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// PodAnnotations are additional annotations applied to the worker pod.
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// TokenVolumes declares explicit projected service-account-token volumes mounted into
	// the worker pod. This is useful for portability when no provider admission webhook
	// injects a federated token automatically.
	// +optional
	TokenVolumes []ProjectedServiceAccountToken `json:"tokenVolumes,omitempty"`

	// Resources overrides the worker container's resource requirements. When unset, the
	// worker inherits the Velero server container defaults.
	// +optional
	Resources *corev1api.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector overrides the worker pod's node selection.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations overrides the worker pod's tolerations.
	// +optional
	Tolerations []corev1api.Toleration `json:"tolerations,omitempty"`
}

// ProjectedServiceAccountToken configures a single projected service-account-token volume
// mounted into the worker pod.
type ProjectedServiceAccountToken struct {
	// Audience is the intended audience of the token (provider specific, e.g.
	// "api://AzureADTokenExchange" for Azure Workload Identity).
	Audience string `json:"audience"`

	// ExpirationSeconds is the requested duration of validity of the token. The default,
	// when unset, is decided by the API server.
	// +optional
	ExpirationSeconds *int64 `json:"expirationSeconds,omitempty"`

	// MountPath is the directory the token volume is mounted at inside the worker
	// container.
	MountPath string `json:"mountPath"`

	// Path is the file name, relative to MountPath, that the token is projected to.
	Path string `json:"path"`
}

// BackupStorageLocationPhase is the lifecycle phase of a Velero BackupStorageLocation.
// +kubebuilder:validation:Enum=Available;Unavailable
// +kubebuilder:default=Unavailable
type BackupStorageLocationPhase string

const (
	// BackupStorageLocationPhaseAvailable means the location is available to read and write from.
	BackupStorageLocationPhaseAvailable BackupStorageLocationPhase = "Available"

	// BackupStorageLocationPhaseUnavailable means the location is unavailable to read and write from.
	BackupStorageLocationPhaseUnavailable BackupStorageLocationPhase = "Unavailable"
)

// BackupStorageLocationAccessMode represents the permissions for a BackupStorageLocation.
// +kubebuilder:validation:Enum=ReadOnly;ReadWrite
type BackupStorageLocationAccessMode string

const (
	// BackupStorageLocationAccessModeReadOnly represents read-only access to a BackupStorageLocation.
	BackupStorageLocationAccessModeReadOnly BackupStorageLocationAccessMode = "ReadOnly"

	// BackupStorageLocationAccessModeReadWrite represents read and write access to a BackupStorageLocation.
	BackupStorageLocationAccessModeReadWrite BackupStorageLocationAccessMode = "ReadWrite"
)

// TODO(2.0): remove the AccessMode field from BackupStorageLocationStatus.
// TODO(2.0): remove the LastSyncedRevision field from BackupStorageLocationStatus.

// Validate validates the BackupStorageLocation to ensure that only one of CACert or CACertRef is set.
func (bsl *BackupStorageLocation) Validate() error {
	if bsl.Spec.ObjectStorage != nil &&
		bsl.Spec.ObjectStorage.CACert != nil &&
		bsl.Spec.ObjectStorage.CACertRef != nil {
		return errors.New("cannot specify both caCert and caCertRef in objectStorage")
	}
	if bsl.Spec.Worker != nil {
		if bsl.Spec.Worker.ServiceAccountName == "" {
			return errors.New("worker.serviceAccountName must be set when worker is specified")
		}
		for i := range bsl.Spec.Worker.TokenVolumes {
			tv := bsl.Spec.Worker.TokenVolumes[i]
			if tv.Audience == "" || tv.MountPath == "" || tv.Path == "" {
				return errors.New("each worker.tokenVolumes entry must set audience, mountPath and path")
			}
		}
	}
	return nil
}
