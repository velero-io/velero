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
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Metadata struct {
	Labels map[string]string `json:"labels,omitempty"`
}

// BackupSpec defines the specification for a Velero backup.
type BackupSpec struct {
	// +optional
	Metadata `json:"metadata,omitempty"`
	// IncludedNamespaces is a slice of namespace names to include objects
	// from. If empty, all namespaces are included.
	// +optional
	// +nullable
	IncludedNamespaces []string `json:"includedNamespaces,omitempty"`

	// ExcludedNamespaces contains a list of namespaces that are not
	// included in the backup.
	// +optional
	// +nullable
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`

	// IncludedResources is a slice of resource names to include
	// in the backup. If empty, all resources are included.
	// +optional
	// +nullable
	IncludedResources []string `json:"includedResources,omitempty"`

	// ExcludedResources is a slice of resource names that are not
	// included in the backup.
	// +optional
	// +nullable
	ExcludedResources []string `json:"excludedResources,omitempty"`

	// IncludedClusterScopedResources is a slice of cluster-scoped
	// resource type names to include in the backup.
	// If set to "*", all cluster-scoped resource types are included.
	// The default value is empty, which means only related
	// cluster-scoped resources are included.
	// +optional
	// +nullable
	IncludedClusterScopedResources []string `json:"includedClusterScopedResources,omitempty"`

	// ExcludedClusterScopedResources is a slice of cluster-scoped
	// resource type names to exclude from the backup.
	// If set to "*", all cluster-scoped resource types are excluded.
	// The default value is empty.
	// +optional
	// +nullable
	ExcludedClusterScopedResources []string `json:"excludedClusterScopedResources,omitempty"`

	// IncludedNamespaceScopedResources is a slice of namespace-scoped
	// resource type names to include in the backup.
	// The default value is "*".
	// +optional
	// +nullable
	IncludedNamespaceScopedResources []string `json:"includedNamespaceScopedResources,omitempty"`

	// ExcludedNamespaceScopedResources is a slice of namespace-scoped
	// resource type names to exclude from the backup.
	// If set to "*", all namespace-scoped resource types are excluded.
	// The default value is empty.
	// +optional
	// +nullable
	ExcludedNamespaceScopedResources []string `json:"excludedNamespaceScopedResources,omitempty"`

	// LabelSelector is a metav1.LabelSelector to filter with
	// when adding individual objects to the backup. If empty
	// or nil, all objects are included. Optional.
	// +optional
	// +nullable
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`

	// OrLabelSelectors is list of metav1.LabelSelector to filter with
	// when adding individual objects to the backup. If multiple provided
	// they will be joined by the OR operator. LabelSelector as well as
	// OrLabelSelectors cannot co-exist in backup request, only one of them
	// can be used.
	// +optional
	// +nullable
	OrLabelSelectors []*metav1.LabelSelector `json:"orLabelSelectors,omitempty"`

	// SnapshotVolumes specifies whether to take snapshots
	// of any PV's referenced in the set of objects included
	// in the Backup.
	// +optional
	// +nullable
	SnapshotVolumes *bool `json:"snapshotVolumes,omitempty"`

	// TTL is a time.Duration-parseable string describing how long
	// the Backup should be retained for.
	// +optional
	TTL metav1.Duration `json:"ttl,omitempty"`

	// VolumeGroupSnapshotLabelKey specifies the label key to group PVCs under a VGS.
	// +optional
	VolumeGroupSnapshotLabelKey string `json:"volumeGroupSnapshotLabelKey,omitempty"`

	// IncludeClusterResources specifies whether cluster-scoped resources
	// should be included for consideration in the backup.
	// +optional
	// +nullable
	IncludeClusterResources *bool `json:"includeClusterResources,omitempty"`

	// Hooks represent custom behaviors that should be executed at different phases of the backup.
	// +optional
	Hooks BackupHooks `json:"hooks,omitempty"`

	// StorageLocation is a string containing the name of a BackupStorageLocation where the backup should be stored.
	// +optional
	StorageLocation string `json:"storageLocation,omitempty"`

	// VolumeSnapshotLocations is a list containing names of VolumeSnapshotLocations associated with this backup.
	// +optional
	VolumeSnapshotLocations []string `json:"volumeSnapshotLocations,omitempty"`

	// DefaultVolumesToRestic specifies whether restic should be used to take a
	// backup of all pod volumes by default.
	//
	// Deprecated: this field is no longer used and will be removed entirely in future. Use DefaultVolumesToFsBackup instead.
	// +optional
	// +nullable
	DefaultVolumesToRestic *bool `json:"defaultVolumesToRestic,omitempty"`

	// DefaultVolumesToFsBackup specifies whether pod volume file system backup should be used
	// for all volumes by default.
	// +optional
	// +nullable
	DefaultVolumesToFsBackup *bool `json:"defaultVolumesToFsBackup,omitempty"`

	// OrderedResources specifies the backup order of resources of specific Kind.
	// The map key is the resource name and value is a list of object names separated by commas.
	// Each resource name has format "namespace/objectname".  For cluster resources, simply use "objectname".
	// +optional
	// +nullable
	OrderedResources map[string]string `json:"orderedResources,omitempty"`

	// CSISnapshotTimeout specifies the time used to wait for CSI VolumeSnapshot status turns to
	// ReadyToUse during creation, before returning error as timeout.
	// The default value is 10 minute.
	// +optional
	CSISnapshotTimeout metav1.Duration `json:"csiSnapshotTimeout,omitempty"`

	// CSISnapshotErrorTimeout specifies how long to tolerate a persistent error
	// reported in a CSI VolumeSnapshot or VolumeSnapshotContent status before
	// failing the backup operation. This bounds how long Velero will keep
	// polling/waiting for a snapshot whose status reports an error, instead of
	// waiting for the much longer ItemOperationTimeout.
	// The default value is 10 minutes.
	// +optional
	CSISnapshotErrorTimeout metav1.Duration `json:"csiSnapshotErrorTimeout,omitempty"`

	// ItemOperationTimeout specifies the time used to wait for asynchronous BackupItemAction operations
	// The default value is 4 hour.
	// +optional
	ItemOperationTimeout metav1.Duration `json:"itemOperationTimeout,omitempty"`
	// ResourcePolicy specifies the referenced resource policies that backup should follow
	// +optional
	ResourcePolicy *corev1api.TypedLocalObjectReference `json:"resourcePolicy,omitempty"`

	// SnapshotMoveData specifies whether snapshot data should be moved
	// +optional
	// +nullable
	SnapshotMoveData *bool `json:"snapshotMoveData,omitempty"`

	// DataMover specifies the data mover to be used by the backup.
	// If DataMover is "" or "velero", the built-in data mover will be used.
	// +optional
	DataMover string `json:"datamover,omitempty"`

	// UploaderConfig specifies the configuration for the uploader.
	// +optional
	// +nullable
	UploaderConfig *UploaderConfigForBackup `json:"uploaderConfig,omitempty"`
}

// UploaderConfigForBackup defines the configuration for the uploader when doing backup.
type UploaderConfigForBackup struct {
	// ParallelFilesUpload is the number of files parallel uploads to perform when using the uploader.
	// +optional
	ParallelFilesUpload int `json:"parallelFilesUpload,omitempty"`
}

// BackupHooks contains custom behaviors that should be executed at different phases of the backup.
type BackupHooks struct {
	// Resources are hooks that should be executed when backing up individual instances of a resource.
	// +optional
	// +nullable
	Resources []BackupResourceHookSpec `json:"resources,omitempty"`
}

// BackupResourceHookSpec defines one or more BackupResourceHooks that should be executed based on
// the rules defined for namespaces, resources, and label selector.
type BackupResourceHookSpec struct {
	// Name is the name of this hook.
	Name string `json:"name"`

	// IncludedNamespaces specifies the namespaces to which this hook spec applies. If empty, it applies
	// to all namespaces.
	// +optional
	// +nullable
	IncludedNamespaces []string `json:"includedNamespaces,omitempty"`

	// ExcludedNamespaces specifies the namespaces to which this hook spec does not apply.
	// +optional
	// +nullable
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`

	// IncludedResources specifies the resources to which this hook spec applies. If empty, it applies
	// to all resources.
	// +optional
	// +nullable
	IncludedResources []string `json:"includedResources,omitempty"`

	// ExcludedResources specifies the resources to which this hook spec does not apply.
	// +optional
	// +nullable
	ExcludedResources []string `json:"excludedResources,omitempty"`

	// LabelSelector, if specified, filters the resources to which this hook spec applies.
	// +optional
	// +nullable
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`

	// PreHooks is a list of BackupResourceHooks to execute prior to storing the item in the backup.
	// These are executed before any "additional items" from item actions are processed.
	// +optional
	PreHooks []BackupResourceHook `json:"pre,omitempty"`

	// PostHooks is a list of BackupResourceHooks to execute after storing the item in the backup.
	// These are executed after all "additional items" from item actions are processed.
	// +optional
	PostHooks []BackupResourceHook `json:"post,omitempty"`
}

// BackupResourceHook defines a hook for a resource.
type BackupResourceHook struct {
	// Exec defines an exec hook.
	Exec *ExecHook `json:"exec"`
}

// ExecHook is a hook that uses the pod exec API to execute a command in a container in a pod.
type ExecHook struct {
	// Container is the container in the pod where the command should be executed. If not specified,
	// the pod's first container is used.
	// +optional
	Container string `json:"container,omitempty"`

	// Command is the command and arguments to execute.
	// +kubebuilder:validation:MinItems=1
	Command []string `json:"command"`

	// OnError specifies how Velero should behave if it encounters an error executing this hook.
	// +optional
	OnError HookErrorMode `json:"onError,omitempty"`

	// Timeout defines the maximum amount of time Velero should wait for the hook to complete before
	// considering the execution a failure.
	// +optional
	Timeout metav1.Duration `json:"timeout,omitempty"`
}

// HookErrorMode defines how Velero should treat an error from a hook.
// +kubebuilder:validation:Enum=Continue;Fail
type HookErrorMode string

const (
	// HookErrorModeContinue means that an error from a hook is acceptable and the backup/restore can
	// proceed with the rest of hooks' execution. This backup/restore should be in `PartiallyFailed` status.
	HookErrorModeContinue HookErrorMode = "Continue"

	// HookErrorModeFail means that an error from a hook is problematic and Velero should stop executing following hooks.
	// This backup/restore should be in `PartiallyFailed` status.
	HookErrorModeFail HookErrorMode = "Fail"
)

// BackupPhase is a string representation of the lifecycle phase
// of a Velero backup.
// +kubebuilder:validation:Enum=New;Queued;ReadyToStart;FailedValidation;InProgress;WaitingForPluginOperations;WaitingForPluginOperationsPartiallyFailed;Finalizing;FinalizingPartiallyFailed;Completed;PartiallyFailed;Failed;Deleting
type BackupPhase string

const (
	// BackupPhaseNew means the backup has been created but not
	// yet processed by the BackupController.
	BackupPhaseNew BackupPhase = "New"

	// BackupPhaseQueued means the backup has been added to the queue and is waiting for the Queue to move it out of the queue.
	BackupPhaseQueued BackupPhase = "Queued"

	// BackupPhaseReadyToStart means the backup has been pulled from the queue and is ready to start.
	BackupPhaseReadyToStart BackupPhase = "ReadyToStart"

	// BackupPhaseFailedValidation means the backup has failed
	// the controller's validations and therefore will not run.
	BackupPhaseFailedValidation BackupPhase = "FailedValidation"

	// BackupPhaseInProgress means the backup is currently executing.
	BackupPhaseInProgress BackupPhase = "InProgress"

	// BackupPhaseWaitingForPluginOperations means the backup of
	// Kubernetes resources, creation of snapshots, and other
	// async plugin operations was successful and snapshot data is
	// currently uploading or other plugin operations are still
	// ongoing.  The backup is not usable yet.
	BackupPhaseWaitingForPluginOperations BackupPhase = "WaitingForPluginOperations"

	// BackupPhaseWaitingForPluginOperationsPartiallyFailed means
	// the backup of Kubernetes resources, creation of snapshots,
	// and other async plugin operations partially failed (final
	// phase will be PartiallyFailed) and snapshot data is
	// currently uploading or other plugin operations are still
	// ongoing.  The backup is not usable yet.
	BackupPhaseWaitingForPluginOperationsPartiallyFailed BackupPhase = "WaitingForPluginOperationsPartiallyFailed"

	// BackupPhaseFinalizing means the backup of
	// Kubernetes resources, creation of snapshots, and other
	// async plugin operations were successful and snapshot upload and
	// other plugin operations are now complete, but the Backup is awaiting
	// final update of resources modified during async operations.
	// The backup is not usable yet.
	BackupPhaseFinalizing BackupPhase = "Finalizing"

	// BackupPhaseFinalizingPartiallyFailed means the backup of
	// Kubernetes resources, creation of snapshots, and other
	// async plugin operations were successful and snapshot upload and
	// other plugin operations are now complete, but one or more errors
	// occurred during backup or async operation processing, and the
	// Backup is awaiting final update of resources modified during async
	// operations. The backup is not usable yet.
	BackupPhaseFinalizingPartiallyFailed BackupPhase = "FinalizingPartiallyFailed"

	// BackupPhaseCompleted means the backup has run successfully without
	// errors.
	BackupPhaseCompleted BackupPhase = "Completed"

	// BackupPhasePartiallyFailed means the backup has run to completion
	// but encountered 1+ errors backing up individual items.
	BackupPhasePartiallyFailed BackupPhase = "PartiallyFailed"

	// BackupPhaseFailed means the backup ran but encountered an error that
	// prevented it from completing successfully.
	BackupPhaseFailed BackupPhase = "Failed"

	// BackupPhaseDeleting means the backup and all its associated data are being deleted.
	BackupPhaseDeleting BackupPhase = "Deleting"
)

// BackupStatus captures the current status of a Velero backup.
type BackupStatus struct {
	// Version is the backup format major version.
	// Deprecated: Please see FormatVersion
	// +optional
	Version int `json:"version,omitempty"`

	// FormatVersion is the backup format version, including major, minor, and patch version.
	// +optional
	FormatVersion string `json:"formatVersion,omitempty"`

	// Expiration is when this Backup is eligible for garbage-collection.
	// +optional
	// +nullable
	Expiration *metav1.Time `json:"expiration,omitempty"`

	// Phase is the current state of the Backup.
	// +optional
	Phase BackupPhase `json:"phase,omitempty"`

	// QueuePosition is the position of the backup in the queue.
	// Only relevant when Phase is "Queued"
	// +optional
	QueuePosition int `json:"queuePosition,omitempty"`

	// ValidationErrors is a slice of all validation errors (if
	// applicable).
	// +optional
	// +nullable
	ValidationErrors []string `json:"validationErrors,omitempty"`

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

	// VolumeSnapshotsAttempted is the total number of attempted
	// volume snapshots for this backup.
	// +optional
	VolumeSnapshotsAttempted int `json:"volumeSnapshotsAttempted,omitempty"`

	// VolumeSnapshotsCompleted is the total number of successfully
	// completed volume snapshots for this backup.
	// +optional
	VolumeSnapshotsCompleted int `json:"volumeSnapshotsCompleted,omitempty"`

	// FailureReason is an error that caused the entire backup to fail.
	// +optional
	FailureReason string `json:"failureReason,omitempty"`

	// Warnings is a count of all warning messages that were generated during
	// execution of the backup. The actual warnings are in the backup's log
	// file in object storage.
	// +optional
	Warnings int `json:"warnings,omitempty"`

	// Errors is a count of all error messages that were generated during
	// execution of the backup.  The actual errors are in the backup's log
	// file in object storage.
	// +optional
	Errors int `json:"errors,omitempty"`

	// Progress contains information about the backup's execution progress. Note
	// that this information is best-effort only -- if Velero fails to update it
	// during a backup for any reason, it may be inaccurate/stale.
	// +optional
	// +nullable
	Progress *BackupProgress `json:"progress,omitempty"`

	// CSIVolumeSnapshotsAttempted is the total number of attempted
	// CSI VolumeSnapshots for this backup.
	// +optional
	CSIVolumeSnapshotsAttempted int `json:"csiVolumeSnapshotsAttempted,omitempty"`

	// CSIVolumeSnapshotsCompleted is the total number of successfully
	// completed CSI VolumeSnapshots for this backup.
	// +optional
	CSIVolumeSnapshotsCompleted int `json:"csiVolumeSnapshotsCompleted,omitempty"`

	// BackupItemOperationsAttempted is the total number of attempted
	// async BackupItemAction operations for this backup.
	// +optional
	BackupItemOperationsAttempted int `json:"backupItemOperationsAttempted,omitempty"`

	// BackupItemOperationsCompleted is the total number of successfully completed
	// async BackupItemAction operations for this backup.
	// +optional
	BackupItemOperationsCompleted int `json:"backupItemOperationsCompleted,omitempty"`

	// BackupItemOperationsFailed is the total number of async
	// BackupItemAction operations for this backup which ended with an error.
	// +optional
	BackupItemOperationsFailed int `json:"backupItemOperationsFailed,omitempty"`

	// HookStatus contains information about the status of the hooks.
	// +optional
	// +nullable
	HookStatus *HookStatus `json:"hookStatus,omitempty"`
}

// BackupProgress stores information about the progress of a Backup's execution.
type BackupProgress struct {
	// TotalItems is the total number of items to be backed up. This number may change
	// throughout the execution of the backup due to plugins that return additional related
	// items to back up, the velero.io/exclude-from-backup label, and various other
	// filters that happen as items are processed.
	// +optional
	TotalItems int `json:"totalItems,omitempty"`

	// ItemsBackedUp is the number of items that have actually been written to the
	// backup tarball so far.
	// +optional
	ItemsBackedUp int `json:"itemsBackedUp,omitempty"`
}

// HookStatus stores information about the status of the hooks.
type HookStatus struct {
	// HooksAttempted is the total number of attempted hooks
	// Specifically, HooksAttempted represents the number of hooks that failed to execute
	// and the number of hooks that executed successfully.
	// +optional
	HooksAttempted int `json:"hooksAttempted,omitempty"`

	// HooksFailed is the total number of hooks which ended with an error
	// +optional
	HooksFailed int `json:"hooksFailed,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:rbac:groups=velero.io,resources=backups,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=velero.io,resources=backups/status,verbs=get;update;patch

// Backup is a Velero resource that represents the capture of Kubernetes
// cluster state at a point in time (API objects and associated volume state).
type Backup struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec BackupSpec `json:"spec,omitempty"`

	// +optional
	Status BackupStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BackupList is a list of Backups.
type BackupList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Backup `json:"items"`
}
