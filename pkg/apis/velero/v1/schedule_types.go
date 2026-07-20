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
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScheduleSpec defines the specification for a Velero schedule
type ScheduleSpec struct {
	// Template is the definition of the Backup to be run
	// on the provided schedule
	Template BackupSpec `json:"template"`

	// Schedule is a Cron expression defining when to run
	// the Backup.
	Schedule string `json:"schedule"`

	// UseOwnerReferencesBackup specifies whether to use
	// OwnerReferences on backups created by this Schedule.
	// +optional
	// +nullable
	UseOwnerReferencesInBackup *bool `json:"useOwnerReferencesInBackup,omitempty"`

	// Paused specifies whether the schedule is paused or not
	// +optional
	Paused bool `json:"paused,omitempty"`

	// SkipImmediately specifies whether to skip backup if schedule is due immediately from `schedule.status.lastBackup` timestamp when schedule is unpaused or if schedule is new.
	// If true, backup will be skipped immediately when schedule is unpaused if it is due based on .Status.LastBackupTimestamp or schedule is new, and will run at next schedule time.
	// If false, backup will not be skipped immediately when schedule is unpaused, but will run at next schedule time.
	// If empty, will follow server configuration (default: false).
	// +optional
	SkipImmediately *bool `json:"skipImmediately,omitempty"`
}

// SchedulePhase is a string representation of the lifecycle phase
// of a Velero schedule
// +kubebuilder:validation:Enum=New;Enabled;FailedValidation
type SchedulePhase string

const (
	// SchedulePhaseNew means the schedule has been created but not
	// yet processed by the ScheduleController
	SchedulePhaseNew SchedulePhase = "New"

	// SchedulePhaseEnabled means the schedule has been validated and
	// will now be triggering backups according to the schedule spec.
	SchedulePhaseEnabled SchedulePhase = "Enabled"

	// SchedulePhaseFailedValidation means the schedule has failed
	// the controller's validations and therefore will not trigger backups.
	SchedulePhaseFailedValidation SchedulePhase = "FailedValidation"
)

// ScheduleStatus captures the current state of a Velero schedule
type ScheduleStatus struct {
	// Phase is the current phase of the Schedule
	// +optional
	Phase SchedulePhase `json:"phase,omitempty"`

	// LastBackup is the last time a Backup was run for this
	// Schedule schedule
	// +optional
	// +nullable
	LastBackup *metav1.Time `json:"lastBackup,omitempty"`

	// LastSkipped is the last time a Schedule was skipped
	// +optional
	// +nullable
	LastSkipped *metav1.Time `json:"lastSkipped,omitempty"`

	// ValidationErrors is a slice of all validation errors (if
	// applicable)
	// +optional
	ValidationErrors []string `json:"validationErrors,omitempty"`
}

// TODO(2.0) After converting all resources to use the runtime-controller client, the genclient and k8s:deepcopy markers will no longer be needed and should be removed.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="Status of the schedule"
// +kubebuilder:printcolumn:name="Schedule",type="string",JSONPath=".spec.schedule",description="A Cron expression defining when to run the Backup"
// +kubebuilder:printcolumn:name="LastBackup",type="date",JSONPath=".status.lastBackup",description="The last time a Backup was run for this schedule"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Paused",type="boolean",JSONPath=".spec.paused"
// +kubebuilder:resource:shortName=sched

// Schedule is a Velero resource that represents a pre-scheduled or
// periodic Backup that should be run.
type Schedule struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata"`

	// +optional
	Spec ScheduleSpec `json:"spec,omitempty"`

	// +optional
	Status ScheduleStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true

// ScheduleList is a list of Schedules.
type ScheduleList struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Schedule `json:"items"`
}

// TimestampedName returns the default backup name format based on the schedule
func (s *Schedule) TimestampedName(timestamp time.Time) string {
	return fmt.Sprintf("%s-%s", s.Name, timestamp.Format("20060102150405"))
}
