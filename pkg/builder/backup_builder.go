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

package builder

import (
	"fmt"
	"time"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/label"

	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

/*

Example usage:

var backup = builder.ForBackup("velero", "backup-1").
	ObjectMeta(
		builder.WithLabels("foo", "bar"),
		builder.WithClusterName("cluster-1"),
	).
	SnapshotVolumes(true).
	Result()

*/

// BackupBuilder builds Backup objects.
type BackupBuilder struct {
	object *velerov1api.Backup
}

// ForBackup is the constructor for a BackupBuilder.
func ForBackup(ns, name string) *BackupBuilder {
	return &BackupBuilder{
		object: &velerov1api.Backup{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "Backup",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built Backup.
func (b *BackupBuilder) Result() *velerov1api.Backup {
	return b.object
}

// ObjectMeta applies functional options to the Backup's ObjectMeta.
func (b *BackupBuilder) ObjectMeta(opts ...ObjectMetaOpt) *BackupBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

// FromSchedule sets the Backup's spec and labels from the Schedule template
func (b *BackupBuilder) FromSchedule(schedule *velerov1api.Schedule) *BackupBuilder {
	var labels map[string]string

	// Check if there's explicit Labels defined in the Schedule object template
	// and if present then copy it to the backup object.
	if schedule.Spec.Template.Metadata.Labels != nil {
		logger := logging.DefaultLogger(logging.LogLevelFlag(logrus.InfoLevel).Parse(), logging.NewFormatFlag().Parse())
		labels = schedule.Spec.Template.Metadata.Labels
		logger.WithFields(logrus.Fields{
			"backup": fmt.Sprintf("%s/%s", b.object.GetNamespace(), b.object.GetName()),
			"labels": schedule.Spec.Template.Metadata.Labels,
		}).Info("Schedule.template.metadata.labels set - using those labels instead of schedule.labels for backup object")
	} else {
		labels = schedule.Labels
		logrus.WithFields(logrus.Fields{
			"backup": fmt.Sprintf("%s/%s", b.object.GetNamespace(), b.object.GetName()),
			"labels": schedule.Labels,
		}).Info("No Schedule.template.metadata.labels set - using Schedule.labels for backup object")
	}
	if labels == nil {
		labels = make(map[string]string)
	}
	labels[velerov1api.ScheduleNameLabel] = label.GetValidName(schedule.Name)

	b.object.Spec = schedule.Spec.Template
	b.ObjectMeta(WithLabelsMap(labels))

	if schedule.Annotations != nil {
		b.ObjectMeta(WithAnnotationsMap(schedule.Annotations))
	}

	if boolptr.IsSetToTrue(schedule.Spec.UseOwnerReferencesInBackup) {
		b.object.SetOwnerReferences([]metav1.OwnerReference{
			{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "Schedule",
				Name:       schedule.Name,
				UID:        schedule.UID,
				Controller: boolptr.True(),
			},
		})
	}

	if schedule.Spec.Template.ResourcePolicy != nil {
		b.ResourcePolicies(schedule.Spec.Template.ResourcePolicy.Name)
	}

	return b
}

// IncludedNamespaces sets the Backup's included namespaces.
func (b *BackupBuilder) IncludedNamespaces(namespaces ...string) *BackupBuilder {
	b.object.Spec.IncludedNamespaces = namespaces
	return b
}

// ExcludedNamespaces sets the Backup's excluded namespaces.
func (b *BackupBuilder) ExcludedNamespaces(namespaces ...string) *BackupBuilder {
	b.object.Spec.ExcludedNamespaces = namespaces
	return b
}

// IncludedResources sets the Backup's included resources.
func (b *BackupBuilder) IncludedResources(resources ...string) *BackupBuilder {
	b.object.Spec.IncludedResources = resources
	return b
}

// ExcludedResources sets the Backup's excluded resources.
func (b *BackupBuilder) ExcludedResources(resources ...string) *BackupBuilder {
	b.object.Spec.ExcludedResources = resources
	return b
}

// IncludedClusterScopedResources sets the Backup's included cluster resources.
func (b *BackupBuilder) IncludedClusterScopedResources(resources ...string) *BackupBuilder {
	b.object.Spec.IncludedClusterScopedResources = resources
	return b
}

// ExcludedClusterScopedResources sets the Backup's excluded cluster resources.
func (b *BackupBuilder) ExcludedClusterScopedResources(resources ...string) *BackupBuilder {
	b.object.Spec.ExcludedClusterScopedResources = resources
	return b
}

// IncludedNamespaceScopedResources sets the Backup's included namespaced resources.
func (b *BackupBuilder) IncludedNamespaceScopedResources(resources ...string) *BackupBuilder {
	b.object.Spec.IncludedNamespaceScopedResources = resources
	return b
}

// ExcludedNamespaceScopedResources sets the Backup's excluded namespaced resources.
func (b *BackupBuilder) ExcludedNamespaceScopedResources(resources ...string) *BackupBuilder {
	b.object.Spec.ExcludedNamespaceScopedResources = resources
	return b
}

// IncludeClusterResources sets the Backup's "include cluster resources" flag.
func (b *BackupBuilder) IncludeClusterResources(val bool) *BackupBuilder {
	b.object.Spec.IncludeClusterResources = &val
	return b
}

// LabelSelector sets the Backup's label selector.
func (b *BackupBuilder) LabelSelector(selector *metav1.LabelSelector) *BackupBuilder {
	b.object.Spec.LabelSelector = selector
	return b
}

// OrLabelSelector sets the Backup's orLabelSelector set.
func (b *BackupBuilder) OrLabelSelector(orSelectors []*metav1.LabelSelector) *BackupBuilder {
	b.object.Spec.OrLabelSelectors = orSelectors
	return b
}

// SnapshotVolumes sets the Backup's "snapshot volumes" flag.
func (b *BackupBuilder) SnapshotVolumes(val bool) *BackupBuilder {
	b.object.Spec.SnapshotVolumes = &val
	return b
}

// DefaultVolumesToFsBackup sets the Backup's "DefaultVolumesToFsBackup" flag.
func (b *BackupBuilder) DefaultVolumesToFsBackup(val bool) *BackupBuilder {
	b.object.Spec.DefaultVolumesToFsBackup = &val
	return b
}

// DefaultVolumesToRestic sets the Backup's "DefaultVolumesToRestic" flag.
func (b *BackupBuilder) DefaultVolumesToRestic(val bool) *BackupBuilder {
	b.object.Spec.DefaultVolumesToRestic = &val
	return b
}

// Phase sets the Backup's phase.
func (b *BackupBuilder) Phase(phase velerov1api.BackupPhase) *BackupBuilder {
	b.object.Status.Phase = phase
	return b
}

// Phase sets the Backup's queue position.
func (b *BackupBuilder) QueuePosition(queuePos int) *BackupBuilder {
	b.object.Status.QueuePosition = queuePos
	return b
}

// StorageLocation sets the Backup's storage location.
func (b *BackupBuilder) StorageLocation(location string) *BackupBuilder {
	b.object.Spec.StorageLocation = location
	return b
}

// VolumeSnapshotLocations sets the Backup's volume snapshot locations.
func (b *BackupBuilder) VolumeSnapshotLocations(locations ...string) *BackupBuilder {
	b.object.Spec.VolumeSnapshotLocations = locations
	return b
}

// TTL sets the Backup's TTL.
func (b *BackupBuilder) TTL(ttl time.Duration) *BackupBuilder {
	b.object.Spec.TTL.Duration = ttl
	return b
}

// VolumeGroupSnapshotLabelKey sets the label key to group PVCs for VolumeGroupSnapshot.
func (b *BackupBuilder) VolumeGroupSnapshotLabelKey(labelKey string) *BackupBuilder {
	b.object.Spec.VolumeGroupSnapshotLabelKey = labelKey
	return b
}

// Expiration sets the Backup's expiration.
func (b *BackupBuilder) Expiration(val time.Time) *BackupBuilder {
	b.object.Status.Expiration = &metav1.Time{Time: val}
	return b
}

// StartTimestamp sets the Backup's start timestamp.
func (b *BackupBuilder) StartTimestamp(val time.Time) *BackupBuilder {
	b.object.Status.StartTimestamp = &metav1.Time{Time: val}
	return b
}

// CompletionTimestamp sets the Backup's completion timestamp.
func (b *BackupBuilder) CompletionTimestamp(val time.Time) *BackupBuilder {
	b.object.Status.CompletionTimestamp = &metav1.Time{Time: val}
	return b
}

// Hooks sets the Backup's hooks.
func (b *BackupBuilder) Hooks(hooks velerov1api.BackupHooks) *BackupBuilder {
	b.object.Spec.Hooks = hooks
	return b
}

// OrderedResources sets the Backup's OrderedResources
func (b *BackupBuilder) OrderedResources(orders map[string]string) *BackupBuilder {
	b.object.Spec.OrderedResources = orders
	return b
}

// CSISnapshotTimeout sets the Backup's CSISnapshotTimeout
func (b *BackupBuilder) CSISnapshotTimeout(timeout time.Duration) *BackupBuilder {
	b.object.Spec.CSISnapshotTimeout.Duration = timeout
	return b
}

// ItemOperationTimeout sets the Backup's ItemOperationTimeout
func (b *BackupBuilder) ItemOperationTimeout(timeout time.Duration) *BackupBuilder {
	b.object.Spec.ItemOperationTimeout.Duration = timeout
	return b
}

// ResourcePolicies sets the Backup's resource polices.
func (b *BackupBuilder) ResourcePolicies(name string) *BackupBuilder {
	b.object.Spec.ResourcePolicy = &corev1api.TypedLocalObjectReference{Kind: resourcepolicies.ConfigmapRefType, Name: name}
	return b
}

// SnapshotMoveData sets the Backup's "snapshot move data" flag.
func (b *BackupBuilder) SnapshotMoveData(val bool) *BackupBuilder {
	b.object.Spec.SnapshotMoveData = &val
	return b
}

// DataMover sets the Backup's data mover
func (b *BackupBuilder) DataMover(name string) *BackupBuilder {
	b.object.Spec.DataMover = name
	return b
}

// ParallelFilesUpload sets the Backup's uploader parallel uploads
func (b *BackupBuilder) ParallelFilesUpload(parallel int) *BackupBuilder {
	if b.object.Spec.UploaderConfig == nil {
		b.object.Spec.UploaderConfig = &velerov1api.UploaderConfigForBackup{}
	}
	b.object.Spec.UploaderConfig.ParallelFilesUpload = parallel
	return b
}

// WithStatus sets the Backup's status.
func (b *BackupBuilder) WithStatus(status velerov1api.BackupStatus) *BackupBuilder {
	b.object.Status = status
	return b
}
