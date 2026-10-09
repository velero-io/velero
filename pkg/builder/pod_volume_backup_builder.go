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

package builder

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// PodVolumeBackupBuilder builds PodVolumeBackup objects
type PodVolumeBackupBuilder struct {
	object *velerov1api.PodVolumeBackup
}

// ForPodVolumeBackup is the constructor for a PodVolumeBackupBuilder.
func ForPodVolumeBackup(ns, name string) *PodVolumeBackupBuilder {
	return &PodVolumeBackupBuilder{
		object: &velerov1api.PodVolumeBackup{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "PodVolumeBackup",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built PodVolumeBackup.
func (b *PodVolumeBackupBuilder) Result() *velerov1api.PodVolumeBackup {
	return b.object
}

// ObjectMeta applies functional options to the PodVolumeBackup's ObjectMeta.
func (b *PodVolumeBackupBuilder) ObjectMeta(opts ...ObjectMetaOpt) *PodVolumeBackupBuilder {
	for _, opt := range opts {
		opt(b.object)
	}
	return b
}

// Phase sets the PodVolumeBackup's phase.
func (b *PodVolumeBackupBuilder) Phase(phase velerov1api.PodVolumeBackupPhase) *PodVolumeBackupBuilder {
	b.object.Status.Phase = phase
	return b
}

// Progress sets the PodVolumeBackup's Progress.
func (b *PodVolumeBackupBuilder) Progress(progress shared.DataMoveOperationProgress) *PodVolumeBackupBuilder {
	b.object.Status.Progress = progress
	return b
}

// TotalBytes sets the PodVolumeBackup's TotalBytes.
func (b *PodVolumeBackupBuilder) TotalBytes(totalBytes int64) *PodVolumeBackupBuilder {
	b.object.Status.Progress.TotalBytes = totalBytes
	return b
}

// IncrementalBytes sets the PodVolumeBackup's IncrementalBytes.
func (b *PodVolumeBackupBuilder) IncrementalBytes(incrementalBytes int64) *PodVolumeBackupBuilder {
	b.object.Status.IncrementalBytes = &incrementalBytes
	return b
}

// Node sets the PodVolumeBackup's node name.
func (b *PodVolumeBackupBuilder) Node(name string) *PodVolumeBackupBuilder {
	b.object.Spec.Node = name
	return b
}

// BackupStorageLocation sets the PodVolumeBackup's backup storage location.
func (b *PodVolumeBackupBuilder) BackupStorageLocation(name string) *PodVolumeBackupBuilder {
	b.object.Spec.BackupStorageLocation = name
	return b
}

// SnapshotID sets the PodVolumeBackup's snapshot ID.
func (b *PodVolumeBackupBuilder) SnapshotID(snapshotID string) *PodVolumeBackupBuilder {
	b.object.Status.SnapshotID = snapshotID
	return b
}

func (b *PodVolumeBackupBuilder) StartTimestamp(startTimestamp *metav1.Time) *PodVolumeBackupBuilder {
	b.object.Status.StartTimestamp = startTimestamp
	return b
}

func (b *PodVolumeBackupBuilder) CompletionTimestamp(completionTimestamp *metav1.Time) *PodVolumeBackupBuilder {
	b.object.Status.CompletionTimestamp = completionTimestamp
	return b
}

// PodName sets the name of the pod associated with this PodVolumeBackup.
func (b *PodVolumeBackupBuilder) PodName(name string) *PodVolumeBackupBuilder {
	b.object.Spec.Pod.Name = name
	return b
}

// PodNamespace sets the name of the pod associated with this PodVolumeBackup.
func (b *PodVolumeBackupBuilder) PodNamespace(ns string) *PodVolumeBackupBuilder {
	b.object.Spec.Pod.Namespace = ns
	return b
}

// Volume sets the name of the volume associated with this PodVolumeBackup.
func (b *PodVolumeBackupBuilder) Volume(volume string) *PodVolumeBackupBuilder {
	b.object.Spec.Volume = volume
	return b
}

// UploaderType sets the type of uploader to use for this PodVolumeBackup.
func (b *PodVolumeBackupBuilder) UploaderType(uploaderType string) *PodVolumeBackupBuilder {
	b.object.Spec.UploaderType = uploaderType
	return b
}

// Annotations sets the PodVolumeBackup's Annotations.
func (b *PodVolumeBackupBuilder) Annotations(annotations map[string]string) *PodVolumeBackupBuilder {
	b.object.Annotations = annotations
	return b
}

// Cancel sets the PodVolumeBackup's Cancel.
func (b *PodVolumeBackupBuilder) Cancel(cancel bool) *PodVolumeBackupBuilder {
	b.object.Spec.Cancel = cancel
	return b
}

// AcceptedTimestamp sets the PodVolumeBackup's AcceptedTimestamp.
func (b *PodVolumeBackupBuilder) AcceptedTimestamp(acceptedTimestamp *metav1.Time) *PodVolumeBackupBuilder {
	b.object.Status.AcceptedTimestamp = acceptedTimestamp
	return b
}

// Finalizers sets the PodVolumeBackup's Finalizers.
func (b *PodVolumeBackupBuilder) Finalizers(finalizers []string) *PodVolumeBackupBuilder {
	b.object.Finalizers = finalizers
	return b
}

// Message sets the PodVolumeBackup's Message.
func (b *PodVolumeBackupBuilder) Message(msg string) *PodVolumeBackupBuilder {
	b.object.Status.Message = msg
	return b
}

// OwnerReference sets the PodVolumeBackup's OwnerReference.
func (b *PodVolumeBackupBuilder) OwnerReference(ref metav1.OwnerReference) *PodVolumeBackupBuilder {
	b.object.OwnerReferences = append(b.object.OwnerReferences, ref)
	return b
}

// Labels sets the PodVolumeBackup's Labels.
func (b *PodVolumeBackupBuilder) Labels(label map[string]string) *PodVolumeBackupBuilder {
	b.object.Labels = label
	return b
}
