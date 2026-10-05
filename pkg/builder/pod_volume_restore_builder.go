/*
Copyright 2023 the Velero contributors.

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

// PodVolumeRestoreBuilder builds PodVolumeRestore objects.
type PodVolumeRestoreBuilder struct {
	object *velerov1api.PodVolumeRestore
}

// ForPodVolumeRestore is the constructor for a PodVolumeRestoreBuilder.
func ForPodVolumeRestore(ns, name string) *PodVolumeRestoreBuilder {
	return &PodVolumeRestoreBuilder{
		object: &velerov1api.PodVolumeRestore{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "PodVolumeRestore",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built PodVolumeRestore.
func (b *PodVolumeRestoreBuilder) Result() *velerov1api.PodVolumeRestore {
	return b.object
}

// ObjectMeta applies functional options to the PodVolumeRestore's ObjectMeta.
func (b *PodVolumeRestoreBuilder) ObjectMeta(opts ...ObjectMetaOpt) *PodVolumeRestoreBuilder {
	for _, opt := range opts {
		opt(b.object)
	}
	return b
}

// Phase sets the PodVolumeRestore's phase.
func (b *PodVolumeRestoreBuilder) Phase(phase velerov1api.PodVolumeRestorePhase) *PodVolumeRestoreBuilder {
	b.object.Status.Phase = phase
	return b
}

// RestoreType sets the PodVolumeRestore's RestoreType.
func (b *PodVolumeRestoreBuilder) RestoreType(restoreType string) *PodVolumeRestoreBuilder {
	b.object.Spec.RestoreType = restoreType
	return b
}

// Progress sets the PodVolumeRestore's Progress.
func (b *PodVolumeRestoreBuilder) Progress(progress shared.DataMoveOperationProgress) *PodVolumeRestoreBuilder {
	b.object.Status.Progress = progress
	return b
}

// TotalBytes sets the PodVolumeRestore's TotalBytes.
func (b *PodVolumeRestoreBuilder) TotalBytes(totalBytes int64) *PodVolumeRestoreBuilder {
	b.object.Status.Progress.TotalBytes = totalBytes
	return b
}

// IncrementalBytes sets the PodVolumeRestore's IncrementalBytes.
func (b *PodVolumeRestoreBuilder) IncrementalBytes(incrementalBytes int64) *PodVolumeRestoreBuilder {
	b.object.Status.IncrementalBytes = &incrementalBytes
	return b
}

// BackupStorageLocation sets the PodVolumeRestore's backup storage location.
func (b *PodVolumeRestoreBuilder) BackupStorageLocation(name string) *PodVolumeRestoreBuilder {
	b.object.Spec.BackupStorageLocation = name
	return b
}

// SnapshotID sets the PodVolumeRestore's snapshot ID.
func (b *PodVolumeRestoreBuilder) SnapshotID(snapshotID string) *PodVolumeRestoreBuilder {
	b.object.Spec.SnapshotID = snapshotID
	return b
}

// PodName sets the name of the pod associated with this PodVolumeRestore.
func (b *PodVolumeRestoreBuilder) PodName(name string) *PodVolumeRestoreBuilder {
	b.object.Spec.Pod.Name = name
	return b
}

// PodNamespace sets the name of the pod associated with this PodVolumeRestore.
func (b *PodVolumeRestoreBuilder) PodNamespace(ns string) *PodVolumeRestoreBuilder {
	b.object.Spec.Pod.Namespace = ns
	return b
}

// Volume sets the name of the volume associated with this PodVolumeRestore.
func (b *PodVolumeRestoreBuilder) Volume(volume string) *PodVolumeRestoreBuilder {
	b.object.Spec.Volume = volume
	return b
}

// UploaderType sets the type of uploader to use for this PodVolumeRestore.
func (b *PodVolumeRestoreBuilder) UploaderType(uploaderType string) *PodVolumeRestoreBuilder {
	b.object.Spec.UploaderType = uploaderType
	return b
}

// OwnerReference sets the OwnerReference for this PodVolumeRestore.
func (b *PodVolumeRestoreBuilder) OwnerReference(ownerRef []metav1.OwnerReference) *PodVolumeRestoreBuilder {
	b.object.OwnerReferences = ownerRef
	return b
}

// Cancel sets the DataDownload's Cancel.
func (b *PodVolumeRestoreBuilder) Cancel(cancel bool) *PodVolumeRestoreBuilder {
	b.object.Spec.Cancel = cancel
	return b
}

// AcceptedTimestamp sets the PodVolumeRestore's AcceptedTimestamp.
func (b *PodVolumeRestoreBuilder) AcceptedTimestamp(acceptedTimestamp *metav1.Time) *PodVolumeRestoreBuilder {
	b.object.Status.AcceptedTimestamp = acceptedTimestamp
	return b
}

// Finalizers sets the PodVolumeRestore's Finalizers.
func (b *PodVolumeRestoreBuilder) Finalizers(finalizers []string) *PodVolumeRestoreBuilder {
	b.object.Finalizers = finalizers
	return b
}

// Message sets the PodVolumeRestore's Message.
func (b *PodVolumeRestoreBuilder) Message(msg string) *PodVolumeRestoreBuilder {
	b.object.Status.Message = msg
	return b
}

// Message sets the PodVolumeRestore's Node.
func (b *PodVolumeRestoreBuilder) Node(node string) *PodVolumeRestoreBuilder {
	b.object.Status.Node = node
	return b
}

// Labels sets the PodVolumeRestoreBuilder's Labels.
func (b *PodVolumeRestoreBuilder) Labels(label map[string]string) *PodVolumeRestoreBuilder {
	b.object.Labels = label
	return b
}
