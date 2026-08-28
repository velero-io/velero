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
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
)

// DataUploadBuilder builds DataUpload objects
type DataUploadBuilder struct {
	object *velerov2alpha1api.DataUpload
}

// ForDataUpload is the constructor for a DataUploadBuilder.
func ForDataUpload(ns, name string) *DataUploadBuilder {
	return &DataUploadBuilder{
		object: &velerov2alpha1api.DataUpload{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov2alpha1api.SchemeGroupVersion.String(),
				Kind:       "DataUpload",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built DataUpload.
func (d *DataUploadBuilder) Result() *velerov2alpha1api.DataUpload {
	return d.object
}

// BackupStorageLocation sets the DataUpload's backup storage location.
func (d *DataUploadBuilder) BackupStorageLocation(name string) *DataUploadBuilder {
	d.object.Spec.BackupStorageLocation = name
	return d
}

// Phase sets the DataUpload's phase.
func (d *DataUploadBuilder) Phase(phase velerov2alpha1api.DataUploadPhase) *DataUploadBuilder {
	d.object.Status.Phase = phase
	return d
}

// SnapshotID sets the DataUpload's SnapshotID.
func (d *DataUploadBuilder) SnapshotID(id string) *DataUploadBuilder {
	d.object.Status.SnapshotID = id
	return d
}

// DataMover sets the DataUpload's DataMover.
func (d *DataUploadBuilder) DataMover(dataMover string) *DataUploadBuilder {
	d.object.Spec.DataMover = dataMover
	return d
}

// SourceNamespace sets the DataUpload's SourceNamespace.
func (d *DataUploadBuilder) SourceNamespace(sourceNamespace string) *DataUploadBuilder {
	d.object.Spec.SourceNamespace = sourceNamespace
	return d
}

// SourcePVC sets the DataUpload's SourcePVC.
func (d *DataUploadBuilder) SourcePVC(sourcePVC string) *DataUploadBuilder {
	d.object.Spec.SourcePVC = sourcePVC
	return d
}

// SnapshotType sets the DataUpload's SnapshotType.
func (d *DataUploadBuilder) SnapshotType(SnapshotType velerov2alpha1api.SnapshotType) *DataUploadBuilder {
	d.object.Spec.SnapshotType = SnapshotType
	return d
}

// Cancel sets the DataUpload's Cancel.
func (d *DataUploadBuilder) Cancel(cancel bool) *DataUploadBuilder {
	d.object.Spec.Cancel = cancel
	return d
}

// OperationTimeout sets the DataUpload's OperationTimeout.
func (d *DataUploadBuilder) OperationTimeout(timeout metav1.Duration) *DataUploadBuilder {
	d.object.Spec.OperationTimeout = timeout
	return d
}

// DataMoverConfig sets the DataUpload's DataMoverConfig.
func (d *DataUploadBuilder) DataMoverConfig(config map[string]string) *DataUploadBuilder {
	d.object.Spec.DataMoverConfig = config
	return d
}

// CSISnapshot sets the DataUpload's CSISnapshot.
func (d *DataUploadBuilder) CSISnapshot(cSISnapshot *velerov2alpha1api.CSISnapshotSpec) *DataUploadBuilder {
	d.object.Spec.CSISnapshot = cSISnapshot
	return d
}

// StartTimestamp sets the DataUpload's StartTimestamp.
func (d *DataUploadBuilder) StartTimestamp(startTimestamp *metav1.Time) *DataUploadBuilder {
	d.object.Status.StartTimestamp = startTimestamp
	return d
}

// CompletionTimestamp sets the DataUpload's StartTimestamp.
func (d *DataUploadBuilder) CompletionTimestamp(completionTimestamp *metav1.Time) *DataUploadBuilder {
	d.object.Status.CompletionTimestamp = completionTimestamp
	return d
}

// Labels sets the DataUpload's Labels.
func (d *DataUploadBuilder) Labels(labels map[string]string) *DataUploadBuilder {
	d.object.Labels = labels
	return d
}

// Annotations sets the DataUpload's Annotations.
func (d *DataUploadBuilder) Annotations(annotations map[string]string) *DataUploadBuilder {
	d.object.Annotations = annotations
	return d
}

// Progress sets the DataUpload's Progress.
func (d *DataUploadBuilder) Progress(progress shared.DataMoveOperationProgress) *DataUploadBuilder {
	d.object.Status.Progress = progress
	return d
}

// Node sets the DataUpload's Node.
func (d *DataUploadBuilder) Node(node string) *DataUploadBuilder {
	d.object.Status.Node = node
	return d
}

// NodeOS sets the DataUpload's Node OS.
func (d *DataUploadBuilder) NodeOS(nodeOS velerov2alpha1api.NodeOS) *DataUploadBuilder {
	d.object.Status.NodeOS = nodeOS
	return d
}

// AcceptedByNode sets the DataUpload's AcceptedByNode.
func (d *DataUploadBuilder) AcceptedByNode(node string) *DataUploadBuilder {
	d.object.Status.AcceptedByNode = node
	return d
}

// AcceptedTimestamp sets the DataUpload's AcceptedTimestamp.
func (d *DataUploadBuilder) AcceptedTimestamp(acceptedTimestamp *metav1.Time) *DataUploadBuilder {
	d.object.Status.AcceptedTimestamp = acceptedTimestamp
	return d
}

// Finalizers sets the DataUpload's Finalizers.
func (d *DataUploadBuilder) Finalizers(finalizers []string) *DataUploadBuilder {
	d.object.Finalizers = finalizers
	return d
}

// Message sets the DataUpload's Message.
func (d *DataUploadBuilder) Message(msg string) *DataUploadBuilder {
	d.object.Status.Message = msg
	return d
}
