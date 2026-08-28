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

// DataDownloadBuilder builds DataDownload objects.
type DataDownloadBuilder struct {
	object *velerov2alpha1api.DataDownload
}

// ForDataDownload is the constructor of DataDownloadBuilder
func ForDataDownload(namespace, name string) *DataDownloadBuilder {
	return &DataDownloadBuilder{
		object: &velerov2alpha1api.DataDownload{
			TypeMeta: metav1.TypeMeta{
				Kind:       "DataDownload",
				APIVersion: velerov2alpha1api.SchemeGroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		},
	}
}

// Result returns the built DataDownload.
func (d *DataDownloadBuilder) Result() *velerov2alpha1api.DataDownload {
	return d.object
}

// BackupStorageLocation sets the DataDownload's backup storage location.
func (d *DataDownloadBuilder) BackupStorageLocation(name string) *DataDownloadBuilder {
	d.object.Spec.BackupStorageLocation = name
	return d
}

// Phase sets the DataDownload's phase.
func (d *DataDownloadBuilder) Phase(phase velerov2alpha1api.DataDownloadPhase) *DataDownloadBuilder {
	d.object.Status.Phase = phase
	return d
}

// SnapshotID sets the DataDownload's SnapshotID.
func (d *DataDownloadBuilder) SnapshotID(id string) *DataDownloadBuilder {
	d.object.Spec.SnapshotID = id
	return d
}

// DataMover sets the DataDownload's DataMover.
func (d *DataDownloadBuilder) DataMover(dataMover string) *DataDownloadBuilder {
	d.object.Spec.DataMover = dataMover
	return d
}

// SourceNamespace sets the DataDownload's SourceNamespace.
func (d *DataDownloadBuilder) SourceNamespace(sourceNamespace string) *DataDownloadBuilder {
	d.object.Spec.SourceNamespace = sourceNamespace
	return d
}

// TargetVolume sets the DataDownload's TargetVolume.
func (d *DataDownloadBuilder) TargetVolume(targetVolume velerov2alpha1api.TargetVolumeSpec) *DataDownloadBuilder {
	d.object.Spec.TargetVolume = targetVolume
	return d
}

// Cancel sets the DataDownload's Cancel.
func (d *DataDownloadBuilder) Cancel(cancel bool) *DataDownloadBuilder {
	d.object.Spec.Cancel = cancel
	return d
}

// OperationTimeout sets the DataDownload's OperationTimeout.
func (d *DataDownloadBuilder) OperationTimeout(timeout metav1.Duration) *DataDownloadBuilder {
	d.object.Spec.OperationTimeout = timeout
	return d
}

// DataMoverConfig sets the DataDownload's DataMoverConfig.
func (d *DataDownloadBuilder) DataMoverConfig(config *map[string]string) *DataDownloadBuilder {
	d.object.Spec.DataMoverConfig = *config
	return d
}

// ObjectMeta applies functional options to the DataDownload's ObjectMeta.
func (d *DataDownloadBuilder) ObjectMeta(opts ...ObjectMetaOpt) *DataDownloadBuilder {
	for _, opt := range opts {
		opt(d.object)
	}

	return d
}

// Labels sets the DataDownload's Labels.
func (d *DataDownloadBuilder) Labels(labels map[string]string) *DataDownloadBuilder {
	d.object.Labels = labels
	return d
}

// Annotations sets the DataDownload's Annotations.
func (d *DataDownloadBuilder) Annotations(annotations map[string]string) *DataDownloadBuilder {
	d.object.Annotations = annotations
	return d
}

// StartTimestamp sets the DataDownload's StartTimestamp.
func (d *DataDownloadBuilder) StartTimestamp(startTime *metav1.Time) *DataDownloadBuilder {
	d.object.Status.StartTimestamp = startTime
	return d
}

// CompletionTimestamp sets the DataDownload's StartTimestamp.
func (d *DataDownloadBuilder) CompletionTimestamp(completionTimestamp *metav1.Time) *DataDownloadBuilder {
	d.object.Status.CompletionTimestamp = completionTimestamp
	return d
}

// Progress sets the DataDownload's Progress.
func (d *DataDownloadBuilder) Progress(progress shared.DataMoveOperationProgress) *DataDownloadBuilder {
	d.object.Status.Progress = progress
	return d
}

// Node sets the DataDownload's Node.
func (d *DataDownloadBuilder) Node(node string) *DataDownloadBuilder {
	d.object.Status.Node = node
	return d
}

// NodeOS sets the DataDownload's Node OS.
func (d *DataDownloadBuilder) NodeOS(nodeOS velerov2alpha1api.NodeOS) *DataDownloadBuilder {
	d.object.Spec.NodeOS = nodeOS
	return d
}

// AcceptedByNode sets the DataDownload's AcceptedByNode.
func (d *DataDownloadBuilder) AcceptedByNode(node string) *DataDownloadBuilder {
	d.object.Status.AcceptedByNode = node
	return d
}

// AcceptedTimestamp sets the DataDownload's AcceptedTimestamp.
func (d *DataDownloadBuilder) AcceptedTimestamp(acceptedTimestamp *metav1.Time) *DataDownloadBuilder {
	d.object.Status.AcceptedTimestamp = acceptedTimestamp
	return d
}

// Finalizers sets the DataDownload's Finalizers.
func (d *DataDownloadBuilder) Finalizers(finalizers []string) *DataDownloadBuilder {
	d.object.Finalizers = finalizers
	return d
}

// Message sets the DataDownload's Message.
func (d *DataDownloadBuilder) Message(msg string) *DataDownloadBuilder {
	d.object.Status.Message = msg
	return d
}
