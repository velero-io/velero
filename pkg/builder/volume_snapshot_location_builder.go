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

package builder

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1api "k8s.io/api/core/v1"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// VolumeSnapshotLocationBuilder builds VolumeSnapshotLocation objects.
type VolumeSnapshotLocationBuilder struct {
	object *velerov1api.VolumeSnapshotLocation
}

// ForVolumeSnapshotLocation is the constructor for a VolumeSnapshotLocationBuilder.
func ForVolumeSnapshotLocation(ns, name string) *VolumeSnapshotLocationBuilder {
	return &VolumeSnapshotLocationBuilder{
		object: &velerov1api.VolumeSnapshotLocation{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "VolumeSnapshotLocation",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built VolumeSnapshotLocation.
func (b *VolumeSnapshotLocationBuilder) Result() *velerov1api.VolumeSnapshotLocation {
	return b.object
}

// ObjectMeta applies functional options to the VolumeSnapshotLocation's ObjectMeta.
func (b *VolumeSnapshotLocationBuilder) ObjectMeta(opts ...ObjectMetaOpt) *VolumeSnapshotLocationBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

// Provider sets the VolumeSnapshotLocation's provider.
func (b *VolumeSnapshotLocationBuilder) Provider(name string) *VolumeSnapshotLocationBuilder {
	b.object.Spec.Provider = name
	return b
}

// Credential sets the VolumeSnapshotLocation's credential selector.
func (b *VolumeSnapshotLocationBuilder) Credential(selector *corev1api.SecretKeySelector) *VolumeSnapshotLocationBuilder {
	b.object.Spec.Credential = selector
	return b
}
