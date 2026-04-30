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
	"time"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// BackupStorageLocationBuilder builds BackupStorageLocation objects.
type BackupStorageLocationBuilder struct {
	object *velerov1api.BackupStorageLocation
}

// ForBackupStorageLocation is the constructor for a BackupStorageLocationBuilder.
func ForBackupStorageLocation(ns, name string) *BackupStorageLocationBuilder {
	return &BackupStorageLocationBuilder{
		object: &velerov1api.BackupStorageLocation{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "BackupStorageLocation",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built BackupStorageLocation.
func (b *BackupStorageLocationBuilder) Result() *velerov1api.BackupStorageLocation {
	return b.object
}

// ObjectMeta applies functional options to the BackupStorageLocation's ObjectMeta.
func (b *BackupStorageLocationBuilder) ObjectMeta(opts ...ObjectMetaOpt) *BackupStorageLocationBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

// Provider sets the BackupStorageLocation's provider.
func (b *BackupStorageLocationBuilder) Provider(name string) *BackupStorageLocationBuilder {
	b.object.Spec.Provider = name
	return b
}

// Bucket sets the BackupStorageLocation's object storage bucket.
func (b *BackupStorageLocationBuilder) Bucket(val string) *BackupStorageLocationBuilder {
	if b.object.Spec.ObjectStorage == nil {
		b.object.Spec.ObjectStorage = new(velerov1api.ObjectStorageLocation)
	}
	b.object.Spec.ObjectStorage.Bucket = val
	return b
}

// Prefix sets the BackupStorageLocation's object storage prefix.
func (b *BackupStorageLocationBuilder) Prefix(val string) *BackupStorageLocationBuilder {
	if b.object.Spec.ObjectStorage == nil {
		b.object.Spec.ObjectStorage = new(velerov1api.ObjectStorageLocation)
	}
	b.object.Spec.ObjectStorage.Prefix = val
	return b
}

// CACert sets the BackupStorageLocation's object storage CACert.
func (b *BackupStorageLocationBuilder) CACert(val []byte) *BackupStorageLocationBuilder {
	if b.object.Spec.ObjectStorage == nil {
		b.object.Spec.ObjectStorage = new(velerov1api.ObjectStorageLocation)
	}
	b.object.Spec.ObjectStorage.CACert = val
	return b
}

// Default sets the BackupStorageLocation's is default or not
func (b *BackupStorageLocationBuilder) Default(isDefault bool) *BackupStorageLocationBuilder {
	b.object.Spec.Default = isDefault
	return b
}

// AccessMode sets the BackupStorageLocation's access mode.
func (b *BackupStorageLocationBuilder) AccessMode(accessMode velerov1api.BackupStorageLocationAccessMode) *BackupStorageLocationBuilder {
	b.object.Spec.AccessMode = accessMode
	return b
}

// ValidationFrequency sets the BackupStorageLocation's validation frequency.
func (b *BackupStorageLocationBuilder) ValidationFrequency(frequency time.Duration) *BackupStorageLocationBuilder {
	b.object.Spec.ValidationFrequency = &metav1.Duration{Duration: frequency}
	return b
}

// LastValidationTime sets the BackupStorageLocation's last validated time.
func (b *BackupStorageLocationBuilder) LastValidationTime(lastValidated time.Time) *BackupStorageLocationBuilder {
	b.object.Status.LastValidationTime = &metav1.Time{Time: lastValidated}
	return b
}

// Phase sets the BackupStorageLocation's status phase.
func (b *BackupStorageLocationBuilder) Phase(phase velerov1api.BackupStorageLocationPhase) *BackupStorageLocationBuilder {
	b.object.Status.Phase = phase
	return b
}

// Credential sets the BackupStorageLocation's credential selector.
func (b *BackupStorageLocationBuilder) Credential(selector *corev1api.SecretKeySelector) *BackupStorageLocationBuilder {
	b.object.Spec.Credential = selector
	return b
}
