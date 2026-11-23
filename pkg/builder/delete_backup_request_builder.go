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

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// DeleteBackupRequestBuilder builds DeleteBackupRequest objects
type DeleteBackupRequestBuilder struct {
	object *velerov1api.DeleteBackupRequest
}

// ForDeleteBackupRequest is the constructor for a DeleteBackupRequestBuilder.
func ForDeleteBackupRequest(ns, name string) *DeleteBackupRequestBuilder {
	return &DeleteBackupRequestBuilder{
		object: &velerov1api.DeleteBackupRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "DeleteBackupRequest",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built DeleteBackupRequest.
func (b *DeleteBackupRequestBuilder) Result() *velerov1api.DeleteBackupRequest {
	return b.object
}

// ObjectMeta applies functional options to the DeleteBackupRequest's ObjectMeta.
func (b *DeleteBackupRequestBuilder) ObjectMeta(opts ...ObjectMetaOpt) *DeleteBackupRequestBuilder {
	for _, opt := range opts {
		opt(b.object)
	}
	return b
}

// BackupName sets the DeleteBackupRequest's backup name.
func (b *DeleteBackupRequestBuilder) BackupName(name string) *DeleteBackupRequestBuilder {
	b.object.Spec.BackupName = name
	return b
}

// Phase sets the DeleteBackupRequest's phase.
func (b *DeleteBackupRequestBuilder) Phase(phase velerov1api.DeleteBackupRequestPhase) *DeleteBackupRequestBuilder {
	b.object.Status.Phase = phase
	return b
}

// Errors sets the DeleteBackupRequest's errors.
func (b *DeleteBackupRequestBuilder) Errors(errors ...string) *DeleteBackupRequestBuilder {
	b.object.Status.Errors = errors
	return b
}
