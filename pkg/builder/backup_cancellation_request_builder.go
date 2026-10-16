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

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// BackupCancellationRequestBuilder builds BackupCancellationRequest objects.
type BackupCancellationRequestBuilder struct {
	object *velerov1api.BackupCancellationRequest
}

// ForBackupCancellationRequest is the constructor for a BackupCancellationRequestBuilder.
func ForBackupCancellationRequest(ns, name string) *BackupCancellationRequestBuilder {
	return &BackupCancellationRequestBuilder{
		object: &velerov1api.BackupCancellationRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "BackupCancellationRequest",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built BackupCancellationRequest.
func (b *BackupCancellationRequestBuilder) Result() *velerov1api.BackupCancellationRequest {
	return b.object
}

// ObjectMeta applies functional options to the BackupCancellationRequest's ObjectMeta.
func (b *BackupCancellationRequestBuilder) ObjectMeta(opts ...ObjectMetaOpt) *BackupCancellationRequestBuilder {
	for _, opt := range opts {
		opt(b.object)
	}
	return b
}

// BackupName sets the BackupCancellationRequest's backup name.
func (b *BackupCancellationRequestBuilder) BackupName(name string) *BackupCancellationRequestBuilder {
	b.object.Spec.BackupName = name
	return b
}

// DeleteBackup sets the BackupCancellationRequest's deleteBackup flag.
func (b *BackupCancellationRequestBuilder) DeleteBackup(deleteBackup bool) *BackupCancellationRequestBuilder {
	b.object.Spec.DeleteBackup = deleteBackup
	return b
}

// Phase sets the BackupCancellationRequest's phase.
func (b *BackupCancellationRequestBuilder) Phase(phase velerov1api.BackupCancellationRequestPhase) *BackupCancellationRequestBuilder {
	b.object.Status.Phase = phase
	return b
}

// BackupUID sets the BackupCancellationRequest's bound backup UID.
func (b *BackupCancellationRequestBuilder) BackupUID(uid string) *BackupCancellationRequestBuilder {
	b.object.Status.BackupUID = uid
	return b
}

// Reason sets the BackupCancellationRequest's rejection reason.
func (b *BackupCancellationRequestBuilder) Reason(reason velerov1api.BackupCancellationRequestRejectedReason) *BackupCancellationRequestBuilder {
	b.object.Status.Reason = reason
	return b
}

// Message sets the BackupCancellationRequest's message.
func (b *BackupCancellationRequestBuilder) Message(message string) *BackupCancellationRequestBuilder {
	b.object.Status.Message = message
	return b
}
