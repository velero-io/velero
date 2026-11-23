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

// DownloadRequestBuilder builds DownloadRequest objects.
type DownloadRequestBuilder struct {
	object *velerov1api.DownloadRequest
}

// ForDownloadRequest is the constructor for a DownloadRequestBuilder.
func ForDownloadRequest(ns, name string) *DownloadRequestBuilder {
	return &DownloadRequestBuilder{
		object: &velerov1api.DownloadRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "DownloadRequest",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built DownloadRequest.
func (b *DownloadRequestBuilder) Result() *velerov1api.DownloadRequest {
	return b.object
}

// Phase sets the DownloadRequest's status phase.
func (b *DownloadRequestBuilder) Phase(phase velerov1api.DownloadRequestPhase) *DownloadRequestBuilder {
	b.object.Status.Phase = phase
	return b
}

// Target sets the DownloadRequest's target kind and target name.
func (b *DownloadRequestBuilder) Target(targetKind velerov1api.DownloadTargetKind, targetName string) *DownloadRequestBuilder {
	b.object.Spec.Target.Kind = targetKind
	b.object.Spec.Target.Name = targetName
	return b
}
