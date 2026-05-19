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

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// CustomResourceBuilder builds objects based on velero APIVersion CRDs.
type TestCRBuilder struct {
	object *TestCR
}

// ForTestCR is the constructor for a TestCRBuilder.
func ForTestCR(crdKind, ns, name string) *TestCRBuilder {
	return &TestCRBuilder{
		object: &TestCR{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       crdKind,
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built TestCR.
func (b *TestCRBuilder) Result() *TestCR {
	return b.object
}

// ObjectMeta applies functional options to the TestCR's ObjectMeta.
func (b *TestCRBuilder) ObjectMeta(opts ...ObjectMetaOpt) *TestCRBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

type TestCR struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +optional
	Spec TestCRSpec `json:"spec,omitzero"`

	// +optional
	Status TestCRStatus `json:"status,omitzero"`
}

type TestCRSpec struct {
}

type TestCRStatus struct {
}
