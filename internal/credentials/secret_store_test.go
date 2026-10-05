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

package credentials

import (
	"testing"

	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNamespacedSecretStore(t *testing.T) {
	scheme := runtime.NewScheme()
	g := NewWithT(t)
	g.Expect(corev1api.AddToScheme(scheme)).To(Succeed())

	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "velero",
		},
		Data: map[string][]byte{
			"creds-key": []byte("my-super-secret-value"),
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(secret).Build()

	store, err := NewNamespacedSecretStore(client, "velero")
	g.Expect(err).ToNot(HaveOccurred())

	tests := []struct {
		name        string
		selector    *corev1api.SecretKeySelector
		expectedVal string
		expectErr   bool
	}{
		{
			name: "existing secret and key returns the correct value",
			selector: &corev1api.SecretKeySelector{
				LocalObjectReference: corev1api.LocalObjectReference{Name: "test-secret"},
				Key:                  "creds-key",
			},
			expectedVal: "my-super-secret-value",
			expectErr:   false,
		},
		{
			name: "missing secret returns an error",
			selector: &corev1api.SecretKeySelector{
				LocalObjectReference: corev1api.LocalObjectReference{Name: "missing-secret"},
				Key:                  "creds-key",
			},
			expectedVal: "",
			expectErr:   true,
		},
		{
			name: "missing key in existing secret returns an error",
			selector: &corev1api.SecretKeySelector{
				LocalObjectReference: corev1api.LocalObjectReference{Name: "test-secret"},
				Key:                  "missing-key",
			},
			expectedVal: "",
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			val, err := store.Get(tc.selector)
			if tc.expectErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(val).To(Equal(tc.expectedVal))
			}
		})
	}
}
