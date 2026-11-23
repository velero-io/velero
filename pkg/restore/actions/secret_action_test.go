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

package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/test"
)

func TestSecretActionAppliesTo(t *testing.T) {
	action := NewSecretAction(test.NewLogger(), nil)
	actual, err := action.AppliesTo()
	require.NoError(t, err)
	assert.Equal(t, velero.ResourceSelector{IncludedResources: []string{"secrets"}}, actual)
}

func TestSecretActionExecute(t *testing.T) {
	tests := []struct {
		name           string
		input          *corev1api.Secret
		serviceAccount *corev1api.ServiceAccount
		skipped        bool
		output         *corev1api.Secret
	}{
		{
			name: "not service account token secret",
			input: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "default-token-sfafa",
				},
				Type: corev1api.SecretTypeOpaque,
			},
			skipped: false,
			output: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "default-token-sfafa",
				},
				Type: corev1api.SecretTypeOpaque,
			},
		},
		{
			name: "auto created service account token",
			input: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "default-token-sfafa",
				},
				Type: corev1api.SecretTypeServiceAccountToken,
			},
			serviceAccount: &corev1api.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "default",
				},
			},
			skipped: true,
		},
		{
			name: "not auto created service account token",
			input: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "my-token",
					Annotations: map[string]string{
						"kubernetes.io/service-account.uid": "uid",
						"key":                               "value",
					},
				},
				Type: corev1api.SecretTypeServiceAccountToken,
				Data: map[string][]byte{
					"token":  []byte("token"),
					"ca.crt": []byte("ca"),
					"key":    []byte("value"),
				},
			},
			skipped: false,
			output: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "my-token",
					Annotations: map[string]string{
						"key": "value",
					},
				},
				Type: corev1api.SecretTypeServiceAccountToken,
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secretUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.input)
			require.NoError(t, err)
			var serviceAccounts []client.Object
			if tc.serviceAccount != nil {
				serviceAccounts = append(serviceAccounts, tc.serviceAccount)
			}
			client := fake.NewClientBuilder().WithObjects(serviceAccounts...).Build()
			action := NewSecretAction(test.NewLogger(), client)
			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item: &unstructured.Unstructured{Object: secretUnstructured},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.skipped, res.SkipRestore)
			if !tc.skipped {
				r, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.output)
				require.NoError(t, err)
				assert.EqualValues(t, &unstructured.Unstructured{Object: r}, res.UpdatedItem)
			}
		})
	}
}
