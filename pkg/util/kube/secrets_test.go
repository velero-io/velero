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

package kube

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestGetSecretKey(t *testing.T) {
	testCases := []struct {
		name         string
		secrets      []*corev1api.Secret
		namespace    string
		selector     *corev1api.SecretKeySelector
		expectedData string
		expectedErr  string
	}{
		{
			name: "error is returned when secret doesn't exist",
			secrets: []*corev1api.Secret{
				builder.ForSecret("ns-1", "secret1").Data(map[string][]byte{
					"key1": []byte("ns1-secretdata1"),
				}).Result(),
			},
			namespace:   "ns-1",
			selector:    builder.ForSecretKeySelector("non-existent-secret", "key2").Result(),
			expectedErr: "secrets \"non-existent-secret\" not found",
		},
		{
			name: "error is returned when key is missing from secret",
			secrets: []*corev1api.Secret{
				builder.ForSecret("ns-1", "secret1").Data(map[string][]byte{
					"key1": []byte("ns1-secretdata1"),
				}).Result(),
			},
			namespace:   "ns-1",
			selector:    builder.ForSecretKeySelector("secret1", "non-existent-key").Result(),
			expectedErr: "\"secret1\" secret is missing data for key \"non-existent-key\"",
		},
		{
			name: "key specified in selector is returned",
			secrets: []*corev1api.Secret{
				builder.ForSecret("ns-1", "secret1").Data(map[string][]byte{
					"key1": []byte("ns1-secretdata1"),
					"key2": []byte("ns1-secretdata2"),
				}).Result(),
				builder.ForSecret("ns-2", "secret1").Data(map[string][]byte{
					"key1": []byte("ns2-secretdata1"),
					"key2": []byte("ns2-secretdata2"),
				}).Result(),
			},
			namespace:    "ns-2",
			selector:     builder.ForSecretKeySelector("secret1", "key2").Result(),
			expectedData: "ns2-secretdata2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t)

			for _, secret := range tc.secrets {
				require.NoError(t, fakeClient.Create(t.Context(), secret))
			}

			data, err := GetSecretKey(context.Background(), fakeClient, tc.namespace, tc.selector)
			if tc.expectedErr != "" {
				require.Nil(t, data)
				require.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedData, string(data))
			}
		})
	}
}
