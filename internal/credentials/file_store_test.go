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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestNamespacedFileStore(t *testing.T) {
	testCases := []struct {
		name             string
		namespace        string
		fsRoot           string
		secrets          []*corev1api.Secret
		secretSelector   *corev1api.SecretKeySelector
		wantErr          string
		expectedPath     string
		expectedContents string
	}{
		{
			name:           "returns an error if the secret can't be found",
			secretSelector: builder.ForSecretKeySelector("non-existent-secret", "secret-key").Result(),
			wantErr:        "unable to get key for secret: secrets \"non-existent-secret\" not found",
		},
		{
			name:           "returns a filepath formed using fsRoot, namespace, secret name and key, with secret contents",
			namespace:      "ns1",
			fsRoot:         "/tmp/credentials",
			secretSelector: builder.ForSecretKeySelector("credential", "key2").Result(),
			secrets: []*corev1api.Secret{
				builder.ForSecret("ns1", "credential").Data(map[string][]byte{
					"key1": []byte("ns1-secretdata1"),
					"key2": []byte("ns1-secretdata2"),
					"key3": []byte("ns1-secretdata3"),
				}).Result(),
				builder.ForSecret("ns2", "credential").Data(map[string][]byte{
					"key2": []byte("ns2-secretdata2"),
				}).Result(),
			},
			expectedPath:     "/tmp/credentials/ns1/credential-key2",
			expectedContents: "ns1-secretdata2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := velerotest.NewFakeControllerRuntimeClient(t)

			for _, secret := range tc.secrets {
				require.NoError(t, client.Create(t.Context(), secret))
			}

			fs := velerotest.NewFakeFileSystem()
			fileStore, err := NewNamespacedFileStore(client, tc.namespace, tc.fsRoot, fs)
			require.NoError(t, err)

			path, err := fileStore.Path(context.Background(), tc.secretSelector)

			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.expectedPath, path)

			contents, err := fs.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, []byte(tc.expectedContents), contents)
		})
	}
}
