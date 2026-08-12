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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/client"
)

const testKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://example.invalid:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    namespace: my-team-ns
    user: test-user
  name: test-context
- context:
    cluster: test-cluster
    user: test-user
  name: no-namespace-context
current-context: test-context
users:
- name: test-user
  user: {}
`

func writeTestKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(testKubeconfig), 0600))
	return path
}

func TestSetNamespaceFromContext(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kubeconfig := writeTestKubeconfig(t)

	namespace, err := setNamespaceFromContext(kubeconfig, "")
	require.NoError(t, err)
	assert.Equal(t, "my-team-ns", namespace)

	config, err := client.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "my-team-ns", config.Namespace())
}

func TestSetNamespaceFromContext_ExplicitContextWithoutNamespace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kubeconfig := writeTestKubeconfig(t)

	namespace, err := setNamespaceFromContext(kubeconfig, "no-namespace-context")
	require.NoError(t, err)
	assert.Equal(t, "default", namespace)
}

func TestSetNamespaceFromContext_OverwritesExistingConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	kubeconfig := writeTestKubeconfig(t)

	require.NoError(t, client.SaveConfig(client.VeleroConfig{client.ConfigKeyNamespace: "old-ns"}))

	namespace, err := setNamespaceFromContext(kubeconfig, "")
	require.NoError(t, err)
	assert.Equal(t, "my-team-ns", namespace)

	config, err := client.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "my-team-ns", config.Namespace())
}

func TestSetNamespaceFromContext_InvalidKubeconfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	_, err := setNamespaceFromContext(filepath.Join(t.TempDir(), "does-not-exist"), "")
	assert.Error(t, err)
}

func TestNewSetNamespaceFromContextCommand(t *testing.T) {
	c := NewSetNamespaceFromContextCommand()
	assert.Equal(t, "set-namespace-from-context", c.Use)
	assert.NotNil(t, c.Flags().Lookup("kubeconfig"))
	assert.NotNil(t, c.Flags().Lookup("kubecontext"))
}
