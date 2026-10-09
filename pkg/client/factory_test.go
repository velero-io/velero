/*
Copyright 2019 the Velero contributors.

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
package client

import (
	"fmt"
	"os"
	"strings"
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestFactory tests the client.Factory interface.
func TestFactory(t *testing.T) {
	// Velero client configuration is currently omitted due to requiring a
	// test filesystem in pkg/test. This causes an import cycle as pkg/test
	// uses pkg/client's interfaces to implement fakes

	// Env variable should set the namespace if no config or argument are used
	os.Setenv("VELERO_NAMESPACE", "env-velero")
	f := NewFactory("velero", make(map[string]any))

	assert.Equal(t, "env-velero", f.Namespace())

	os.Unsetenv("VELERO_NAMESPACE")

	// Argument should change the namespace
	f = NewFactory("velero", make(map[string]any))
	s := "flag-velero"
	flags := new(flag.FlagSet)

	f.BindFlags(flags)

	flags.Parse([]string{"--namespace", s})

	assert.Equal(t, s, f.Namespace())

	// An argument overrides the env variable if both are set.
	os.Setenv("VELERO_NAMESPACE", "env-velero")
	f = NewFactory("velero", make(map[string]any))
	flags = new(flag.FlagSet)

	f.BindFlags(flags)
	flags.Parse([]string{"--namespace", s})
	assert.Equal(t, s, f.Namespace())

	os.Unsetenv("VELERO_NAMESPACE")

	// namespace-mode=auto should resolve the namespace from the current kubeconfig context.
	f = NewFactory("velero", VeleroConfig{ConfigKeyNamespaceMode: NamespaceModeAuto})
	flags = new(flag.FlagSet)
	f.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--kubeconfig", "kubeconfig", "--kubecontext", "federal-context"}))
	assert.Equal(t, "chisel-ns", f.Namespace())

	// namespace-mode=auto should track kubecontext changes dynamically.
	f = NewFactory("velero", VeleroConfig{ConfigKeyNamespaceMode: NamespaceModeAuto})
	flags = new(flag.FlagSet)
	f.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--kubeconfig", "kubeconfig", "--kubecontext", "queen-anne-context"}))
	assert.Equal(t, "saw-ns", f.Namespace())

	// An explicit --namespace flag overrides namespace-mode=auto.
	f = NewFactory("velero", VeleroConfig{ConfigKeyNamespaceMode: NamespaceModeAuto})
	flags = new(flag.FlagSet)
	f.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--kubeconfig", "kubeconfig", "--kubecontext", "federal-context", "--namespace", s}))
	assert.Equal(t, s, f.Namespace())

	// VELERO_NAMESPACE overrides namespace-mode=auto.
	t.Run("VELERO_NAMESPACE overrides namespace-mode=auto", func(t *testing.T) {
		t.Setenv("VELERO_NAMESPACE", "env-velero")
		f := NewFactory("velero", VeleroConfig{ConfigKeyNamespaceMode: NamespaceModeAuto})
		flags := new(flag.FlagSet)
		f.BindFlags(flags)
		require.NoError(t, flags.Parse([]string{"--kubeconfig", "kubeconfig", "--kubecontext", "federal-context"}))
		assert.Equal(t, "env-velero", f.Namespace())
	})

	// namespace-mode=auto falls back to the stored/default namespace when the kubeconfig
	// namespace can't be resolved (e.g. the kubeconfig file doesn't exist).
	f = NewFactory("velero", VeleroConfig{ConfigKeyNamespace: "stored-ns", ConfigKeyNamespaceMode: NamespaceModeAuto})
	flags = new(flag.FlagSet)
	f.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--kubeconfig", "nonexistent-kubeconfig"}))
	assert.Equal(t, "stored-ns", f.Namespace())

	tests := []struct {
		name         string
		kubeconfig   string
		kubecontext  string
		QPS          float32
		burst        int
		baseName     string
		expectedHost string
	}{
		{
			name:         "Test flag setting in factory ClientConfig (test data #1)",
			kubeconfig:   "kubeconfig",
			kubecontext:  "federal-context",
			QPS:          1.0,
			burst:        1,
			baseName:     "bn-velero-1",
			expectedHost: "https://horse.org:4443",
		},
		{
			name:         "Test flag setting in factory ClientConfig (test data #2)",
			kubeconfig:   "kubeconfig",
			kubecontext:  "queen-anne-context",
			QPS:          200.0,
			burst:        20,
			baseName:     "bn-velero-2",
			expectedHost: "https://pig.org:443",
		},
	}

	baseName := "velero-bn"
	config, err := LoadConfig()
	require.NoError(t, err)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f = NewFactory(baseName, config)
			f.SetClientBurst(test.burst)
			f.SetClientQPS(test.QPS)
			f.SetBasename(test.baseName)

			flags = new(flag.FlagSet)
			f.BindFlags(flags)
			flags.Parse([]string{"--kubeconfig", test.kubeconfig, "--kubecontext", test.kubecontext})
			clientConfig, _ := f.ClientConfig()
			assert.Equal(t, test.expectedHost, clientConfig.Host)
			assert.Equal(t, test.QPS, clientConfig.QPS)
			assert.Equal(t, test.burst, clientConfig.Burst)
			strings.Contains(clientConfig.UserAgent, test.baseName)

			kubeClient, _ := f.KubeClient()
			group := kubeClient.NodeV1().RESTClient().APIVersion().Group
			assert.NotNil(t, kubeClient)
			assert.Equal(t, "node.k8s.io", group)

			namespace := "ns1"
			dynamicClient, _ := f.DynamicClient()
			resource := &schema.GroupVersionResource{
				Group:   "group_test",
				Version: "verion_test",
			}
			list, e := dynamicClient.Resource(*resource).Namespace(namespace).List(
				t.Context(),
				metav1.ListOptions{
					LabelSelector: "none",
				},
			)
			require.ErrorContains(t, e, fmt.Sprintf("Get \"%s/apis/%s/%s/namespaces/%s", test.expectedHost, resource.Group, resource.Version, namespace))
			assert.Nil(t, list)
			assert.NotNil(t, dynamicClient)

			kubebuilderClient, e := f.KubebuilderClient()
			require.NoError(t, e)
			assert.NotNil(t, kubebuilderClient)

			kbClientWithWatch, e := f.KubebuilderWatchClient()
			require.NoError(t, e)
			assert.NotNil(t, kbClientWithWatch)
		})
	}
}
