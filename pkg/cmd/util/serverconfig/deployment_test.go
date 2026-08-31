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

package serverconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/velero/pkg/cmd/server/config"
	"github.com/vmware-tanzu/velero/pkg/install"
)

func TestParseServerArgs(t *testing.T) {
	t.Parallel()

	t.Run("no server subcommand returns defaults", func(t *testing.T) {
		t.Parallel()

		cfg, err := parseServerArgs([]string{"--log-level", "debug"})
		require.NoError(t, err)
		assert.Equal(t, config.GetDefaultConfig().StoreValidationFrequency, cfg.StoreValidationFrequency)
	})

	t.Run("custom store-validation-frequency", func(t *testing.T) {
		t.Parallel()

		cfg, err := parseServerArgs([]string{"server", "--store-validation-frequency", "5m"})
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, cfg.StoreValidationFrequency)
	})

	t.Run("unknown flags are ignored", func(t *testing.T) {
		t.Parallel()

		cfg, err := parseServerArgs([]string{"server", "--unknown-flag", "value", "--store-validation-frequency", "30s"})
		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, cfg.StoreValidationFrequency)
	})
}

func TestGetStoreValidationFrequencyFallback(t *testing.T) {
	t.Parallel()

	defaultFrequency := config.GetDefaultConfig().StoreValidationFrequency

	assert.Equal(t, defaultFrequency, GetStoreValidationFrequency(t.Context(), nil, "velero"))

	clientset := fake.NewSimpleClientset()
	assert.Equal(t, defaultFrequency, GetStoreValidationFrequency(t.Context(), clientset, "velero"))
}

func TestGetStoreValidationFrequencyFromDeployment(t *testing.T) {
	t.Parallel()

	deployment := veleroDeploymentWithArgs("velero", []string{"server", "--store-validation-frequency", "5m"})
	clientset := fake.NewSimpleClientset(deployment)

	assert.Equal(t, 5*time.Minute, GetStoreValidationFrequency(t.Context(), clientset, "velero"))
}

func TestGetStoreValidationFrequencyNoVeleroContainer(t *testing.T) {
	t.Parallel()

	deployment := &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "velero",
			Labels:    install.Labels(),
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{{
						Name: "not-velero",
						Args: []string{"server", "--store-validation-frequency", "5m"},
					}},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(deployment)
	defaultFrequency := config.GetDefaultConfig().StoreValidationFrequency
	assert.Equal(t, defaultFrequency, GetStoreValidationFrequency(t.Context(), clientset, "velero"))
}

func veleroDeploymentWithArgs(namespace string, args []string) *appsv1api.Deployment {
	return &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "velero",
			Labels:    install.Labels(),
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{{
						Name: "velero",
						Args: args,
					}},
				},
			},
		},
	}
}
