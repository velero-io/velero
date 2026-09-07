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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/velero/pkg/install"
)

func TestParseServerArgsDefaultVolumeSnapshotLocations(t *testing.T) {
	t.Parallel()

	t.Run("no server subcommand returns empty defaults", func(t *testing.T) {
		t.Parallel()

		cfg, err := parseServerArgs([]string{"--log-level", "debug"})
		require.NoError(t, err)
		assert.Empty(t, cfg.DefaultVolumeSnapshotLocations.Data())
	})

	t.Run("custom default-volume-snapshot-locations", func(t *testing.T) {
		t.Parallel()

		cfg, err := parseServerArgs([]string{"server", "--default-volume-snapshot-locations", "aws:my-aws-location,gcp:my-gcp-location"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"aws": "my-aws-location",
			"gcp": "my-gcp-location",
		}, cfg.DefaultVolumeSnapshotLocations.Data())
	})

	t.Run("unknown flags are ignored", func(t *testing.T) {
		t.Parallel()

		cfg, err := parseServerArgs([]string{"server", "--unknown-flag", "value", "--default-volume-snapshot-locations", "azure:default"})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"azure": "default"}, cfg.DefaultVolumeSnapshotLocations.Data())
	})
}

func TestGetDefaultVolumeSnapshotLocationsFallback(t *testing.T) {
	t.Parallel()

	locations := GetDefaultVolumeSnapshotLocations(t.Context(), nil, "velero")
	assert.Empty(t, locations)
}

func TestGetDefaultVolumeSnapshotLocationsFromDeployment(t *testing.T) {
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
						Name: "velero",
						Args: []string{"server", "--default-volume-snapshot-locations", "aws:my-aws,gcp:my-gcp"},
					}},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(deployment)
	locations := GetDefaultVolumeSnapshotLocations(t.Context(), clientset, "velero")
	assert.Equal(t, map[string]string{
		"aws": "my-aws",
		"gcp": "my-gcp",
	}, locations)
}

func TestGetDefaultVolumeSnapshotLocationsNoDeployment(t *testing.T) {
	t.Parallel()

	clientset := fake.NewSimpleClientset()
	assert.Empty(t, GetDefaultVolumeSnapshotLocations(t.Context(), clientset, "velero"))
}

func TestGetDefaultVolumeSnapshotLocationsNoVeleroContainer(t *testing.T) {
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
						Args: []string{"server", "--default-volume-snapshot-locations", "aws:my-aws"},
					}},
				},
			},
		},
	}

	clientset := fake.NewSimpleClientset(deployment)
	assert.Empty(t, GetDefaultVolumeSnapshotLocations(t.Context(), clientset, "velero"))
}
