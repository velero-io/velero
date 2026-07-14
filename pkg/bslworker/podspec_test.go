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

package bslworker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func veleroServerDeployment() *appsv1api.Deployment {
	return &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "velero", Namespace: "velero"},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					ServiceAccountName: "velero",
					InitContainers: []corev1api.Container{
						{Name: "velero-plugin-for-microsoft-azure", Image: "velero/velero-plugin-for-microsoft-azure:v1"},
					},
					Containers: []corev1api.Container{
						{
							Name:  "velero",
							Image: "velero/velero:v1.16.0",
							Env: []corev1api.EnvVar{
								{Name: "VELERO_SCRATCH_DIR", Value: "/scratch"},
								{Name: "LD_LIBRARY_PATH", Value: "/plugins"},
								{Name: "AZURE_CLIENT_ID", Value: "central-identity"},
								{Name: "AWS_WEB_IDENTITY_TOKEN_FILE", Value: "/var/run/secrets/token"},
							},
							VolumeMounts: []corev1api.VolumeMount{
								{Name: "plugins", MountPath: "/plugins"},
								{Name: "scratch", MountPath: "/scratch"},
								{Name: "cloud-credentials", MountPath: "/credentials"},
							},
						},
					},
					Volumes: []corev1api.Volume{
						{Name: "plugins", VolumeSource: corev1api.VolumeSource{EmptyDir: &corev1api.EmptyDirVolumeSource{}}},
						{Name: "scratch", VolumeSource: corev1api.VolumeSource{EmptyDir: &corev1api.EmptyDirVolumeSource{}}},
						{Name: "cloud-credentials", VolumeSource: corev1api.VolumeSource{Secret: &corev1api.SecretVolumeSource{SecretName: "cloud-credentials"}}},
					},
				},
			},
		},
	}
}

func TestBuildWorkerDeployment(t *testing.T) {
	bsl := &velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Namespace: "velero"},
		Spec: velerov1api.BackupStorageLocationSpec{
			Provider: "velero.io/azure",
			Worker: &velerov1api.BackupStorageLocationWorker{
				ServiceAccountName: "tenant-a-sa",
				PodLabels:          map[string]string{"azure.workload.identity/use": "true"},
				TokenVolumes: []velerov1api.ProjectedServiceAccountToken{
					{Audience: "api://AzureADTokenExchange", MountPath: "/var/run/secrets/azure/tokens", Path: "azure-identity-token"},
				},
			},
		},
	}

	dep := BuildWorkerDeployment(bsl, veleroServerDeployment(), "velero", "info", "text")
	podSpec := dep.Spec.Template.Spec

	// Runs under the tenant's ServiceAccount, not the Velero server's.
	assert.Equal(t, "tenant-a-sa", podSpec.ServiceAccountName)

	// Init containers (which populate /plugins) are inherited.
	require.Len(t, podSpec.InitContainers, 1)
	assert.Equal(t, "velero-plugin-for-microsoft-azure", podSpec.InitContainers[0].Name)

	// Central identity env vars are stripped; benign plugin-runtime env is kept.
	envNames := map[string]bool{}
	for _, e := range podSpec.Containers[0].Env {
		envNames[e.Name] = true
	}
	assert.True(t, envNames["VELERO_SCRATCH_DIR"])
	assert.True(t, envNames["LD_LIBRARY_PATH"])
	assert.False(t, envNames["AZURE_CLIENT_ID"], "central identity env must not leak to worker")
	assert.False(t, envNames["AWS_WEB_IDENTITY_TOKEN_FILE"], "central identity env must not leak to worker")

	// Secret-backed volumes (central credentials) are dropped; EmptyDirs kept.
	volNames := map[string]bool{}
	for _, v := range podSpec.Volumes {
		volNames[v.Name] = true
	}
	assert.True(t, volNames["plugins"])
	assert.True(t, volNames["scratch"])
	assert.False(t, volNames["cloud-credentials"], "central credentials secret must not be mounted into worker")
	assert.True(t, volNames["bsl-worker-tls"])
	assert.True(t, volNames["bsl-worker-token-0"])

	// The dropped secret volume's mount is also removed.
	mountNames := map[string]bool{}
	for _, m := range podSpec.Containers[0].VolumeMounts {
		mountNames[m.Name] = true
	}
	assert.False(t, mountNames["cloud-credentials"])
	assert.True(t, mountNames["plugins"])
	assert.True(t, mountNames["bsl-worker-tls"])

	// Pod label for the Azure webhook is present.
	assert.Equal(t, "true", dep.Spec.Template.ObjectMeta.Labels["azure.workload.identity/use"])

	// Command targets the worker subcommand with the right provider.
	args := podSpec.Containers[0].Args
	assert.Equal(t, "backup-store-server", args[0])
	assert.Contains(t, args, "--provider=velero.io/azure")
}
