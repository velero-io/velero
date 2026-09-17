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

package velero

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

func TestGetNodeSelectorFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   map[string]string
	}{
		{
			name: "no node selector",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							NodeSelector: map[string]string{},
						},
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "node selector",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							NodeSelector: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
			},
			want: map[string]string{
				"foo": "bar",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetNodeSelectorFromVeleroServer(test.deploy)
			if len(got) != len(test.want) {
				t.Errorf("expected node selector to have %d elements, got %d", len(test.want), len(got))
			}
			for k, v := range test.want {
				if got[k] != v {
					t.Errorf("expected node selector to have key %s with value %s, got %s", k, v, got[k])
				}
			}
		})
	}
}

func TestGetTolerationsFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   []corev1api.Toleration
	}{
		{
			name: "no tolerations",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Tolerations: []corev1api.Toleration{},
						},
					},
				},
			},
			want: []corev1api.Toleration{},
		},
		{
			name: "tolerations",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Tolerations: []corev1api.Toleration{
								{
									Key:      "foo",
									Operator: "Exists",
								},
							},
						},
					},
				},
			},
			want: []corev1api.Toleration{
				{
					Key:      "foo",
					Operator: "Exists",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetTolerationsFromVeleroServer(test.deploy)
			if len(got) != len(test.want) {
				t.Errorf("expected tolerations to have %d elements, got %d", len(test.want), len(got))
			}
			for i, want := range test.want {
				if got[i] != want {
					t.Errorf("expected toleration at index %d to be %v, got %v", i, want, got[i])
				}
			}
		})
	}
}

func TestGetAffinityFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   *corev1api.Affinity
	}{
		{
			name: "no affinity",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Affinity: nil,
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "affinity",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Affinity: &corev1api.Affinity{
								NodeAffinity: &corev1api.NodeAffinity{
									RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
										NodeSelectorTerms: []corev1api.NodeSelectorTerm{
											{
												MatchExpressions: []corev1api.NodeSelectorRequirement{
													{
														Key:      "foo",
														Operator: "In",
														Values:   []string{"bar"},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "foo",
										Operator: "In",
										Values:   []string{"bar"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetAffinityFromVeleroServer(test.deploy)
			if test.want != nil {
				require.NotNilf(t, got, "expected affinity to be %v, got nil", test.want)
				if test.want.NodeAffinity != nil {
					require.NotNilf(t, got.NodeAffinity, "expected node affinity to be %v, got nil", test.want.NodeAffinity)
					if test.want.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
						require.NotNilf(t, got.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution, "expected required during scheduling ignored during execution to be %v, got nil", test.want.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
						assert.Truef(t, reflect.DeepEqual(got.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution, test.want.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution), "expected required during scheduling ignored during execution to be %v, got %v", test.want.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution, got.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
					} else {
						assert.Nilf(t, got.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution, "expected required during scheduling ignored during execution to be nil, got %v", got.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
					}
				} else {
					assert.Nilf(t, got.NodeAffinity, "expected node affinity to be nil, got %v", got.NodeAffinity)
				}
			} else {
				assert.Nilf(t, got, "expected affinity to be nil, got %v", got)
			}
		})
	}
}

func TestGetEnvVarsFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   []corev1api.EnvVar
	}{
		{
			name: "no env vars",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									Env: []corev1api.EnvVar{},
								},
							},
						},
					},
				},
			},
			want: []corev1api.EnvVar{},
		},
		{
			name: "env vars",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									Env: []corev1api.EnvVar{
										{
											Name:  "foo",
											Value: "bar",
										},
									},
								},
							},
						},
					},
				},
			},
			want: []corev1api.EnvVar{
				{
					Name:  "foo",
					Value: "bar",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetEnvVarsFromVeleroServer(test.deploy)
			if len(got) != len(test.want) {
				t.Errorf("expected env vars to have %d elements, got %d", len(test.want), len(got))
			}
			for i, want := range test.want {
				if got[i] != want {
					t.Errorf("expected env var at index %d to be %v, got %v", i, want, got[i])
				}
			}
		})
	}
}

func TestGetEnvFromSourcesFromVeleroServer(t *testing.T) {
	tests := []struct {
		name     string
		deploy   *appsv1api.Deployment
		expected []corev1api.EnvFromSource
	}{
		{
			name: "no env vars",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									EnvFrom: []corev1api.EnvFromSource{},
								},
							},
						},
					},
				},
			},
			expected: []corev1api.EnvFromSource{},
		},
		{
			name: "configmap",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									EnvFrom: []corev1api.EnvFromSource{
										{
											ConfigMapRef: &corev1api.ConfigMapEnvSource{
												LocalObjectReference: corev1api.LocalObjectReference{
													Name: "foo",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []corev1api.EnvFromSource{
				{
					ConfigMapRef: &corev1api.ConfigMapEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "foo",
						},
					},
				},
			},
		},
		{
			name: "secret",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									EnvFrom: []corev1api.EnvFromSource{
										{
											SecretRef: &corev1api.SecretEnvSource{
												LocalObjectReference: corev1api.LocalObjectReference{
													Name: "foo",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: []corev1api.EnvFromSource{
				{
					SecretRef: &corev1api.SecretEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "foo",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetEnvFromSourcesFromVeleroServer(test.deploy)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetVolumeMountsFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   []corev1api.VolumeMount
	}{
		{
			name: "no volume mounts",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									VolumeMounts: []corev1api.VolumeMount{},
								},
							},
						},
					},
				},
			},
			want: []corev1api.VolumeMount{},
		},
		{
			name: "volume mounts",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									VolumeMounts: []corev1api.VolumeMount{
										{
											Name:      "foo",
											MountPath: "/bar",
										},
									},
								},
							},
						},
					},
				},
			},
			want: []corev1api.VolumeMount{
				{
					Name:      "foo",
					MountPath: "/bar",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetVolumeMountsFromVeleroServer(test.deploy)
			if len(got) != len(test.want) {
				t.Errorf("expected volume mounts to have %d elements, got %d", len(test.want), len(got))
			}
			for i, want := range test.want {
				if got[i] != want {
					t.Errorf("expected volume mount at index %d to be %v, got %v", i, want, got[i])
				}
			}
		})
	}
}

func TestGetVolumesFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   []corev1api.Volume
	}{
		{
			name: "no volumes",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Volumes: []corev1api.Volume{},
						},
					},
				},
			},
			want: []corev1api.Volume{},
		},
		{
			name: "volumes",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Volumes: []corev1api.Volume{
								{
									Name: "foo",
								},
							},
						},
					},
				},
			},
			want: []corev1api.Volume{
				{
					Name: "foo",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetVolumesFromVeleroServer(test.deploy)
			if len(got) != len(test.want) {
				t.Errorf("expected volumes to have %d elements, got %d", len(test.want), len(got))
			}
			for i, want := range test.want {
				if got[i] != want {
					t.Errorf("expected volume at index %d to be %v, got %v", i, want, got[i])
				}
			}
		})
	}
}

func TestGetPodSecurityContextsFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   *corev1api.PodSecurityContext
	}{
		{
			name: "no security context",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							SecurityContext: nil,
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "security context",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							SecurityContext: &corev1api.PodSecurityContext{
								RunAsNonRoot: boolptr.True(),
							},
						},
					},
				},
			},
			want: &corev1api.PodSecurityContext{
				RunAsNonRoot: boolptr.True(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetPodSecurityContextsFromVeleroServer(test.deploy)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestGetContainerSecurityContextsFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   *corev1api.SecurityContext
	}{
		{
			name: "no container",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "no security context",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									SecurityContext: nil,
								},
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "security context",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									SecurityContext: &corev1api.SecurityContext{
										RunAsNonRoot: boolptr.True(),
									},
								},
							},
						},
					},
				},
			},
			want: &corev1api.SecurityContext{
				RunAsNonRoot: boolptr.True(),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetContainerSecurityContextsFromVeleroServer(test.deploy)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestGetServiceAccountFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   string
	}{
		{
			name: "no service account",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							ServiceAccountName: "",
						},
					},
				},
			},
			want: "",
		},
		{
			name: "service account",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							ServiceAccountName: "foo",
						},
					},
				},
			},
			want: "foo",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetServiceAccountFromVeleroServer(test.deploy)
			if got != test.want {
				t.Errorf("expected service account to be %s, got %s", test.want, got)
			}
		})
	}
}

func TestGetImagePullSecretsFromVeleroServer(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   []corev1api.LocalObjectReference
	}{
		{
			name: "no image pull secrets",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							ServiceAccountName: "",
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "image pull secrets",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							ImagePullSecrets: []corev1api.LocalObjectReference{
								{
									Name: "imagePullSecret1",
								},
								{
									Name: "imagePullSecret2",
								},
							},
						},
					},
				},
			},
			want: []corev1api.LocalObjectReference{
				{
					Name: "imagePullSecret1",
				},
				{
					Name: "imagePullSecret2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetImagePullSecretsFromVeleroServer(test.deploy)

			require.Equal(t, test.want, got)
		})
	}
}

func TestGetVeleroServerImage(t *testing.T) {
	tests := []struct {
		name   string
		deploy *appsv1api.Deployment
		want   string
	}{
		{
			name: "velero server image",
			deploy: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									Image: "velero/velero:latest",
								},
							},
						},
					},
				},
			},
			want: "velero/velero:latest",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := GetVeleroServerImage(test.deploy)
			if got != test.want {
				t.Errorf("expected velero server image to be %s, got %s", test.want, got)
			}
		})
	}
}

func TestGetVeleroServerLables(t *testing.T) {
	tests := []struct {
		name       string
		deployment *appsv1api.Deployment
		expected   map[string]string
	}{
		{
			name: "Empty Labels",
			deployment: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{},
						},
					},
				},
			},
			expected: map[string]string{},
		},
		{
			name: "Non-empty Labels",
			deployment: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app":       "velero",
								"component": "server",
							},
						},
					},
				},
			},
			expected: map[string]string{
				"app":       "velero",
				"component": "server",
			},
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetVeleroServerLables(tt.deployment)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetVeleroServerAnnotations(t *testing.T) {
	tests := []struct {
		name       string
		deployment *appsv1api.Deployment
		expected   map[string]string
	}{
		{
			name: "Empty Labels",
			deployment: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{},
						},
					},
				},
			},
			expected: map[string]string{},
		},
		{
			name: "Non-empty Labels",
			deployment: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"app":       "velero",
								"component": "server",
							},
						},
					},
				},
			},
			expected: map[string]string{
				"app":       "velero",
				"component": "server",
			},
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetVeleroServerAnnotations(tt.deployment)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetVeleroServerLabelValue(t *testing.T) {
	tests := []struct {
		name       string
		deployment *appsv1api.Deployment
		expected   string
	}{
		{
			name:       "nil Labels",
			deployment: &appsv1api.Deployment{},
			expected:   "",
		},
		{
			name: "no label key",
			deployment: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{},
						},
					},
				},
			},
			expected: "",
		},
		{
			name: "with label key",
			deployment: &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{"fake-key": "fake-value"},
						},
					},
				},
			},
			expected: "fake-value",
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetVeleroServerLabelValue(tt.deployment, "fake-key")
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBSLIsAvailable(t *testing.T) {
	availableBSL := builder.ForBackupStorageLocation("velero", "available").Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result()
	unavailableBSL := builder.ForBackupStorageLocation("velero", "unavailable").Phase(velerov1api.BackupStorageLocationPhaseUnavailable).Result()

	assert.True(t, BSLIsAvailable(*availableBSL))
	assert.False(t, BSLIsAvailable(*unavailableBSL))
}

func TestGetVeleroServerDeployment(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, appsv1api.AddToScheme(scheme))

	veleroLabels := map[string]string{"component": "velero"}

	matchingDeploy := &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-velero-name",
			Namespace: "velero",
			Labels:    veleroLabels,
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{Name: "velero", Image: "velero/velero:latest"},
					},
				},
			},
		},
	}

	nonVeleroContainerDeploy := &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other",
			Namespace: "velero",
			Labels:    veleroLabels,
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{Name: "other-container"},
					},
				},
			},
		},
	}

	unlabeledDeploy := &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "velero",
			Namespace: "velero",
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{Name: "velero"},
					},
				},
			},
		},
	}

	tests := []struct {
		name      string
		objects   []ctrlclient.Object
		namespace string
		wantName  string
		wantErr   bool
	}{
		{
			name:      "finds deployment by labels and velero container",
			objects:   []ctrlclient.Object{matchingDeploy},
			namespace: "velero",
			wantName:  "custom-velero-name",
		},
		{
			name:      "skips labeled deployment without velero container",
			objects:   []ctrlclient.Object{nonVeleroContainerDeploy},
			namespace: "velero",
			wantErr:   true,
		},
		{
			name:      "skips deployment without velero labels",
			objects:   []ctrlclient.Object{unlabeledDeploy},
			namespace: "velero",
			wantErr:   true,
		},
		{
			name:      "no deployment in namespace",
			objects:   nil,
			namespace: "velero",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cli := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.objects...).Build()
			got, err := GetVeleroServerDeployment(context.Background(), cli, tc.namespace)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, got.Name)
		})
	}
}
