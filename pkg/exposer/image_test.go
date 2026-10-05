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

package exposer

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"

	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	"github.com/vmware-tanzu/velero/pkg/util/kube"

	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetInheritedPodInfo(t *testing.T) {
	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
		},
	}

	daemonSetWithNoLog := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Name:  "container-1",
							Image: "image-1",
							Env: []corev1api.EnvVar{
								{
									Name:  "env-1",
									Value: "value-1",
								},
								{
									Name:  "env-2",
									Value: "value-2",
								},
							},
							EnvFrom: []corev1api.EnvFromSource{
								{
									ConfigMapRef: &corev1api.ConfigMapEnvSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "test-configmap",
										},
									},
								},
								{
									SecretRef: &corev1api.SecretEnvSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "test-secret",
										},
									},
								},
							},
							VolumeMounts: []corev1api.VolumeMount{
								{
									Name: "volume-1",
								},
								{
									Name: "volume-2",
								},
							},
						},
					},
					Volumes: []corev1api.Volume{
						{
							Name: "volume-1",
						},
						{
							Name: "volume-2",
						},
					},
					ServiceAccountName: "sa-1",
				},
			},
		},
	}

	daemonSetWithLog := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Name:  "container-1",
							Image: "image-1",
							Env: []corev1api.EnvVar{
								{
									Name:  "env-1",
									Value: "value-1",
								},
								{
									Name:  "env-2",
									Value: "value-2",
								},
							},
							EnvFrom: []corev1api.EnvFromSource{
								{
									ConfigMapRef: &corev1api.ConfigMapEnvSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "test-configmap",
										},
									},
								},
								{
									SecretRef: &corev1api.SecretEnvSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "test-secret",
										},
									},
								},
							},
							VolumeMounts: []corev1api.VolumeMount{
								{
									Name: "volume-1",
								},
								{
									Name: "volume-2",
								},
							},
							Args: []string{
								"--log-format=json",
								"--log-level",
								"debug",
							},
							Command: []string{
								"command-1",
							},
						},
					},
					Volumes: []corev1api.Volume{
						{
							Name: "volume-1",
						},
						{
							Name: "volume-2",
						},
					},
					ServiceAccountName: "sa-1",
					ImagePullSecrets: []corev1api.LocalObjectReference{
						{
							Name: "imagePullSecret1",
						},
					},
				},
			},
		},
	}

	daemonSetWithHostPath := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Name:  "container-1",
							Image: "image-1",
							VolumeMounts: []corev1api.VolumeMount{
								{
									Name:      nodeagent.HostPodVolumeMount,
									MountPath: "/host_pods",
								},
								{
									Name:      "host-plugins",
									MountPath: "/var/lib/kubelet/plugins",
								},
								{
									Name:      "customized-host-path",
									MountPath: "/customized",
								},
								{
									Name:      "scratch",
									MountPath: "/scratch",
								},
								{
									Name:      "user-credentials",
									MountPath: "/credentials",
								},
							},
						},
					},
					Volumes: []corev1api.Volume{
						{
							Name: nodeagent.HostPodVolumeMount,
							VolumeSource: corev1api.VolumeSource{
								HostPath: &corev1api.HostPathVolumeSource{
									Path: "/var/lib/kubelet/pods",
								},
							},
						},
						{
							Name: "host-plugins",
							VolumeSource: corev1api.VolumeSource{
								HostPath: &corev1api.HostPathVolumeSource{
									Path: "/var/lib/kubelet/plugins",
								},
							},
						},
						{
							// A host path volume added by users. It's not named after any
							// well-known volume, so it can only be recognized by its source.
							Name: "customized-host-path",
							VolumeSource: corev1api.VolumeSource{
								HostPath: &corev1api.HostPathVolumeSource{
									Path: "/mnt/customized",
								},
							},
						},
						{
							Name: "scratch",
							VolumeSource: corev1api.VolumeSource{
								EmptyDir: new(corev1api.EmptyDirVolumeSource),
							},
						},
						{
							Name: "user-credentials",
							VolumeSource: corev1api.VolumeSource{
								Secret: &corev1api.SecretVolumeSource{
									SecretName: "user-credentials",
								},
							},
						},
					},
					ServiceAccountName: "sa-1",
				},
			},
		},
	}

	scratchAndCredentialMounts := []corev1api.VolumeMount{
		{
			Name:      "scratch",
			MountPath: "/scratch",
		},
		{
			Name:      "user-credentials",
			MountPath: "/credentials",
		},
	}

	scratchAndCredentialVolumes := []corev1api.Volume{
		{
			Name: "scratch",
			VolumeSource: corev1api.VolumeSource{
				EmptyDir: new(corev1api.EmptyDirVolumeSource),
			},
		},
		{
			Name: "user-credentials",
			VolumeSource: corev1api.VolumeSource{
				Secret: &corev1api.SecretVolumeSource{
					SecretName: "user-credentials",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	appsv1api.AddToScheme(scheme)

	tests := []struct {
		name            string
		namespace       string
		client          kubernetes.Interface
		kubeClientObj   []runtime.Object
		excludeHostPath bool
		result          inheritedPodInfo
		expectErr       string
	}{
		{
			name:      "ds is not found",
			namespace: "fake-ns",
			expectErr: "error to get node-agent pod template: error to get node-agent daemonset: daemonsets.apps \"node-agent\" not found",
		},
		{
			name:      "ds pod container number is invalidate",
			namespace: "fake-ns",
			kubeClientObj: []runtime.Object{
				daemonSet,
			},
			expectErr: "unexpected pod template from node-agent",
		},
		{
			name:      "no log info",
			namespace: "fake-ns",
			kubeClientObj: []runtime.Object{
				daemonSetWithNoLog,
			},
			result: inheritedPodInfo{
				image:          "image-1",
				serviceAccount: "sa-1",
				env: []corev1api.EnvVar{
					{
						Name:  "env-1",
						Value: "value-1",
					},
					{
						Name:  "env-2",
						Value: "value-2",
					},
				},
				envFrom: []corev1api.EnvFromSource{
					{
						ConfigMapRef: &corev1api.ConfigMapEnvSource{
							LocalObjectReference: corev1api.LocalObjectReference{
								Name: "test-configmap",
							},
						},
					},
					{
						SecretRef: &corev1api.SecretEnvSource{
							LocalObjectReference: corev1api.LocalObjectReference{
								Name: "test-secret",
							},
						},
					},
				},
				volumeMounts: []corev1api.VolumeMount{
					{
						Name: "volume-1",
					},
					{
						Name: "volume-2",
					},
				},
				volumes: []corev1api.Volume{
					{
						Name: "volume-1",
					},
					{
						Name: "volume-2",
					},
				},
			},
		},
		{
			name:      "with log info",
			namespace: "fake-ns",
			kubeClientObj: []runtime.Object{
				daemonSetWithLog,
			},
			result: inheritedPodInfo{
				image:          "image-1",
				serviceAccount: "sa-1",
				env: []corev1api.EnvVar{
					{
						Name:  "env-1",
						Value: "value-1",
					},
					{
						Name:  "env-2",
						Value: "value-2",
					},
				},
				envFrom: []corev1api.EnvFromSource{
					{
						ConfigMapRef: &corev1api.ConfigMapEnvSource{
							LocalObjectReference: corev1api.LocalObjectReference{
								Name: "test-configmap",
							},
						},
					},
					{
						SecretRef: &corev1api.SecretEnvSource{
							LocalObjectReference: corev1api.LocalObjectReference{
								Name: "test-secret",
							},
						},
					},
				},
				volumeMounts: []corev1api.VolumeMount{
					{
						Name: "volume-1",
					},
					{
						Name: "volume-2",
					},
				},
				volumes: []corev1api.Volume{
					{
						Name: "volume-1",
					},
					{
						Name: "volume-2",
					},
				},
				logFormatArgs: []string{
					"--log-format=json",
				},
				logLevelArgs: []string{
					"--log-level",
					"debug",
				},
				imagePullSecrets: []corev1api.LocalObjectReference{
					{
						Name: "imagePullSecret1",
					},
				},
			},
		},
		{
			name:      "host path volumes are inherited by default",
			namespace: "fake-ns",
			kubeClientObj: []runtime.Object{
				daemonSetWithHostPath,
			},
			result: inheritedPodInfo{
				image:          "image-1",
				serviceAccount: "sa-1",
				volumeMounts:   daemonSetWithHostPath.Spec.Template.Spec.Containers[0].VolumeMounts,
				volumes:        daemonSetWithHostPath.Spec.Template.Spec.Volumes,
			},
		},
		{
			name:      "host path volumes and their mounts are excluded, no matter how they are named",
			namespace: "fake-ns",
			kubeClientObj: []runtime.Object{
				daemonSetWithHostPath,
			},
			excludeHostPath: true,
			result: inheritedPodInfo{
				image:          "image-1",
				serviceAccount: "sa-1",
				volumeMounts:   scratchAndCredentialMounts,
				volumes:        scratchAndCredentialVolumes,
			},
		},
		{
			name:      "excluding host path volumes keeps the others when there is none",
			namespace: "fake-ns",
			kubeClientObj: []runtime.Object{
				daemonSetWithNoLog,
			},
			excludeHostPath: true,
			result: inheritedPodInfo{
				image:          "image-1",
				serviceAccount: "sa-1",
				env: []corev1api.EnvVar{
					{
						Name:  "env-1",
						Value: "value-1",
					},
					{
						Name:  "env-2",
						Value: "value-2",
					},
				},
				envFrom: []corev1api.EnvFromSource{
					{
						ConfigMapRef: &corev1api.ConfigMapEnvSource{
							LocalObjectReference: corev1api.LocalObjectReference{
								Name: "test-configmap",
							},
						},
					},
					{
						SecretRef: &corev1api.SecretEnvSource{
							LocalObjectReference: corev1api.LocalObjectReference{
								Name: "test-secret",
							},
						},
					},
				},
				volumeMounts: []corev1api.VolumeMount{
					{
						Name: "volume-1",
					},
					{
						Name: "volume-2",
					},
				},
				volumes: []corev1api.Volume{
					{
						Name: "volume-1",
					},
					{
						Name: "volume-2",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)
			info, err := getInheritedPodInfo(t.Context(), fakeKubeClient, test.namespace, kube.NodeOSLinux, test.excludeHostPath)

			if test.expectErr == "" {
				require.NoError(t, err)
				assert.True(t, reflect.DeepEqual(info, test.result))
			} else {
				assert.EqualError(t, err, test.expectErr)
			}
		})
	}
}
