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

package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestPodActionExecute(t *testing.T) {
	var priority int32 = 1

	tests := []struct {
		name            string
		obj             corev1api.Pod
		expectedErr     bool
		expectedRes     corev1api.Pod
		additionalItems []velero.ResourceIdentifier
	}{
		{
			name: "nodeName (only) should be deleted from spec",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					NodeName:           "foo",
					ServiceAccountName: "bar",
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "bar",
				},
			},
		},
		{
			name: "priority (only) should be deleted from spec",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					Priority:           &priority,
					ServiceAccountName: "bar",
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "bar",
				},
			},
		},
		{
			name: "volumes matching prefix <service account name>-token- should be deleted",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
						{Name: "foo-token-foo"},
					},
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
					},
				},
			},
		},
		{
			name: "container volumeMounts matching prefix <service account name>-token- should be deleted",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
						{Name: "foo-token-foo"},
					},
					Containers: []corev1api.Container{
						{
							VolumeMounts: []corev1api.VolumeMount{
								{Name: "foo"},
								{Name: "foo-token-foo"},
							},
						},
					},
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
					},
					Containers: []corev1api.Container{
						{
							VolumeMounts: []corev1api.VolumeMount{
								{Name: "foo"},
							},
						},
					},
				},
			},
		},
		{
			name: "initContainer volumeMounts matching prefix <service account name>-token- should be deleted",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
						{Name: "foo-token-foo"},
					},
					InitContainers: []corev1api.Container{
						{
							VolumeMounts: []corev1api.VolumeMount{
								{Name: "foo"},
								{Name: "foo-token-foo"},
							},
						},
					},
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
					},
					InitContainers: []corev1api.Container{
						{
							VolumeMounts: []corev1api.VolumeMount{
								{Name: "foo"},
							},
						},
					},
				},
			},
		},
		{
			name: "ephemeralContainer volumeMounts matching prefix <service account name>-token- should be deleted",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
						{Name: "foo-token-foo"},
					},
					EphemeralContainers: []corev1api.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1api.EphemeralContainerCommon{
								VolumeMounts: []corev1api.VolumeMount{
									{Name: "foo"},
									{Name: "foo-token-foo"},
								},
							},
						},
					},
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
					},
					EphemeralContainers: []corev1api.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1api.EphemeralContainerCommon{
								VolumeMounts: []corev1api.VolumeMount{
									{Name: "foo"},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "containers and initContainers with no volume mounts should not error",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
						{Name: "foo-token-foo"},
					},
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
					},
				},
			},
		},
		{
			name: "test priority class",
			obj: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					PriorityClassName:  "testPriorityClass",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
						{Name: "foo-token-foo"},
					},
				},
			},
			expectedRes: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-1"},
				Spec: corev1api.PodSpec{
					ServiceAccountName: "foo",
					PriorityClassName:  "testPriorityClass",
					Volumes: []corev1api.Volume{
						{Name: "foo"},
					},
				},
			},
			additionalItems: []velero.ResourceIdentifier{
				{GroupResource: kuberesource.PriorityClasses,
					Name: "testPriorityClass",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := NewPodAction(velerotest.NewLogger())

			unstructuredPod, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&test.obj)
			require.NoError(t, err)

			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: unstructuredPod},
				ItemFromBackup: &unstructured.Unstructured{Object: unstructuredPod},
				Restore:        nil,
			})

			if test.expectedErr {
				assert.Error(t, err, "expected an error")
				return
			}
			require.NoError(t, err, "expected no error, got %v", err)

			var pod corev1api.Pod
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &pod))

			assert.Equal(t, test.expectedRes, pod)
			assert.Equal(t, test.additionalItems, res.AdditionalItems)
		})
	}
}
