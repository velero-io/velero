/*
Copyright 2020 the Velero contributors.

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

	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestInitContainerRestoreHookPodActionExecute(t *testing.T) {
	testCases := []struct {
		name        string
		obj         *corev1api.Pod
		expectedErr bool
		expectedRes *corev1api.Pod
		restore     *velerov1api.Restore
	}{
		{
			name:    "should run restore hooks from pod annotation",
			restore: &velerov1api.Restore{},
			obj: builder.ForPod("default", "app1").
				ObjectMeta(builder.WithAnnotations(
					"init.hook.restore.velero.io/container-image", "nginx",
					"init.hook.restore.velero.io/container-name", "restore-init-container",
					"init.hook.restore.velero.io/command", `["a", "b", "c"]`,
				)).
				ServiceAccount("foo").
				Volumes([]*corev1api.Volume{{Name: "foo"}}...).
				InitContainers([]*corev1api.Container{
					builder.ForContainer("init-app-step1", "busy-box").
						Command([]string{"init-step1"}).Result(),
					builder.ForContainer("init-app-step2", "busy-box").
						Command([]string{"init-step2"}).Result(),
					builder.ForContainer("init-app-step3", "busy-box").
						Command([]string{"init-step3"}).Result()}...).Result(),
			expectedRes: builder.ForPod("default", "app1").
				ObjectMeta(builder.WithAnnotations(
					"init.hook.restore.velero.io/container-image", "nginx",
					"init.hook.restore.velero.io/container-name", "restore-init-container",
					"init.hook.restore.velero.io/command", `["a", "b", "c"]`,
				)).
				ServiceAccount("foo").
				Volumes([]*corev1api.Volume{{Name: "foo"}}...).
				InitContainers([]*corev1api.Container{
					builder.ForContainer("restore-init-container", "nginx").
						Command([]string{"a", "b", "c"}).Result(),
					builder.ForContainer("init-app-step1", "busy-box").
						Command([]string{"init-step1"}).Result(),
					builder.ForContainer("init-app-step2", "busy-box").
						Command([]string{"init-step2"}).Result(),
					builder.ForContainer("init-app-step3", "busy-box").
						Command([]string{"init-step3"}).Result()}...).Result(),
		},
		{
			name: "should run restore hook from restore spec",
			restore: &velerov1api.Restore{
				Spec: velerov1api.RestoreSpec{
					Hooks: velerov1api.RestoreHooks{
						Resources: []velerov1api.RestoreResourceHookSpec{
							{
								Name:               "h1",
								IncludedNamespaces: []string{"default"},
								IncludedResources:  []string{kuberesource.Pods.Resource},
								PostHooks: []velerov1api.RestoreResourceHook{
									{
										Init: &velerov1api.InitRestoreHook{
											InitContainers: []runtime.RawExtension{
												builder.ForContainer("restore-init1", "busy-box").
													Command([]string{"foobarbaz"}).ResultRawExtension(),
												builder.ForContainer("restore-init2", "busy-box").
													Command([]string{"foobarbaz"}).ResultRawExtension(),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			obj: builder.ForPod("default", "app1").
				ServiceAccount("foo").
				Volumes([]*corev1api.Volume{{Name: "foo"}}...).Result(),
			expectedRes: builder.ForPod("default", "app1").
				ServiceAccount("foo").
				Volumes([]*corev1api.Volume{{Name: "foo"}}...).
				InitContainers([]*corev1api.Container{
					builder.ForContainer("restore-init1", "busy-box").
						Command([]string{"foobarbaz"}).Result(),
					builder.ForContainer("restore-init2", "busy-box").
						Command([]string{"foobarbaz"}).Result(),
				}...).Result(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			action := NewInitRestoreHookPodAction(velerotest.NewLogger())
			unstructuredPod, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&tc.obj)
			require.NoError(t, err)

			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: unstructuredPod},
				ItemFromBackup: &unstructured.Unstructured{Object: unstructuredPod},
				Restore:        tc.restore,
			})
			if tc.expectedErr {
				assert.Error(t, err, "expected an error")
				return
			}
			require.NoError(t, err, "expected no error, got %v", err)

			var pod corev1api.Pod
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &pod))

			assert.Equal(t, *tc.expectedRes, pod)
		})
	}
}
