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

package hook

import (
	"fmt"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
)

func TestHandleHooksSkips(t *testing.T) {
	tests := []struct {
		name          string
		groupResource string
		item          runtime.Unstructured
		hooks         []ResourceHook
	}{
		{
			name:          "not a pod",
			groupResource: "widget.group",
		},
		{
			name: "pod without annotation / no spec hooks",
			item: velerotest.UnstructuredOrDie(
				`
				{
					"apiVersion": "v1",
					"kind": "Pod",
					"metadata": {
						"namespace": "ns",
						"name": "foo"
					}
				}
				`,
			),
		},
		{
			name:          "spec hooks not applicable",
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(
				`
				{
					"apiVersion": "v1",
					"kind": "Pod",
					"metadata": {
						"namespace": "ns",
						"name": "foo",
						"labels": {
							"color": "blue"
						}
					}
				}
				`,
			),
			hooks: []ResourceHook{
				{
					Name:     "ns exclude",
					Selector: ResourceHookSelector{Namespaces: collections.NewIncludesExcludes().Excludes("ns")},
				},
				{
					Name:     "resource exclude",
					Selector: ResourceHookSelector{Resources: collections.NewIncludesExcludes().Includes("widgets.group")},
				},
				{
					Name:     "label selector mismatch",
					Selector: ResourceHookSelector{LabelSelector: parseLabelSelectorOrDie("color=green")},
				},
				{
					Name: "missing exec hook",
					Pre: []velerov1api.BackupResourceHook{
						{},
						{},
					},
				},
			},
		},
	}

	hookTracker := NewHookTracker()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			podCommandExecutor := &velerotest.MockPodCommandExecutor{}
			defer podCommandExecutor.AssertExpectations(t)

			h := &DefaultItemHookHandler{
				PodCommandExecutor: podCommandExecutor,
			}

			groupResource := schema.ParseGroupResource(test.groupResource)
			err := h.HandleHooks(velerotest.NewLogger(), groupResource, test.item, test.hooks, PhasePre, hookTracker)
			require.NoError(t, err)
		})
	}
}

func TestHandleHooks(t *testing.T) {
	tests := []struct {
		name                  string
		phase                 HookPhase
		groupResource         string
		item                  runtime.Unstructured
		hooks                 []ResourceHook
		hookErrorsByContainer map[string]error
		expectedError         error
		expectedPodHook       *velerov1api.ExecHook
		expectedPodHookError  error
	}{
		{
			name:          "pod, no annotation, spec (multiple pre hooks) = run spec",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name"
			}
		}`),
			hooks: []ResourceHook{
				{
					Name: "hook1",
					Pre: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "1a",
								Command:   []string{"pre-1a"},
							},
						},
						{
							Exec: &velerov1api.ExecHook{
								Container: "1b",
								Command:   []string{"pre-1b"},
							},
						},
					},
				},
				{
					Name: "hook2",
					Pre: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "2a",
								Command:   []string{"2a"},
							},
						},
						{
							Exec: &velerov1api.ExecHook{
								Container: "2b",
								Command:   []string{"2b"},
							},
						},
					},
				},
			},
		},
		{
			name:          "pod, no annotation, spec (multiple post hooks) = run spec",
			phase:         PhasePost,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name"
			}
		}`),
			hooks: []ResourceHook{
				{
					Name: "hook1",
					Post: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "1a",
								Command:   []string{"pre-1a"},
							},
						},
						{
							Exec: &velerov1api.ExecHook{
								Container: "1b",
								Command:   []string{"pre-1b"},
							},
						},
					},
				},
				{
					Name: "hook2",
					Post: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "2a",
								Command:   []string{"2a"},
							},
						},
						{
							Exec: &velerov1api.ExecHook{
								Container: "2b",
								Command:   []string{"2b"},
							},
						},
					},
				},
			},
		},
		{
			name:          "pod, annotation (legacy), no spec = run annotation",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name",
				"annotations": {
					"hook.backup.velero.io/container": "c",
					"hook.backup.velero.io/command": "/bin/ls"
				}
			}
		}`),
			expectedPodHook: &velerov1api.ExecHook{
				Container: "c",
				Command:   []string{"/bin/ls"},
			},
		},
		{
			name:          "pod, annotation (pre), no spec = run annotation",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name",
				"annotations": {
					"pre.hook.backup.velero.io/container": "c",
					"pre.hook.backup.velero.io/command": "/bin/ls"
				}
			}
		}`),
			expectedPodHook: &velerov1api.ExecHook{
				Container: "c",
				Command:   []string{"/bin/ls"},
			},
		},
		{
			name:          "pod, annotation (post), no spec = run annotation",
			phase:         PhasePost,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name",
				"annotations": {
					"post.hook.backup.velero.io/container": "c",
					"post.hook.backup.velero.io/command": "/bin/ls"
				}
			}
		}`),
			expectedPodHook: &velerov1api.ExecHook{
				Container: "c",
				Command:   []string{"/bin/ls"},
			},
		},
		{
			name:          "pod, annotation & spec = run annotation",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name",
				"annotations": {
					"hook.backup.velero.io/container": "c",
					"hook.backup.velero.io/command": "/bin/ls"
				}
			}
		}`),
			expectedPodHook: &velerov1api.ExecHook{
				Container: "c",
				Command:   []string{"/bin/ls"},
			},
			hooks: []ResourceHook{
				{
					Name: "hook1",
					Pre: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "1a",
								Command:   []string{"1a"},
							},
						},
					},
				},
			},
		},
		{
			name:          "pod, annotation, onError=fail = return error",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name",
				"annotations": {
					"hook.backup.velero.io/container": "c",
					"hook.backup.velero.io/command": "/bin/ls",
					"hook.backup.velero.io/on-error": "Fail"
				}
			}
		}`),
			expectedPodHook: &velerov1api.ExecHook{
				Container: "c",
				Command:   []string{"/bin/ls"},
				OnError:   velerov1api.HookErrorModeFail,
			},
			expectedPodHookError: errors.New("pod hook error"),
			expectedError:        errors.New("pod hook error"),
		},
		{
			name:          "pod, annotation, onError=continue = return nil",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name",
				"annotations": {
					"hook.backup.velero.io/container": "c",
					"hook.backup.velero.io/command": "/bin/ls",
					"hook.backup.velero.io/on-error": "Continue"
				}
			}
		}`),
			expectedPodHook: &velerov1api.ExecHook{
				Container: "c",
				Command:   []string{"/bin/ls"},
				OnError:   velerov1api.HookErrorModeContinue,
			},
			expectedPodHookError: errors.New("pod hook error"),
			expectedError:        nil,
		},
		{
			name:          "pod, spec, onError=fail = don't run other hooks",
			phase:         PhasePre,
			groupResource: "pods",
			item: velerotest.UnstructuredOrDie(`
		{
			"apiVersion": "v1",
			"kind": "Pod",
			"metadata": {
				"namespace": "ns",
				"name": "name"
			}
		}`),
			hooks: []ResourceHook{
				{
					Name: "hook1",
					Pre: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "1a",
								Command:   []string{"1a"},
								OnError:   velerov1api.HookErrorModeContinue,
							},
						},
						{
							Exec: &velerov1api.ExecHook{
								Container: "1b",
								Command:   []string{"1b"},
							},
						},
					},
				},
				{
					Name: "hook2",
					Pre: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "2",
								Command:   []string{"2"},
								OnError:   velerov1api.HookErrorModeFail,
							},
						},
					},
				},
				{
					Name: "hook3",
					Pre: []velerov1api.BackupResourceHook{
						{
							Exec: &velerov1api.ExecHook{
								Container: "3",
								Command:   []string{"3"},
							},
						},
					},
				},
			},
			hookErrorsByContainer: map[string]error{
				"1a": errors.New("1a error, but continue"),
				"2":  errors.New("2 error, fail"),
			},
			expectedError: errors.New("2 error, fail"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			podCommandExecutor := &velerotest.MockPodCommandExecutor{}
			defer podCommandExecutor.AssertExpectations(t)

			h := &DefaultItemHookHandler{
				PodCommandExecutor: podCommandExecutor,
			}

			if test.expectedPodHook != nil {
				podCommandExecutor.On("ExecutePodCommand", mock.Anything, test.item.UnstructuredContent(), "ns", "name", "<from-annotation>", test.expectedPodHook).Return(test.expectedPodHookError)
			} else {
			hookLoop:
				for _, resourceHook := range test.hooks {
					for _, hook := range resourceHook.Pre {
						hookError := test.hookErrorsByContainer[hook.Exec.Container]
						podCommandExecutor.On("ExecutePodCommand", mock.Anything, test.item.UnstructuredContent(), "ns", "name", resourceHook.Name, hook.Exec).Return(hookError)
						if hookError != nil && hook.Exec.OnError == velerov1api.HookErrorModeFail {
							break hookLoop
						}
					}
					for _, hook := range resourceHook.Post {
						hookError := test.hookErrorsByContainer[hook.Exec.Container]
						podCommandExecutor.On("ExecutePodCommand", mock.Anything, test.item.UnstructuredContent(), "ns", "name", resourceHook.Name, hook.Exec).Return(hookError)
						if hookError != nil && hook.Exec.OnError == velerov1api.HookErrorModeFail {
							break hookLoop
						}
					}
				}
			}

			groupResource := schema.ParseGroupResource(test.groupResource)
			hookTracker := NewHookTracker()
			err := h.HandleHooks(velerotest.NewLogger(), groupResource, test.item, test.hooks, test.phase, hookTracker)

			if test.expectedError != nil {
				assert.EqualError(t, err, test.expectedError.Error())
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestGetPodExecHookFromAnnotations(t *testing.T) {
	phases := []HookPhase{"", PhasePre, PhasePost}
	for _, phase := range phases {
		tests := []struct {
			name         string
			annotations  map[string]string
			expectedHook *velerov1api.ExecHook
		}{
			{
				name:         "missing command annotation",
				expectedHook: nil,
			},
			{
				name: "malformed command json array",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): "[blarg",
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"[blarg"},
				},
			},
			{
				name: "valid command json array",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): `["a","b","c"]`,
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"a", "b", "c"},
				},
			},
			{
				name: "command as a string",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): "/usr/bin/foo",
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"/usr/bin/foo"},
				},
			},
			{
				name: "hook mode set to continue",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): "/usr/bin/foo",
					phasedKey(phase, podBackupHookOnErrorAnnotationKey): string(velerov1api.HookErrorModeContinue),
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"/usr/bin/foo"},
					OnError: velerov1api.HookErrorModeContinue,
				},
			},
			{
				name: "hook mode set to fail",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): "/usr/bin/foo",
					phasedKey(phase, podBackupHookOnErrorAnnotationKey): string(velerov1api.HookErrorModeFail),
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"/usr/bin/foo"},
					OnError: velerov1api.HookErrorModeFail,
				},
			},
			{
				name: "use the specified timeout",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): "/usr/bin/foo",
					phasedKey(phase, podBackupHookTimeoutAnnotationKey): "5m3s",
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"/usr/bin/foo"},
					Timeout: metav1.Duration{Duration: 5*time.Minute + 3*time.Second},
				},
			},
			{
				name: "invalid timeout is logged",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookCommandAnnotationKey): "/usr/bin/foo",
					phasedKey(phase, podBackupHookTimeoutAnnotationKey): "invalid",
				},
				expectedHook: &velerov1api.ExecHook{
					Command: []string{"/usr/bin/foo"},
				},
			},
			{
				name: "use the specified container",
				annotations: map[string]string{
					phasedKey(phase, podBackupHookContainerAnnotationKey): "some-container",
					phasedKey(phase, podBackupHookCommandAnnotationKey):   "/usr/bin/foo",
				},
				expectedHook: &velerov1api.ExecHook{
					Container: "some-container",
					Command:   []string{"/usr/bin/foo"},
				},
			},
		}

		for _, test := range tests {
			t.Run(fmt.Sprintf("%s (phase=%q)", test.name, phase), func(t *testing.T) {
				l := velerotest.NewLogger()
				hook := getPodExecHookFromAnnotations(test.annotations, phase, l)
				assert.Equal(t, test.expectedHook, hook)
			})
		}
	}
}

func TestResourceHookApplicableTo(t *testing.T) {
	tests := []struct {
		name               string
		includedNamespaces []string
		excludedNamespaces []string
		includedResources  []string
		excludedResources  []string
		labelSelector      string
		namespace          string
		resource           schema.GroupResource
		labels             labels.Set
		expected           bool
	}{
		{
			name:      "allow anything",
			namespace: "foo",
			resource:  schema.GroupResource{Group: "foo", Resource: "bar"},
			expected:  true,
		},
		{
			name:               "namespace in included list",
			includedNamespaces: []string{"a", "b"},
			excludedNamespaces: []string{"c", "d"},
			namespace:          "b",
			expected:           true,
		},
		{
			name:               "namespace not in included list",
			includedNamespaces: []string{"a", "b"},
			namespace:          "c",
			expected:           false,
		},
		{
			name:               "namespace excluded",
			excludedNamespaces: []string{"a", "b"},
			namespace:          "a",
			expected:           false,
		},
		{
			name:              "resource in included list",
			includedResources: []string{"foo.a", "bar.b"},
			excludedResources: []string{"baz.c"},
			resource:          schema.GroupResource{Group: "a", Resource: "foo"},
			expected:          true,
		},
		{
			name:              "resource not in included list",
			includedResources: []string{"foo.a", "bar.b"},
			resource:          schema.GroupResource{Group: "c", Resource: "baz"},
			expected:          false,
		},
		{
			name:              "resource excluded",
			excludedResources: []string{"foo.a", "bar.b"},
			resource:          schema.GroupResource{Group: "b", Resource: "bar"},
			expected:          false,
		},
		{
			name:          "label selector matches",
			labelSelector: "a=b",
			labels:        labels.Set{"a": "b"},
			expected:      true,
		},
		{
			name:          "label selector doesn't match",
			labelSelector: "a=b",
			labels:        labels.Set{"a": "c"},
			expected:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := ResourceHook{
				Selector: ResourceHookSelector{
					Namespaces: collections.NewIncludesExcludes().Includes(test.includedNamespaces...).Excludes(test.excludedNamespaces...),
					Resources:  collections.NewIncludesExcludes().Includes(test.includedResources...).Excludes(test.excludedResources...),
				},
			}
			if test.labelSelector != "" {
				selector, err := labels.Parse(test.labelSelector)
				require.NoError(t, err)
				h.Selector.LabelSelector = selector
			}

			result := h.Selector.applicableTo(test.resource, test.namespace, test.labels)
			assert.Equal(t, test.expected, result)
		})
	}
}

func parseLabelSelectorOrDie(s string) labels.Selector {
	ret, err := labels.Parse(s)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestGetPodExecRestoreHookFromAnnotations(t *testing.T) {
	testCases := []struct {
		name             string
		inputAnnotations map[string]string
		expected         *velerov1api.ExecRestoreHook
	}{
		{
			name:             "should return nil when command is missing",
			inputAnnotations: nil,
			expected:         nil,
		},
		{
			name: "should return nil when command is empty string",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey: "",
			},
			expected: nil,
		},
		{
			name: "should return a hook when 1 item command is a string",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey: "/usr/bin/foo",
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "should return a multi-item hook when command is a json array",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey: `["a","b","c"]`,
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"a", "b", "c"},
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "error mode continue should be in returned hook when set in annotation",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey: "/usr/bin/foo",
				podRestoreHookOnErrorAnnotationKey: string(velerov1api.HookErrorModeContinue),
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				OnError:      velerov1api.HookErrorModeContinue,
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "error mode fail should be in returned hook when set in annotation",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey: "/usr/bin/foo",
				podRestoreHookOnErrorAnnotationKey: string(velerov1api.HookErrorModeFail),
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				OnError:      velerov1api.HookErrorModeFail,
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "exec and wait timeouts should be in returned hook when set in annotations",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey:     "/usr/bin/foo",
				podRestoreHookTimeoutAnnotationKey:     "45s",
				podRestoreHookWaitTimeoutAnnotationKey: "1h",
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				ExecTimeout:  metav1.Duration{Duration: 45 * time.Second},
				WaitTimeout:  metav1.Duration{Duration: time.Hour},
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "container should be in returned hook when set in annotation",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey:   "/usr/bin/foo",
				podRestoreHookContainerAnnotationKey: "my-app",
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				Container:    "my-app",
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "bad exec timeout should be discarded",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey:   "/usr/bin/foo",
				podRestoreHookContainerAnnotationKey: "my-app",
				podRestoreHookTimeoutAnnotationKey:   "none",
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				Container:    "my-app",
				ExecTimeout:  metav1.Duration{Duration: 0},
				WaitForReady: boolptr.False(),
			},
		},
		{
			name: "bad wait timeout should be discarded",
			inputAnnotations: map[string]string{
				podRestoreHookCommandAnnotationKey:     "/usr/bin/foo",
				podRestoreHookContainerAnnotationKey:   "my-app",
				podRestoreHookWaitTimeoutAnnotationKey: "none",
			},
			expected: &velerov1api.ExecRestoreHook{
				Command:      []string{"/usr/bin/foo"},
				Container:    "my-app",
				ExecTimeout:  metav1.Duration{Duration: 0},
				WaitForReady: boolptr.False(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := velerotest.NewLogger()
			actual := getPodExecRestoreHookFromAnnotations(tc.inputAnnotations, l)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGroupRestoreExecHooks(t *testing.T) {
	testCases := []struct {
		name                 string
		resourceRestoreHooks []ResourceRestoreHook
		pod                  *corev1api.Pod
		expected             map[string][]PodExecRestoreHook
	}{
		{
			name:                 "should return empty map when neither spec hooks nor annotations hooks are set",
			resourceRestoreHooks: nil,
			pod:                  builder.ForPod("default", "my-pod").Result(),
			expected:             map[string][]PodExecRestoreHook{},
		},
		{
			name:                 "should return hook from annotation when no spec hooks are set",
			resourceRestoreHooks: nil,
			pod: builder.ForPod("default", "my-pod").
				ObjectMeta(builder.WithAnnotations(
					podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
					podRestoreHookContainerAnnotationKey, "container1",
					podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeContinue),
					podRestoreHookTimeoutAnnotationKey, "1s",
					podRestoreHookWaitTimeoutAnnotationKey, "1m",
					podRestoreHookWaitForReadyAnnotationKey, "true",
				)).
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/foo"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second},
							WaitTimeout:  metav1.Duration{Duration: time.Minute},
							WaitForReady: boolptr.True(),
						},
					},
				},
			},
		},
		{
			name:                 "should default to first pod container when not set in annotation",
			resourceRestoreHooks: nil,
			pod: builder.ForPod("default", "my-pod").
				ObjectMeta(builder.WithAnnotations(
					podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
					podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeContinue),
					podRestoreHookTimeoutAnnotationKey, "1s",
					podRestoreHookWaitTimeoutAnnotationKey, "1m",
				)).
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/foo"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second},
							WaitTimeout:  metav1.Duration{Duration: time.Minute},
							WaitForReady: boolptr.False(),
						},
					},
				},
			},
		},
		{
			name: "should return hook from spec for pod with no hook annotations",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container1",
								Command:     []string{"/usr/bin/foo"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "hook1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/foo"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second},
							WaitTimeout:  metav1.Duration{Duration: time.Minute},
							WaitForReady: boolptr.False(),
						},
					},
				},
			},
		},
		{
			name: "should default to first container pod when unset in spec hook",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Command:     []string{"/usr/bin/foo"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "hook1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/foo"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second},
							WaitTimeout:  metav1.Duration{Duration: time.Minute},
							WaitForReady: boolptr.False(),
						},
					},
				},
			},
		},
		{
			name: "should return hook from annotation ignoring hooks in spec",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container2",
								Command:     []string{"/usr/bin/bar"},
								OnError:     velerov1api.HookErrorModeFail,
								ExecTimeout: metav1.Duration{Duration: time.Hour},
								WaitTimeout: metav1.Duration{Duration: time.Hour},
							},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				ObjectMeta(builder.WithAnnotations(
					podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
					podRestoreHookContainerAnnotationKey, "container1",
					podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeContinue),
					podRestoreHookTimeoutAnnotationKey, "1s",
					podRestoreHookWaitTimeoutAnnotationKey, "1m",
				)).
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/foo"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second},
							WaitTimeout:  metav1.Duration{Duration: time.Minute},
							WaitForReady: boolptr.False(),
						},
					},
				},
			},
		},
		{
			name: "should return empty map when only has init hook and pod has no hook annotations",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{},
		},
		{
			name: "should return empty map when spec has exec hook for pod in different namespace and pod has no hook annotations",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("other"),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container1",
								Command:     []string{"/usr/bin/foo"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
					},
				},
			},
			pod:      builder.ForPod("default", "my-pod").Result(),
			expected: map[string][]PodExecRestoreHook{},
		},
		{
			name: "should return map with multiple keys when spec hooks apply to multiple containers in pod and has no hook annotations",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container1",
								Command:     []string{"/usr/bin/foo"},
								OnError:     velerov1api.HookErrorModeFail,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container2",
								Command:     []string{"/usr/bin/baz"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second * 3},
								WaitTimeout: metav1.Duration{Duration: time.Second * 3},
							},
						},
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container1",
								Command:     []string{"/usr/bin/bar"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second * 2},
								WaitTimeout: metav1.Duration{Duration: time.Minute * 2},
							},
						},
					},
				},
				{
					Name:     "hook2",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:    "container1",
								Command:      []string{"/usr/bin/aaa"},
								OnError:      velerov1api.HookErrorModeContinue,
								ExecTimeout:  metav1.Duration{Duration: time.Second * 4},
								WaitTimeout:  metav1.Duration{Duration: time.Minute * 4},
								WaitForReady: boolptr.True(),
							},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			expected: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "hook1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/foo"},
							OnError:      velerov1api.HookErrorModeFail,
							ExecTimeout:  metav1.Duration{Duration: time.Second},
							WaitTimeout:  metav1.Duration{Duration: time.Minute},
							WaitForReady: boolptr.False(),
						},
						hookIndex: 0,
					},
					{
						HookName:   "hook1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/bar"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second * 2},
							WaitTimeout:  metav1.Duration{Duration: time.Minute * 2},
							WaitForReady: boolptr.False(),
						},
						hookIndex: 2,
					},
					{
						HookName:   "hook2",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container1",
							Command:      []string{"/usr/bin/aaa"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second * 4},
							WaitTimeout:  metav1.Duration{Duration: time.Minute * 4},
							WaitForReady: boolptr.True(),
						},
						hookIndex: 0,
					},
				},
				"container2": {
					{
						HookName:   "hook1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:    "container2",
							Command:      []string{"/usr/bin/baz"},
							OnError:      velerov1api.HookErrorModeContinue,
							ExecTimeout:  metav1.Duration{Duration: time.Second * 3},
							WaitTimeout:  metav1.Duration{Duration: time.Second * 3},
							WaitForReady: boolptr.False(),
						},
						hookIndex: 1,
					},
				},
			},
		},
	}

	hookTracker := NewMultiHookTracker()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := GroupRestoreExecHooks("restore1", tc.resourceRestoreHooks, tc.pod, velerotest.NewLogger(), hookTracker)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGetInitContainerFromAnnotations(t *testing.T) {
	testCases := []struct {
		name             string
		inputAnnotations map[string]string
		expected         *corev1api.Container
		expectNil        bool
	}{
		{
			name:      "should return nil when container image is empty",
			expectNil: true,
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerImageAnnotationKey:   "",
				podRestoreHookInitContainerNameAnnotationKey:    "restore-init",
				podRestoreHookInitContainerCommandAnnotationKey: "/usr/bin/data-populator",
			},
		},
		{
			name:      "should return nil when container image is missing",
			expectNil: true,
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerNameAnnotationKey:    "restore-init",
				podRestoreHookInitContainerCommandAnnotationKey: "/usr/bin/data-populator",
			},
		},
		{
			name:      "should generate container name when container name is empty",
			expectNil: false,
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerImageAnnotationKey:   "busy-box",
				podRestoreHookInitContainerNameAnnotationKey:    "",
				podRestoreHookInitContainerCommandAnnotationKey: "/usr/bin/data-populator /user-data full",
			},
			expected: builder.ForContainer("restore-init1", "busy-box").
				Command([]string{"/usr/bin/data-populator /user-data full"}).Result(),
		},
		{
			name:      "should generate container name when container name is missing",
			expectNil: false,
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerImageAnnotationKey:   "busy-box",
				podRestoreHookInitContainerCommandAnnotationKey: "/usr/bin/data-populator /user-data full",
			},
			expected: builder.ForContainer("restore-init1", "busy-box").
				Command([]string{"/usr/bin/data-populator /user-data full"}).Result(),
		},
		{
			name:      "should return expected init container when all annotations are specified",
			expectNil: false,
			expected: builder.ForContainer("restore-init1", "busy-box").
				Command([]string{"/usr/bin/data-populator /user-data full"}).Result(),
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerImageAnnotationKey:   "busy-box",
				podRestoreHookInitContainerNameAnnotationKey:    "restore-init",
				podRestoreHookInitContainerCommandAnnotationKey: "/usr/bin/data-populator /user-data full",
			},
		},
		{
			name:      "should return expected init container when all annotations are specified with command as a JSON array",
			expectNil: false,
			expected: builder.ForContainer("restore-init1", "busy-box").
				Command([]string{"a", "b", "c"}).Result(),
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerImageAnnotationKey:   "busy-box",
				podRestoreHookInitContainerNameAnnotationKey:    "restore-init",
				podRestoreHookInitContainerCommandAnnotationKey: `["a","b","c"]`,
			},
		},
		{
			name:      "should return expected init container when all annotations are specified with command as malformed a JSON array",
			expectNil: false,
			expected: builder.ForContainer("restore-init1", "busy-box").
				Command([]string{"[foobarbaz"}).Result(),
			inputAnnotations: map[string]string{
				podRestoreHookInitContainerImageAnnotationKey:   "busy-box",
				podRestoreHookInitContainerNameAnnotationKey:    "restore-init",
				podRestoreHookInitContainerCommandAnnotationKey: "[foobarbaz",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualInitContainer := getInitContainerFromAnnotation("test/pod1", tc.inputAnnotations, velerotest.NewLogger())
			if tc.expectNil {
				assert.Nil(t, actualInitContainer)
				return
			}
			assert.NotEmpty(t, actualInitContainer.Name)
			assert.Equal(t, tc.expected.Image, actualInitContainer.Image)
			assert.Equal(t, tc.expected.Command, actualInitContainer.Command)
		})
	}
}

func TestGetRestoreHooksFromSpec(t *testing.T) {
	testCases := []struct {
		name          string
		hookSpec      *velerov1api.RestoreHooks
		expected      []ResourceRestoreHook
		expectedError error
	}{
		{
			name:          "should return empty hooks and no error when hookSpec is nil",
			hookSpec:      nil,
			expected:      []ResourceRestoreHook{},
			expectedError: nil,
		},
		{
			name: "should return empty hooks and no error when hookSpec resources is nil",
			hookSpec: &velerov1api.RestoreHooks{
				Resources: nil,
			},
			expected:      []ResourceRestoreHook{},
			expectedError: nil,
		},
		{
			name: "should return empty hooks and no error when hookSpec resources is empty",
			hookSpec: &velerov1api.RestoreHooks{
				Resources: []velerov1api.RestoreResourceHookSpec{},
			},
			expected:      []ResourceRestoreHook{},
			expectedError: nil,
		},
		{
			name: "should return hooks specified in the hookSpec initContainer hooks only",
			hookSpec: &velerov1api.RestoreHooks{
				Resources: []velerov1api.RestoreResourceHookSpec{
					{
						Name:               "h1",
						IncludedNamespaces: []string{"ns1", "ns2", "ns3"},
						ExcludedNamespaces: []string{"ns4", "ns5", "ns6"},
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
			expected: []ResourceRestoreHook{
				{
					Name: "h1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("ns1", "ns2", "ns3").Excludes("ns4", "ns5", "ns6"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := GetRestoreHooksFromSpec(tc.hookSpec)

			assert.Equal(t, tc.expected, actual)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestHandleRestoreHooks(t *testing.T) {
	testCases := []struct {
		name             string
		podInput         corev1api.Pod
		restoreHooks     []ResourceRestoreHook
		namespaceMapping map[string]string
		expectedPod      *corev1api.Pod
		expectedError    error
	}{
		{
			name: "should handle hook from annotation no hooks in spec on pod with no init containers",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
					Annotations: map[string]string{
						podRestoreHookInitContainerImageAnnotationKey:   "nginx",
						podRestoreHookInitContainerNameAnnotationKey:    "restore-init-container",
						podRestoreHookInitContainerCommandAnnotationKey: `["a", "b", "c"]`,
					},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
					Annotations: map[string]string{
						podRestoreHookInitContainerImageAnnotationKey:   "nginx",
						podRestoreHookInitContainerNameAnnotationKey:    "restore-init-container",
						podRestoreHookInitContainerCommandAnnotationKey: `["a", "b", "c"]`,
					},
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-init-container", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
					},
				},
			},
		},
		{
			name: "should handle hook from annotation no hooks in spec on pod with init containers",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
					Annotations: map[string]string{
						podRestoreHookInitContainerImageAnnotationKey:   "nginx",
						podRestoreHookInitContainerNameAnnotationKey:    "restore-init-container",
						podRestoreHookInitContainerCommandAnnotationKey: `["a", "b", "c"]`,
					},
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
						*builder.ForContainer("init-app-step3", "busy-box").
							Command([]string{"init-step3"}).Result(),
					},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
					Annotations: map[string]string{
						podRestoreHookInitContainerImageAnnotationKey:   "nginx",
						podRestoreHookInitContainerNameAnnotationKey:    "restore-init-container",
						podRestoreHookInitContainerCommandAnnotationKey: `["a", "b", "c"]`,
					},
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-init-container", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
						*builder.ForContainer("init-app-step3", "busy-box").
							Command([]string{"init-step3"}).Result(),
					},
				},
			},
		},
		{
			name: "should handle hook from annotation ignoring hooks in spec",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
					Annotations: map[string]string{
						podRestoreHookInitContainerImageAnnotationKey:   "nginx",
						podRestoreHookInitContainerNameAnnotationKey:    "restore-init-container",
						podRestoreHookInitContainerCommandAnnotationKey: `["a", "b", "c"]`,
					},
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
						*builder.ForContainer("init-app-step3", "busy-box").
							Command([]string{"init-step3"}).Result(),
					},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
					Annotations: map[string]string{
						podRestoreHookInitContainerImageAnnotationKey:   "nginx",
						podRestoreHookInitContainerNameAnnotationKey:    "restore-init-container",
						podRestoreHookInitContainerCommandAnnotationKey: `["a", "b", "c"]`,
					},
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-init-container", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
						*builder.ForContainer("init-app-step3", "busy-box").
							Command([]string{"init-step3"}).Result(),
					},
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "ignore-hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("should-not exist", "does-not-matter").
										Command([]string{""}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "should handle hook from spec on pod with no init containers",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-init-container-1", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("restore-init-container-2", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
					},
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
									builder.ForContainer("restore-init-container-2", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "should handle hook from spec when no restore hook annotation and existing init containers",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
						*builder.ForContainer("init-app-step3", "busy-box").
							Command([]string{"init-step3"}).Result(),
					},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-init-container-1", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("restore-init-container-2", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
						*builder.ForContainer("init-app-step3", "busy-box").
							Command([]string{"init-step3"}).Result(),
					},
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
									builder.ForContainer("restore-init-container-2", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "should not apply any restore hook init containers when resource hook selector mismatch",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Excludes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
									builder.ForContainer("restore-init-container-2", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "should preserve restore-wait init container when it is the only existing init container",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-wait", "bus-box").
							Command([]string{"pod-volume-restore"}).Result(),
					},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-wait", "bus-box").
							Command([]string{"pod-volume-restore"}).Result(),
						*builder.ForContainer("restore-init-container-1", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("restore-init-container-2", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
					},
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
									builder.ForContainer("restore-init-container-2", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},

		{
			name: "should preserve restore-wait init container when it exits with other init containers",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-wait", "bus-box").
							Command([]string{"pod-volume-restore"}).Result(),
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
					},
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-wait", "bus-box").
							Command([]string{"pod-volume-restore"}).Result(),
						*builder.ForContainer("restore-init-container-1", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("restore-init-container-2", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
						*builder.ForContainer("init-app-step1", "busy-box").
							Command([]string{"init-step1"}).Result(),
						*builder.ForContainer("init-app-step2", "busy-box").
							Command([]string{"init-step2"}).Result(),
					},
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
									builder.ForContainer("restore-init-container-2", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "should not apply any restore hook init containers when resource hook is nil",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
			},
			restoreHooks: nil,
		},
		{
			name: "should not apply any restore hook init containers when resource hook is empty",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
			},
			restoreHooks: []ResourceRestoreHook{},
		},
		{
			name: "should not apply init container when the namespace mapping is provided and the hook points to the original namespace",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("default"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
			namespaceMapping: map[string]string{"default": "new"},
		},
		{
			name: "should apply init container when the namespace mapping is provided and the hook points to the new namespace",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{},
			},
			expectedError: nil,
			expectedPod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "default",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						*builder.ForContainer("restore-init-container-1", "nginx").
							Command([]string{"a", "b", "c"}).Result(),
					},
				},
			},
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("new"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										Command([]string{"a", "b", "c"}).ResultRawExtension(),
								},
							},
						},
					},
				},
			},
			namespaceMapping: map[string]string{"default": "new"},
		},
		{
			name: "Invalid InitContainer in Restore hook should return nil as pod, and error.",
			podInput: corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app1",
					Namespace: "new",
				},
				Spec: corev1api.PodSpec{},
			},
			expectedError: fmt.Errorf("invalid InitContainer in restore hook, it doesn't have Command, Name or Image field"),
			expectedPod:   nil,
			restoreHooks: []ResourceRestoreHook{
				{
					Name: "hook1",
					Selector: ResourceHookSelector{
						Namespaces: collections.NewIncludesExcludes().Includes("new"),
						Resources:  collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
					},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Init: &velerov1api.InitRestoreHook{
								InitContainers: []runtime.RawExtension{
									builder.ForContainer("restore-init-container-1", "nginx").
										ResultRawExtension(),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := InitContainerRestoreHookHandler{}
			podMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&tc.podInput)
			require.NoError(t, err)
			actual, err := handler.HandleRestoreHooks(velerotest.NewLogger(), kuberesource.Pods, &unstructured.Unstructured{Object: podMap}, tc.restoreHooks, tc.namespaceMapping)
			assert.Equal(t, tc.expectedError, err)
			if actual != nil {
				actualPod := new(corev1api.Pod)
				err = runtime.DefaultUnstructuredConverter.FromUnstructured(actual.UnstructuredContent(), actualPod)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedPod, actualPod)
			}
		})
	}
}

func TestValidateContainer(t *testing.T) {
	valid := `{"name": "test", "image": "busybox", "command": ["pwd"]}`
	noName := `{"image": "busybox", "command": ["pwd"]}`
	noImage := `{"name": "test", "command": ["pwd"]}`
	noCommand := `{"name": "test", "image": "busybox"}`
	expectedError := fmt.Errorf("invalid InitContainer in restore hook, it doesn't have Command, Name or Image field")

	// valid string should return nil as result.
	require.NoError(t, ValidateContainer([]byte(valid)))

	// noName string should return expected error as result.
	assert.Equal(t, expectedError, ValidateContainer([]byte(noName)))

	// noImage string should return expected error as result.
	assert.Equal(t, expectedError, ValidateContainer([]byte(noImage)))

	// noCommand string should return expected error as result.
	assert.Equal(t, expectedError, ValidateContainer([]byte(noCommand)))
}

func TestBackupHookTracker(t *testing.T) {
	type podWithHook struct {
		item                  runtime.Unstructured
		hooks                 []ResourceHook
		hookErrorsByContainer map[string]error
		expectedPodHook       *velerov1api.ExecHook
		expectedPodHookError  error
		expectedError         error
	}
	test1 := []struct {
		name                  string
		phase                 HookPhase
		groupResource         string
		pods                  []podWithHook
		hookTracker           *HookTracker
		expectedHookAttempted int
		expectedHookFailed    int
	}{
		{
			name:                  "a pod with spec hooks, no error",
			phase:                 PhasePre,
			groupResource:         "pods",
			hookTracker:           NewHookTracker(),
			expectedHookAttempted: 2,
			expectedHookFailed:    0,
			pods: []podWithHook{
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name"
						}
					}`),
					hooks: []ResourceHook{
						{
							Name: "hook1",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "1a",
										Command:   []string{"pre-1a"},
									},
								},
								{
									Exec: &velerov1api.ExecHook{
										Container: "1b",
										Command:   []string{"pre-1b"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:                  "a pod with spec hooks and same container under different hook name, no error",
			phase:                 PhasePre,
			groupResource:         "pods",
			hookTracker:           NewHookTracker(),
			expectedHookAttempted: 4,
			expectedHookFailed:    0,
			pods: []podWithHook{
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name"
						}
					}`),
					hooks: []ResourceHook{
						{
							Name: "hook1",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "1a",
										Command:   []string{"pre-1a"},
									},
								},
								{
									Exec: &velerov1api.ExecHook{
										Container: "1b",
										Command:   []string{"pre-1b"},
									},
								},
							},
						},
						{
							Name: "hook2",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "1a",
										Command:   []string{"2a"},
									},
								},
								{
									Exec: &velerov1api.ExecHook{
										Container: "2b",
										Command:   []string{"2b"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:                  "a pod with spec hooks, on error=fail",
			phase:                 PhasePre,
			groupResource:         "pods",
			hookTracker:           NewHookTracker(),
			expectedHookAttempted: 4,
			expectedHookFailed:    2,
			pods: []podWithHook{
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name"
						}
					}`),
					hooks: []ResourceHook{
						{
							Name: "hook1",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "1a",
										Command:   []string{"1a"},
										OnError:   velerov1api.HookErrorModeContinue,
									},
								},
								{
									Exec: &velerov1api.ExecHook{
										Container: "1b",
										Command:   []string{"1b"},
									},
								},
							},
						},
						{
							Name: "hook2",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "2",
										Command:   []string{"2"},
										OnError:   velerov1api.HookErrorModeFail,
									},
								},
							},
						},
						{
							Name: "hook3",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "3",
										Command:   []string{"3"},
									},
								},
							},
						},
					},
					hookErrorsByContainer: map[string]error{
						"1a": errors.New("1a error, but continue"),
						"2":  errors.New("2 error, fail"),
					},
				},
			},
		},
		{
			name:                  "a pod with annotation and spec hooks",
			phase:                 PhasePre,
			groupResource:         "pods",
			hookTracker:           NewHookTracker(),
			expectedHookAttempted: 1,
			expectedHookFailed:    0,
			pods: []podWithHook{
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name",
							"annotations": {
								"hook.backup.velero.io/container": "c",
								"hook.backup.velero.io/command": "/bin/ls"
							}
						}
					}`),
					expectedPodHook: &velerov1api.ExecHook{
						Container: "c",
						Command:   []string{"/bin/ls"},
					},
					hooks: []ResourceHook{
						{
							Name: "hook1",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "1a",
										Command:   []string{"1a"},
										OnError:   velerov1api.HookErrorModeContinue,
									},
								},
								{
									Exec: &velerov1api.ExecHook{
										Container: "1b",
										Command:   []string{"1b"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:                  "a pod with annotation, on error=fail",
			phase:                 PhasePre,
			groupResource:         "pods",
			hookTracker:           NewHookTracker(),
			expectedHookAttempted: 1,
			expectedHookFailed:    1,
			pods: []podWithHook{
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name",
							"annotations": {
								"hook.backup.velero.io/container": "c",
								"hook.backup.velero.io/command": "/bin/ls",
								"hook.backup.velero.io/on-error": "Fail"
							}
						}
					}`),
					expectedPodHook: &velerov1api.ExecHook{
						Container: "c",
						Command:   []string{"/bin/ls"},
						OnError:   velerov1api.HookErrorModeFail,
					},
					expectedPodHookError: errors.New("pod hook error"),
				},
			},
		},
		{
			name:                  "two pods, one with annotation, the other with spec",
			phase:                 PhasePre,
			groupResource:         "pods",
			hookTracker:           NewHookTracker(),
			expectedHookAttempted: 3,
			expectedHookFailed:    1,
			pods: []podWithHook{
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name",
							"annotations": {
								"hook.backup.velero.io/container": "c",
								"hook.backup.velero.io/command": "/bin/ls",
								"hook.backup.velero.io/on-error": "Fail"
							}
						}
					}`),
					expectedPodHook: &velerov1api.ExecHook{
						Container: "c",
						Command:   []string{"/bin/ls"},
						OnError:   velerov1api.HookErrorModeFail,
					},
					expectedPodHookError: errors.New("pod hook error"),
				},
				{
					item: velerotest.UnstructuredOrDie(`
					{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"namespace": "ns",
							"name": "name"
						}
					}`),
					hooks: []ResourceHook{
						{
							Name: "hook1",
							Pre: []velerov1api.BackupResourceHook{
								{
									Exec: &velerov1api.ExecHook{
										Container: "1a",
										Command:   []string{"pre-1a"},
									},
								},
								{
									Exec: &velerov1api.ExecHook{
										Container: "1b",
										Command:   []string{"pre-1b"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range test1 {
		t.Run(test.name, func(t *testing.T) {
			podCommandExecutor := &velerotest.MockPodCommandExecutor{}
			defer podCommandExecutor.AssertExpectations(t)

			h := &DefaultItemHookHandler{
				PodCommandExecutor: podCommandExecutor,
			}

			groupResource := schema.ParseGroupResource(test.groupResource)
			hookTracker := test.hookTracker

			for _, pod := range test.pods {
				if pod.expectedPodHook != nil {
					podCommandExecutor.On("ExecutePodCommand", mock.Anything, pod.item.UnstructuredContent(), "ns", "name", "<from-annotation>", pod.expectedPodHook).Return(pod.expectedPodHookError)
				} else {
				hookLoop:
					for _, resourceHook := range pod.hooks {
						for _, hook := range resourceHook.Pre {
							hookError := pod.hookErrorsByContainer[hook.Exec.Container]
							podCommandExecutor.On("ExecutePodCommand", mock.Anything, pod.item.UnstructuredContent(), "ns", "name", resourceHook.Name, hook.Exec).Return(hookError)
							if hookError != nil && hook.Exec.OnError == velerov1api.HookErrorModeFail {
								break hookLoop
							}
						}
						for _, hook := range resourceHook.Post {
							hookError := pod.hookErrorsByContainer[hook.Exec.Container]
							podCommandExecutor.On("ExecutePodCommand", mock.Anything, pod.item.UnstructuredContent(), "ns", "name", resourceHook.Name, hook.Exec).Return(hookError)
							if hookError != nil && hook.Exec.OnError == velerov1api.HookErrorModeFail {
								break hookLoop
							}
						}
					}
				}
				h.HandleHooks(velerotest.NewLogger(), groupResource, pod.item, pod.hooks, test.phase, hookTracker)
			}
			actualAtemptted, actualFailed := hookTracker.Stat()
			assert.Equal(t, test.expectedHookAttempted, actualAtemptted)
			assert.Equal(t, test.expectedHookFailed, actualFailed)
		})
	}
}

func TestRestoreHookTrackerAdd(t *testing.T) {
	testCases := []struct {
		name                 string
		resourceRestoreHooks []ResourceRestoreHook
		pod                  *corev1api.Pod
		hookTracker          *MultiHookTracker
		expectedCnt          int
	}{
		{
			name:                 "neither spec hooks nor annotations hooks are set",
			resourceRestoreHooks: nil,
			pod:                  builder.ForPod("default", "my-pod").Result(),
			hookTracker:          NewMultiHookTracker(),
			expectedCnt:          0,
		},
		{
			name:                 "a hook specified in pod annotation",
			resourceRestoreHooks: nil,
			pod: builder.ForPod("default", "my-pod").
				ObjectMeta(builder.WithAnnotations(
					podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
					podRestoreHookContainerAnnotationKey, "container1",
					podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeContinue),
					podRestoreHookTimeoutAnnotationKey, "1s",
					podRestoreHookWaitTimeoutAnnotationKey, "1m",
					podRestoreHookWaitForReadyAnnotationKey, "true",
				)).
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			hookTracker: NewMultiHookTracker(),
			expectedCnt: 1,
		},
		{
			name: "two hooks specified in restore spec",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container1",
								Command:     []string{"/usr/bin/foo"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container2",
								Command:     []string{"/usr/bin/foo"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}, &corev1api.Container{
					Name: "container2",
				}).
				Result(),
			hookTracker: NewMultiHookTracker(),
			expectedCnt: 2,
		},
		{
			name: "both spec hooks and annotations hooks are set",
			resourceRestoreHooks: []ResourceRestoreHook{
				{
					Name:     "hook1",
					Selector: ResourceHookSelector{},
					RestoreHooks: []velerov1api.RestoreResourceHook{
						{
							Exec: &velerov1api.ExecRestoreHook{
								Container:   "container1",
								Command:     []string{"/usr/bin/foo2"},
								OnError:     velerov1api.HookErrorModeContinue,
								ExecTimeout: metav1.Duration{Duration: time.Second},
								WaitTimeout: metav1.Duration{Duration: time.Minute},
							},
						},
					},
				},
			},
			pod: builder.ForPod("default", "my-pod").
				ObjectMeta(builder.WithAnnotations(
					podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
					podRestoreHookContainerAnnotationKey, "container1",
					podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeContinue),
					podRestoreHookTimeoutAnnotationKey, "1s",
					podRestoreHookWaitTimeoutAnnotationKey, "1m",
					podRestoreHookWaitForReadyAnnotationKey, "true",
				)).
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
			hookTracker: NewMultiHookTracker(),
			expectedCnt: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = GroupRestoreExecHooks("restore1", tc.resourceRestoreHooks, tc.pod, velerotest.NewLogger(), tc.hookTracker)
			if _, ok := tc.hookTracker.trackers["restore1"]; !ok {
				return
			}
			tracker := tc.hookTracker.trackers["restore1"].tracker
			assert.Len(t, tracker, tc.expectedCnt)
		})
	}
}
