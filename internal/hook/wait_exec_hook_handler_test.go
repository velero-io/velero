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
	"context"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	fcache "k8s.io/client-go/tools/cache/testing"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

type fakeListWatchFactory struct {
	lw cache.ListerWatcher
}

func (f *fakeListWatchFactory) NewListWatch(ns string, selector fields.Selector) cache.ListerWatcher {
	return f.lw
}

var _ ListWatchFactory = &fakeListWatchFactory{}

func TestWaitExecHandleHooks(t *testing.T) {
	type change struct {
		// delta to wait since last change applied or pod added
		wait    time.Duration
		updated *corev1api.Pod
		// waitForSignal, if set, blocks the goroutine after applying this change
		// until the channel is closed. Use this to ensure the handler processes
		// an intermediate pod state before the next change is applied.
		waitForSignal chan struct{}
	}
	type expectedExecution struct {
		hook  *velerov1api.ExecHook
		name  string
		error error
		pod   *corev1api.Pod
		// onCalled, if set, is invoked by the mock when ExecutePodCommand is called.
		// Use this together with change.waitForSignal to synchronize state transitions.
		onCalled func()
	}
	// hookFired is used by the test case that has two containers with hooks in
	// different containers. It ensures the second pod state change is only sent
	// after the first hook has fired, preventing the informer from coalescing
	// both updates and skipping the intermediate state.
	hookFired := make(chan struct{})
	tests := []struct {
		name string
		// Used as argument to HandleHooks and first state added to ListerWatcher
		initialPod         *corev1api.Pod
		groupResource      string
		byContainer        map[string][]PodExecRestoreHook
		expectedExecutions []expectedExecution
		expectedErrors     []error
		// changes represents the states of the pod over time. It can be used to test a container
		// becoming ready at some point after it is first observed by the controller.
		changes                   []change
		sharedHooksContextTimeout time.Duration
	}{
		{
			name: "should return no error when hook from annotation executes successfully",
			initialPod: builder.ForPod("default", "my-pod").
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
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			groupResource: "pods",
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "<from-annotation>",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
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
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			expectedErrors: nil,
		},
		{
			name: "should return an error when hook from annotation fails with on error mode fail",
			initialPod: builder.ForPod("default", "my-pod").
				ObjectMeta(builder.WithAnnotations(
					podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
					podRestoreHookContainerAnnotationKey, "container1",
					podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeFail),
					podRestoreHookTimeoutAnnotationKey, "1s",
					podRestoreHookWaitTimeoutAnnotationKey, "1m",
				)).
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			groupResource: "pods",
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeFail,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "<from-annotation>",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
						OnError:   velerov1api.HookErrorModeFail,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: errors.New("pod hook error"),
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
						ObjectMeta(builder.WithAnnotations(
							podRestoreHookCommandAnnotationKey, "/usr/bin/foo",
							podRestoreHookContainerAnnotationKey, "container1",
							podRestoreHookOnErrorAnnotationKey, string(velerov1api.HookErrorModeFail),
							podRestoreHookTimeoutAnnotationKey, "1s",
							podRestoreHookWaitTimeoutAnnotationKey, "1m",
						)).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			expectedErrors: []error{errors.New("hook <from-annotation> in container container1 failed to execute, err: pod hook error")},
		},
		{
			name: "should return error when hook from annotation fails with on error mode continue",
			initialPod: builder.ForPod("default", "my-pod").
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
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			groupResource: "pods",
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "<from-annotation>",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: errors.New("pod hook error"),
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
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
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			expectedErrors: []error{errors.New("hook <from-annotation> in container container1 failed to execute, err: pod hook error")},
		},
		{
			name: "should return no error when hook from annotation executes after 10ms wait for container to start",
			initialPod: builder.ForPod("default", "my-pod").
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
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			groupResource: "pods",
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "<from-annotation>",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("2")).
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
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			expectedErrors: nil,
			changes: []change{
				{
					wait: 10 * time.Millisecond,
					updated: builder.ForPod("default", "my-pod").
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
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
		},
		{
			name:          "should return no error when hook from spec executes successfully",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			expectedErrors: nil,
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container: "container1",
							Command:   []string{"/usr/bin/foo"},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "my-hook-1",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
					},
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
		},
		{
			name:          "should return error when spec hook with wait timeout expires with OnError mode Continue",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			expectedErrors: []error{errors.New("hook my-hook-1 in container container1 in pod default/my-pod not executed: context deadline exceeded")},
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{},
		},
		{
			name:          "should return an error when spec hook with wait timeout expires with OnError mode Fail",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			expectedErrors: []error{errors.New("hook my-hook-1 in container container1 in pod default/my-pod not executed: context deadline exceeded")},
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeFail,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{},
		},
		{
			name:          "should return an error when shared hooks context is canceled before spec hook with OnError mode Fail executes",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			expectedErrors: []error{errors.New("hook my-hook-1 in container container1 in pod default/my-pod not executed: context deadline exceeded")},
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container: "container1",
							Command:   []string{"/usr/bin/foo"},
							OnError:   velerov1api.HookErrorModeFail,
						},
					},
				},
			},
			expectedExecutions:        []expectedExecution{},
			sharedHooksContextTimeout: time.Millisecond,
		},
		{
			name:           "should return error when shared hooks context is canceled before spec hook with OnError mode Continue executes",
			expectedErrors: []error{errors.New("hook my-hook-1 in container container1 in pod default/my-pod not executed: context deadline exceeded")},
			groupResource:  "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container: "container1",
							Command:   []string{"/usr/bin/foo"},
							OnError:   velerov1api.HookErrorModeContinue,
						},
					},
				},
			},
			expectedExecutions:        []expectedExecution{},
			sharedHooksContextTimeout: time.Millisecond,
		},
		{
			name:          "should return no error with 2 spec hooks in 2 different containers, 1st container starts running after 10ms, 2nd container after 20ms, both succeed",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Containers(&corev1api.Container{
					Name: "container2",
				}).
				// initially both are waiting
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container2",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			expectedErrors: nil,
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container: "container1",
							Command:   []string{"/usr/bin/foo"},
						},
					},
				},
				"container2": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container: "container2",
							Command:   []string{"/usr/bin/bar"},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "my-hook-1",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("2")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						Containers(&corev1api.Container{
							Name: "container2",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						// container 2 is still waiting when the first hook executes in container1
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container2",
							State: corev1api.ContainerState{
								Waiting: &corev1api.ContainerStateWaiting{},
							},
						}).
						Result(),
					// Signal after this hook fires so the goroutine can apply the next change.
					onCalled: func() { close(hookFired) },
				},
				{
					name: "my-hook-1",
					hook: &velerov1api.ExecHook{
						Container: "container2",
						Command:   []string{"/usr/bin/bar"},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("3")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						Containers(&corev1api.Container{
							Name: "container2",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container2",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			changes: []change{
				// 1st modification: container1 starts running, resourceVersion 2, container2 still waiting
				{
					wait: 10 * time.Millisecond,
					updated: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("2")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						Containers(&corev1api.Container{
							Name: "container2",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container2",
							State: corev1api.ContainerState{
								Waiting: &corev1api.ContainerStateWaiting{},
							},
						}).
						Result(),
					// Block until the hook for container1 has fired before sending the
					// next change. Without this, the informer may coalesce both updates
					// and deliver only resourceVersion:3, skipping the intermediate state.
					waitForSignal: hookFired,
				},
				// 2nd modification: container2 starts running, resourceVersion 3
				{
					wait: 10 * time.Millisecond,
					updated: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("3")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						Containers(&corev1api.Container{
							Name: "container2",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container2",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
		},
		{
			name: "Multiple hooks with non-sequential indices (bug #9359)",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			groupResource: "pods",
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "first-hook",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
						hookIndex: 0,
					},
					{
						HookName:   "second-hook",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/bar"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
						hookIndex: 2,
					},
					{
						HookName:   "third-hook",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/third"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
						hookIndex: 4,
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "first-hook",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
				{
					name: "second-hook",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/bar"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
				{
					name: "third-hook",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/third"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
						Containers(&corev1api.Container{
							Name: "container1",
						}).
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			expectedErrors: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := fcache.NewFakeControllerSource()
			go func() {
				// This is the state of the pod that will be seen by the AddFunc handler.
				source.Add(test.initialPod)
				// Changes holds the versions of the pod over time. The informer may
				// coalesce rapid updates, so use waitForSignal when a test requires the
				// handler to observe a specific intermediate state before the next change.
				for _, change := range test.changes {
					time.Sleep(change.wait)
					source.Modify(change.updated)
					if change.waitForSignal != nil {
						<-change.waitForSignal
					}
				}
			}()

			podCommandExecutor := &velerotest.MockPodCommandExecutor{}
			defer podCommandExecutor.AssertExpectations(t)

			h := &DefaultWaitExecHookHandler{
				PodCommandExecutor: podCommandExecutor,
				ListWatchFactory:   &fakeListWatchFactory{source},
			}

			for _, e := range test.expectedExecutions {
				obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(e.pod)
				require.NoError(t, err)
				call := podCommandExecutor.On("ExecutePodCommand", mock.Anything, obj, e.pod.Namespace, e.pod.Name, e.name, e.hook).Return(e.error)
				if e.onCalled != nil {
					onCalled := e.onCalled
					call.Run(func(mock.Arguments) { onCalled() })
				}
			}

			ctx := t.Context()
			if test.sharedHooksContextTimeout > 0 {
				var ctxCancel context.CancelFunc
				ctx, ctxCancel = context.WithTimeout(ctx, test.sharedHooksContextTimeout)
				defer ctxCancel()
			}

			hookTracker := NewMultiHookTracker()
			errs := h.HandleHooks(ctx, velerotest.NewLogger(), test.initialPod, test.byContainer, hookTracker, "restore1")

			// for i, ee := range test.expectedErrors {
			require.Len(t, errs, len(test.expectedErrors))
			for i, ee := range test.expectedErrors {
				assert.EqualError(t, errs[i], ee.Error())
			}
		})
	}
}

func TestPodHasContainer(t *testing.T) {
	tests := []struct {
		name      string
		pod       *corev1api.Pod
		container string
		expect    bool
	}{
		{
			name:      "has container",
			expect:    true,
			container: "container1",
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Result(),
		},
		{
			name:      "does not have container",
			expect:    false,
			container: "container1",
			pod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container2",
				}).
				Result(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := podHasContainer(test.pod, test.container)
			assert.Equal(t, actual, test.expect)
		})
	}
}

func TestIsContainerUp(t *testing.T) {
	tests := []struct {
		name      string
		pod       *corev1api.Pod
		container string
		expect    bool
		hooks     []PodExecRestoreHook
	}{
		{
			name:      "should return true when running",
			container: "container1",
			expect:    true,
			pod: builder.ForPod("default", "my-pod").
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			hooks: []PodExecRestoreHook{},
		},
		{
			name:      "should return false when running but not ready",
			container: "container1",
			expect:    false,
			pod: builder.ForPod("default", "my-pod").
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
					Ready: false,
				}).
				Result(),
			hooks: []PodExecRestoreHook{
				{
					Hook: velerov1api.ExecRestoreHook{
						WaitForReady: boolptr.True(),
					},
				},
			},
		},
		{
			name:      "should return true when running and ready",
			container: "container1",
			expect:    true,
			pod: builder.ForPod("default", "my-pod").
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
					Ready: true,
				}).
				Result(),
			hooks: []PodExecRestoreHook{
				{
					Hook: velerov1api.ExecRestoreHook{
						WaitForReady: boolptr.True(),
					},
				},
			},
		},
		{
			name:      "should return false when no state is set",
			container: "container1",
			expect:    false,
			pod: builder.ForPod("default", "my-pod").
				ContainerStatuses(&corev1api.ContainerStatus{
					Name:  "container1",
					State: corev1api.ContainerState{},
				}).
				Result(),
			hooks: []PodExecRestoreHook{},
		},
		{
			name:      "should return false when waiting",
			container: "container1",
			expect:    false,
			pod: builder.ForPod("default", "my-pod").
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			hooks: []PodExecRestoreHook{},
		},
		{
			name:      "should return true when running and first container is terminated",
			container: "container1",
			expect:    true,
			pod: builder.ForPod("default", "my-pod").
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container0",
					State: corev1api.ContainerState{
						Terminated: &corev1api.ContainerStateTerminated{},
					},
				},
					&corev1api.ContainerStatus{
						Name: "container1",
						State: corev1api.ContainerState{
							Running: &corev1api.ContainerStateRunning{},
						},
					}).
				Result(),
			hooks: []PodExecRestoreHook{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := isContainerUp(test.pod, test.container, test.hooks)
			assert.Equal(t, actual, test.expect)
		})
	}
}

func TestMaxHookWait(t *testing.T) {
	tests := []struct {
		name        string
		byContainer map[string][]PodExecRestoreHook
		expect      time.Duration
	}{
		{
			name:        "should return 0 for nil map",
			byContainer: nil,
			expect:      0,
		},
		{
			name:   "should return 0 if all hooks are 0 or negative",
			expect: 0,
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						Hook: velerov1api.ExecRestoreHook{
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: 0},
						},
					},
					{
						Hook: velerov1api.ExecRestoreHook{
							WaitTimeout: metav1.Duration{Duration: -1},
						},
					},
				},
			},
		},
		{
			name:   "should return biggest wait timeout from multiple hooks in multiple containers",
			expect: time.Hour,
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						Hook: velerov1api.ExecRestoreHook{
							WaitTimeout: metav1.Duration{Duration: time.Second},
						},
					},
					{
						Hook: velerov1api.ExecRestoreHook{
							WaitTimeout: metav1.Duration{Duration: time.Second},
						},
					},
				},
				"container2": {
					{
						Hook: velerov1api.ExecRestoreHook{
							WaitTimeout: metav1.Duration{Duration: time.Hour},
						},
					},
					{
						Hook: velerov1api.ExecRestoreHook{
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
					},
				},
			},
		},
		{
			name:   "should return 0 if any hook does not have a wait timeout",
			expect: 0,
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						Hook: velerov1api.ExecRestoreHook{
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Second},
						},
					},
					{
						Hook: velerov1api.ExecRestoreHook{
							WaitTimeout: metav1.Duration{Duration: 0},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := maxHookWait(test.byContainer)
			assert.Equal(t, actual, test.expect)
		})
	}
}

func TestRestoreHookTrackerUpdate(t *testing.T) {
	type expectedExecution struct {
		hook  *velerov1api.ExecHook
		name  string
		error error
		pod   *corev1api.Pod
	}

	hookTracker1 := NewMultiHookTracker()
	hookTracker1.Add("restore1", "default", "my-pod", "container1", HookSourceAnnotation, "<from-annotation>", HookPhase(""), 0)

	hookTracker2 := NewMultiHookTracker()
	hookTracker2.Add("restore1", "default", "my-pod", "container1", HookSourceSpec, "my-hook-1", HookPhase(""), 0)

	hookTracker3 := NewMultiHookTracker()
	hookTracker3.Add("restore1", "default", "my-pod", "container1", HookSourceSpec, "my-hook-1", HookPhase(""), 0)
	hookTracker3.Add("restore1", "default", "my-pod", "container2", HookSourceSpec, "my-hook-2", HookPhase(""), 0)

	hookTracker4 := NewMultiHookTracker()
	hookTracker4.Add("restore1", "default", "my-pod", "container1", HookSourceSpec, "my-hook-1", HookPhase(""), 0)

	tests1 := []struct {
		name               string
		initialPod         *corev1api.Pod
		groupResource      string
		byContainer        map[string][]PodExecRestoreHook
		expectedExecutions []expectedExecution
		hookTracker        *MultiHookTracker
		expectedFailed     int
	}{
		{
			name: "a hook executes successfully",
			initialPod: builder.ForPod("default", "my-pod").
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
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Running: &corev1api.ContainerStateRunning{},
					},
				}).
				Result(),
			groupResource: "pods",
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "<from-annotation>",
						HookSource: HookSourceAnnotation,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							ExecTimeout: metav1.Duration{Duration: time.Second},
							WaitTimeout: metav1.Duration{Duration: time.Minute},
						},
					},
				},
			},
			expectedExecutions: []expectedExecution{
				{
					name: "<from-annotation>",
					hook: &velerov1api.ExecHook{
						Container: "container1",
						Command:   []string{"/usr/bin/foo"},
						OnError:   velerov1api.HookErrorModeContinue,
						Timeout:   metav1.Duration{Duration: time.Second},
					},
					error: nil,
					pod: builder.ForPod("default", "my-pod").
						ObjectMeta(builder.WithResourceVersion("1")).
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
						ContainerStatuses(&corev1api.ContainerStatus{
							Name: "container1",
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{},
							},
						}).
						Result(),
				},
			},
			hookTracker:    hookTracker1,
			expectedFailed: 0,
		},
		{
			name:          "a hook with OnError mode Fail failed to execute",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeFail,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
			},
			hookTracker:    hookTracker2,
			expectedFailed: 1,
		},
		{
			name:          "a hook with OnError mode Continue failed to execute",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
			},
			hookTracker:    hookTracker4,
			expectedFailed: 1,
		},
		{
			name:          "two hooks with OnError mode Continue failed to execute",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				Containers(&corev1api.Container{
					Name: "container2",
				}).
				// initially both are waiting
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container2",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
				"container2": {
					{
						HookName:   "my-hook-2",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container2",
							Command:     []string{"/usr/bin/bar"},
							OnError:     velerov1api.HookErrorModeContinue,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
			},
			hookTracker:    hookTracker3,
			expectedFailed: 2,
		},
		{
			name:          "a hook was recorded before added to tracker",
			groupResource: "pods",
			initialPod: builder.ForPod("default", "my-pod").
				Containers(&corev1api.Container{
					Name: "container1",
				}).
				ContainerStatuses(&corev1api.ContainerStatus{
					Name: "container1",
					State: corev1api.ContainerState{
						Waiting: &corev1api.ContainerStateWaiting{},
					},
				}).
				Result(),
			byContainer: map[string][]PodExecRestoreHook{
				"container1": {
					{
						HookName:   "my-hook-1",
						HookSource: HookSourceSpec,
						Hook: velerov1api.ExecRestoreHook{
							Container:   "container1",
							Command:     []string{"/usr/bin/foo"},
							OnError:     velerov1api.HookErrorModeContinue,
							WaitTimeout: metav1.Duration{Duration: time.Millisecond},
						},
					},
				},
			},
			hookTracker:    NewMultiHookTracker(),
			expectedFailed: 0,
		},
	}

	for _, test := range tests1 {
		t.Run(test.name, func(t *testing.T) {
			source := fcache.NewFakeControllerSource()
			go func() {
				// This is the state of the pod that will be seen by the AddFunc handler.
				source.Add(test.initialPod)
			}()

			podCommandExecutor := &velerotest.MockPodCommandExecutor{}
			defer podCommandExecutor.AssertExpectations(t)

			h := &DefaultWaitExecHookHandler{
				PodCommandExecutor: podCommandExecutor,
				ListWatchFactory:   &fakeListWatchFactory{source},
			}

			for _, e := range test.expectedExecutions {
				obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(e.pod)
				require.NoError(t, err)
				podCommandExecutor.On("ExecutePodCommand", mock.Anything, obj, e.pod.Namespace, e.pod.Name, e.name, e.hook).Return(e.error)
			}

			ctx := t.Context()
			_ = h.HandleHooks(ctx, velerotest.NewLogger(), test.initialPod, test.byContainer, test.hookTracker, "restore1")
			_, actualFailed := test.hookTracker.Stat("restore1")
			assert.Equal(t, test.expectedFailed, actualFailed)
		})
	}
}
