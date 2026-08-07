/*
Copyright 2017, 2020 the Velero contributors.

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

package podexec

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestNewPodCommandExecutor(t *testing.T) {
	restClientConfig := &rest.Config{Host: "foo"}
	poster := &mockPoster{}
	pce := NewPodCommandExecutor(restClientConfig, poster).(*defaultPodCommandExecutor)
	assert.Equal(t, restClientConfig, pce.restClientConfig)
	assert.Equal(t, poster, pce.restClient)
	assert.Equal(t, &defaultStreamExecutorFactory{}, pce.streamExecutorFactory)
}

func TestExecutePodCommandMissingInputs(t *testing.T) {
	tests := []struct {
		name         string
		item         map[string]any
		podNamespace string
		podName      string
		hookName     string
		hook         *v1.ExecHook
	}{
		{
			name: "missing item",
		},
		{
			name: "missing pod namespace",
			item: map[string]any{},
		},
		{
			name:         "missing pod name",
			item:         map[string]any{},
			podNamespace: "ns",
		},
		{
			name:         "missing hookName",
			item:         map[string]any{},
			podNamespace: "ns",
			podName:      "pod",
		},
		{
			name:         "missing hook",
			item:         map[string]any{},
			podNamespace: "ns",
			podName:      "pod",
			hookName:     "hook",
		},
		{
			name:         "container not found",
			item:         velerotest.UnstructuredOrDie(`{"kind":"Pod","spec":{"containers":[{"name":"foo"}]}}`).Object,
			podNamespace: "ns",
			podName:      "pod",
			hookName:     "hook",
			hook: &v1.ExecHook{
				Container: "missing",
			},
		},
		{
			name:         "command missing",
			item:         velerotest.UnstructuredOrDie(`{"kind":"Pod","spec":{"containers":[{"name":"foo"}]}}`).Object,
			podNamespace: "ns",
			podName:      "pod",
			hookName:     "hook",
			hook: &v1.ExecHook{
				Container: "foo",
			},
		},
		{
			name:         "hook's container is not overwritten by pod",
			item:         velerotest.UnstructuredOrDie(`{"kind":"Pod","spec":{"containers":[{"name":"foo"}]}}`).Object,
			podNamespace: "ns",
			podName:      "pod",
			hookName:     "hook",
			hook: &v1.ExecHook{
				Container: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := new(corev1api.Pod)
			hookPodContainerNotSame := false
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(test.item, pod); err != nil {
				assert.Error(t, err)
			}
			if (len(pod.Spec.Containers) > 0) && (pod.Spec.Containers[0].Name != test.hook.Container) {
				hookPodContainerNotSame = true
			}

			e := &defaultPodCommandExecutor{}
			err := e.ExecutePodCommand(velerotest.NewLogger(), test.item, test.podNamespace, test.podName, test.hookName, test.hook)

			if hookPodContainerNotSame && test.hook.Container == pod.Spec.Containers[0].Name {
				require.Error(t, fmt.Errorf("hook exec container is overwritten"))
			}
			assert.Error(t, err)
		})
	}
}

func TestExecutePodCommand(t *testing.T) {
	tests := []struct {
		name                  string
		containerName         string
		expectedContainerName string
		command               []string
		errorMode             v1.HookErrorMode
		expectedErrorMode     v1.HookErrorMode
		timeout               time.Duration
		expectedTimeout       time.Duration
		hookError             error
		expectedError         string
	}{
		{
			name:                  "validate defaults",
			command:               []string{"some", "command"},
			expectedContainerName: "foo",
			expectedErrorMode:     v1.HookErrorModeFail,
			expectedTimeout:       30 * time.Second,
		},
		{
			name:                  "use specified values",
			command:               []string{"some", "command"},
			containerName:         "bar",
			expectedContainerName: "bar",
			errorMode:             v1.HookErrorModeContinue,
			expectedErrorMode:     v1.HookErrorModeContinue,
			timeout:               10 * time.Second,
			expectedTimeout:       10 * time.Second,
		},
		{
			name:                  "hook error",
			command:               []string{"some", "command"},
			expectedContainerName: "foo",
			expectedErrorMode:     v1.HookErrorModeFail,
			expectedTimeout:       30 * time.Second,
			hookError:             errors.New("hook error"),
			expectedError:         "hook error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hook := v1.ExecHook{
				Container: test.containerName,
				Command:   test.command,
				OnError:   test.errorMode,
				Timeout:   metav1.Duration{Duration: test.timeout},
			}

			pod, err := velerotest.GetAsMap(`
{
	"metadata": {
		"namespace": "namespace",
		"name": "name"
	},
	"spec": {
		"containers": [
			{"name": "foo"},
			{"name": "bar"}
		]
	}
}`)

			require.NoError(t, err)

			clientConfig := &rest.Config{}
			poster := &mockPoster{}
			defer poster.AssertExpectations(t)
			podCommandExecutor := NewPodCommandExecutor(clientConfig, poster).(*defaultPodCommandExecutor)

			streamExecutorFactory := &mockStreamExecutorFactory{}
			defer streamExecutorFactory.AssertExpectations(t)
			podCommandExecutor.streamExecutorFactory = streamExecutorFactory

			baseURL, _ := url.Parse("https://some.server")
			contentConfig := rest.ClientContentConfig{
				GroupVersion: schema.GroupVersion{Group: "", Version: "v1"},
			}
			poster.On("Post").Return(rest.NewRequestWithClient(baseURL, "/api/v1", contentConfig, nil))

			streamExecutor := &mockStreamExecutor{}
			defer streamExecutor.AssertExpectations(t)

			expectedCommand := strings.Join(test.command, "&command=")
			expectedURL, _ := url.Parse(
				fmt.Sprintf("https://some.server/api/v1/namespaces/namespace/pods/name/exec?command=%s&container=%s&stderr=true&stdout=true", expectedCommand, test.expectedContainerName),
			)
			streamExecutorFactory.On("NewSPDYExecutor", clientConfig, "POST", expectedURL).Return(streamExecutor, nil)

			var stdout, stderr bytes.Buffer
			expectedStreamOptions := remotecommand.StreamOptions{
				Stdout: &stdout,
				Stderr: &stderr,
			}
			streamExecutor.On("StreamWithContext", mock.Anything, expectedStreamOptions).Return(test.hookError)

			err = podCommandExecutor.ExecutePodCommand(velerotest.NewLogger(), pod, "namespace", "name", "hookName", &hook)
			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestEnsureContainerExists(t *testing.T) {
	pod := &corev1api.Pod{
		Spec: corev1api.PodSpec{
			Containers: []corev1api.Container{
				{
					Name: "foo",
				},
			},
			InitContainers: []corev1api.Container{
				{
					Name: "baz",
				},
				{
					Name:          "qux",
					RestartPolicy: ptr.To(corev1api.ContainerRestartPolicyAlways),
				},
			},
		},
	}

	err := ensureContainerExists(pod, "bar")
	require.EqualError(t, err, `no such container: "bar"`)

	err = ensureContainerExists(pod, "foo")
	require.NoError(t, err)

	err = ensureContainerExists(pod, "baz")
	require.EqualError(t, err, `no such container: "baz"`)

	err = ensureContainerExists(pod, "qux")
	require.NoError(t, err)
}

func TestPodCompleted(t *testing.T) {
	pod := &corev1api.Pod{
		Spec: corev1api.PodSpec{
			Containers: []corev1api.Container{
				{
					Name: "foo",
				},
			},
		},
		Status: corev1api.PodStatus{
			Phase: corev1api.PodSucceeded,
		},
	}

	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	require.NoError(t, err)

	clientConfig := &rest.Config{}
	poster := &mockPoster{}
	defer poster.AssertExpectations(t)
	podCommandExecutor := NewPodCommandExecutor(clientConfig, poster).(*defaultPodCommandExecutor)

	hook := v1.ExecHook{
		Container: "foo",
		Command:   []string{"some", "command"},
	}

	err = podCommandExecutor.ExecutePodCommand(velerotest.NewLogger(), obj, "namespace", "name", "hookName", &hook)
	require.NoError(t, err)
}

type mockStreamExecutorFactory struct {
	mock.Mock
}

func (f *mockStreamExecutorFactory) NewSPDYExecutor(config *rest.Config, method string, url *url.URL) (remotecommand.Executor, error) {
	args := f.Called(config, method, url)
	return args.Get(0).(remotecommand.Executor), args.Error(1)
}

type mockStreamExecutor struct {
	mock.Mock
	remotecommand.Executor
}

func (e *mockStreamExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	args := e.Called(ctx, options)
	return args.Error(0)
}

type mockPoster struct {
	mock.Mock
}

func (p *mockPoster) Post() *rest.Request {
	args := p.Called()
	return args.Get(0).(*rest.Request)
}
