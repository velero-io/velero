/*
Copyright 2026 the Velero contributors.

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
	"context"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

const timeoutTestPodJSON = `{
	"metadata": {"namespace": "ns", "name": "pod-1"},
	"spec": {"containers": [{"name": "container-1"}]}
}`

// contextAwareExecutor returns once its context is canceled, like the SPDY executor does.
type contextAwareExecutor struct {
	canceled     chan struct{}
	canceledOnce bool
}

func (e *contextAwareExecutor) Stream(options remotecommand.StreamOptions) error { return nil }

func (e *contextAwareExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	<-ctx.Done()
	if !e.canceledOnce {
		e.canceledOnce = true
		close(e.canceled)
	}
	return ctx.Err()
}

// contextIgnoringExecutor lets the outer timeout path return before the stream does.
// Once released, the stream goroutine can only exit if its result channel is buffered.
type contextIgnoringExecutor struct {
	release  <-chan struct{}
	returned *sync.WaitGroup
}

func (e *contextIgnoringExecutor) Stream(options remotecommand.StreamOptions) error { return nil }

func (e *contextIgnoringExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	defer e.returned.Done()
	<-e.release
	return nil
}

func newTimeoutTestExecutor(t *testing.T, exec remotecommand.Executor) (*defaultPodCommandExecutor, map[string]any) {
	t.Helper()

	clientConfig := &rest.Config{}
	poster := &mockPoster{}
	podCommandExecutor := NewPodCommandExecutor(clientConfig, poster).(*defaultPodCommandExecutor)

	factory := &mockStreamExecutorFactory{}
	podCommandExecutor.streamExecutorFactory = factory

	baseURL, _ := url.Parse("https://some.server")
	contentConfig := rest.ClientContentConfig{GroupVersion: schema.GroupVersion{Group: "", Version: "v1"}}
	poster.On("Post").Return(rest.NewRequestWithClient(baseURL, "/api/v1", contentConfig, nil))
	factory.On("NewSPDYExecutor", clientConfig, "POST", mock.Anything).Return(exec, nil)

	pod, err := velerotest.GetAsMap(timeoutTestPodJSON)
	if err != nil {
		t.Fatal(err)
	}

	return podCommandExecutor, pod
}

func timeoutTestHook(timeout time.Duration) *v1.ExecHook {
	return &v1.ExecHook{
		Container: "container-1",
		Command:   []string{"sh", "-c", "sleep 60"},
		Timeout:   metav1.Duration{Duration: timeout},
	}
}

// A hook that times out must have its exec stream canceled, otherwise the command keeps
// running on the API server after ExecutePodCommand has returned.
func TestExecutePodCommandCancelsStreamOnTimeout(t *testing.T) {
	exec := &contextAwareExecutor{canceled: make(chan struct{})}
	podCommandExecutor, pod := newTimeoutTestExecutor(t, exec)

	err := podCommandExecutor.ExecutePodCommand(velerotest.NewLogger(), pod, "ns", "pod-1", "hookName", timeoutTestHook(100*time.Millisecond))
	if err == nil {
		t.Fatal("expected a timeout error")
	}

	select {
	case <-exec.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("stream was not canceled after the hook timed out")
	}
}

// When the stream returns because the context expired, both select cases are ready and one
// is picked at random, so the reported error must not depend on which one wins.
func TestExecutePodCommandTimeoutErrorIsDeterministic(t *testing.T) {
	const (
		rounds        = 50
		expectedError = "timed out after 1ms"
	)

	messages := map[string]int{}
	for range rounds {
		exec := &contextAwareExecutor{canceled: make(chan struct{})}
		podCommandExecutor, pod := newTimeoutTestExecutor(t, exec)

		err := podCommandExecutor.ExecutePodCommand(velerotest.NewLogger(), pod, "ns", "pod-1", "hookName", timeoutTestHook(time.Millisecond))
		if err == nil {
			t.Fatal("expected a timeout error")
		}
		if err.Error() != expectedError {
			t.Fatalf("expected %q, got %q", expectedError, err)
		}
		messages[err.Error()]++
	}

	if len(messages) != 1 {
		t.Fatalf("expected one error message, got %d: %v", len(messages), messages)
	}
}

func TestExecutePodCommandDoesNotLeakOnTimeout(t *testing.T) {
	const rounds = 10

	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	before := runtime.NumGoroutine()

	release := make(chan struct{})
	returned := &sync.WaitGroup{}
	for range rounds {
		returned.Add(1)
		exec := &contextIgnoringExecutor{release: release, returned: returned}
		podCommandExecutor, pod := newTimeoutTestExecutor(t, exec)

		if err := podCommandExecutor.ExecutePodCommand(velerotest.NewLogger(), pod, "ns", "pod-1", "hookName", timeoutTestHook(50*time.Millisecond)); err == nil {
			t.Fatal("expected a timeout error")
		}
	}

	// Every ExecutePodCommand call has already taken the timeout path. Releasing the
	// streams now forces their goroutines to send into an errCh with no receiver.
	close(release)
	returned.Wait()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	if leaked := runtime.NumGoroutine() - before; leaked >= rounds {
		t.Fatalf("%d goroutines leaked over %d timed out hooks", leaked, rounds)
	}
}
