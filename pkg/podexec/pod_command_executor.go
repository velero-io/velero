/*
Copyright 2017 the Velero contributors.

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
	"net/url"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const defaultTimeout = 30 * time.Second

// maxHookTimeout bounds a user-supplied hook timeout, which can come from a pod
// annotation, so a single hook cannot hold up a backup for an unbounded time.
const maxHookTimeout = 4 * time.Hour

// PodCommandExecutor is capable of executing a command in a container in a pod.
type PodCommandExecutor interface {
	// ExecutePodCommand executes a command in a container in a pod. If the command takes longer than
	// the specified timeout, an error is returned.
	ExecutePodCommand(log logrus.FieldLogger, item map[string]any, namespace, name, hookName string, hook *api.ExecHook) error
}

type poster interface {
	Post() *rest.Request
}

type defaultPodCommandExecutor struct {
	restClientConfig *rest.Config
	restClient       poster

	streamExecutorFactory streamExecutorFactory
}

// NewPodCommandExecutor creates a new PodCommandExecutor.
func NewPodCommandExecutor(restClientConfig *rest.Config, restClient poster) PodCommandExecutor {
	return &defaultPodCommandExecutor{
		restClientConfig: restClientConfig,
		restClient:       restClient,

		streamExecutorFactory: &defaultStreamExecutorFactory{},
	}
}

// ExecutePodCommand uses the pod exec API to execute a command in a container in a pod. If the
// command takes longer than the specified timeout, an error is returned (NOTE: it is not currently
// possible to ensure the command is terminated when the timeout occurs, so it may continue to run
// in the background).
func (e *defaultPodCommandExecutor) ExecutePodCommand(log logrus.FieldLogger, item map[string]any, namespace, name, hookName string, hook *api.ExecHook) error {
	if item == nil {
		return errors.New("item is required")
	}
	if namespace == "" {
		return errors.New("namespace is required")
	}
	if name == "" {
		return errors.New("name is required")
	}
	if hookName == "" {
		return errors.New("hookName is required")
	}
	if hook == nil {
		return errors.New("hook is required")
	}

	localHook := *hook

	pod := new(corev1api.Pod)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item, pod); err != nil {
		return errors.WithStack(err)
	}

	if localHook.Container == "" {
		if err := setDefaultHookContainer(pod, &localHook); err != nil {
			return err
		}
	} else if err := ensureContainerExists(pod, localHook.Container); err != nil {
		return err
	}

	if len(localHook.Command) == 0 {
		return errors.New("command is required")
	}

	switch localHook.OnError {
	case api.HookErrorModeFail, api.HookErrorModeContinue:
		// use the specified value
	default:
		// default to fail
		localHook.OnError = api.HookErrorModeFail
	}

	// A non-positive timeout is not a valid bound. Timeouts sourced from pod annotations are
	// parsed with time.ParseDuration, which accepts negative values, and a negative duration
	// would otherwise leave the hook without any timeout at all.
	if localHook.Timeout.Duration <= 0 {
		localHook.Timeout.Duration = defaultTimeout
	}
	if localHook.Timeout.Duration > maxHookTimeout {
		localHook.Timeout.Duration = maxHookTimeout
	}

	hookLog := log.WithFields(
		logrus.Fields{
			"hookName":      hookName,
			"hookContainer": localHook.Container,
			"hookCommand":   localHook.Command,
			"hookOnError":   localHook.OnError,
			"hookTimeout":   localHook.Timeout,
		},
	)

	if pod.Status.Phase == corev1api.PodSucceeded || pod.Status.Phase == corev1api.PodFailed {
		hookLog.Infof("Pod entered phase %s before some post-backup exec hooks ran", pod.Status.Phase)
		return nil
	}

	hookLog.Info("running exec hook")

	req := e.restClient.Post().
		Resource("pods").
		Namespace(namespace).
		Name(name).
		SubResource("exec")

	req.VersionedParams(&corev1api.PodExecOptions{
		Container: localHook.Container,
		Command:   localHook.Command,
		Stdout:    true,
		Stderr:    true,
	}, kscheme.ParameterCodec)

	executor, err := e.streamExecutorFactory.NewSPDYExecutor(e.restClientConfig, "POST", req.URL())
	if err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer

	streamOptions := remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}

	// The timeout drives the context so the exec stream is actually canceled, rather than
	// being left running on the API server after this function has returned.
	ctx, cancel := context.WithTimeout(context.Background(), localHook.Timeout.Duration)
	defer cancel()

	// Buffered so the goroutine below can always send its result and exit, even when this
	// function has already returned on the timeout path.
	errCh := make(chan error, 1)

	go func() {
		streamErr := executor.StreamWithContext(ctx, streamOptions)
		// Inspect the local context as soon as the stream returns. Otherwise a stream error
		// completed before the deadline could be misclassified if this goroutine sends its
		// result before the caller is scheduled to receive it.
		errCh <- normalizeExecHookError(streamErr, ctx.Err(), localHook.Timeout.Duration)
	}()

	select {
	case err = <-errCh:
	case <-ctx.Done():
		return errors.Errorf("timed out after %v", localHook.Timeout.Duration)
	}

	hookLog.Infof("stdout: %s", stdout.String())
	hookLog.Infof("stderr: %s", stderr.String())

	return err
}

func normalizeExecHookError(streamErr, contextErr error, timeout time.Duration) error {
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return errors.Errorf("timed out after %v", timeout)
	}

	return streamErr
}

func ensureContainerExists(pod *corev1api.Pod, container string) error {
	existsAsMainContainer := slices.ContainsFunc(pod.Spec.Containers, func(c corev1api.Container) bool {
		return c.Name == container
	})

	if existsAsMainContainer {
		return nil
	}

	existsAsSidecar := slices.ContainsFunc(pod.Spec.InitContainers, func(c corev1api.Container) bool {
		return c.RestartPolicy != nil &&
			*c.RestartPolicy == corev1api.ContainerRestartPolicyAlways &&
			c.Name == container
	})

	if existsAsSidecar {
		return nil
	}

	return errors.Errorf("no such container: %q", container)
}

func setDefaultHookContainer(pod *corev1api.Pod, hook *api.ExecHook) error {
	if len(pod.Spec.Containers) < 1 {
		return errors.New("need at least 1 container")
	}

	hook.Container = pod.Spec.Containers[0].Name

	return nil
}

type streamExecutorFactory interface {
	NewSPDYExecutor(config *rest.Config, method string, url *url.URL) (remotecommand.Executor, error)
}

type defaultStreamExecutorFactory struct{}

func (f *defaultStreamExecutorFactory) NewSPDYExecutor(config *rest.Config, method string, url *url.URL) (remotecommand.Executor, error) {
	return remotecommand.NewSPDYExecutor(config, method, url)
}
