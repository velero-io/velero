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
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/podexec"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

type WaitExecHookHandler interface {
	HandleHooks(
		ctx context.Context,
		log logrus.FieldLogger,
		pod *corev1api.Pod,
		byContainer map[string][]PodExecRestoreHook,
		multiHookTracker *MultiHookTracker,
		restoreName string,
	) []error
}

type ListWatchFactory interface {
	NewListWatch(namespace string, selector fields.Selector) cache.ListerWatcher
}

type DefaultListWatchFactory struct {
	PodsGetter cache.Getter
}

type HookErrInfo struct {
	Namespace string
	Err       error
}

func (d *DefaultListWatchFactory) NewListWatch(namespace string, selector fields.Selector) cache.ListerWatcher {
	return cache.NewListWatchFromClient(d.PodsGetter, "pods", namespace, selector)
}

var _ ListWatchFactory = &DefaultListWatchFactory{}

type DefaultWaitExecHookHandler struct {
	ListWatchFactory   ListWatchFactory
	PodCommandExecutor podexec.PodCommandExecutor
}

var _ WaitExecHookHandler = &DefaultWaitExecHookHandler{}

func (e *DefaultWaitExecHookHandler) HandleHooks(
	ctx context.Context,
	log logrus.FieldLogger,
	pod *corev1api.Pod,
	byContainer map[string][]PodExecRestoreHook,
	multiHookTracker *MultiHookTracker,
	restoreName string,
) []error {
	if pod == nil {
		return nil
	}

	var errors []error
	// If hooks are defined for a container that does not exist in the pod log a warning and discard
	// those hooks to avoid waiting for a container that will never become ready. After that if
	// there are no hooks left to be executed return immediately.
	// Discarded hooks must be recorded as failed in the hook tracker, otherwise the tracker
	// will never reach completion and the restore finalizer will poll forever waiting on hooks
	// that can never run.
	for containerName, hooks := range byContainer {
		if !podHasContainer(pod, containerName) {
			discardErr := fmt.Errorf("pod %s does not have container %s: discarding post-restore exec hooks", kube.NamespaceAndName(pod), containerName)
			log.Warning(discardErr)
			for i, hook := range hooks {
				hookLog := log.WithFields(
					logrus.Fields{
						"hookSource": hook.HookSource,
						"hookType":   "exec",
						"hookPhase":  "post",
						"hookName":   hook.HookName,
						"container":  hook.Hook.Container,
					},
				)
				errTracker := multiHookTracker.Record(restoreName, pod.Namespace, pod.Name, hook.Hook.Container, hook.HookSource, hook.HookName, HookPhase(""), i, true, discardErr)
				if errTracker != nil {
					hookLog.WithError(errTracker).Warn("Error recording the discarded hook in hook tracker")
				}
			}
			errors = append(errors, discardErr)
			delete(byContainer, containerName)
		}
	}
	if len(byContainer) == 0 {
		return errors
	}

	// Every hook in every container can have its own wait timeout. Rather than setting up separate
	// contexts for each, find the largest wait timeout for any hook that should be executed in
	// the pod and watch the pod for up to that long. Before executing any hook in a container,
	// check if that hook has a timeout and skip execution if expired.
	ctx, cancel := context.WithCancel(ctx)
	maxWait := maxHookWait(byContainer)
	// If no hook has a wait timeout then this function will continue waiting for containers to
	// become ready until the shared hook context is canceled.
	if maxWait > 0 {
		ctx, cancel = context.WithTimeout(ctx, maxWait)
	}
	waitStart := time.Now()

	// The first time this handler is called after a container starts running it will execute all
	// pending hooks for that container. Subsequent invocations of this handler will never execute
	// hooks in that container. It uses the byContainer map to keep track of which containers have
	// not yet been observed to be running. It relies on the Informer not to be called concurrently.
	// When a container is observed running and its hooks are executed, the container is deleted
	// from the byContainer map. When the map is empty the watch is ended.
	handler := func(newObj any) {
		newPod, ok := newObj.(*corev1api.Pod)
		if !ok {
			return
		}

		podLog := log.WithFields(
			logrus.Fields{
				"pod": kube.NamespaceAndName(newPod),
			},
		)

		if newPod.Status.Phase == corev1api.PodSucceeded || newPod.Status.Phase == corev1api.PodFailed {
			err := fmt.Errorf("pod entered phase %s before some post-restore exec hooks ran", newPod.Status.Phase)
			podLog.Warning(err)
			cancel()
			return
		}

		for containerName, hooks := range byContainer {
			if !isContainerUp(newPod, containerName, hooks) {
				podLog.Infof("Container %s is not up: post-restore hooks will not yet be executed", containerName)
				continue
			}
			podMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(newPod)
			if err != nil {
				podLog.WithError(err).Error("error unstructuring pod")
				cancel()
				return
			}

			// Sequentially run all hooks for the ready container. The container's hooks are not
			// removed from the byContainer map until all have completed so that if one fails
			// remaining unexecuted hooks can be handled by the outer function.
			for i, hook := range hooks {
				// This indicates to the outer function not to handle this hook as unexecuted in
				// case of terminating before deleting this container's slice of hooks from the
				// byContainer map.
				byContainer[containerName][i].executed = true

				hookLog := podLog.WithFields(
					logrus.Fields{
						"hookSource": hook.HookSource,
						"hookType":   "exec",
						"hookPhase":  "post",
					},
				)
				// Check the individual hook's wait timeout is not expired
				if hook.Hook.WaitTimeout.Duration != 0 && time.Since(waitStart) > hook.Hook.WaitTimeout.Duration {
					err := fmt.Errorf("hook %s in container %s expired before executing", hook.HookName, hook.Hook.Container)
					hookLog.Error(err)
					errors = append(errors, err)

					errTracker := multiHookTracker.Record(restoreName, newPod.Namespace, newPod.Name, hook.Hook.Container, hook.HookSource, hook.HookName, HookPhase(""), hook.hookIndex, true, err)
					if errTracker != nil {
						hookLog.WithError(errTracker).Warn("Error recording the hook in hook tracker")
					}

					if hook.Hook.OnError == velerov1api.HookErrorModeFail {
						cancel()
						return
					}
				}
				eh := &velerov1api.ExecHook{
					Container: hook.Hook.Container,
					Command:   hook.Hook.Command,
					OnError:   hook.Hook.OnError,
					Timeout:   hook.Hook.ExecTimeout,
				}

				hookFailed := false
				var hookErr error
				if hookErr = e.PodCommandExecutor.ExecutePodCommand(hookLog, podMap, pod.Namespace, pod.Name, hook.HookName, eh); hookErr != nil {
					hookLog.WithError(hookErr).Error("Error executing hook")
					hookErr = fmt.Errorf("hook %s in container %s failed to execute, err: %v", hook.HookName, hook.Hook.Container, hookErr)
					errors = append(errors, hookErr)
					hookFailed = true
				}

				errTracker := multiHookTracker.Record(restoreName, newPod.Namespace, newPod.Name, hook.Hook.Container, hook.HookSource, hook.HookName, HookPhase(""), hook.hookIndex, hookFailed, hookErr)
				if errTracker != nil {
					hookLog.WithError(errTracker).Warn("Error recording the hook in hook tracker")
				}

				if hookErr != nil && hook.Hook.OnError == velerov1api.HookErrorModeFail {
					cancel()
					return
				}
			}
			delete(byContainer, containerName)
		}
		if len(byContainer) == 0 {
			cancel()
		}
	}

	selector := fields.OneTermEqualSelector("metadata.name", pod.Name)
	lw := e.ListWatchFactory.NewListWatch(pod.Namespace, selector)
	_, podWatcher := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: lw,
		ObjectType:    pod,
		ResyncPeriod:  0,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: handler,
			UpdateFunc: func(_, newObj any) {
				handler(newObj)
			},
			DeleteFunc: func(obj any) {
				err := fmt.Errorf("pod %s deleted before all hooks were executed", kube.NamespaceAndName(pod))
				log.Error(err)
				cancel()
			},
		},
	},
	)

	podWatcher.Run(ctx.Done())

	// There are some cases where this function could return with unexecuted hooks: the pod may
	// be deleted, a hook could fail, or it may timeout waiting for
	// containers to become ready.
	// Each unexecuted hook is logged as an error and this error will be returned from this function.
	for _, hooks := range byContainer {
		for _, hook := range hooks {
			if hook.executed {
				continue
			}
			err := fmt.Errorf("hook %s in container %s in pod %s not executed: %v", hook.HookName, hook.Hook.Container, kube.NamespaceAndName(pod), ctx.Err())
			hookLog := log.WithFields(
				logrus.Fields{
					"hookSource": hook.HookSource,
					"hookType":   "exec",
					"hookPhase":  "post",
				},
			)

			errTracker := multiHookTracker.Record(restoreName, pod.Namespace, pod.Name, hook.Hook.Container, hook.HookSource, hook.HookName, HookPhase(""), hook.hookIndex, true, err)
			if errTracker != nil {
				hookLog.WithError(errTracker).Warn("Error recording the hook in hook tracker")
			}

			hookLog.Error(err)
			errors = append(errors, err)
		}
	}

	return errors
}

func podHasContainer(pod *corev1api.Pod, containerName string) bool {
	if pod == nil {
		return false
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == containerName {
			return true
		}
	}

	return false
}

func isContainerUp(pod *corev1api.Pod, containerName string, hooks []PodExecRestoreHook) bool {
	if pod == nil {
		return false
	}
	var waitForReady bool
	for _, hook := range hooks {
		if boolptr.IsSetToTrue(hook.Hook.WaitForReady) {
			waitForReady = true
			break
		}
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name != containerName {
			continue
		}
		if waitForReady {
			return cs.Ready
		}
		return cs.State.Running != nil
	}

	return false
}

// maxHookWait returns 0 to mean wait indefinitely. Any hook without a wait timeout will cause this
// function to return 0.
func maxHookWait(byContainer map[string][]PodExecRestoreHook) time.Duration {
	var maxWait time.Duration
	for _, hooks := range byContainer {
		for _, hook := range hooks {
			if hook.Hook.WaitTimeout.Duration <= 0 {
				return 0
			}
			if hook.Hook.WaitTimeout.Duration > maxWait {
				maxWait = hook.Hook.WaitTimeout.Duration
			}
		}
	}
	return maxWait
}
