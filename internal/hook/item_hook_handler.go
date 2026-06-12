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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/podexec"
	"github.com/vmware-tanzu/velero/pkg/restorehelper"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

type HookPhase string

const (
	PhasePre  HookPhase = "pre"
	PhasePost HookPhase = "post"
)

const (
	// Backup hook annotations
	podBackupHookContainerAnnotationKey = "hook.backup.velero.io/container"
	podBackupHookCommandAnnotationKey   = "hook.backup.velero.io/command"
	podBackupHookOnErrorAnnotationKey   = "hook.backup.velero.io/on-error"
	podBackupHookTimeoutAnnotationKey   = "hook.backup.velero.io/timeout"

	// Restore hook annotations
	podRestoreHookContainerAnnotationKey            = "post.hook.restore.velero.io/container"
	podRestoreHookCommandAnnotationKey              = "post.hook.restore.velero.io/command"
	podRestoreHookOnErrorAnnotationKey              = "post.hook.restore.velero.io/on-error"
	podRestoreHookTimeoutAnnotationKey              = "post.hook.restore.velero.io/exec-timeout"
	podRestoreHookWaitTimeoutAnnotationKey          = "post.hook.restore.velero.io/wait-timeout"
	podRestoreHookWaitForReadyAnnotationKey         = "post.hook.restore.velero.io/wait-for-ready"
	podRestoreHookInitContainerImageAnnotationKey   = "init.hook.restore.velero.io/container-image"
	podRestoreHookInitContainerNameAnnotationKey    = "init.hook.restore.velero.io/container-name"
	podRestoreHookInitContainerCommandAnnotationKey = "init.hook.restore.velero.io/command"
	podRestoreHookInitContainerTimeoutAnnotationKey = "init.hook.restore.velero.io/timeout"
)

// ItemHookHandler invokes hooks for an item.
type ItemHookHandler interface {
	// HandleHooks invokes hooks for an item. If the item is a pod and the appropriate annotations exist
	// to specify a hook, that is executed. Otherwise, this looks at the backup context's Backup to
	// determine if there are any hooks relevant to the item, taking into account the hook spec's
	// namespaces, resources, and label selector.
	HandleHooks(
		log logrus.FieldLogger,
		groupResource schema.GroupResource,
		obj runtime.Unstructured,
		resourceHooks []ResourceHook,
		phase HookPhase,
		hookTracker *HookTracker,
	) error
}

// ItemRestoreHookHandler invokes restore hooks for an item
type ItemRestoreHookHandler interface {
	HandleRestoreHooks(
		log logrus.FieldLogger,
		groupResource schema.GroupResource,
		obj runtime.Unstructured,
		rh []ResourceRestoreHook,
	) (runtime.Unstructured, error)
}

// InitContainerRestoreHookHandler is the restore hook handler to add init containers to restored pods.
type InitContainerRestoreHookHandler struct{}

// HandleRestoreHooks runs the restore hooks for an item.
// If the item is a pod, then hooks are chosen to be run as follows:
// If the pod has the appropriate annotations specifying the hook action, then hooks from the annotation are run
// Otherwise, the supplied ResourceRestoreHooks are applied.
func (i *InitContainerRestoreHookHandler) HandleRestoreHooks(
	log logrus.FieldLogger,
	groupResource schema.GroupResource,
	obj runtime.Unstructured,
	resourceRestoreHooks []ResourceRestoreHook,
	namespaceMapping map[string]string,
) (runtime.Unstructured, error) {
	// We only support hooks on pods right now
	if groupResource != kuberesource.Pods {
		return nil, nil
	}

	metadata, err := meta.Accessor(obj)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get a metadata accessor")
	}
	pod := new(corev1api.Pod)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pod); err != nil {
		return nil, errors.WithStack(err)
	}

	initContainers := []corev1api.Container{}
	// If this pod is backed up with data movement, then we want to the pod volumes restored prior to
	// running the restore hook init containers. This allows the restore hook init containers to prepare the
	// restored data to be consumed by the application container(s).
	// So if there is a "restore-wait" init container already on the pod at index 0, we'll preserve that and run
	// it before running any other init container.
	if len(pod.Spec.InitContainers) > 0 && pod.Spec.InitContainers[0].Name == restorehelper.WaitInitContainer {
		initContainers = append(initContainers, pod.Spec.InitContainers[0])
		pod.Spec.InitContainers = pod.Spec.InitContainers[1:]
	}

	initContainerFromAnnotations := getInitContainerFromAnnotation(kube.NamespaceAndName(pod), metadata.GetAnnotations(), log)
	if initContainerFromAnnotations != nil {
		log.Infof("Handling InitRestoreHooks from pod annotations")
		initContainers = append(initContainers, *initContainerFromAnnotations)
	} else {
		log.Infof("Handling InitRestoreHooks from RestoreSpec")
		// pod did not have the annotations appropriate for restore hooks
		// running applicable ResourceRestoreHooks supplied.
		namespace := metadata.GetNamespace()
		labels := labels.Set(metadata.GetLabels())

		// Apply the hook according to the target namespace in which the pod will be restored
		// more details see https://github.com/vmware-tanzu/velero/issues/4720
		if namespaceMapping != nil {
			if n, ok := namespaceMapping[namespace]; ok {
				namespace = n
			}
		}
		for _, rh := range resourceRestoreHooks {
			if !rh.Selector.applicableTo(groupResource, namespace, labels) {
				continue
			}
			for _, hook := range rh.RestoreHooks {
				if hook.Init != nil {
					containers := make([]corev1api.Container, 0)
					for _, raw := range hook.Init.InitContainers {
						container := corev1api.Container{}
						err := ValidateContainer(raw.Raw)
						if err != nil {
							log.Errorf("invalid Restore Init hook: %s", err.Error())
							return nil, err
						}
						err = json.Unmarshal(raw.Raw, &container)
						if err != nil {
							log.Errorf("fail to Unmarshal hook Init into container: %s", err.Error())
							return nil, errors.WithStack(err)
						}
						containers = append(containers, container)
					}
					initContainers = append(initContainers, containers...)
				}
			}
		}
	}

	pod.Spec.InitContainers = append(initContainers, pod.Spec.InitContainers...)
	log.Infof("Returning pod %s/%s with %d init container(s)", pod.Namespace, pod.Name, len(pod.Spec.InitContainers))

	podMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pod)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &unstructured.Unstructured{Object: podMap}, nil
}

// DefaultItemHookHandler is the default itemHookHandler.
type DefaultItemHookHandler struct {
	PodCommandExecutor podexec.PodCommandExecutor
}

func (h *DefaultItemHookHandler) HandleHooks(
	log logrus.FieldLogger,
	groupResource schema.GroupResource,
	obj runtime.Unstructured,
	resourceHooks []ResourceHook,
	phase HookPhase,
	hookTracker *HookTracker,
) error {
	// We only support hooks on pods right now
	if groupResource != kuberesource.Pods {
		return nil
	}

	metadata, err := meta.Accessor(obj)
	if err != nil {
		return errors.Wrap(err, "unable to get a metadata accessor")
	}

	namespace := metadata.GetNamespace()
	name := metadata.GetName()

	// If the pod has the hook specified via annotations, that takes priority.
	hookFromAnnotations := getPodExecHookFromAnnotations(metadata.GetAnnotations(), phase, log)
	if phase == PhasePre && hookFromAnnotations == nil {
		// See if the pod has the legacy hook annotation keys (i.e. without a phase specified)
		hookFromAnnotations = getPodExecHookFromAnnotations(metadata.GetAnnotations(), "", log)
	}
	if hookFromAnnotations != nil {
		hookTracker.Add(namespace, name, hookFromAnnotations.Container, HookSourceAnnotation, "", phase, 0)

		hookLog := log.WithFields(
			logrus.Fields{
				"hookSource": HookSourceAnnotation,
				"hookType":   "exec",
				"hookPhase":  phase,
			},
		)

		hookFailed := false
		var errExec error
		if errExec = h.PodCommandExecutor.ExecutePodCommand(hookLog, obj.UnstructuredContent(), namespace, name, "<from-annotation>", hookFromAnnotations); errExec != nil {
			hookLog.WithError(errExec).Error("Error executing hook")
			hookFailed = true
		}
		errTracker := hookTracker.Record(namespace, name, hookFromAnnotations.Container, HookSourceAnnotation, "", phase, 0, hookFailed, errExec)
		if errTracker != nil {
			hookLog.WithError(errTracker).Warn("Error recording the hook in hook tracker")
		}

		if errExec != nil && hookFromAnnotations.OnError == velerov1api.HookErrorModeFail {
			return errExec
		}

		return nil
	}

	labels := labels.Set(metadata.GetLabels())
	// Otherwise, check for hooks defined in the backup spec.
	// modeFailError records the error from the hook with "Fail" error mode
	var modeFailError error
	for _, resourceHook := range resourceHooks {
		if !resourceHook.Selector.applicableTo(groupResource, namespace, labels) {
			continue
		}

		var hooks []velerov1api.BackupResourceHook
		if phase == PhasePre {
			hooks = resourceHook.Pre
		} else {
			hooks = resourceHook.Post
		}

		for i, hook := range hooks {
			if groupResource == kuberesource.Pods {
				if hook.Exec != nil {
					hookTracker.Add(namespace, name, hook.Exec.Container, HookSourceSpec, resourceHook.Name, phase, i)
					// The remaining hooks will only be executed if modeFailError is nil.
					// Otherwise, execution will stop and only hook collection will occur.
					if modeFailError == nil {
						hookLog := log.WithFields(
							logrus.Fields{
								"hookSource": HookSourceSpec,
								"hookType":   "exec",
								"hookPhase":  phase,
							},
						)

						hookFailed := false
						err := h.PodCommandExecutor.ExecutePodCommand(hookLog, obj.UnstructuredContent(), namespace, name, resourceHook.Name, hook.Exec)
						if err != nil {
							hookLog.WithError(err).Error("Error executing hook")
							hookFailed = true
							if hook.Exec.OnError == velerov1api.HookErrorModeFail {
								modeFailError = err
							}
						}
						errTracker := hookTracker.Record(namespace, name, hook.Exec.Container, HookSourceSpec, resourceHook.Name, phase, i, hookFailed, err)
						if errTracker != nil {
							hookLog.WithError(errTracker).Warn("Error recording the hook in hook tracker")
						}
					}
				}
			}
		}
	}

	return modeFailError
}

// NoOpItemHookHandler is the an itemHookHandler for the Finalize controller where hooks don't run
type NoOpItemHookHandler struct{}

func (h *NoOpItemHookHandler) HandleHooks(
	log logrus.FieldLogger,
	groupResource schema.GroupResource,
	obj runtime.Unstructured,
	resourceHooks []ResourceHook,
	phase HookPhase,
	hookTracker *HookTracker,
) error {
	return nil
}

func phasedKey(phase HookPhase, key string) string {
	if phase != "" {
		return fmt.Sprintf("%v.%v", phase, key)
	}
	return key
}

func getHookAnnotation(annotations map[string]string, key string, phase HookPhase) string {
	return annotations[phasedKey(phase, key)]
}

// getPodExecHookFromAnnotations returns an ExecHook based on the annotations, as long as the
// 'command' annotation is present. If it is absent, this returns nil.
// If there is an error in parsing a supplied timeout, it is logged.
func getPodExecHookFromAnnotations(annotations map[string]string, phase HookPhase, log logrus.FieldLogger) *velerov1api.ExecHook {
	commandValue := getHookAnnotation(annotations, podBackupHookCommandAnnotationKey, phase)
	if commandValue == "" {
		return nil
	}

	container := getHookAnnotation(annotations, podBackupHookContainerAnnotationKey, phase)

	onError := velerov1api.HookErrorMode(getHookAnnotation(annotations, podBackupHookOnErrorAnnotationKey, phase))
	if onError != velerov1api.HookErrorModeContinue && onError != velerov1api.HookErrorModeFail {
		onError = ""
	}

	var timeout time.Duration
	timeoutString := getHookAnnotation(annotations, podBackupHookTimeoutAnnotationKey, phase)
	if timeoutString != "" {
		if temp, err := time.ParseDuration(timeoutString); err == nil {
			timeout = temp
		} else {
			log.Warn(errors.Wrapf(err, "Unable to parse provided timeout %s, using default", timeoutString))
		}
	}

	return &velerov1api.ExecHook{
		Container: container,
		Command:   parseStringToCommand(commandValue),
		OnError:   onError,
		Timeout:   metav1.Duration{Duration: timeout},
	}
}

func parseStringToCommand(commandValue string) []string {
	var command []string
	// check for json array
	if commandValue[0] == '[' {
		if err := json.Unmarshal([]byte(commandValue), &command); err != nil {
			command = []string{commandValue}
		}
	} else {
		command = append(command, commandValue)
	}
	return command
}

type ResourceHookSelector struct {
	Namespaces    *collections.IncludesExcludes
	Resources     *collections.IncludesExcludes
	LabelSelector labels.Selector
}

// ResourceHook is a hook for a given resource.
type ResourceHook struct {
	Name     string
	Selector ResourceHookSelector
	Pre      []velerov1api.BackupResourceHook
	Post     []velerov1api.BackupResourceHook
}

func (r ResourceHookSelector) applicableTo(groupResource schema.GroupResource, namespace string, labels labels.Set) bool {
	if r.Namespaces != nil && !r.Namespaces.ShouldInclude(namespace) {
		return false
	}
	if r.Resources != nil && !r.Resources.ShouldInclude(groupResource.String()) {
		return false
	}
	if r.LabelSelector != nil && !r.LabelSelector.Matches(labels) {
		return false
	}
	return true
}

// ResourceRestoreHook is a restore hook for a given resource.
type ResourceRestoreHook struct {
	Name         string
	Selector     ResourceHookSelector
	RestoreHooks []velerov1api.RestoreResourceHook
}

func getInitContainerFromAnnotation(podName string, annotations map[string]string, log logrus.FieldLogger) *corev1api.Container {
	containerImage := annotations[podRestoreHookInitContainerImageAnnotationKey]
	containerName := annotations[podRestoreHookInitContainerNameAnnotationKey]
	command := annotations[podRestoreHookInitContainerCommandAnnotationKey]
	if containerImage == "" {
		log.Infof("Pod %s has no %s annotation, no initRestoreHook in annotation", podName, podRestoreHookInitContainerImageAnnotationKey)
		return nil
	}
	if command == "" {
		log.Infof("RestoreHook init container for pod %s is using container's default entrypoint", podName, containerImage)
	}
	if containerName == "" {
		uid, err := uuid.NewRandom()
		uuidStr := "deadfeed"
		if err != nil {
			log.Errorf("Failed to generate UUID for container name")
		} else {
			uuidStr = strings.Split(uid.String(), "-")[0]
		}
		containerName = fmt.Sprintf("velero-restore-init-%s", uuidStr)
		log.Infof("Pod %s has no %s annotation, using generated name %s for initContainer", podName, podRestoreHookInitContainerNameAnnotationKey, containerName)
	}

	initContainer := corev1api.Container{
		Image:   containerImage,
		Name:    containerName,
		Command: parseStringToCommand(command),
	}

	return &initContainer
}

// GetRestoreHooksFromSpec returns a list of ResourceRestoreHooks from the restore Spec.
func GetRestoreHooksFromSpec(hooksSpec *velerov1api.RestoreHooks) ([]ResourceRestoreHook, error) {
	if hooksSpec == nil {
		return []ResourceRestoreHook{}, nil
	}
	restoreHooks := make([]ResourceRestoreHook, 0, len(hooksSpec.Resources))
	for _, rs := range hooksSpec.Resources {
		rh := ResourceRestoreHook{
			Name: rs.Name,
			Selector: ResourceHookSelector{
				Namespaces: collections.NewIncludesExcludes().Includes(rs.IncludedNamespaces...).Excludes(rs.ExcludedNamespaces...),
				// these hooks ara applicable only to pods.
				// TODO: resolve the pods resource via discovery?
				Resources: collections.NewIncludesExcludes().Includes(kuberesource.Pods.Resource),
			},
			// TODO does this work for ExecRestoreHook as well?
			RestoreHooks: rs.PostHooks,
		}

		if rs.LabelSelector != nil {
			ls, err := metav1.LabelSelectorAsSelector(rs.LabelSelector)
			if err != nil {
				return []ResourceRestoreHook{}, errors.WithStack(err)
			}
			rh.Selector.LabelSelector = ls
		}
		restoreHooks = append(restoreHooks, rh)
	}

	return restoreHooks, nil
}

// getPodExecRestoreHookFromAnnotations returns an ExecRestoreHook based on restore annotations, as
// long as the 'command' annotation is present. If it is absent, this returns nil.
func getPodExecRestoreHookFromAnnotations(annotations map[string]string, log logrus.FieldLogger) *velerov1api.ExecRestoreHook {
	commandValue := annotations[podRestoreHookCommandAnnotationKey]
	if commandValue == "" {
		return nil
	}

	container := annotations[podRestoreHookContainerAnnotationKey]

	onError := velerov1api.HookErrorMode(annotations[podRestoreHookOnErrorAnnotationKey])
	if onError != velerov1api.HookErrorModeContinue && onError != velerov1api.HookErrorModeFail {
		onError = ""
	}

	var execTimeout time.Duration
	execTimeoutString := annotations[podRestoreHookTimeoutAnnotationKey]
	if execTimeoutString != "" {
		if temp, err := time.ParseDuration(execTimeoutString); err == nil {
			execTimeout = temp
		} else {
			log.Warn(errors.Wrapf(err, "Unable to parse exec timeout %s, ignoring", execTimeoutString))
		}
	}

	var waitTimeout time.Duration
	waitTimeoutString := annotations[podRestoreHookWaitTimeoutAnnotationKey]
	if waitTimeoutString != "" {
		if temp, err := time.ParseDuration(waitTimeoutString); err == nil {
			waitTimeout = temp
		} else {
			log.Warn(errors.Wrapf(err, "Unable to parse wait timeout %s, ignoring", waitTimeoutString))
		}
	}

	waitForReadyString := annotations[podRestoreHookWaitForReadyAnnotationKey]
	waitForReady := boolptr.False()
	if waitForReadyString != "" {
		var err error
		*waitForReady, err = strconv.ParseBool(waitForReadyString)
		if err != nil {
			log.Warn(errors.Wrapf(err, "Unable to parse wait for ready %s, ignoring", waitForReadyString))
		}
	}

	return &velerov1api.ExecRestoreHook{
		Container:    container,
		Command:      parseStringToCommand(commandValue),
		OnError:      onError,
		ExecTimeout:  metav1.Duration{Duration: execTimeout},
		WaitTimeout:  metav1.Duration{Duration: waitTimeout},
		WaitForReady: waitForReady,
	}
}

type PodExecRestoreHook struct {
	HookName   string
	HookSource string
	Hook       velerov1api.ExecRestoreHook
	executed   bool
	// hookIndex contains the slice index for the specific hook from the restore spec
	// in order to track multiple hooks. Stored here because restore hook results are recorded
	// outside of the original slice iteration
	// for the same container
	hookIndex int
}

// GroupRestoreExecHooks returns a list of hooks to be executed in a pod grouped by
// container name. If an exec hook is defined in annotation that is used, else applicable exec
// hooks from the restore resource are accumulated.
func GroupRestoreExecHooks(
	restoreName string,
	resourceRestoreHooks []ResourceRestoreHook,
	pod *corev1api.Pod,
	log logrus.FieldLogger,
	hookTrack *MultiHookTracker,
) (map[string][]PodExecRestoreHook, error) {
	byContainer := map[string][]PodExecRestoreHook{}

	if pod == nil || len(pod.Spec.Containers) == 0 {
		return byContainer, nil
	}
	metadata, err := meta.Accessor(pod)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	hookFromAnnotation := getPodExecRestoreHookFromAnnotations(metadata.GetAnnotations(), log)
	if hookFromAnnotation != nil {
		// default to first container in pod if unset
		if hookFromAnnotation.Container == "" {
			hookFromAnnotation.Container = pod.Spec.Containers[0].Name
		}
		hookTrack.Add(restoreName, metadata.GetNamespace(), metadata.GetName(), hookFromAnnotation.Container, HookSourceAnnotation, "<from-annotation>", HookPhase(""), 0)
		byContainer[hookFromAnnotation.Container] = []PodExecRestoreHook{
			{
				HookName:   "<from-annotation>",
				HookSource: HookSourceAnnotation,
				Hook:       *hookFromAnnotation,
				hookIndex:  0,
			},
		}
		return byContainer, nil
	}

	// No hook found on pod's annotations so check for applicable hooks from the restore spec
	labels := metadata.GetLabels()
	namespace := metadata.GetNamespace()
	for _, rrh := range resourceRestoreHooks {
		if !rrh.Selector.applicableTo(kuberesource.Pods, namespace, labels) {
			continue
		}
		for i, rh := range rrh.RestoreHooks {
			if rh.Exec == nil {
				continue
			}
			named := PodExecRestoreHook{
				HookName:   rrh.Name,
				Hook:       *rh.Exec,
				HookSource: HookSourceSpec,
				hookIndex:  i,
			}
			// default to false if attr WaitForReady not set
			if named.Hook.WaitForReady == nil {
				named.Hook.WaitForReady = boolptr.False()
			}
			// default to first container in pod if unset, without mutating resource restore hook
			if named.Hook.Container == "" {
				named.Hook.Container = pod.Spec.Containers[0].Name
			}
			hookTrack.Add(restoreName, metadata.GetNamespace(), metadata.GetName(), named.Hook.Container, HookSourceSpec, rrh.Name, HookPhase(""), i)
			byContainer[named.Hook.Container] = append(byContainer[named.Hook.Container], named)
		}
	}

	return byContainer, nil
}

// ValidateContainer validate whether a map contains mandatory k8s Container fields.
// mandatory fields include name, image and commands.
func ValidateContainer(raw []byte) error {
	container := corev1api.Container{}
	err := json.Unmarshal(raw, &container)
	if err != nil {
		return err
	}
	if len(container.Command) <= 0 || len(container.Name) <= 0 || len(container.Image) <= 0 {
		return fmt.Errorf("invalid InitContainer in restore hook, it doesn't have Command, Name or Image field")
	}
	return nil
}
