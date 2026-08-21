/*
Copyright The Velero Contributors.

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
package kube

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type LoadAffinity struct {
	// NodeSelector specifies the label selector to match nodes
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`

	// StorageClass specifies the VGDPs the LoadAffinity applied to. If the StorageClass doesn't have value, it applies to all. If not, it applies to only the VGDPs that use this StorageClass.
	StorageClass string `json:"storageClass"`
}

type PodResources struct {
	CPURequest              string `json:"cpuRequest,omitempty"`
	CPULimit                string `json:"cpuLimit,omitempty"`
	MemoryRequest           string `json:"memoryRequest,omitempty"`
	MemoryLimit             string `json:"memoryLimit,omitempty"`
	EphemeralStorageRequest string `json:"ephemeralStorageRequest,omitempty"`
	EphemeralStorageLimit   string `json:"ephemeralStorageLimit,omitempty"`
}

// IsPodRunning does a well-rounded check to make sure the specified pod is running stably.
// If not, return the error found
func IsPodRunning(pod *corev1api.Pod) error {
	return isPodScheduledInStatus(pod, func(pod *corev1api.Pod) error {
		if pod.Status.Phase != corev1api.PodRunning {
			return errors.New("pod is not running")
		}

		return nil
	})
}

// IsPodScheduled does a well-rounded check to make sure the specified pod has been scheduled into a node and in a stable status.
// If not, return the error found
func IsPodScheduled(pod *corev1api.Pod) error {
	return isPodScheduledInStatus(pod, func(pod *corev1api.Pod) error {
		if pod.Status.Phase != corev1api.PodRunning && pod.Status.Phase != corev1api.PodPending {
			return errors.New("pod is not running or pending")
		}

		return nil
	})
}

func isPodScheduledInStatus(pod *corev1api.Pod, statusCheckFunc func(*corev1api.Pod) error) error {
	if pod == nil {
		return errors.New("invalid input pod")
	}

	if pod.Spec.NodeName == "" {
		return errors.Errorf("pod is not scheduled, name=%s, namespace=%s, phase=%s", pod.Name, pod.Namespace, pod.Status.Phase)
	}

	if err := statusCheckFunc(pod); err != nil {
		return errors.Wrapf(err, "pod is not in the expected status, name=%s, namespace=%s, phase=%s", pod.Name, pod.Namespace, pod.Status.Phase)
	}

	if pod.DeletionTimestamp != nil {
		return errors.Errorf("pod is being terminated, name=%s, namespace=%s, phase=%s", pod.Name, pod.Namespace, pod.Status.Phase)
	}

	return nil
}

// DeletePodIfAny deletes a pod by name if it exists, and log an error when the deletion fails
func DeletePodIfAny(ctx context.Context, podGetter corev1client.CoreV1Interface, podName string, podNamespace string, log logrus.FieldLogger) {
	err := podGetter.Pods(podNamespace).Delete(ctx, podName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Debugf("Abort deleting pod, it doesn't exist %s/%s", podNamespace, podName)
		} else {
			log.WithError(err).Errorf("Failed to delete pod %s/%s", podNamespace, podName)
		}
	}
}

// EnsureDeletePod asserts the existence of a pod by name, deletes it and waits for its disappearance and returns errors on any failure
func EnsureDeletePod(ctx context.Context, podGetter corev1client.CoreV1Interface, pod string, namespace string, timeout time.Duration) error {
	err := podGetter.Pods(namespace).Delete(ctx, pod, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "error to delete pod %s", pod)
	}

	var updated *corev1api.Pod
	err = wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		po, err := podGetter.Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			return false, errors.Wrapf(err, "error to get pod %s", pod)
		}

		updated = po
		return false, nil
	})

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Errorf("timeout to assure pod %s is deleted, finalizers in pod %v", pod, updated.Finalizers)
		} else {
			return errors.Wrapf(err, "error to assure pod is deleted, %s", pod)
		}
	}

	return nil
}

// IsPodUnrecoverable checks if the pod is in an abnormal state and could not be recovered
// It could not cover all the cases but we could add more cases in the future
func IsPodUnrecoverable(ctx context.Context, kubeClient kubernetes.Interface, pod *corev1api.Pod, log logrus.FieldLogger) (bool, string) {
	// Check the Phase field
	if pod.Status.Phase == corev1api.PodFailed || pod.Status.Phase == corev1api.PodUnknown {
		message := ""
		if pod.Status.Message != "" {
			message += pod.Status.Message + "/"
		}

		message += GetPodTerminateMessage(pod)

		log.Warnf("Pod is in abnormal state %s, message [%s]", pod.Status.Phase, message)
		return true, fmt.Sprintf("Pod is in abnormal state [%s], message [%s]", pod.Status.Phase, message)
	}

	// removed "Unschedulable" check since unschedulable condition isn't always permanent -- see
	// the node-affinity check below for the one case (zero nodes can ever satisfy the pod's
	// required node affinity) narrow enough to still treat as permanent.

	// Check the Status field
	for _, containerStatus := range pod.Status.ContainerStatuses {
		// If the container's image state is ImagePullBackOff, it indicates an image pull failure
		if containerStatus.State.Waiting != nil && (containerStatus.State.Waiting.Reason == "ImagePullBackOff" || containerStatus.State.Waiting.Reason == "ErrImageNeverPull") {
			log.Warnf("Container %s in Pod %s/%s is in pull image failed with reason %s", containerStatus.Name, pod.Namespace, pod.Name, containerStatus.State.Waiting.Reason)
			return true, fmt.Sprintf("Container %s in Pod %s/%s is in pull image failed with reason %s", containerStatus.Name, pod.Namespace, pod.Name, containerStatus.State.Waiting.Reason)
		}
	}

	// Node affinity requirements are purely label-based (they match node labels, not capacity),
	// so if zero EXISTING nodes' labels satisfy them, it's very likely a permanent scheduling
	// mismatch, most commonly caused by a node-agent loadAffinity configuration that references
	// labels no node actually has - though a brand new node joining later with different labels
	// (e.g. a fresh autoscaled node pool) could still resolve it, which is exactly why this only
	// fires after the grace period below, not on the first observation. Reporting it once
	// persistent, rather than waiting out the full preparing/operation timeout, gives users an
	// actionable error instead of an opaque "timeout" message.
	if unschedulable, reason := isPodUnschedulableDueToNodeAffinity(ctx, kubeClient, pod); unschedulable {
		return true, reason
	}

	return false, ""
}

// unschedulableNodeAffinityGracePeriod is the minimum time the PodScheduled condition must have
// held False before isPodUnschedulableDueToNodeAffinity will treat a node-affinity mismatch as
// permanent. Without this, a single node-list snapshot taken at exactly the wrong moment (e.g. a
// cluster-autoscaler-provisioned node that matches the affinity but hasn't finished
// joining/registering yet, or an admin mid-relabel) could cause a false permanent verdict on
// what's actually about to resolve itself - the same trap that #9697 hit with a blanket
// Unschedulable check.
//
// Deliberately set toward the generous end of "long enough to ride out ordinary node-join
// latency": a false "permanent" verdict silently fails the data mover, while a slower-than-ideal
// but correct verdict just costs a few extra minutes of an operation that was already going to
// take a while. 5 minutes is still well short of the default ~10 minute preparing/operation
// timeout, so misconfigured node affinity (the actual permanent case this exists for) is still
// reported far faster than that opaque timeout would.
const unschedulableNodeAffinityGracePeriod = 5 * time.Minute

// isPodUnschedulableDueToNodeAffinity reports whether pod's PodScheduled condition has held
// False for at least unschedulableNodeAffinityGracePeriod, with its required node affinity
// unsatisfiable by ANY node currently in the cluster. See the comment on
// unschedulableNodeAffinityGracePeriod above for why this only fires after the grace period, and
// the comment on IsPodUnrecoverable above for why this check is narrower than a blanket
// Unschedulable check.
func isPodUnschedulableDueToNodeAffinity(ctx context.Context, kubeClient kubernetes.Interface, pod *corev1api.Pod) (bool, string) {
	cond := getPodScheduledCondition(pod)
	if cond == nil || cond.Status != corev1api.ConditionFalse {
		return false, ""
	}

	if time.Since(cond.LastTransitionTime.Time) < unschedulableNodeAffinityGracePeriod {
		// Too recent to distinguish from a transient/in-progress scheduling situation.
		return false, ""
	}

	if pod.Spec.Affinity == nil || pod.Spec.Affinity.NodeAffinity == nil ||
		pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return false, ""
	}

	terms := pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) == 0 {
		return false, ""
	}

	nodeList, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		// Can't verify one way or the other; don't claim a permanent mismatch on missing data.
		return false, ""
	}

	if nodeAffinitySatisfiableByAny(nodeList.Items, terms) {
		return false, ""
	}

	return true, fmt.Sprintf(
		"pod %s/%s has been unschedulable for over %s: no node in the cluster satisfies its required node affinity, so this cannot resolve by waiting; reported scheduling failure: %s",
		pod.Namespace, pod.Name, unschedulableNodeAffinityGracePeriod, cond.Message,
	)
}

func getPodScheduledCondition(pod *corev1api.Pod) *corev1api.PodCondition {
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1api.PodScheduled {
			return &pod.Status.Conditions[i]
		}
	}
	return nil
}

// nodeAffinitySatisfiableByAny reports whether any node in nodes satisfies any of terms.
// NodeSelectorTerms are OR'd together; a single term's MatchExpressions are AND'd (matching
// standard Kubernetes node affinity semantics). MatchFields is intentionally not evaluated,
// and Gt/Lt operators are intentionally treated as always-satisfiable (see
// nodeMatchesSelectorRequirement): the only producer of node affinity for the pods this
// function is ever called on is Velero's own ToSystemAffinity, which builds MatchExpressions
// exclusively from a metav1.LabelSelector (LoadAffinity.NodeSelector) - a type whose operator
// enum has no Gt/Lt - plus CSI topology requirements, which are always simple equality
// matches. Neither MatchFields nor Gt/Lt can occur in practice here; implementing them (or
// pulling in k8s.io/component-helpers/scheduling/corev1/nodeaffinity as a new dependency to
// get them for free) would be dead code for this caller.
func nodeAffinitySatisfiableByAny(nodes []corev1api.Node, terms []corev1api.NodeSelectorTerm) bool {
	for i := range nodes {
		for _, term := range terms {
			if nodeMatchesSelectorTerm(&nodes[i], term) {
				return true
			}
		}
	}
	return false
}

func nodeMatchesSelectorTerm(node *corev1api.Node, term corev1api.NodeSelectorTerm) bool {
	for _, req := range term.MatchExpressions {
		if !nodeMatchesSelectorRequirement(node, req) {
			return false
		}
	}
	return true
}

func nodeMatchesSelectorRequirement(node *corev1api.Node, req corev1api.NodeSelectorRequirement) bool {
	value, exists := node.Labels[req.Key]
	switch req.Operator {
	case corev1api.NodeSelectorOpIn:
		return exists && slices.Contains(req.Values, value)
	case corev1api.NodeSelectorOpNotIn:
		return !exists || !slices.Contains(req.Values, value)
	case corev1api.NodeSelectorOpExists:
		return exists
	case corev1api.NodeSelectorOpDoesNotExist:
		return !exists
	default:
		// NodeSelectorOpGt/Lt and any future/unknown operator: don't have a precise
		// implementation here, so err on the side of "might be satisfiable" rather than
		// risk a false permanent-mismatch report.
		return true
	}
}

// GetPodContainerTerminateMessage returns the terminate message for a specific container of a pod
func GetPodContainerTerminateMessage(pod *corev1api.Pod, container string) string {
	message := ""
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.Name == container {
			if containerStatus.State.Terminated != nil {
				message = containerStatus.State.Terminated.Message
			}
			break
		}
	}

	return message
}

// GetPodTerminateMessage returns the terminate message for all containers of a pod
func GetPodTerminateMessage(pod *corev1api.Pod) string {
	var message strings.Builder
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Terminated != nil {
			if containerStatus.State.Terminated.Message != "" {
				message.WriteString(containerStatus.State.Terminated.Message + "/")
			}
		}
	}

	return message.String()
}

func getPodLogReader(ctx context.Context, podGetter corev1client.CoreV1Interface, pod string, namespace string, logOptions *corev1api.PodLogOptions) (io.ReadCloser, error) {
	request := podGetter.Pods(namespace).GetLogs(pod, logOptions)
	return request.Stream(ctx)
}

var podLogReaderGetter = getPodLogReader

// CollectPodLogs collects logs of the specified container of a pod and write to the output
func CollectPodLogs(ctx context.Context, podGetter corev1client.CoreV1Interface, pod string, namespace string, container string, output io.Writer) error {
	logIndicator := fmt.Sprintf("***************************begin pod logs[%s/%s]***************************\n", pod, container)

	if _, err := output.Write([]byte(logIndicator)); err != nil {
		return errors.Wrap(err, "error to write begin pod log indicator")
	}

	logOptions := &corev1api.PodLogOptions{
		Container: container,
	}

	if input, err := podLogReaderGetter(ctx, podGetter, pod, namespace, logOptions); err != nil {
		logIndicator = fmt.Sprintf("No present log retrieved, err: %v\n", err)
	} else {
		if _, err := io.Copy(output, input); err != nil {
			return errors.Wrap(err, "error to copy input")
		}

		logIndicator = ""
	}

	logIndicator += fmt.Sprintf("***************************end pod logs[%s/%s]***************************\n", pod, container)
	if _, err := output.Write([]byte(logIndicator)); err != nil {
		return errors.Wrap(err, "error to write end pod log indicator")
	}

	return nil
}

func ToSystemAffinity(loadAffinity *LoadAffinity, volumeTopology *corev1api.NodeSelector) *corev1api.Affinity {
	requirements := []corev1api.NodeSelectorRequirement{}
	if loadAffinity != nil {
		for k, v := range loadAffinity.NodeSelector.MatchLabels {
			requirements = append(requirements, corev1api.NodeSelectorRequirement{
				Key:      k,
				Values:   []string{v},
				Operator: corev1api.NodeSelectorOpIn,
			})
		}

		for _, exp := range loadAffinity.NodeSelector.MatchExpressions {
			requirements = append(requirements, corev1api.NodeSelectorRequirement{
				Key:      exp.Key,
				Values:   exp.Values,
				Operator: corev1api.NodeSelectorOperator(exp.Operator),
			})
		}
	}

	result := new(corev1api.Affinity)
	result.NodeAffinity = new(corev1api.NodeAffinity)
	result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = new(corev1api.NodeSelector)

	if volumeTopology != nil {
		result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = append(result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, volumeTopology.NodeSelectorTerms...)
	} else if len(requirements) > 0 {
		result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = make([]corev1api.NodeSelectorTerm, 1)
	} else {
		return nil
	}

	for i := range result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[i].MatchExpressions = append(result.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[i].MatchExpressions, requirements...)
	}

	return result
}

func DiagnosePod(pod *corev1api.Pod, events *corev1api.EventList) string {
	var diag strings.Builder
	_, _ = fmt.Fprintf(&diag, "Pod %s/%s, phase %s, node name %s, message %s\n", pod.Namespace, pod.Name, pod.Status.Phase, pod.Spec.NodeName, pod.Status.Message)

	for _, condition := range pod.Status.Conditions {
		_, _ = fmt.Fprintf(&diag, "Pod condition %s, status %s, reason %s, message %s\n", condition.Type, condition.Status, condition.Reason, condition.Message)
	}

	if events != nil {
		for _, e := range events.Items {
			if e.InvolvedObject.UID == pod.UID && e.Type == corev1api.EventTypeWarning {
				_, _ = fmt.Fprintf(&diag, "Pod event reason %s, message %s\n", e.Reason, e.Message)
			}
		}
	}

	return diag.String()
}

var funcExit = os.Exit
var funcCreateFile = os.Create

func ExitPodWithMessage(logger logrus.FieldLogger, succeed bool, message string, a ...any) {
	exitCode := 0
	if !succeed {
		exitCode = 1
	}

	toWrite := fmt.Sprintf(message, a...)

	podFile, err := funcCreateFile("/dev/termination-log")
	if err != nil {
		logger.WithError(err).Error("Failed to create termination log file")
		exitCode = 1
	} else {
		if _, err := podFile.WriteString(toWrite); err != nil {
			logger.WithError(err).Error("Failed to write error to termination log file")
			exitCode = 1
		}

		podFile.Close()
	}

	funcExit(exitCode)
}

// GetLoadAffinityByStorageClass retrieves the LoadAffinity from the parameter affinityList.
// The function first try to find by the scName. If there is no such LoadAffinity,
// it will try to get the LoadAffinity whose StorageClass has no value.
func GetLoadAffinityByStorageClass(
	affinityList []*LoadAffinity,
	scName string,
	logger logrus.FieldLogger,
) *LoadAffinity {
	var globalAffinity *LoadAffinity

	for _, affinity := range affinityList {
		if affinity.StorageClass == scName {
			logger.WithField("StorageClass", scName).Info("Found pod's affinity setting per StorageClass.")
			return affinity
		}

		if affinity.StorageClass == "" && globalAffinity == nil {
			globalAffinity = affinity
		}
	}

	if globalAffinity != nil {
		logger.Info("Use the Global affinity for pod.")
	} else {
		logger.Info("No Affinity is found for pod.")
	}

	return globalAffinity
}
