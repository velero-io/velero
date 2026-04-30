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

package nodeagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	// daemonSet is the name of the Velero node agent daemonset on linux nodes.
	daemonSet = "node-agent"

	// daemonsetWindows is the name of the Velero node agent daemonset on Windows nodes.
	daemonsetWindows = "node-agent-windows"

	// nodeAgentRole marks pods with node-agent role on all nodes.
	nodeAgentRole = "node-agent"

	// HostPodVolumeMount is the name of the volume in node-agent for host-pod mount
	HostPodVolumeMount = "host-pods"

	// HostPodVolumeMountPoint is the mount point of the volume in node-agent for host-pod mount
	HostPodVolumeMountPoint = "host_pods"
)

var (
	ErrDaemonSetNotFound           = errors.New("daemonset not found")
	ErrNodeAgentLabelNotFound      = errors.New("node-agent label not found")
	ErrNodeAgentAnnotationNotFound = errors.New("node-agent annotation not found")
)

func IsRunningOnLinux(ctx context.Context, kubeClient kubernetes.Interface, namespace string) error {
	return isRunning(ctx, kubeClient, namespace, daemonSet)
}

func IsRunningOnWindows(ctx context.Context, kubeClient kubernetes.Interface, namespace string) error {
	return isRunning(ctx, kubeClient, namespace, daemonsetWindows)
}

func isRunning(ctx context.Context, kubeClient kubernetes.Interface, namespace string, daemonset string) error {
	if _, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, daemonset, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		return ErrDaemonSetNotFound
	} else if err != nil {
		return err
	} else {
		return nil
	}
}

// KbClientIsRunningInNode checks if the node agent pod is running properly in a specified node through kube client. If not, return the error found
func KbClientIsRunningInNode(ctx context.Context, namespace string, nodeName string, kubeClient kubernetes.Interface) error {
	return isRunningInNode(ctx, namespace, nodeName, nil, kubeClient)
}

// IsRunningInNode checks if the node agent pod is running properly in a specified node through controller client. If not, return the error found
func IsRunningInNode(ctx context.Context, namespace string, nodeName string, crClient ctrlclient.Client) error {
	return isRunningInNode(ctx, namespace, nodeName, crClient, nil)
}

func isRunningInNode(ctx context.Context, namespace string, nodeName string, crClient ctrlclient.Client, kubeClient kubernetes.Interface) error {
	if nodeName == "" {
		return errors.New("node name is empty")
	}

	pods := new(corev1api.PodList)
	parsedSelector, err := labels.Parse(fmt.Sprintf("role=%s", nodeAgentRole))
	if err != nil {
		return errors.Wrap(err, "fail to parse selector")
	}

	if crClient != nil {
		err = crClient.List(ctx, pods, &ctrlclient.ListOptions{
			LabelSelector: parsedSelector,
			Namespace:     namespace,
		})
	} else {
		pods, err = kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: parsedSelector.String()})
	}

	if err != nil {
		return errors.Wrap(err, "failed to list node-agent pods")
	}

	for i := range pods.Items {
		if kube.IsPodRunning(&pods.Items[i]) != nil {
			continue
		}

		if pods.Items[i].Spec.NodeName == nodeName {
			return nil
		}
	}

	return errors.Errorf("daemonset pod not found in running state in node %s", nodeName)
}

func GetPodSpec(ctx context.Context, kubeClient kubernetes.Interface, namespace string, osType string) (*corev1api.PodSpec, error) {
	dsName := daemonSet
	if osType == kube.NodeOSWindows {
		dsName = daemonsetWindows
	}

	ds, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, dsName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error to get %s daemonset", dsName)
	}

	return &ds.Spec.Template.Spec, nil
}

func GetConfigs(ctx context.Context, namespace string, kubeClient kubernetes.Interface, configName string) (*velerotypes.NodeAgentConfigs, error) {
	cm, err := kubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, configName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error to get node agent configs %s", configName)
	}

	if cm.Data == nil {
		return nil, errors.Errorf("data is not available in config map %s", configName)
	}

	if len(cm.Data) > 1 {
		return nil, errors.Errorf("more than one keys are found in ConfigMap %s's data. only expect one", configName)
	}

	jsonString := ""
	for _, v := range cm.Data {
		jsonString = v
	}

	configs := &velerotypes.NodeAgentConfigs{}
	err = json.Unmarshal([]byte(jsonString), configs)
	if err != nil {
		return nil, errors.Wrapf(err, "error to unmarshall configs from %s", configName)
	}

	return configs, nil
}

func GetLabelValue(ctx context.Context, kubeClient kubernetes.Interface, namespace string, key string, osType string) (string, error) {
	dsName := daemonSet
	if osType == kube.NodeOSWindows {
		dsName = daemonsetWindows
	}

	ds, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, dsName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "error getting %s daemonset", dsName)
	}

	if ds.Spec.Template.Labels == nil {
		return "", ErrNodeAgentLabelNotFound
	}

	val, found := ds.Spec.Template.Labels[key]
	if !found {
		return "", ErrNodeAgentLabelNotFound
	}

	return val, nil
}

func GetAnnotationValue(ctx context.Context, kubeClient kubernetes.Interface, namespace string, key string, osType string) (string, error) {
	dsName := daemonSet
	if osType == kube.NodeOSWindows {
		dsName = daemonsetWindows
	}

	ds, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, dsName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "error getting %s daemonset", dsName)
	}

	if ds.Spec.Template.Annotations == nil {
		return "", ErrNodeAgentAnnotationNotFound
	}

	val, found := ds.Spec.Template.Annotations[key]
	if !found {
		return "", ErrNodeAgentAnnotationNotFound
	}

	return val, nil
}

// GetTolerations returns all tolerations from the node-agent daemonset.
func GetTolerations(ctx context.Context, kubeClient kubernetes.Interface, namespace string, osType string) ([]corev1api.Toleration, error) {
	dsName := daemonSet
	if osType == kube.NodeOSWindows {
		dsName = daemonsetWindows
	}

	ds, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, dsName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error getting %s daemonset", dsName)
	}

	return ds.Spec.Template.Spec.Tolerations, nil
}

func GetHostPodPath(ctx context.Context, kubeClient kubernetes.Interface, namespace string, osType string) (string, error) {
	dsName := daemonSet
	if osType == kube.NodeOSWindows {
		dsName = daemonsetWindows
	}

	ds, err := kubeClient.AppsV1().DaemonSets(namespace).Get(ctx, dsName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "error getting daemonset %s", dsName)
	}

	var volume *corev1api.Volume
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == HostPodVolumeMount {
			volume = &v
			break
		}
	}

	if volume == nil {
		return "", errors.New("host pod volume is not found")
	}

	if volume.HostPath == nil {
		return "", errors.New("host pod volume is not a host path volume")
	}

	if volume.HostPath.Path == "" {
		return "", errors.New("host pod volume path is empty")
	}

	return volume.HostPath.Path, nil
}

func HostPodVolumeMountPath() string {
	return "/" + HostPodVolumeMountPoint
}

func HostPodVolumeMountPathWin() string {
	return "\\" + HostPodVolumeMountPoint
}
