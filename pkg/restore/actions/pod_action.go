/*
Copyright the Velero contributors.

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
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

type PodAction struct {
	logger logrus.FieldLogger
}

func NewPodAction(logger logrus.FieldLogger) *PodAction {
	return &PodAction{logger: logger}
}

func (a *PodAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"pods"},
	}, nil
}

func (a *PodAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	pod := new(corev1api.Pod)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), pod); err != nil {
		return nil, errors.WithStack(err)
	}

	pod.Spec.NodeName = ""
	pod.Spec.Priority = nil

	serviceAccountTokenPrefix := pod.Spec.ServiceAccountName + "-token-"

	var preservedVolumes []corev1api.Volume
	for _, vol := range pod.Spec.Volumes {
		if !strings.HasPrefix(vol.Name, serviceAccountTokenPrefix) {
			preservedVolumes = append(preservedVolumes, vol)
		}
	}
	pod.Spec.Volumes = preservedVolumes

	pod.Spec.Containers = filterContainerVolumeMounts(pod.Spec.Containers, serviceAccountTokenPrefix)
	pod.Spec.InitContainers = filterContainerVolumeMounts(pod.Spec.InitContainers, serviceAccountTokenPrefix)
	pod.Spec.EphemeralContainers = filterEphemeralContainerVolumeMounts(pod.Spec.EphemeralContainers, serviceAccountTokenPrefix)

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pod)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	restoreExecuteOutput := velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: res})
	if pod.Spec.PriorityClassName != "" {
		a.logger.Infof("Adding priorityclass %s to AdditionalItems", pod.Spec.PriorityClassName)
		restoreExecuteOutput.AdditionalItems = []velero.ResourceIdentifier{
			{GroupResource: kuberesource.PriorityClasses, Name: pod.Spec.PriorityClassName}}
	}
	return restoreExecuteOutput, nil
}

func filterVolumeMounts(mounts []corev1api.VolumeMount, prefix string) []corev1api.VolumeMount {
	var preserved []corev1api.VolumeMount
	for _, mount := range mounts {
		if !strings.HasPrefix(mount.Name, prefix) {
			preserved = append(preserved, mount)
		}
	}
	return preserved
}

func filterContainerVolumeMounts(containers []corev1api.Container, prefix string) []corev1api.Container {
	for i, container := range containers {
		containers[i].VolumeMounts = filterVolumeMounts(container.VolumeMounts, prefix)
	}
	return containers
}

func filterEphemeralContainerVolumeMounts(containers []corev1api.EphemeralContainer, prefix string) []corev1api.EphemeralContainer {
	for i, container := range containers {
		containers[i].VolumeMounts = filterVolumeMounts(container.VolumeMounts, prefix)
	}
	return containers
}
