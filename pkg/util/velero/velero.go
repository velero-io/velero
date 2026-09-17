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

package velero

import (
	"context"
	"fmt"

	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/install"
)

// GetVeleroServerDeployment finds the Velero server deployment by label selector
// instead of by hardcoded name, to support custom deployment names.
func GetVeleroServerDeployment(ctx context.Context, cli ctrlclient.Client, namespace string) (*appsv1api.Deployment, error) {
	deployList := new(appsv1api.DeploymentList)
	labelSelector := ctrlclient.MatchingLabels(install.Labels())
	if err := cli.List(ctx, deployList, ctrlclient.InNamespace(namespace), labelSelector); err != nil {
		return nil, err
	}
	for i := range deployList.Items {
		for _, container := range deployList.Items[i].Spec.Template.Spec.Containers {
			if container.Name == "velero" {
				return &deployList.Items[i], nil
			}
		}
	}
	return nil, fmt.Errorf("velero server deployment not found in namespace %q", namespace)
}

// getVeleroContainer returns the container named "velero" from the deployment,
// or the first container if no container is named "velero".
func getVeleroContainer(deployment *appsv1api.Deployment) *corev1api.Container {
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == "velero" {
			return &deployment.Spec.Template.Spec.Containers[i]
		}
	}
	if len(deployment.Spec.Template.Spec.Containers) > 0 {
		return &deployment.Spec.Template.Spec.Containers[0]
	}
	return nil
}

// GetNodeSelectorFromVeleroServer get the node selector from the Velero server deployment
func GetNodeSelectorFromVeleroServer(deployment *appsv1api.Deployment) map[string]string {
	return deployment.Spec.Template.Spec.NodeSelector
}

// GetTolerationsFromVeleroServer get the tolerations from the Velero server deployment
func GetTolerationsFromVeleroServer(deployment *appsv1api.Deployment) []corev1api.Toleration {
	return deployment.Spec.Template.Spec.Tolerations
}

// GetAffinityFromVeleroServer get the affinity from the Velero server deployment
func GetAffinityFromVeleroServer(deployment *appsv1api.Deployment) *corev1api.Affinity {
	return deployment.Spec.Template.Spec.Affinity
}

// GetEnvVarsFromVeleroServer get the environment variables from the Velero server deployment
func GetEnvVarsFromVeleroServer(deployment *appsv1api.Deployment) []corev1api.EnvVar {
	if c := getVeleroContainer(deployment); c != nil {
		return c.Env
	}
	return nil
}

// GetEnvFromSourcesFromVeleroServer get the environment sources from the Velero server deployment
func GetEnvFromSourcesFromVeleroServer(deployment *appsv1api.Deployment) []corev1api.EnvFromSource {
	if c := getVeleroContainer(deployment); c != nil {
		return c.EnvFrom
	}
	return nil
}

// GetVolumeMountsFromVeleroServer get the volume mounts from the Velero server deployment
func GetVolumeMountsFromVeleroServer(deployment *appsv1api.Deployment) []corev1api.VolumeMount {
	if c := getVeleroContainer(deployment); c != nil {
		return c.VolumeMounts
	}
	return nil
}

// GetPodSecurityContextsFromVeleroServer get the pod security context from the Velero server deployment
func GetPodSecurityContextsFromVeleroServer(deployment *appsv1api.Deployment) *corev1api.PodSecurityContext {
	return deployment.Spec.Template.Spec.SecurityContext
}

// GetContainerSecurityContextsFromVeleroServer get the security context from the Velero server deployment
func GetContainerSecurityContextsFromVeleroServer(deployment *appsv1api.Deployment) *corev1api.SecurityContext {
	if c := getVeleroContainer(deployment); c != nil {
		return c.SecurityContext
	}
	return nil
}

// GetVolumesFromVeleroServer get the volumes from the Velero server deployment
func GetVolumesFromVeleroServer(deployment *appsv1api.Deployment) []corev1api.Volume {
	return deployment.Spec.Template.Spec.Volumes
}

// GetServiceAccountFromVeleroServer get the service account from the Velero server deployment
func GetServiceAccountFromVeleroServer(deployment *appsv1api.Deployment) string {
	return deployment.Spec.Template.Spec.ServiceAccountName
}

// GetImagePullSecretsFromVeleroServer get the image pull secrets from the Velero server deployment
func GetImagePullSecretsFromVeleroServer(deployment *appsv1api.Deployment) []corev1api.LocalObjectReference {
	return deployment.Spec.Template.Spec.ImagePullSecrets
}

// GetVeleroServerImage get the image of the Velero server deployment
func GetVeleroServerImage(deployment *appsv1api.Deployment) string {
	if c := getVeleroContainer(deployment); c != nil {
		return c.Image
	}
	return ""
}

// GetVeleroServerLables get the labels of the Velero server deployment
func GetVeleroServerLables(deployment *appsv1api.Deployment) map[string]string {
	return deployment.Spec.Template.Labels
}

// GetVeleroServerAnnotations get the annotations of the Velero server deployment
func GetVeleroServerAnnotations(deployment *appsv1api.Deployment) map[string]string {
	return deployment.Spec.Template.Annotations
}

// GetVeleroServerLabelValue returns the value of specified label of Velero server deployment
func GetVeleroServerLabelValue(deployment *appsv1api.Deployment, key string) string {
	if deployment.Spec.Template.Labels == nil {
		return ""
	}

	return deployment.Spec.Template.Labels[key]
}

// GetVeleroServerAnnotationValue returns the value of specified annotation of Velero server deployment
func GetVeleroServerAnnotationValue(deployment *appsv1api.Deployment, key string) string {
	if deployment.Spec.Template.Annotations == nil {
		return ""
	}

	return deployment.Spec.Template.Annotations[key]
}

func BSLIsAvailable(bsl velerov1api.BackupStorageLocation) bool {
	return bsl.Status.Phase == velerov1api.BackupStorageLocationPhaseAvailable
}
