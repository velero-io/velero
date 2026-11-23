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

package actionhelpers

import (
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"

	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
)

func RelatedItemsForPod(pod *corev1api.Pod, log logrus.FieldLogger) []velero.ResourceIdentifier {
	var additionalItems []velero.ResourceIdentifier
	if pod.Spec.PriorityClassName != "" {
		log.Infof("Adding priorityclass %s to additionalItems", pod.Spec.PriorityClassName)
		additionalItems = append(additionalItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.PriorityClasses,
			Name:          pod.Spec.PriorityClassName,
		})
	}

	if len(pod.Spec.Volumes) == 0 {
		log.Info("pod has no volumes")
	}

	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName != "" {
			log.Infof("Adding pvc %s to additionalItems", volume.PersistentVolumeClaim.ClaimName)

			additionalItems = append(additionalItems, velero.ResourceIdentifier{
				GroupResource: kuberesource.PersistentVolumeClaims,
				Namespace:     pod.Namespace,
				Name:          volume.PersistentVolumeClaim.ClaimName,
			})
		}
	}
	return additionalItems
}
