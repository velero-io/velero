/*
Copyright 2019 the Velero contributors.

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
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

type AddPVCFromPodAction struct {
	logger logrus.FieldLogger
}

func NewAddPVCFromPodAction(logger logrus.FieldLogger) *AddPVCFromPodAction {
	return &AddPVCFromPodAction{logger: logger}
}

func (a *AddPVCFromPodAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"pods"},
	}, nil
}

func (a *AddPVCFromPodAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	a.logger.Info("Executing AddPVCFromPodAction")

	var pod corev1api.Pod
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), &pod); err != nil {
		return nil, errors.Wrap(err, "unable to convert unstructured item to pod")
	}

	var additionalItems []velero.ResourceIdentifier

	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim == nil {
			continue
		}

		a.logger.Infof("Adding PVC %s/%s as an additional item to restore", pod.Namespace, volume.PersistentVolumeClaim.ClaimName)
		additionalItems = append(additionalItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.PersistentVolumeClaims,
			Namespace:     pod.Namespace,
			Name:          volume.PersistentVolumeClaim.ClaimName,
		})
	}

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem:     input.Item,
		AdditionalItems: additionalItems,
	}, nil
}
