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
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/actionhelpers"
)

// PodAction implements ItemBlockAction.
type PodAction struct {
	log logrus.FieldLogger
}

// NewPodAction creates a new ItemBlockAction for pods.
func NewPodAction(logger logrus.FieldLogger) *PodAction {
	return &PodAction{log: logger}
}

// AppliesTo returns a ResourceSelector that applies only to pods.
func (a *PodAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"pods"},
	}, nil
}

// GetRelatedItems scans the pod's spec.volumes for persistentVolumeClaim volumes and returns a
// ResourceIdentifier list containing references to all of the persistentVolumeClaim volumes used by
// the pod. This ensures that when a pod is backed up, all referenced PVCs are backed up along with the pod.
func (a *PodAction) GetRelatedItems(item runtime.Unstructured, backup *v1.Backup) ([]velero.ResourceIdentifier, error) {
	a.log.Info("Executing pod ItemBlockAction")
	defer a.log.Info("Done executing pod ItemBlockAction")

	pod := new(corev1api.Pod)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.UnstructuredContent(), pod); err != nil {
		return nil, errors.WithStack(err)
	}
	return actionhelpers.RelatedItemsForPod(pod, a.log), nil
}

func (a *PodAction) Name() string {
	return "PodItemBlockAction"
}
