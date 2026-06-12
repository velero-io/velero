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

package actions

import (
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/internal/hook"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// InitRestoreHookPodAction is a RestoreItemAction plugin applicable to pods that runs
// restore hooks to add init containers to pods prior to them being restored.
type InitRestoreHookPodAction struct {
	logger logrus.FieldLogger
}

// NewInitRestoreHookPodAction returns a new InitRestoreHookPodAction.
func NewInitRestoreHookPodAction(logger logrus.FieldLogger) *InitRestoreHookPodAction {
	return &InitRestoreHookPodAction{logger: logger}
}

// AppliesTo implements the RestoreItemAction plugin interface method.
func (a *InitRestoreHookPodAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"pods"},
	}, nil
}

// Execute implements the RestoreItemAction plugin interface method.
func (a *InitRestoreHookPodAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	a.logger.Infof("Executing InitRestoreHookPodAction")
	// handle any init container restore hooks for the pod
	restoreHooks, err := hook.GetRestoreHooksFromSpec(&input.Restore.Spec.Hooks)
	nsMapping := input.Restore.Spec.NamespaceMapping
	if err != nil {
		return nil, errors.WithStack(err)
	}
	hookHandler := hook.InitContainerRestoreHookHandler{}
	postHooksItem, err := hookHandler.HandleRestoreHooks(a.logger, kuberesource.Pods, input.Item, restoreHooks, nsMapping)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	a.logger.Infof("Returning from InitRestoreHookPodAction")

	return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: postHooksItem.UnstructuredContent()}), nil
}
