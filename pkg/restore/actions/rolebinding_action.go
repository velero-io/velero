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
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// RoleBindingAction handle namespace remappings for role bindings
type RoleBindingAction struct {
	logger logrus.FieldLogger
}

func NewRoleBindingAction(logger logrus.FieldLogger) *RoleBindingAction {
	return &RoleBindingAction{logger: logger}
}

func (a *RoleBindingAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"rolebindings"},
	}, nil
}

func (a *RoleBindingAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	namespaceMapping := input.Restore.Spec.NamespaceMapping
	if len(namespaceMapping) == 0 {
		return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: input.Item.UnstructuredContent()}), nil
	}

	roleBinding := new(rbacv1.RoleBinding)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), roleBinding); err != nil {
		return nil, errors.WithStack(err)
	}

	for i, subject := range roleBinding.Subjects {
		if newNamespace, ok := namespaceMapping[subject.Namespace]; ok {
			roleBinding.Subjects[i].Namespace = newNamespace
		}
	}

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(roleBinding)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: res}), nil
}
