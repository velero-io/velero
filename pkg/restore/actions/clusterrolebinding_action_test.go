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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/test"
)

func TestClusterRoleBindingActionAppliesTo(t *testing.T) {
	action := NewClusterRoleBindingAction(test.NewLogger())
	actual, err := action.AppliesTo()
	require.NoError(t, err)
	assert.Equal(t, velero.ResourceSelector{IncludedResources: []string{"clusterrolebindings"}}, actual)
}

func TestClusterRoleBindingActionExecute(t *testing.T) {
	tests := []struct {
		name             string
		namespaces       []string
		namespaceMapping map[string]string
		expected         []string
	}{
		{
			name:             "namespace mapping disabled",
			namespaces:       []string{"foo"},
			namespaceMapping: map[string]string{},
			expected:         []string{"foo"},
		},
		{
			name:             "namespace mapping enabled",
			namespaces:       []string{"foo"},
			namespaceMapping: map[string]string{"foo": "bar", "fizz": "buzz"},
			expected:         []string{"bar"},
		},
		{
			name:             "namespace mapping enabled, not included namespace remains unchanged",
			namespaces:       []string{"foo", "xyz"},
			namespaceMapping: map[string]string{"foo": "bar", "fizz": "buzz"},
			expected:         []string{"bar", "xyz"},
		},
		{
			name:             "namespace mapping enabled, not included namespace remains unchanged",
			namespaces:       []string{"foo", "xyz"},
			namespaceMapping: map[string]string{"a": "b", "c": "d"},
			expected:         []string{"foo", "xyz"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subjects := []rbacv1.Subject{}

			for _, ns := range tc.namespaces {
				subjects = append(subjects, rbacv1.Subject{
					Namespace: ns,
				})
			}

			clusterRoleBinding := rbacv1.ClusterRoleBinding{
				Subjects: subjects,
			}

			roleBindingUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&clusterRoleBinding)
			require.NoError(t, err)

			action := NewClusterRoleBindingAction(test.NewLogger())
			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: roleBindingUnstructured},
				ItemFromBackup: &unstructured.Unstructured{Object: roleBindingUnstructured},
				Restore: &api.Restore{
					Spec: api.RestoreSpec{
						NamespaceMapping: tc.namespaceMapping,
					},
				},
			})
			require.NoError(t, err)

			var resClusterRoleBinding *rbacv1.ClusterRoleBinding
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &resClusterRoleBinding)
			require.NoError(t, err)

			actual := []string{}
			for _, subject := range resClusterRoleBinding.Subjects {
				actual = append(actual, subject.Namespace)
			}

			sort.Strings(tc.expected)
			sort.Strings(actual)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
