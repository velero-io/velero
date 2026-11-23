/*
Copyright 2018, 2019 the Velero contributors.

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
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/test"
)

func TestServiceAccountActionAppliesTo(t *testing.T) {
	action := NewServiceAccountAction(test.NewLogger())
	actual, err := action.AppliesTo()
	require.NoError(t, err)
	assert.Equal(t, velero.ResourceSelector{IncludedResources: []string{"serviceaccounts"}}, actual)
}

func TestServiceAccountActionExecute(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []string
		expected []string
	}{
		{
			name:     "no secrets",
			secrets:  []string{},
			expected: []string{},
		},
		{
			name:     "no match",
			secrets:  []string{"a", "bar-TOKN-nomatch", "baz"},
			expected: []string{"a", "bar-TOKN-nomatch", "baz"},
		},
		{
			name:     "match - first",
			secrets:  []string{"bar-token-a1b2c", "a", "baz"},
			expected: []string{"a", "baz"},
		},
		{
			name:     "match - middle",
			secrets:  []string{"a", "bar-token-a1b2c", "baz"},
			expected: []string{"a", "baz"},
		},
		{
			name:     "match - end",
			secrets:  []string{"a", "baz", "bar-token-a1b2c"},
			expected: []string{"a", "baz"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sa := corev1api.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "bar",
				},
			}

			for _, secret := range tc.secrets {
				sa.Secrets = append(sa.Secrets, corev1api.ObjectReference{
					Name: secret,
				})
			}

			saUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&sa)
			require.NoError(t, err)

			action := NewServiceAccountAction(test.NewLogger())
			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: saUnstructured},
				ItemFromBackup: &unstructured.Unstructured{Object: saUnstructured},
				Restore:        nil,
			})
			require.NoError(t, err)

			var resSA *corev1api.ServiceAccount
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &resSA)
			require.NoError(t, err)

			actual := []string{}
			for _, secret := range resSA.Secrets {
				actual = append(actual, secret.Name)
			}

			sort.Strings(tc.expected)
			sort.Strings(actual)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
