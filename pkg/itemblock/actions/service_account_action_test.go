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
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacbeta "k8s.io/api/rbac/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util/actionhelpers"
)

func newV1ClusterRoleBindingList(rbacCRBList []rbacv1.ClusterRoleBinding) []actionhelpers.ClusterRoleBinding {
	var crbs []actionhelpers.ClusterRoleBinding
	for _, c := range rbacCRBList {
		crbs = append(crbs, actionhelpers.V1ClusterRoleBinding{Crb: c})
	}

	return crbs
}

func newV1beta1ClusterRoleBindingList(rbacCRBList []rbacbeta.ClusterRoleBinding) []actionhelpers.ClusterRoleBinding {
	var crbs []actionhelpers.ClusterRoleBinding
	for _, c := range rbacCRBList {
		crbs = append(crbs, actionhelpers.V1beta1ClusterRoleBinding{Crb: c})
	}

	return crbs
}

type FakeV1ClusterRoleBindingLister struct {
	v1crbs []rbacv1.ClusterRoleBinding
}

func (f FakeV1ClusterRoleBindingLister) List() ([]actionhelpers.ClusterRoleBinding, error) {
	var crbs []actionhelpers.ClusterRoleBinding
	for _, c := range f.v1crbs {
		crbs = append(crbs, actionhelpers.V1ClusterRoleBinding{Crb: c})
	}
	return crbs, nil
}

type FakeV1beta1ClusterRoleBindingLister struct {
	v1beta1crbs []rbacbeta.ClusterRoleBinding
}

func (f FakeV1beta1ClusterRoleBindingLister) List() ([]actionhelpers.ClusterRoleBinding, error) {
	var crbs []actionhelpers.ClusterRoleBinding
	for _, c := range f.v1beta1crbs {
		crbs = append(crbs, actionhelpers.V1beta1ClusterRoleBinding{Crb: c})
	}
	return crbs, nil
}

func TestServiceAccountActionAppliesTo(t *testing.T) {
	// Instantiating the struct directly since using
	// NewServiceAccountAction requires a full Kubernetes clientset
	a := &ServiceAccountAction{}

	actual, err := a.AppliesTo()
	require.NoError(t, err)

	expected := velero.ResourceSelector{
		IncludedResources: []string{"serviceaccounts"},
	}
	assert.Equal(t, expected, actual)
}

func TestNewServiceAccountAction(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		expectedCRBs []actionhelpers.ClusterRoleBinding
	}{
		{
			name:    "rbac v1 API instantiates an saAction",
			version: rbacv1.SchemeGroupVersion.Version,
			expectedCRBs: []actionhelpers.ClusterRoleBinding{
				actionhelpers.V1ClusterRoleBinding{
					Crb: rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "v1crb-1",
						},
					},
				},
				actionhelpers.V1ClusterRoleBinding{
					Crb: rbacv1.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "v1crb-2",
						},
					},
				},
			},
		},
		{
			name:    "rbac v1beta1 API instantiates an saAction",
			version: rbacbeta.SchemeGroupVersion.Version,
			expectedCRBs: []actionhelpers.ClusterRoleBinding{
				actionhelpers.V1beta1ClusterRoleBinding{
					Crb: rbacbeta.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "v1beta1crb-1",
						},
					},
				},
				actionhelpers.V1beta1ClusterRoleBinding{
					Crb: rbacbeta.ClusterRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "v1beta1crb-2",
						},
					},
				},
			},
		},
		{
			name:         "no RBAC API instantiates an saAction with empty slice",
			version:      "",
			expectedCRBs: []actionhelpers.ClusterRoleBinding{},
		},
	}
	// Set up all of our fakes outside the test loop
	discoveryHelper := velerotest.FakeDiscoveryHelper{}
	logger := velerotest.NewLogger()

	v1crbs := []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "v1crb-1",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "v1crb-2",
			},
		},
	}

	v1beta1crbs := []rbacbeta.ClusterRoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "v1beta1crb-1",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "v1beta1crb-2",
			},
		},
	}

	clusterRoleBindingListers := map[string]actionhelpers.ClusterRoleBindingLister{
		rbacv1.SchemeGroupVersion.Version:   FakeV1ClusterRoleBindingLister{v1crbs: v1crbs},
		rbacbeta.SchemeGroupVersion.Version: FakeV1beta1ClusterRoleBindingLister{v1beta1crbs: v1beta1crbs},
		"":                                  actionhelpers.NoopClusterRoleBindingLister{},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// We only care about the preferred version, nothing else in the list
			discoveryHelper.APIGroupsList = []metav1.APIGroup{
				{
					Name: rbacv1.GroupName,
					PreferredVersion: metav1.GroupVersionForDiscovery{
						Version: test.version,
					},
				},
			}
			action, err := NewServiceAccountAction(logger, clusterRoleBindingListers, &discoveryHelper)
			require.NoError(t, err)
			assert.Equal(t, test.expectedCRBs, action.clusterRoleBindings)
		})
	}
}

func TestServiceAccountActionExecute(t *testing.T) {
	tests := []struct {
		name                    string
		serviceAccount          runtime.Unstructured
		crbs                    []rbacv1.ClusterRoleBinding
		expectedAdditionalItems []velero.ResourceIdentifier
	}{
		{
			name: "no crbs",
			serviceAccount: velerotest.UnstructuredOrDie(`
			{
				"apiVersion": "v1",
				"kind": "ServiceAccount",
				"metadata": {
					"namespace": "velero",
					"name": "velero"
				}
			}
			`),
			crbs:                    nil,
			expectedAdditionalItems: nil,
		},
		{
			name: "no matching crbs",
			serviceAccount: velerotest.UnstructuredOrDie(`
			{
				"apiVersion": "v1",
				"kind": "ServiceAccount",
				"metadata": {
					"namespace": "velero",
					"name": "velero"
				}
			}
			`),
			crbs: []rbacv1.ClusterRoleBinding{
				{
					Subjects: []rbacv1.Subject{
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
						{
							Kind:      "non-matching-kind",
							Namespace: "velero",
							Name:      "velero",
						},
						{
							Kind:      rbacv1.ServiceAccountKind,
							Namespace: "non-matching-ns",
							Name:      "velero",
						},
						{
							Kind:      rbacv1.ServiceAccountKind,
							Namespace: "velero",
							Name:      "non-matching-name",
						},
					},
					RoleRef: rbacv1.RoleRef{
						Name: "role",
					},
				},
			},
			expectedAdditionalItems: nil,
		},
		{
			name: "some matching crbs",
			serviceAccount: velerotest.UnstructuredOrDie(`
			{
				"apiVersion": "v1",
				"kind": "ServiceAccount",
				"metadata": {
					"namespace": "velero",
					"name": "velero"
				}
			}
			`),
			crbs: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-1",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
					},
					RoleRef: rbacv1.RoleRef{
						Name: "role-1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-2",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
						{
							Kind:      rbacv1.ServiceAccountKind,
							Namespace: "velero",
							Name:      "velero",
						},
					},
					RoleRef: rbacv1.RoleRef{
						Name: "role-2",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-3",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      rbacv1.ServiceAccountKind,
							Namespace: "velero",
							Name:      "velero",
						},
					},
					RoleRef: rbacv1.RoleRef{
						Name: "role-3",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-4",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      rbacv1.ServiceAccountKind,
							Namespace: "velero",
							Name:      "velero",
						},
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
					},
					RoleRef: rbacv1.RoleRef{
						Name: "role-4",
					},
				},
			},
			expectedAdditionalItems: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.ClusterRoleBindings,
					Name:          "crb-2",
				},
				{
					GroupResource: kuberesource.ClusterRoleBindings,
					Name:          "crb-3",
				},
				{
					GroupResource: kuberesource.ClusterRoleBindings,
					Name:          "crb-4",
				},
				{
					GroupResource: kuberesource.ClusterRoles,
					Name:          "role-2",
				},
				{
					GroupResource: kuberesource.ClusterRoles,
					Name:          "role-3",
				},
				{
					GroupResource: kuberesource.ClusterRoles,
					Name:          "role-4",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create the action struct directly so we don't need to mock a clientset
			action := &ServiceAccountAction{
				log:                 velerotest.NewLogger(),
				clusterRoleBindings: newV1ClusterRoleBindingList(test.crbs),
			}

			additional, err := action.GetRelatedItems(test.serviceAccount, nil)

			require.NoError(t, err)

			// ensure slices are ordered for valid comparison
			sort.Slice(test.expectedAdditionalItems, func(i, j int) bool {
				return fmt.Sprintf("%s.%s", test.expectedAdditionalItems[i].GroupResource.String(), test.expectedAdditionalItems[i].Name) <
					fmt.Sprintf("%s.%s", test.expectedAdditionalItems[j].GroupResource.String(), test.expectedAdditionalItems[j].Name)
			})

			sort.Slice(additional, func(i, j int) bool {
				return fmt.Sprintf("%s.%s", additional[i].GroupResource.String(), additional[i].Name) <
					fmt.Sprintf("%s.%s", additional[j].GroupResource.String(), additional[j].Name)
			})

			assert.Equal(t, test.expectedAdditionalItems, additional)
		})
	}
}

func TestServiceAccountActionExecuteOnBeta1(t *testing.T) {
	tests := []struct {
		name                    string
		serviceAccount          runtime.Unstructured
		crbs                    []rbacbeta.ClusterRoleBinding
		expectedAdditionalItems []velero.ResourceIdentifier
	}{
		{
			name: "no crbs",
			serviceAccount: velerotest.UnstructuredOrDie(`
			{
				"apiVersion": "v1",
				"kind": "ServiceAccount",
				"metadata": {
					"namespace": "velero",
					"name": "velero"
				}
			}
			`),
			crbs:                    nil,
			expectedAdditionalItems: nil,
		},
		{
			name: "no matching crbs",
			serviceAccount: velerotest.UnstructuredOrDie(`
			{
				"apiVersion": "v1",
				"kind": "ServiceAccount",
				"metadata": {
					"namespace": "velero",
					"name": "velero"
				}
			}
			`),
			crbs: []rbacbeta.ClusterRoleBinding{
				{
					Subjects: []rbacbeta.Subject{
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
						{
							Kind:      "non-matching-kind",
							Namespace: "velero",
							Name:      "velero",
						},
						{
							Kind:      rbacbeta.ServiceAccountKind,
							Namespace: "non-matching-ns",
							Name:      "velero",
						},
						{
							Kind:      rbacbeta.ServiceAccountKind,
							Namespace: "velero",
							Name:      "non-matching-name",
						},
					},
					RoleRef: rbacbeta.RoleRef{
						Name: "role",
					},
				},
			},
			expectedAdditionalItems: nil,
		},
		{
			name: "some matching crbs",
			serviceAccount: velerotest.UnstructuredOrDie(`
			{
				"apiVersion": "v1",
				"kind": "ServiceAccount",
				"metadata": {
					"namespace": "velero",
					"name": "velero"
				}
			}
			`),
			crbs: []rbacbeta.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-1",
					},
					Subjects: []rbacbeta.Subject{
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
					},
					RoleRef: rbacbeta.RoleRef{
						Name: "role-1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-2",
					},
					Subjects: []rbacbeta.Subject{
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
						{
							Kind:      rbacbeta.ServiceAccountKind,
							Namespace: "velero",
							Name:      "velero",
						},
					},
					RoleRef: rbacbeta.RoleRef{
						Name: "role-2",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-3",
					},
					Subjects: []rbacbeta.Subject{
						{
							Kind:      rbacbeta.ServiceAccountKind,
							Namespace: "velero",
							Name:      "velero",
						},
					},
					RoleRef: rbacbeta.RoleRef{
						Name: "role-3",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "crb-4",
					},
					Subjects: []rbacbeta.Subject{
						{
							Kind:      rbacbeta.ServiceAccountKind,
							Namespace: "velero",
							Name:      "velero",
						},
						{
							Kind:      "non-matching-kind",
							Namespace: "non-matching-ns",
							Name:      "non-matching-name",
						},
					},
					RoleRef: rbacbeta.RoleRef{
						Name: "role-4",
					},
				},
			},
			expectedAdditionalItems: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.ClusterRoleBindings,
					Name:          "crb-2",
				},
				{
					GroupResource: kuberesource.ClusterRoleBindings,
					Name:          "crb-3",
				},
				{
					GroupResource: kuberesource.ClusterRoleBindings,
					Name:          "crb-4",
				},
				{
					GroupResource: kuberesource.ClusterRoles,
					Name:          "role-2",
				},
				{
					GroupResource: kuberesource.ClusterRoles,
					Name:          "role-3",
				},
				{
					GroupResource: kuberesource.ClusterRoles,
					Name:          "role-4",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create the action struct directly so we don't need to mock a clientset
			action := &ServiceAccountAction{
				log:                 velerotest.NewLogger(),
				clusterRoleBindings: newV1beta1ClusterRoleBindingList(test.crbs),
			}

			additional, err := action.GetRelatedItems(test.serviceAccount, nil)

			require.NoError(t, err)

			// ensure slices are ordered for valid comparison
			sort.Slice(test.expectedAdditionalItems, func(i, j int) bool {
				return fmt.Sprintf("%s.%s", test.expectedAdditionalItems[i].GroupResource.String(), test.expectedAdditionalItems[i].Name) <
					fmt.Sprintf("%s.%s", test.expectedAdditionalItems[j].GroupResource.String(), test.expectedAdditionalItems[j].Name)
			})

			sort.Slice(additional, func(i, j int) bool {
				return fmt.Sprintf("%s.%s", additional[i].GroupResource.String(), additional[i].Name) <
					fmt.Sprintf("%s.%s", additional[j].GroupResource.String(), additional[j].Name)
			})

			assert.Equal(t, test.expectedAdditionalItems, additional)
		})
	}
}
