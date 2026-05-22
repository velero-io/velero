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
	"slices"

	"github.com/sirupsen/logrus"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	velerodiscovery "github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

func ClusterRoleBindingsForAction(clusterRoleBindingListers map[string]ClusterRoleBindingLister, discoveryHelper velerodiscovery.Helper) ([]ClusterRoleBinding, error) {
	// Look up the supported RBAC version
	var supportedAPI metav1.GroupVersionForDiscovery
	for _, ag := range discoveryHelper.APIGroups() {
		if ag.Name == rbacv1.GroupName {
			supportedAPI = ag.PreferredVersion
			break
		}
	}

	crbLister := clusterRoleBindingListers[supportedAPI.Version]

	// This should be safe because the List call will return a 0-item slice
	// if there's no matching API version.
	return crbLister.List()
}

func RelatedItemsForServiceAccount(objectMeta metav1.Object, clusterRoleBindings []ClusterRoleBinding, log logrus.FieldLogger) []velero.ResourceIdentifier {
	var (
		namespace = objectMeta.GetNamespace()
		name      = objectMeta.GetName()
		bindings  = sets.NewString()
		roles     = sets.NewString()
	)

	for _, crb := range clusterRoleBindings {
		if slices.Contains(crb.ServiceAccountSubjects(namespace), name) {
			log.Infof("Adding clusterrole %s and clusterrolebinding %s to relatedItems since serviceaccount %s/%s is a subject",
				crb.RoleRefName(), crb.Name(), namespace, name)

			bindings.Insert(crb.Name())
			roles.Insert(crb.RoleRefName())
		}
	}

	var relatedItems []velero.ResourceIdentifier
	for binding := range bindings {
		relatedItems = append(relatedItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.ClusterRoleBindings,
			Name:          binding,
		})
	}

	for role := range roles {
		relatedItems = append(relatedItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.ClusterRoles,
			Name:          role,
		})
	}

	return relatedItems
}
