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

package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateRBACWithBindingSA(ctx context.Context, client TestClient, namespace string, serviceaccount string, clusterrole string, clusterrolebinding string) error {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterrole,
		},
	}

	_, err = client.ClientGo.RbacV1().ClusterRoles().Create(context.TODO(), role, metav1.CreateOptions{})

	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	//creating role binding and binding it to the test service account
	rolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterrolebinding,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceaccount,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: clusterrole,
		},
	}

	_, err = client.ClientGo.RbacV1().ClusterRoleBindings().Create(ctx, rolebinding, metav1.CreateOptions{})

	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func GetClusterRole(ctx context.Context, client TestClient, role string) (*rbacv1.ClusterRole, error) {
	return client.ClientGo.RbacV1().ClusterRoles().Get(ctx, role, metav1.GetOptions{})
}

func GetClusterRoleBinding(ctx context.Context, client TestClient, rolebinding string) (*rbacv1.ClusterRoleBinding, error) {
	return client.ClientGo.RbacV1().ClusterRoleBindings().Get(ctx, rolebinding, metav1.GetOptions{})
}

func CleanupClusterRole(ctx context.Context, client TestClient, CaseBaseName string) error {
	clusterroles, err := client.ClientGo.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not retrieve clusterroles")
	}

	for _, checkClusterRole := range clusterroles.Items {
		if strings.HasPrefix(checkClusterRole.Name, "clusterrole-"+CaseBaseName) {
			fmt.Printf("Cleaning up clusterrole %s\n", checkClusterRole.Name)
			err = client.ClientGo.RbacV1().ClusterRoles().Delete(ctx, checkClusterRole.Name, metav1.DeleteOptions{})
			if err != nil {
				return errors.Wrapf(err, "Could not delete clusterrole %s", checkClusterRole.Name)
			}
		}
	}
	return nil
}

func CleanupClusterRoleBinding(ctx context.Context, client TestClient, CaseBaseName string) error {
	clusterrolebindings, err := client.ClientGo.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not retrieve clusterrolebindings")
	}

	for _, checkClusterRoleBinding := range clusterrolebindings.Items {
		if strings.HasPrefix(checkClusterRoleBinding.Name, "clusterrolebinding-"+CaseBaseName) {
			fmt.Printf("Cleaning up clusterrolebinding %s\n", checkClusterRoleBinding.Name)
			err = client.ClientGo.RbacV1().ClusterRoleBindings().Delete(ctx, checkClusterRoleBinding.Name, metav1.DeleteOptions{})
			if err != nil {
				return errors.Wrapf(err, "Could not delete clusterrolebinding %s", checkClusterRoleBinding.Name)
			}
		}
	}
	return nil
}
