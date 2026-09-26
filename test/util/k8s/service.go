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
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	waitutil "k8s.io/apimachinery/pkg/util/wait"
)

func CreateService(ctx context.Context, client TestClient, namespace string,
	service string, labels map[string]string, serviceSpec *corev1api.ServiceSpec) error {
	se := &corev1api.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      service,
			Labels:    labels,
			Namespace: namespace,
		},
		Spec: *serviceSpec,
	}
	_, err = client.ClientGo.CoreV1().Services(namespace).Create(ctx, se, metav1.CreateOptions{})

	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func GetService(ctx context.Context, client TestClient, namespace string, service string) (*corev1api.Service, error) {
	return client.ClientGo.CoreV1().Services(namespace).Get(ctx, service, metav1.GetOptions{})
}

func WaitForServiceDelete(client TestClient, ns, name string, deleteFirst bool) error {
	if deleteFirst {
		if err := client.ClientGo.CoreV1().Services(ns).Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to delete  secret in namespace %q", ns))
		}
	}
	return waitutil.PollImmediateInfinite(5*time.Second,
		func() (bool, error) {
			if _, err := client.ClientGo.CoreV1().Services(ns).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				return false, err
			}
			logrus.Debugf("service %q in namespace %q is still being deleted...", name, ns)
			return false, nil
		})
}
