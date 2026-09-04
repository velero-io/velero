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
	"fmt"
	"time"

	"context"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	waitutil "k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
)

func CreateConfigMap(c clientset.Interface, ns, name string, labels, data map[string]string) (*corev1api.ConfigMap, error) {
	cm := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Data: data,
	}
	return c.CoreV1().ConfigMaps(ns).Create(context.TODO(), cm, metav1.CreateOptions{})
}

func CreateConfigMapFromYAMLData(c clientset.Interface, yamlData, cmName, namespace string) error {
	cmData := make(map[string]string)
	cmData[cmName] = yamlData
	cm := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: namespace,
		},
		Data: cmData,
	}
	_, err := c.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
	return err
}

// WaitForConfigMapComplete uses c to wait for completions to complete for the Job jobName in namespace ns.
func WaitForConfigMapComplete(c clientset.Interface, ns, cmName string) error {
	return wait.Poll(PollInterval, PollTimeout, func() (bool, error) {
		_, err := c.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func GetConfigMap(c clientset.Interface, ns, secretName string) (*corev1api.ConfigMap, error) {
	return c.CoreV1().ConfigMaps(ns).Get(context.TODO(), secretName, metav1.GetOptions{})
}

func DeleteConfigMap(c clientset.Interface, ns, name string) error {
	if err := c.CoreV1().ConfigMaps(ns).Delete(context.TODO(), name, metav1.DeleteOptions{}); err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to delete  ConfigMap in namespace %q", ns))
	}
	return nil
}

func WaitForConfigmapDelete(c clientset.Interface, ns, name string) error {
	if err := DeleteConfigMap(c, ns, name); err != nil {
		return err
	}

	return waitutil.PollImmediateInfinite(5*time.Second,
		func() (bool, error) {
			if _, err := c.CoreV1().ConfigMaps(ns).Get(context.TODO(), name, metav1.GetOptions{}); err != nil {
				if apierrors.IsNotFound(err) {
					return true, nil
				}
				return false, err
			}
			logrus.Debugf("configmap %q in namespace %q is still being deleted...", name, ns)
			return false, nil
		})
}
