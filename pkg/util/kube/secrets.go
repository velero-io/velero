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

package kube

import (
	"context"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSecret(client kbclient.Client, namespace, name string) (*corev1api.Secret, error) {
	secret := &corev1api.Secret{}
	if err := client.Get(context.TODO(), kbclient.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func GetSecretKey(client kbclient.Client, namespace string, selector *corev1api.SecretKeySelector) ([]byte, error) {
	secret, err := GetSecret(client, namespace, selector.Name)
	if err != nil {
		return nil, err
	}

	key, found := secret.Data[selector.Key]
	if !found {
		return nil, errors.Errorf("%q secret is missing data for key %q", selector.Name, selector.Key)
	}

	return key, nil
}
