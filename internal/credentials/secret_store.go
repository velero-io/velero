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

package credentials

import (
	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// SecretStore defines operations for interacting with credentials
// that are stored in Secret.
type SecretStore interface {
	// Get returns the secret key defined by the given selector
	Get(selector *corev1api.SecretKeySelector) (string, error)
}

type namespacedSecretStore struct {
	client    kbclient.Client
	namespace string
}

// NewNamespacedSecretStore returns a SecretStore which can interact with credentials
// for the given namespace.
func NewNamespacedSecretStore(client kbclient.Client, namespace string) (SecretStore, error) {
	return &namespacedSecretStore{
		client:    client,
		namespace: namespace,
	}, nil
}

// Buffer returns the secret key defined by the given selector.
func (n *namespacedSecretStore) Get(selector *corev1api.SecretKeySelector) (string, error) {
	creds, err := kube.GetSecretKey(n.client, n.namespace, selector)
	if err != nil {
		return "", errors.Wrap(err, "unable to get key for secret")
	}

	return string(creds), nil
}
