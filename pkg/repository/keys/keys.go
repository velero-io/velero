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

//nolint:gosec // Internal call. No need to check.
package keys

import (
	"context"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/vmware-tanzu/velero/pkg/builder"
)

const (
	credentialsSecretName = "velero-repo-credentials"
	credentialsKey        = "repository-password"

	encryptionKey = "static-passw0rd"
)

func EnsureCommonRepositoryKey(secretClient corev1client.SecretsGetter, namespace string) error {
	_, err := secretClient.Secrets(namespace).Get(context.TODO(), credentialsSecretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.WithStack(err)
	}
	if err == nil {
		return nil
	}

	// if we got here, we got an IsNotFound error, so we need to create the key

	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      credentialsSecretName,
		},
		Type: corev1api.SecretTypeOpaque,
		Data: map[string][]byte{
			credentialsKey: []byte(encryptionKey),
		},
	}

	if _, err = secretClient.Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return errors.Wrapf(err, "error creating %s secret", credentialsSecretName)
	}

	return nil
}

// RepoKeySelector returns the SecretKeySelector which can be used to fetch
// the backup repository key.
func RepoKeySelector() *corev1api.SecretKeySelector {
	// For now, all backup repos share the same key so we don't need the repoName to fetch it.
	// When we move to full-backup encryption, we'll likely have a separate key per backup repo
	// (all within the Velero server's namespace) so RepoKeySelector will need to select the key
	// for that repo.
	return builder.ForSecretKeySelector(credentialsSecretName, credentialsKey).Result()
}
