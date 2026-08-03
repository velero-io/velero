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

package keys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/vmware-tanzu/velero/pkg/builder"
)

const (
	// credentialsSecretName is the legacy shared secret name kept for backward compatibility.
	credentialsSecretName = "velero-repo-credentials"
	credentialsKey        = "repository-password"

	// bslCredentialsSecretPrefix is the prefix for per-BSL encryption key secrets.
	// Each BSL gets its own secret named "velero-repo-credentials-<bsl-name>".
	bslCredentialsSecretPrefix = "velero-repo-credentials-"

	// generatedKeyLength is the number of random bytes used to generate a per-BSL password.
	// 32 bytes = 256 bits of entropy, rendered as 64 hex characters.
	generatedKeyLength = 32
)

// generateSecurePassword generates a cryptographically random password.
var generateSecurePassword = func() (string, error) {
	b := make([]byte, generatedKeyLength)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrap(err, "error generating random password")
	}
	return hex.EncodeToString(b), nil
}

// EnsureCommonRepositoryKey ensures the legacy shared repository key secret exists.
// This is kept for backward compatibility with existing installations.
func EnsureCommonRepositoryKey(secretClient corev1client.SecretsGetter, namespace string) error {
	_, err := secretClient.Secrets(namespace).Get(context.TODO(), credentialsSecretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.WithStack(err)
	}
	if err == nil {
		return nil
	}

	// if we got here, we got an IsNotFound error, so we need to create the key
	// Generate a cryptographically random password instead of using a static one
	password, err := generateSecurePassword()
	if err != nil {
		return errors.Wrap(err, "error generating repository password")
	}

	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      credentialsSecretName,
		},
		Type: corev1api.SecretTypeOpaque,
		Data: map[string][]byte{
			credentialsKey: []byte(password),
		},
	}

	if _, err = secretClient.Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return errors.Wrapf(err, "error creating %s secret", credentialsSecretName)
	}

	return nil
}

// EnsureBSLRepositoryKey ensures a per-BSL encryption key secret exists.
// Each BSL gets its own unique, cryptographically random encryption password
// stored in a separate Kubernetes Secret. This provides isolation so that
// compromising one BSL's key does not expose backups in other BSLs.
// If the per-BSL secret does not exist, it falls back to the legacy shared key
// for backward compatibility with existing repositories.
func EnsureBSLRepositoryKey(secretClient corev1client.SecretsGetter, namespace, bslName string) error {
	secretName := bslSecretName(bslName)

	_, err := secretClient.Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.WithStack(err)
	}
	if err == nil {
		return nil
	}

	// Generate a unique cryptographically random password for this BSL
	password, err := generateSecurePassword()
	if err != nil {
		return errors.Wrap(err, "error generating BSL repository password")
	}

	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
			Labels: map[string]string{
				"velero.io/bsl-name":    bslName,
				"velero.io/secret-type": "bsl-repo-credentials",
			},
		},
		Type: corev1api.SecretTypeOpaque,
		Data: map[string][]byte{
			credentialsKey: []byte(password),
		},
	}

	if _, err = secretClient.Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
		return errors.Wrapf(err, "error creating BSL secret %s", secretName)
	}

	return nil
}

// RepoKeySelector returns the SecretKeySelector for the legacy shared key.
// Deprecated: Use BSLRepoKeySelector instead for per-BSL key isolation.
func RepoKeySelector() *corev1api.SecretKeySelector {
	return builder.ForSecretKeySelector(credentialsSecretName, credentialsKey).Result()
}

// BSLRepoKeySelector returns the SecretKeySelector for a BSL-specific encryption key.
// If a per-BSL secret exists, it returns a selector for that secret.
// Otherwise, it falls back to the legacy shared key for backward compatibility.
func BSLRepoKeySelector(secretClient corev1client.SecretsGetter, namespace, bslName string) *corev1api.SecretKeySelector {
	if bslName != "" {
		secretName := bslSecretName(bslName)
		_, err := secretClient.Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err == nil {
			return builder.ForSecretKeySelector(secretName, credentialsKey).Result()
		}
	}
	// Fall back to the legacy shared key
	return builder.ForSecretKeySelector(credentialsSecretName, credentialsKey).Result()
}

// bslSecretName returns the Kubernetes Secret name for a given BSL.
func bslSecretName(bslName string) string {
	return fmt.Sprintf("%s%s", bslCredentialsSecretPrefix, bslName)
}

// GetBSLSecretName is exported for testing purposes.
func GetBSLSecretName(bslName string) string {
	return bslSecretName(bslName)
}
