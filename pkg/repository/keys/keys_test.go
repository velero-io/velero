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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRepoKeySelector(t *testing.T) {
	selector := RepoKeySelector()

	require.Equal(t, credentialsSecretName, selector.Name)
	require.Equal(t, credentialsKey, selector.Key)
}

func TestEnsureCommonRepositoryKey_GeneratesRandomPassword(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"

	err := EnsureCommonRepositoryKey(client.CoreV1(), namespace)
	require.NoError(t, err)

	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), credentialsSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	password := string(secret.Data[credentialsKey])
	// Should be a 64-char hex string (32 random bytes)
	assert.Len(t, password, 64, "generated password should be 64 hex characters")
	// Should NOT be the old static password
	assert.NotEqual(t, "static-passw0rd", password, "password should not be the old hardcoded value")
}

func TestEnsureCommonRepositoryKey_PreservesExisting(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"

	// Pre-create a secret with a custom password
	customPassword := "my-custom-password"
	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      credentialsSecretName,
		},
		Type: corev1api.SecretTypeOpaque,
		Data: map[string][]byte{
			credentialsKey: []byte(customPassword),
		},
	}
	_, err := client.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	// EnsureCommonRepositoryKey should not overwrite it
	err = EnsureCommonRepositoryKey(client.CoreV1(), namespace)
	require.NoError(t, err)

	got, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), credentialsSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, customPassword, string(got.Data[credentialsKey]))
}

func TestEnsureBSLRepositoryKey_CreatesPerBSLSecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"
	bslName := "my-bsl"

	err := EnsureBSLRepositoryKey(client.CoreV1(), namespace, bslName)
	require.NoError(t, err)

	expectedSecretName := bslCredentialsSecretPrefix + bslName
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), expectedSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	password := string(secret.Data[credentialsKey])
	assert.Len(t, password, 64, "generated BSL password should be 64 hex characters")
	assert.Equal(t, bslName, secret.Labels["velero.io/bsl-name"])
	assert.Equal(t, "bsl-repo-credentials", secret.Labels["velero.io/secret-type"])
}

func TestEnsureBSLRepositoryKey_PreservesExisting(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"
	bslName := "my-bsl"

	// Pre-create
	secretName := bslCredentialsSecretPrefix + bslName
	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
		},
		Data: map[string][]byte{
			credentialsKey: []byte("existing-password"),
		},
	}
	_, err := client.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	err = EnsureBSLRepositoryKey(client.CoreV1(), namespace, bslName)
	require.NoError(t, err)

	got, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "existing-password", string(got.Data[credentialsKey]))
}

func TestBSLRepoKeySelector_UsesBSLSecret(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"
	bslName := "my-bsl"

	// Create per-BSL secret
	secretName := bslCredentialsSecretPrefix + bslName
	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      secretName,
		},
		Data: map[string][]byte{
			credentialsKey: []byte("bsl-specific-password"),
		},
	}
	_, err := client.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	selector := BSLRepoKeySelector(client.CoreV1(), namespace, bslName)
	assert.Equal(t, secretName, selector.Name)
	assert.Equal(t, credentialsKey, selector.Key)
}

func TestBSLRepoKeySelector_FallsBackToSharedKey(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"
	bslName := "nonexistent-bsl"

	// No per-BSL secret exists, should fall back to legacy shared key
	selector := BSLRepoKeySelector(client.CoreV1(), namespace, bslName)
	assert.Equal(t, credentialsSecretName, selector.Name)
	assert.Equal(t, credentialsKey, selector.Key)
}

func TestBSLRepoKeySelector_EmptyBSLName(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"

	// Empty BSL name should fall back to legacy shared key
	selector := BSLRepoKeySelector(client.CoreV1(), namespace, "")
	assert.Equal(t, credentialsSecretName, selector.Name)
	assert.Equal(t, credentialsKey, selector.Key)
}

func TestMultipleBSLs_GetUniquePasswords(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "velero"

	err := EnsureBSLRepositoryKey(client.CoreV1(), namespace, "bsl-1")
	require.NoError(t, err)
	err = EnsureBSLRepositoryKey(client.CoreV1(), namespace, "bsl-2")
	require.NoError(t, err)

	secret1, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), bslCredentialsSecretPrefix+"bsl-1", metav1.GetOptions{})
	require.NoError(t, err)
	secret2, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), bslCredentialsSecretPrefix+"bsl-2", metav1.GetOptions{})
	require.NoError(t, err)

	password1 := string(secret1.Data[credentialsKey])
	password2 := string(secret2.Data[credentialsKey])

	assert.NotEqual(t, password1, password2, "different BSLs should get different passwords")
}

func TestGetBSLSecretName(t *testing.T) {
	assert.Equal(t, "velero-repo-credentials-my-bsl", GetBSLSecretName("my-bsl"))
	assert.Equal(t, "velero-repo-credentials-default", GetBSLSecretName("default"))
}
