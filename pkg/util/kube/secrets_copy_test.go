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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
)

func TestCopySecret(t *testing.T) {
	log := logrus.New()

	tests := []struct {
		name        string
		secretName  string
		sourceNS    string
		targetNS    string
		ownerName   string
		objects     []k8sruntime.Object
		expectErr   bool
		errContains string
	}{
		{
			name:       "successfully copies secret to target namespace",
			secretName: "ceph-csi-kms-token",
			sourceNS:   "app-ns",
			targetNS:   "velero",
			ownerName:  "du-123",
			objects: []k8sruntime.Object{
				&corev1api.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ceph-csi-kms-token", Namespace: "app-ns"},
					Data:       map[string][]byte{"token": []byte("vault-token-a")},
					Type:       corev1api.SecretTypeOpaque,
				},
			},
		},
		{
			name:        "returns error when source secret does not exist",
			secretName:  "missing-secret",
			sourceNS:    "app-ns",
			targetNS:    "velero",
			ownerName:   "du-123",
			objects:     []k8sruntime.Object{},
			expectErr:   true,
			errContains: "error getting secret",
		},
		{
			name:       "no-op when target already has secret with same data",
			secretName: "ceph-csi-kms-token",
			sourceNS:   "app-ns",
			targetNS:   "velero",
			ownerName:  "du-123",
			objects: []k8sruntime.Object{
				&corev1api.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ceph-csi-kms-token", Namespace: "app-ns"},
					Data:       map[string][]byte{"token": []byte("same-token")},
					Type:       corev1api.SecretTypeOpaque,
				},
				&corev1api.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ceph-csi-kms-token", Namespace: "velero"},
					Data:       map[string][]byte{"token": []byte("same-token")},
					Type:       corev1api.SecretTypeOpaque,
				},
			},
		},
		{
			name:       "returns collision error when target has secret with different data",
			secretName: "ceph-csi-kms-token",
			sourceNS:   "app-ns",
			targetNS:   "velero",
			ownerName:  "du-123",
			objects: []k8sruntime.Object{
				&corev1api.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ceph-csi-kms-token", Namespace: "app-ns"},
					Data:       map[string][]byte{"token": []byte("token-a")},
					Type:       corev1api.SecretTypeOpaque,
				},
				&corev1api.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "ceph-csi-kms-token", Namespace: "velero"},
					Data:       map[string][]byte{"token": []byte("token-b")},
					Type:       corev1api.SecretTypeOpaque,
				},
			},
			expectErr:   true,
			errContains: "secret collision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset(tt.objects...)

			err := CopySecret(context.Background(), fakeClient.CoreV1(),
				tt.secretName, tt.sourceNS, tt.targetNS, tt.ownerName, log)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)

			copied, getErr := fakeClient.CoreV1().Secrets(tt.targetNS).Get(
				context.Background(), tt.secretName, metav1.GetOptions{})
			require.NoError(t, getErr)
			assert.NotNil(t, copied)
		})
	}
}

func TestDeleteSecretIfAny(t *testing.T) {
	log := logrus.New()

	t.Run("deletes existing secret", func(t *testing.T) {
		secret := &corev1api.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "velero"},
		}
		fakeClient := fake.NewSimpleClientset(secret)

		DeleteSecretIfAny(context.Background(), fakeClient.CoreV1(), "test-secret", "velero", log)

		_, err := fakeClient.CoreV1().Secrets("velero").Get(
			context.Background(), "test-secret", metav1.GetOptions{})
		assert.True(t, err != nil)
	})

	t.Run("no error when secret does not exist", func(t *testing.T) {
		fakeClient := fake.NewSimpleClientset()
		DeleteSecretIfAny(context.Background(), fakeClient.CoreV1(), "missing", "velero", log)
	})
}

func TestDeleteSecretsWithLabel(t *testing.T) {
	log := logrus.New()

	fakeClient := fake.NewSimpleClientset(
		&corev1api.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "secret-1", Namespace: "velero",
				Labels: map[string]string{BackupPVCSecretLabel: "du-123"},
			},
		},
		&corev1api.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "secret-2", Namespace: "velero",
				Labels: map[string]string{BackupPVCSecretLabel: "du-456"},
			},
		},
	)

	DeleteSecretsWithLabel(context.Background(), fakeClient.CoreV1(), "velero",
		BackupPVCSecretLabel, "du-123", log)

	_, err := fakeClient.CoreV1().Secrets("velero").Get(
		context.Background(), "secret-1", metav1.GetOptions{})
	assert.True(t, err != nil, "secret-1 should be deleted")

	_, err = fakeClient.CoreV1().Secrets("velero").Get(
		context.Background(), "secret-2", metav1.GetOptions{})
	assert.NoError(t, err, "secret-2 should still exist")
}
