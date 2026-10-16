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

package cacert

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

func GetBackupFromRestore(ctx context.Context, client kbclient.Client, restore *velerov1api.Restore) (*velerov1api.Backup, error) {
	backup := &velerov1api.Backup{}
	key := kbclient.ObjectKey{
		Namespace: restore.Namespace,
		Name:      restore.Spec.BackupName,
	}
	if err := client.Get(ctx, key, backup); err != nil {
		if apierrors.IsNotFound(err) {
			// Backup not found is not a fatal error for cacert retrieval
			return nil, nil
		}

		return nil, errors.Wrapf(err, "error getting backup %s", restore.Spec.BackupName)
	}
	return backup, nil
}

func GetBSLFromRestore(ctx context.Context, client kbclient.Client, restore *velerov1api.Restore) (*velerov1api.BackupStorageLocation, error) {
	backup, err := GetBackupFromRestore(ctx, client, restore)
	if err != nil {
		return nil, err
	}
	if backup == nil {
		return nil, nil
	}
	return GetBSLFromBackup(ctx, client, backup)
}

func GetBSLFromBackup(ctx context.Context, client kbclient.Client, backup *velerov1api.Backup) (*velerov1api.BackupStorageLocation, error) {
	return GetBSL(ctx, client, backup.Namespace, backup.Spec.StorageLocation)
}

func GetBSL(ctx context.Context, client kbclient.Client, namespace string, bslName string) (*velerov1api.BackupStorageLocation, error) {
	if bslName == "" {
		return nil, nil
	}
	bsl := &velerov1api.BackupStorageLocation{}
	key := kbclient.ObjectKey{
		Namespace: namespace,
		Name:      bslName,
	}
	if err := client.Get(ctx, key, bsl); err != nil {
		if apierrors.IsNotFound(err) {
			// BSL not found is not a fatal error; callers treat a nil BSL as "no cacert, no SSE-C key"
			return nil, nil
		}
		return nil, errors.Wrapf(err, "error getting backup storage location %s", bslName)
	}
	return bsl, nil
}

func GetSSECKeyFromBSL(ctx context.Context, client kbclient.Client, bsl *velerov1api.BackupStorageLocation) (string, error) {
	if bsl == nil {
		return "", nil
	}
	secretPath, exists := bsl.Spec.Config["customerKeyEncryptionSecret"]
	if !exists {
		if _, hasFile := bsl.Spec.Config["customerKeyEncryptionFile"]; hasFile {
			return "", errors.Errorf("bsl %s uses customerKeyEncryptionFile, which the CLI cannot read (the path only exists in the velero server pod); use customerKeyEncryptionSecret instead", bsl.Name)
		}
		return "", nil
	}
	secretPathParts := strings.Split(secretPath, "/")
	if len(secretPathParts) != 2 {
		return "", errors.Errorf("bsl %s .spec.config.customerKeyEncryptionSecret is malformed", bsl.Name)
	}
	secretName, secretKey := secretPathParts[0], secretPathParts[1]

	secret := &corev1api.Secret{}
	key := kbclient.ObjectKey{
		Namespace: bsl.Namespace,
		Name:      secretName,
	}
	if err := client.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", errors.Errorf("secret %s not found in namespace %s", key.Name, key.Namespace)
		}
		return "", errors.Wrapf(err, "error getting secret %s", secretName)
	}
	encryptionKey, exists := secret.Data[secretKey]
	if !exists {
		return "", errors.Errorf("key %s not found in secret %s", secretKey, secret.Name)
	}
	return string(encryptionKey), nil
}

// GetCACertFromBSL fetches a BackupStorageLocation directly and returns its cacert
// Priority order: caCertRef (from Secret) > caCert (inline, deprecated)
func GetCACertFromBSL(ctx context.Context, client kbclient.Client, bsl *velerov1api.BackupStorageLocation) (string, error) {
	if bsl == nil {
		return "", nil
	}
	if bsl.Spec.ObjectStorage == nil {
		return "", nil
	}

	// Prefer caCertRef over inline caCert
	if bsl.Spec.ObjectStorage.CACertRef != nil {
		// Fetch certificate from Secret
		secret := &corev1api.Secret{}
		secretKey := types.NamespacedName{
			Name:      bsl.Spec.ObjectStorage.CACertRef.Name,
			Namespace: bsl.Namespace,
		}

		if err := client.Get(ctx, secretKey, secret); err != nil {
			if apierrors.IsNotFound(err) {
				return "", errors.Errorf("certificate secret %s not found in namespace %s",
					bsl.Spec.ObjectStorage.CACertRef.Name, bsl.Namespace)
			}
			return "", errors.Wrapf(err, "error getting certificate secret %s",
				bsl.Spec.ObjectStorage.CACertRef.Name)
		}

		keyName := bsl.Spec.ObjectStorage.CACertRef.Key
		if keyName == "" {
			return "", errors.New("caCertRef key is empty")
		}

		certData, ok := secret.Data[keyName]
		if !ok {
			return "", errors.Errorf("key %s not found in secret %s",
				keyName, bsl.Spec.ObjectStorage.CACertRef.Name)
		}

		return string(certData), nil
	}

	// Fall back to inline caCert (deprecated)
	if len(bsl.Spec.ObjectStorage.CACert) > 0 {
		return string(bsl.Spec.ObjectStorage.CACert), nil
	}

	return "", nil
}
