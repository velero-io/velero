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
	"reflect"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
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

// ErrSecretCollision is returned when a secret or configmap with the same name but different
// data already exists in the target namespace, indicating another owner is using it.
var ErrSecretCollision = errors.New("secret collision: same name exists with different data")

// labelsMatch reports whether all entries in want are present in have with matching values.
func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// CopySecret copies a secret from sourceNamespace to targetNamespace, applying the given labels.
// If a secret with the same name already exists in the target with identical data and matching
// labels, it is a no-op. If the data matches but the labels differ, or the data differs, it
// returns ErrSecretCollision.
func CopySecret(ctx context.Context, client corev1client.CoreV1Interface, secretName, sourceNamespace, targetNamespace string, labels map[string]string, log logrus.FieldLogger) error {
	srcSecret, err := client.Secrets(sourceNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "error getting secret %s/%s", sourceNamespace, secretName)
	}

	newSecret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: targetNamespace,
			Labels:    labels,
		},
		Type: srcSecret.Type,
		Data: srcSecret.Data,
	}

	_, err = client.Secrets(targetNamespace).Create(ctx, newSecret, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Copied secret %s from %s to %s", secretName, sourceNamespace, targetNamespace)
		return nil
	}

	if !apierrors.IsAlreadyExists(err) {
		return errors.Wrapf(err, "error creating secret %s in %s", secretName, targetNamespace)
	}

	existing, err := client.Secrets(targetNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "error getting existing secret %s/%s", targetNamespace, secretName)
	}

	if reflect.DeepEqual(existing.Data, srcSecret.Data) && labelsMatch(existing.Labels, labels) {
		log.Infof("Secret %s already exists in %s with same data and labels, skipping copy", secretName, targetNamespace)
		return nil
	}

	log.Infof("Secret %s already exists in %s owned by a different owner, collision detected", secretName, targetNamespace)
	return ErrSecretCollision
}

// DeleteSecretsWithLabel deletes all secrets in a namespace matching a label key=value pair.
// Uses UID preconditions to avoid deleting a recreated object with the same name.
func DeleteSecretsWithLabel(ctx context.Context, client corev1client.CoreV1Interface, namespace, labelKey, labelValue string, log logrus.FieldLogger) {
	secrets, err := client.Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelKey + "=" + labelValue,
	})
	if err != nil {
		log.WithError(err).Errorf("Failed to list secrets with label %s=%s in %s", labelKey, labelValue, namespace)
		return
	}

	for i := range secrets.Items {
		uid := secrets.Items[i].UID
		err := client.Secrets(namespace).Delete(ctx, secrets.Items[i].Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			log.WithError(err).Errorf("Failed to delete secret %s/%s", namespace, secrets.Items[i].Name)
		}
	}
}

// CopyConfigMap copies a configmap from sourceNamespace to targetNamespace, applying the given
// labels. If a configmap with the same name already exists in the target with identical data and
// matching labels, it is a no-op. If the data matches but the labels differ, or the data differs,
// it returns ErrSecretCollision.
func CopyConfigMap(ctx context.Context, client corev1client.CoreV1Interface, cmName, sourceNamespace, targetNamespace string, labels map[string]string, log logrus.FieldLogger) error {
	srcCM, err := client.ConfigMaps(sourceNamespace).Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "error getting configmap %s/%s", sourceNamespace, cmName)
	}

	newCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: targetNamespace,
			Labels:    labels,
		},
		Data:       srcCM.Data,
		BinaryData: srcCM.BinaryData,
	}

	_, err = client.ConfigMaps(targetNamespace).Create(ctx, newCM, metav1.CreateOptions{})
	if err == nil {
		log.Infof("Copied configmap %s from %s to %s", cmName, sourceNamespace, targetNamespace)
		return nil
	}

	if !apierrors.IsAlreadyExists(err) {
		return errors.Wrapf(err, "error creating configmap %s in %s", cmName, targetNamespace)
	}

	existing, err := client.ConfigMaps(targetNamespace).Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "error getting existing configmap %s/%s", targetNamespace, cmName)
	}

	if reflect.DeepEqual(existing.Data, srcCM.Data) &&
		reflect.DeepEqual(existing.BinaryData, srcCM.BinaryData) &&
		labelsMatch(existing.Labels, labels) {
		log.Infof("ConfigMap %s already exists in %s with same data and labels, skipping copy", cmName, targetNamespace)
		return nil
	}

	log.Infof("ConfigMap %s already exists in %s owned by a different owner, collision detected", cmName, targetNamespace)
	return ErrSecretCollision
}

// DeleteConfigMapsWithLabel deletes all configmaps in a namespace matching a label key=value pair.
// Uses UID preconditions to avoid deleting a recreated object with the same name.
func DeleteConfigMapsWithLabel(ctx context.Context, client corev1client.CoreV1Interface, namespace, labelKey, labelValue string, log logrus.FieldLogger) {
	cms, err := client.ConfigMaps(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelKey + "=" + labelValue,
	})
	if err != nil {
		log.WithError(err).Errorf("Failed to list configmaps with label %s=%s in %s", labelKey, labelValue, namespace)
		return
	}

	for i := range cms.Items {
		uid := cms.Items[i].UID
		err := client.ConfigMaps(namespace).Delete(ctx, cms.Items[i].Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			log.WithError(err).Errorf("Failed to delete configmap %s/%s", namespace, cms.Items[i].Name)
		}
	}
}
