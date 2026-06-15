/*
Copyright The Velero Contributors.

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

package actions

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// SecretAction is a restore item action for secrets
type SecretAction struct {
	logger logrus.FieldLogger
	client client.Client
}

// NewSecretAction creates a new SecretAction instance
func NewSecretAction(logger logrus.FieldLogger, client client.Client) *SecretAction {
	return &SecretAction{
		logger: logger,
		client: client,
	}
}

// AppliesTo indicates which resources this action applies
func (s *SecretAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"secrets"},
	}, nil
}

// Execute the action
func (s *SecretAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	s.logger.Info("Executing SecretAction")
	defer s.logger.Info("Done executing SecretAction")

	var secret corev1api.Secret
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), &secret); err != nil {
		return nil, errors.Wrap(err, "unable to convert secret from runtime.Unstructured")
	}

	log := s.logger.WithField("secret", kube.NamespaceAndName(&secret))
	if secret.Type != corev1api.SecretTypeServiceAccountToken {
		log.Debug("No match found - including this secret")
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	// The auto created service account token secret will be created by kube controller automatically again(before Kubernetes v1.22), no need to restore.
	// This will cause the patch operation of managedFields failed if we restore it as the secret is removed immediately
	// after restoration and the patch operation reports not found error.
	list := &corev1api.ServiceAccountList{}
	if err := s.client.List(context.Background(), list, &client.ListOptions{Namespace: secret.Namespace}); err != nil {
		return nil, errors.Wrap(err, "unable to list the service accounts")
	}
	for _, sa := range list.Items {
		if strings.HasPrefix(secret.Name, fmt.Sprintf("%s-token-", sa.Name)) {
			log.Debug("auto created service account token secret found - excluding this secret")
			return &velero.RestoreItemActionExecuteOutput{
				UpdatedItem: input.Item,
				SkipRestore: true,
			}, nil
		}
	}

	log.Debug("service account token secret(not auto created) found - remove some fields from this secret")
	// If the annotation and data are not removed, the secret cannot be restored successfully.
	// The kube controller will fill the annotation and data with new value automatically:
	// https://kubernetes.io/docs/concepts/configuration/secret/#service-account-token-secrets
	delete(secret.Annotations, "kubernetes.io/service-account.uid")
	delete(secret.Data, "token")
	delete(secret.Data, "ca.crt")

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&secret)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert secret to runtime.Unstructured")
	}

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{Object: res},
	}, nil
}
