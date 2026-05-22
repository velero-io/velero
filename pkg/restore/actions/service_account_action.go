/*
Copyright 2018 the Velero contributors.

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
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

type ServiceAccountAction struct {
	logger logrus.FieldLogger
}

func NewServiceAccountAction(logger logrus.FieldLogger) *ServiceAccountAction {
	return &ServiceAccountAction{logger: logger}
}

func (a *ServiceAccountAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"serviceaccounts"},
	}, nil
}

func (a *ServiceAccountAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	a.logger.Info("Executing ServiceAccountAction")
	defer a.logger.Info("Done executing ServiceAccountAction")

	var serviceAccount corev1api.ServiceAccount
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), &serviceAccount); err != nil {
		return nil, errors.Wrap(err, "unable to convert serviceaccount from runtime.Unstructured")
	}

	log := a.logger.WithField("serviceaccount", kube.NamespaceAndName(&serviceAccount))

	log.Debug("Checking secrets")
	check := serviceAccount.Name + "-token-"
	for i, v := range slices.Backward(serviceAccount.Secrets) {
		log.Debugf("Checking if secret %s matches %s", v.Name, check)

		if strings.HasPrefix(v.Name, check) {
			// Copy all secrets *except* -token-
			log.Debug("Match found - excluding this secret")
			serviceAccount.Secrets = append(serviceAccount.Secrets[:i], serviceAccount.Secrets[i+1:]...)
			break
		} else {
			log.Debug("No match found - including this secret")
		}
	}

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&serviceAccount)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert serviceaccount to runtime.Unstructured")
	}

	return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: res}), nil
}
