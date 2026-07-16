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

package actions

import (
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// AdmissionWebhookConfigurationAction is a RestoreItemAction plugin applicable to mutatingwebhookconfiguration and
// validatingwebhookconfiguration to reset the invalid value for "sideEffects" of the webhooks.
// More background please refer to https://github.com/vmware-tanzu/velero/issues/3516
type AdmissionWebhookConfigurationAction struct {
	logger logrus.FieldLogger
}

// NewAdmissionWebhookConfigurationAction creates a new instance of AdmissionWebhookConfigurationAction
func NewAdmissionWebhookConfigurationAction(logger logrus.FieldLogger) *AdmissionWebhookConfigurationAction {
	return &AdmissionWebhookConfigurationAction{logger: logger}
}

// AppliesTo implements the RestoreItemAction plugin interface method.
func (a *AdmissionWebhookConfigurationAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
	}, nil
}

// Execute will reset the value of "sideEffects" attribute of each item in the "webhooks" list to "None" if they are invalid values for
// v1, such as "Unknown" or "Some"
func (a *AdmissionWebhookConfigurationAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	a.logger.Info("Executing ChangeStorageClassAction")
	defer a.logger.Info("Done executing ChangeStorageClassAction")

	item := input.Item
	apiVersion, _, err := unstructured.NestedString(item.UnstructuredContent(), "apiVersion")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the apiVersion from input item")
	}
	name, _, _ := unstructured.NestedString(item.UnstructuredContent(), "metadata", "name")
	logger := a.logger.WithField("resource_name", name)
	if apiVersion != "admissionregistration.k8s.io/v1" {
		logger.Infof("unable to handle api version: %s, skip", apiVersion)
		return velero.NewRestoreItemActionExecuteOutput(input.Item), nil
	}
	webhooks, ok, err := unstructured.NestedSlice(item.UnstructuredContent(), "webhooks")
	if err != nil {
		return nil, errors.Wrap(err, "failed to get webhooks slice from input item")
	}
	if !ok {
		logger.Info("webhooks is not set, skip")
		return velero.NewRestoreItemActionExecuteOutput(input.Item), nil
	}
	newWebhooks := make([]any, 0)
	for i := range webhooks {
		logger2 := logger.WithField("index", i)
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&webhooks[i])
		if err != nil {
			logger2.Errorf("failed to convert the webhook entry, error: %v, it will be dropped", err)
			continue
		}
		s, _, _ := unstructured.NestedString(obj, "sideEffects")
		if s != "None" && s != "NoneOnDryRun" {
			logger2.Infof("reset the invalid sideEffects value '%s' to 'None'", s)
			obj["sideEffects"] = "None"
		}
		newWebhooks = append(newWebhooks, obj)
	}
	item.UnstructuredContent()["webhooks"] = newWebhooks
	return velero.NewRestoreItemActionExecuteOutput(item), nil
}
