/*
Copyright 2020 the Velero contributors.

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
	"encoding/json"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// CRDV1PreserveUnknownFieldsAction will take a CRD and inspect it for the API version and the PreserveUnknownFields value.
// If the API Version is 1 and the PreserveUnknownFields value is True, then the x-preserve-unknown-fields value in the OpenAPIV3 schema will be set to True
// and PreserveUnknownFields set to False in order to allow Kubernetes 1.16+ servers to accept the object.
type CRDV1PreserveUnknownFieldsAction struct {
	logger logrus.FieldLogger
}

func NewCRDV1PreserveUnknownFieldsAction(logger logrus.FieldLogger) *CRDV1PreserveUnknownFieldsAction {
	return &CRDV1PreserveUnknownFieldsAction{logger: logger}
}

func (c *CRDV1PreserveUnknownFieldsAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"customresourcedefinition.apiextensions.k8s.io"},
	}, nil
}

func (c *CRDV1PreserveUnknownFieldsAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	c.logger.Info("Executing CRDV1PreserveUnknownFieldsAction")

	name, _, err := unstructured.NestedString(input.Item.UnstructuredContent(), "name")
	if err != nil {
		return nil, errors.Wrap(err, "could not get CRD name")
	}

	log := c.logger.WithField("plugin", "CRDV1PreserveUnknownFieldsAction").WithField("CRD", name)

	version, _, err := unstructured.NestedString(input.Item.UnstructuredContent(), "apiVersion")
	if err != nil {
		return nil, errors.Wrap(err, "could not get CRD version")
	}

	// We don't want to "fix" anything in beta CRDs at the moment, just v1 versions with preserveunknownfields = true
	if version != "apiextensions.k8s.io/v1" {
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	// Do not use runtime.DefaultUnstructuredConverter.FromUnstructured here because it has a bug when converting integers/whole
	// numbers in float fields (https://github.com/kubernetes/kubernetes/issues/87675).
	// Using JSON as a go-between avoids this issue, without adding a bunch of type conversion by using unstructured helper functions
	// to inspect the fields we want to look at.
	crd, err := fromUnstructured(input.Item.UnstructuredContent())
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert CRD from unstructured to structured")
	}

	// The v1 API doesn't allow the PreserveUnknownFields value to be true, so make sure the schema flag is set instead
	if crd.Spec.PreserveUnknownFields {
		// First, change the top-level value since the Kubernetes API server on 1.16+ will generate errors otherwise.
		log.Debug("Set PreserveUnknownFields to False")
		crd.Spec.PreserveUnknownFields = false

		// Make sure all versions are set to preserve unknown fields
		for _, v := range crd.Spec.Versions {
			// If the schema fields are nil, there are no nested fields to set, so skip over it for this version.
			if v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
				continue
			}

			// Use the address, since the XPreserveUnknownFields value is nil or
			// a pointer to true (false is not allowed)
			preserve := true
			v.Schema.OpenAPIV3Schema.XPreserveUnknownFields = &preserve
			log.Debugf("Set x-preserve-unknown-fields in Open API for schema version %s", v.Name)
		}
	}

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&crd)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert crd to runtime.Unstructured")
	}

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{Object: res},
	}, nil
}

func fromUnstructured(unstructured map[string]any) (*apiextv1.CustomResourceDefinition, error) {
	var crd apiextv1.CustomResourceDefinition

	js, err := json.Marshal(unstructured)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert unstructured item to JSON")
	}

	if err = json.Unmarshal(js, &crd); err != nil {
		return nil, errors.Wrap(err, "unable to convert JSON to CRD Go type")
	}

	return &crd, nil
}
