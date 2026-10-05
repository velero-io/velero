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
	"context"
	"encoding/json"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	apiextv1beta1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerodiscovery "github.com/vmware-tanzu/velero/pkg/discovery"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// RemapCRDVersionAction inspects CustomResourceDefinition and decides if it is a v1
// CRD that needs to be backed up as v1beta1.
type RemapCRDVersionAction struct {
	logger          logrus.FieldLogger
	betaCRDClient   apiextv1beta1client.CustomResourceDefinitionInterface
	discoveryHelper velerodiscovery.Helper
}

// NewRemapCRDVersionAction instantiates a new RemapCRDVersionAction plugin.
func NewRemapCRDVersionAction(logger logrus.FieldLogger, betaCRDClient apiextv1beta1client.CustomResourceDefinitionInterface, discoveryHelper velerodiscovery.Helper) *RemapCRDVersionAction {
	return &RemapCRDVersionAction{logger: logger, betaCRDClient: betaCRDClient, discoveryHelper: discoveryHelper}
}

// AppliesTo selects the resources the plugin should run against. In this case, CustomResourceDefinitions.
func (a *RemapCRDVersionAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"customresourcedefinition.apiextensions.k8s.io"},
	}, nil
}

// Execute executes logic necessary to check a CustomResourceDefinition and inspect it for characteristics that necessitate saving it as v1beta1 instead of v1.
func (a *RemapCRDVersionAction) Execute(item runtime.Unstructured, backup *v1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, error) {
	a.logger.Info("Executing RemapCRDVersionAction")

	// This plugin is only relevant for CRDs retrieved from the v1 endpoint that were installed via the v1beta1
	// endpoint, so we can exit immediately if the resource in question isn't v1.
	apiVersion, ok, err := unstructured.NestedString(item.UnstructuredContent(), "apiVersion")
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to read apiVersion from CRD")
	}
	if ok && apiVersion != "apiextensions.k8s.io/v1" {
		a.logger.Info("Exiting RemapCRDVersionAction, CRD is not v1")
		return item, nil, nil
	}

	// This plugin will exit if the CRD was installed via v1beta1 but the cluster does not support v1beta1 CRD
	supportv1b1 := false
CheckVersion:
	for _, g := range a.discoveryHelper.APIGroups() {
		if g.Name == apiextv1.GroupName {
			for _, v := range g.Versions {
				if v.Version == apiextv1beta1.SchemeGroupVersion.Version {
					supportv1b1 = true
					break CheckVersion
				}
			}
		}
	}
	if !supportv1b1 {
		a.logger.Info("Exiting RemapCRDVersionAction, the cluster does not support v1beta1 CRD")
		return item, nil, nil
	}

	// We've got a v1 CRD and the cluster supports v1beta1 CRD, so proceed.
	var crd apiextv1.CustomResourceDefinition

	// Do not use runtime.DefaultUnstructuredConverter.FromUnstructured here because it has a bug when converting integers/whole
	// numbers in float fields (https://github.com/kubernetes/kubernetes/issues/87675).
	// Using JSON as a go-between avoids this issue, without adding a bunch of type conversion by using unstructured helper functions
	// to inspect the fields we want to look at.
	js, err := json.Marshal(item.UnstructuredContent())
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to convert unstructured item to JSON")
	}

	if err = json.Unmarshal(js, &crd); err != nil {
		return nil, nil, errors.Wrap(err, "unable to convert JSON to CRD Go type")
	}

	log := a.logger.WithField("plugin", "RemapCRDVersionAction").WithField("CRD", crd.Name)

	switch {
	case hasSingleVersion(crd), hasNonStructuralSchema(crd), hasPreserveUnknownFields(crd):
		log.Infof("CustomResourceDefinition %s appears to be v1beta1, fetching the v1beta version", crd.Name)
		item, err = fetchV1beta1CRD(crd.Name, a.betaCRDClient)
		if err != nil {
			return nil, nil, err
		}
	default:
		log.Infof("CustomResourceDefinition %s does not appear to be v1beta1, backing up as v1", crd.Name)
	}

	return item, nil, nil
}

func fetchV1beta1CRD(name string, betaCRDClient apiextv1beta1client.CustomResourceDefinitionInterface) (*unstructured.Unstructured, error) {
	betaCRD, err := betaCRDClient.Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error fetching v1beta1 version of %s", name)
	}

	// Individual items fetched from the API don't always have the kind/API version set
	// See https://github.com/kubernetes/kubernetes/issues/3030. Unsure why this is happening here and not in main Velero;
	// probably has to do with List calls and Dynamic client vs typed client
	// Set these all the time, since they shouldn't ever be different, anyway
	betaCRD.Kind = "CustomResourceDefinition"
	betaCRD.APIVersion = apiextv1beta1.SchemeGroupVersion.String()

	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&betaCRD)
	if err != nil {
		return nil, errors.Wrapf(err, "error converting v1beta1 version of %s to unstructured", name)
	}
	item := &unstructured.Unstructured{Object: m}

	return item, nil
}

// hasPreserveUnknownFields determines whether or not a CRD is set to preserve unknown fields or not.
func hasPreserveUnknownFields(crd apiextv1.CustomResourceDefinition) bool {
	return crd.Spec.PreserveUnknownFields
}

// hasNonStructuralSchema determines whether or not a CRD has had a nonstructural schema condition applied.
func hasNonStructuralSchema(crd apiextv1.CustomResourceDefinition) bool {
	var ret bool
	for _, c := range crd.Status.Conditions {
		if c.Type == apiextv1.NonStructuralSchema {
			ret = true
			break
		}
	}
	return ret
}

// hasSingleVersion checks a CRD to see if it has a single version with no schema information.
func hasSingleVersion(crd apiextv1.CustomResourceDefinition) bool {
	// Looking for 1 version should be enough to tell if it's a v1beta1 CRD, as all v1beta1 CRD versions share the same schema.
	// v1 CRDs can have different schemas per version
	// The silently upgraded versions will often have a `versions` entry that looks like this:
	//   versions:
	//   - name: v1
	//     served:  true
	//     storage: true
	// This is acceptable when re-submitted to a v1beta1 endpoint on restore.
	var ret bool
	if len(crd.Spec.Versions) > 0 {
		if crd.Spec.Versions[0].Schema == nil || crd.Spec.Versions[0].Schema.OpenAPIV3Schema == nil {
			ret = true
		}
	}
	return ret
}
