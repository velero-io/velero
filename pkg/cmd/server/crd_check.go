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

package server

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
)

type crdSchemaExpectation struct {
	crdName            string
	specType           reflect.Type
	statusType         reflect.Type
	apiGroupVersion    string
	storedVersionLabel string
}

func expectedCRDSchemas() []crdSchemaExpectation {
	var expectations []crdSchemaExpectation

	for kind, info := range velerov1api.CustomResources() {
		exp := crdSchemaExpectation{
			crdName:            info.PluralName + "." + velerov1api.SchemeGroupVersion.Group,
			apiGroupVersion:    velerov1api.SchemeGroupVersion.Version,
			storedVersionLabel: kind,
		}
		itemType := reflect.TypeOf(info.ItemType)
		if itemType.Kind() == reflect.Pointer {
			itemType = itemType.Elem()
		}
		if structField, ok := itemType.FieldByName("Spec"); ok {
			exp.specType = structField.Type
		}
		if statusField, ok := itemType.FieldByName("Status"); ok {
			exp.statusType = statusField.Type
		}
		expectations = append(expectations, exp)
	}

	for kind, info := range velerov2alpha1api.CustomResources() {
		exp := crdSchemaExpectation{
			crdName:            info.PluralName + "." + velerov2alpha1api.SchemeGroupVersion.Group,
			apiGroupVersion:    velerov2alpha1api.SchemeGroupVersion.Version,
			storedVersionLabel: kind,
		}
		itemType := reflect.TypeOf(info.ItemType)
		if itemType.Kind() == reflect.Pointer {
			itemType = itemType.Elem()
		}
		if structField, ok := itemType.FieldByName("Spec"); ok {
			exp.specType = structField.Type
		}
		if statusField, ok := itemType.FieldByName("Status"); ok {
			exp.statusType = statusField.Type
		}
		expectations = append(expectations, exp)
	}

	return expectations
}

// jsonFieldNames extracts top-level JSON field names from a Go struct type using reflection.
func jsonFieldNames(t reflect.Type) sets.Set[string] {
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}

	fields := sets.New[string]()
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		// An anonymous field with no JSON tag is promoted/flattened by encoding/json.
		// One with an explicit tag name (e.g. `json:"metadata,omitempty"`) is instead
		// marshaled as a regular named field, not inlined.
		if field.Anonymous && tag == "" {
			embedded := jsonFieldNames(field.Type)
			fields = fields.Union(embedded)
			continue
		}
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			continue
		}
		fields.Insert(name)
	}
	return fields
}

// schemaPropertyNames extracts top-level property names from a CRD OpenAPI schema.
// The second return value is false if path could not be traversed (schema is nil,
// or an intermediate/final segment is missing), distinct from reaching a node that
// legitimately declares no properties (true, empty set).
func schemaPropertyNames(schema *apiextv1.JSONSchemaProps, path string) (sets.Set[string], bool) {
	if schema == nil {
		return nil, false
	}

	current := schema
	for segment := range strings.SplitSeq(path, ".") {
		if segment == "" {
			continue
		}
		if current.Properties == nil {
			return nil, false
		}
		next, ok := current.Properties[segment]
		if !ok {
			return nil, false
		}
		current = &next
	}

	names := sets.New[string]()
	if current.Properties == nil {
		return names, true
	}
	for name := range current.Properties {
		names.Insert(name)
	}
	return names, true
}

func (s *server) validateCRDSchemas() error {
	mode := s.config.CRDSchemaCheck.String()
	if mode == "skip" {
		s.logger.Info("CRD schema validation skipped (--crd-schema-check=skip)")
		return nil
	}

	s.logger.Info("Validating CRD schemas match server expectations")

	apiextClient, err := apiextclient.NewForConfig(s.kubeClientConfig)
	if err != nil {
		return errors.Wrap(err, "creating apiextensions client for CRD schema validation")
	}

	return runCRDSchemaValidation(s.ctx, apiextClient, expectedCRDSchemas(), mode, s.logger)
}

func runCRDSchemaValidation(ctx context.Context, client apiextclient.Interface, expectations []crdSchemaExpectation, mode string, logger logrus.FieldLogger) error {
	var allMissing []string

	for _, exp := range expectations {
		crd, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(
			ctx, exp.crdName, metav1.GetOptions{})
		if err != nil {
			logger.WithField("crd", exp.crdName).WithError(err).Warn("Could not fetch CRD for schema validation")
			allMissing = append(allMissing, fmt.Sprintf("%s: could not fetch CRD (%v)", exp.crdName, err))
			continue
		}

		var versionSchema *apiextv1.CustomResourceValidation
		for _, v := range crd.Spec.Versions {
			if v.Name == exp.apiGroupVersion {
				versionSchema = v.Schema
				break
			}
		}
		if versionSchema == nil || versionSchema.OpenAPIV3Schema == nil {
			logger.WithField("crd", exp.crdName).Warn("CRD has no OpenAPI schema for version " + exp.apiGroupVersion)
			allMissing = append(allMissing, fmt.Sprintf("%s: no OpenAPI schema for version %s", exp.crdName, exp.apiGroupVersion))
			continue
		}

		schema := versionSchema.OpenAPIV3Schema

		missing := checkMissing(exp.specType, schema, "spec", exp.crdName)
		missing = append(missing, checkMissing(exp.statusType, schema, "status", exp.crdName)...)

		allMissing = append(allMissing, missing...)
	}

	if len(allMissing) > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "CRD schema mismatch detected — %d field(s) expected by server not found in installed CRDs. "+
			"Update CRDs with: velero install --crds-only\n", len(allMissing))
		for _, m := range allMissing {
			sb.WriteString("  - " + m + "\n")
		}
		msg := sb.String()

		if mode == "strict" {
			return errors.New(msg)
		}
		logger.Error(msg)
	} else {
		logger.Info("All CRD schemas match server expectations")
	}

	return nil
}

func checkMissing(goType reflect.Type, schema *apiextv1.JSONSchemaProps, section, crdName string) []string {
	if goType == nil {
		return nil
	}
	expectedFields := jsonFieldNames(goType)
	installedFields, ok := schemaPropertyNames(schema, section)
	if !ok {
		installedFields = sets.New[string]()
	}

	var missing []string
	for field := range expectedFields {
		if !installedFields.Has(field) {
			missing = append(missing, fmt.Sprintf("%s: %s.%s", crdName, section, field))
		}
	}
	return missing
}
