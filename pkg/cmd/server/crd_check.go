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
	"encoding/json"
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

// jsonFieldInfo describes one JSON-tagged field of a Go struct: whether it's
// optional from the server's perspective (carries `omitempty`, so the server
// may legitimately not send it on every write), and — when the field is
// itself a struct (directly or through a pointer) — its type, so callers can
// recurse into it to check nested fields the same way.
type jsonFieldInfo struct {
	optional  bool
	nestedTyp reflect.Type // nil unless the field is a struct/pointer-to-struct
}

// jsonFields extracts the JSON field names of a Go struct type using
// reflection, one level deep (anonymous/inlined fields are flattened into
// the parent, matching encoding/json's own promotion rules, so they don't
// count as a nesting level here).
func jsonFields(t reflect.Type) map[string]jsonFieldInfo {
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}

	fields := map[string]jsonFieldInfo{}
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		// An anonymous field with no JSON tag, or tagged `json:",inline"` (the
		// Kubernetes convention for structural-schema inlining), is promoted/
		// flattened rather than nested under its own field name. One with an
		// explicit tag name (e.g. `json:"metadata,omitempty"`) is instead
		// marshaled as a regular named field, not inlined.
		if field.Anonymous && name == "" && tag != "-" {
			for embeddedName, info := range jsonFields(field.Type) {
				fields[embeddedName] = info
			}
			continue
		}
		if tag == "" || tag == "-" || name == "" {
			continue
		}

		ft := field.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		info := jsonFieldInfo{
			optional: strings.Contains(","+opts+",", ",omitempty,"),
		}
		// A struct type with its own custom json.Marshaler (e.g. metav1.Time,
		// metav1.Duration) serializes to a scalar (string/number), not a nested JSON
		// object -- the CRD schema represents it as a plain leaf property, so recursing
		// into its internal Go fields would compare against a schema node that doesn't
		// and shouldn't exist, producing false "missing field" reports. Only recurse
		// into plain structs that rely on the default field-by-field JSON encoding.
		if ft.Kind() == reflect.Struct && !implementsJSONMarshaler(ft) {
			info.nestedTyp = ft
		}
		fields[name] = info
	}
	return fields
}

var jsonMarshalerType = reflect.TypeFor[json.Marshaler]()

// implementsJSONMarshaler reports whether t or *t implements json.Marshaler, covering both
// value-receiver marshalers (e.g. metav1.Duration) and pointer-receiver ones (e.g. metav1.Time).
func implementsJSONMarshaler(t reflect.Type) bool {
	return t.Implements(jsonMarshalerType) || reflect.PointerTo(t).Implements(jsonMarshalerType)
}

// schemaNodeAt walks a CRD OpenAPI schema down a dotted path and returns the
// node reached, plus false if the path could not be traversed at all (schema
// is nil, or an intermediate/final segment is missing) — distinct from
// reaching a node that legitimately declares no properties (true, with a nil
// Properties map on the returned node).
func schemaNodeAt(schema *apiextv1.JSONSchemaProps, path string) (*apiextv1.JSONSchemaProps, bool) {
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
	return current, true
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

	expectations := expectedCRDSchemas()

	if mode == "strict" {
		ctx, cancel := context.WithTimeout(s.ctx, s.config.ResourceTimeout)
		defer cancel()
		return runCRDSchemaValidation(ctx, apiextClient, expectations, mode, s.logger)
	}

	// warn mode never gates startup on this check — the goroutine is bound by
	// s.ctx (cancels on server shutdown) and by the same ResourceTimeout used
	// for strict mode's synchronous pass, so it self-terminates against an
	// unresponsive API server instead of hanging around in the background
	// indefinitely. Binding the deadline is not the same as gating startup on
	// it: validateCRDSchemas itself returns immediately below, before this
	// goroutine's result is known.
	go func() {
		ctx, cancel := context.WithTimeout(s.ctx, s.config.ResourceTimeout)
		defer cancel()
		if err := runCRDSchemaValidation(ctx, apiextClient, expectations, mode, s.logger); err != nil {
			s.logger.WithError(err).Error("CRD schema validation failed")
		}
	}()

	return nil
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
			"Update CRDs with: velero install --crds-only --apply\n", len(allMissing))
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
	node, ok := schemaNodeAt(schema, section)
	if !ok {
		node = &apiextv1.JSONSchemaProps{}
	}
	return checkMissingAt(goType, node, section, crdName)
}

// checkMissingAt is the recursive core of checkMissing: it diffs one Go
// struct type against one CRD schema node (already resolved to the given
// dotted path) and returns every mismatch found, either directly at this
// level or in a nested struct field. A "mismatch" is either:
//   - a field the server's Go type has that the installed CRD schema does
//     not declare at all (an outdated CRD, the original check), or
//   - a field the CRD schema *does* declare, but marks `required` while the
//     server's Go type treats it as optional (`omitempty`) — i.e. the server
//     may legitimately not set it on some writes, which the older/stricter
//     CRD would then reject as a validation failure, exactly the failure
//     mode raised in review (e.g. BackupRepository.spec.resticIdentifier).
//
// Fields present in the CRD but absent from the Go type are intentionally
// not flagged either way — see checkMissing's callers / the design doc's
// Non Goals for why a CRD newer/wider than the server isn't this check's
// concern.
func checkMissingAt(goType reflect.Type, node *apiextv1.JSONSchemaProps, path, crdName string) []string {
	fields := jsonFields(goType)
	if fields == nil {
		return nil
	}

	installedRequired := sets.New[string]()
	if node != nil {
		installedRequired = sets.New(node.Required...)
	}

	var mismatches []string
	for name, info := range fields {
		fieldPath := path + "." + name
		var installed *apiextv1.JSONSchemaProps
		if node != nil && node.Properties != nil {
			if p, ok := node.Properties[name]; ok {
				installed = &p
			}
		}

		if installed == nil {
			mismatches = append(mismatches, fmt.Sprintf("%s: %s", crdName, fieldPath))
			continue
		}

		if info.optional && installedRequired.Has(name) {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: %s is required by installed CRD but optional (omitempty) on the server — a write that omits it would be rejected",
				crdName, fieldPath))
		}

		if info.nestedTyp != nil {
			mismatches = append(mismatches, checkMissingAt(info.nestedTyp, installed, fieldPath, crdName)...)
		}
	}
	return mismatches
}
