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
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	fakeapiext "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type TestBase struct {
	Name  string `json:"name"`
	Count int    `json:"count,omitempty"`
}

type testSpec struct {
	Name    string `json:"name"`
	Count   int    `json:"count,omitempty"`
	Ignored string `json:"-"`
	private string
}

type testSpecWithEmbedded struct {
	TestBase
	Extra string `json:"extra"`
}

// testSpecWithNamedEmbedded mirrors BackupSpec embedding Metadata with an
// explicit json tag: encoding/json marshals it as a nested "base" object,
// not promoted/flattened fields.
type testSpecWithNamedEmbedded struct {
	TestBase `json:"base,omitempty"`
	Extra    string `json:"extra"`
}

func TestJsonFieldNames(t *testing.T) {
	tests := []struct {
		name     string
		input    reflect.Type
		expected []string
	}{
		{
			name:     "simple struct",
			input:    reflect.TypeFor[testSpec](),
			expected: []string{"name", "count"},
		},
		{
			name:     "pointer to struct",
			input:    reflect.TypeFor[*testSpec](),
			expected: []string{"name", "count"},
		},
		{
			name:     "struct with anonymous embedded",
			input:    reflect.TypeFor[testSpecWithEmbedded](),
			expected: []string{"name", "count", "extra"},
		},
		{
			name:     "nil type",
			input:    nil,
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := jsonFieldNames(tc.input)
			if tc.expected == nil {
				assert.Nil(t, result)
				return
			}
			for _, field := range tc.expected {
				assert.True(t, result.Has(field), "expected field %q", field)
			}
			assert.False(t, result.Has("Ignored"))
			assert.False(t, result.Has("private"))
		})
	}

	t.Run("embedded field with explicit json tag name is not promoted", func(t *testing.T) {
		result := jsonFieldNames(reflect.TypeFor[testSpecWithNamedEmbedded]())
		assert.True(t, result.Has("base"))
		assert.True(t, result.Has("extra"))
		assert.False(t, result.Has("name"), "embedded fields should nest under their tag name, not promote")
		assert.False(t, result.Has("count"), "embedded fields should nest under their tag name, not promote")
	})
}

func TestSchemaPropertyNames(t *testing.T) {
	schema := &apiextv1.JSONSchemaProps{
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Properties: map[string]apiextv1.JSONSchemaProps{
					"name":  {Type: "string"},
					"count": {Type: "integer"},
				},
			},
			"status": {
				Properties: map[string]apiextv1.JSONSchemaProps{
					"phase":   {Type: "string"},
					"message": {Type: "string"},
				},
			},
		},
	}

	t.Run("extract spec properties", func(t *testing.T) {
		result, ok := schemaPropertyNames(schema, "spec")
		require.True(t, ok)
		require.NotNil(t, result)
		assert.True(t, result.Has("name"))
		assert.True(t, result.Has("count"))
		assert.Equal(t, 2, result.Len())
	})

	t.Run("extract status properties", func(t *testing.T) {
		result, ok := schemaPropertyNames(schema, "status")
		require.True(t, ok)
		require.NotNil(t, result)
		assert.True(t, result.Has("phase"))
		assert.True(t, result.Has("message"))
	})

	t.Run("nonexistent path", func(t *testing.T) {
		result, ok := schemaPropertyNames(schema, "nonexistent")
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("nil schema", func(t *testing.T) {
		result, ok := schemaPropertyNames(nil, "spec")
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("section present but empty", func(t *testing.T) {
		emptySchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {},
			},
		}
		result, ok := schemaPropertyNames(emptySchema, "spec")
		assert.True(t, ok)
		require.NotNil(t, result)
		assert.Equal(t, 0, result.Len())
	})
}

func TestCheckMissing(t *testing.T) {
	schema := &apiextv1.JSONSchemaProps{
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Properties: map[string]apiextv1.JSONSchemaProps{
					"name": {Type: "string"},
				},
			},
		},
	}

	t.Run("missing field detected", func(t *testing.T) {
		missing := checkMissing(reflect.TypeFor[testSpec](), schema, "spec", "tests.velero.io")
		assert.Len(t, missing, 1)
		assert.Contains(t, missing[0], "count")
	})

	t.Run("no missing fields", func(t *testing.T) {
		fullSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"name":  {Type: "string"},
						"count": {Type: "integer"},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[testSpec](), fullSchema, "spec", "tests.velero.io")
		assert.Empty(t, missing)
	})

	t.Run("extra fields in CRD are OK", func(t *testing.T) {
		extraSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"name":      {Type: "string"},
						"count":     {Type: "integer"},
						"newField":  {Type: "string"},
						"anotherEx": {Type: "boolean"},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[testSpec](), extraSchema, "spec", "tests.velero.io")
		assert.Empty(t, missing)
	})

	t.Run("nil go type", func(t *testing.T) {
		missing := checkMissing(nil, schema, "spec", "tests.velero.io")
		assert.Nil(t, missing)
	})

	t.Run("missing schema section reports all expected fields missing", func(t *testing.T) {
		noSpecSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"status": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"phase": {Type: "string"},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[testSpec](), noSpecSchema, "spec", "tests.velero.io")
		assert.Len(t, missing, 2)
		assert.Contains(t, missing, "tests.velero.io: spec.name")
		assert.Contains(t, missing, "tests.velero.io: spec.count")
	})
}

func TestExpectedCRDSchemas(t *testing.T) {
	expectations := expectedCRDSchemas()
	assert.NotEmpty(t, expectations)

	crdNames := make(map[string]bool)
	for _, exp := range expectations {
		crdNames[exp.crdName] = true
		assert.NotEmpty(t, exp.crdName, "CRD name should not be empty")
		assert.NotEmpty(t, exp.apiGroupVersion, "API group version should not be empty")
	}

	assert.True(t, crdNames["backups.velero.io"], "should include backups CRD")
	assert.True(t, crdNames["restores.velero.io"], "should include restores CRD")
	assert.True(t, crdNames["schedules.velero.io"], "should include schedules CRD")
	assert.True(t, crdNames["datauploads.velero.io"], "should include datauploads CRD")
	assert.True(t, crdNames["datadownloads.velero.io"], "should include datadownloads CRD")
}

func makeCRD(name, version string, specProps, statusProps map[string]apiextv1.JSONSchemaProps) *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name: version,
					Schema: &apiextv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
							Properties: map[string]apiextv1.JSONSchemaProps{
								"spec":   {Properties: specProps},
								"status": {Properties: statusProps},
							},
						},
					},
				},
			},
		},
	}
}

func TestRunCRDSchemaValidation(t *testing.T) {
	ctx := context.Background()
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	expectations := []crdSchemaExpectation{
		{
			crdName:         "tests.velero.io",
			specType:        reflect.TypeFor[testSpec](),
			apiGroupVersion: "v1",
		},
	}

	t.Run("matching schema passes", func(t *testing.T) {
		crd := makeCRD("tests.velero.io", "v1",
			map[string]apiextv1.JSONSchemaProps{
				"name":  {Type: "string"},
				"count": {Type: "integer"},
			}, nil)
		client := fakeapiext.NewSimpleClientset([]runtime.Object{crd}...)
		err := runCRDSchemaValidation(ctx, client, expectations, "strict", logger)
		assert.NoError(t, err)
	})

	t.Run("missing field in strict mode returns error", func(t *testing.T) {
		crd := makeCRD("tests.velero.io", "v1",
			map[string]apiextv1.JSONSchemaProps{
				"name": {Type: "string"},
			}, nil)
		client := fakeapiext.NewSimpleClientset([]runtime.Object{crd}...)
		err := runCRDSchemaValidation(ctx, client, expectations, "strict", logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "count")
		assert.Contains(t, err.Error(), "CRD schema mismatch")
	})

	t.Run("missing field in warn mode logs but no error", func(t *testing.T) {
		crd := makeCRD("tests.velero.io", "v1",
			map[string]apiextv1.JSONSchemaProps{
				"name": {Type: "string"},
			}, nil)
		client := fakeapiext.NewSimpleClientset([]runtime.Object{crd}...)
		err := runCRDSchemaValidation(ctx, client, expectations, "warn", logger)
		assert.NoError(t, err)
	})

	t.Run("CRD not found in strict mode returns error", func(t *testing.T) {
		client := fakeapiext.NewSimpleClientset()
		err := runCRDSchemaValidation(ctx, client, expectations, "strict", logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tests.velero.io")
		assert.Contains(t, err.Error(), "could not fetch")
	})

	t.Run("CRD not found in warn mode logs warning but no error", func(t *testing.T) {
		client := fakeapiext.NewSimpleClientset()
		err := runCRDSchemaValidation(ctx, client, expectations, "warn", logger)
		assert.NoError(t, err)
	})

	t.Run("CRD with no schema for version in strict mode returns error", func(t *testing.T) {
		crd := makeCRD("tests.velero.io", "v2",
			map[string]apiextv1.JSONSchemaProps{
				"name": {Type: "string"},
			}, nil)
		client := fakeapiext.NewSimpleClientset([]runtime.Object{crd}...)
		err := runCRDSchemaValidation(ctx, client, expectations, "strict", logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tests.velero.io")
		assert.Contains(t, err.Error(), "no OpenAPI schema for version")
	})

	t.Run("CRD with no schema for version in warn mode logs warning but no error", func(t *testing.T) {
		crd := makeCRD("tests.velero.io", "v2",
			map[string]apiextv1.JSONSchemaProps{
				"name": {Type: "string"},
			}, nil)
		client := fakeapiext.NewSimpleClientset([]runtime.Object{crd}...)
		err := runCRDSchemaValidation(ctx, client, expectations, "warn", logger)
		assert.NoError(t, err)
	})

	t.Run("extra fields in CRD are OK", func(t *testing.T) {
		crd := makeCRD("tests.velero.io", "v1",
			map[string]apiextv1.JSONSchemaProps{
				"name":     {Type: "string"},
				"count":    {Type: "integer"},
				"newField": {Type: "string"},
			}, nil)
		client := fakeapiext.NewSimpleClientset([]runtime.Object{crd}...)
		err := runCRDSchemaValidation(ctx, client, expectations, "strict", logger)
		assert.NoError(t, err)
	})
}
