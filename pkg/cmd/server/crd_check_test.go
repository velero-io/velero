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

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
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

// testSpecWithInlineEmbedded mirrors BackupStorageLocationSpec embedding
// StorageType with `json:",inline"` — the Kubernetes structural-schema
// convention for promoting an embedded struct's fields, distinct from both
// the no-tag case and a named-tag nested object.
type testSpecWithInlineEmbedded struct {
	TestBase `json:",inline"`
	Extra    string `json:"extra"`
}

func TestJsonFields(t *testing.T) {
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
			result := jsonFields(tc.input)
			if tc.expected == nil {
				assert.Nil(t, result)
				return
			}
			for _, field := range tc.expected {
				_, ok := result[field]
				assert.True(t, ok, "expected field %q", field)
			}
			_, hasIgnored := result["Ignored"]
			_, hasPrivate := result["private"]
			assert.False(t, hasIgnored)
			assert.False(t, hasPrivate)
		})
	}

	t.Run("embedded field with explicit json tag name is not promoted", func(t *testing.T) {
		result := jsonFields(reflect.TypeFor[testSpecWithNamedEmbedded]())
		_, hasBase := result["base"]
		_, hasExtra := result["extra"]
		_, hasName := result["name"]
		_, hasCount := result["count"]
		assert.True(t, hasBase)
		assert.True(t, hasExtra)
		assert.False(t, hasName, "embedded fields should nest under their tag name, not promote")
		assert.False(t, hasCount, "embedded fields should nest under their tag name, not promote")
		// The named-embedded field is itself a struct, so it should be
		// reported as nested for recursion rather than a plain leaf.
		require.NotNil(t, result["base"].nestedTyp)
	})

	t.Run("embedded field tagged json:,inline is promoted like an untagged one", func(t *testing.T) {
		result := jsonFields(reflect.TypeFor[testSpecWithInlineEmbedded]())
		_, hasName := result["name"]
		_, hasCount := result["count"]
		_, hasExtra := result["extra"]
		_, hasBase := result["base"]
		assert.True(t, hasName)
		assert.True(t, hasCount)
		assert.True(t, hasExtra)
		assert.False(t, hasBase, "\",inline\" tag has no name to nest under")
	})

	t.Run("real BackupStorageLocationSpec promotes inline-embedded StorageType", func(t *testing.T) {
		result := jsonFields(reflect.TypeFor[velerov1api.BackupStorageLocationSpec]())
		_, hasObjectStorage := result["objectStorage"]
		_, hasProvider := result["provider"]
		assert.True(t, hasObjectStorage,
			"StorageType is embedded with `json:\\\",inline\\\"` and must be flattened, not dropped")
		assert.True(t, hasProvider)
	})

	t.Run("omitempty marks a field optional, its absence does not", func(t *testing.T) {
		result := jsonFields(reflect.TypeFor[testSpec]())
		assert.True(t, result["count"].optional, "count carries omitempty")
		assert.False(t, result["name"].optional, "name has no omitempty")
	})

	t.Run("struct-typed field is reported as nested for recursion", func(t *testing.T) {
		type withNested struct {
			Base TestBase `json:"base"`
		}
		result := jsonFields(reflect.TypeFor[withNested]())
		require.NotNil(t, result["base"].nestedTyp)
		assert.Equal(t, reflect.TypeFor[TestBase](), result["base"].nestedTyp)
	})

	t.Run("pointer-to-struct field is unwrapped and reported as nested", func(t *testing.T) {
		type withNestedPtr struct {
			Base *TestBase `json:"base"`
		}
		result := jsonFields(reflect.TypeFor[withNestedPtr]())
		require.NotNil(t, result["base"].nestedTyp)
		assert.Equal(t, reflect.TypeFor[TestBase](), result["base"].nestedTyp)
	})

	t.Run("struct field with a custom json.Marshaler is NOT reported as nested (regression)", func(t *testing.T) {
		// metav1.Duration/metav1.Time marshal to a scalar (string), not a JSON object --
		// recursing into their internal Go fields as if they were a nested CRD schema
		// object produces false "missing field" reports against a real, unmodified CRD.
		// This is the exact bug that broke the kind e2e CRDSchemaCheck suite (all versions)
		// against backuprepositories.velero.io's maintenanceFrequency/lastMaintenanceTime.
		type withTimeAndDuration struct {
			MaintenanceFrequency metav1.Duration `json:"maintenanceFrequency"`
			LastMaintenanceTime  *metav1.Time    `json:"lastMaintenanceTime,omitempty"`
		}
		result := jsonFields(reflect.TypeFor[withTimeAndDuration]())
		assert.Nil(t, result["maintenanceFrequency"].nestedTyp, "metav1.Duration must not be recursed into")
		assert.Nil(t, result["lastMaintenanceTime"].nestedTyp, "*metav1.Time must not be recursed into")
	})
}

func TestSchemaNodeAt(t *testing.T) {
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

	t.Run("extract spec node", func(t *testing.T) {
		result, ok := schemaNodeAt(schema, "spec")
		require.True(t, ok)
		require.NotNil(t, result)
		_, hasName := result.Properties["name"]
		_, hasCount := result.Properties["count"]
		assert.True(t, hasName)
		assert.True(t, hasCount)
		assert.Len(t, result.Properties, 2)
	})

	t.Run("extract status node", func(t *testing.T) {
		result, ok := schemaNodeAt(schema, "status")
		require.True(t, ok)
		require.NotNil(t, result)
		_, hasPhase := result.Properties["phase"]
		_, hasMessage := result.Properties["message"]
		assert.True(t, hasPhase)
		assert.True(t, hasMessage)
	})

	t.Run("nonexistent path", func(t *testing.T) {
		result, ok := schemaNodeAt(schema, "nonexistent")
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("nil schema", func(t *testing.T) {
		result, ok := schemaNodeAt(nil, "spec")
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("section present but empty", func(t *testing.T) {
		emptySchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {},
			},
		}
		result, ok := schemaNodeAt(emptySchema, "spec")
		assert.True(t, ok)
		require.NotNil(t, result)
		assert.Empty(t, result.Properties)
	})

	t.Run("nested dotted path", func(t *testing.T) {
		nested := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"objectStorage": {
							Properties: map[string]apiextv1.JSONSchemaProps{
								"caCertRef": {Type: "string"},
							},
						},
					},
				},
			},
		}
		result, ok := schemaNodeAt(nested, "spec.objectStorage")
		require.True(t, ok)
		require.NotNil(t, result)
		_, hasCaCertRef := result.Properties["caCertRef"]
		assert.True(t, hasCaCertRef)
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

	t.Run("nested struct field: missing nested property is detected", func(t *testing.T) {
		type nestedSpec struct {
			ObjectStorage TestBase `json:"objectStorage"`
		}
		// CRD declares objectStorage but only "name", missing "count".
		schemaMissingNested := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"objectStorage": {
							Properties: map[string]apiextv1.JSONSchemaProps{
								"name": {Type: "string"},
							},
						},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[nestedSpec](), schemaMissingNested, "spec", "backupstoragelocations.velero.io")
		assert.Contains(t, missing, "backupstoragelocations.velero.io: spec.objectStorage.count")
	})

	t.Run("nested struct field: fully present nested property is not flagged", func(t *testing.T) {
		type nestedSpec struct {
			ObjectStorage TestBase `json:"objectStorage"`
		}
		fullNestedSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"objectStorage": {
							Properties: map[string]apiextv1.JSONSchemaProps{
								"name":  {Type: "string"},
								"count": {Type: "integer"},
							},
						},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[nestedSpec](), fullNestedSchema, "spec", "backupstoragelocations.velero.io")
		assert.Empty(t, missing)
	})

	t.Run("required-field mismatch: CRD requires a field the server treats as optional", func(t *testing.T) {
		type repoSpec struct {
			ResticIdentifier string `json:"resticIdentifier,omitempty"`
		}
		strictSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Required: []string{"resticIdentifier"},
					Properties: map[string]apiextv1.JSONSchemaProps{
						"resticIdentifier": {Type: "string"},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[repoSpec](), strictSchema, "spec", "backuprepositories.velero.io")
		require.Len(t, missing, 1)
		assert.Contains(t, missing[0], "resticIdentifier")
		assert.Contains(t, missing[0], "required by installed CRD but optional")
	})

	t.Run("required-field match: CRD does not require what the server treats as optional", func(t *testing.T) {
		type repoSpec struct {
			ResticIdentifier string `json:"resticIdentifier,omitempty"`
		}
		looseSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Properties: map[string]apiextv1.JSONSchemaProps{
						"resticIdentifier": {Type: "string"},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[repoSpec](), looseSchema, "spec", "backuprepositories.velero.io")
		assert.Empty(t, missing)
	})

	t.Run("required-field on server-required field is fine even if CRD also requires it", func(t *testing.T) {
		type repoSpec struct {
			ResticIdentifier string `json:"resticIdentifier"`
		}
		strictSchema := &apiextv1.JSONSchemaProps{
			Properties: map[string]apiextv1.JSONSchemaProps{
				"spec": {
					Required: []string{"resticIdentifier"},
					Properties: map[string]apiextv1.JSONSchemaProps{
						"resticIdentifier": {Type: "string"},
					},
				},
			},
		}
		missing := checkMissing(reflect.TypeFor[repoSpec](), strictSchema, "spec", "backuprepositories.velero.io")
		assert.Empty(t, missing)
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
