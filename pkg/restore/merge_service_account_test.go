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
package restore

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	velerotest "github.com/velero-io/velero/pkg/test"
)

var mergedServiceAccountsBenchmarkResult *unstructured.Unstructured

func BenchmarkMergeServiceAccountBasic(b *testing.B) {
	tests := []struct {
		name        string
		fromCluster *unstructured.Unstructured
		fromBackup  *unstructured.Unstructured
	}{
		{
			name: "only default tokens present",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			fromBackup: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-xzy12" }
					]
				}`,
			),
		},
		{
			name: "service accounts with multiple secrets",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" },
						{ "name": "my-secret" },
						{ "name": "sekrit" }
					]
				}`,
			),

			fromBackup: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-xzy12" },
						{ "name": "my-old-secret" },
						{ "name": "secrete"}
					]
				}`,
			),
		},
		{
			name: "service accounts with labels and annotations",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"labels": {
							"l1": "v1",
							"l2": "v2",
							"l3": "v3"
						},
						"annotations": {
							"a1": "v1",
							"a2": "v2",
							"a3": "v3",
							"a4": "v4"
						}
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),

			fromBackup: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"labels": {
							"l1": "v1",
							"l2": "v2",
							"l3": "v3",
							"l4": "v4",
							"l5": "v5"
						},
						"annotations": {
							"a1": "v1",
							"a2": "v2",
							"a3": "v3",
							"a4": "v4",
							"a5": "v5",
							"a6": "v6"
						}
					},
					"secrets": [
						{ "name": "default-token-xzy12" }
					]
				}`,
			),
		},
	}

	var desired *unstructured.Unstructured

	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				desired, _ = mergeServiceAccounts(test.fromCluster, test.fromBackup)
			}

			mergedServiceAccountsBenchmarkResult = desired
		})
	}
}

func TestMergeLocalObjectReferenceSlices(t *testing.T) {
	tests := []struct {
		name     string
		first    []corev1api.LocalObjectReference
		second   []corev1api.LocalObjectReference
		expected []corev1api.LocalObjectReference
	}{
		{
			name: "two slices without overlapping elements",
			first: []corev1api.LocalObjectReference{
				{Name: "lor1"},
				{Name: "lor2"},
			},
			second: []corev1api.LocalObjectReference{
				{Name: "lor3"},
				{Name: "lor4"},
			},
			expected: []corev1api.LocalObjectReference{
				{Name: "lor1"},
				{Name: "lor2"},
				{Name: "lor3"},
				{Name: "lor4"},
			},
		},
		{
			name: "two slices with an overlapping element",
			first: []corev1api.LocalObjectReference{
				{Name: "lor1"},
				{Name: "lor2"},
			},
			second: []corev1api.LocalObjectReference{
				{Name: "lor3"},
				{Name: "lor2"},
			},
			expected: []corev1api.LocalObjectReference{
				{Name: "lor1"},
				{Name: "lor2"},
				{Name: "lor3"},
			},
		},
		{
			name: "merging always adds elements to the end",
			first: []corev1api.LocalObjectReference{
				{Name: "lor3"},
				{Name: "lor4"},
			},
			second: []corev1api.LocalObjectReference{
				{Name: "lor1"},
				{Name: "lor2"},
			},
			expected: []corev1api.LocalObjectReference{
				{Name: "lor3"},
				{Name: "lor4"},
				{Name: "lor1"},
				{Name: "lor2"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mergeLocalObjectReferenceSlices(test.first, test.second)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestMergeObjectReferenceSlices(t *testing.T) {
	tests := []struct {
		name     string
		first    []corev1api.ObjectReference
		second   []corev1api.ObjectReference
		expected []corev1api.ObjectReference
	}{
		{
			name: "two slices without overlapping elements",
			first: []corev1api.ObjectReference{
				{Name: "or1"},
				{Name: "or2"},
			},
			second: []corev1api.ObjectReference{
				{Name: "or3"},
				{Name: "or4"},
			},
			expected: []corev1api.ObjectReference{
				{Name: "or1"},
				{Name: "or2"},
				{Name: "or3"},
				{Name: "or4"},
			},
		},
		{
			name: "two slices with an overlapping element",
			first: []corev1api.ObjectReference{
				{Name: "or1"},
				{Name: "or2"},
			},
			second: []corev1api.ObjectReference{
				{Name: "or3"},
				{Name: "or2"},
			},
			expected: []corev1api.ObjectReference{
				{Name: "or1"},
				{Name: "or2"},
				{Name: "or3"},
			},
		},
		{
			name: "merging always adds elements to the end",
			first: []corev1api.ObjectReference{
				{Name: "or3"},
				{Name: "or4"},
			},
			second: []corev1api.ObjectReference{
				{Name: "or1"},
				{Name: "or2"},
			},
			expected: []corev1api.ObjectReference{
				{Name: "or3"},
				{Name: "or4"},
				{Name: "or1"},
				{Name: "or2"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := mergeObjectReferenceSlices(test.first, test.second)
			assert.Equal(t, test.expected, result)
		})
	}
}

// stripWhitespace removes any Unicode whitespace from a string.
// Useful for cleaning up formatting on expected JSON strings before comparison
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func TestMergeMaps(t *testing.T) {
	var testCases = []struct {
		name        string
		source      map[string]string
		destination map[string]string
		expected    map[string]string
	}{
		{
			name:        "nil destination should result in source being copied",
			destination: nil,
			source: map[string]string{
				"k1": "v1",
			},
			expected: map[string]string{
				"k1": "v1",
			},
		},
		{
			name: "keys missing from destination should be copied from source",
			destination: map[string]string{
				"k2": "v2",
			},
			source: map[string]string{
				"k1": "v1",
			},
			expected: map[string]string{
				"k1": "v1",
				"k2": "v2",
			},
		},
		{
			name: "matching key should not have value copied from source",
			destination: map[string]string{
				"k1": "v1",
			},
			source: map[string]string{
				"k1": "v2",
			},
			expected: map[string]string{
				"k1": "v1",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mergeMaps(tc.destination, tc.source)

			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGeneratePatch(t *testing.T) {
	tests := []struct {
		name           string
		fromCluster    *unstructured.Unstructured
		desired        *unstructured.Unstructured
		expectedString string
		expectedErr    bool
	}{
		{
			name: "objects are equal, no patch needed",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			desired: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			expectedString: "",
			expectedErr:    false,
		},
		{
			name: "patch is required when labels are present",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			desired: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"labels": {
							"label1": "value1",
							"label2": "value2"
						}
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			expectedString: stripWhitespace(
				`{
					"metadata": {
						"labels": {
							"label1":"value1",
							"label2":"value2"
						}
					}
				}`,
			),
			expectedErr: false,
		},
		{
			name: "patch is required when annotations are present",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			desired: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"annotations" :{
							"a1": "v1",
							"a2": "v2"
						}
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			expectedString: stripWhitespace(
				`{
					"metadata": {
						"annotations": {
							"a1":"v1",
							"a2":"v2"
						}
					}
				}`,
			),
			expectedErr: false,
		},
		{
			name: "patch is required many secrets are present",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			desired: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" },
						{ "name": "sekrit" },
						{ "name": "secrete" }
					]
				}`,
			),
			expectedString: stripWhitespace(
				`{
					"secrets": [
						{"name": "default-token-abcde"},
						{"name": "sekrit"},
						{"name": "secrete"}
					]
				}`,
			),
			expectedErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := generatePatch(test.fromCluster, test.desired)
			if assert.Equal(t, test.expectedErr, err != nil) {
				assert.Equal(t, test.expectedString, string(result))
			}
		})
	}
}

func TestMergeServiceAccountBasic(t *testing.T) {
	tests := []struct {
		name        string
		fromCluster *unstructured.Unstructured
		fromBackup  *unstructured.Unstructured
		expectedRes *unstructured.Unstructured
		expectedErr bool
	}{
		{
			name: "only default token",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			// fromBackup doesn't have the default token because it is expected to already have been removed
			// by the service account action
			fromBackup: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": []
				}`,
			),
			expectedRes: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
		},
		{
			name: "service accounts with multiple secrets",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" },
						{ "name": "my-secret" },
						{ "name": "sekrit" }
					]
				}`,
			),
			// fromBackup doesn't have the default token because it is expected to already have been removed
			// by the service account action
			fromBackup: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "my-old-secret" },
						{ "name": "secrete"}
					]
				}`,
			),
			expectedRes: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default"
					},
					"secrets": [
						{ "name": "default-token-abcde" },
						{ "name": "my-secret" },
						{ "name": "sekrit" },
						{ "name": "my-old-secret" },
						{ "name": "secrete"}
					]
				}`,
			),
		},
		{
			name: "service accounts with labels and annotations",
			fromCluster: velerotest.UnstructuredOrDie(
				`{
					"apiVersion": "v1",
					"kind": "ServiceAccount",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"labels": {
							"l1": "v1",
							"l2": "v2",
							"l3": "v3"
						},
						"annotations": {
							"a1": "v1",
							"a2": "v2",
							"a3": "v3",
							"a4": "v4"
						}
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
			// fromBackup doesn't have the default token because it is expected to already have been removed
			// by the service account action
			fromBackup: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"labels": {
							"l1": "v1",
							"l2": "v2",
							"l3": "v3",
							"l4": "v4",
							"l5": "v5"
						},
						"annotations": {
							"a1": "v1",
							"a2": "v2",
							"a3": "v3",
							"a4": "v4",
							"a5": "v5",
							"a6": "v6"
						}
					},
					"secrets": []
				}`,
			),
			expectedRes: velerotest.UnstructuredOrDie(
				`{
					"kind": "ServiceAccount",
					"apiVersion": "v1",
					"metadata": {
						"namespace": "ns1",
						"name": "default",
						"labels": {
							"l1": "v1",
							"l2": "v2",
							"l3": "v3",
							"l4": "v4",
							"l5": "v5"
						},
						"annotations": {
							"a1": "v1",
							"a2": "v2",
							"a3": "v3",
							"a4": "v4",
							"a5": "v5",
							"a6": "v6"
						}
					},
					"secrets": [
						{ "name": "default-token-abcde" }
					]
				}`,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := mergeServiceAccounts(test.fromCluster, test.fromBackup)
			require.NoError(t, err)
			assert.Equal(t, test.expectedRes, result)
		})
	}
}
