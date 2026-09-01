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

package itemblock

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// newUnstructuredItem creates an unstructured object with the given apiVersion,
// kind, namespace, and name for use in tests.
func newUnstructuredItem(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": apiVersion,
			"kind":       kind,
			"metadata": map[string]any{
				"namespace": namespace,
				"name":      name,
			},
		},
	}
}

func TestAddUnstructured(t *testing.T) {
	tests := []struct {
		name        string
		items       []ItemBlockItem
		expectedLen int
	}{
		{
			name: "add single item to empty block",
			items: []ItemBlockItem{
				{
					Gr:           schema.GroupResource{Group: "apps", Resource: "deployments"},
					Item:         newUnstructuredItem("apps/v1", "Deployment", "default", "nginx"),
					PreferredGVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
				},
			},
			expectedLen: 1,
		},
		{
			name: "add multiple items",
			items: []ItemBlockItem{
				{
					Gr:           schema.GroupResource{Group: "", Resource: "pods"},
					Item:         newUnstructuredItem("v1", "Pod", "default", "pod-1"),
					PreferredGVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
				},
				{
					Gr:           schema.GroupResource{Group: "", Resource: "services"},
					Item:         newUnstructuredItem("v1", "Service", "kube-system", "kube-dns"),
					PreferredGVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
				},
				{
					Gr:           schema.GroupResource{Group: "apps", Resource: "deployments"},
					Item:         newUnstructuredItem("apps/v1", "Deployment", "default", "web"),
					PreferredGVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
				},
			},
			expectedLen: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ib := &ItemBlock{
				Log: logrus.New(),
			}

			for _, item := range tc.items {
				ib.AddUnstructured(item.Gr, item.Item, item.PreferredGVR)
			}

			require.Len(t, ib.Items, tc.expectedLen)

			// Verify each added item matches what was provided
			for i, item := range tc.items {
				assert.Equal(t, item.Gr, ib.Items[i].Gr)
				assert.Equal(t, item.Item, ib.Items[i].Item)
				assert.Equal(t, item.PreferredGVR, ib.Items[i].PreferredGVR)
			}
		})
	}
}

func TestFindItem(t *testing.T) {
	podsGR := schema.GroupResource{Group: "", Resource: "pods"}
	deploymentsGR := schema.GroupResource{Group: "apps", Resource: "deployments"}
	servicesGR := schema.GroupResource{Group: "", Resource: "services"}

	podsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	deploymentsGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	tests := []struct {
		name            string
		existingItems   []ItemBlockItem
		searchGR        schema.GroupResource
		searchNamespace string
		searchName      string
		expectedCount   int
		// If set, verifies the names in the returned items are in this exact order
		expectedNames []string
	}{
		{
			name:            "find item in empty block returns nil",
			existingItems:   nil,
			searchGR:        podsGR,
			searchNamespace: "default",
			searchName:      "pod-1",
			expectedCount:   0,
		},
		{
			name: "find matching item by GR, namespace, and name",
			existingItems: []ItemBlockItem{
				{
					Gr:           podsGR,
					Item:         newUnstructuredItem("v1", "Pod", "default", "pod-1"),
					PreferredGVR: podsGVR,
				},
			},
			searchGR:        podsGR,
			searchNamespace: "default",
			searchName:      "pod-1",
			expectedCount:   1,
			expectedNames:   []string{"pod-1"},
		},
		{
			name: "no match when GR differs",
			existingItems: []ItemBlockItem{
				{
					Gr:           podsGR,
					Item:         newUnstructuredItem("v1", "Pod", "default", "pod-1"),
					PreferredGVR: podsGVR,
				},
			},
			searchGR:        deploymentsGR,
			searchNamespace: "default",
			searchName:      "pod-1",
			expectedCount:   0,
		},
		{
			name: "no match when namespace differs",
			existingItems: []ItemBlockItem{
				{
					Gr:           podsGR,
					Item:         newUnstructuredItem("v1", "Pod", "default", "pod-1"),
					PreferredGVR: podsGVR,
				},
			},
			searchGR:        podsGR,
			searchNamespace: "kube-system",
			searchName:      "pod-1",
			expectedCount:   0,
		},
		{
			name: "no match when name differs",
			existingItems: []ItemBlockItem{
				{
					Gr:           podsGR,
					Item:         newUnstructuredItem("v1", "Pod", "default", "pod-1"),
					PreferredGVR: podsGVR,
				},
			},
			searchGR:        podsGR,
			searchNamespace: "default",
			searchName:      "pod-2",
			expectedCount:   0,
		},
		{
			name: "nil item is skipped",
			existingItems: []ItemBlockItem{
				{
					Gr:           podsGR,
					Item:         nil,
					PreferredGVR: podsGVR,
				},
			},
			searchGR:        podsGR,
			searchNamespace: "default",
			searchName:      "pod-1",
			expectedCount:   0,
		},
		{
			name: "preferred GVR match is returned first",
			existingItems: []ItemBlockItem{
				{
					Gr:           deploymentsGR,
					Item:         newUnstructuredItem("apps/v1beta1", "Deployment", "default", "web"),
					PreferredGVR: deploymentsGVR, // preferred is v1, item is v1beta1 → non-preferred
				},
				{
					Gr:           deploymentsGR,
					Item:         newUnstructuredItem("apps/v1", "Deployment", "default", "web"),
					PreferredGVR: deploymentsGVR, // preferred is v1, item is v1 → preferred match
				},
			},
			searchGR:        deploymentsGR,
			searchNamespace: "default",
			searchName:      "web",
			expectedCount:   2,
			expectedNames:   []string{"web", "web"},
		},
		{
			name: "multiple non-preferred items returned when no preferred match",
			existingItems: []ItemBlockItem{
				{
					Gr:           deploymentsGR,
					Item:         newUnstructuredItem("apps/v1beta1", "Deployment", "default", "web"),
					PreferredGVR: deploymentsGVR,
				},
				{
					Gr:           deploymentsGR,
					Item:         newUnstructuredItem("apps/v1beta2", "Deployment", "default", "web"),
					PreferredGVR: deploymentsGVR,
				},
			},
			searchGR:        deploymentsGR,
			searchNamespace: "default",
			searchName:      "web",
			expectedCount:   2,
		},
		{
			name: "item with unparsable apiVersion is treated as non-preferred",
			existingItems: []ItemBlockItem{
				{
					Gr:           deploymentsGR,
					Item:         newUnstructuredItem("not/a/valid/version", "Deployment", "default", "web"),
					PreferredGVR: deploymentsGVR,
				},
			},
			searchGR:        deploymentsGR,
			searchNamespace: "default",
			searchName:      "web",
			expectedCount:   1,
		},
		{
			name: "only matching GR items are returned from mixed block",
			existingItems: []ItemBlockItem{
				{
					Gr:           podsGR,
					Item:         newUnstructuredItem("v1", "Pod", "default", "app"),
					PreferredGVR: podsGVR,
				},
				{
					Gr:           deploymentsGR,
					Item:         newUnstructuredItem("apps/v1", "Deployment", "default", "app"),
					PreferredGVR: deploymentsGVR,
				},
				{
					Gr:           servicesGR,
					Item:         newUnstructuredItem("v1", "Service", "default", "app"),
					PreferredGVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
				},
			},
			searchGR:        deploymentsGR,
			searchNamespace: "default",
			searchName:      "app",
			expectedCount:   1,
			expectedNames:   []string{"app"},
		},
		{
			name: "cluster-scoped item found with empty namespace",
			existingItems: []ItemBlockItem{
				{
					Gr:   schema.GroupResource{Group: "", Resource: "namespaces"},
					Item: newUnstructuredItem("v1", "Namespace", "", "production"),
					PreferredGVR: schema.GroupVersionResource{
						Group: "", Version: "v1", Resource: "namespaces",
					},
				},
			},
			searchGR:        schema.GroupResource{Group: "", Resource: "namespaces"},
			searchNamespace: "",
			searchName:      "production",
			expectedCount:   1,
			expectedNames:   []string{"production"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ib := &ItemBlock{
				Log:   logrus.New(),
				Items: tc.existingItems,
			}

			result := ib.FindItem(tc.searchGR, tc.searchNamespace, tc.searchName)

			require.Len(t, result, tc.expectedCount)

			if tc.expectedNames != nil {
				for i, expectedName := range tc.expectedNames {
					assert.Equal(t, expectedName, result[i].Item.GetName())
				}
			}
		})
	}
}

func TestFindItemPreferredOrdering(t *testing.T) {
	deploymentsGR := schema.GroupResource{Group: "apps", Resource: "deployments"}
	deploymentsGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

	// Insert non-preferred first, preferred second to verify ordering
	ib := &ItemBlock{
		Log: logrus.New(),
		Items: []ItemBlockItem{
			{
				Gr:           deploymentsGR,
				Item:         newUnstructuredItem("apps/v1beta1", "Deployment", "ns", "deploy"),
				PreferredGVR: deploymentsGVR,
			},
			{
				Gr:           deploymentsGR,
				Item:         newUnstructuredItem("apps/v1", "Deployment", "ns", "deploy"),
				PreferredGVR: deploymentsGVR,
			},
			{
				Gr:           deploymentsGR,
				Item:         newUnstructuredItem("apps/v1beta2", "Deployment", "ns", "deploy"),
				PreferredGVR: deploymentsGVR,
			},
		},
	}

	result := ib.FindItem(deploymentsGR, "ns", "deploy")

	require.Len(t, result, 3)

	// The preferred match (apps/v1) should be first, regardless of insertion order
	assert.Equal(t, "apps/v1", result[0].Item.GetAPIVersion(),
		"preferred GVR match should be returned first")

	// Non-preferred items follow in insertion order
	assert.Equal(t, "apps/v1beta1", result[1].Item.GetAPIVersion())
	assert.Equal(t, "apps/v1beta2", result[2].Item.GetAPIVersion())
}
