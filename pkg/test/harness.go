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

package test

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

type refreshable interface {
	Refresh() error
}

// Harness wraps an APIServer and provides AddResource for seeding
// the fake API server with resources and items.
// It is shared across delete, restore, and backup test packages.
type Harness struct {
	*APIServer
}

// NewHarness creates a Harness from an existing APIServer.
func NewHarness(t *testing.T, apiServer *APIServer) *Harness {
	t.Helper()
	require.NotNil(t, apiServer, "apiServer must not be nil")
	return &Harness{APIServer: apiServer}
}

// AddResource registers an API resource with the discovery client,
// refreshes the discovery helper, and creates all of the resource's
// items in the fake dynamic client.
func (h *Harness) AddResource(t *testing.T, dh refreshable, resource *APIResource) {
	t.Helper()

	h.DiscoveryClient.WithAPIResource(resource)
	require.NoError(t, dh.Refresh())

	for _, item := range resource.Items {
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
		require.NoError(t, err)

		unstructuredObj := &unstructured.Unstructured{Object: obj}

		// These fields have non-nil zero values in the unstructured objects. We remove
		// them to make comparison easier in our tests.
		unstructured.RemoveNestedField(unstructuredObj.Object, "metadata", "creationTimestamp")
		unstructured.RemoveNestedField(unstructuredObj.Object, "status")

		if resource.Namespaced {
			_, err = h.DynamicClient.Resource(resource.GVR()).Namespace(item.GetNamespace()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		} else {
			_, err = h.DynamicClient.Resource(resource.GVR()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		}
		require.NoError(t, err)
	}
}
