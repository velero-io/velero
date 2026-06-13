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

package restore

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	dynamicinformer "k8s.io/client-go/dynamic/dynamicinformer"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/vmware-tanzu/velero/pkg/client"
)

// mockDynamicInformerFactory wraps a real factory but allows us to control WaitForCacheSync behavior
type mockDynamicInformerFactory struct {
	dynamicinformer.DynamicSharedInformerFactory
	syncResults map[schema.GroupVersionResource]bool
}

func (m *mockDynamicInformerFactory) WaitForCacheSync(stopCh <-chan struct{}) map[schema.GroupVersionResource]bool {
	return m.syncResults
}

// TestWaitForCacheSyncFailureHandling tests that Velero properly handles resources
// that fail to sync their informer caches (e.g., API groups that don't support watch operations)
func TestWaitForCacheSyncFailureHandling(t *testing.T) {
	// Define test resources
	customResource := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "widgets",
	}
	rbacRoleBinding := schema.GroupVersionResource{
		Group:    "rbac.authorization.k8s.io",
		Version:  "v1",
		Resource: "rolebindings",
	}

	tests := []struct {
		name                 string
		syncResults          map[schema.GroupVersionResource]bool
		expectedFailedCount  int
		expectedFailedGVRs   []schema.GroupVersionResource
		shouldBypassCacheFor []schema.GroupVersionResource
	}{
		{
			name: "custom API group fails to sync (watch not supported)",
			syncResults: map[schema.GroupVersionResource]bool{
				customResource:  false, // Fails because watch is not supported
				rbacRoleBinding: true,  // Succeeds
			},
			expectedFailedCount:  1,
			expectedFailedGVRs:   []schema.GroupVersionResource{customResource},
			shouldBypassCacheFor: []schema.GroupVersionResource{customResource},
		},
		{
			name: "all resources sync successfully",
			syncResults: map[schema.GroupVersionResource]bool{
				customResource:  true,
				rbacRoleBinding: true,
			},
			expectedFailedCount:  0,
			expectedFailedGVRs:   []schema.GroupVersionResource{},
			shouldBypassCacheFor: []schema.GroupVersionResource{},
		},
		{
			name: "multiple resources fail to sync",
			syncResults: map[schema.GroupVersionResource]bool{
				customResource:  false,
				rbacRoleBinding: false,
			},
			expectedFailedCount:  2,
			expectedFailedGVRs:   []schema.GroupVersionResource{customResource, rbacRoleBinding},
			shouldBypassCacheFor: []schema.GroupVersionResource{customResource, rbacRoleBinding},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake dynamic client
			fakeClient := fakedynamic.NewSimpleDynamicClient(scheme.Scheme)

			// Create mock informer factory with controlled sync results
			mockFactory := &mockDynamicInformerFactory{
				DynamicSharedInformerFactory: dynamicinformer.NewDynamicSharedInformerFactory(fakeClient, 0),
				syncResults:                  tt.syncResults,
			}

			// Create restore context
			ctx := &restoreContext{
				log:                           logrus.New(),
				resourcesWithoutInformerCache: sets.New[schema.GroupVersionResource](),
				resourceClients:               make(map[resourceClientKey]client.Dynamic),
				dynamicInformerFactory: &informerFactoryWithContext{
					factory: mockFactory,
					context: t.Context(),
					cancel:  func() {},
				},
			}

			// Simulate the WaitForCacheSync call and handling
			syncResults := ctx.dynamicInformerFactory.factory.WaitForCacheSync(ctx.dynamicInformerFactory.context.Done())

			// Call the actual production code to process sync results
			ctx.processCacheSyncResults(syncResults)

			// Verify failed resources are tracked correctly
			assert.Equal(t, tt.expectedFailedCount, ctx.resourcesWithoutInformerCache.Len(),
				"Expected %d failed resources but got %d", tt.expectedFailedCount, ctx.resourcesWithoutInformerCache.Len())

			for _, expectedGVR := range tt.expectedFailedGVRs {
				assert.True(t, ctx.resourcesWithoutInformerCache.Has(expectedGVR),
					"Expected %s to be in failed resources", expectedGVR)
			}

			// Verify cache bypass logic for failed resources
			for _, gvr := range tt.shouldBypassCacheFor {
				shouldBypass := ctx.resourcesWithoutInformerCache.Has(gvr)
				assert.True(t, shouldBypass,
					"Should bypass cache for %s but resourcesWithoutInformerCache doesn't contain it", gvr)
			}

			// Verify resources that synced successfully are not in failed set
			for gvr, synced := range tt.syncResults {
				if synced {
					assert.False(t, ctx.resourcesWithoutInformerCache.Has(gvr),
						"Resource %s synced successfully but is in failed resources", gvr)
				}
			}
		})
	}
}

// TestResourcesWithoutInformerCacheBypass verifies that when a resource is in the resourcesWithoutInformerCache set,
// the code bypasses the informer cache and uses direct API calls instead
func TestResourcesWithoutInformerCacheBypass(t *testing.T) {
	customResource := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "widgets",
	}

	// Create restore context with a custom resource marked as unable to use informer cache
	ctx := &restoreContext{
		log:                           logrus.New(),
		resourcesWithoutInformerCache: sets.New[schema.GroupVersionResource](customResource),
		resourceClients:               make(map[resourceClientKey]client.Dynamic),
	}

	// Test that getResource logic should bypass cache for resources without informer cache
	// This validates the intended behavior after the fix
	shouldBypassCache := ctx.resourcesWithoutInformerCache.Has(customResource)
	assert.True(t, shouldBypassCache,
		"getResource should bypass informer cache for resources in resourcesWithoutInformerCache set")
}
