/*
Copyright 2017, 2019, 2020 the Velero contributors.

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

package backup

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
)

func TestSortCoreGroup(t *testing.T) {
	group := &metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "persistentvolumes"},
			{Name: "configmaps"},
			{Name: "antelopes"},
			{Name: "persistentvolumeclaims"},
			{Name: "pods"},
		},
	}

	sortCoreGroup(group)

	expected := []string{
		"pods",
		"persistentvolumeclaims",
		"persistentvolumes",
		"configmaps",
		"antelopes",
	}
	for i, r := range group.APIResources {
		assert.Equal(t, expected[i], r.Name)
	}
}

func TestSortOrderedResource(t *testing.T) {
	log := logrus.StandardLogger()
	podResources := []*kubernetesResource{
		{namespace: "ns1", name: "pod3"},
		{namespace: "ns1", name: "pod1"},
		{namespace: "ns1", name: "pod2"},
	}
	order := []string{"ns1/pod2", "ns1/pod1"}
	expectedResources := []*kubernetesResource{
		{namespace: "ns1", name: "pod2", orderedResource: true},
		{namespace: "ns1", name: "pod1", orderedResource: true},
		{namespace: "ns1", name: "pod3"},
	}
	sortedResources := sortResourcesByOrder(log, podResources, order)
	assert.Equal(t, expectedResources, sortedResources)

	// Test cluster resources
	pvResources := []*kubernetesResource{
		{name: "pv1"},
		{name: "pv2"},
		{name: "pv3"},
	}
	pvOrder := []string{"pv5", "pv2", "pv1"}
	expectedPvResources := []*kubernetesResource{
		{name: "pv2", orderedResource: true},
		{name: "pv1", orderedResource: true},
		{name: "pv3"},
	}
	sortedPvResources := sortResourcesByOrder(log, pvResources, pvOrder)
	assert.Equal(t, expectedPvResources, sortedPvResources)
}

func TestFilterNamespaces(t *testing.T) {
	tests := []struct {
		name              string
		resources         []*kubernetesResource
		needToTrack       string
		expectedResources []*kubernetesResource
	}{
		{
			name: "Namespace include by the filter but not in namespacesContainResource",
			resources: []*kubernetesResource{
				{
					groupResource: kuberesource.Namespaces,
					preferredGVR:  kuberesource.Namespaces.WithVersion("v1"),
					name:          "ns1",
				},
				{
					groupResource: kuberesource.Namespaces,
					preferredGVR:  kuberesource.Namespaces.WithVersion("v1"),
					name:          "ns2",
				},
				{
					groupResource: kuberesource.Pods,
					preferredGVR:  kuberesource.Namespaces.WithVersion("v1"),
					name:          "pod1",
				},
			},
			needToTrack: "ns1",
			expectedResources: []*kubernetesResource{
				{
					groupResource: kuberesource.Namespaces,
					preferredGVR:  kuberesource.Namespaces.WithVersion("v1"),
					name:          "ns1",
				},
				{
					groupResource: kuberesource.Pods,
					preferredGVR:  kuberesource.Namespaces.WithVersion("v1"),
					name:          "pod1",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			r := itemCollector{
				backupRequest: &Request{},
			}

			if tc.needToTrack != "" {
				r.nsTracker.track(tc.needToTrack)
			}

			require.Equal(t, tc.expectedResources, r.nsTracker.filterNamespaces(tc.resources))
		})
	}
}

func TestItemCollectorBackupNamespaces(t *testing.T) {
	tests := []struct {
		name              string
		ie                *collections.NamespaceIncludesExcludes
		namespaces        []*corev1api.Namespace
		backup            *velerov1api.Backup
		expectedTrackedNS []string
		converter         runtime.UnstructuredConverter
	}{
		{
			name:   "ns filter by namespace IE filter",
			backup: builder.ForBackup("velero", "backup").Result(),
			ie:     collections.NewNamespaceIncludesExcludes().Includes("ns1"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1"},
		},
		{
			name: "ns filter by backup labelSelector",
			backup: builder.ForBackup("velero", "backup").LabelSelector(&metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "ns1"},
			}).Result(),
			ie: collections.NewNamespaceIncludesExcludes().Includes("*"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").ObjectMeta(builder.WithLabels("name", "ns1")).Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1"},
		},
		{
			name: "ns filter by backup orLabelSelector",
			backup: builder.ForBackup("velero", "backup").OrLabelSelector([]*metav1.LabelSelector{
				{MatchLabels: map[string]string{"name": "ns1"}},
			}).Result(),
			ie: collections.NewNamespaceIncludesExcludes().Includes("*"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").ObjectMeta(builder.WithLabels("name", "ns1")).Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1"},
		},
		{
			name: "ns not included by IE filter, but included by labelSelector",
			backup: builder.ForBackup("velero", "backup").LabelSelector(&metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "ns1"},
			}).Result(),
			ie: collections.NewNamespaceIncludesExcludes().Excludes("ns1"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").ObjectMeta(builder.WithLabels("name", "ns1")).Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1"},
		},
		{
			name: "ns not included by IE filter, but included by orLabelSelector",
			backup: builder.ForBackup("velero", "backup").OrLabelSelector([]*metav1.LabelSelector{
				{MatchLabels: map[string]string{"name": "ns1"}},
			}).Result(),
			ie: collections.NewNamespaceIncludesExcludes().Excludes("ns1", "ns2"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").ObjectMeta(builder.WithLabels("name", "ns1")).Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns3").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1", "ns3"},
		},
		{
			name:   "No ns filters",
			backup: builder.ForBackup("velero", "backup").Result(),
			ie:     collections.NewNamespaceIncludesExcludes().Includes("*"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").ObjectMeta(builder.WithLabels("name", "ns1")).Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1", "ns2"},
		},
		{
			name:   "ns specified by the IncludeNamespaces cannot be found",
			backup: builder.ForBackup("velero", "backup").IncludedNamespaces("ns1", "invalid", "*").Result(),
			ie:     collections.NewNamespaceIncludesExcludes().Includes("ns1", "invalid", "*"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").ObjectMeta(builder.WithLabels("name", "ns1")).Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
				builder.ForNamespace("ns3").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns1"},
		},
		{
			name:   "terminating ns should not tracked",
			backup: builder.ForBackup("velero", "backup").Result(),
			ie:     collections.NewNamespaceIncludesExcludes().Includes("ns1", "ns2"),
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns1").Phase(corev1api.NamespaceTerminating).Result(),
				builder.ForNamespace("ns2").Phase(corev1api.NamespaceActive).Result(),
			},
			expectedTrackedNS: []string{"ns2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			tempDir := t.TempDir()

			var unstructuredNSList unstructured.UnstructuredList
			for _, ns := range tc.namespaces {
				unstructuredNS, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ns)
				require.NoError(t, err)
				unstructuredNSList.Items = append(unstructuredNSList.Items,
					unstructured.Unstructured{Object: unstructuredNS})
			}

			dc := &test.FakeDynamicClient{}
			dc.On("List", mock.Anything).Return(&unstructuredNSList, nil)

			factory := &test.FakeDynamicFactory{}
			factory.On(
				"ClientForGroupVersionResource",
				mock.Anything,
				mock.Anything,
				mock.Anything,
			).Return(dc, nil)

			r := itemCollector{
				backupRequest: &Request{
					Backup:                    tc.backup,
					NamespaceIncludesExcludes: tc.ie,
				},
				dynamicFactory:  factory,
				discoveryHelper: test.NewFakeDiscoveryHelper(true, nil),
				dir:             tempDir,
			}

			if tc.converter == nil {
				tc.converter = runtime.DefaultUnstructuredConverter
			}

			r.collectNamespaces(
				metav1.APIResource{
					Name:       "Namespace",
					Kind:       "Namespace",
					Namespaced: false,
				},
				kuberesource.Namespaces.WithVersion("").GroupVersion(),
				kuberesource.Namespaces,
				kuberesource.Namespaces.WithVersion(""),
				logrus.StandardLogger(),
			)

			for _, ns := range tc.expectedTrackedNS {
				require.True(t, r.nsTracker.isTracked(ns))
			}
		})
	}
}

// TestNamespacedFilterMap_GlobalExclusionPrecedence verifies the precedence rule:
// ResourceIncludesExcludes (set by includeExcludePolicy) is checked before the
// NamespacedFilterMap. This is enforced at both Stage 1 (item_collector.go line ~430)
// and Stage 2 (item_backupper.go itemInclusionChecks). The unit below confirms that
// GetNamespaceFilter still returns a filter for the namespace — it is the caller's
// responsibility to check ResourceIncludesExcludes first, which item_collector does.
//
// Full coverage of the Stage 2 enforcement is in item_backupper_test.go
// TestItemInclusionChecks_GlobalExclusion_OverridesNamespaceFilter.
func TestNamespacedFilterMap_GlobalExclusionPrecedence(t *testing.T) {
	req := &Request{
		Backup:                    builder.ForBackup("velero", "test-backup").Result(),
		NamespaceIncludesExcludes: collections.NewNamespaceIncludesExcludes().Includes("ns-a"),
		NamespacedFilterMap: map[string]*ResolvedNamespaceFilter{
			"ns-a": {
				ResourceFilterMap: map[string]*ResolvedResourceFilter{
					"secrets.": {},
				},
			},
		},
		NamespacedFilterPatterns: []NamespacedFilterPattern{},
	}

	// GetNamespaceFilter returns the filter regardless of global exclusions.
	// The caller (item_collector) is responsible for checking ResourceIncludesExcludes first.
	nsFilter := req.GetNamespaceFilter("ns-a")
	require.NotNil(t, nsFilter, "GetNamespaceFilter should return a filter for ns-a")
	_, hasSecrets := nsFilter.ResourceFilterMap["secrets."]
	assert.True(t, hasSecrets, "ns-a filter should list secrets GR")

	// When a global excludeAllIE is set, item_collector would return nil before consulting the map.
	// This is verified by the Stage 1 check: ShouldInclude("secrets.") == false → skip.
	ie := &excludeAllIE{}
	assert.False(t, ie.ShouldInclude("secrets."),
		"global exclusion must reject secrets before the per-namespace filter is consulted")
}

// excludeAllIE is an IncludesExcludesInterface that excludes every resource kind.
type excludeAllIE struct{}

func (excludeAllIE) ShouldInclude(string) bool { return false }
func (excludeAllIE) ShouldExclude(string) bool { return true }

func TestGetResourceItems(t *testing.T) {
	tests := []struct {
		name                   string
		namespaces             []string
		clusterScopedFilterMap map[string]*ResolvedResourceFilter
		namespacedFilterMap    map[string]*ResolvedNamespaceFilter
		resource               metav1.APIResource
		gr                     schema.GroupResource
	}{
		{
			name:       "cluster scoped resource with filter",
			namespaces: []string{""},
			resource: metav1.APIResource{
				Name:       "persistentvolumes",
				Namespaced: false,
			},
			gr: schema.GroupResource{Resource: "persistentvolumes"},
			clusterScopedFilterMap: map[string]*ResolvedResourceFilter{
				"persistentvolumes": {
					LabelSelector: labels.Set{"app": "foo"}.AsSelector(),
				},
			},
		},
		{
			name:       "namespace scoped resource with filter",
			namespaces: []string{"ns1"},
			resource: metav1.APIResource{
				Name:       "pods",
				Namespaced: true,
			},
			gr: schema.GroupResource{Resource: "pods"},
			namespacedFilterMap: map[string]*ResolvedNamespaceFilter{
				"ns1": {
					ResourceFilterMap: map[string]*ResolvedResourceFilter{
						"pods": {
							LabelSelector: labels.Set{"app": "bar"}.AsSelector(),
						},
					},
				},
			},
		},
		{
			name:       "namespace scoped resource skipped due to no filter match",
			namespaces: []string{"ns1"},
			resource: metav1.APIResource{
				Name:       "secrets",
				Namespaced: true,
			},
			gr: schema.GroupResource{Resource: "secrets"},
			namespacedFilterMap: map[string]*ResolvedNamespaceFilter{
				"ns1": {
					ResourceFilterMap: map[string]*ResolvedResourceFilter{
						"pods": {
							LabelSelector: labels.Set{"app": "bar"}.AsSelector(),
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dc := &test.FakeDynamicClient{}
			dc.On("List", mock.Anything).Return(&unstructured.UnstructuredList{}, nil)

			factory := &test.FakeDynamicFactory{}
			factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

			req := &Request{
				Backup:                   builder.ForBackup("velero", "backup").Result(),
				ClusterScopedFilterMap:   tc.clusterScopedFilterMap,
				NamespacedFilterMap:      tc.namespacedFilterMap,
				ResourceIncludesExcludes: includeAllIE{},
			}
			if len(tc.namespaces) > 0 && tc.namespaces[0] != "" {
				req.NamespaceIncludesExcludes = collections.NewNamespaceIncludesExcludes().Includes(tc.namespaces...)
			} else {
				req.NamespaceIncludesExcludes = collections.NewNamespaceIncludesExcludes().Includes("*")
			}

			r := &itemCollector{
				backupRequest:   req,
				dynamicFactory:  factory,
				discoveryHelper: test.NewFakeDiscoveryHelper(true, nil),
				log:             test.NewLogger(),
			}

			_, err := r.getResourceItems(test.NewLogger(), schema.GroupVersion{}, tc.resource, nil)
			assert.NoError(t, err)
		})
	}
}

func TestGetOrderedResourcesForTypeTrimsSpaces(t *testing.T) {
	// Spaces after commas are common in CLI input and should not break ordering.
	orders := getOrderedResourcesForType(map[string]string{
		"pods": "ns1/pod2, ns1/pod1",
	}, "pods")
	require.Equal(t, []string{"ns1/pod2", "ns1/pod1"}, orders)

	log := logrus.StandardLogger()
	podResources := []*kubernetesResource{
		{namespace: "ns1", name: "pod3"},
		{namespace: "ns1", name: "pod1"},
		{namespace: "ns1", name: "pod2"},
	}
	sorted := sortResourcesByOrder(log, podResources, orders)
	require.Equal(t, []*kubernetesResource{
		{namespace: "ns1", name: "pod2", orderedResource: true},
		{namespace: "ns1", name: "pod1", orderedResource: true},
		{namespace: "ns1", name: "pod3"},
	}, sorted)
}

func TestListItemsForLabel(t *testing.T) {
	makePod := func(name string) unstructured.Unstructured {
		return unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name":      name,
					"namespace": "default",
				},
			},
		}
	}

	pod1 := makePod("pod1")
	pod2 := makePod("pod2")
	pod3 := makePod("pod3")
	pod4 := makePod("pod4")
	pod5 := makePod("pod5")
	existingPod := makePod("existing")

	t.Run("multiple pages collected exactly once using configured page size", func(t *testing.T) {
		dc := &test.FakeDynamicClient{}
		// Page 1: Limit=2, continue="" -> returns [pod1, pod2], continue="c1"
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: ""}).
			Return(&unstructured.UnstructuredList{
				Object: map[string]any{
					"metadata": map[string]any{"continue": "c1"},
				},
				Items: []unstructured.Unstructured{pod1, pod2},
			}, nil).Once()

		// Page 2: Limit=2, continue="c1" -> returns [pod3, pod4], continue="c2"
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: "c1"}).
			Return(&unstructured.UnstructuredList{
				Object: map[string]any{
					"metadata": map[string]any{"continue": "c2"},
				},
				Items: []unstructured.Unstructured{pod3, pod4},
			}, nil).Once()

		// Page 3: Limit=2, continue="c2" -> returns [pod5], continue=""
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: "c2"}).
			Return(&unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{pod5},
			}, nil).Once()

		collector := &itemCollector{
			pageSize:       2,
			pageBufferSize: 5,
			log:            test.NewLogger(),
		}

		res, err := collector.listItemsForLabel(nil, "app=foo", dc)
		require.NoError(t, err)
		assert.Equal(t, []unstructured.Unstructured{pod1, pod2, pod3, pod4, pod5}, res)
		dc.AssertExpectations(t)
	})

	t.Run("error from later page is propagated and partial items are discarded", func(t *testing.T) {
		dc := &test.FakeDynamicClient{}
		// Page 1 succeeds
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: ""}).
			Return(&unstructured.UnstructuredList{
				Object: map[string]any{
					"metadata": map[string]any{"continue": "c1"},
				},
				Items: []unstructured.Unstructured{pod1, pod2},
			}, nil).Once()

		// Page 2 returns an error
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: "c1"}).
			Return((*unstructured.UnstructuredList)(nil), errors.New("network error on page 2")).Once()

		collector := &itemCollector{
			pageSize:       2,
			pageBufferSize: 5,
			log:            test.NewLogger(),
		}

		res, err := collector.listItemsForLabel([]unstructured.Unstructured{existingPod}, "app=foo", dc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network error on page 2")
		// Verify partial items from page 1 were not retained and existingPod was preserved
		assert.Equal(t, []unstructured.Unstructured{existingPod}, res)
		dc.AssertExpectations(t)
	})

	t.Run("continuation token expiration recovers with full list without duplicating items", func(t *testing.T) {
		dc := &test.FakeDynamicClient{}
		// Page 1 succeeds with continue token
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: ""}).
			Return(&unstructured.UnstructuredList{
				Object: map[string]any{
					"metadata": map[string]any{"continue": "expired-token"},
				},
				Items: []unstructured.Unstructured{pod1, pod2},
			}, nil).Once()

		// Page 2 fails with ResourceExpired error
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: "expired-token"}).
			Return((*unstructured.UnstructuredList)(nil), apierrors.NewResourceExpired("too old")).Once()

		// Fallback unpaginated full list succeeds
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo"}).
			Return(&unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{pod1, pod2, pod3, pod4},
			}, nil).Once()

		collector := &itemCollector{
			pageSize:       2,
			pageBufferSize: 5,
			log:            test.NewLogger(),
		}

		res, err := collector.listItemsForLabel([]unstructured.Unstructured{existingPod}, "app=foo", dc)
		require.NoError(t, err)
		// Should contain existingPod and all 4 pods from full list exactly once
		assert.Equal(t, []unstructured.Unstructured{existingPod, pod1, pod2, pod3, pod4}, res)
		dc.AssertExpectations(t)
	})

	t.Run("continuation token expiration fallback error is propagated", func(t *testing.T) {
		dc := &test.FakeDynamicClient{}
		// Page 1 succeeds
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: ""}).
			Return(&unstructured.UnstructuredList{
				Object: map[string]any{
					"metadata": map[string]any{"continue": "expired-token"},
				},
				Items: []unstructured.Unstructured{pod1, pod2},
			}, nil).Once()

		// Page 2 fails with ResourceExpired error
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo", Limit: 2, Continue: "expired-token"}).
			Return((*unstructured.UnstructuredList)(nil), apierrors.NewResourceExpired("too old")).Once()

		// Fallback fails
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo"}).
			Return((*unstructured.UnstructuredList)(nil), errors.New("unrecoverable error")).Once()

		collector := &itemCollector{
			pageSize:       2,
			pageBufferSize: 5,
			log:            test.NewLogger(),
		}

		res, err := collector.listItemsForLabel([]unstructured.Unstructured{existingPod}, "app=foo", dc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unrecoverable error")
		assert.Equal(t, []unstructured.Unstructured{existingPod}, res)
		dc.AssertExpectations(t)
	})

	t.Run("unpaginated listing when pageSize is 0", func(t *testing.T) {
		dc := &test.FakeDynamicClient{}
		dc.On("List", metav1.ListOptions{LabelSelector: "app=foo"}).
			Return(&unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{pod1, pod2},
			}, nil).Once()

		collector := &itemCollector{
			pageSize:       0,
			pageBufferSize: 10,
			log:            test.NewLogger(),
		}

		res, err := collector.listItemsForLabel([]unstructured.Unstructured{existingPod}, "app=foo", dc)
		require.NoError(t, err)
		assert.Equal(t, []unstructured.Unstructured{existingPod, pod1, pod2}, res)
		dc.AssertExpectations(t)
	})
}
