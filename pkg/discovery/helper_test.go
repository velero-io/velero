/*
Copyright 2017 the Velero contributors.

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

package discovery

import (
	"errors"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery/fake"
	clientgotesting "k8s.io/client-go/testing"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	discoverymocks "github.com/vmware-tanzu/velero/pkg/discovery/mocks"
	"github.com/vmware-tanzu/velero/pkg/features"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

func TestSortResources(t *testing.T) {
	tests := []struct {
		name      string
		resources []*metav1.APIResourceList
		expected  []*metav1.APIResourceList
	}{
		{
			name: "no resources",
		},
		{
			name: "no extensions, order is preserved",
			resources: []*metav1.APIResourceList{
				{GroupVersion: "v1"},
				{GroupVersion: "groupC/v1"},
				{GroupVersion: "groupA/v1"},
				{GroupVersion: "groupB/v1"},
			},
			expected: []*metav1.APIResourceList{
				{GroupVersion: "v1"},
				{GroupVersion: "groupC/v1"},
				{GroupVersion: "groupA/v1"},
				{GroupVersion: "groupB/v1"},
			},
		},
		{
			name: "extensions moves to end, order is preserved",
			resources: []*metav1.APIResourceList{
				{GroupVersion: "extensions/v1beta1"},
				{GroupVersion: "v1"},
				{GroupVersion: "groupC/v1"},
				{GroupVersion: "groupA/v1"},
				{GroupVersion: "groupB/v1"},
				{GroupVersion: "apps/v1beta1"},
			},
			expected: []*metav1.APIResourceList{
				{GroupVersion: "v1"},
				{GroupVersion: "groupC/v1"},
				{GroupVersion: "groupA/v1"},
				{GroupVersion: "groupB/v1"},
				{GroupVersion: "apps/v1beta1"},
				{GroupVersion: "extensions/v1beta1"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("before")
			for _, r := range test.resources {
				t.Logf("%s", r.GroupVersion)
			}
			sortResources(test.resources)
			t.Logf("after")
			for _, r := range test.resources {
				t.Logf("%s", r.GroupVersion)
			}
			assert.Equal(t, test.expected, test.resources)
		})
	}
}

func TestFilteringByVerbs(t *testing.T) {
	tests := []struct {
		name         string
		groupVersion string
		res          *metav1.APIResource
		expected     bool
	}{
		{
			name:         "resource that supports list, create, get, delete",
			groupVersion: "v1",
			res: &metav1.APIResource{
				Verbs: metav1.Verbs{"list", "create", "get", "delete"},
			},
			expected: true,
		},
		{
			name:         "resource that supports list, create, get, delete in a different order",
			groupVersion: "v1",
			res: &metav1.APIResource{
				Verbs: metav1.Verbs{"delete", "get", "create", "list"},
			},
			expected: true,
		},
		{
			name:         "resource that supports list, create, get, delete, and more",
			groupVersion: "v1",
			res: &metav1.APIResource{
				Verbs: metav1.Verbs{"list", "create", "get", "delete", "update", "patch", "deletecollection"},
			},
			expected: true,
		},
		{
			name:         "resource that supports only list and create",
			groupVersion: "v1",
			res: &metav1.APIResource{
				Verbs: metav1.Verbs{"list", "create"},
			},
			expected: false,
		},
		{
			name:         "resource that supports only get and delete",
			groupVersion: "v1",
			res: &metav1.APIResource{
				Verbs: metav1.Verbs{"get", "delete"},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := filterByVerbs(test.groupVersion, test.res)
			assert.Equal(t, test.expected, out)
		})
	}
}

func TestRefreshServerPreferredResources(t *testing.T) {
	tests := []struct {
		name         string
		resourceList []*metav1.APIResourceList
		apiGroup     []*metav1.APIGroup
		failedGroups map[schema.GroupVersion]error
		returnError  error
	}{
		{
			name: "all groups discovered, no error is returned",
			resourceList: []*metav1.APIResourceList{
				{GroupVersion: "groupB/v1"},
				{GroupVersion: "apps/v1beta1"},
				{GroupVersion: "extensions/v1beta1"},
			},
		},
		{
			name: "failed to discover some groups, no error is returned",
			resourceList: []*metav1.APIResourceList{
				{GroupVersion: "groupB/v1"},
				{GroupVersion: "apps/v1beta1"},
				{GroupVersion: "extensions/v1beta1"},
			},
			failedGroups: map[schema.GroupVersion]error{
				{Group: "groupA", Version: "v1"}: errors.New("Fake error"),
				{Group: "groupC", Version: "v2"}: errors.New("Fake error"),
			},
		},
		{
			name:        "non ErrGroupDiscoveryFailed error, returns error",
			returnError: errors.New("Generic error"),
		},
	}

	formatFlag := logging.FormatText

	for _, test := range tests {
		fakeServer := velerotest.NewFakeServerResourcesInterface(test.resourceList, test.apiGroup, test.failedGroups, test.returnError)
		t.Run(test.name, func(t *testing.T) {
			resources, err := refreshServerPreferredResources(fakeServer, logging.DefaultLogger(logrus.DebugLevel, formatFlag))
			if test.returnError != nil {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.returnError, err)
			}

			assert.Equal(t, test.resourceList, resources)
		})
	}
}

func TestHelper_ResourceFor(t *testing.T) {
	fakeDiscoveryClient := &fake.FakeDiscovery{
		Fake: &clientgotesting.Fake{},
	}
	fakeDiscoveryClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{
					Name:    "pods",
					Kind:    "Pod",
					Group:   "",
					Version: "v1",
					Verbs:   []string{"create", "get", "list"},
				},
			},
		},
	}

	h := &helper{
		discoveryClient: fakeDiscoveryClient,
		lock:            sync.RWMutex{},
		mapper:          nil,
		resources:       fakeDiscoveryClient.Resources,
		resourcesMap:    make(map[schema.GroupVersionResource]metav1.APIResource),
		serverVersion:   &version.Info{Major: "1", Minor: "22", GitVersion: "v1.22.1"},
	}

	for _, resourceList := range h.resources {
		for _, resource := range resourceList.APIResources {
			gvr := schema.GroupVersionResource{
				Group:    resource.Group,
				Version:  resource.Version,
				Resource: resource.Name,
			}
			h.resourcesMap[gvr] = resource
		}
	}
	pvGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}
	h.mapper = &velerotest.FakeMapper{Resources: map[schema.GroupVersionResource]schema.GroupVersionResource{pvGVR: pvGVR}}

	tests := []struct {
		name                string
		err                 string
		input               *schema.GroupVersionResource
		isNotFoundRes       bool
		expectedGVR         *schema.GroupVersionResource
		expectedAPIResource *metav1.APIResource
	}{
		{
			name: "Found resource",
			input: &schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			expectedAPIResource: &metav1.APIResource{
				Name:    "pods",
				Kind:    "Pod",
				Group:   "",
				Version: "v1",
				Verbs:   []string{"create", "get", "list"},
			},
			expectedGVR: &schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
		},
		{
			name: "Error to found resource",
			input: &schema.GroupVersionResource{
				Group:    "",
				Version:  "v2",
				Resource: "pods",
			},
			err:                 "invalid resource",
			expectedGVR:         &schema.GroupVersionResource{},
			expectedAPIResource: &metav1.APIResource{},
		},
		{
			name: "Error to found api resource",
			input: &schema.GroupVersionResource{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			},
			isNotFoundRes:       true,
			err:                 "APIResource not found for GroupVersionResource",
			expectedGVR:         &schema.GroupVersionResource{},
			expectedAPIResource: &metav1.APIResource{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.isNotFoundRes {
				h.resourcesMap = nil
			}
			gvr, apiResource, err := h.ResourceFor(*tc.input)
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), tc.err)
			}
			assert.Equal(t, *tc.expectedGVR, gvr)
			assert.Equal(t, *tc.expectedAPIResource, apiResource)
		})
	}
}

func TestHelper_KindFor(t *testing.T) {
	fakeDiscoveryClient := &fake.FakeDiscovery{
		Fake: &clientgotesting.Fake{},
	}
	fakeDiscoveryClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{
					Name:    "pods",
					Kind:    "Pod",
					Group:   "",
					Version: "v1",
					Verbs:   []string{"create", "get", "list"},
				},
			},
		},
	}
	pvGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Deployment",
	}
	pvAPIRes := metav1.APIResource{
		Name:    "deployments",
		Kind:    "Deployment",
		Group:   "apps",
		Version: "v1",
		Verbs:   []string{"create", "get", "list"},
	}

	h := &helper{
		discoveryClient: fakeDiscoveryClient,
		lock:            sync.RWMutex{},
		resources:       fakeDiscoveryClient.Resources,
		resourcesMap:    make(map[schema.GroupVersionResource]metav1.APIResource),
		serverVersion:   &version.Info{Major: "1", Minor: "22", GitVersion: "v1.22.1"},
	}

	h.kindMap = map[schema.GroupVersionKind]metav1.APIResource{pvGVK: pvAPIRes}
	h.mapper = &velerotest.FakeMapper{KindToPluralResource: map[schema.GroupVersionKind]schema.GroupVersionResource{}}
	for _, resourceList := range h.resources {
		for _, resource := range resourceList.APIResources {
			gvr := schema.GroupVersionResource{
				Group:    resource.Group,
				Version:  resource.Version,
				Resource: resource.Name,
			}
			h.resourcesMap[gvr] = resource
		}
	}

	tests := []struct {
		name                string
		err                 string
		input               *schema.GroupVersionKind
		isNotFoundRes       bool
		expectedGVR         *schema.GroupVersionResource
		expectedAPIResource *metav1.APIResource
	}{
		{
			name: "Found resource",
			input: &schema.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Deployment",
			},
			expectedAPIResource: &metav1.APIResource{
				Name:    "deployments",
				Kind:    "Deployment",
				Group:   "apps",
				Version: "v1",
				Verbs:   []string{"create", "get", "list"},
			},
			expectedGVR: &schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			},
		}, {
			name: "Not found resource",
			input: &schema.GroupVersionKind{
				Group:   "",
				Version: "v2",
				Kind:    "Deployment",
			},
			expectedAPIResource: &metav1.APIResource{},
			expectedGVR:         &schema.GroupVersionResource{},
			err:                 "no matches for kind",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gvr, apiResource, err := h.KindFor(*tc.input)
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), tc.err)
			}
			assert.Equal(t, *tc.expectedGVR, gvr)
			assert.Equal(t, *tc.expectedAPIResource, apiResource)
		})
	}
}

func TestHelper_Refresh(t *testing.T) {
	testCases := []struct {
		description      string
		features         string
		groupResources   []*metav1.APIResourceList
		serverGroups     []*metav1.APIGroup
		expectedErr      error
		expectedResource metav1.APIResource
	}{
		{
			description: "Default case - Resource found",
			groupResources: []*metav1.APIResourceList{
				{
					GroupVersion: "v1",
					APIResources: []metav1.APIResource{
						{
							Name:    "pods",
							Kind:    "Pod",
							Group:   "",
							Version: "v1",
							Verbs:   []string{"get", "list", "create"},
						},
					},
				},
			},
			serverGroups: []*metav1.APIGroup{
				{
					Name: "group1",
					Versions: []metav1.GroupVersionForDiscovery{
						{
							GroupVersion: "v1",
							Version:      "v1",
						},
					},
				},
			},
			expectedErr: nil,
			expectedResource: metav1.APIResource{
				Name:    "pods",
				Kind:    "Pod",
				Group:   "",
				Version: "v1",
				Verbs:   []string{"get", "list", "create"},
			},
		},
		{
			description:    "Feature flag enabled - ServerGroupsAndResources",
			features:       velerov1api.APIGroupVersionsFeatureFlag,
			groupResources: []*metav1.APIResourceList{},
			serverGroups: []*metav1.APIGroup{
				{
					Name: "group1",
					Versions: []metav1.GroupVersionForDiscovery{
						{
							GroupVersion: "v1",
							Version:      "v1",
						},
					},
				},
			},
			expectedErr: nil,
			expectedResource: metav1.APIResource{
				Name:    "pods",
				Kind:    "Pod",
				Group:   "",
				Version: "v1",
				Verbs:   []string{"get", "list", "create"},
			},
		},
	}

	fakeDiscoveryClient := &fake.FakeDiscovery{
		Fake: &clientgotesting.Fake{},
	}
	fakeDiscoveryClient.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{
					Name:    "pods",
					Kind:    "Pod",
					Group:   "",
					Version: "v1",
					Verbs:   []string{"create", "get", "list"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			h := &helper{
				lock:            sync.RWMutex{},
				discoveryClient: fakeDiscoveryClient,
				logger:          logrus.New(),
			}
			// Set feature flags
			if testCase.features != "" {
				features.Enable(testCase.features)
			}
			err := h.Refresh()
			assert.Equal(t, testCase.expectedErr, err)
		})
	}
}

func TestHelper_refreshServerPreferredResources(t *testing.T) {
	apiList := []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{
					Name:    "pods",
					Kind:    "Pod",
					Group:   "",
					Version: "v1",
					Verbs:   []string{"create", "get", "list"},
				},
			},
		},
	}

	tests := []struct {
		name          string
		isGetResError bool
	}{
		{
			name: "success get preferred resources",
		},
		{
			name:          "failed to get preferred resources",
			isGetResError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := discoverymocks.NewServerResourcesInterface(t)

			if tc.isGetResError {
				fakeClient.On("ServerPreferredResources").Return(nil, errors.New("Failed to discover preferred resources"))
			} else {
				fakeClient.On("ServerPreferredResources").Return(apiList, nil)
			}

			resources, err := refreshServerPreferredResources(fakeClient, logrus.New())

			if tc.isGetResError {
				assert.NotNil(t, err)
				assert.Nil(t, resources)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, resources)
			}

			fakeClient.AssertExpectations(t)
		})
	}
}

func TestHelper_refreshServerGroupsAndResources(t *testing.T) {
	apiList := []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{
					Name:    "pods",
					Kind:    "Pod",
					Group:   "",
					Version: "v1",
					Verbs:   []string{"create", "get", "list"},
				},
			},
		},
	}
	apiGroup := []*metav1.APIGroup{
		{
			Name: "group1",
			Versions: []metav1.GroupVersionForDiscovery{
				{
					GroupVersion: "v1",
					Version:      "v1",
				},
			},
		},
	}
	tests := []struct {
		name          string
		isGetResError bool
	}{
		{
			name: "success get service groups and resouorces",
		},
		{
			name:          "failed to service groups and resouorces",
			isGetResError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := discoverymocks.NewServerResourcesInterface(t)

			if tc.isGetResError {
				fakeClient.On("ServerGroupsAndResources").Return(nil, nil, errors.New("Failed to discover service groups and resouorces"))
			} else {
				fakeClient.On("ServerGroupsAndResources").Return(apiGroup, apiList, nil)
			}

			serverGroups, serverResources, err := refreshServerGroupsAndResources(fakeClient, logrus.New())

			if tc.isGetResError {
				assert.NotNil(t, err)
				assert.Nil(t, serverGroups)
				assert.Nil(t, serverResources)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, serverGroups)
				assert.NotNil(t, serverResources)
			}

			fakeClient.AssertExpectations(t)
		})
	}
}

func TestHelper(t *testing.T) {
	fakeDiscoveryClient := &fake.FakeDiscovery{
		Fake: &clientgotesting.Fake{},
	}
	h, err := NewHelper(fakeDiscoveryClient, logrus.New())
	assert.Nil(t, err)
	// All below calls put together for the implementation are empty or just very simple, and just want to cover testing
	// If wanting to write unit tests for some functions could remove it and with writing new function alone
	h.Resources()
	h.APIGroups()
	h.ServerVersion()
}
