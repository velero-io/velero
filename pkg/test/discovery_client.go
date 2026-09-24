/*
Copyright 2019 the Velero contributors.

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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
)

// DiscoveryClient is a wrapper for the client-go FakeDiscovery struct. It
// adds some extra functionality that's necessary/useful for Velero tests.
type DiscoveryClient struct {
	*discoveryfake.FakeDiscovery
}

func (c *DiscoveryClient) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	return discovery.ServerPreferredResources(c)
}

//
// TEST HELPERS
//

// WithAPIResource adds the API resource to the discovery client.
func (c *DiscoveryClient) WithAPIResource(resource *APIResource) *DiscoveryClient {
	gv := metav1.GroupVersion{
		Group:   resource.Group,
		Version: resource.Version,
	}

	var resourceList *metav1.APIResourceList
	for _, itm := range c.Resources {
		if itm.GroupVersion == gv.String() {
			resourceList = itm
			break
		}
	}

	if resourceList == nil {
		resourceList = &metav1.APIResourceList{
			GroupVersion: gv.String(),
		}

		c.Resources = append(c.Resources, resourceList)
	}

	for _, itm := range resourceList.APIResources {
		if itm.Name == resource.Name {
			return c
		}
	}

	verbs := resource.Verbs
	if len(verbs) == 0 {
		verbs = []string{"list", "create", "get", "delete"}
	}

	resourceList.APIResources = append(resourceList.APIResources, metav1.APIResource{
		Name:         resource.Name,
		SingularName: strings.TrimSuffix(resource.Name, "s"),
		Namespaced:   resource.Namespaced,
		Group:        resource.Group,
		Version:      resource.Version,
		Kind:         resource.Kind,
		Verbs:        metav1.Verbs(verbs),
		ShortNames:   []string{resource.ShortName},
	})

	return c
}

func (c *DiscoveryClient) GroupsAndMaybeResources() (*metav1.APIGroupList, map[schema.GroupVersion]*metav1.APIResourceList, map[schema.GroupVersion]error, error) {
	apiGroupList, err := c.ServerGroups()
	if err != nil {
		return nil, nil, nil, err
	}
	return apiGroupList, nil, nil, nil
}
