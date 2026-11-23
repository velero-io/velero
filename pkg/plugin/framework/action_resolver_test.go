/*
Copyright the Velero Contributors.

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

package framework

import (
	"testing"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

type mockApplicable struct {
	selector velero.ResourceSelector
}

func (recv mockApplicable) AppliesTo() (velero.ResourceSelector, error) {
	return recv.selector, nil
}

func TestActionResolverNamespace(t *testing.T) {
	discoveryHelper := velerotest.NewFakeDiscoveryHelper(false, map[schema.GroupVersionResource]schema.GroupVersionResource{})
	namespaceMatchApplicable := mockApplicable{
		selector: velero.ResourceSelector{
			IncludedNamespaces: []string{"default"},
		},
	}
	resources, namespaces, selector, err := resolveAction(discoveryHelper, namespaceMatchApplicable)
	require.NoError(t, err)
	require.Equal(t, []string{"default"}, namespaces.GetIncludes())
	require.Empty(t, namespaces.GetExcludes())
	require.Empty(t, resources.GetIncludes())
	require.Empty(t, resources.GetExcludes())
	require.True(t, selector.Empty())
}

func TestActionResolverResource(t *testing.T) {
	pvGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "persistentvolumes",
	}
	discoveryHelper := velerotest.NewFakeDiscoveryHelper(false, map[schema.GroupVersionResource]schema.GroupVersionResource{pvGVR: pvGVR})
	namespaceMatchApplicable := mockApplicable{
		selector: velero.ResourceSelector{
			IncludedResources: []string{"persistentvolumes"},
		},
	}
	resources, namespaces, selector, err := resolveAction(discoveryHelper, namespaceMatchApplicable)
	require.NoError(t, err)
	require.Empty(t, namespaces.GetIncludes())
	require.Empty(t, namespaces.GetExcludes())
	require.True(t, resources.ShouldInclude("persistentvolumes"))
	require.Empty(t, resources.GetExcludes())
	require.True(t, selector.Empty())
}

func TestActionResolverLabel(t *testing.T) {
	discoveryHelper := velerotest.NewFakeDiscoveryHelper(false, map[schema.GroupVersionResource]schema.GroupVersionResource{})
	namespaceMatchApplicable := mockApplicable{
		selector: velero.ResourceSelector{
			LabelSelector: "myLabel=true",
		},
	}
	checkLabel, err := labels.ConvertSelectorToLabelsMap("myLabel=true")
	require.NoError(t, err)

	resources, namespaces, selector, err := resolveAction(discoveryHelper, namespaceMatchApplicable)
	require.NoError(t, err)
	require.Empty(t, namespaces.GetIncludes())
	require.Empty(t, namespaces.GetExcludes())
	require.Empty(t, resources.GetIncludes())
	require.Empty(t, resources.GetExcludes())
	require.True(t, selector.Matches(checkLabel))
}
