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

package itemoutcome

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	"github.com/velero-io/velero/pkg/plugin/velero"
)

type ownerResolverFunc func(schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error)

func (f ownerResolverFunc) KindFor(gvk schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error) {
	return f(gvk)
}

func pvcWithOwner(apiVersion, kind, name string, controller *bool) *corev1api.PersistentVolumeClaim {
	p := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "disk1"},
	}
	p.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		Controller: controller,
		UID:        "uid-1",
	}}
	return p
}

func TestOwnerFromOwnerReferenceUsesControllerReference(t *testing.T) {
	resolver := ownerResolverFunc(func(gvk schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error) {
		assert.Equal(t, schema.GroupVersionKind{Group: "cdi.kubevirt.io", Version: "v1beta1", Kind: "DataVolume"}, gvk)
		return schema.GroupVersionResource{Group: "cdi.kubevirt.io", Version: "v1beta1", Resource: "datavolumes"},
			metav1.APIResource{Name: "datavolumes", Namespaced: true}, nil
	})

	item := velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
		Namespace:     "ns1",
		Name:          "disk1",
	}
	owner, ok := OwnerFromOwnerReference(pvcWithOwner("cdi.kubevirt.io/v1beta1", "DataVolume", "disk1", ptr.To(true)), item, resolver)

	require.True(t, ok)
	assert.Equal(t, velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{Group: "cdi.kubevirt.io", Resource: "datavolumes"},
		Namespace:     "ns1",
		Name:          "disk1",
	}, owner)
}

// A cluster-scoped owner is not in the item's namespace, so inheriting it would
// name an item that cannot exist.
func TestOwnerFromOwnerReferenceLeavesClusterScopedOwnerUnnamespaced(t *testing.T) {
	resolver := ownerResolverFunc(func(gvk schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error) {
		return schema.GroupVersionResource{Version: "v1", Resource: "nodes"},
			metav1.APIResource{Name: "nodes", Namespaced: false}, nil
	})

	item := velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{Resource: "pods"},
		Namespace:     "ns1",
		Name:          "pod1",
	}
	owner, ok := OwnerFromOwnerReference(pvcWithOwner("v1", "Node", "node1", ptr.To(true)), item, resolver)

	require.True(t, ok)
	assert.Empty(t, owner.Namespace)
	assert.Equal(t, "node1", owner.Name)
}

func TestOwnerFromOwnerReferenceSkipsUnresolvableOwner(t *testing.T) {
	resolver := ownerResolverFunc(func(schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error) {
		return schema.GroupVersionResource{}, metav1.APIResource{}, assert.AnError
	})

	_, ok := OwnerFromOwnerReference(pvcWithOwner("v1", "Node", "node1", ptr.To(true)), velero.ResourceIdentifier{}, resolver)
	assert.False(t, ok)
}

func TestOwnerFromOwnerReferenceIgnoresNonControllerReferences(t *testing.T) {
	resolver := ownerResolverFunc(func(schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error) {
		t.Fatal("a non-controller reference must not be resolved")
		return schema.GroupVersionResource{}, metav1.APIResource{}, nil
	})

	_, ok := OwnerFromOwnerReference(pvcWithOwner("v1", "Node", "node1", nil), velero.ResourceIdentifier{}, resolver)
	assert.False(t, ok)
}

func TestOwnerFromOwnerReferenceRefusesSelfEdge(t *testing.T) {
	resolver := ownerResolverFunc(func(schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error) {
		return schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"},
			metav1.APIResource{Name: "persistentvolumeclaims", Namespaced: true}, nil
	})

	item := velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
		Namespace:     "ns1",
		Name:          "disk1",
	}
	_, ok := OwnerFromOwnerReference(pvcWithOwner("v1", "PersistentVolumeClaim", "disk1", ptr.To(true)), item, resolver)
	assert.False(t, ok)
}
