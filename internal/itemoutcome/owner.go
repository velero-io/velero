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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/velero-io/velero/pkg/plugin/velero"
)

// OwnerResolver resolves a kind to the resource Velero identifies items by and
// reports whether that resource is namespaced. discovery.Helper satisfies it.
type OwnerResolver interface {
	KindFor(input schema.GroupVersionKind) (schema.GroupVersionResource, metav1.APIResource, error)
}

// OwnerFromOwnerReference derives an item's controller owner from its metadata.ownerReferences.
func OwnerFromOwnerReference(metadata metav1.Object, item velero.ResourceIdentifier, resolver OwnerResolver) (velero.ResourceIdentifier, bool) {
	if metadata == nil || resolver == nil {
		return velero.ResourceIdentifier{}, false
	}

	// The controller owner is the one relationship Kubernetes guarantees is
	// single-valued; an object's other owner references say only that it is also
	// associated with something, which is too weak to call a reported-by entry.
	owner := metav1.GetControllerOf(metadata)
	if owner == nil {
		return velero.ResourceIdentifier{}, false
	}

	gv, err := schema.ParseGroupVersion(owner.APIVersion)
	if err != nil {
		return velero.ResourceIdentifier{}, false
	}

	gvr, apiResource, err := resolver.KindFor(gv.WithKind(owner.Kind))
	if err != nil {
		return velero.ResourceIdentifier{}, false
	}

	// An owner reference names no namespace of its own, so the scope has to come
	// from discovery. It matters: a namespaced owner is in the item's namespace,
	// but a cluster-scoped one (a Node owning a Pod) is not in any namespace, and
	// naming the item's would match nothing in the artifact.
	namespace := ""
	if apiResource.Namespaced {
		namespace = metadata.GetNamespace()
	}

	reporter := velero.ResourceIdentifier{
		GroupResource: gvr.GroupResource(),
		Namespace:     namespace,
		Name:          owner.Name,
	}
	if reporter == item {
		// A self-edge would make the item its own root and run every tree walk to
		// its depth limit. Nothing honest produces one; refuse it here rather than
		// rely on every reader to notice.
		return velero.ResourceIdentifier{}, false
	}

	return reporter, true
}
