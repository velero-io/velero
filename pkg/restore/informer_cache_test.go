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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// verbAwareDiscoveryHelper wraps FakeDiscoveryHelper to return APIResources
// with verbs populated, which the shared fake omits.
type verbAwareDiscoveryHelper struct {
	*velerotest.FakeDiscoveryHelper
	apiResources map[schema.GroupVersionResource]metav1.APIResource
}

func (h *verbAwareDiscoveryHelper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, metav1.APIResource, error) {
	if r, ok := h.apiResources[input]; ok {
		return input, r, nil
	}
	return schema.GroupVersionResource{}, metav1.APIResource{}, fmt.Errorf("APIResource not found for GroupVersionResource %s", input)
}

func TestInformerCacheSupported(t *testing.T) {
	watchable := schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}
	watchless := schema.GroupVersionResource{Group: "authorization.openshift.io", Version: "v1", Resource: "rolebindings"}
	verbless := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"}
	unknown := schema.GroupVersionResource{Group: "unknown.io", Version: "v1", Resource: "things"}

	helper := &verbAwareDiscoveryHelper{
		FakeDiscoveryHelper: velerotest.NewFakeDiscoveryHelper(false, nil),
		apiResources: map[schema.GroupVersionResource]metav1.APIResource{
			watchable: {Name: "rolebindings", Verbs: metav1.Verbs{"create", "delete", "get", "list", "watch"}},
			watchless: {Name: "rolebindings", Verbs: metav1.Verbs{"create", "delete", "get", "list"}},
			verbless:  {Name: "widgets"},
		},
	}

	ctx := &restoreContext{
		log:                        velerotest.NewLogger(),
		discoveryHelper:            helper,
		informerCacheableResources: make(map[schema.GroupVersionResource]bool),
	}

	assert.True(t, ctx.informerCacheSupported(watchable))
	// watch verb missing: informer cache must not be used
	assert.False(t, ctx.informerCacheSupported(watchless))
	// no verbs reported at all: assume supported, as some discovery sources omit verbs
	assert.True(t, ctx.informerCacheSupported(verbless))
	// unknown to discovery: report supported so the informer path surfaces the lookup error
	assert.True(t, ctx.informerCacheSupported(unknown))

	// results for known resources are memoized, unknown resources are not
	assert.Equal(t, map[schema.GroupVersionResource]bool{
		watchable: true,
		watchless: false,
		verbless:  true,
	}, ctx.informerCacheableResources)

	// memoized answers stick even if discovery answers change
	helper.apiResources[watchless] = metav1.APIResource{Name: "rolebindings", Verbs: metav1.Verbs{"list", "watch"}}
	assert.False(t, ctx.informerCacheSupported(watchless))

	// resources unknown at first are re-checked once discovery learns about
	// them, e.g. after a discovery refresh triggered by restoring CRDs
	helper.apiResources[unknown] = metav1.APIResource{Name: "things", Verbs: metav1.Verbs{"get", "list"}}
	assert.False(t, ctx.informerCacheSupported(unknown))
}
