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

package backup

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/velero/pkg/kuberesource"
)

func TestPVCInclusionTracker_IsPVCIncluded(t *testing.T) {
	mustIncludeMap := NewBackedUpItemsMap()
	backedUpMap := NewBackedUpItemsMap()

	tracker := NewPVCInclusionTracker(mustIncludeMap, backedUpMap)

	pvcKey1 := itemKey{
		resource:  kuberesource.PersistentVolumeClaims.String(),
		namespace: "ns-1",
		name:      "pvc-1",
	}

	pvcKey2 := itemKey{
		resource:  kuberesource.PersistentVolumeClaims.String(),
		namespace: "ns-1",
		name:      "pvc-2",
	}

	// Initially neither PVC is included
	assert.False(t, tracker.IsPVCIncluded("ns-1", "pvc-1"))
	assert.False(t, tracker.IsPVCIncluded("ns-1", "pvc-2"))

	// Add pvc-1 to mustInclude map
	mustIncludeMap.AddItem(pvcKey1)
	assert.True(t, tracker.IsPVCIncluded("ns-1", "pvc-1"))
	assert.False(t, tracker.IsPVCIncluded("ns-1", "pvc-2"))

	// Add pvc-2 to backedUp map
	backedUpMap.AddItem(pvcKey2)
	assert.True(t, tracker.IsPVCIncluded("ns-1", "pvc-1"))
	assert.True(t, tracker.IsPVCIncluded("ns-1", "pvc-2"))

	// Check a PVC not in any map
	assert.False(t, tracker.IsPVCIncluded("ns-1", "pvc-3"))
}
