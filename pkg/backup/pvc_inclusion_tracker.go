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
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	vhutil "github.com/vmware-tanzu/velero/pkg/util/volumehelper"
)

// pvcInclusionTracker implements vhutil.PVCInclusionTracker with read-only checks
// for whether a PVC should be included in backup operations.
type pvcInclusionTracker struct {
	mustInclude *backedUpItemsMap
	backedUp    *backedUpItemsMap
}

func NewPVCInclusionTracker(mustInclude, backedUp *backedUpItemsMap) vhutil.PVCInclusionTracker {
	return &pvcInclusionTracker{
		mustInclude: mustInclude,
		backedUp:    backedUp,
	}
}

func (p *pvcInclusionTracker) IsPVCIncluded(namespace, pvcName string) bool {
	pvcKey := itemKey{
		resource:  kuberesource.PersistentVolumeClaims.String(),
		namespace: namespace,
		name:      pvcName,
	}

	// 1. If the PVC was explicitly forced into the backup by a BIA, it will be backed up.
	if p.mustInclude != nil && p.mustInclude.Has(pvcKey) {
		return true
	}

	// 2. If the PVC was already backed up (e.g. in a scenario where PVCs are processed first), we know it's included.
	if p.backedUp != nil && p.backedUp.Has(pvcKey) {
		return true
	}

	return false
}
