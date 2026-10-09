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

// pvcMustInclusionTracker provides read-only checks for whether a PVC is included
// in the backup as BIA's additionalItems through annotation
// backup.velero.io/must-include-additional-items.
type pvcMustInclusionTracker struct {
	mustInclude *backedUpItemsMap
}

func NewPVCMustInclusionTracker(mustInclude *backedUpItemsMap) vhutil.PVCMustInclusionTracker {
	return &pvcMustInclusionTracker{
		mustInclude: mustInclude,
	}
}

func (p *pvcMustInclusionTracker) IsPVCIncluded(namespace, pvcName string) bool {
	pvcKey := itemKey{
		resource:  kuberesource.PersistentVolumeClaims.String(),
		namespace: namespace,
		name:      pvcName,
	}

	// 1. If the PVC was explicitly forced into the backup by a BIA, it will be backed up.
	if p.mustInclude != nil && p.mustInclude.Has(pvcKey) {
		return true
	}

	return false
}
