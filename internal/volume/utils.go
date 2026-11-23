/*
Copyright The Velero Contributors.

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

package volume

import (
	"regexp"
)

// it has to have the same value as "github.com/velero-io/velero/pkg/restore".ItemRestoreResultCreated
const itemRestoreResultCreated = "created"

// RestoredPVCFromRestoredResourceList returns a set of PVCs that were restored from the given restoredResourceList.
func RestoredPVCFromRestoredResourceList(restoredResourceList map[string][]string) map[string]struct{} {
	pvcKey := "v1/PersistentVolumeClaim"
	pvcList := make(map[string]struct{})

	for _, pvc := range restoredResourceList[pvcKey] {
		// the format of pvc string in restoredResourceList is like: "namespace/pvcName(status)"
		// extract the substring before "(created)" if the status in rightmost Parenthesis is "created"
		r := regexp.MustCompile(`\(([^)]+)\)`)
		matches := r.FindAllStringSubmatch(pvc, -1)
		if len(matches) > 0 && matches[len(matches)-1][1] == itemRestoreResultCreated {
			pvcList[pvc[:len(pvc)-len("(created)")]] = struct{}{}
		}
	}

	return pvcList
}
