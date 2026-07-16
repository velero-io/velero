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

package datamover

import (
	"fmt"

	datamoverutil "github.com/vmware-tanzu/velero/pkg/util/datamover"
)

func GetUploaderType(dataMover string) string {
	if datamoverutil.IsBuiltInDataMover(dataMover) {
		return "kopia"
	} else {
		return dataMover
	}
}

func GetRealSource(sourceNamespace string, pvcName string) string {
	return fmt.Sprintf("%s/%s", sourceNamespace, pvcName)
}
