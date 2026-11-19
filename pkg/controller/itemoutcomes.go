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

package controller

import (
	"bytes"

	pkgbackup "github.com/velero-io/velero/pkg/backup"
	"github.com/velero-io/velero/pkg/util/encode"
)

// encodeItemOutcomes returns the gzipped artifact for backup, or nil when
// collection is disabled. The caller keeps the reader nil on any persist error.
func encodeItemOutcomes(backup *pkgbackup.Request) (*bytes.Buffer, []error) {
	if backup.ItemOutcomes == nil {
		return nil, nil
	}
	itemOutcomes := backup.ItemOutcomes.Result()
	itemOutcomes.BackupName = backup.Name
	return encode.ToJSONGzip(itemOutcomes, "backup item outcomes")
}
