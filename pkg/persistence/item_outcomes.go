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

package persistence

import (
	"fmt"
	"io"
	"path"

	"github.com/velero-io/velero/internal/itemoutcome"
)

// GetBackupItemOutcomes returns the per-item outcomes artifact for name, or
// an empty result if the artifact is absent, since backups taken before this
// feature existed (or with it disabled) won't have one.
func (s *objectBackupStore) GetBackupItemOutcomes(name string) (*itemoutcome.ItemOutcomes, error) {
	itemOutcomes := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Kind:          itemoutcome.KindBackup,
		BackupName:    name,
		Items:         []itemoutcome.ItemOutcome{},
	}

	res, err := tryGet(s.objectStore, s.bucket, s.layout.getBackupItemOutcomesKey(name))
	if err != nil {
		return itemOutcomes, err
	}
	if res == nil {
		return itemOutcomes, nil
	}
	defer res.Close()

	if err := decode(res, itemOutcomes); err != nil {
		return itemOutcomes, err
	}
	if itemOutcomes.BackupName == "" {
		// Artifacts written before the field existed still belong to the key
		// that carried them.
		itemOutcomes.BackupName = name
	}

	return itemOutcomes, nil
}

// PutBackupItemOutcomes stores the per-item outcomes artifact for name.
//
// It goes through seekAndPutObject like most of the other artifact writers in
// this file. A nil reader then stores nothing rather than reaching the object
// store, and a reader that implements io.Seeker is rewound first.
//
// Note that the rewind does not apply to the callers today: they pass the
// *bytes.Buffer that encode.ToJSONGzip returns, and *bytes.Buffer has no Seek
// method, so seekToBeginning is a no-op for it. What this buys is the nil guard
// and one fewer writer in this file behaving unlike its neighbours.
func (s *objectBackupStore) PutBackupItemOutcomes(name string, itemOutcomes io.Reader) error {
	return seekAndPutObject(s.objectStore, s.bucket, s.layout.getBackupItemOutcomesKey(name), itemOutcomes)
}

func (l *ObjectStoreLayout) getBackupItemOutcomesKey(backup string) string {
	return path.Join(l.subdirs["backups"], backup, fmt.Sprintf("%s-item-outcomes.json.gz", backup))
}
