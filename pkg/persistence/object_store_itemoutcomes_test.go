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
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/velero-io/velero/internal/itemoutcome"
)

func TestGetBackupItemOutcomes(t *testing.T) {
	tests := []struct {
		name           string
		itemOutcomes   *itemoutcome.ItemOutcomes
		expectedResult *itemoutcome.ItemOutcomes
	}{
		{
			name:           "No item outcomes artifact, expect empty result and no error.",
			expectedResult: &itemoutcome.ItemOutcomes{SchemaVersion: itemoutcome.SchemaVersion, Kind: itemoutcome.KindBackup, BackupName: "test-backup", Items: []itemoutcome.ItemOutcome{}},
		},
		{
			name: "Valid ItemOutcomes, should pass.",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Kind:          itemoutcome.KindBackup,
				Items: []itemoutcome.ItemOutcome{
					{
						GroupResource: "pods",
						Namespace:     "ns1",
						Name:          "pod1",
						Outcome:       itemoutcome.OutcomeSucceeded,
					},
				},
			},
			expectedResult: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Kind:          itemoutcome.KindBackup,
				BackupName:    "test-backup",
				Items: []itemoutcome.ItemOutcome{
					{
						GroupResource: "pods",
						Namespace:     "ns1",
						Name:          "pod1",
						Outcome:       itemoutcome.OutcomeSucceeded,
					},
				},
			},
		},
	}

	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.itemOutcomes != nil {
				obj := new(bytes.Buffer)
				gzw := gzip.NewWriter(obj)

				require.NoError(t, json.NewEncoder(gzw).Encode(tc.itemOutcomes))
				require.NoError(t, gzw.Close())
				harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-item-outcomes.json.gz", obj)
			}

			result, err := harness.GetBackupItemOutcomes("test-backup")
			require.NoError(t, err)
			require.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestPutBackupItemOutcomes(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("foo", "")

	outcomes := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Kind:          itemoutcome.KindBackup,
		BackupName:    "backup-1",
		Items: []itemoutcome.ItemOutcome{
			{GroupResource: "pods", Namespace: "ns1", Name: "pod1", Outcome: itemoutcome.OutcomeSucceeded},
		},
	}

	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	require.NoError(t, json.NewEncoder(gzw).Encode(outcomes))
	require.NoError(t, gzw.Close())

	require.NoError(t, harness.PutBackupItemOutcomes("backup-1", buf))

	keys, err := harness.objectStore.ListObjects("foo", "")
	require.NoError(t, err)
	assert.Contains(t, keys, "backups/backup-1/backup-1-item-outcomes.json.gz")

	result, err := harness.GetBackupItemOutcomes("backup-1")
	require.NoError(t, err)
	assert.Equal(t, outcomes, result)
}

// A reader that has already been consumed must be rewound rather than uploaded
// empty. Storing an empty artifact would look like a backup that touched no
// items, which reads as a clean backup rather than a corrupt file.
func TestPutBackupItemOutcomesNilReaderIsNoOp(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("foo", "")

	require.NoError(t, harness.PutBackupItemOutcomes("backup-1", nil))

	keys, err := harness.objectStore.ListObjects("foo", "")
	require.NoError(t, err)
	assert.NotContains(t, keys, "backups/backup-1/backup-1-item-outcomes.json.gz",
		"a nil reader must store nothing rather than reach the object store")
}

// *bytes.Buffer, the type the callers actually pass, has no Seek method, so the
// rewind in seekAndPutObject only reaches readers that implement io.Seeker. This
// pins that path with a *bytes.Reader, which does.
func TestPutBackupItemOutcomesRewindsSeekableReader(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("foo", "")

	outcomes := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Kind:          itemoutcome.KindBackup,
		BackupName:    "backup-1",
		Items: []itemoutcome.ItemOutcome{
			{GroupResource: "pods", Namespace: "ns1", Name: "pod1", Outcome: itemoutcome.OutcomeSucceeded},
		},
	}

	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	require.NoError(t, json.NewEncoder(gzw).Encode(outcomes))
	require.NoError(t, gzw.Close())

	reader := bytes.NewReader(buf.Bytes())

	// Drain the reader first, as a caller that inspected the bytes would.
	_, err := io.ReadAll(reader)
	require.NoError(t, err)

	require.NoError(t, harness.PutBackupItemOutcomes("backup-1", reader))

	result, err := harness.GetBackupItemOutcomes("backup-1")
	require.NoError(t, err)
	assert.Equal(t, outcomes, result, "the artifact must be the full payload, not what remained unread")
}
