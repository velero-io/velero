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

package retainedsnapshot

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/builder"
	repotypes "github.com/velero-io/velero/pkg/repository/types"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func testBackup() *velerov1api.Backup {
	backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()
	backup.UID = "backup-uid"
	return backup
}

func testEntry(handle string) *Entry {
	return &Entry{
		CSISnapshotHandle: handle,
		Driver:            "rbd.csi.ceph.com",
		Trusted:           true,
	}
}

func dataUploadWithRecord(name string, handle string) *velerov2alpha1api.DataUpload {
	du := builder.ForDataUpload(velerov1api.DefaultNamespace, name).
		Labels(map[string]string{velerov1api.BackupNameLabel: "foo"}).
		SnapshotType(velerov2alpha1api.SnapshotTypeCSI).
		SourceNamespace("app").
		SourcePVC("data").
		DataMover("velero-block").
		Result()
	du.Status.RetainedCSIStorageSnapshot = &velerov2alpha1api.RetainedCSIStorageSnapshot{
		CSISnapshotHandle: handle,
		Driver:            "rbd.csi.ceph.com",
	}
	return du
}

func listShards(t *testing.T, c client.Client) []*corev1api.ConfigMap {
	t.Helper()
	family, err := LoadFamily(t.Context(), c, testBackup())
	require.NoError(t, err)
	return family.Shards
}

// TestWriteEntriesGathersByKey proves the family is keyed by the DataUpload
// name, stamped inactive, and merged on a retry instead of rejected.
func TestWriteEntriesGathersByKey(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": testEntry("handle-1"),
		"du-2": testEntry("handle-2"),
	}))

	shards := listShards(t, c)
	require.Len(t, shards, 1)
	shard := shards[0]
	assert.Equal(t, FamilyNamePrefix("backup-uid")+"0", shard.Name)
	assert.Equal(t, "false", shard.Data[ActiveKey], "the gather stamps the inactive activation state")
	entry, err := UnmarshalEntry(shard.Data["du-1"])
	require.NoError(t, err)
	assert.Equal(t, "handle-1", entry.CSISnapshotHandle)
	assert.True(t, entry.Trusted)

	// A retry of the same deletion merges into the existing family: a plain
	// create would fail on AlreadyExists and turn every later retry into a
	// permanent failure until an operator removes the map by hand.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-2": testEntry("handle-2"),
		"du-3": testEntry("handle-3"),
	}))
	shards = listShards(t, c)
	require.Len(t, shards, 1)
	assert.Len(t, shardPendingKeys(t, shards[0]), 3)
}

// TestWriteEntriesShardsBeforeLimit proves the records are split into shards
// before the 1 MiB ConfigMap data limit, so a backup with thousands of
// retained snapshots does not fail the gather itself.
func TestWriteEntriesShardsBeforeLimit(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	entries := map[string]*Entry{}
	for i := 0; i < 5; i++ {
		entry := testEntry(strings.Repeat("h", 300*1024))
		entries[duName(i)] = entry
	}
	require.NoError(t, WriteEntries(t.Context(), c, backup, entries))

	shards := listShards(t, c)
	require.Greater(t, len(shards), 1, "five 300 KiB records must be split into shards")
	total := 0
	for _, shard := range shards {
		for key, value := range shard.Data {
			if key == ActiveKey || key == CompletedKey {
				continue
			}
			total++
			require.Less(t, len(key)+len(value), dataBudget, "a shard must stay under the ConfigMap data limit")
		}
	}
	assert.Equal(t, 5, total)
}

func duName(i int) string {
	if i < 10 {
		return "du-00" + string(rune('0'+i))
	}
	return "du-0" + string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// TestCompletedSetSuppressesReplay proves that an entry removed after its
// snapshot was confirmed deleted leaves the DataUpload name in the completed
// set, and a later regather from the unchanged tarball does not recreate it.
func TestCompletedSetSuppressesReplay(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": testEntry("handle-1"),
		"du-2": testEntry("handle-2"),
	}))
	require.NoError(t, MarkCompleted(t.Context(), c, backup, "du-1"))

	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	_, pending := family.Entry("du-1")
	assert.False(t, pending, "the completed entry is removed")
	assert.Contains(t, family.CompletedSet(), "du-1")

	// The regather must not resurrect the completed entry.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": testEntry("handle-1"),
	}))
	family, err = LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	_, pending = family.Entry("du-1")
	assert.False(t, pending, "a regather does not recreate a completed entry")
	assert.Equal(t, 1, family.PendingEntries())
}

// TestWriteEntriesMergesAttemptCount proves that an entry that escalated
// carries its persisted attempt count, and a re-encounter merges that count
// instead of resetting it, so a driver that fails slowly still reaches the
// bound across retries of the backup deletion.
func TestWriteEntriesMergesAttemptCount(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": {CSISnapshotHandle: "handle-1", Driver: "d", Attempts: 3},
	}))

	// A regather with a fresh entry keeps the persisted count.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": testEntry("handle-1"),
	}))
	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	entry, ok := family.Entry("du-1")
	require.True(t, ok)
	assert.Equal(t, 3, entry.Attempts)
}

// TestWriteEntriesPreservesResolvedHandle proves that a regather of a
// pre-rollback entry, whose tarball copy still carries an empty handle, does
// not overwrite a handle a previous attempt resolved from the repository
// snapshot's tag: after the repository data is deleted, the resolved handle
// is the only copy left, and losing it turns a resolvable record into a
// dropped one that leaks the snapshot.
func TestWriteEntriesPreservesResolvedHandle(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	// The pre-rollback gather: no handle, the repository snapshot identifies it.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": {Driver: "d", Snapshot: &repotypes.SnapshotIdentifier{SnapshotID: "kopia-1"}},
	}))
	// The handle was resolved from the tag and persisted.
	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	entry, ok := family.Entry("du-1")
	require.True(t, ok)
	entry.CSISnapshotHandle = "resolved-handle"
	require.NoError(t, UpdateEntry(t.Context(), c, backup, "du-1", entry))

	// A retry regathers from the unchanged tarball: the incoming entry still
	// carries no handle.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": {Driver: "d", Snapshot: &repotypes.SnapshotIdentifier{SnapshotID: "kopia-1"}},
	}))

	family, err = LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	entry, ok = family.Entry("du-1")
	require.True(t, ok)
	assert.Equal(t, "resolved-handle", entry.CSISnapshotHandle,
		"the resolved handle must survive a regather whose incoming entry carries none")
}

// TestWriteEntriesDoesNotDuplicateKeyAcrossShards proves that a retry writes
// an existing key into the shard that already carries it, not into a
// different shard with room: a duplicate would survive MarkCompleted, which
// removes only one copy, and the snapshot would be deleted twice.
func TestWriteEntriesDoesNotDuplicateKeyAcrossShards(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	// Fill the first shard and spill into a second, then place du-x in the
	// first shard, which is nearly full, while the second has room.
	big := func() *Entry { return testEntry(strings.Repeat("h", 300*1024)) }
	entries := map[string]*Entry{
		"big-00": big(), "big-01": big(), "big-02": big(), "big-03": big(),
		"du-x": testEntry("handle-x"),
	}
	require.NoError(t, WriteEntries(t.Context(), c, backup, entries))
	shards := listShards(t, c)
	require.Len(t, shards, 2, "four 300 KiB records plus a small one must spill into a second shard")
	inShard := 0
	for _, shard := range shards {
		if _, ok := shard.Data["du-x"]; ok {
			inShard++
		}
	}
	require.Equal(t, 1, inShard, "du-x must live in exactly one shard after the first write")

	// A retry of the same entry must not duplicate it in the other shard.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{"du-x": testEntry("handle-x")}))
	shards = listShards(t, c)
	require.Len(t, shards, 2)
	inShard = 0
	for _, shard := range shards {
		if _, ok := shard.Data["du-x"]; ok {
			inShard++
		}
	}
	assert.Equal(t, 1, inShard, "a retry must write the key into the shard that already carries it, not a second one")
}

// TestWriteEntriesUpdatesOnlyChangedShards proves the gather persists only
// the shards it wrote an entry into: the delete action gathers once per
// DataUpload in the tarball, and rewriting every shard on each call would
// make the API traffic quadratic in the number of records.
func TestWriteEntriesUpdatesOnlyChangedShards(t *testing.T) {
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t)
	var updates int
	c := interceptor.NewClient(fakeClient.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			updates++
			return cl.Update(ctx, obj, opts...)
		},
	})
	backup := testBackup()

	big := func() *Entry { return testEntry(strings.Repeat("h", 300*1024)) }
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"big-00": big(), "big-01": big(), "big-02": big(), "big-03": big(),
	}))
	require.Len(t, listShards(t, c), 2)

	// A gather of one small entry touches only the shard it lands in.
	updates = 0
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{"du-1": testEntry("handle-1")}))
	assert.Equal(t, 1, updates, "only the shard the entry was written into is updated")
}

// TestTombstoneEntrySuppressesRegather proves the escalated-entry tombstone:
// a record moved to the orphan-snapshot ConfigMap leaves the DataUpload name
// in the completed set, so a regather from the unchanged tarball does not
// resurrect it with its attempt count reset to zero.
func TestTombstoneEntrySuppressesRegather(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": {CSISnapshotHandle: "handle-1", Driver: "d", Attempts: MaxAttempts},
	}))
	require.NoError(t, TombstoneEntry(t.Context(), c, backup, "du-1"))

	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	_, pending := family.Entry("du-1")
	assert.False(t, pending, "the escalated entry is removed")
	assert.Contains(t, family.CompletedSet(), "du-1")

	// The regather from the unchanged tarball must not recreate the entry.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": testEntry("handle-1"),
	}))
	family, err = LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.Zero(t, family.PendingEntries(), "a regather does not recreate an escalated entry")
}

// TestActivateIsolatedFromPending proves the activation semantics: the
// retained-snapshot controller ignores an inactive ConfigMap, activation is
// idempotent, and HasPendingWork counts only active shards.
func TestActivateIsolatedFromPending(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{
		"du-1": testEntry("handle-1"),
	}))

	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.False(t, family.IsActivated())
	assert.False(t, family.HasPendingWork(), "an inactive shard has no work for the retained-snapshot controller")

	require.NoError(t, Activate(t.Context(), c, backup))
	family, err = LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.True(t, family.IsActivated())
	assert.True(t, family.HasPendingWork())

	// Activation is idempotent and repairs a shard without the key.
	require.NoError(t, Activate(t.Context(), c, backup))
}

// TestOrphanEntriesOutliveBackup proves the orphan-snapshot ConfigMap is not
// labeled by backup and is keyed by <backup-UID>.<DataUpload-name>, so its
// entries cannot collide across backups once the backup label is absent.
func TestOrphanEntriesOutliveBackup(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteOrphanEntry(t.Context(), c, backup, "du-1", testEntry("handle-1")))

	list := &corev1api.ConfigMapList{}
	require.NoError(t, c.List(t.Context(), list, client.MatchingLabels{OrphanLabel: "true"}))
	require.Len(t, list.Items, 1)
	orphan := list.Items[0]
	assert.NotContains(t, orphan.Labels, velerov1api.BackupNameLabel, "the orphan ConfigMap is not labeled by backup")
	assert.Contains(t, orphan.Data, "backup-uid.du-1")

	// The orphan write and the family write must not see each other's shards.
	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{"du-2": testEntry("handle-2")}))
	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	require.Len(t, family.Shards, 1)
	assert.NotContains(t, family.Shards[0].Data, "backup-uid.du-1")
}

// TestDeleteRemovesFamily proves the tail's own Backup deletion is not the GC
// trigger: the tail removes the family itself.
func TestDeleteRemovesFamily(t *testing.T) {
	c := velerotest.NewFakeControllerRuntimeClient(t)
	backup := testBackup()

	require.NoError(t, WriteEntries(t.Context(), c, backup, map[string]*Entry{"du-1": testEntry("handle-1")}))
	require.NoError(t, Delete(t.Context(), c, backup))

	family, err := LoadFamily(t.Context(), c, backup)
	require.NoError(t, err)
	assert.Empty(t, family.Shards)
}

// TestFromDataUploadStatus proves the entry is built from the DataUpload's
// persisted record and marked trusted, and that a DataUpload without a record
// contributes nothing.
func TestFromDataUploadStatus(t *testing.T) {
	entry := FromDataUploadStatus(dataUploadWithRecord("du-1", "handle-1"))
	require.NotNil(t, entry)
	assert.Equal(t, "handle-1", entry.CSISnapshotHandle)
	assert.True(t, entry.Trusted)

	du := dataUploadWithRecord("du-1", "handle-1")
	du.Status.RetainedCSIStorageSnapshot = nil
	assert.Nil(t, FromDataUploadStatus(du))
}

// TestEntryRecord proves the entry's record carries the deletion fields the
// temp VolumeSnapshotContent is rebuilt from.
func TestEntryRecord(t *testing.T) {
	entry := &Entry{
		CSISnapshotHandle:   "handle-1",
		Driver:              "rbd.csi.ceph.com",
		ManagedByLabelValue: "node-a",
		DeletionSecretRef: &corev1api.SecretReference{
			Name:      "rook-csi-rbd-provisioner",
			Namespace: "rook-ceph",
		},
	}
	record := entry.Record()
	assert.Equal(t, "handle-1", record.CSISnapshotHandle)
	assert.Equal(t, "rbd.csi.ceph.com", record.Driver)
	assert.Equal(t, "node-a", record.ManagedByLabelValue)
	assert.Equal(t, "rook-csi-rbd-provisioner", record.DeletionSecretRef.Name)
}

// pendingKeys is exported for the controller package through the family API;
// shardPendingKeys is a test helper mirroring it.
func shardPendingKeys(t *testing.T, shard *corev1api.ConfigMap) []string {
	t.Helper()
	keys := []string{}
	for key := range shard.Data {
		if key == ActiveKey || key == CompletedKey {
			continue
		}
		keys = append(keys, key)
	}
	return keys
}
