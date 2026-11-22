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

// Package retainedsnapshot holds the working record of a backup's retained
// snapshots during backup deletion.
//
// The DataUploads are deleted in an earlier step of the deletion, so the
// working record is a sharded ConfigMap family, retained-snapshots-<backup-UID>-<n>,
// in the Velero namespace, keyed by the DataUpload name. The family is written
// create-or-update, so a retry of `velero backup delete` merges into the map
// an earlier, failed attempt left behind instead of failing on AlreadyExists.
// ConfigMap data is limited to 1 MiB and a record is a few hundred bytes, so
// the records are sharded, split before the limit and labeled by backup for
// discovery. A surviving record means the snapshot was not released; even a
// stale record is harmless, because a deletion that finds the snapshot already
// gone is a success.
package retainedsnapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/label"
	repotypes "github.com/velero-io/velero/pkg/repository/types"
)

const (
	// FamilyLabel marks the ConfigMaps of a backup's retained snapshot record
	// family. The retained-snapshot controller is keyed by it.
	FamilyLabel = "velero.io/retained-snapshots"

	// OrphanLabel marks the ConfigMaps that hold snapshots the deletion
	// escalated or skipped. They are not labeled by backup, so they are neither
	// deleted by the family's last-entry rule nor garbage-collected when the
	// Backup is gone; the orphan record is the durable home for manual cleanup
	// after the Backup object is gone.
	OrphanLabel = "velero.io/orphan-snapshots"

	// ActiveKey is the ConfigMap data key carrying the family's persisted
	// activation state. The gather writes it as inactive; the DeleteBackupRequest
	// stamps it active only after every prerequisite step -- repository data and
	// DataUploads -- has succeeded. The retained-snapshot controller ignores an
	// inactive ConfigMap, so a deletion whose repository step failed gathers
	// records but never creates a temporary content. A shard without the key is
	// never treated as complete or empty while unactivated.
	ActiveKey = "active"

	// CompletedKey holds the JSON array of DataUpload names whose snapshots
	// were confirmed deleted. A shard with no pending entries keeps its
	// completed set -- the evidence that suppresses replay -- until the
	// deletion finishes, so a later regather from the unchanged tarball does
	// not recreate an entry.
	CompletedKey = "completed"

	// activeValue / inactiveValue are the two states of ActiveKey.
	activeValue   = "true"
	inactiveValue = "false"

	// dataBudget is the ConfigMap data size limit; the records are split into
	// shards before the limit is reached.
	dataBudget = 1 << 20

	// MaxAttempts is the bounded number of persisted DeleteSnapshot failures,
	// for one record, that come from the DeleteSnapshot call itself, after
	// which the record is escalated to the orphan ConfigMap and the backup
	// deletion proceeds. A driver that fails slowly still reaches the bound
	// across retries of `velero backup delete`, because the counter is
	// persisted in the entry.
	MaxAttempts = 5
)

// FamilyNamePrefix returns the prefix of the shard names of a backup's record
// family. The backup UID, not the name, keys the family: names can repeat.
func FamilyNamePrefix(backupUID string) string {
	return "retained-snapshots-" + backupUID + "-"
}

// OrphanNamePrefix returns the prefix of the orphan-snapshot ConfigMap names.
func OrphanNamePrefix() string {
	return "orphan-snapshots-"
}

// FamilyLabels returns the discovery labels of a backup's record family.
func FamilyLabels(backup *velerov1api.Backup) map[string]string {
	return map[string]string{
		velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
		velerov1api.BackupUIDLabel:  string(backup.UID),
		FamilyLabel:                 "true",
	}
}

// Entry is one retained snapshot record in a shard, keyed by the DataUpload
// name. The snapshot fields carry the record gathered from the DataUpload
// status, the backup tarball or the repository tag; a record whose
// CSISnapshotHandle is empty is a pre-rollback backup whose handle still has
// to be resolved from the repository snapshot's cbt-change-id tag before the
// repository data is deleted.
type Entry struct {
	// CSISnapshotHandle is the CSI snapshot handle of the retained snapshot.
	CSISnapshotHandle string `json:"csiSnapshotHandle,omitempty"`
	// Driver is the name of the CSI driver that created the snapshot.
	Driver string `json:"driver,omitempty"`
	// DeletionSecretRef names the secret the driver requires to delete the snapshot.
	DeletionSecretRef *corev1api.SecretReference `json:"deletionSecretRef,omitempty"`
	// ManagedByLabelValue is the managed-by label value of the backup content.
	ManagedByLabelValue string `json:"managedByLabelValue,omitempty"`
	// Snapshot identifies the repository snapshot that holds the handle as its
	// cbt-change-id tag, for a backup taken before Velero recorded retained
	// snapshots. The handle must be resolved from it before the repository
	// data is deleted, because deleting that data destroys the tag.
	Snapshot *repotypes.SnapshotIdentifier `json:"snapshot,omitempty"`
	// Attempts is the persisted number of DeleteSnapshot failures that came
	// from the call itself. A retry of `velero backup delete` is a new
	// DeleteBackupRequest and any in-memory count would reset on it, so the
	// counter lives here.
	Attempts int `json:"attempts,omitempty"`
	// Trusted is true when the record was sourced from DataUpload.status, which
	// entered through the API; tarball- and tag-sourced values are written by
	// anyone who can write the backup storage, so they are preferred only
	// where no trusted value exists.
	Trusted bool `json:"trusted,omitempty"`
}

// FromDataUploadStatus builds the entry of a DataUpload's persisted record.
func FromDataUploadStatus(du *velerov2alpha1api.DataUpload) *Entry {
	record := du.Status.RetainedCSIStorageSnapshot
	if record == nil {
		return nil
	}
	return &Entry{
		CSISnapshotHandle:   record.CSISnapshotHandle,
		Driver:              record.Driver,
		DeletionSecretRef:   record.DeletionSecretRef,
		ManagedByLabelValue: record.ManagedByLabelValue,
		Trusted:             true,
	}
}

// Record returns the retained snapshot record of the entry.
func (e *Entry) Record() *velerov2alpha1api.RetainedCSIStorageSnapshot {
	return &velerov2alpha1api.RetainedCSIStorageSnapshot{
		CSISnapshotHandle:   e.CSISnapshotHandle,
		Driver:              e.Driver,
		DeletionSecretRef:   e.DeletionSecretRef,
		ManagedByLabelValue: e.ManagedByLabelValue,
	}
}

func marshalEntry(entry *Entry) (string, error) {
	b, err := json.Marshal(entry)
	if err != nil {
		return "", errors.Wrap(err, "error marshaling the retained snapshot entry")
	}
	return string(b), nil
}

// UnmarshalEntry decodes one entry value.
func UnmarshalEntry(value string) (*Entry, error) {
	entry := &Entry{}
	if err := json.Unmarshal([]byte(value), entry); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling the retained snapshot entry")
	}
	return entry, nil
}

// Family is the shard family of one backup's records, discovered by label.
// No shard is special, and "the family empties" means every shard of the
// family is empty of pending entries.
type Family struct {
	Shards []*corev1api.ConfigMap
}

// LoadFamily discovers a backup's shard family by label. A backup whose
// records were never gathered, or whose family a previous attempt already
// emptied and deleted, returns an empty family. The reader may be an uncached
// API reader: the backup-deletion controller's safety decisions must not be
// made on an informer-lagged list that misses a shard a gather just created.
func LoadFamily(ctx context.Context, c client.Reader, backup *velerov1api.Backup) (*Family, error) {
	list := &corev1api.ConfigMapList{}
	if err := c.List(ctx, list, &client.ListOptions{
		Namespace:     backup.Namespace,
		LabelSelector: labels.SelectorFromSet(FamilyLabels(backup)),
	}); err != nil {
		return nil, errors.Wrap(err, "error listing the retained snapshot record family")
	}
	family := &Family{}
	for i := range list.Items {
		family.Shards = append(family.Shards, &list.Items[i])
	}
	sort.Slice(family.Shards, func(i, j int) bool {
		return family.Shards[i].Name < family.Shards[j].Name
	})
	return family, nil
}

// IsEmpty reports whether no shard of the family carries a pending entry. A
// shard with no pending entries still counts its completed set, and an
// inactive shard is never treated as complete or empty for the activation
// decision; see HasPendingWork.
func (f *Family) IsEmpty() bool {
	return f.PendingEntries() == 0
}

// PendingEntries returns the number of pending entries across the family.
func (f *Family) PendingEntries() int {
	pending := 0
	for _, shard := range f.Shards {
		pending += len(pendingKeys(shard))
	}
	return pending
}

// HasPendingWork reports whether the family has work for the retained-snapshot
// controller: an active shard with a pending entry. An inactive shard is never
// treated as complete or empty while unactivated, so a family that is entirely
// inactive has no work but also does not count as finished for a request that
// has not activated it yet; the request decides through IsActivated.
func (f *Family) HasPendingWork() bool {
	for _, shard := range f.Shards {
		if shard.Data[ActiveKey] != activeValue {
			continue
		}
		if len(pendingKeys(shard)) > 0 {
			return true
		}
	}
	return false
}

// IsActivated reports whether every shard of the family carries the active
// state. A shard without the key counts as unactivated.
func (f *Family) IsActivated() bool {
	for _, shard := range f.Shards {
		if shard.Data[ActiveKey] != activeValue {
			return false
		}
	}
	return len(f.Shards) > 0
}

// Entry returns the pending entry of the named DataUpload.
func (f *Family) Entry(duName string) (*Entry, bool) {
	for _, shard := range f.Shards {
		if value, ok := shard.Data[duName]; ok {
			entry, err := UnmarshalEntry(value)
			if err != nil {
				return nil, true
			}
			return entry, true
		}
	}
	return nil, false
}

// CompletedSet returns the names whose snapshots were confirmed deleted.
func (f *Family) CompletedSet() map[string]struct{} {
	completed := map[string]struct{}{}
	for _, shard := range f.Shards {
		var names []string
		if value, ok := shard.Data[CompletedKey]; ok && value != "" {
			if err := json.Unmarshal([]byte(value), &names); err != nil {
				continue
			}
		}
		for _, name := range names {
			completed[name] = struct{}{}
		}
	}
	return completed
}

func pendingKeys(shard *corev1api.ConfigMap) []string {
	var keys []string
	for key := range shard.Data {
		if key == ActiveKey || key == CompletedKey {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func shardSize(shard *corev1api.ConfigMap) int {
	size := 0
	for key, value := range shard.Data {
		size += len(key) + len(value)
	}
	return size
}

// WriteEntries merges entries into the backup's shard family, create-or-update,
// keyed by the DataUpload name, and stamps the inactive activation state on
// every shard it creates or merges. An existing map from an earlier, failed
// attempt of the same deletion is merged into, never rejected. An entry whose
// DataUpload name is in a shard's completed set is not resurrected; where both
// the family and the given entries carry a record for the same DataUpload, the
// given entry wins, except that its persisted attempt count merges with, never
// resets, the count already in the family.
func WriteEntries(ctx context.Context, c client.Client, backup *velerov1api.Backup, entries map[string]*Entry) error {
	return writeShardedEntries(ctx, c, backup, FamilyLabels(backup), FamilyNamePrefix(string(backup.UID)), entries)
}

// WriteOrphanEntry merges one escalated or skipped entry into the
// orphan-snapshot ConfigMaps, keyed by <backup-UID>.<DataUpload-name>, which
// satisfies the ConfigMap data key charset and cannot collide across backups
// once the backup label is absent. The orphan ConfigMaps are not labeled by
// backup and outlive the Backup; removing an entry after its snapshot is
// cleaned up by hand is the operator's action.
func WriteOrphanEntry(ctx context.Context, c client.Client, backup *velerov1api.Backup, duName string, entry *Entry) error {
	entries := map[string]*Entry{string(backup.UID) + "." + duName: entry}
	return writeShardedEntries(ctx, c, backup, map[string]string{OrphanLabel: "true"}, OrphanNamePrefix(), entries)
}

func writeShardedEntries(ctx context.Context, c client.Client, backup *velerov1api.Backup, shardLabels map[string]string, namePrefix string, entries map[string]*Entry) error {
	if len(entries) == 0 {
		return nil
	}

	// Discover the shards carrying the same labels and prefix: an orphan write
	// and a family write must not see each other's shards, so both the labels
	// and the name prefix narrow the list.
	list := &corev1api.ConfigMapList{}
	if err := c.List(ctx, list, &client.ListOptions{
		Namespace:     backup.Namespace,
		LabelSelector: labels.SelectorFromSet(shardLabels),
	}); err != nil {
		return errors.Wrap(err, "error listing the retained snapshot shards")
	}
	shards := map[string]*corev1api.ConfigMap{}
	for i := range list.Items {
		if len(list.Items[i].Name) > len(namePrefix) && list.Items[i].Name[:len(namePrefix)] == namePrefix {
			shards[list.Items[i].Name] = &list.Items[i]
		}
	}

	completed := map[string]struct{}{}
	for _, shard := range shards {
		for _, name := range decodeCompleted(shard) {
			completed[name] = struct{}{}
		}
	}

	// Order the names so the shard assignment is deterministic across retries.
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	nextIndex := len(shards)
	// Only the shards an entry was written into are persisted: the delete
	// action gathers once per DataUpload in the tarball, and rewriting every
	// shard on each of those calls would make the API traffic quadratic in
	// the number of records and starve the single-worker controllers behind
	// it.
	dirty := map[string]struct{}{}
	for _, name := range names {
		if _, done := completed[name]; done {
			// The snapshot was already confirmed deleted by an earlier
			// attempt; a regather from the unchanged tarball must not
			// recreate the entry.
			continue
		}
		entry := entries[name]
		// Merge the persisted state instead of resetting it: the attempt
		// count, and a handle a previous attempt resolved from the repository
		// snapshot's tag. The regather's entry still carries an empty handle
		// -- the tarball never changes -- while the resolved handle is the
		// only copy left once the repository data is deleted; losing it turns
		// a resolvable record into a dropped one and leaks the snapshot.
		for _, shard := range shards {
			if value, ok := shard.Data[name]; ok {
				if existing, err := UnmarshalEntry(value); err == nil {
					if existing.Attempts > entry.Attempts {
						entry.Attempts = existing.Attempts
					}
					if entry.CSISnapshotHandle == "" && existing.CSISnapshotHandle != "" {
						entry.CSISnapshotHandle = existing.CSISnapshotHandle
					}
				}
			}
		}

		value, err := marshalEntry(entry)
		if err != nil {
			return err
		}
		shard := findShardWithRoom(shards, name, value)
		if shard == nil {
			shard = &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: backup.Namespace,
					Name:      fmt.Sprintf("%s%d", namePrefix, nextIndex),
					Labels:    shardLabels,
					// The full backup name lives in an annotation because the
					// backup-name label cannot carry it: label values are
					// capped at 63 characters and the sanitized label hashes
					// longer names, which cannot be turned back into the
					// Backup's name.
					Annotations: map[string]string{velerov1api.RetainedSnapshotsBackupNameAnnotation: backup.Name},
				},
				Data: map[string]string{},
			}
			nextIndex++
		}
		if shard.Data == nil {
			shard.Data = map[string]string{}
		}
		if shard.Annotations == nil {
			shard.Annotations = map[string]string{}
		}
		shard.Annotations[velerov1api.RetainedSnapshotsBackupNameAnnotation] = backup.Name
		shard.Data[name] = value
		shard.Data[ActiveKey] = inactiveValue
		shards[shard.Name] = shard
		dirty[shard.Name] = struct{}{}
	}

	for name, shard := range shards {
		if _, changed := dirty[name]; !changed && shard.ResourceVersion != "" {
			continue
		}
		if shard.ResourceVersion == "" {
			if err := c.Create(ctx, shard); err != nil {
				return errors.Wrapf(err, "error creating the retained snapshot shard %s", shard.Name)
			}
			continue
		}
		if err := c.Update(ctx, shard); err != nil {
			return errors.Wrapf(err, "error updating the retained snapshot shard %s", shard.Name)
		}
	}
	return nil
}

// findShardWithRoom returns the shard the key belongs in: the shard that
// already carries the key, searched across the whole family first, so a retry
// never duplicates an entry in a second shard -- a duplicate would survive
// MarkCompleted, which removes only one copy, and be deleted twice. A key not
// yet present goes to a shard with room for it.
func findShardWithRoom(shards map[string]*corev1api.ConfigMap, key, value string) *corev1api.ConfigMap {
	shardNames := make([]string, 0, len(shards))
	for name := range shards {
		shardNames = append(shardNames, name)
	}
	sort.Strings(shardNames)
	for _, name := range shardNames {
		if _, exists := shards[name].Data[key]; exists {
			return shards[name]
		}
	}
	for _, name := range shardNames {
		if shardSize(shards[name])+len(key)+len(value) < dataBudget {
			return shards[name]
		}
	}
	return nil
}

func isNotFound(err error) bool {
	return err != nil && apierrors.IsNotFound(err)
}

func decodeCompleted(shard *corev1api.ConfigMap) []string {
	var names []string
	if value, ok := shard.Data[CompletedKey]; ok && value != "" {
		if err := json.Unmarshal([]byte(value), &names); err != nil {
			return nil
		}
	}
	return names
}

// MarkCompleted removes the entry of the named DataUpload from its shard and
// records the name in the shard's completed set, so the entry is removed only
// after the snapshot is confirmed deleted and a later regather does not
// recreate it.
func MarkCompleted(ctx context.Context, c client.Client, backup *velerov1api.Backup, duName string) error {
	return TombstoneEntry(ctx, c, backup, duName)
}

// TombstoneEntry removes the entry of the named DataUpload from its shard and
// records the name in the shard's completed set, for a record this controller
// will not delete: escalated, skipped, or undecodable. The tombstone is what
// suppresses a regather from the unchanged tarball; without it, a retry of
// the backup deletion would resurrect the entry with its attempt count reset
// to zero and hammer a driver that already failed the bounded number of
// DeleteSnapshot calls.
func TombstoneEntry(ctx context.Context, c client.Client, backup *velerov1api.Backup, duName string) error {
	family, err := LoadFamily(ctx, c, backup)
	if err != nil {
		return err
	}
	for _, shard := range family.Shards {
		if _, ok := shard.Data[duName]; !ok {
			continue
		}
		delete(shard.Data, duName)
		completed := decodeCompleted(shard)
		completed = append(completed, duName)
		b, err := json.Marshal(completed)
		if err != nil {
			return errors.Wrap(err, "error marshaling the completed set")
		}
		shard.Data[CompletedKey] = string(b)
		return c.Update(ctx, shard)
	}
	return nil
}

// UpdateEntry persists a mutation of one pending entry, e.g. the resolved
// handle of a pre-rollback record or the incremented attempt count.
func UpdateEntry(ctx context.Context, c client.Client, backup *velerov1api.Backup, duName string, entry *Entry) error {
	family, err := LoadFamily(ctx, c, backup)
	if err != nil {
		return err
	}
	value, err := marshalEntry(entry)
	if err != nil {
		return err
	}
	for _, shard := range family.Shards {
		if _, ok := shard.Data[duName]; !ok {
			continue
		}
		shard.Data[duName] = value
		return c.Update(ctx, shard)
	}
	return errors.Errorf("no pending entry for DataUpload %s in the retained snapshot record family of backup %s", duName, backup.Name)
}

// RemoveEntry drops an entry without recording it as completed, for a record
// that turned out to hold nothing deletable, e.g. a repository snapshot
// without the tag.
func RemoveEntry(ctx context.Context, c client.Client, backup *velerov1api.Backup, duName string) error {
	family, err := LoadFamily(ctx, c, backup)
	if err != nil {
		return err
	}
	for _, shard := range family.Shards {
		if _, ok := shard.Data[duName]; !ok {
			continue
		}
		delete(shard.Data, duName)
		return c.Update(ctx, shard)
	}
	return nil
}

// Activate stamps the active state on every shard of the family, so a
// deletion whose repository step failed gathers records but never has them
// deleted: the retained-snapshot controller ignores an inactive ConfigMap.
// Shards without the key are activated here too, which is how the request's
// re-entry repairs an activation a crash interrupted.
func Activate(ctx context.Context, c client.Client, backup *velerov1api.Backup) error {
	family, err := LoadFamily(ctx, c, backup)
	if err != nil {
		return err
	}
	for _, shard := range family.Shards {
		if shard.Data[ActiveKey] == activeValue {
			continue
		}
		if shard.Data == nil {
			shard.Data = map[string]string{}
		}
		shard.Data[ActiveKey] = activeValue
		if err := c.Update(ctx, shard); err != nil {
			return errors.Wrapf(err, "error activating the retained snapshot shard %s", shard.Name)
		}
	}
	return nil
}

// Delete removes the shard family of the backup. The tail of the deletion
// removes the family itself; it is not left to the Backup's garbage collection.
func Delete(ctx context.Context, c client.Client, backup *velerov1api.Backup) error {
	family, err := LoadFamily(ctx, c, backup)
	if err != nil {
		return err
	}
	for _, shard := range family.Shards {
		if err := c.Delete(ctx, shard); err != nil && !isNotFound(err) {
			return errors.Wrapf(err, "error deleting the retained snapshot shard %s", shard.Name)
		}
	}
	return nil
}
