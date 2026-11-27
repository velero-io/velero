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

package itemoutcome

import (
	"github.com/velero-io/velero/pkg/plugin/velero"
)

// Item is a handle that binds the Recorder to one item's identity, so callers
// record outcomes with explicit calls instead of relying on log fields.
//
// A nil *Item is valid and every method is a no-op, so callers need no nil
// checks when the feature is disabled.
type Item struct {
	rec *Recorder
	id  velero.ResourceIdentifier
}

// For returns a handle for id. It returns nil when the Recorder is nil, which
// is how a backup with collection disabled is represented.
func (r *Recorder) For(id velero.ResourceIdentifier) *Item {
	if r == nil {
		return nil
	}
	return &Item{rec: r, id: id}
}

// ID returns the identity this handle currently records against.
func (i *Item) ID() velero.ResourceIdentifier {
	if i == nil {
		return velero.ResourceIdentifier{}
	}
	return i.id
}

// Observe records that the item began processing.
func (i *Item) Observe() {
	if i == nil {
		return
	}
	i.rec.Observe(i.id)
}

// Fail records a failure with msg.
func (i *Item) Fail(msg string) {
	if i == nil {
		return
	}
	i.rec.Fail(i.id, msg)
}

// Warn records a warning with msg.
func (i *Item) Warn(msg string) {
	if i == nil {
		return
	}
	i.rec.Warn(i.id, msg)
}

// Skip records that the item was skipped, with reason. It marks an item-level
// skip, which a later volume verdict cannot turn into a success.
func (i *Item) Skip(reason string) {
	if i == nil {
		return
	}
	i.rec.Skip(i.id, reason)
}

// SkipVolume records a skip from a volume path, with reason. If another method
// later captures the same volume, finalize rescues the row to Succeeded.
func (i *Item) SkipVolume(reason string) {
	if i == nil {
		return
	}
	i.rec.SkipVolume(i.id, reason)
}

// RecordVolumeAttempt keeps a capture-time volume attempt on this item. The
// finalize fold merges it into the owning volume's attempt list.
func (i *Item) RecordVolumeAttempt(attempt VolumeAttempt) {
	if i == nil {
		return
	}
	i.rec.RecordVolumeAttempt(i.id, attempt)
}

// SetOwner records that this item names owner as its controller ownerReference.
func (i *Item) SetOwner(owner velero.ResourceIdentifier) {
	if i == nil {
		return
	}
	i.rec.SetOwner(i.id, owner)
}

// SetReportedBy records that a backup item action named this item as an
// additional item.
func (i *Item) SetReportedBy(reporter velero.ResourceIdentifier) {
	if i == nil {
		return
	}
	i.rec.SetReportedBy(i.id, reporter)
}

// Rekey follows an item renamed by a plugin. It moves the row to the new
// identity so later writes land on the item that was actually backed up, rather
// than minting a second row under the new name. Edges that name the old
// identity are left alone; a dangling reporter is tolerated by every reader.
func (i *Item) Rekey(id velero.ResourceIdentifier) {
	if i == nil {
		return
	}
	i.rec.rekey(i.id, id)
	i.id = id
}
