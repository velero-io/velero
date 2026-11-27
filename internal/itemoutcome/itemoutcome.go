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

// Package itemoutcome defines the per-item outcomes artifact and the recorder
// used to build it during a backup.
package itemoutcome

import (
	"fmt"

	"github.com/velero-io/velero/pkg/plugin/velero"
)

// SchemaVersion is the current schema version of the ItemOutcomes artifact.
const SchemaVersion = "v1"

// Outcome is the result of processing a single item during a backup.
type Outcome string

const (
	// OutcomeSucceeded means the item was backed up with no error or warning.
	OutcomeSucceeded Outcome = "Succeeded"
	// OutcomeWarning means the item was processed but produced one or more warnings.
	OutcomeWarning Outcome = "Warning"
	// OutcomeFailed means the item errored, synchronously or during an async operation.
	OutcomeFailed Outcome = "Failed"
	// OutcomeSkipped means the item was excluded or skipped (e.g. a skipped PVC).
	OutcomeSkipped Outcome = "Skipped"
	// OutcomeNamed means another item reported this one, but nothing processed it.
	OutcomeNamed Outcome = "Named"
)

// precedence orders outcomes from least to most significant.
var precedence = map[Outcome]int{
	OutcomeNamed:     -1,
	OutcomeSucceeded: 0,
	OutcomeWarning:   1,
	OutcomeSkipped:   2,
	OutcomeFailed:    3,
}

// MaxMessagesPerItem bounds the messages retained per item.
const MaxMessagesPerItem = 5

// MaxVolumeAttempts bounds the attempts retained per volume.
const MaxVolumeAttempts = 8

// capMessages bounds msgs and replaces the tail with a counted marker.
func capMessages(msgs []string) []string {
	if len(msgs) <= MaxMessagesPerItem {
		return msgs
	}

	shown := make([]string, 0, MaxMessagesPerItem)
	shown = append(shown, msgs[:MaxMessagesPerItem-1]...)
	shown = append(shown, fmt.Sprintf("... and %d more", len(msgs)-MaxMessagesPerItem+1))
	return shown
}

// capMessagesWithTerminal keeps terminal visible and preserves any hidden count.
func capMessagesWithTerminal(msgs []string, terminal string) []string {
	if terminal == "" {
		return msgs
	}

	visible := make([]string, 0, len(msgs))
	hidden := 0
	for _, msg := range msgs {
		if msg == terminal {
			// The caller may already have retained it; do not duplicate it.
			continue
		}
		if n, ok := moreMarkerCount(msg); ok {
			hidden += n
			continue
		}
		visible = append(visible, msg)
	}

	// A terminal beside a marker leaves MaxMessagesPerItem-2 slots for leading
	// messages. Without a marker it can use one more.
	visibleSlots := MaxMessagesPerItem - 1
	if hidden > 0 || len(visible)+1 > MaxMessagesPerItem {
		visibleSlots = MaxMessagesPerItem - 2
	}
	if visibleSlots < 0 {
		visibleSlots = 0
	}
	if len(visible) > visibleSlots {
		hidden += len(visible) - visibleSlots
		visible = visible[:visibleSlots]
	}

	shown := make([]string, 0, MaxMessagesPerItem)
	shown = append(shown, visible...)
	shown = append(shown, terminal)
	if hidden > 0 {
		shown = append(shown, fmt.Sprintf("... and %d more", hidden))
	}
	return shown
}

// appendTerminalMessage appends msg unless it is already present.
func appendTerminalMessage(msgs []string, msg string) []string {
	for _, existing := range msgs {
		if existing == msg {
			return msgs
		}
	}
	return capMessagesWithTerminal(append(msgs, msg), msg)
}

// moreMarkerCount recognizes the counted marker emitted by capMessages.
func moreMarkerCount(msg string) (int, bool) {
	var n int
	if _, err := fmt.Sscanf(msg, "... and %d more", &n); err != nil {
		return 0, false
	}
	if msg != fmt.Sprintf("... and %d more", n) {
		return 0, false
	}
	return n, true
}

// capMessagesWithHidden caps visible messages while preserving the number of
// messages already hidden behind a marker.
func capMessagesWithHidden(msgs []string, hidden int) []string {
	if hidden == 0 {
		return capMessages(msgs)
	}

	if len(msgs) < MaxMessagesPerItem {
		shown := append([]string{}, msgs...)
		shown = append(shown, fmt.Sprintf("... and %d more", hidden))
		return shown
	}

	shown := make([]string, 0, MaxMessagesPerItem)
	shown = append(shown, msgs[:MaxMessagesPerItem-1]...)
	shown = append(shown, fmt.Sprintf("... and %d more", hidden+len(msgs)-(MaxMessagesPerItem-1)))
	return shown
}

// VolumeResult is the outcome of backing up a volume's data, mirroring
// volume.VolumeResult but declared here so this package owns the artifact's
// serialized shape.
type VolumeResult string

const (
	VolumeResultSucceeded VolumeResult = "succeeded"
	VolumeResultFailed    VolumeResult = "failed"
)

// Volume method names used by the artifact.
const (
	VolumeMethodPodVolumeBackup = "PodVolumeBackup"
	VolumeMethodCSISnapshot     = "CSISnapshot"
	VolumeMethodNativeSnapshot  = "NativeSnapshot"
)

// VolumeOutcome is the volume verdict attached to the owning item row.
type VolumeOutcome struct {
	PVCNamespace string       `json:"pvcNamespace,omitempty"`
	PVCName      string       `json:"pvcName,omitempty"`
	PVName       string       `json:"pvName,omitempty"`
	Method       string       `json:"method,omitempty"`
	Result       VolumeResult `json:"result,omitempty"` // empty when the volume was skipped
	Skipped      bool         `json:"skipped,omitempty"`
	// SkippedReason is meaningful only for a skip with no result.
	SkippedReason string `json:"skippedReason,omitempty"`

	// Attempts is set only for multiple distinct attempts or a capped list.
	Attempts []VolumeAttempt `json:"attempts,omitempty"`

	// DroppedAttempts is the number of attempts omitted by MaxVolumeAttempts.
	DroppedAttempts int `json:"droppedAttempts,omitempty"`
}

// VolumeAttempt is one method's report on a volume.
type VolumeAttempt struct {
	Method        string       `json:"method,omitempty"`
	Result        VolumeResult `json:"result,omitempty"`
	Skipped       bool         `json:"skipped,omitempty"`
	SkippedReason string       `json:"skippedReason,omitempty"`
}

// ItemOutcome is the outcome of a single item in a backup.
type ItemOutcome struct {
	// Identity and verdict.
	GroupResource string   `json:"groupResource"` // e.g. "deployments.apps"
	Namespace     string   `json:"namespace,omitempty"`
	Name          string   `json:"name"`
	Outcome       Outcome  `json:"outcome"`
	Messages      []string `json:"messages,omitempty"` // errors/warnings/skip reasons attributed to this item

	// Owner is the item's controller ownerReference. It is the only true
	// parentage relationship in the artifact.
	Owner *ItemRef `json:"owner,omitempty"`

	// ReportedBy lists items that named this item as an additional item through
	// a backup item action. It is provenance, not parentage: direction is
	// implementation-defined and the same identity may also appear as Owner.
	ReportedBy []ItemRef `json:"reportedBy,omitempty"`

	// SkippedByVolume records that the skip came from a volume path.
	SkippedByVolume bool `json:"skippedByVolume,omitempty"`

	// Volume is carried by the PVC row, or the PV row when no PVC row exists.
	Volume *VolumeOutcome `json:"volume,omitempty"`

	// VolumeAttempts is capture-time evidence folded into Volume.Attempts.
	VolumeAttempts []VolumeAttempt `json:"volumeAttempts,omitempty"`
}

// ItemRef identifies an item using the same flattened shape as ItemOutcome.
type ItemRef struct {
	GroupResource string `json:"groupResource"`
	Namespace     string `json:"namespace,omitempty"`
	Name          string `json:"name"`
}

func newItemRef(id velero.ResourceIdentifier) *ItemRef {
	return &ItemRef{
		GroupResource: id.GroupResource.String(),
		Namespace:     id.Namespace,
		Name:          id.Name,
	}
}

// Kind identifies which operation produced an item outcomes artifact, so the
// envelope is self-describing without relying on the download target that
// carried it. Phase 1 writes KindBackup.
type Kind string

const (
	KindBackup Kind = "backup"
)

// OutcomeLabel returns the user-facing verb for outcome. The JSON vocabulary is
// operation-neutral; a backup reads better with its own verb.
func OutcomeLabel(outcome Outcome) string {
	if outcome == OutcomeSucceeded {
		return "BackedUp"
	}
	return string(outcome)
}

// ItemOutcomes is the top-level artifact.
type ItemOutcomes struct {
	SchemaVersion string `json:"schemaVersion"` // "v1"
	// Kind is the operation that produced this artifact.
	Kind Kind `json:"kind,omitempty"`
	// BackupName identifies the backup that produced this artifact.
	BackupName string `json:"backupName,omitempty"`
	// Finalized reports that the finalize pass completed.
	Finalized bool          `json:"finalized"`
	Items     []ItemOutcome `json:"items"`
}

// Key identifies an item within one artifact.
type Key struct {
	GroupResource string
	Namespace     string
	Name          string
}

// KeyOf returns the key identifying item.
func KeyOf(item ItemOutcome) Key {
	return Key{GroupResource: item.GroupResource, Namespace: item.Namespace, Name: item.Name}
}

// KeyOfRef returns the key identifying ref, for callers joining a row against
// its reporter.
func KeyOfRef(ref *ItemRef) Key {
	return Key{GroupResource: ref.GroupResource, Namespace: ref.Namespace, Name: ref.Name}
}

// SupportedSchemaVersion reports whether this build understands the artifact's schema version.
func (o *ItemOutcomes) SupportedSchemaVersion() bool {
	if o == nil {
		return false
	}
	return o.SchemaVersion == "" || o.SchemaVersion == SchemaVersion
}

// CollectEnabled returns the effective collect-item-outcomes setting.
func CollectEnabled(spec *bool, serverDefault bool) bool {
	if spec != nil {
		return *spec
	}
	return serverDefault
}
