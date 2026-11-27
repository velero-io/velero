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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func volumeFixture() *ItemOutcomes {
	return &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(vmGR, "ns", "vm1", OutcomeSucceeded, nil),
			row("pods", "ns", "virt-launcher-vm1", OutcomeSucceeded, ref(vmGR, "ns", "vm1")),
			row(pvcGR, "ns", "disk1", OutcomeSucceeded, ref("pods", "ns", "virt-launcher-vm1")),
			row(pvGR, "", "pv-1", OutcomeSucceeded, ref(pvcGR, "ns", "disk1")),
		},
	}
}

// A failed volume is folded into the one row that owns it, and the row stops
// claiming success. This is what lets a reader tell a lost disk from a clean
// backup without the volume info artifact.
func TestApplyVolumesRaisesOwningRowWhoseVolumeFailed(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultFailed,
	}})

	pvc := items.Items[2]
	require.NotNil(t, pvc.Volume)
	assert.Equal(t, VolumeResultFailed, pvc.Volume.Result)
	assert.Equal(t, OutcomeFailed, pvc.Outcome, "the row must not claim BackedUp for a lost disk")
	require.Len(t, pvc.Messages, 1)
	assert.Contains(t, pvc.Messages[0], "pvc=ns/disk1")
	assert.Contains(t, pvc.Messages[0], "CSISnapshot")

	// The structured summary is recorded on the PVC row only. The PV row still
	// shares the verdict: it must not keep claiming success while the disk it
	// backs failed.
	assert.Nil(t, items.Items[3].Volume, "only the owner carries the structured volume record")
	assert.Equal(t, OutcomeFailed, items.Items[3].Outcome)
	assert.Contains(t, items.Items[3].Messages, pvc.Messages[0])
}

// A captured volume must not inherit the losing skip entry's reason: the state
// table says skippedReason is meaningful only for a skip with no result.
func TestApplyVolumesSummarizesCapturedVolumeWithoutSkipReason(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Skipped: true, SkippedReason: "opted out"},
	})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.Equal(t, VolumeResultSucceeded, vol.Result)
	assert.False(t, vol.Skipped)
	assert.Empty(t, vol.SkippedReason)

	require.Len(t, vol.Attempts, 2)
	assert.Equal(t, VolumeResultSucceeded, vol.Attempts[0].Result)
	assert.Equal(t, "CSISnapshot", vol.Attempts[0].Method)
	assert.True(t, vol.Attempts[1].Skipped)
	assert.Equal(t, "opted out", vol.Attempts[1].SkippedReason)
}

// Identical volume-info entries from different sources are one attempt. The
// summary is not repeated in Attempts when only one distinct attempt exists.
func TestApplyVolumesDedupesIdenticalAttempts(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Skipped: true, SkippedReason: "opted out"},
	})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	require.Len(t, vol.Attempts, 2)
	assert.Equal(t, "CSISnapshot", vol.Attempts[0].Method)
	assert.True(t, vol.Attempts[1].Skipped)
}

// Attempts are ordered worst first, then by method, so the artifact is stable
// and a capped list cannot drop a failure.
func TestApplyVolumesSortsAttemptsDeterministically(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "PodVolumeBackup", Skipped: true, SkippedReason: "opted out"},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "NativeSnapshot", Result: VolumeResultFailed},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
	})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	require.Len(t, vol.Attempts, 3)
	assert.Equal(t, VolumeResultFailed, vol.Attempts[0].Result)
	assert.Equal(t, "NativeSnapshot", vol.Attempts[0].Method)
	assert.Equal(t, VolumeResultSucceeded, vol.Attempts[1].Result)
	assert.Equal(t, "CSISnapshot", vol.Attempts[1].Method)
	assert.True(t, vol.Attempts[2].Skipped)
	assert.Equal(t, "PodVolumeBackup", vol.Attempts[2].Method)
}

// When two methods produce the same winning result, the summary cannot name one
// of them without misattributing the verdict. The attempts carry both.
func TestApplyVolumesLeavesSummaryMethodEmptyWhenMethodsDisagree(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "PodVolumeBackup", Result: VolumeResultSucceeded},
	})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.Equal(t, VolumeResultSucceeded, vol.Result)
	assert.Empty(t, vol.Method)
	require.Len(t, vol.Attempts, 2)
}

// Every skip reason survives in the attempts; the summary keeps the distinct
// reasons in a stable order.
func TestApplyVolumesJoinsMultipleSkipReasons(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "PodVolumeBackup", Skipped: true, SkippedReason: "opted out"},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "NativeSnapshot", Skipped: true, SkippedReason: "no snapshotter"},
	})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.True(t, vol.Skipped)
	assert.Empty(t, vol.Result)
	assert.Empty(t, vol.Method)
	assert.Equal(t, "no snapshotter; opted out", vol.SkippedReason)
	require.Len(t, vol.Attempts, 2)
}

// A failure message names every failed method when the summary cannot name a
// single one.
func TestApplyVolumesNamesEveryFailedMethod(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "NativeSnapshot", Result: VolumeResultFailed},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultFailed},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "PodVolumeBackup", Result: VolumeResultSucceeded},
	})

	pvc := items.Items[2]
	assert.Equal(t, OutcomeFailed, pvc.Outcome)
	require.NotNil(t, pvc.Volume)
	assert.Empty(t, pvc.Volume.Method)
	require.Len(t, pvc.Messages, 1)
	assert.Equal(t, "volume pvc=ns/disk1 pv=pv-1 (CSISnapshot, NativeSnapshot) failed", pvc.Messages[0])
}

// MaxVolumeAttempts keeps the evidence bounded without dropping the worst
// attempts, because the list is sorted failure first.
func TestApplyVolumesCapsAttempts(t *testing.T) {
	items := volumeFixture()
	vols := make([]VolumeOutcome, 0, MaxVolumeAttempts+2)
	for i := 0; i < MaxVolumeAttempts+2; i++ {
		vols = append(vols, VolumeOutcome{
			PVCNamespace: "ns",
			PVCName:      "disk1",
			PVName:       "pv-1",
			Method:       fmt.Sprintf("method-%02d", i),
			Result:       VolumeResultSucceeded,
		})
	}

	ApplyVolumes(items, vols)

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.Len(t, vol.Attempts, MaxVolumeAttempts)
	assert.Equal(t, 2, vol.DroppedAttempts)
}

// A skip recorded during processing can be absent from volume info because the
// capturing method untracked it. The row keeps the attempt, and the fold moves
// it into the volume evidence alongside the capture.
func TestApplyVolumesMergesCaptureAttempts(t *testing.T) {
	items := volumeFixture()
	items.Items[2].Outcome = OutcomeSkipped
	items.Items[2].SkippedByVolume = true
	items.Items[2].VolumeAttempts = []VolumeAttempt{{
		Method:        "PodVolumeBackup",
		Skipped:       true,
		SkippedReason: "opted out",
	}}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultSucceeded,
	}})

	pvc := items.Items[2]
	assert.Equal(t, OutcomeSucceeded, pvc.Outcome)
	require.NotNil(t, pvc.Volume)
	assert.Equal(t, VolumeResultSucceeded, pvc.Volume.Result)
	require.Len(t, pvc.Volume.Attempts, 2)
	assert.Equal(t, "CSISnapshot", pvc.Volume.Attempts[0].Method)
	assert.Equal(t, "PodVolumeBackup", pvc.Volume.Attempts[1].Method)
	assert.True(t, pvc.Volume.Attempts[1].Skipped)
	assert.Empty(t, pvc.VolumeAttempts, "capture attempts move into the volume evidence")
}

// A methodless skip from volume info and a named capture skip with the same
// reason are one attempt; the named form says which path skipped the volume.
func TestApplyVolumesMergesNamelessSkipWithNamedCaptureAttempt(t *testing.T) {
	items := volumeFixture()
	items.Items[2].VolumeAttempts = []VolumeAttempt{{
		Method:        "PodVolumeBackup",
		Skipped:       true,
		SkippedReason: "opted out",
	}}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Skipped: true, SkippedReason: "opted out",
	}})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.True(t, vol.Skipped)
	assert.Equal(t, "PodVolumeBackup", vol.Method)
	assert.Equal(t, "opted out", vol.SkippedReason)
	assert.Empty(t, vol.Attempts, "one distinct attempt is fully described by the summary")
}

// If volume info has no entry at all, the capture-time attempt stays on the row
// so the skip is not lost.
func TestApplyVolumesKeepsCaptureAttemptsWithoutVolumeInfo(t *testing.T) {
	items := volumeFixture()
	items.Items[2].VolumeAttempts = []VolumeAttempt{{
		Method:        "PodVolumeBackup",
		Skipped:       true,
		SkippedReason: "opted out",
	}}

	ApplyVolumes(items, nil)

	assert.Equal(t, OutcomeSucceeded, items.Items[2].Outcome)
	assert.Nil(t, items.Items[2].Volume)
	require.Len(t, items.Items[2].VolumeAttempts, 1)
	assert.Equal(t, "PodVolumeBackup", items.Items[2].VolumeAttempts[0].Method)
}

// A finalizer retry may apply the same volume result again. The failure
// message must be stable, not duplicated.
func TestApplyVolumesIsIdempotent(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items:         []ItemOutcome{row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil)},
	}
	vol := VolumeOutcome{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultFailed,
	}

	ApplyVolumes(items, []VolumeOutcome{vol})
	ApplyVolumes(items, []VolumeOutcome{vol})

	msg := volumeFailureMessage(vol)
	count := 0
	for _, existing := range items.Items[0].Messages {
		if existing == msg {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// The volume failure message is the reason the row is Failed. It must survive
// the message cap even when the capture-time row was already full.
func TestApplyVolumesKeepsFailureMessageWhenMessagesAreCapped(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{{
			GroupResource: pvcGR,
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       OutcomeSucceeded,
			Messages:      []string{"m1", "m2", "m3", "m4", "m5"},
		}},
	}
	vol := VolumeOutcome{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultFailed,
	}

	ApplyVolumes(items, []VolumeOutcome{vol})

	msg := volumeFailureMessage(vol)
	msgs := items.Items[0].Messages
	require.Len(t, msgs, MaxMessagesPerItem)
	assert.Contains(t, msgs, msg)
	assert.Equal(t, "... and 2 more", msgs[len(msgs)-1])
}

// A row capped before the volume fold already has a marker. The volume error
// must survive without losing the messages that marker counted.
func TestApplyVolumesPreservesHiddenCountWhenMessagesAreCapped(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{{
			GroupResource: pvcGR,
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       OutcomeSucceeded,
			Messages:      []string{"m1", "m2", "m3", "m4", "... and 8 more"},
		}},
	}
	vol := VolumeOutcome{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultFailed,
	}

	ApplyVolumes(items, []VolumeOutcome{vol})

	msg := volumeFailureMessage(vol)
	assert.Equal(t, []string{"m1", "m2", "m3", msg, "... and 9 more"},
		items.Items[0].Messages)
}

// The PV row carries the verdict when its PVC is not part of the backup.
func TestApplyVolumesFallsBackToThePVRow(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvGR, "", "pv-1", OutcomeSucceeded, nil),
		},
	}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Result: VolumeResultSucceeded,
	}})

	require.NotNil(t, items.Items[0].Volume)
	assert.Equal(t, VolumeResultSucceeded, items.Items[0].Volume.Result)
	assert.Equal(t, OutcomeSucceeded, items.Items[0].Outcome)
}

// A bound PVC and its PV are two items backed by one disk. The PVC owns the
// summary, but a captured volume must rescue the PV's volume-path skip too;
// otherwise the artifact says the same disk both succeeded and was skipped.
func TestApplyVolumesRescuesPVRowAlongsidePVC(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil),
			{
				GroupResource:   pvGR,
				Name:            "pv-1",
				Outcome:         OutcomeSkipped,
				SkippedByVolume: true,
				Messages:        []string{"volumeSnapshot volume skipped (pvc=disk1 pv=pv-1): handed off"},
			},
		},
	}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "PodVolumeBackup", Result: VolumeResultSucceeded,
	}})

	assert.Equal(t, OutcomeSucceeded, items.Items[0].Outcome)
	require.NotNil(t, items.Items[0].Volume, "the PVC owns the structured summary")

	assert.Equal(t, OutcomeSucceeded, items.Items[1].Outcome,
		"the PV must not keep claiming the captured disk was skipped")
	assert.Nil(t, items.Items[1].Volume, "only the owner carries the structured summary")
	assert.True(t, items.Items[1].SkippedByVolume, "the marker stays as provenance")
	require.Len(t, items.Items[1].Messages, 1, "the original skip reason is preserved")
}

// A failed disk fails both items that depend on it, while the PVC remains the
// single owner of the structured volume record.
func TestApplyVolumesFailsPVRowAlongsidePVC(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil),
			{
				GroupResource:   pvGR,
				Name:            "pv-1",
				Outcome:         OutcomeSkipped,
				SkippedByVolume: true,
				Messages:        []string{"volumeSnapshot volume skipped (pvc=disk1 pv=pv-1): handed off"},
			},
		},
	}
	vol := VolumeOutcome{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultFailed,
	}

	ApplyVolumes(items, []VolumeOutcome{vol})

	msg := volumeFailureMessage(vol)
	for i, item := range items.Items {
		assert.Equal(t, OutcomeFailed, item.Outcome, "row %d must not claim success for a lost disk", i)
		assert.Contains(t, item.Messages, msg)
	}
	require.NotNil(t, items.Items[0].Volume, "the PVC owns the structured summary")
	assert.Nil(t, items.Items[1].Volume)
}

// Capture-time attempts can live on either row. The summary collects both and
// clears each row's staging field.
func TestApplyVolumesMergesAttemptsFromBothRows(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			{
				GroupResource: pvcGR, Namespace: "ns", Name: "disk1", Outcome: OutcomeSucceeded,
				VolumeAttempts: []VolumeAttempt{{Method: "PodVolumeBackup", Skipped: true, SkippedReason: "opted out"}},
			},
			{
				GroupResource: pvGR, Name: "pv-1", Outcome: OutcomeSkipped, SkippedByVolume: true,
				VolumeAttempts: []VolumeAttempt{{Method: "VolumeSnapshotter", Skipped: true, SkippedReason: "no snapshotter"}},
			},
		},
	}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultSucceeded,
	}})

	vol := items.Items[0].Volume
	require.NotNil(t, vol)
	methods := make(map[string]bool)
	for _, attempt := range vol.Attempts {
		methods[attempt.Method] = true
	}
	assert.True(t, methods["CSISnapshot"])
	assert.True(t, methods["PodVolumeBackup"])
	assert.True(t, methods["VolumeSnapshotter"], "the PV row's capture-time attempt belongs to the same disk")
	assert.Empty(t, items.Items[0].VolumeAttempts)
	assert.Empty(t, items.Items[1].VolumeAttempts)
}

// A non-volume skip on the non-owner row is still an item-level skip; the
// captured disk does not rescue it.
func TestApplyVolumesDoesNotRescueNonVolumeSkipOnNonOwnerRow(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil),
			{GroupResource: pvGR, Name: "pv-1", Outcome: OutcomeSkipped},
		},
	}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "PodVolumeBackup", Result: VolumeResultSucceeded,
	}})

	assert.Equal(t, OutcomeSucceeded, items.Items[0].Outcome)
	assert.Equal(t, OutcomeSkipped, items.Items[1].Outcome)
}

// A volume whose object was never recorded as an item is dropped: the artifact
// is per-item, and volumeinfo still records the volume.
func TestApplyVolumesDropsVolumeWithNoOwningRow(t *testing.T) {
	items := &ItemOutcomes{SchemaVersion: SchemaVersion}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Result: VolumeResultFailed,
	}})

	assert.Empty(t, items.Items)
}

// A volume skipped by one path and captured by another is one volume: the
// method's entry outranks the skip, so the row reads as captured and is not
// raised.
func TestApplyVolumesPrefersCapturedEntryOverSkippedTwin(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Skipped: true, SkippedReason: "CSI is taking it"},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
	})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.Equal(t, VolumeResultSucceeded, vol.Result)
	assert.Equal(t, "CSISnapshot", vol.Method)
	assert.Len(t, vol.Attempts, 2)
	assert.Equal(t, OutcomeSucceeded, items.Items[2].Outcome)
}

// Any failed entry for a volume is the verdict, regardless of order.
func TestApplyVolumesFailureWinsAmongDuplicates(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "PodVolumeBackup", Result: VolumeResultSucceeded},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultFailed},
	})

	require.NotNil(t, items.Items[2].Volume)
	assert.Equal(t, VolumeResultFailed, items.Items[2].Volume.Result)
	assert.Equal(t, "CSISnapshot", items.Items[2].Volume.Method)
	assert.Len(t, items.Items[2].Volume.Attempts, 2)
	assert.Equal(t, OutcomeFailed, items.Items[2].Outcome)
}

// A skip-only volume keeps its reason and does not raise the row.
func TestApplyVolumesRecordsSkippedVolumeWithoutRaising(t *testing.T) {
	items := volumeFixture()

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Skipped: true, SkippedReason: "no applicable volumesnapshotter found",
	}})

	vol := items.Items[2].Volume
	require.NotNil(t, vol)
	assert.True(t, vol.Skipped)
	assert.Empty(t, vol.Result)
	assert.Equal(t, "no applicable volumesnapshotter found", vol.SkippedReason)
	assert.Equal(t, OutcomeSucceeded, items.Items[2].Outcome)
}

// A PVC skipped by the fs path is not a skipped item when a CSI snapshot
// captured the same volume. The skip entry is already gone from volume info:
// the capturing method untracked it. The row's own marker is the only
// provenance left, so the fold must trust it.
func TestApplyVolumesUpgradesSkippedRowWhenVolumeSucceeded(t *testing.T) {
	items := volumeFixture()
	items.Items[2].Outcome = OutcomeSkipped
	items.Items[2].SkippedByVolume = true
	items.Items[2].Messages = []string{"podvolume volume skipped (pvc=disk1 pv=pv-1): opted out"}

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
	})

	pvc := items.Items[2]
	assert.Equal(t, OutcomeSucceeded, pvc.Outcome, "a captured volume must not leave the row reading Skipped")
	require.NotNil(t, pvc.Volume)
	assert.Equal(t, VolumeResultSucceeded, pvc.Volume.Result)
	assert.Equal(t, "CSISnapshot", pvc.Volume.Method)
	require.Len(t, pvc.Messages, 1, "the skip reason is preserved alongside the verdict")
	assert.Contains(t, pvc.Messages[0], "opted out")
}

// A skip-only volume is still a skip: nothing captured the disk.
func TestApplyVolumesKeepsSkippedRowWhenVolumeWasSkipped(t *testing.T) {
	items := volumeFixture()
	items.Items[2].Outcome = OutcomeSkipped
	items.Items[2].SkippedByVolume = true
	items.Items[2].Messages = []string{"podvolume volume skipped (pvc=disk1 pv=pv-1): opted out"}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Skipped: true, SkippedReason: "opted out",
	}})

	pvc := items.Items[2]
	assert.Equal(t, OutcomeSkipped, pvc.Outcome)
	require.NotNil(t, pvc.Volume)
	assert.True(t, pvc.Volume.Skipped)
	assert.Empty(t, pvc.Volume.Result)
}

// A failed volume is a failure even when the row was skipped: a disk that was
// attempted and lost is worse than one that was never captured.
func TestApplyVolumesRaisesSkippedRowWhenVolumeFailed(t *testing.T) {
	items := volumeFixture()
	items.Items[2].Outcome = OutcomeSkipped
	items.Items[2].SkippedByVolume = true
	items.Items[2].Messages = []string{"podvolume volume skipped (pvc=disk1 pv=pv-1): opted out"}

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Skipped: true, SkippedReason: "opted out"},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultFailed},
	})

	pvc := items.Items[2]
	assert.Equal(t, OutcomeFailed, pvc.Outcome)
	require.NotNil(t, pvc.Volume)
	assert.Equal(t, VolumeResultFailed, pvc.Volume.Result)
	assert.Len(t, pvc.Volume.Attempts, 2)
	require.Len(t, pvc.Messages, 2)
	assert.Contains(t, pvc.Messages[1], "CSISnapshot")
}

// An item excluded from the backup with no volume entry keeps its skip: there
// is no capture to promote it.
func TestApplyVolumesLeavesExcludedItemWithoutVolumeUnchanged(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvcGR, "ns", "excluded", OutcomeSkipped, nil),
		},
	}
	items.Items[0].Messages = []string{"item has label velero.io/exclude-from-backup=true"}

	ApplyVolumes(items, nil)

	assert.False(t, items.Finalized, "the volume fold does not own the finalized flag")
	assert.Equal(t, OutcomeSkipped, items.Items[0].Outcome)
	assert.Nil(t, items.Items[0].Volume)
	assert.Equal(t, []string{"item has label velero.io/exclude-from-backup=true"}, items.Items[0].Messages)
}

// An item-level skip is not rescued by a volume verdict. The disk may have been
// captured, but the item itself was not backed up, so the row must stay Skipped.
func TestApplyVolumesDoesNotRescueNonVolumeSkip(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items:         []ItemOutcome{row(pvcGR, "ns", "disk1", OutcomeSkipped, nil)},
	}
	items.Items[0].Messages = []string{"skipped by backup item action"}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1",
		Method: "CSISnapshot", Result: VolumeResultSucceeded,
	}})

	assert.Equal(t, OutcomeSkipped, items.Items[0].Outcome,
		"a volume verdict must not turn an item-level skip into a success")
	require.NotNil(t, items.Items[0].Volume)
	assert.Equal(t, VolumeResultSucceeded, items.Items[0].Volume.Result)
}

// ApplyVolumes does not own Finalized: the operation overlay does.
func TestApplyVolumesDoesNotSetFinalized(t *testing.T) {
	items := &ItemOutcomes{SchemaVersion: SchemaVersion}
	assert.False(t, items.Finalized)

	ApplyVolumes(items, nil)

	assert.False(t, items.Finalized)
}

func TestApplyVolumesHandlesNilArtifact(t *testing.T) {
	ApplyVolumes(nil, []VolumeOutcome{{PVCName: "x", Result: VolumeResultFailed}})
}

// The attempts list is the serialized evidence behind a multi-method volume.
func TestVolumeAttemptsJSONShape(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Kind:          KindBackup,
		Finalized:     true,
		Items: []ItemOutcome{{
			GroupResource: pvcGR,
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       OutcomeSucceeded,
		}},
	}

	ApplyVolumes(items, []VolumeOutcome{
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "CSISnapshot", Result: VolumeResultSucceeded},
		{PVCNamespace: "ns", PVCName: "disk1", PVName: "pv-1", Method: "PodVolumeBackup", Skipped: true, SkippedReason: "opted out"},
	})

	got, err := json.Marshal(items)
	require.NoError(t, err)

	want := `{"schemaVersion":"v1","kind":"backup","finalized":true,"items":[` +
		`{"groupResource":"persistentvolumeclaims","namespace":"ns","name":"disk1",` +
		`"outcome":"Succeeded",` +
		`"volume":{"pvcNamespace":"ns","pvcName":"disk1","pvName":"pv-1",` +
		`"method":"CSISnapshot","result":"succeeded","attempts":[` +
		`{"method":"CSISnapshot","result":"succeeded"},` +
		`{"method":"PodVolumeBackup","skipped":true,"skippedReason":"opted out"}]}}]}`
	assert.JSONEq(t, want, string(got))
}

// The volume-skip provenance is part of the serialized contract: finalize needs
// it after the artifact has been written and re-read, and a later reader can see
// why a Succeeded row still carries a skip message.
func TestSkippedByVolumeJSONShape(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Kind:          KindBackup,
		Finalized:     true,
		Items: []ItemOutcome{{
			GroupResource:   pvcGR,
			Namespace:       "ns",
			Name:            "disk1",
			Outcome:         OutcomeSucceeded,
			SkippedByVolume: true,
			Volume: &VolumeOutcome{
				PVCNamespace: "ns",
				PVCName:      "disk1",
				PVName:       "pv-1",
				Method:       "CSISnapshot",
				Result:       VolumeResultSucceeded,
			},
		}},
	}

	got, err := json.Marshal(items)
	require.NoError(t, err)

	want := `{"schemaVersion":"v1","kind":"backup","finalized":true,"items":[` +
		`{"groupResource":"persistentvolumeclaims","namespace":"ns","name":"disk1",` +
		`"outcome":"Succeeded","skippedByVolume":true,` +
		`"volume":{"pvcNamespace":"ns","pvcName":"disk1","pvName":"pv-1","method":"CSISnapshot","result":"succeeded"}}]}`
	assert.JSONEq(t, want, string(got))
}

// The serialized shape is the contract every consumer reads. Pin it, including
// the volume verdict that makes the artifact self-describing.
func TestFinalizedArtifactJSONShape(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Kind:          KindBackup,
		Finalized:     true,
		Items: []ItemOutcome{
			{
				GroupResource: pvcGR,
				Namespace:     "ns",
				Name:          "disk1",
				Outcome:       OutcomeSucceeded,
			},
		},
	}

	ApplyVolumes(items, []VolumeOutcome{{
		PVCNamespace: "ns",
		PVCName:      "disk1",
		PVName:       "pv-1",
		Method:       "CSISnapshot",
		Result:       VolumeResultFailed,
	}})

	got, err := json.Marshal(items)
	require.NoError(t, err)

	want := `{"schemaVersion":"v1","kind":"backup","finalized":true,"items":[` +
		`{"groupResource":"persistentvolumeclaims","namespace":"ns","name":"disk1",` +
		`"outcome":"Failed",` +
		`"messages":["volume pvc=ns/disk1 pv=pv-1 (CSISnapshot) failed"],` +
		`"volume":{"pvcNamespace":"ns","pvcName":"disk1","pvName":"pv-1","method":"CSISnapshot","result":"failed"}}]}`
	assert.JSONEq(t, want, string(got))
}
