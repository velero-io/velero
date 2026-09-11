/*
Copyright 2018 the Velero contributors.

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

package backup

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummary(t *testing.T) {
	tracker := NewSkipPVTracker()
	tracker.Track("pv5", "pvc5", "ns1", "", "skipped due to policy")
	tracker.Track("pv3", "pvc3", "ns1", podVolumeApproach, "it's set to opt-out")
	tracker.Track("pv3", "pvc3", "ns1", csiSnapshotApproach, "not applicable for CSI ")
	// shouldn't be added
	tracker.Track("", "", "", podVolumeApproach, "pvc3 is set to be skipped")
	tracker.Track("pv10", "pvc10", "ns1", volumeSnapshotApproach, "added by mistake")
	tracker.Untrack("pv10", "pvc10", "ns1")
	expected := []SkippedPV{
		{
			Name:         "pv3",
			PVCName:      "pvc3",
			PVCNamespace: "ns1",
			Reasons: []PVSkipReason{
				{
					Approach: csiSnapshotApproach,
					Reason:   "not applicable for CSI ",
				},
				{
					Approach: podVolumeApproach,
					Reason:   "it's set to opt-out",
				},
			},
		},
		{
			Name:         "pv5",
			PVCName:      "pvc5",
			PVCNamespace: "ns1",
			Reasons: []PVSkipReason{
				{
					Approach: anyApproach,
					Reason:   "skipped due to policy",
				},
			},
		},
	}
	assert.Equal(t, expected, tracker.Summary())
}

func TestSerializeSkipReasons(t *testing.T) {
	tracker := NewSkipPVTracker()
	tracker.Track("pv3", "pvc3", "ns1", podVolumeApproach, "it's set to opt-out")
	tracker.Track("pv3", "pvc3", "ns1", csiSnapshotApproach, "not applicable for CSI ")

	for _, skippedPV := range tracker.Summary() {
		require.Equal(t, "csiSnapshot: not applicable for CSI ;podvolume: it's set to opt-out;", skippedPV.SerializeSkipReasons())
	}
}

func TestTrackUntrack(t *testing.T) {
	// If a pv is untracked explicitly it can't be Tracked again, b/c the pv is considered backed up already.
	tracker := NewSkipPVTracker()
	tracker.Track("pv3", "pvc3", "ns1", podVolumeApproach, "it's set to opt-out")
	tracker.Untrack("pv3", "pvc3", "ns1")
	tracker.Track("pv3", "pvc3", "ns1", csiSnapshotApproach, "not applicable for CSI ")
	assert.Empty(t, tracker.Summary())
}
