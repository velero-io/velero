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

package backup

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/velero-io/velero/internal/itemoutcome"
)

func TestItemOutcomeVolumeMethod(t *testing.T) {
	tests := []struct {
		name     string
		approach string
		expected string
	}{
		{name: "pod volume backup", approach: podVolumeApproach, expected: itemoutcome.VolumeMethodPodVolumeBackup},
		{name: "csi snapshot", approach: csiSnapshotApproach, expected: itemoutcome.VolumeMethodCSISnapshot},
		{name: "native snapshot", approach: volumeSnapshotApproach, expected: itemoutcome.VolumeMethodNativeSnapshot},
		{name: "vsphere snapshot", approach: vsphereSnapshotApproach, expected: itemoutcome.VolumeMethodNativeSnapshot},
		{name: "any approach", approach: anyApproach, expected: ""},
		{name: "empty approach", approach: "", expected: ""},
		{name: "already normalized", approach: itemoutcome.VolumeMethodCSISnapshot, expected: itemoutcome.VolumeMethodCSISnapshot},
		{name: "unknown approach", approach: "custom", expected: "custom"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, itemOutcomeVolumeMethod(tc.approach))
		})
	}
}

func TestParseSkipReasons(t *testing.T) {
	tests := []struct {
		name       string
		serialized string
		expected   []Reason
	}{
		{name: "empty"},
		{
			name:       "single reason",
			serialized: "podvolume: opted out;",
			expected:   []Reason{{Approach: "podvolume", Reason: "opted out"}},
		},
		{
			name:       "multiple reasons preserve order and trailing spaces",
			serialized: "csiSnapshot: not applicable for CSI ;podvolume: it's set to opt-out;",
			expected: []Reason{
				{Approach: "csiSnapshot", Reason: "not applicable for CSI "},
				{Approach: "podvolume", Reason: "it's set to opt-out"},
			},
		},
		{
			name:       "no trailing semicolon",
			serialized: "podvolume: opted out",
			expected:   []Reason{{Approach: "podvolume", Reason: "opted out"}},
		},
		{
			name:       "no prefix stays methodless",
			serialized: "captured elsewhere",
			expected:   []Reason{{Reason: "captured elsewhere"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseSkipReasons(tc.serialized))
		})
	}
}
