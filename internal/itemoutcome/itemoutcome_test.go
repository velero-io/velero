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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportedSchemaVersion(t *testing.T) {
	tests := []struct {
		name  string
		items *ItemOutcomes
		want  bool
	}{
		{name: "nil artifact", items: nil, want: false},
		{name: "pre-version artifact", items: &ItemOutcomes{}, want: true},
		{name: "current version", items: &ItemOutcomes{SchemaVersion: SchemaVersion}, want: true},
		{name: "future version", items: &ItemOutcomes{SchemaVersion: "v2"}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.items.SupportedSchemaVersion())
		})
	}
}

func TestOutcomeLabel(t *testing.T) {
	assert.Equal(t, "BackedUp", OutcomeLabel(OutcomeSucceeded))
	assert.Equal(t, "Failed", OutcomeLabel(OutcomeFailed))
	assert.Equal(t, "Skipped", OutcomeLabel(OutcomeSkipped))
}

func TestOwnershipAndReportingJSONShape(t *testing.T) {
	item := ItemOutcome{
		GroupResource: "persistentvolumeclaims",
		Namespace:     "ns",
		Name:          "shared-pvc",
		Outcome:       OutcomeSucceeded,
		Owner: &ItemRef{
			GroupResource: "datavolumes.cdi.kubevirt.io",
			Namespace:     "ns",
			Name:          "shared-pvc",
		},
		ReportedBy: []ItemRef{
			{GroupResource: "pods", Namespace: "ns", Name: "virt-launcher-a"},
			{GroupResource: "pods", Namespace: "ns", Name: "virt-launcher-b"},
		},
	}

	got, err := json.Marshal(item)
	require.NoError(t, err)

	want := `{
		"groupResource": "persistentvolumeclaims",
		"namespace": "ns",
		"name": "shared-pvc",
		"outcome": "Succeeded",
		"owner": {"groupResource": "datavolumes.cdi.kubevirt.io", "namespace": "ns", "name": "shared-pvc"},
		"reportedBy": [
			{"groupResource": "pods", "namespace": "ns", "name": "virt-launcher-a"},
			{"groupResource": "pods", "namespace": "ns", "name": "virt-launcher-b"}
		]
	}`
	assert.JSONEq(t, want, string(got))
	assert.NotContains(t, string(got), `"parent"`)
	assert.NotContains(t, string(got), `"source"`)
}

func TestCollectEnabled(t *testing.T) {
	assert.True(t, CollectEnabled(nil, true))
	assert.False(t, CollectEnabled(nil, false))

	truthy := true
	falsy := false
	assert.True(t, CollectEnabled(&truthy, false))
	assert.False(t, CollectEnabled(&falsy, true))
}
func TestBackupNameJSONShape(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Kind:          KindBackup,
		BackupName:    "backup-1",
		Finalized:     true,
		Items:         []ItemOutcome{},
	}

	got, err := json.Marshal(items)
	require.NoError(t, err)

	want := `{"schemaVersion":"v1","kind":"backup","backupName":"backup-1","finalized":true,"items":[]}`
	assert.JSONEq(t, want, string(got))
}
