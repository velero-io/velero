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

package output

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestFormatTimestamp(t *testing.T) {
	set := metav1.NewTime(time.Date(2026, 8, 8, 21, 6, 28, 0, time.UTC))

	tests := []struct {
		name  string
		input *metav1.Time
		want  string
	}{
		{
			name:  "nil renders as n/a",
			input: nil,
			want:  "n/a",
		},
		{
			name:  "zero value renders as n/a",
			input: &metav1.Time{},
			want:  "n/a",
		},
		{
			name:  "a set timestamp is unchanged",
			input: &set,
			want:  set.String(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, formatTimestamp(tc.input))
		})
	}
}

// A backup that fails validation never starts, so StartTimestamp stays nil.
func TestPrintBackupWithoutStartTimestamp(t *testing.T) {
	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-validation"},
		Status: velerov1api.BackupStatus{
			Phase: velerov1api.BackupPhaseFailedValidation,
		},
	}

	rows := printBackup(backup)
	require.Len(t, rows, 1)

	// Name, Status, Errors, Warnings, Created, ...
	assert.Equal(t, "n/a", rows[0].Cells[4], "unset start time should not print as <nil>")
	assert.Equal(t, string(velerov1api.BackupPhaseFailedValidation), rows[0].Cells[1])
}

func TestPrintBackupExpiresForStalledNewBackup(t *testing.T) {
	created := metav1.NewTime(time.Now().Add(-20 * 24 * time.Hour))
	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "clusterstate-20210128123759",
			CreationTimestamp: created,
		},
		Spec: velerov1api.BackupSpec{
			TTL: metav1.Duration{Duration: 10 * 24 * time.Hour},
		},
		Status: velerov1api.BackupStatus{
			Phase: velerov1api.BackupPhaseNew,
		},
	}

	rows := printBackup(backup)
	require.Len(t, rows, 1)
	assert.Equal(t, "n/a", rows[0].Cells[5], "stalled New backup should not show expiration in the past")
}

func TestPrintBackupWithStartTimestamp(t *testing.T) {
	started := metav1.NewTime(time.Date(2026, 8, 8, 21, 6, 28, 0, time.UTC))
	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{Name: "completed"},
		Status: velerov1api.BackupStatus{
			Phase:          velerov1api.BackupPhaseCompleted,
			StartTimestamp: &started,
		},
	}

	rows := printBackup(backup)
	require.Len(t, rows, 1)
	assert.Equal(t, started.String(), rows[0].Cells[4])
}

// A restore that fails validation gets neither timestamp.
func TestPrintRestoreWithoutTimestamps(t *testing.T) {
	restore := &velerov1api.Restore{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-validation"},
		Spec:       velerov1api.RestoreSpec{BackupName: "does-not-exist"},
		Status: velerov1api.RestoreStatus{
			Phase: velerov1api.RestorePhaseFailedValidation,
		},
	}

	rows := printRestore(restore)
	require.Len(t, rows, 1)

	// Name, Backup, Status, Started, Completed, ...
	assert.Equal(t, "n/a", rows[0].Cells[3], "unset start time should not print as <nil>")
	assert.Equal(t, "n/a", rows[0].Cells[4], "unset completion time should not print as <nil>")
}

func TestPrintRestoreWithTimestamps(t *testing.T) {
	started := metav1.NewTime(time.Date(2026, 8, 8, 21, 9, 40, 0, time.UTC))
	completed := metav1.NewTime(time.Date(2026, 8, 8, 21, 9, 41, 0, time.UTC))

	restore := &velerov1api.Restore{
		ObjectMeta: metav1.ObjectMeta{Name: "completed"},
		Spec:       velerov1api.RestoreSpec{BackupName: "nightly-1"},
		Status: velerov1api.RestoreStatus{
			Phase:               velerov1api.RestorePhaseCompleted,
			StartTimestamp:      &started,
			CompletionTimestamp: &completed,
		},
	}

	rows := printRestore(restore)
	require.Len(t, rows, 1)
	assert.Equal(t, started.String(), rows[0].Cells[3])
	assert.Equal(t, completed.String(), rows[0].Cells[4])
}
