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

package builder

import (
	"testing"

	"github.com/stretchr/testify/assert"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

func TestBackupCancellationRequestBuilder(t *testing.T) {
	bcr := ForBackupCancellationRequest("velero", "test-bcr").
		ObjectMeta(
			WithLabels("custom-label", "custom-value"),
		).
		BackupName("test-backup").
		DeleteBackup(true).
		Phase(velerov1api.BackupCancellationRequestPhaseRejected).
		BackupUID("test-uid").
		Reason(velerov1api.BackupCancellationRequestRejectedReasonTooLate).
		Message("backup is finalizing").
		Result()

	assert.Equal(t, "velero", bcr.Namespace)
	assert.Equal(t, "test-bcr", bcr.Name)
	assert.Equal(t, velerov1api.SchemeGroupVersion.String(), bcr.APIVersion)
	assert.Equal(t, "BackupCancellationRequest", bcr.Kind)
	assert.Equal(t, map[string]string{"custom-label": "custom-value"}, bcr.GetLabels())
	assert.Equal(t, "test-backup", bcr.Spec.BackupName)
	assert.True(t, bcr.Spec.DeleteBackup)
	assert.Equal(t, velerov1api.BackupCancellationRequestPhaseRejected, bcr.Status.Phase)
	assert.Equal(t, "test-uid", bcr.Status.BackupUID)
	assert.Equal(t, velerov1api.BackupCancellationRequestRejectedReasonTooLate, bcr.Status.Reason)
	assert.Equal(t, "backup is finalizing", bcr.Status.Message)
}
