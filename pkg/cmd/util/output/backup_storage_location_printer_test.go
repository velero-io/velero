/*
Copyright The Velero Contributors.

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
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/cmd"
	"github.com/vmware-tanzu/velero/pkg/cmd/server/config"
)

func TestFormatValidationFrequency(t *testing.T) {
	t.Parallel()

	serverDefault := config.GetDefaultConfig().StoreValidationFrequency

	assert.Equal(t, serverDefault.String(), formatValidationFrequency(nil, serverDefault))
	assert.Equal(t, "0s", formatValidationFrequency(&metav1.Duration{Duration: 0}, serverDefault))
	assert.Equal(t, "2m0s", formatValidationFrequency(&metav1.Duration{Duration: 2 * time.Minute}, serverDefault))
	assert.Equal(t, "5m0s", formatValidationFrequency(nil, 5*time.Minute))
}

func TestPrintBackupStorageLocationValidationFrequencyColumn(t *testing.T) {
	t.Parallel()

	location := builder.ForBackupStorageLocation("velero", "default").
		Provider("aws").
		Bucket("my-bucket").
		Default(true).
		ValidationFrequency(5 * time.Minute).
		Result()
	location.Status.Phase = velerov1api.BackupStorageLocationPhaseAvailable

	serverDefault := config.GetDefaultConfig().StoreValidationFrequency
	rows := printBackupStorageLocation(location, serverDefault)
	require.Len(t, rows, 1)
	require.Len(t, rows[0].Cells, len(backupStorageLocationColumns))

	assert.Equal(t, "5m0s", rows[0].Cells[5])
	assert.Equal(t, cmd.TRUE, rows[0].Cells[7])
}

func TestPrintBackupStorageLocationValidationFrequencyDefault(t *testing.T) {
	t.Parallel()

	location := builder.ForBackupStorageLocation("velero", "secondary").
		Provider("gcp").
		Bucket("other-bucket").
		Result()

	serverDefault := 3 * time.Minute
	rows := printBackupStorageLocation(location, serverDefault)
	require.Len(t, rows, 1)

	assert.Equal(t, "3m0s", rows[0].Cells[5])
}
