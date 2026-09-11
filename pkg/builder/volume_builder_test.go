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

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestDataDownloadBuilder_Bytes(t *testing.T) {
	dd := ForDataDownload("velero", "dd-1").
		TotalBytes(2048).
		IncrementalBytes(512).
		Result()

	assert.Equal(t, int64(2048), dd.Status.Progress.TotalBytes)
	assert.NotNil(t, dd.Status.IncrementalBytes)
	assert.Equal(t, int64(512), *dd.Status.IncrementalBytes)
}

func TestDataDownloadBuilder_FallbackFull(t *testing.T) {
	dd1 := ForDataDownload("velero", "dd-1").
		FallbackFull(true).
		Result()
	assert.True(t, dd1.Status.FallbackFull)

	dd2 := ForDataDownload("velero", "dd-2").
		FallbackFull(false).
		Result()
	assert.False(t, dd2.Status.FallbackFull)
}

func TestPodVolumeBackupBuilder_ProgressAndBytes(t *testing.T) {
	pvb1 := ForPodVolumeBackup("velero", "pvb-1").
		Progress(shared.DataMoveOperationProgress{
			TotalBytes: 4096,
			BytesDone:  2048,
		}).
		Phase(velerov1api.PodVolumeBackupPhaseCompleted).
		Result()

	assert.Equal(t, int64(4096), pvb1.Status.Progress.TotalBytes)
	assert.Equal(t, int64(2048), pvb1.Status.Progress.BytesDone)

	pvb2 := ForPodVolumeBackup("velero", "pvb-2").
		TotalBytes(1024).
		IncrementalBytes(256).
		Result()

	assert.Equal(t, int64(1024), pvb2.Status.Progress.TotalBytes)
	assert.NotNil(t, pvb2.Status.IncrementalBytes)
	assert.Equal(t, int64(256), *pvb2.Status.IncrementalBytes)
}

func TestPodVolumeRestoreBuilder_ProgressAndBytes(t *testing.T) {
	pvr1 := ForPodVolumeRestore("velero", "pvr-1").
		RestoreType("Incremental").
		Progress(shared.DataMoveOperationProgress{
			TotalBytes: 8192,
			BytesDone:  4096,
		}).
		Phase(velerov1api.PodVolumeRestorePhaseCompleted).
		Result()

	assert.Equal(t, "Incremental", pvr1.Spec.RestoreType)
	assert.Equal(t, int64(8192), pvr1.Status.Progress.TotalBytes)
	assert.Equal(t, int64(4096), pvr1.Status.Progress.BytesDone)

	pvr2 := ForPodVolumeRestore("velero", "pvr-2").
		TotalBytes(2048).
		IncrementalBytes(512).
		Result()

	assert.Equal(t, int64(2048), pvr2.Status.Progress.TotalBytes)
	assert.NotNil(t, pvr2.Status.IncrementalBytes)
	assert.Equal(t, int64(512), *pvr2.Status.IncrementalBytes)
}
