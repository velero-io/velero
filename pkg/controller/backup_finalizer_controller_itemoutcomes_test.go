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

package controller

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/velero-io/velero/internal/itemoutcome"
	"github.com/velero-io/velero/internal/volume"
	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/metrics"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"
	"github.com/velero-io/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/velero-io/velero/pkg/plugin/mocks"
	velerotest "github.com/velero-io/velero/pkg/test"
	"k8s.io/apimachinery/pkg/types"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
)

// A backup with no async operations still reaches the finalizer. Its archive
// does not need rewriting, but its item outcomes artifact must receive the
// volume verdicts and be marked finalized; otherwise a successful backup's
// artifact reads as if the finalize pass never ran.
func TestBackupFinalizerReconcileFinalizesItemOutcomesWithoutOperations(t *testing.T) {
	fakeClock := testclocks.NewFakeClock(time.Now())
	backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup-no-ops").
		StorageLocation("default").
		CollectItemOutcomes(true).
		ObjectMeta(builder.WithUID("foo")).
		StartTimestamp(fakeClock.Now()).
		Phase(velerov1api.BackupPhaseFinalizing).Result()
	location := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Result()

	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, backup, location)
	fakeGlobalClient := velerotest.NewFakeControllerRuntimeClient(t, backup, location)

	localPluginManager := &pluginmocks.Manager{}
	localBackupStore := &persistencemocks.BackupStore{}
	backupper := new(fakeBackupper)
	reconciler := NewBackupFinalizerReconciler(
		fakeClient,
		fakeGlobalClient,
		fakeClock,
		backupper,
		func(logrus.FieldLogger) clientmgmt.Manager { return localPluginManager },
		NewBackupTracker(),
		NewFakeSingleObjectBackupStoreGetter(localBackupStore),
		logrus.StandardLogger(),
		metrics.NewServerMetrics(),
		10*time.Minute,
	)

	outcomes := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Items: []itemoutcome.ItemOutcome{{
			GroupResource: kuberesource.PersistentVolumeClaims.String(),
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       itemoutcome.OutcomeSkipped,
			// The marker is what makes the row eligible for rescue. Without it,
			// this is an item-level skip and ApplyVolumes must leave it alone.
			SkippedByVolume: true,
			Messages:        []string{"podvolume volume skipped (pvc=disk1 pv=pv-1): opted out"},
		}},
	}
	volumeInfos := []*volume.BackupVolumeInfo{{
		PVCNamespace: "ns",
		PVCName:      "disk1",
		PVName:       "pv-1",
		BackupMethod: volume.CSISnapshot,
		Result:       volume.VolumeResultSucceeded,
	}}

	var written *itemoutcome.ItemOutcomes
	localPluginManager.On("CleanupClients").Return(nil)
	localBackupStore.On("GetBackupItemOperations", backup.Name).Return(nil, nil)
	localBackupStore.On("GetBackupVolumeInfos", backup.Name).Return(volumeInfos, nil)
	localBackupStore.On("GetBackupItemOutcomes", backup.Name).Return(outcomes, nil)
	localBackupStore.On("PutBackupItemOutcomes", backup.Name, mock.Anything).
		Run(func(args mock.Arguments) {
			gz, err := gzip.NewReader(args.Get(1).(io.Reader))
			require.NoError(t, err)
			defer gz.Close()

			var got itemoutcome.ItemOutcomes
			require.NoError(t, json.NewDecoder(gz).Decode(&got))
			written = &got
		}).Return(nil)
	localBackupStore.On("PutBackupMetadata", mock.Anything, mock.Anything).Return(nil)

	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: backup.Namespace,
		Name:      backup.Name,
	}})
	require.NoError(t, err)

	require.NotNil(t, written)
	assert.True(t, written.Finalized, "a completed backup's artifact must not claim finalize never ran")
	require.Len(t, written.Items, 1)
	assert.Equal(t, itemoutcome.OutcomeSucceeded, written.Items[0].Outcome,
		"the captured volume is the item's verdict, not the fs-path skip")
	require.NotNil(t, written.Items[0].Volume)
	assert.Equal(t, itemoutcome.VolumeResultSucceeded, written.Items[0].Volume.Result)

	backupper.AssertNotCalled(t, "FinalizeBackup", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	localBackupStore.AssertNotCalled(t, "GetBackupContents", mock.Anything)
	localBackupStore.AssertNotCalled(t, "PutBackupContents", mock.Anything, mock.Anything)
}
