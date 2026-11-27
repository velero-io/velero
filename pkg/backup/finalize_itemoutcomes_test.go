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
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/velero-io/velero/internal/itemoutcome"
	"github.com/velero-io/velero/internal/volume"
	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/itemoperation"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"
	"github.com/velero-io/velero/pkg/plugin/velero"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestUpdateItemOutcomes(t *testing.T) {
	now := metav1.Now()

	tests := []struct {
		name            string
		itemOutcomes    *itemoutcome.ItemOutcomes
		operations      []*itemoperation.BackupOperation
		expectedResults map[string]itemoutcome.Outcome
		expectedCount   int
	}{
		{
			name: "failed operation upgrades a previously BackedUp item to Failed and appends the error",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Items: []itemoutcome.ItemOutcome{
					{GroupResource: "persistentvolumeclaims", Namespace: "ns-1", Name: "pvc-1", Outcome: itemoutcome.OutcomeSucceeded},
				},
			},
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
							Namespace:     "ns-1",
							Name:          "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseFailed, Error: "snapshot timed out", Created: &now},
				},
			},
			expectedResults: map[string]itemoutcome.Outcome{"pvc-1": itemoutcome.OutcomeFailed},
			expectedCount:   1,
		},
		{
			name: "completed operation leaves the item unchanged",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Items: []itemoutcome.ItemOutcome{
					{GroupResource: "persistentvolumeclaims", Namespace: "ns-1", Name: "pvc-1", Outcome: itemoutcome.OutcomeSucceeded},
				},
			},
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
							Namespace:     "ns-1",
							Name:          "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseCompleted, Created: &now},
				},
			},
			expectedResults: map[string]itemoutcome.Outcome{"pvc-1": itemoutcome.OutcomeSucceeded},
			expectedCount:   1,
		},
		{
			name: "failed operation with no matching item gets its own row",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Items:         []itemoutcome.ItemOutcome{},
			},
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
							Namespace:     "ns-1",
							Name:          "pvc-unseen",
						},
					},
					Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseFailed, Error: "boom", Created: &now},
				},
			},
			expectedResults: map[string]itemoutcome.Outcome{"pvc-unseen": itemoutcome.OutcomeFailed},
			expectedCount:   1,
		},
		{
			name: "owner is untouched by the overlay",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Items: []itemoutcome.ItemOutcome{
					{
						GroupResource: "persistentvolumeclaims",
						Namespace:     "ns-1",
						Name:          "pvc-1",
						Outcome:       itemoutcome.OutcomeSucceeded,
						Owner: &itemoutcome.ItemRef{
							GroupResource: "virtualmachines.kubevirt.io", Namespace: "ns-1", Name: "vm-1",
						},
					},
				},
			},
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
							Namespace:     "ns-1",
							Name:          "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseFailed, Error: "boom", Created: &now},
				},
			},
			expectedResults: map[string]itemoutcome.Outcome{"pvc-1": itemoutcome.OutcomeFailed},
			expectedCount:   1,
		},
		{
			// The backup is not supposed to reach finalize with a running
			// operation, but if it does the item must not gain a row or a verdict
			// it never earned. It keeps what capture recorded and the condition is
			// reported.
			name: "in-flight operation neither creates nor changes a row",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Items: []itemoutcome.ItemOutcome{
					{GroupResource: "persistentvolumeclaims", Namespace: "ns-1", Name: "pvc-1", Outcome: itemoutcome.OutcomeSucceeded},
				},
			},
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
							Namespace:     "ns-1",
							Name:          "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseInProgress, Created: &now},
				},
			},
			expectedResults: map[string]itemoutcome.Outcome{"pvc-1": itemoutcome.OutcomeSucceeded},
			expectedCount:   1,
		},
		{
			name: "unstarted operation for an unseen item does not invent a row",
			itemOutcomes: &itemoutcome.ItemOutcomes{
				SchemaVersion: itemoutcome.SchemaVersion,
				Items:         []itemoutcome.ItemOutcome{},
			},
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
							Namespace:     "ns-1",
							Name:          "pvc-unseen",
						},
					},
					Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseNew, Created: &now},
				},
			},
			expectedResults: map[string]itemoutcome.Outcome{},
			expectedCount:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updateItemOutcomes(tc.itemOutcomes, tc.operations, logrus.New())

			require.Len(t, tc.itemOutcomes.Items, tc.expectedCount)

			byName := map[string]itemoutcome.ItemOutcome{}
			for _, item := range tc.itemOutcomes.Items {
				byName[item.Name] = item
			}
			for name, outcome := range tc.expectedResults {
				assert.Equal(t, outcome, byName[name].Outcome)
			}

			if tc.name == "owner is untouched by the overlay" {
				require.NotNil(t, byName["pvc-1"].Owner)
				assert.Equal(t, "vm-1", byName["pvc-1"].Owner.Name)
				assert.Contains(t, byName["pvc-1"].Messages, "boom")
			}
		})
	}
}

// TestUpdateItemOutcomesKeepsCaptureMessages pins the append-only invariant
// stated beside the Messages write in updateItemOutcomes: the finalize overlay
// adds the async operation's error but never rewrites or drops what capture
// recorded. If this ever fails, a row has silently lost what the item said
// about itself, which is the failure the invariant exists to rule out.
func TestUpdateItemOutcomesKeepsCaptureMessages(t *testing.T) {
	now := metav1.Now()

	captureMessages := []string{
		"volume snapshot for pvc-1 could not be taken, backing up the contents instead",
		"including item because it is a PVC referenced by pending pod ns-1/pod-1",
	}

	itemOutcomes := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Items: []itemoutcome.ItemOutcome{
			{
				GroupResource: "persistentvolumeclaims",
				Namespace:     "ns-1",
				Name:          "pvc-1",
				Outcome:       itemoutcome.OutcomeWarning,
				Messages:      captureMessages,
			},
		},
	}

	updateItemOutcomes(itemOutcomes, []*itemoperation.BackupOperation{
		{
			Spec: itemoperation.BackupOperationSpec{
				ResourceIdentifier: velero.ResourceIdentifier{
					GroupResource: schema.GroupResource{Resource: "persistentvolumeclaims"},
					Namespace:     "ns-1",
					Name:          "pvc-1",
				},
			},
			Status: itemoperation.OperationStatus{Phase: itemoperation.OperationPhaseFailed, Error: "snapshot timed out", Created: &now},
		},
	}, logrus.New())

	require.Len(t, itemOutcomes.Items, 1)
	item := itemOutcomes.Items[0]

	// The verdict is upgraded, not replaced wholesale: the row keeps its identity.
	assert.Equal(t, itemoutcome.OutcomeFailed, item.Outcome)
	assert.Equal(t, "pvc-1", item.Name)

	// Every capture-time message survives, in order, ahead of the appended error.
	require.Len(t, item.Messages, len(captureMessages)+1)
	assert.Equal(t, captureMessages, item.Messages[:len(captureMessages)])
	assert.Equal(t, "snapshot timed out", item.Messages[len(captureMessages)])
}

func TestPutItemOutcomes(t *testing.T) {
	backupName := "backup-01"

	backupStore := new(persistencemocks.BackupStore)

	backupStore.On("PutBackupItemOutcomes", mock.Anything, mock.Anything).Return(nil)

	require.NoError(t, putItemOutcomes(backupName, &itemoutcome.ItemOutcomes{SchemaVersion: itemoutcome.SchemaVersion, Items: []itemoutcome.ItemOutcome{}}, backupStore))
}

func TestPutItemOutcomesSetsBackupName(t *testing.T) {
	backupName := "backup-name"

	backupStore := new(persistencemocks.BackupStore)
	var got *itemoutcome.ItemOutcomes
	backupStore.On("PutBackupItemOutcomes", backupName, mock.Anything).Run(func(args mock.Arguments) {
		reader, ok := args.Get(1).(io.Reader)
		require.True(t, ok)
		gzr, err := gzip.NewReader(reader)
		require.NoError(t, err)
		defer gzr.Close()
		got = new(itemoutcome.ItemOutcomes)
		require.NoError(t, json.NewDecoder(gzr).Decode(got))
	}).Return(nil)

	require.NoError(t, putItemOutcomes(backupName, &itemoutcome.ItemOutcomes{SchemaVersion: itemoutcome.SchemaVersion, Items: []itemoutcome.ItemOutcome{}}, backupStore))

	require.NotNil(t, got)
	assert.Equal(t, backupName, got.BackupName)
}

// The finalize pass is a second capture pass. A warning recorded on a
// post-operation item must be merged into the stored artifact, not discarded.
func TestFinalizeItemOutcomesRejectsUnsupportedSchema(t *testing.T) {
	const backupName = "backup-schema"
	stored := &itemoutcome.ItemOutcomes{SchemaVersion: "v999", Kind: itemoutcome.KindBackup}
	backupStore := new(persistencemocks.BackupStore)
	backupStore.On("GetBackupItemOutcomes", backupName).Return(stored, nil)

	request := &Request{
		Backup:       &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{Name: backupName}},
		ItemOutcomes: itemoutcome.NewRecorder(),
	}

	err := finalizeItemOutcomes(logrus.New(), request, nil, nil, backupStore)

	require.Error(t, err)
	backupStore.AssertNotCalled(t, "PutBackupItemOutcomes", mock.Anything, mock.Anything)
}

func TestFinalizeItemOutcomesRejectsWrongKind(t *testing.T) {
	const backupName = "backup-kind"
	stored := &itemoutcome.ItemOutcomes{SchemaVersion: itemoutcome.SchemaVersion, Kind: itemoutcome.Kind("other")}
	backupStore := new(persistencemocks.BackupStore)
	backupStore.On("GetBackupItemOutcomes", backupName).Return(stored, nil)

	request := &Request{
		Backup:       &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{Name: backupName}},
		ItemOutcomes: itemoutcome.NewRecorder(),
	}

	err := finalizeItemOutcomes(logrus.New(), request, nil, nil, backupStore)

	require.Error(t, err)
	backupStore.AssertNotCalled(t, "PutBackupItemOutcomes", mock.Anything, mock.Anything)
}

func TestFinalizeItemOutcomesMergesFinalizePassRows(t *testing.T) {
	const backupName = "backup-merge"
	stored := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Kind:          itemoutcome.KindBackup,
		Items: []itemoutcome.ItemOutcome{{
			GroupResource: "pods",
			Namespace:     "ns",
			Name:          "captured",
			Outcome:       itemoutcome.OutcomeSucceeded,
		}},
	}
	recorder := itemoutcome.NewRecorder()
	recorder.For(velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{Resource: "volumesnapshots", Group: "snapshot.storage.k8s.io"},
		Namespace:     "ns",
		Name:          "post-op",
	}).Warn("finalize warning")

	backupStore := new(persistencemocks.BackupStore)
	backupStore.On("GetBackupItemOutcomes", backupName).Return(stored, nil)

	var written *itemoutcome.ItemOutcomes
	backupStore.On("PutBackupItemOutcomes", backupName, mock.Anything).Run(func(args mock.Arguments) {
		buf := args.Get(1).(*bytes.Buffer)
		gz, err := gzip.NewReader(buf)
		require.NoError(t, err)
		defer gz.Close()
		var decoded itemoutcome.ItemOutcomes
		require.NoError(t, json.NewDecoder(gz).Decode(&decoded))
		written = &decoded
	}).Return(nil)

	request := &Request{
		Backup:       &velerov1.Backup{ObjectMeta: metav1.ObjectMeta{Name: backupName}},
		ItemOutcomes: recorder,
	}

	require.NoError(t, finalizeItemOutcomes(logrus.New(), request, nil, nil, backupStore))

	require.NotNil(t, written)
	require.Len(t, written.Items, 2)
	byName := map[string]itemoutcome.ItemOutcome{}
	for _, item := range written.Items {
		byName[item.Name] = item
	}
	require.Contains(t, byName, "post-op")
	assert.Equal(t, itemoutcome.OutcomeWarning, byName["post-op"].Outcome)
	assert.Contains(t, byName["post-op"].Messages, "finalize warning")
	assert.Equal(t, itemoutcome.OutcomeSucceeded, byName["captured"].Outcome)
}

// volumeOutcomes is the one place the backup's volume info meets the item
// outcomes artifact. It must preserve the fields the join needs and map the
// verdict without inventing one.
func TestVolumeOutcomesProjection(t *testing.T) {
	infos := []*volume.BackupVolumeInfo{
		{
			PVCNamespace:  "ns",
			PVCName:       "disk1",
			PVName:        "pv-1",
			BackupMethod:  volume.CSISnapshot,
			Result:        volume.VolumeResultFailed,
			Skipped:       false,
			SkippedReason: "",
		},
		{
			PVCNamespace:  "ns",
			PVCName:       "disk2",
			PVName:        "pv-2",
			Skipped:       true,
			SkippedReason: "podvolume: captured elsewhere;",
		},
		nil,
	}

	got := volumeOutcomes(infos)

	require.Len(t, got, 2, "a nil entry is dropped rather than projected")
	assert.Equal(t, itemoutcome.VolumeResultFailed, got[0].Result)
	assert.Equal(t, "CSISnapshot", got[0].Method)
	assert.Equal(t, "disk1", got[0].PVCName)
	assert.Empty(t, got[1].Result)
	assert.True(t, got[1].Skipped)
	assert.Equal(t, itemoutcome.VolumeMethodPodVolumeBackup, got[1].Method,
		"the serialized approach is normalized to the volume-info method name")
	assert.Equal(t, "captured elsewhere", got[1].SkippedReason,
		"the method prefix is not part of the reason")
}

// Volume info still writes skip reasons as the legacy "approach: reason;"
// string, while a capture-time attempt stores the raw reason under the
// artifact's method vocabulary. The projection must turn both into the same
// attempt, not two.
func TestFinalizeNormalizesSerializedSkipReasons(t *testing.T) {
	items := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Items: []itemoutcome.ItemOutcome{{
			GroupResource:   "persistentvolumeclaims",
			Namespace:       "ns",
			Name:            "disk1",
			Outcome:         itemoutcome.OutcomeSkipped,
			SkippedByVolume: true,
			VolumeAttempts: []itemoutcome.VolumeAttempt{{
				Method:        itemoutcome.VolumeMethodPodVolumeBackup,
				Skipped:       true,
				SkippedReason: "opted out",
			}},
		}},
	}

	itemoutcome.ApplyVolumes(items, volumeOutcomes([]*volume.BackupVolumeInfo{{
		PVCNamespace:  "ns",
		PVCName:       "disk1",
		PVName:        "pv-1",
		Skipped:       true,
		SkippedReason: "podvolume: opted out;csiSnapshot: no snapshotter;",
	}}))

	row := items.Items[0]
	require.NotNil(t, row.Volume)
	assert.True(t, row.Volume.Skipped)
	assert.Empty(t, row.Volume.Method, "two methods at the skip rank leave the summary method empty")
	assert.Equal(t, "no snapshotter; opted out", row.Volume.SkippedReason)
	require.Len(t, row.Volume.Attempts, 2, "the capture attempt merges with its serialized twin")
	assert.Equal(t, itemoutcome.VolumeMethodCSISnapshot, row.Volume.Attempts[0].Method)
	assert.Equal(t, itemoutcome.VolumeMethodPodVolumeBackup, row.Volume.Attempts[1].Method)
	assert.Equal(t, "no snapshotter", row.Volume.Attempts[0].SkippedReason)
	assert.Equal(t, "opted out", row.Volume.Attempts[1].SkippedReason)
}

// The finalize pass is what makes the artifact self-describing: it folds the
// volume verdict into the item row before the artifact is written.
func TestFinalizeFoldsVolumeVerdictIntoItemOutcomes(t *testing.T) {
	items := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Items: []itemoutcome.ItemOutcome{{
			GroupResource: "persistentvolumeclaims",
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       itemoutcome.OutcomeSucceeded,
		}},
	}

	itemoutcome.ApplyVolumes(items, volumeOutcomes([]*volume.BackupVolumeInfo{{
		PVCNamespace: "ns",
		PVCName:      "disk1",
		PVName:       "pv-1",
		BackupMethod: volume.CSISnapshot,
		Result:       volume.VolumeResultFailed,
	}}))

	row := items.Items[0]
	require.NotNil(t, row.Volume)
	assert.Equal(t, itemoutcome.VolumeResultFailed, row.Volume.Result)
	assert.Equal(t, itemoutcome.OutcomeFailed, row.Outcome,
		"a reader must not need volume info to learn the disk failed")
}

// A volume skipped by one path and captured by another stays one volume, and
// the item row carries both attempts so the reader can see why the skip was
// rescued.
func TestFinalizeFoldsAllVolumeAttemptsIntoItemOutcomes(t *testing.T) {
	items := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Items: []itemoutcome.ItemOutcome{{
			GroupResource:   "persistentvolumeclaims",
			Namespace:       "ns",
			Name:            "disk1",
			Outcome:         itemoutcome.OutcomeSkipped,
			SkippedByVolume: true,
		}},
	}

	itemoutcome.ApplyVolumes(items, volumeOutcomes([]*volume.BackupVolumeInfo{
		{
			PVCNamespace:  "ns",
			PVCName:       "disk1",
			PVName:        "pv-1",
			Skipped:       true,
			SkippedReason: "podvolume: opted out;",
		},
		{
			PVCNamespace: "ns",
			PVCName:      "disk1",
			PVName:       "pv-1",
			BackupMethod: volume.CSISnapshot,
			Result:       volume.VolumeResultSucceeded,
		},
	}))

	row := items.Items[0]
	require.NotNil(t, row.Volume)
	assert.Equal(t, itemoutcome.VolumeResultSucceeded, row.Volume.Result)
	assert.Equal(t, itemoutcome.OutcomeSucceeded, row.Outcome)
	require.Len(t, row.Volume.Attempts, 2)
	assert.Equal(t, "CSISnapshot", row.Volume.Attempts[0].Method)
	assert.Equal(t, itemoutcome.VolumeMethodPodVolumeBackup, row.Volume.Attempts[1].Method)
	assert.True(t, row.Volume.Attempts[1].Skipped)
}

// The VM case: the pod-volume path skipped and was untracked when CSI captured
// the volume. The capture attempt lives on the row, and finalize moves it into
// the volume evidence alongside the CSI success.
func TestFinalizeMergesCaptureAttemptWithVolumeInfo(t *testing.T) {
	items := &itemoutcome.ItemOutcomes{
		SchemaVersion: itemoutcome.SchemaVersion,
		Items: []itemoutcome.ItemOutcome{{
			GroupResource:   "persistentvolumeclaims",
			Namespace:       "ns",
			Name:            "disk1",
			Outcome:         itemoutcome.OutcomeSkipped,
			SkippedByVolume: true,
			VolumeAttempts: []itemoutcome.VolumeAttempt{{
				Method:        string(volume.PodVolumeBackup),
				Skipped:       true,
				SkippedReason: "opted out",
			}},
		}},
	}

	itemoutcome.ApplyVolumes(items, volumeOutcomes([]*volume.BackupVolumeInfo{{
		PVCNamespace: "ns",
		PVCName:      "disk1",
		PVName:       "pv-1",
		BackupMethod: volume.CSISnapshot,
		Result:       volume.VolumeResultSucceeded,
	}}))

	row := items.Items[0]
	require.NotNil(t, row.Volume)
	assert.Equal(t, itemoutcome.VolumeResultSucceeded, row.Volume.Result)
	assert.Equal(t, itemoutcome.OutcomeSucceeded, row.Outcome)
	require.Len(t, row.Volume.Attempts, 2)
	assert.Equal(t, "CSISnapshot", row.Volume.Attempts[0].Method)
	assert.Equal(t, string(volume.PodVolumeBackup), row.Volume.Attempts[1].Method)
	assert.True(t, row.Volume.Attempts[1].Skipped)
	assert.Empty(t, row.VolumeAttempts)
}
