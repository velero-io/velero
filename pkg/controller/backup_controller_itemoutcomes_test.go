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
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	testclocks "k8s.io/utils/clock/testing"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/internal/itemoutcome"
	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	pkgbackup "github.com/velero-io/velero/pkg/backup"
	"github.com/velero-io/velero/pkg/discovery"
	"github.com/velero-io/velero/pkg/persistence"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util/logging"
)

func TestPrepareBackupRequest_SetsCollectItemOutcomes(t *testing.T) {
	now, err := time.Parse(time.RFC1123Z, time.RFC1123Z)
	require.NoError(t, err)
	now = now.Local()

	tests := []struct {
		name                       string
		backup                     *velerov1api.Backup
		defaultCollectItemOutcomes bool
		expectEnabled              bool
	}{
		{
			name:                       "unset per-backup field falls back to server default (off)",
			backup:                     defaultBackup().Result(),
			defaultCollectItemOutcomes: false,
			expectEnabled:              false,
		},
		{
			name:                       "unset per-backup field falls back to server default (on)",
			backup:                     defaultBackup().Result(),
			defaultCollectItemOutcomes: true,
			expectEnabled:              true,
		},
		{
			name:                       "per-backup field overrides server default off->on",
			backup:                     defaultBackup().CollectItemOutcomes(true).Result(),
			defaultCollectItemOutcomes: false,
			expectEnabled:              true,
		},
		{
			name:                       "per-backup field overrides server default on->off",
			backup:                     defaultBackup().CollectItemOutcomes(false).Result(),
			defaultCollectItemOutcomes: true,
			expectEnabled:              false,
		},
	}

	for _, test := range tests {
		formatFlag := logging.FormatText
		var (
			fakeClient kbclient.Client
			logger     = logging.DefaultLogger(logrus.DebugLevel, formatFlag)
		)

		t.Run(test.name, func(t *testing.T) {
			apiServer := velerotest.NewAPIServer(t)
			discoveryHelper, err := discovery.NewHelper(apiServer.DiscoveryClient, logger)
			require.NoError(t, err)
			fakeClient = velerotest.NewFakeControllerRuntimeClient(t)
			c := &backupReconciler{
				logger:                     logger,
				discoveryHelper:            discoveryHelper,
				kbClient:                   fakeClient,
				formatFlag:                 formatFlag,
				clock:                      testclocks.NewFakeClock(now),
				defaultCollectItemOutcomes: test.defaultCollectItemOutcomes,
			}

			res := c.prepareBackupRequest(ctx, test.backup, logger)
			defer res.WorkerPool.Stop()
			assert.NotNil(t, res)

			require.NotNil(t, res.Spec.CollectItemOutcomes)
			assert.Equal(t, test.expectEnabled, *res.Spec.CollectItemOutcomes)
			if test.expectEnabled {
				assert.NotNil(t, res.ItemOutcomes)
			} else {
				assert.Nil(t, res.ItemOutcomes)
			}
		})
	}
}

func TestPersistBackupWithItemOutcomesDisabledDoesNotPanic(t *testing.T) {
	backup := defaultBackup().Result()
	request := &pkgbackup.Request{
		Backup:               backup,
		BackedUpItems:        pkgbackup.NewBackedUpItemsMap(),
		SkippedVolumeTracker: pkgbackup.NewSkipVolumeTracker(),
		// ItemOutcomes intentionally left nil: the feature is disabled.
	}

	backupStore := new(persistencemocks.BackupStore)
	var captured persistence.BackupInfo
	backupStore.On("PutBackup", mock.Anything).
		Run(func(args mock.Arguments) {
			captured = args.Get(0).(persistence.BackupInfo)
		}).
		Return(nil)

	logger := logging.DefaultLogger(logrus.DebugLevel, logging.FormatText)

	require.NotPanics(t, func() {
		errs := persistBackup(request, nil, nil, backupStore, nil, nil, nil, nil, nil, logger)
		assert.Empty(t, errs)
	})

	// The key assertion: a plain `== nil` comparison, matching exactly what
	// seekAndPutObject uses before deciding to skip uploading a field.
	// assert.Nil is reflection-based and can't tell a true nil interface
	// apart from one wrapping a nil *bytes.Buffer -- both report
	// IsNil()==true -- so it would pass either way and miss this bug.
	assert.True(t, captured.BackupItemOutcomes == nil, "BackupItemOutcomes must be a true nil interface, not a non-nil interface wrapping a nil *bytes.Buffer")
}

// The first write must name the backup so a saved artifact identifies its
// source without relying on the object key.

func TestPersistBackupSetsItemOutcomesBackupName(t *testing.T) {
	backup := defaultBackup().Result()
	request := &pkgbackup.Request{
		Backup:               backup,
		ItemOutcomes:         itemoutcome.NewRecorder(),
		BackedUpItems:        pkgbackup.NewBackedUpItemsMap(),
		SkippedVolumeTracker: pkgbackup.NewSkipVolumeTracker(),
	}

	backupStore := new(persistencemocks.BackupStore)
	var captured persistence.BackupInfo
	backupStore.On("PutBackup", mock.Anything).
		Run(func(args mock.Arguments) {
			captured = args.Get(0).(persistence.BackupInfo)
		}).
		Return(nil)

	logger := logging.DefaultLogger(logrus.DebugLevel, logging.FormatText)

	errs := persistBackup(request, nil, nil, backupStore, nil, nil, nil, nil, nil, logger)
	require.Empty(t, errs)
	require.NotNil(t, captured.BackupItemOutcomes)

	gzr, err := gzip.NewReader(captured.BackupItemOutcomes)
	require.NoError(t, err)
	defer gzr.Close()

	var outcomes itemoutcome.ItemOutcomes
	require.NoError(t, json.NewDecoder(gzr).Decode(&outcomes))
	assert.Equal(t, backup.Name, outcomes.BackupName)
}
