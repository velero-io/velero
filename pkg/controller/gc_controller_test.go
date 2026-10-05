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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func mockGCReconciler(fakeClient kbclient.Client, fakeClock *testclocks.FakeClock, freq time.Duration) *gcReconciler {
	gcr := NewGCReconciler(
		velerotest.NewLogger(),
		fakeClient,
		freq,
	)
	gcr.clock = fakeClock
	return gcr
}

func TestGCReconcile(t *testing.T) {
	fakeClock := testclocks.NewFakeClock(time.Now())
	defaultBackupLocation := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result()

	tests := []struct {
		name                   string
		backup                 *velerov1api.Backup
		deleteBackupRequests   []*velerov1api.DeleteBackupRequest
		backupLocation         *velerov1api.BackupStorageLocation
		expectError            bool
		expectedGCFailureLabel string
	}{
		{
			name: "can't find backup - no error",
		},
		{
			name:           "unexpired backup is not deleted",
			backup:         defaultBackup().Expiration(fakeClock.Now().Add(time.Minute)).StorageLocation("default").Result(),
			backupLocation: defaultBackupLocation,
		},
		{
			name:           "expired backup in read-only storage location is not deleted",
			backup:         defaultBackup().Expiration(fakeClock.Now().Add(-time.Minute)).StorageLocation("read-only").Result(),
			backupLocation: builder.ForBackupStorageLocation("velero", "read-only").AccessMode(velerov1api.BackupStorageLocationAccessModeReadOnly).Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result(),
		},
		{
			name:           "expired backup in read-write storage location is deleted",
			backup:         defaultBackup().Expiration(fakeClock.Now().Add(-time.Minute)).StorageLocation("read-write").Result(),
			backupLocation: builder.ForBackupStorageLocation("velero", "read-write").AccessMode(velerov1api.BackupStorageLocationAccessModeReadWrite).Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result(),
		},
		{
			name:           "expired backup with no pending deletion requests is deleted",
			backup:         defaultBackup().Expiration(fakeClock.Now().Add(-time.Second)).StorageLocation("default").Result(),
			backupLocation: defaultBackupLocation,
		},
		{
			name:           "expired backup with a pending deletion request is not deleted",
			backup:         defaultBackup().Expiration(fakeClock.Now().Add(-time.Second)).StorageLocation("default").Result(),
			backupLocation: defaultBackupLocation,
			deleteBackupRequests: []*velerov1api.DeleteBackupRequest{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: velerov1api.DefaultNamespace,
						Name:      "foo",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "backup-1",
							velerov1api.BackupUIDLabel:  "",
						},
					},
					Status: velerov1api.DeleteBackupRequestStatus{
						Phase: velerov1api.DeleteBackupRequestPhaseInProgress,
					},
				},
			},
		},
		{
			name:           "expired backup with only processed deletion requests is deleted",
			backup:         defaultBackup().Expiration(fakeClock.Now().Add(-time.Second)).StorageLocation("default").Result(),
			backupLocation: defaultBackupLocation,
			deleteBackupRequests: []*velerov1api.DeleteBackupRequest{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: velerov1api.DefaultNamespace,
						Name:      "foo",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "backup-1",
							velerov1api.BackupUIDLabel:  "",
						},
					},
					Status: velerov1api.DeleteBackupRequestStatus{
						Phase: velerov1api.DeleteBackupRequestPhaseProcessed,
					},
				},
			},
		},
		{
			name:                   "BSL is unavailable",
			backup:                 defaultBackup().Expiration(fakeClock.Now().Add(-time.Second)).StorageLocation("default").Result(),
			backupLocation:         builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Phase(velerov1api.BackupStorageLocationPhaseUnavailable).Result(),
			expectError:            true,
			expectedGCFailureLabel: gcFailureBSLUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.backup == nil {
				return
			}

			initObjs := []runtime.Object{}
			initObjs = append(initObjs, test.backup)

			if test.backupLocation != nil {
				initObjs = append(initObjs, test.backupLocation)
			}

			for _, dbr := range test.deleteBackupRequests {
				initObjs = append(initObjs, dbr)
			}

			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)
			reconciler := mockGCReconciler(fakeClient, fakeClock, defaultGCFrequency)
			_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: test.backup.Namespace, Name: test.backup.Name}})
			gotErr := err != nil
			assert.Equal(t, test.expectError, gotErr)

			if test.expectedGCFailureLabel != "" {
				updatedBackup := &velerov1api.Backup{}
				require.NoError(t, fakeClient.Get(t.Context(), types.NamespacedName{Namespace: test.backup.Namespace, Name: test.backup.Name}, updatedBackup))
				assert.Equal(t, test.expectedGCFailureLabel, updatedBackup.Labels[garbageCollectionFailure])
			}
		})
	}
}
