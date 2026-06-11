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

package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"context"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	pkgbackup "github.com/vmware-tanzu/velero/pkg/backup"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	persistencemocks "github.com/vmware-tanzu/velero/pkg/persistence/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/vmware-tanzu/velero/pkg/plugin/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero/mocks"
	"github.com/vmware-tanzu/velero/pkg/repository"
	repomanager "github.com/vmware-tanzu/velero/pkg/repository/manager"
	repomocks "github.com/vmware-tanzu/velero/pkg/repository/mocks"
	repotypes "github.com/vmware-tanzu/velero/pkg/repository/types"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

type backupDeletionControllerTestData struct {
	fakeClient        client.Client
	volumeSnapshotter *velerotest.FakeVolumeSnapshotter
	backupStore       *persistencemocks.BackupStore
	controller        *backupDeletionReconciler
	req               ctrl.Request
}

func defaultTestDbr() *velerov1api.DeleteBackupRequest {
	req := pkgbackup.NewDeleteBackupRequest("foo", "uid")
	req.Namespace = velerov1api.DefaultNamespace
	req.Name = "foo-abcde"
	return req
}

func setupBackupDeletionControllerTest(t *testing.T, req *velerov1api.DeleteBackupRequest, objects ...runtime.Object) *backupDeletionControllerTestData {
	t.Helper()
	var (
		fakeClient        = velerotest.NewFakeControllerRuntimeClient(t, append(objects, req)...)
		volumeSnapshotter = &velerotest.FakeVolumeSnapshotter{SnapshotsTaken: sets.NewString()}
		pluginManager     = &pluginmocks.Manager{}
		backupStore       = &persistencemocks.BackupStore{}
	)

	data := &backupDeletionControllerTestData{
		fakeClient:        fakeClient,
		volumeSnapshotter: volumeSnapshotter,
		backupStore:       backupStore,
		controller: NewBackupDeletionReconciler(
			velerotest.NewLogger(),
			fakeClient,
			NewBackupTracker(),
			nil, // repository manager
			metrics.NewServerMetrics(),
			nil, // discovery helper
			func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
			NewFakeSingleObjectBackupStoreGetter(backupStore),
			velerotest.NewFakeCredentialsFileStore("", nil),
			nil,
		),
		req: ctrl.Request{NamespacedName: types.NamespacedName{Namespace: req.Namespace, Name: req.Name}},
	}

	pluginManager.On("CleanupClients").Return(nil)
	return data
}

func TestBackupDeletionControllerReconcile(t *testing.T) {
	t.Run("failed to get backup store", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()
		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}
		dbr := defaultTestDbr()
		td := setupBackupDeletionControllerTest(t, dbr, location, backup)
		td.controller.backupStoreGetter = &fakeErrorBackupStoreGetter{}
		_, err := td.controller.Reconcile(ctx, td.req)
		require.NoError(t, err)
		res := &velerov1api.DeleteBackupRequest{}
		td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.True(t, strings.HasPrefix(res.Status.Errors[0], "error getting the backup store"))
	})

	t.Run("missing spec.backupName", func(t *testing.T) {
		dbr := defaultTestDbr()
		dbr.Spec.BackupName = ""
		td := setupBackupDeletionControllerTest(t, dbr)

		_, err := td.controller.Reconcile(ctx, td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "spec.backupName is required", res.Status.Errors[0])
	})

	t.Run("existing deletion requests for the backup are deleted", func(t *testing.T) {
		input := defaultTestDbr()
		td := setupBackupDeletionControllerTest(t, input)

		// add the backup to the tracker so the execution of reconcile doesn't progress
		// past checking for an in-progress backup. this makes validation easier.
		td.controller.backupTracker.Add(td.req.Namespace, input.Spec.BackupName)
		existing := &velerov1api.DeleteBackupRequest{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: td.req.Namespace,
				Name:      "bar",
				Labels: map[string]string{
					velerov1api.BackupNameLabel: input.Spec.BackupName,
				},
			},
			Spec: velerov1api.DeleteBackupRequestSpec{
				BackupName: input.Spec.BackupName,
			},
		}
		err := td.fakeClient.Create(t.Context(), existing)
		require.NoError(t, err)
		existing2 :=
			&velerov1api.DeleteBackupRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: td.req.Namespace,
					Name:      "bar-2",
					Labels: map[string]string{
						velerov1api.BackupNameLabel: "some-other-backup",
					},
				},
				Spec: velerov1api.DeleteBackupRequestSpec{
					BackupName: "some-other-backup",
				},
			}
		err = td.fakeClient.Create(t.Context(), existing2)
		require.NoError(t, err)
		_, err = td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)
		// verify "existing" is deleted
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: existing.Namespace,
			Name:      existing.Name,
		}, &velerov1api.DeleteBackupRequest{})

		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		// verify "existing2" remains
		assert.NoError(t, td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: existing2.Namespace,
			Name:      existing2.Name,
		}, &velerov1api.DeleteBackupRequest{}))
	})
	t.Run("deleting an in progress backup isn't allowed", func(t *testing.T) {
		dbr := defaultTestDbr()
		td := setupBackupDeletionControllerTest(t, dbr)

		td.controller.backupTracker.Add(td.req.Namespace, dbr.Spec.BackupName)
		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "backup is still in progress", res.Status.Errors[0])
	})

	t.Run("unable to find backup", func(t *testing.T) {
		td := setupBackupDeletionControllerTest(t, defaultTestDbr())

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "backup not found", res.Status.Errors[0])
	})
	t.Run("unable to find backup storage location", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()

		td := setupBackupDeletionControllerTest(t, defaultTestDbr(), backup)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "backup storage location default not found", res.Status.Errors[0])
	})

	t.Run("backup storage location is in read-only mode", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()
		location := builder.ForBackupStorageLocation("velero", "default").Phase(velerov1api.BackupStorageLocationPhaseAvailable).AccessMode(velerov1api.BackupStorageLocationAccessModeReadOnly).Result()

		td := setupBackupDeletionControllerTest(t, defaultTestDbr(), location, backup)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "cannot delete backup because backup storage location default is currently in read-only mode", res.Status.Errors[0])
	})

	t.Run("backup storage location is in unavailable state", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("default").Result()
		location := builder.ForBackupStorageLocation("velero", "default").Phase(velerov1api.BackupStorageLocationPhaseUnavailable).Result()

		td := setupBackupDeletionControllerTest(t, defaultTestDbr(), location, backup)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "cannot delete backup because backup storage location default is currently in Unavailable state", res.Status.Errors[0])
	})

	t.Run("full delete, no errors", func(t *testing.T) {
		input := defaultTestDbr()

		// Clear out resource labels to make sure the controller adds them and does not
		// panic when encountering a nil Labels map
		// (https://github.com/vmware-tanzu/velero/issues/1546)
		input.Labels = nil

		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		restore1 := builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Phase(velerov1api.RestorePhaseCompleted).Backup("foo").Result()
		restore2 := builder.ForRestore(velerov1api.DefaultNamespace, "restore-2").Phase(velerov1api.RestorePhaseCompleted).Backup("foo").Result()
		restore3 := builder.ForRestore(velerov1api.DefaultNamespace, "restore-3").Phase(velerov1api.RestorePhaseCompleted).Backup("some-other-backup").Result()

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}

		snapshotLocation := &velerov1api.VolumeSnapshotLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "vsl-1",
			},
			Spec: velerov1api.VolumeSnapshotLocationSpec{
				Provider: "provider-1",
			},
		}
		td := setupBackupDeletionControllerTest(t, input, backup, restore1, restore2, restore3, location, snapshotLocation)

		td.volumeSnapshotter.SnapshotsTaken.Insert("snap-1")

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "snap-1",
				},
			},
		}

		pluginManager := &pluginmocks.Manager{}
		pluginManager.On("GetVolumeSnapshotter", "provider-1").Return(td.volumeSnapshotter, nil)
		pluginManager.On("GetDeleteItemActions").Return(nil, nil)
		pluginManager.On("CleanupClients")
		td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }

		td.backupStore.On("GetBackupVolumeSnapshots", input.Spec.BackupName).Return(snapshots, nil)
		td.backupStore.On("GetBackupContents", input.Spec.BackupName).Return(io.NopCloser(bytes.NewReader([]byte("hello world"))), nil)
		td.backupStore.On("DeleteBackup", input.Spec.BackupName).Return(nil)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		// the dbr should be deleted
		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)
		if err == nil {
			t.Logf("status of the dbr: %s, errors in dbr: %v", res.Status.Phase, res.Status.Errors)
		}

		// backup CR, restore CR restore-1 and restore-2 should be deleted
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      backup.Name,
		}, &velerov1api.Backup{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      "restore-1",
		}, &velerov1api.Restore{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      "restore-2",
		}, &velerov1api.Restore{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		// restore-3 should remain
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      "restore-3",
		}, &velerov1api.Restore{})
		require.NoError(t, err)

		td.backupStore.AssertCalled(t, "DeleteBackup", input.Spec.BackupName)

		// Make sure snapshot was deleted
		assert.Equal(t, 0, td.volumeSnapshotter.SnapshotsTaken.Len())
	})
	t.Run("full delete, no errors, with backup name greater than 63 chars", func(t *testing.T) {
		backup := defaultBackup().
			ObjectMeta(
				builder.WithName("the-really-long-backup-name-that-is-much-more-than-63-characters"),
			).
			Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		restore1 := builder.ForRestore(backup.Namespace, "restore-1").
			Phase(velerov1api.RestorePhaseCompleted).
			Backup(backup.Name).
			Result()
		restore2 := builder.ForRestore(backup.Namespace, "restore-2").
			Phase(velerov1api.RestorePhaseCompleted).
			Backup(backup.Name).
			Result()
		restore3 := builder.ForRestore(backup.Namespace, "restore-3").
			Phase(velerov1api.RestorePhaseCompleted).
			Backup("some-other-backup").
			Result()

		dbr := pkgbackup.NewDeleteBackupRequest(backup.Name, "uid")
		dbr.Namespace = velerov1api.DefaultNamespace
		dbr.Name = "foo-abcde"
		// Clear out resource labels to make sure the controller adds them
		dbr.Labels = nil

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}

		snapshotLocation := &velerov1api.VolumeSnapshotLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "vsl-1",
			},
			Spec: velerov1api.VolumeSnapshotLocationSpec{
				Provider: "provider-1",
			},
		}
		td := setupBackupDeletionControllerTest(t, dbr, backup, restore1, restore2, restore3, location, snapshotLocation)

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "snap-1",
				},
			},
		}

		pluginManager := &pluginmocks.Manager{}
		pluginManager.On("GetVolumeSnapshotter", "provider-1").Return(td.volumeSnapshotter, nil)
		pluginManager.On("GetDeleteItemActions").Return(nil, nil)
		pluginManager.On("CleanupClients")
		td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }

		td.backupStore.On("GetBackupVolumeSnapshots", dbr.Spec.BackupName).Return(snapshots, nil)
		td.backupStore.On("GetBackupContents", dbr.Spec.BackupName).Return(io.NopCloser(bytes.NewReader([]byte("hello world"))), nil)
		td.backupStore.On("DeleteBackup", dbr.Spec.BackupName).Return(nil)
		td.backupStore.On("DeleteRestore", "restore-1").Return(nil)
		td.backupStore.On("DeleteRestore", "restore-2").Return(nil)

		td.volumeSnapshotter.SnapshotsTaken.Insert("snap-1")

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		// the dbr should be deleted
		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)
		if err == nil {
			t.Logf("status of the dbr: %s, errors in dbr: %v", res.Status.Phase, res.Status.Errors)
		}

		// backup CR, restore CR restore-1 and restore-2 should be deleted
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      backup.Name,
		}, &velerov1api.Backup{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      "restore-1",
		}, &velerov1api.Restore{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      "restore-2",
		}, &velerov1api.Restore{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		// restore-3 should remain
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      "restore-3",
		}, &velerov1api.Restore{})
		require.NoError(t, err)

		// Make sure snapshot was deleted
		assert.Equal(t, 0, td.volumeSnapshotter.SnapshotsTaken.Len())
	})
	t.Run("backup is not downloaded when there are no DeleteItemAction plugins", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		input := defaultTestDbr()
		// Clear out resource labels to make sure the controller adds them and does not
		// panic when encountering a nil Labels map
		// (https://github.com/vmware-tanzu/velero/issues/1546)
		input.Labels = nil

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}

		snapshotLocation := &velerov1api.VolumeSnapshotLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "vsl-1",
			},
			Spec: velerov1api.VolumeSnapshotLocationSpec{
				Provider: "provider-1",
			},
		}
		td := setupBackupDeletionControllerTest(t, defaultTestDbr(), backup, location, snapshotLocation)
		td.volumeSnapshotter.SnapshotsTaken.Insert("snap-1")

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "snap-1",
				},
			},
		}

		pluginManager := &pluginmocks.Manager{}
		pluginManager.On("GetVolumeSnapshotter", "provider-1").Return(td.volumeSnapshotter, nil)
		pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{}, nil)
		pluginManager.On("CleanupClients")
		td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }

		td.backupStore.On("GetBackupVolumeSnapshots", input.Spec.BackupName).Return(snapshots, nil)
		td.backupStore.On("DeleteBackup", input.Spec.BackupName).Return(nil)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		td.backupStore.AssertNotCalled(t, "GetBackupContents", mock.Anything)
		td.backupStore.AssertCalled(t, "DeleteBackup", input.Spec.BackupName)

		// the dbr should be deleted
		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)
		if err == nil {
			t.Logf("status of the dbr: %s, errors in dbr: %v", res.Status.Phase, res.Status.Errors)
		}

		// backup CR should be deleted
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      backup.Name,
		}, &velerov1api.Backup{})
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		// Make sure snapshot was deleted
		assert.Equal(t, 0, td.volumeSnapshotter.SnapshotsTaken.Len())
	})
	t.Run("backup deletion fails with error when downloading tarball fails for DeleteItemAction plugins", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		input := defaultTestDbr()
		// Clear out resource labels to make sure the controller adds them and does not
		// panic when encountering a nil Labels map
		// (https://github.com/vmware-tanzu/velero/issues/1546)
		input.Labels = nil

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}

		snapshotLocation := &velerov1api.VolumeSnapshotLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "vsl-1",
			},
			Spec: velerov1api.VolumeSnapshotLocationSpec{
				Provider: "provider-1",
			},
		}

		csiSnapshot := builder.ForVolumeSnapshot("user-ns", "vs-1").ObjectMeta(
			builder.WithLabelsMap(map[string]string{
				"velero.io/backup-name": "foo",
			})).SourcePVC("some-pvc").Result()

		td := setupBackupDeletionControllerTest(t, defaultTestDbr(), backup, location, snapshotLocation, csiSnapshot)
		td.volumeSnapshotter.SnapshotsTaken.Insert("snap-1")

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "snap-1",
				},
			},
		}

		pluginManager := &pluginmocks.Manager{}
		pluginManager.On("GetVolumeSnapshotter", "provider-1").Return(td.volumeSnapshotter, nil)
		pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{new(mocks.DeleteItemAction)}, nil)
		pluginManager.On("CleanupClients")
		td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }

		td.backupStore.On("GetBackupVolumeSnapshots", input.Spec.BackupName).Return(snapshots, nil)
		td.backupStore.On("GetBackupContents", input.Spec.BackupName).Return(nil, fmt.Errorf("error downloading tarball"))

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		td.backupStore.AssertCalled(t, "GetBackupContents", input.Spec.BackupName)
		// DeleteBackup (removing backup data from object storage) must NOT be called
		// when there are errors, so that the deletion can be retried later.
		td.backupStore.AssertNotCalled(t, "DeleteBackup", input.Spec.BackupName)

		// the dbr should still exist and be marked Processed with errors
		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err, "Expected DBR to still exist after tarball download failure")
		assert.Equal(t, velerov1api.DeleteBackupRequestPhaseProcessed, res.Status.Phase)
		require.Len(t, res.Status.Errors, 1)
		assert.Contains(t, res.Status.Errors[0], "error downloading backup tarball, CSI snapshot cleanup was skipped")

		// backup CR should NOT be deleted
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      backup.Name,
		}, &velerov1api.Backup{})
		require.NoError(t, err, "Expected backup CR to still exist after tarball download failure")
	})
	t.Run("backup is still deleted if downloading tarball returns a not-found error", func(t *testing.T) {
		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		input := defaultTestDbr()
		input.Labels = nil

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}

		snapshotLocation := &velerov1api.VolumeSnapshotLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "vsl-1",
			},
			Spec: velerov1api.VolumeSnapshotLocationSpec{
				Provider: "provider-1",
			},
		}

		td := setupBackupDeletionControllerTest(t, defaultTestDbr(), backup, location, snapshotLocation)
		td.volumeSnapshotter.SnapshotsTaken.Insert("snap-1")

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "snap-1",
				},
			},
		}

		pluginManager := &pluginmocks.Manager{}
		pluginManager.On("GetVolumeSnapshotter", "provider-1").Return(td.volumeSnapshotter, nil)
		pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{new(mocks.DeleteItemAction)}, nil)
		pluginManager.On("CleanupClients")
		td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }

		td.backupStore.On("GetBackupVolumeSnapshots", input.Spec.BackupName).Return(snapshots, nil)
		// Simulate a 404/not-found error (tarball has already been removed from storage)
		td.backupStore.On("GetBackupContents", input.Spec.BackupName).Return(nil, fmt.Errorf("key not found"))
		td.backupStore.On("DeleteBackup", input.Spec.BackupName).Return(nil)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		td.backupStore.AssertCalled(t, "GetBackupContents", input.Spec.BackupName)
		td.backupStore.AssertCalled(t, "DeleteBackup", input.Spec.BackupName)

		// the dbr should be deleted (not-found is treated as permanent, deletion proceeds)
		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.True(t, apierrors.IsNotFound(err), "Expected DBR to be deleted after not-found tarball error, but actual error: %v", err)

		// backup CR should be deleted because there are no errors in errs
		err = td.fakeClient.Get(t.Context(), types.NamespacedName{
			Namespace: velerov1api.DefaultNamespace,
			Name:      backup.Name,
		}, &velerov1api.Backup{})
		assert.True(t, apierrors.IsNotFound(err), "Expected backup CR to be deleted after not-found tarball error, but actual error: %v", err)
	})
	t.Run("Expired request will be deleted if the status is processed", func(t *testing.T) {
		expired := time.Date(2018, 4, 3, 12, 0, 0, 0, time.UTC)
		input := defaultTestDbr()
		input.CreationTimestamp = metav1.Time{
			Time: expired,
		}
		input.Status.Phase = velerov1api.DeleteBackupRequestPhaseProcessed
		td := setupBackupDeletionControllerTest(t, input)
		td.backupStore.On("DeleteBackup", mock.Anything).Return(nil)
		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)
		td.backupStore.AssertNotCalled(t, "DeleteBackup", mock.Anything)
	})

	t.Run("Expired request will not be deleted if the status is not processed", func(t *testing.T) {
		expired := time.Date(2018, 4, 3, 12, 0, 0, 0, time.UTC)
		input := defaultTestDbr()
		input.CreationTimestamp = metav1.Time{
			Time: expired,
		}
		input.Status.Phase = velerov1api.DeleteBackupRequestPhaseNew
		td := setupBackupDeletionControllerTest(t, input)
		td.backupStore.On("DeleteBackup", mock.Anything).Return(nil)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		require.NoError(t, err)
		assert.Equal(t, "Processed", string(res.Status.Phase))
		assert.Len(t, res.Status.Errors, 1)
		assert.Equal(t, "backup not found", res.Status.Errors[0])
	})

	t.Run("snapshot with empty ProviderSnapshotID is skipped during deletion", func(t *testing.T) {
		input := defaultTestDbr()
		input.Labels = nil

		backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      backup.Spec.StorageLocation,
			},
			Spec: velerov1api.BackupStorageLocationSpec{
				Provider: "objStoreProvider",
				StorageType: velerov1api.StorageType{
					ObjectStorage: &velerov1api.ObjectStorageLocation{
						Bucket: "bucket",
					},
				},
			},
			Status: velerov1api.BackupStorageLocationStatus{
				Phase: velerov1api.BackupStorageLocationPhaseAvailable,
			},
		}

		snapshotLocation := &velerov1api.VolumeSnapshotLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "vsl-1",
			},
			Spec: velerov1api.VolumeSnapshotLocationSpec{
				Provider: "provider-1",
			},
		}
		td := setupBackupDeletionControllerTest(t, input, backup, location, snapshotLocation)

		// Create snapshots with one having empty ProviderSnapshotID (failed snapshot)
		// and one with valid ProviderSnapshotID
		td.volumeSnapshotter.SnapshotsTaken.Insert("snap-1")

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "", // Empty snapshot ID (failed creation)
				},
			},
			{
				Spec: volume.SnapshotSpec{
					Location: "vsl-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "snap-1", // Valid snapshot ID
				},
			},
		}

		pluginManager := &pluginmocks.Manager{}
		pluginManager.On("GetVolumeSnapshotter", "provider-1").Return(td.volumeSnapshotter, nil)
		pluginManager.On("GetDeleteItemActions").Return(nil, nil)
		pluginManager.On("CleanupClients")
		td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }

		td.backupStore.On("GetBackupVolumeSnapshots", input.Spec.BackupName).Return(snapshots, nil)
		td.backupStore.On("GetBackupContents", input.Spec.BackupName).Return(io.NopCloser(bytes.NewReader([]byte("hello world"))), nil)
		td.backupStore.On("DeleteBackup", input.Spec.BackupName).Return(nil)

		_, err := td.controller.Reconcile(t.Context(), td.req)
		require.NoError(t, err)

		// the dbr should be deleted
		res := &velerov1api.DeleteBackupRequest{}
		err = td.fakeClient.Get(ctx, td.req.NamespacedName, res)
		assert.True(t, apierrors.IsNotFound(err), "Expected not found error, but actual value of error: %v", err)

		td.backupStore.AssertCalled(t, "DeleteBackup", input.Spec.BackupName)

		// Only the valid snapshot should have been deleted (snap-1)
		// The empty ProviderSnapshotID snapshot should have been skipped
		assert.Equal(t, 0, td.volumeSnapshotter.SnapshotsTaken.Len())
	})
}

func TestGetSnapshotsInBackup(t *testing.T) {
	tests := []struct {
		name                  string
		podVolumeBackups      []velerov1api.PodVolumeBackup
		expected              map[string][]repotypes.SnapshotIdentifier
		longBackupNameEnabled bool
	}{
		{
			name:             "no pod volume backups",
			podVolumeBackups: nil,
			expected:         map[string][]repotypes.SnapshotIdentifier{},
		},
		{
			name: "no pod volume backups with matching label",
			podVolumeBackups: []velerov1api.PodVolumeBackup{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{velerov1api.BackupNameLabel: "non-matching-backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "bar", Labels: map[string]string{velerov1api.BackupNameLabel: "non-matching-backup-2"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-2", Namespace: "ns-2"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-2"},
				},
			},
			expected: map[string][]repotypes.SnapshotIdentifier{},
		},
		{
			name: "some pod volume backups with matching label",
			podVolumeBackups: []velerov1api.PodVolumeBackup{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{velerov1api.BackupNameLabel: "non-matching-backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "bar", Labels: map[string]string{velerov1api.BackupNameLabel: "non-matching-backup-2"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-2", Namespace: "ns-2"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-2"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "completed-pvb", Labels: map[string]string{velerov1api.BackupNameLabel: "backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-3"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "completed-pvb-2", Labels: map[string]string{velerov1api.BackupNameLabel: "backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-4"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "incomplete-or-failed-pvb", Labels: map[string]string{velerov1api.BackupNameLabel: "backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-2"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: ""},
				},
			},
			expected: map[string][]repotypes.SnapshotIdentifier{
				"ns-1": {
					{
						VolumeNamespace: "ns-1",
						SnapshotID:      "snap-3",
						RepositoryType:  "kopia",
					},
					{
						VolumeNamespace: "ns-1",
						SnapshotID:      "snap-4",
						RepositoryType:  "kopia",
					},
				},
			},
		},
		{
			name:                  "some pod volume backups with matching label and backup name greater than 63 chars",
			longBackupNameEnabled: true,
			podVolumeBackups: []velerov1api.PodVolumeBackup{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "foo", Labels: map[string]string{velerov1api.BackupNameLabel: "non-matching-backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "bar", Labels: map[string]string{velerov1api.BackupNameLabel: "non-matching-backup-2"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-2", Namespace: "ns-2"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-2"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "completed-pvb", Labels: map[string]string{velerov1api.BackupNameLabel: "the-really-long-backup-name-that-is-much-more-than-63-cha6ca4bc"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-3"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "completed-pvb-2", Labels: map[string]string{velerov1api.BackupNameLabel: "backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-1"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: "snap-4"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "incomplete-or-failed-pvb", Labels: map[string]string{velerov1api.BackupNameLabel: "backup-1"}},
					Spec: velerov1api.PodVolumeBackupSpec{
						Pod: corev1api.ObjectReference{Name: "pod-1", Namespace: "ns-2"},
					},
					Status: velerov1api.PodVolumeBackupStatus{SnapshotID: ""},
				},
			},
			expected: map[string][]repotypes.SnapshotIdentifier{
				"ns-1": {
					{
						VolumeNamespace: "ns-1",
						SnapshotID:      "snap-3",
						RepositoryType:  "kopia",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				clientBuilder = velerotest.NewFakeControllerRuntimeClientBuilder(t)
				veleroBackup  = &velerov1api.Backup{}
			)

			veleroBackup.Name = "backup-1"

			if test.longBackupNameEnabled {
				veleroBackup.Name = "the-really-long-backup-name-that-is-much-more-than-63-characters"
			}
			clientBuilder.WithLists(&velerov1api.PodVolumeBackupList{
				Items: test.podVolumeBackups,
			})

			res, err := getSnapshotsInBackup(t.Context(), veleroBackup, clientBuilder.Build())
			require.NoError(t, err)

			assert.True(t, reflect.DeepEqual(res, test.expected))
		})
	}
}

func batchDeleteSucceed(ctx context.Context, repoEnsurer *repository.Ensurer, repoMgr repomanager.Manager, directSnapshots map[string][]repotypes.SnapshotIdentifier, backup *velerov1api.Backup, logger logrus.FieldLogger) []error {
	return nil
}

func batchDeleteFail(ctx context.Context, repoEnsurer *repository.Ensurer, repoMgr repomanager.Manager, directSnapshots map[string][]repotypes.SnapshotIdentifier, backup *velerov1api.Backup, logger logrus.FieldLogger) []error {
	return []error{
		errors.New("fake-delete-1"),
		errors.New("fake-delete-2"),
	}
}

func generateSnapshotData(snapshot *repotypes.SnapshotIdentifier) (map[string]string, error) {
	if snapshot == nil {
		return nil, nil
	}

	b, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}

	data := make(map[string]string)
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func TestDeleteMovedSnapshots(t *testing.T) {
	tests := []struct {
		name               string
		repoMgr            repomanager.Manager
		batchDeleteSucceed bool
		backupName         string
		snapshots          []*repotypes.SnapshotIdentifier
		expected           []string
	}{
		{
			name: "repoMgr is nil",
		},
		{
			name:    "no cm",
			repoMgr: repomocks.NewManager(t),
		},
		{
			name:       "bad cm info",
			repoMgr:    repomocks.NewManager(t),
			backupName: "backup-01",
			snapshots:  []*repotypes.SnapshotIdentifier{nil},
			expected:   []string{"no snapshot info in config"},
		},
		{
			name:       "invalid snapshots",
			repoMgr:    repomocks.NewManager(t),
			backupName: "backup-01",
			snapshots: []*repotypes.SnapshotIdentifier{
				{
					RepositoryType:  "repo-1",
					VolumeNamespace: "ns-1",
				},
				{
					SnapshotID:      "snapshot-1",
					VolumeNamespace: "ns-1",
				},
				{
					SnapshotID:     "snapshot-1",
					RepositoryType: "repo-1",
				},
			},
			batchDeleteSucceed: true,
			expected: []string{
				"invalid snapshot, ID , namespace ns-1, repository repo-1",
				"invalid snapshot, ID snapshot-1, namespace ns-1, repository ",
				"invalid snapshot, ID snapshot-1, namespace , repository repo-1",
			},
		},
		{
			name:       "batch delete succeed",
			repoMgr:    repomocks.NewManager(t),
			backupName: "backup-01",
			snapshots: []*repotypes.SnapshotIdentifier{

				{
					SnapshotID:      "snapshot-1",
					RepositoryType:  "repo-1",
					VolumeNamespace: "ns-1",
				},
			},
			batchDeleteSucceed: true,
			expected:           []string{},
		},
		{
			name:       "batch delete fail",
			repoMgr:    repomocks.NewManager(t),
			backupName: "backup-01",
			snapshots: []*repotypes.SnapshotIdentifier{
				{
					RepositoryType:  "repo-1",
					VolumeNamespace: "ns-1",
				},
				{
					SnapshotID:      "snapshot-1",
					RepositoryType:  "repo-1",
					VolumeNamespace: "ns-1",
				},
			},
			expected: []string{"invalid snapshot, ID , namespace ns-1, repository repo-1", "fake-delete-1", "fake-delete-2"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for i, snapshot := range test.snapshots {
				snapshotData, err := generateSnapshotData(snapshot)
				require.NoError(t, err)

				cm := corev1api.ConfigMap{
					TypeMeta: metav1.TypeMeta{
						APIVersion: corev1api.SchemeGroupVersion.String(),
						Kind:       "ConfigMap",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      fmt.Sprintf("du-info-%d", i),
						Labels: map[string]string{
							velerov1api.BackupNameLabel:             test.backupName,
							velerov1api.DataUploadSnapshotInfoLabel: "true",
						},
					},
					Data: snapshotData,
				}

				objs = append(objs, &cm)
			}

			veleroBackup := &velerov1api.Backup{}
			controller := NewBackupDeletionReconciler(
				velerotest.NewLogger(),
				velerotest.NewFakeControllerRuntimeClient(t, objs...),
				NewBackupTracker(),
				test.repoMgr,
				metrics.NewServerMetrics(),
				nil, // discovery helper
				func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
				NewFakeSingleObjectBackupStoreGetter(backupStore),
				velerotest.NewFakeCredentialsFileStore("", nil),
				nil,
			)

			veleroBackup.Name = test.backupName

			if test.batchDeleteSucceed {
				batchDeleteSnapshotFunc = batchDeleteSucceed
			} else {
				batchDeleteSnapshotFunc = batchDeleteFail
			}

			errs := controller.deleteMovedSnapshots(t.Context(), veleroBackup)
			if test.expected == nil {
				assert.Nil(t, errs)
			} else {
				assert.Len(t, errs, len(test.expected))
				for i := range test.expected {
					assert.EqualError(t, errs[i], test.expected[i])
				}
			}
		})
	}
}
