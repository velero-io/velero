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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"context"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
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

	"github.com/velero-io/velero/internal/volume"
	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	pkgbackup "github.com/velero-io/velero/pkg/backup"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/metrics"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"
	"github.com/velero-io/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/velero-io/velero/pkg/plugin/mocks"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/plugin/velero/mocks"
	"github.com/velero-io/velero/pkg/repository"
	repomanager "github.com/velero-io/velero/pkg/repository/manager"
	repomocks "github.com/velero-io/velero/pkg/repository/mocks"
	repotypes "github.com/velero-io/velero/pkg/repository/types"
	"github.com/velero-io/velero/pkg/repository/udmrepo"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/uploader"
	"github.com/velero-io/velero/pkg/util/csi"
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
		assert.True(t, strings.HasPrefix(res.Status.Errors[0], "backup deletion failed: error getting the backup store"))
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
		assert.Equal(t, "backup deletion failed: spec.backupName is required", res.Status.Errors[0])
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
		assert.Equal(t, "backup deletion failed: backup is still in progress", res.Status.Errors[0])
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
		assert.Equal(t, "backup deletion failed: backup not found", res.Status.Errors[0])
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
		assert.Equal(t, "backup deletion failed: backup storage location default not found", res.Status.Errors[0])
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
		assert.Equal(t, "backup deletion failed: cannot delete backup because backup storage location default is currently in read-only mode", res.Status.Errors[0])
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
		assert.Equal(t, "backup deletion failed: cannot delete backup because backup storage location default is currently in Unavailable state", res.Status.Errors[0])
	})

	t.Run("full delete, no errors", func(t *testing.T) {
		input := defaultTestDbr()

		// Clear out resource labels to make sure the controller adds them and does not
		// panic when encountering a nil Labels map
		// (https://github.com/velero-io/velero/issues/1546)
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
	t.Run("empty ProviderSnapshotID skips DeleteSnapshot call", func(t *testing.T) {
		input := defaultTestDbr()

		backup := builder.ForBackup(velerov1api.DefaultNamespace, input.Spec.BackupName).Result()
		backup.UID = "uid"
		backup.Spec.StorageLocation = "primary"

		restore1 := builder.ForRestore(backup.Namespace, "restore-1").
			Phase(velerov1api.RestorePhaseCompleted).
			Backup(backup.Name).
			Result()

		location := &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: backup.Namespace,
				Name:      "primary",
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
		td := setupBackupDeletionControllerTest(t, input, backup, restore1, location, snapshotLocation)

		snapshots := []*volume.Snapshot{
			{
				Spec: volume.SnapshotSpec{
					Location:             "vsl-1",
					PersistentVolumeName: "pv-1",
				},
				Status: volume.SnapshotStatus{
					ProviderSnapshotID: "",
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

		td.backupStore.AssertCalled(t, "DeleteBackup", input.Spec.BackupName)
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
		// (https://github.com/velero-io/velero/issues/1546)
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
		// (https://github.com/velero-io/velero/issues/1546)
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
		assert.Equal(t, "backup deletion failed: backup not found", res.Status.Errors[0])
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

func TestIsTarballNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"generic not found", errors.New("not found"), true},
		{"generic does not exist", errors.New("does not exist"), true},
		{"aws s3 nosuchkey", errors.New("nosuchkey"), true},
		{"azure blobnotfound", errors.New("blobnotfound"), true},
		{"gcs objectnotexist", errors.New("objectnotexist"), true},
		{"gcs object doesn't exist", errors.New("storage: object doesn't exist"), true},
		{
			"gcs object doesn't exist in wrapped error",
			errors.New("error downloading backup tarball, CSI snapshot cleanup was skipped: rpc error: code = Unknown desc = storage: object doesn't exist"),
			true,
		},
		{"transient network error", errors.New("connection refused"), false},
		{"auth failure", errors.New("access denied"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isTarballNotFoundError(tc.err))
		})
	}
}

func TestDeletionRejectsUnsupportedUploaderBeforeMutation(t *testing.T) {
	for _, uploaderType := range []string{"unsupported", "restic", ""} {
		t.Run(fmt.Sprintf("uploader=%q", uploaderType), func(t *testing.T) {
			dbr := defaultTestDbr()
			backup := builder.ForBackup(dbr.Namespace, dbr.Spec.BackupName).
				StorageLocation("location-1").Phase(velerov1api.BackupPhaseCompleted).Result()
			pvb := builder.ForPodVolumeBackup(dbr.Namespace, "pvb").
				UploaderType(uploaderType).
				ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backup.Name)).Result()
			td := setupBackupDeletionControllerTest(t, dbr, backup, defaultLocation(dbr.Namespace), pvb)

			_, err := td.controller.Reconcile(t.Context(), td.req)
			require.NoError(t, err)
			require.NoError(t, td.fakeClient.Get(t.Context(), client.ObjectKeyFromObject(dbr), dbr))
			require.Equal(t, velerov1api.DeleteBackupRequestPhaseProcessed, dbr.Status.Phase)
			require.Len(t, dbr.Status.Errors, 1)
			require.Contains(t, dbr.Status.Errors[0], "invalid uploader type")
			require.NoError(t, td.fakeClient.Get(t.Context(), client.ObjectKeyFromObject(backup), backup))
			require.Equal(t, velerov1api.BackupPhaseCompleted, backup.Status.Phase)
			require.NoError(t, td.fakeClient.Get(t.Context(), client.ObjectKeyFromObject(pvb), pvb))
			require.Empty(t, td.backupStore.Calls)
		})
	}
}

func retainedSnapshotConfigMap(t *testing.T, backupName string, name string, retained *velerov2alpha1api.RetainedSnapshot) *corev1api.ConfigMap {
	t.Helper()
	b, err := json.Marshal(retained)
	require.NoError(t, err)
	data := make(map[string]string)
	require.NoError(t, json.Unmarshal(b, &data))
	return &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1api.DefaultNamespace,
			Name:      name,
			Labels: map[string]string{
				velerov1api.BackupNameLabel:                 backupName,
				velerov1api.DataUploadRetainedSnapshotLabel: "true",
			},
		},
		Data: data,
	}
}

func stubTempVSCDeletion(t *testing.T, waitErr error) *[]string {
	t.Helper()
	waited := []string{}
	originalStatusWait := csi.WaitTempVSCStatus
	t.Cleanup(func() { csi.WaitTempVSCStatus = originalStatusWait })
	csi.WaitTempVSCStatus = func(context.Context, client.Client, *snapshotv1api.VolumeSnapshotContent, time.Duration, logrus.FieldLogger) error {
		return nil
	}
	originalWait := csi.WaitTempVSCDeleted
	t.Cleanup(func() { csi.WaitTempVSCDeleted = originalWait })
	csi.WaitTempVSCDeleted = func(_ context.Context, _ client.Client, name string, _ time.Duration, _ logrus.FieldLogger) error {
		waited = append(waited, name)
		return waitErr
	}
	return &waited
}

func TestBackupDeletionRetainedSnapshotAfterOtherData(t *testing.T) {
	tests := []struct {
		name               string
		batchDeleteSucceed bool
		existingTempVSC    bool
		wantSnapshotDelete bool
	}{
		{
			name:               "retained snapshot is deleted after the moved snapshot data",
			batchDeleteSucceed: true,
			wantSnapshotDelete: true,
		},
		{
			name:               "retry of an interrupted deletion reuses the temp VSC it left",
			batchDeleteSucceed: true,
			existingTempVSC:    true,
			wantSnapshotDelete: true,
		},
		{
			name: "retained snapshot is kept when deleting the moved snapshot data fails",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			waited := stubTempVSCDeletion(t, nil)
			originalBatchDelete := batchDeleteSnapshotFunc
			t.Cleanup(func() { batchDeleteSnapshotFunc = originalBatchDelete })
			if tc.batchDeleteSucceed {
				batchDeleteSnapshotFunc = batchDeleteSucceed
			} else {
				batchDeleteSnapshotFunc = batchDeleteFail
			}

			backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("primary").SnapshotMoveData(true).Result()
			backup.UID = "uid"
			location := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "primary").Provider("objStoreProvider").Bucket("bucket").Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result()

			snapshotData, err := generateSnapshotData(&repotypes.SnapshotIdentifier{
				SnapshotID:      "kopia-snapshot-1",
				RepositoryType:  "kopia",
				VolumeNamespace: "app",
			})
			require.NoError(t, err)
			snapshotInfoCM := &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: velerov1api.DefaultNamespace,
					Name:      "foo-du-info",
					Labels: map[string]string{
						velerov1api.BackupNameLabel:             "foo",
						velerov1api.DataUploadSnapshotInfoLabel: "true",
					},
				},
				Data: snapshotData,
			}
			retainedCM := retainedSnapshotConfigMap(t, "foo", "foo-du-retained-snapshot", &velerov2alpha1api.RetainedSnapshot{
				SnapshotHandle: "snap-handle",
				Driver:         "hostpath.csi.k8s.io",
			})

			objs := []runtime.Object{backup, location, snapshotInfoCM, retainedCM}
			if tc.existingTempVSC {
				sum := sha256.Sum256([]byte("hostpath.csi.k8s.io/snap-handle"))
				handle := "snap-handle"
				objs = append(objs, &snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name:       "vsc-" + hex.EncodeToString(sum[:16]),
						Labels:     map[string]string{velerov1api.BackupNameLabel: "foo"},
						Finalizers: []string{csi.VSCBoundProtectionFinalizer},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
						Driver:         "hostpath.csi.k8s.io",
						Source:         snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: &handle},
					},
				})
			}

			dbr := defaultTestDbr()
			td := setupBackupDeletionControllerTest(t, dbr, objs...)
			td.controller.repoMgr = repomocks.NewManager(t)

			pluginManager := &pluginmocks.Manager{}
			pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{}, nil)
			pluginManager.On("CleanupClients")
			td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }
			td.backupStore.On("GetBackupVolumeSnapshots", dbr.Spec.BackupName).Return(nil, nil)
			td.backupStore.On("DeleteBackup", dbr.Spec.BackupName).Return(nil)

			_, err = td.controller.Reconcile(t.Context(), td.req)
			require.NoError(t, err)

			vscs := &snapshotv1api.VolumeSnapshotContentList{}
			require.NoError(t, td.fakeClient.List(t.Context(), vscs))
			if tc.wantSnapshotDelete {
				require.Len(t, vscs.Items, 1)
				require.NotNil(t, vscs.Items[0].Spec.Source.SnapshotHandle)
				assert.Equal(t, "snap-handle", *vscs.Items[0].Spec.Source.SnapshotHandle)
				assert.Equal(t, "foo", vscs.Items[0].Labels[velerov1api.BackupNameLabel])
				assert.NotNil(t, vscs.Items[0].DeletionTimestamp, "expected the temp VSC to be deleted")
				assert.Len(t, *waited, 1)
				td.backupStore.AssertCalled(t, "DeleteBackup", dbr.Spec.BackupName)
			} else {
				assert.Empty(t, vscs.Items)
				assert.Empty(t, *waited)
				td.backupStore.AssertNotCalled(t, "DeleteBackup", mock.Anything)

				res := &velerov1api.DeleteBackupRequest{}
				require.NoError(t, td.fakeClient.Get(t.Context(), td.req.NamespacedName, res))
				assert.Contains(t, strings.Join(res.Status.Errors, "\n"), "error deleting moved snapshot data")
			}

			// The configmap is the record of the snapshot, so it is kept until the snapshot is deleted.
			err = td.fakeClient.Get(t.Context(), client.ObjectKeyFromObject(retainedCM), &corev1api.ConfigMap{})
			if tc.wantSnapshotDelete {
				assert.True(t, apierrors.IsNotFound(err), "expected the retained snapshot configmap to be removed, got %v", err)
			} else {
				require.NoError(t, err, "expected the retained snapshot configmap to be kept")
			}
		})
	}
}

func TestDeleteRetainedSnapshots(t *testing.T) {
	tests := []struct {
		name       string
		retained   *velerov2alpha1api.RetainedSnapshot
		otherCM    bool
		waitErr    error
		wantWaited int
		wantErr    string
		wantCMKept bool
	}{
		{
			name:       "retained snapshot is deleted",
			retained:   &velerov2alpha1api.RetainedSnapshot{SnapshotHandle: "snap-handle", Driver: "hostpath.csi.k8s.io"},
			wantWaited: 1,
		},
		{
			name:       "retained snapshot of another backup is not touched",
			retained:   &velerov2alpha1api.RetainedSnapshot{SnapshotHandle: "snap-handle", Driver: "hostpath.csi.k8s.io"},
			otherCM:    true,
			wantCMKept: true,
		},
		{
			name:       "invalid retained snapshot fails",
			retained:   &velerov2alpha1api.RetainedSnapshot{Driver: "hostpath.csi.k8s.io"},
			wantErr:    "invalid retained snapshot",
			wantCMKept: true,
		},
		{
			name:       "failure of the CSI driver fails",
			retained:   &velerov2alpha1api.RetainedSnapshot{SnapshotHandle: "snap-handle", Driver: "hostpath.csi.k8s.io"},
			waitErr:    errors.New("fake-snapshot-delete-error"),
			wantWaited: 1,
			wantErr:    "fake-snapshot-delete-error",
			wantCMKept: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			waited := stubTempVSCDeletion(t, tc.waitErr)

			owner := "foo"
			if tc.otherCM {
				owner = "bar"
			}
			cm := retainedSnapshotConfigMap(t, owner, "du-retained-snapshot", tc.retained)
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, cm)
			r := &backupDeletionReconciler{Client: fakeClient, logger: velerotest.NewLogger()}
			backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()

			errs := r.deleteRetainedSnapshots(t.Context(), backup, velerotest.NewLogger())
			if tc.wantErr != "" {
				require.Len(t, errs, 1)
				require.ErrorContains(t, errs[0], tc.wantErr)
			} else {
				assert.Empty(t, errs)
			}
			assert.Len(t, *waited, tc.wantWaited)

			err := fakeClient.Get(t.Context(), client.ObjectKeyFromObject(cm), &corev1api.ConfigMap{})
			if tc.wantCMKept {
				require.NoError(t, err, "expected the configmap to be kept")
			} else {
				assert.True(t, apierrors.IsNotFound(err), "expected the configmap to be removed, got %v", err)
			}
		})
	}
}

func TestSnapshotDeletionClientReadsFromAPIServer(t *testing.T) {
	// The CSI snapshotter records the events of a VolumeSnapshotContent in the
	// default namespace, which the manager's cache doesn't cover.
	event := &corev1api.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceDefault, Name: "vsc-event"},
		Reason:     "SnapshotDeleteError",
	}
	apiReader := velerotest.NewFakeControllerRuntimeClient(t, event)
	cachedClient := velerotest.NewFakeControllerRuntimeClient(t)

	r := &backupDeletionReconciler{Client: cachedClient, apiReader: apiReader}
	c := r.snapshotDeletionClient()

	events := &corev1api.EventList{}
	require.NoError(t, c.List(t.Context(), events, client.InNamespace(metav1.NamespaceDefault)))
	require.Len(t, events.Items, 1)
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(event), &corev1api.Event{}))

	// Writes still go through the client.
	vsc := &snapshotv1api.VolumeSnapshotContent{ObjectMeta: metav1.ObjectMeta{Name: "vsc-1"}}
	require.NoError(t, c.Create(t.Context(), vsc))
	require.NoError(t, cachedClient.Get(t.Context(), client.ObjectKeyFromObject(vsc), &snapshotv1api.VolumeSnapshotContent{}))

	// Without an API reader, e.g. in tests that don't set up the manager, the client is used.
	assert.Equal(t, cachedClient, (&backupDeletionReconciler{Client: cachedClient}).snapshotDeletionClient())
}

func unrecordedRetainedSnapshotConfigMap(name string, snapshotID string) *corev1api.ConfigMap {
	return &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1api.DefaultNamespace,
			Name:      name,
			Labels: map[string]string{
				velerov1api.BackupNameLabel:                 "foo",
				velerov1api.DataUploadRetainedSnapshotLabel: "true",
			},
		},
		Data: map[string]string{
			"snapshotHandle":        "",
			"driver":                "rbd.csi.ceph.com",
			"volumeNamespace":       "app",
			"backupStorageLocation": "default",
			"snapshotID":            snapshotID,
			"repositoryType":        "kopia",
		},
	}
}

func stubRepoSnapshotTags(t *testing.T, tags map[string]string, err error) *[]string {
	t.Helper()
	looked := []string{}
	original := getRepoSnapshotTagsFunc
	t.Cleanup(func() { getRepoSnapshotTagsFunc = original })
	getRepoSnapshotTagsFunc = func(_ context.Context, _ *repository.Ensurer, _ repomanager.Manager, _ *velerov1api.Backup, snapshot repotypes.SnapshotIdentifier) (map[string]string, error) {
		looked = append(looked, snapshot.SnapshotID)
		return tags, err
	}
	return &looked
}

func TestResolveUnrecordedRetainedSnapshots(t *testing.T) {
	tests := []struct {
		name       string
		cm         *corev1api.ConfigMap
		tags       map[string]string
		tagsErr    error
		wantLooked []string
		wantHandle string
		wantCMGone bool
		wantErr    string
	}{
		{
			name:       "the handle is read from the CBT change ID tag of the repository snapshot",
			cm:         unrecordedRetainedSnapshotConfigMap("du-1-retained-snapshot", "kopia-1"),
			tags:       map[string]string{uploader.CBTChangeIDTag: "snap-handle"},
			wantLooked: []string{"kopia-1"},
			wantHandle: "snap-handle",
		},
		{
			// An earlier attempt deleted the repository snapshot after the snapshot.
			name:       "repository snapshot already deleted",
			cm:         unrecordedRetainedSnapshotConfigMap("du-1-retained-snapshot", "kopia-1"),
			tagsErr:    udmrepo.SnapshotNotFound(errors.New("snapshot not found")),
			wantLooked: []string{"kopia-1"},
			wantCMGone: true,
		},
		{
			name:       "repository snapshot without the tag",
			cm:         unrecordedRetainedSnapshotConfigMap("du-1-retained-snapshot", "kopia-1"),
			tags:       map[string]string{},
			wantLooked: []string{"kopia-1"},
			wantCMGone: true,
		},
		{
			// The deletion fails before the repository snapshot is deleted, so a retry can still read it.
			name:       "error reading the repository snapshot",
			cm:         unrecordedRetainedSnapshotConfigMap("du-1-retained-snapshot", "kopia-1"),
			tagsErr:    errors.New("fake-repo-error"),
			wantLooked: []string{"kopia-1"},
			wantErr:    "fake-repo-error",
		},
		{
			name:       "configmap that already has the handle is left alone",
			cm:         retainedSnapshotConfigMap(t, "foo", "du-1-retained-snapshot", &velerov2alpha1api.RetainedSnapshot{SnapshotHandle: "recorded-handle", Driver: "rbd.csi.ceph.com"}),
			wantLooked: []string{},
			wantHandle: "recorded-handle",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			looked := stubRepoSnapshotTags(t, tc.tags, tc.tagsErr)
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, tc.cm)
			r := &backupDeletionReconciler{Client: fakeClient, logger: velerotest.NewLogger(), repoMgr: repomocks.NewManager(t)}
			backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result()

			errs := r.resolveUnrecordedRetainedSnapshots(t.Context(), backup, velerotest.NewLogger())
			if tc.wantErr != "" {
				require.Len(t, errs, 1)
				require.ErrorContains(t, errs[0], tc.wantErr)
			} else {
				assert.Empty(t, errs)
			}
			assert.Equal(t, tc.wantLooked, *looked)

			cm := &corev1api.ConfigMap{}
			err := fakeClient.Get(t.Context(), client.ObjectKeyFromObject(tc.cm), cm)
			if tc.wantCMGone {
				assert.True(t, apierrors.IsNotFound(err), "expected the configmap to be removed, got %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHandle, cm.Data["snapshotHandle"])
		})
	}
}

func TestBackupDeletionKeepsSnapshotDataWhenUnrecordedSnapshotCantBeRead(t *testing.T) {
	stubTempVSCDeletion(t, nil)
	stubRepoSnapshotTags(t, nil, errors.New("fake-repo-error"))
	originalBatchDelete := batchDeleteSnapshotFunc
	t.Cleanup(func() { batchDeleteSnapshotFunc = originalBatchDelete })
	batchDeleteCalled := false
	batchDeleteSnapshotFunc = func(context.Context, *repository.Ensurer, repomanager.Manager, map[string][]repotypes.SnapshotIdentifier, *velerov1api.Backup, logrus.FieldLogger) []error {
		batchDeleteCalled = true
		return nil
	}

	backup := builder.ForBackup(velerov1api.DefaultNamespace, "foo").StorageLocation("primary").SnapshotMoveData(true).Result()
	backup.UID = "uid"
	location := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "primary").Provider("objStoreProvider").Bucket("bucket").Phase(velerov1api.BackupStorageLocationPhaseAvailable).Result()
	dbr := defaultTestDbr()
	td := setupBackupDeletionControllerTest(t, dbr, backup, location, unrecordedRetainedSnapshotConfigMap("du-1-retained-snapshot", "kopia-1"))
	td.controller.repoMgr = repomocks.NewManager(t)

	pluginManager := &pluginmocks.Manager{}
	pluginManager.On("GetDeleteItemActions").Return([]velero.DeleteItemAction{}, nil)
	pluginManager.On("CleanupClients")
	td.controller.newPluginManager = func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager }
	td.backupStore.On("GetBackupVolumeSnapshots", dbr.Spec.BackupName).Return(nil, nil)

	_, err := td.controller.Reconcile(t.Context(), td.req)
	require.NoError(t, err)

	// Deleting the repository snapshot would lose the handle, so the snapshot data is kept for a retry.
	assert.False(t, batchDeleteCalled)
	td.backupStore.AssertNotCalled(t, "DeleteBackup", mock.Anything)
	res := &velerov1api.DeleteBackupRequest{}
	require.NoError(t, td.fakeClient.Get(t.Context(), td.req.NamespacedName, res))
	assert.Contains(t, strings.Join(res.Status.Errors, "\n"), "error reading retained volume snapshot from snapshot data")
}
