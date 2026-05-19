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

package persistence

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	providermocks "github.com/vmware-tanzu/velero/pkg/plugin/velero/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/encode"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

type objectBackupStoreTestHarness struct {
	// embedded to reduce verbosity when calling methods
	*objectBackupStore

	objectStore    *inMemoryObjectStore
	bucket, prefix string
}

func newObjectBackupStoreTestHarness(bucket, prefix string) *objectBackupStoreTestHarness {
	objectStore := newInMemoryObjectStore(bucket)

	return &objectBackupStoreTestHarness{
		objectBackupStore: &objectBackupStore{
			objectStore: objectStore,
			bucket:      bucket,
			layout:      NewObjectStoreLayout(prefix),
			logger:      velerotest.NewLogger(),
		},
		objectStore: objectStore,
		bucket:      bucket,
		prefix:      prefix,
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		storageData BucketData
		expectErr   bool
	}{
		{
			name:      "empty backup store with no prefix is valid",
			expectErr: false,
		},
		{
			name:      "empty backup store with a prefix is valid",
			prefix:    "bar",
			expectErr: false,
		},
		{
			name: "backup store with no prefix and only unsupported directories is invalid",
			storageData: map[string][]byte{
				"backup-1/velero-backup.json": {},
				"backup-2/velero-backup.json": {},
			},
			expectErr: true,
		},
		{
			name:   "backup store with a prefix and only unsupported directories is invalid",
			prefix: "backups",
			storageData: map[string][]byte{
				"backups/backup-1/velero-backup.json": {},
				"backups/backup-2/velero-backup.json": {},
			},
			expectErr: true,
		},
		{
			name: "backup store with no prefix and both supported and unsupported directories is invalid",
			storageData: map[string][]byte{
				"backups/backup-1/velero-backup.json": {},
				"backups/backup-2/velero-backup.json": {},
				"restores/restore-1/foo":              {},
				"unsupported-dir/foo":                 {},
			},
			expectErr: true,
		},
		{
			name:   "backup store with a prefix and both supported and unsupported directories is invalid",
			prefix: "cluster-1",
			storageData: map[string][]byte{
				"cluster-1/backups/backup-1/velero-backup.json": {},
				"cluster-1/backups/backup-2/velero-backup.json": {},
				"cluster-1/restores/restore-1/foo":              {},
				"cluster-1/unsupported-dir/foo":                 {},
			},
			expectErr: true,
		},
		{
			name: "backup store with no prefix and only supported directories is valid",
			storageData: map[string][]byte{
				"backups/backup-1/velero-backup.json": {},
				"backups/backup-2/velero-backup.json": {},
				"restores/restore-1/foo":              {},
			},
			expectErr: false,
		},
		{
			name:   "backup store with a prefix and only supported directories is valid",
			prefix: "cluster-1",
			storageData: map[string][]byte{
				"cluster-1/backups/backup-1/velero-backup.json": {},
				"cluster-1/backups/backup-2/velero-backup.json": {},
				"cluster-1/restores/restore-1/foo":              {},
			},
			expectErr: false,
		},
		{
			name: "backup store with plugins directory is valid",
			storageData: map[string][]byte{
				"plugins/vsphere/foo": {},
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := newObjectBackupStoreTestHarness("foo", tc.prefix)

			for key, obj := range tc.storageData {
				require.NoError(t, harness.objectStore.PutObject(harness.bucket, key, bytes.NewReader(obj)))
			}

			err := harness.IsValid()
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListBackups(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		storageData BucketData
		expectedRes []string
		expectedErr string
	}{
		{
			name: "normal case",
			storageData: map[string][]byte{
				"backups/backup-1/velero-backup.json": encodeToBytes(builder.ForBackup("", "backup-1").Result()),
				"backups/backup-2/velero-backup.json": encodeToBytes(builder.ForBackup("", "backup-2").Result()),
			},
			expectedRes: []string{"backup-1", "backup-2"},
		},
		{
			name:   "normal case with backup store prefix",
			prefix: "velero-backups/",
			storageData: map[string][]byte{
				"velero-backups/backups/backup-1/velero-backup.json": encodeToBytes(builder.ForBackup("", "backup-1").Result()),
				"velero-backups/backups/backup-2/velero-backup.json": encodeToBytes(builder.ForBackup("", "backup-2").Result()),
			},
			expectedRes: []string{"backup-1", "backup-2"},
		},
		{
			name: "backup directories without metadata file are excluded",
			storageData: map[string][]byte{
				"backups/backup-1/velero-backup.json": []byte("{}"),
				// backup-2 has only a log file, no metadata - simulates empty directory with suspended versioning
				"backups/backup-2/backup-2-logs.gz": []byte("log data"),
			},
			expectedRes: []string{"backup-1"},
		},
		{
			name: "all backup directories without metadata file returns empty list",
			storageData: map[string][]byte{
				// Both backups have only log files, no metadata
				"backups/backup-1/backup-1-logs.gz": []byte("log data"),
				"backups/backup-2/backup-2-logs.gz": []byte("log data"),
			},
			expectedRes: []string{},
		},
		{
			name:   "backup directories without metadata file are excluded with prefix",
			prefix: "velero-backups/",
			storageData: map[string][]byte{
				"velero-backups/backups/backup-1/velero-backup.json": []byte("{}"),
				// backup-2 has only a log file, no metadata
				"velero-backups/backups/backup-2/backup-2-logs.gz":   []byte("log data"),
				"velero-backups/backups/backup-3/velero-backup.json": []byte("{}"),
			},
			expectedRes: []string{"backup-1", "backup-3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := newObjectBackupStoreTestHarness("foo", tc.prefix)

			for key, obj := range tc.storageData {
				require.NoError(t, harness.objectStore.PutObject(harness.bucket, key, bytes.NewReader(obj)))
			}

			res, err := harness.ListBackups()

			velerotest.AssertErrorMatches(t, tc.expectedErr, err)

			sort.Strings(tc.expectedRes)
			sort.Strings(res)

			assert.Equal(t, tc.expectedRes, res)
		})
	}
}

func TestPutBackup(t *testing.T) {
	tests := []struct {
		name                 string
		prefix               string
		metadata             io.Reader
		contents             io.Reader
		log                  io.Reader
		podVolumeBackup      io.Reader
		snapshots            io.Reader
		backupItemOperations io.Reader
		resourceList         io.Reader
		backupVolumeInfo     io.Reader
		expectedErr          string
		expectedKeys         []string
	}{
		{
			name:                 "normal case",
			metadata:             newStringReadSeeker("metadata"),
			contents:             newStringReadSeeker("contents"),
			log:                  newStringReadSeeker("log"),
			podVolumeBackup:      newStringReadSeeker("podVolumeBackup"),
			snapshots:            newStringReadSeeker("snapshots"),
			backupItemOperations: newStringReadSeeker("backupItemOperations"),
			resourceList:         newStringReadSeeker("resourceList"),
			backupVolumeInfo:     newStringReadSeeker("backupVolumeInfo"),
			expectedErr:          "",
			expectedKeys: []string{
				"backups/backup-1/velero-backup.json",
				"backups/backup-1/backup-1.tar.gz",
				"backups/backup-1/backup-1-logs.gz",
				"backups/backup-1/backup-1-podvolumebackups.json.gz",
				"backups/backup-1/backup-1-volumesnapshots.json.gz",
				"backups/backup-1/backup-1-itemoperations.json.gz",
				"backups/backup-1/backup-1-resource-list.json.gz",
				"backups/backup-1/backup-1-volumeinfo.json.gz",
			},
		},
		{
			name:                 "normal case with backup store prefix",
			prefix:               "prefix-1/",
			metadata:             newStringReadSeeker("metadata"),
			contents:             newStringReadSeeker("contents"),
			log:                  newStringReadSeeker("log"),
			podVolumeBackup:      newStringReadSeeker("podVolumeBackup"),
			snapshots:            newStringReadSeeker("snapshots"),
			backupItemOperations: newStringReadSeeker("backupItemOperations"),
			resourceList:         newStringReadSeeker("resourceList"),
			backupVolumeInfo:     newStringReadSeeker("backupVolumeInfo"),
			expectedErr:          "",
			expectedKeys: []string{
				"prefix-1/backups/backup-1/velero-backup.json",
				"prefix-1/backups/backup-1/backup-1.tar.gz",
				"prefix-1/backups/backup-1/backup-1-logs.gz",
				"prefix-1/backups/backup-1/backup-1-podvolumebackups.json.gz",
				"prefix-1/backups/backup-1/backup-1-volumesnapshots.json.gz",
				"prefix-1/backups/backup-1/backup-1-itemoperations.json.gz",
				"prefix-1/backups/backup-1/backup-1-resource-list.json.gz",
				"prefix-1/backups/backup-1/backup-1-volumeinfo.json.gz",
			},
		},
		{
			name:                 "error on metadata upload does not upload data",
			metadata:             new(errorReader),
			contents:             newStringReadSeeker("contents"),
			log:                  newStringReadSeeker("log"),
			podVolumeBackup:      newStringReadSeeker("podVolumeBackup"),
			snapshots:            newStringReadSeeker("snapshots"),
			backupItemOperations: newStringReadSeeker("backupItemOperations"),
			resourceList:         newStringReadSeeker("resourceList"),
			backupVolumeInfo:     newStringReadSeeker("backupVolumeInfo"),
			expectedErr:          "error readers return errors",
			expectedKeys:         []string{"backups/backup-1/backup-1-logs.gz"},
		},
		{
			name:                 "error on data upload deletes metadata",
			metadata:             newStringReadSeeker("metadata"),
			contents:             new(errorReader),
			log:                  newStringReadSeeker("log"),
			snapshots:            newStringReadSeeker("snapshots"),
			backupItemOperations: newStringReadSeeker("backupItemOperations"),
			resourceList:         newStringReadSeeker("resourceList"),
			backupVolumeInfo:     newStringReadSeeker("backupVolumeInfo"),
			expectedErr:          "error readers return errors",
			expectedKeys:         []string{"backups/backup-1/backup-1-logs.gz"},
		},
		{
			name:                 "error on log upload is ok",
			metadata:             newStringReadSeeker("foo"),
			contents:             newStringReadSeeker("bar"),
			log:                  new(errorReader),
			podVolumeBackup:      newStringReadSeeker("podVolumeBackup"),
			snapshots:            newStringReadSeeker("snapshots"),
			backupItemOperations: newStringReadSeeker("backupItemOperations"),
			resourceList:         newStringReadSeeker("resourceList"),
			backupVolumeInfo:     newStringReadSeeker("backupVolumeInfo"),
			expectedErr:          "",
			expectedKeys: []string{
				"backups/backup-1/velero-backup.json",
				"backups/backup-1/backup-1.tar.gz",
				"backups/backup-1/backup-1-podvolumebackups.json.gz",
				"backups/backup-1/backup-1-volumesnapshots.json.gz",
				"backups/backup-1/backup-1-itemoperations.json.gz",
				"backups/backup-1/backup-1-resource-list.json.gz",
				"backups/backup-1/backup-1-volumeinfo.json.gz",
			},
		},
		{
			name:             "data should be uploaded even when metadata is nil",
			metadata:         nil,
			contents:         newStringReadSeeker("contents"),
			log:              newStringReadSeeker("log"),
			podVolumeBackup:  newStringReadSeeker("podVolumeBackup"),
			snapshots:        newStringReadSeeker("snapshots"),
			resourceList:     newStringReadSeeker("resourceList"),
			backupVolumeInfo: newStringReadSeeker("backupVolumeInfo"),
			expectedErr:      "",
			expectedKeys: []string{
				"backups/backup-1/backup-1.tar.gz",
				"backups/backup-1/backup-1-logs.gz",
				"backups/backup-1/backup-1-podvolumebackups.json.gz",
				"backups/backup-1/backup-1-volumesnapshots.json.gz",
				"backups/backup-1/backup-1-resource-list.json.gz",
				"backups/backup-1/backup-1-volumeinfo.json.gz",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := newObjectBackupStoreTestHarness("foo", tc.prefix)

			backupInfo := BackupInfo{
				Name:                 "backup-1",
				Metadata:             tc.metadata,
				Contents:             tc.contents,
				Log:                  tc.log,
				PodVolumeBackups:     tc.podVolumeBackup,
				VolumeSnapshots:      tc.snapshots,
				BackupItemOperations: tc.backupItemOperations,
				BackupResourceList:   tc.resourceList,
				BackupVolumeInfo:     tc.backupVolumeInfo,
			}
			err := harness.PutBackup(backupInfo)

			velerotest.AssertErrorMatches(t, tc.expectedErr, err)
			assert.Len(t, harness.objectStore.Data[harness.bucket], len(tc.expectedKeys))
			for _, key := range tc.expectedKeys {
				assert.Contains(t, harness.objectStore.Data[harness.bucket], key)
			}
		})
	}
}

func TestGetBackupMetadata(t *testing.T) {
	tests := []struct {
		name       string
		backupName string
		key        string
		obj        metav1.Object
		wantErr    error
	}{
		{
			name:       "metadata file returns correctly",
			backupName: "foo",
			key:        "backups/foo/velero-backup.json",
			obj:        builder.ForBackup(velerov1api.DefaultNamespace, "foo").Result(),
		},
		{
			name:       "no metadata file returns an error",
			backupName: "foo",
			wantErr:    errors.New("key not found"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := newObjectBackupStoreTestHarness("test-bucket", "")

			if tc.obj != nil {
				jsonBytes, err := json.Marshal(tc.obj)
				require.NoError(t, err)

				require.NoError(t, harness.objectStore.PutObject(harness.bucket, tc.key, bytes.NewReader(jsonBytes)))
			}

			res, err := harness.GetBackupMetadata(tc.backupName)
			if tc.wantErr != nil {
				assert.Equal(t, tc.wantErr, err)
			} else {
				require.NoError(t, err)

				assert.Equal(t, tc.obj.GetNamespace(), res.Namespace)
				assert.Equal(t, tc.obj.GetName(), res.Name)
			}
		})
	}
}

func TestGetBackupVolumeSnapshots(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// volumesnapshots file not found should not error
	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/velero-backup.json", newStringReadSeeker("foo"))
	res, err := harness.GetBackupVolumeSnapshots("test-backup")
	require.NoError(t, err)
	assert.Nil(t, res)

	// volumesnapshots file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-volumesnapshots.json.gz", newStringReadSeeker("foo"))
	_, err = harness.GetBackupVolumeSnapshots("test-backup")
	require.Error(t, err)

	// volumesnapshots file containing gzipped json data should return correctly
	snapshots := []*volume.Snapshot{
		{
			Spec: volume.SnapshotSpec{
				BackupName:           "test-backup",
				PersistentVolumeName: "pv-1",
			},
		},
		{
			Spec: volume.SnapshotSpec{
				BackupName:           "test-backup",
				PersistentVolumeName: "pv-2",
			},
		},
	}

	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(snapshots))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-volumesnapshots.json.gz", obj))

	res, err = harness.GetBackupVolumeSnapshots("test-backup")
	require.NoError(t, err)
	assert.Equal(t, snapshots, res)
}

func TestGetBackupItemOperations(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// itemoperations file not found should not error
	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/velero-backup.json", newStringReadSeeker("foo"))
	res, err := harness.GetBackupItemOperations("test-backup")
	require.NoError(t, err)
	assert.Nil(t, res)

	// itemoperations file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-itemoperations.json.gz", newStringReadSeeker("foo"))
	_, err = harness.GetBackupItemOperations("test-backup")
	require.Error(t, err)

	// itemoperations file containing gzipped json data should return correctly
	operations := []*itemoperation.BackupOperation{
		{
			Spec: itemoperation.BackupOperationSpec{
				BackupName: "test-backup",
				ResourceIdentifier: velero.ResourceIdentifier{
					GroupResource: kuberesource.Pods,
					Namespace:     "ns",
					Name:          "item-1",
				},
			},
		},
		{
			Spec: itemoperation.BackupOperationSpec{
				BackupName: "test-backup",
				ResourceIdentifier: velero.ResourceIdentifier{
					GroupResource: kuberesource.Pods,
					Namespace:     "ns",
					Name:          "item-2",
				},
			},
		},
	}

	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(operations))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-itemoperations.json.gz", obj))

	res, err = harness.GetBackupItemOperations("test-backup")
	require.NoError(t, err)
	assert.Equal(t, operations, res)
}

func TestGetRestoreItemOperations(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// itemoperations file not found should not error
	res, err := harness.GetRestoreItemOperations("test-restore")
	require.NoError(t, err)
	assert.Nil(t, res)

	// itemoperations file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "restores/test-restore/restore-test-restore-itemoperations.json.gz", newStringReadSeeker("foo"))
	_, err = harness.GetRestoreItemOperations("test-restore")
	require.Error(t, err)

	// itemoperations file containing gzipped json data should return correctly
	operations := []*itemoperation.RestoreOperation{
		{
			Spec: itemoperation.RestoreOperationSpec{
				RestoreName: "test-restore",
				ResourceIdentifier: velero.ResourceIdentifier{
					GroupResource: kuberesource.Pods,
					Namespace:     "ns",
					Name:          "item-1",
				},
			},
		},
		{
			Spec: itemoperation.RestoreOperationSpec{
				RestoreName: "test-restore",
				ResourceIdentifier: velero.ResourceIdentifier{
					GroupResource: kuberesource.Pods,
					Namespace:     "ns",
					Name:          "item-2",
				},
			},
		},
	}

	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(operations))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "restores/test-restore/restore-test-restore-itemoperations.json.gz", obj))

	res, err = harness.GetRestoreItemOperations("test-restore")
	require.NoError(t, err)
	assert.Equal(t, operations, res)
}

func TestGetBackupContents(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup.tar.gz", newStringReadSeeker("foo"))

	rc, err := harness.GetBackupContents("test-backup")
	require.NoError(t, err)
	require.NotNil(t, rc)

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "foo", string(data))
}

func TestDeleteBackup(t *testing.T) {
	tests := []struct {
		name             string
		prefix           string
		listObjectsError error
		deleteErrors     []error
		expectedErr      string
	}{
		{
			name: "normal case",
		},
		{
			name:   "normal case with backup store prefix",
			prefix: "velero-backups/",
		},
		{
			name:         "some delete errors, do as much as we can",
			deleteErrors: []error{errors.New("a"), nil, errors.New("c")},
			expectedErr:  "[a, c]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objectStore := new(providermocks.ObjectStore)
			backupStore := &objectBackupStore{
				objectStore: objectStore,
				bucket:      "test-bucket",
				layout:      NewObjectStoreLayout(test.prefix),
				logger:      velerotest.NewLogger(),
			}
			defer objectStore.AssertExpectations(t)

			objects := []string{test.prefix + "backups/bak/velero-backup.json", test.prefix + "backups/bak/bak.tar.gz", test.prefix + "backups/bak/bak.log.gz"}

			objectStore.On("ListObjects", backupStore.bucket, test.prefix+"backups/bak/").Return(objects, test.listObjectsError)
			for i, obj := range objects {
				var err error
				if i < len(test.deleteErrors) {
					err = test.deleteErrors[i]
				}

				objectStore.On("DeleteObject", backupStore.bucket, obj).Return(err)
			}

			err := backupStore.DeleteBackup("bak")

			velerotest.AssertErrorMatches(t, test.expectedErr, err)
		})
	}
}

func TestDeleteRestore(t *testing.T) {
	tests := []struct {
		name             string
		prefix           string
		listObjectsError error
		deleteErrors     []error
		expectedErr      string
	}{
		{
			name: "normal case",
		},
		{
			name:   "normal case with backup store prefix",
			prefix: "velero-backups/",
		},
		{
			name:         "some delete errors, do as much as we can",
			deleteErrors: []error{errors.New("a"), nil, errors.New("c")},
			expectedErr:  "[a, c]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objectStore := new(providermocks.ObjectStore)
			backupStore := &objectBackupStore{
				objectStore: objectStore,
				bucket:      "test-bucket",
				layout:      NewObjectStoreLayout(test.prefix),
				logger:      velerotest.NewLogger(),
			}
			defer objectStore.AssertExpectations(t)

			objects := []string{test.prefix + "restores/bak/velero-restore.json", test.prefix + "restores/bak/bak.tar.gz", test.prefix + "restores/bak/bak.log.gz"}

			objectStore.On("ListObjects", backupStore.bucket, test.prefix+"restores/bak/").Return(objects, test.listObjectsError)
			for i, obj := range objects {
				var err error
				if i < len(test.deleteErrors) {
					err = test.deleteErrors[i]
				}

				objectStore.On("DeleteObject", backupStore.bucket, obj).Return(err)
			}

			err := backupStore.DeleteRestore("bak")

			velerotest.AssertErrorMatches(t, test.expectedErr, err)
		})
	}
}

func TestGetDownloadURL(t *testing.T) {
	tests := []struct {
		name              string
		targetName        string
		expectedKeyByKind map[velerov1api.DownloadTargetKind]string
		prefix            string
	}{
		{
			name:       "backup",
			targetName: "my-backup",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindBackupContents:        "backups/my-backup/my-backup.tar.gz",
				velerov1api.DownloadTargetKindBackupLog:             "backups/my-backup/my-backup-logs.gz",
				velerov1api.DownloadTargetKindBackupVolumeSnapshots: "backups/my-backup/my-backup-volumesnapshots.json.gz",
				velerov1api.DownloadTargetKindBackupItemOperations:  "backups/my-backup/my-backup-itemoperations.json.gz",
				velerov1api.DownloadTargetKindBackupResourceList:    "backups/my-backup/my-backup-resource-list.json.gz",
			},
		},
		{
			name:       "backup with prefix",
			targetName: "my-backup",
			prefix:     "velero-backups/",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindBackupContents:        "velero-backups/backups/my-backup/my-backup.tar.gz",
				velerov1api.DownloadTargetKindBackupLog:             "velero-backups/backups/my-backup/my-backup-logs.gz",
				velerov1api.DownloadTargetKindBackupVolumeSnapshots: "velero-backups/backups/my-backup/my-backup-volumesnapshots.json.gz",
				velerov1api.DownloadTargetKindBackupItemOperations:  "velero-backups/backups/my-backup/my-backup-itemoperations.json.gz",
				velerov1api.DownloadTargetKindBackupResourceList:    "velero-backups/backups/my-backup/my-backup-resource-list.json.gz",
			},
		},
		{
			name:       "backup with multiple dashes",
			targetName: "b-cool-20170913154901-20170913154902",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindBackupContents:        "backups/b-cool-20170913154901-20170913154902/b-cool-20170913154901-20170913154902.tar.gz",
				velerov1api.DownloadTargetKindBackupLog:             "backups/b-cool-20170913154901-20170913154902/b-cool-20170913154901-20170913154902-logs.gz",
				velerov1api.DownloadTargetKindBackupVolumeSnapshots: "backups/b-cool-20170913154901-20170913154902/b-cool-20170913154901-20170913154902-volumesnapshots.json.gz",
				velerov1api.DownloadTargetKindBackupItemOperations:  "backups/b-cool-20170913154901-20170913154902/b-cool-20170913154901-20170913154902-itemoperations.json.gz",
				velerov1api.DownloadTargetKindBackupResourceList:    "backups/b-cool-20170913154901-20170913154902/b-cool-20170913154901-20170913154902-resource-list.json.gz",
			},
		},
		{
			name:       "scheduled backup",
			targetName: "my-backup-20170913154901",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindBackupContents:        "backups/my-backup-20170913154901/my-backup-20170913154901.tar.gz",
				velerov1api.DownloadTargetKindBackupLog:             "backups/my-backup-20170913154901/my-backup-20170913154901-logs.gz",
				velerov1api.DownloadTargetKindBackupVolumeSnapshots: "backups/my-backup-20170913154901/my-backup-20170913154901-volumesnapshots.json.gz",
				velerov1api.DownloadTargetKindBackupItemOperations:  "backups/my-backup-20170913154901/my-backup-20170913154901-itemoperations.json.gz",
				velerov1api.DownloadTargetKindBackupResourceList:    "backups/my-backup-20170913154901/my-backup-20170913154901-resource-list.json.gz",
			},
		},
		{
			name:       "scheduled backup with prefix",
			targetName: "my-backup-20170913154901",
			prefix:     "velero-backups/",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindBackupContents:        "velero-backups/backups/my-backup-20170913154901/my-backup-20170913154901.tar.gz",
				velerov1api.DownloadTargetKindBackupLog:             "velero-backups/backups/my-backup-20170913154901/my-backup-20170913154901-logs.gz",
				velerov1api.DownloadTargetKindBackupVolumeSnapshots: "velero-backups/backups/my-backup-20170913154901/my-backup-20170913154901-volumesnapshots.json.gz",
				velerov1api.DownloadTargetKindBackupItemOperations:  "velero-backups/backups/my-backup-20170913154901/my-backup-20170913154901-itemoperations.json.gz",
				velerov1api.DownloadTargetKindBackupResourceList:    "velero-backups/backups/my-backup-20170913154901/my-backup-20170913154901-resource-list.json.gz",
			},
		},
		{
			name:       "restore",
			targetName: "my-backup",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindRestoreLog:            "restores/my-backup/restore-my-backup-logs.gz",
				velerov1api.DownloadTargetKindRestoreResults:        "restores/my-backup/restore-my-backup-results.gz",
				velerov1api.DownloadTargetKindRestoreItemOperations: "restores/my-backup/restore-my-backup-itemoperations.json.gz",
				velerov1api.DownloadTargetKindRestoreResourceList:   "restores/my-backup/restore-my-backup-resource-list.json.gz",
			},
		},
		{
			name:       "restore with prefix",
			targetName: "my-backup",
			prefix:     "velero-backups/",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindRestoreLog:            "velero-backups/restores/my-backup/restore-my-backup-logs.gz",
				velerov1api.DownloadTargetKindRestoreResults:        "velero-backups/restores/my-backup/restore-my-backup-results.gz",
				velerov1api.DownloadTargetKindRestoreItemOperations: "velero-backups/restores/my-backup/restore-my-backup-itemoperations.json.gz",
				velerov1api.DownloadTargetKindRestoreResourceList:   "velero-backups/restores/my-backup/restore-my-backup-resource-list.json.gz",
			},
		},
		{
			name:       "restore with multiple dashes",
			targetName: "b-cool-20170913154901-20170913154902",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindRestoreLog:            "restores/b-cool-20170913154901-20170913154902/restore-b-cool-20170913154901-20170913154902-logs.gz",
				velerov1api.DownloadTargetKindRestoreResults:        "restores/b-cool-20170913154901-20170913154902/restore-b-cool-20170913154901-20170913154902-results.gz",
				velerov1api.DownloadTargetKindRestoreItemOperations: "restores/b-cool-20170913154901-20170913154902/restore-b-cool-20170913154901-20170913154902-itemoperations.json.gz",
				velerov1api.DownloadTargetKindRestoreResourceList:   "restores/b-cool-20170913154901-20170913154902/restore-b-cool-20170913154901-20170913154902-resource-list.json.gz",
			},
		},
		{
			name:       "",
			targetName: "my-backup",
			expectedKeyByKind: map[velerov1api.DownloadTargetKind]string{
				velerov1api.DownloadTargetKindBackupVolumeInfos: "backups/my-backup/my-backup-volumeinfo.json.gz",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newObjectBackupStoreTestHarness("test-bucket", test.prefix)

			for kind, expectedKey := range test.expectedKeyByKind {
				t.Run(string(kind), func(t *testing.T) {
					require.NoError(t, harness.objectStore.PutObject("test-bucket", expectedKey, newStringReadSeeker("foo")))

					url, err := harness.GetDownloadURL(velerov1api.DownloadTarget{Kind: kind, Name: test.targetName})
					require.NoError(t, err)
					assert.Equal(t, "a-url", url)
				})
			}
		})
	}
}

func TestGetCSIVolumeSnapshotClasses(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// file not found should not error
	res, err := harness.GetCSIVolumeSnapshotClasses("test-backup")
	require.NoError(t, err)
	assert.Nil(t, res)

	// file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-csi-volumesnapshotclasses.json.gz", newStringReadSeeker("foo"))
	_, err = harness.GetCSIVolumeSnapshotClasses("test-backup")
	require.Error(t, err)

	// file containing gzipped json data should return correctly
	classes := []*snapshotv1api.VolumeSnapshotClass{
		{
			Driver: "driver",
		},
	}

	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(classes))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-csi-volumesnapshotclasses.json.gz", obj))

	res, err = harness.GetCSIVolumeSnapshotClasses("test-backup")
	require.NoError(t, err)
	assert.Equal(t, classes, res)
}

func TestGetCSIVolumeSnapshots(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// file not found should not error
	res, err := harness.GetCSIVolumeSnapshots("test-backup")
	require.NoError(t, err)
	assert.Nil(t, res)

	// file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-csi-volumesnapshots.json.gz", newStringReadSeeker("foo"))
	_, err = harness.GetCSIVolumeSnapshots("test-backup")
	require.Error(t, err)

	// file containing gzipped json data should return correctly
	snapshots := []*snapshotv1api.VolumeSnapshot{
		{
			Spec: snapshotv1api.VolumeSnapshotSpec{
				Source: snapshotv1api.VolumeSnapshotSource{
					VolumeSnapshotContentName: nil,
				},
			},
		},
	}

	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(snapshots))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-csi-volumesnapshots.json.gz", obj))

	res, err = harness.GetCSIVolumeSnapshots("test-backup")
	require.NoError(t, err)
	assert.Equal(t, snapshots, res)
}

type objectStoreGetter map[string]velero.ObjectStore

func (osg objectStoreGetter) GetObjectStore(provider string) (velero.ObjectStore, error) {
	res, ok := osg[provider]
	if !ok {
		return nil, errors.New("object store not found")
	}

	return res, nil
}

// TestNewObjectBackupStore runs the NewObjectBackupStoreGetter constructor and ensures
// that it provides a BackupStore with a correctly constructed ObjectBackupStore or
// that an appropriate error is returned.
func TestNewObjectBackupStoreGetter(t *testing.T) {
	tests := []struct {
		name              string
		location          *velerov1api.BackupStorageLocation
		objectStoreGetter objectStoreGetter
		credFileStore     credentials.FileStore
		fileStoreErr      error
		wantBucket        string
		wantPrefix        string
		wantErr           string
	}{
		{
			name:          "when location does not use object storage, a backup store can't be retrieved",
			location:      new(velerov1api.BackupStorageLocation),
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantErr:       "backup storage location does not use object storage",
		},
		{
			name:          "when object storage does not specify a provider, a backup store can't be retrieved",
			location:      builder.ForBackupStorageLocation("", "").Bucket("").Result(),
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantErr:       "object storage provider name must not be empty",
		},
		{
			name:          "when the Bucket field has a '/' in the middle, a backup store can't be retrieved",
			location:      builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("invalid/bucket").Result(),
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantErr:       "backup storage location's bucket name \"invalid/bucket\" must not contain a '/' (if using a prefix, put it in the 'Prefix' field instead)",
		},
		{
			name: "when the credential selector is invalid, a backup store can't be retrieved",
			location: builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("bucket").Credential(
				builder.ForSecretKeySelector("does-not-exist", "does-not-exist").Result(),
			).Result(),
			credFileStore: velerotest.NewFakeCredentialsFileStore("", fmt.Errorf("secret does not exist")),
			wantErr:       "unable to get credentials: secret does not exist",
		},
		{
			name:     "when Bucket has a leading and trailing slash, they are both stripped",
			location: builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("/bucket/").Result(),
			objectStoreGetter: objectStoreGetter{
				"provider-1": newInMemoryObjectStore("bucket"),
			},
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantBucket:    "bucket",
		},
		{
			name:     "when Prefix has a leading and trailing slash, the leading slash is stripped and the trailing slash is left",
			location: builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("bucket").Prefix("/prefix/").Result(),
			objectStoreGetter: objectStoreGetter{
				"provider-1": newInMemoryObjectStore("bucket"),
			},
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantBucket:    "bucket",
			wantPrefix:    "prefix/",
		},
		{
			name:     "when Prefix has no leading or trailing slash, a trailing slash is added",
			location: builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("bucket").Prefix("prefix").Result(),
			objectStoreGetter: objectStoreGetter{
				"provider-1": newInMemoryObjectStore("bucket"),
			},
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantBucket:    "bucket",
			wantPrefix:    "prefix/",
		},
		{
			name:     "when the Bucket field is an MRAP ARN, it should be valid",
			location: builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("arn:aws:s3::123456789012:accesspoint/abcdef0123456.mrap").Result(),
			objectStoreGetter: objectStoreGetter{
				"provider-1": newInMemoryObjectStore("arn:aws:s3::123456789012:accesspoint/abcdef0123456.mrap"),
			},
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantBucket:    "arn:aws:s3::123456789012:accesspoint/abcdef0123456.mrap",
		},
		{
			name:     "when the Bucket field is an MRAP ARN with trailing slash, it should be valid and trimmed",
			location: builder.ForBackupStorageLocation("", "").Provider("provider-1").Bucket("arn:aws:s3::123456789012:accesspoint/abcdef0123456.mrap/").Result(),
			objectStoreGetter: objectStoreGetter{
				"provider-1": newInMemoryObjectStore("arn:aws:s3::123456789012:accesspoint/abcdef0123456.mrap"),
			},
			credFileStore: velerotest.NewFakeCredentialsFileStore("", nil),
			wantBucket:    "arn:aws:s3::123456789012:accesspoint/abcdef0123456.mrap",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getter := NewObjectBackupStoreGetter(tc.credFileStore)
			res, err := getter.Get(tc.location, tc.objectStoreGetter, velerotest.NewLogger())
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)

				store, ok := res.(*objectBackupStore)
				require.True(t, ok)

				assert.Equal(t, tc.wantBucket, store.bucket)
				assert.Equal(t, tc.wantPrefix, store.layout.rootPrefix)
			}
		})
	}
}

// TestNewObjectBackupStoreGetterConfig runs the NewObjectBackupStoreGetter constructor and ensures
// that it initializes the ObjectBackupStore with the correct config.
func TestNewObjectBackupStoreGetterConfig(t *testing.T) {
	provider := "provider"
	bucket := "bucket"

	tests := []struct {
		name           string
		location       *velerov1api.BackupStorageLocation
		getter         ObjectBackupStoreGetter
		credentialPath string
		wantConfig     map[string]string
	}{
		{
			name:     "location with bucket but no prefix has config initialized with bucket and empty prefix",
			location: builder.ForBackupStorageLocation("", "").Provider(provider).Bucket(bucket).Result(),
			getter:   NewObjectBackupStoreGetter(velerotest.NewFakeCredentialsFileStore("", nil)),
			wantConfig: map[string]string{
				"bucket": "bucket",
				"prefix": "",
			},
		},
		{
			name:     "location with bucket and prefix has config initialized with bucket and prefix",
			location: builder.ForBackupStorageLocation("", "").Provider(provider).Bucket(bucket).Prefix("prefix").Result(),
			getter:   NewObjectBackupStoreGetter(velerotest.NewFakeCredentialsFileStore("", nil)),
			wantConfig: map[string]string{
				"bucket": "bucket",
				"prefix": "prefix",
			},
		},
		{
			name:     "location with CACert is initialized with caCert",
			location: builder.ForBackupStorageLocation("", "").Provider(provider).Bucket(bucket).CACert([]byte("cacert-data")).Result(),
			getter:   NewObjectBackupStoreGetter(velerotest.NewFakeCredentialsFileStore("", nil)),
			wantConfig: map[string]string{
				"bucket": "bucket",
				"prefix": "",
				"caCert": "cacert-data",
			},
		},
		{
			name: "location with Credential is initialized with path of serialized secret",
			location: builder.ForBackupStorageLocation("", "").Provider(provider).Bucket(bucket).Credential(
				builder.ForSecretKeySelector("does-not-exist", "does-not-exist").Result(),
			).Result(),
			getter: NewObjectBackupStoreGetter(velerotest.NewFakeCredentialsFileStore("/tmp/credentials/secret-file", nil)),
			wantConfig: map[string]string{
				"bucket":          "bucket",
				"prefix":          "",
				"credentialsFile": "/tmp/credentials/secret-file",
			},
		},
		{
			name: "location with CACertRef is initialized with caCert from secret",
			location: builder.ForBackupStorageLocation("", "").Provider(provider).Bucket(bucket).CACertRef(
				builder.ForSecretKeySelector("cacert-secret", "ca.crt").Result(),
			).Result(),
			getter: NewObjectBackupStoreGetterWithSecretStore(
				velerotest.NewFakeCredentialsFileStore("", nil),
				velerotest.NewFakeCredentialsSecretStore("cacert-from-secret", nil),
			),
			wantConfig: map[string]string{
				"bucket": "bucket",
				"prefix": "",
				"caCert": "cacert-from-secret",
			},
		},
		{
			name: "location with CACertRef and no SecretStore uses no caCert",
			location: builder.ForBackupStorageLocation("", "").Provider(provider).Bucket(bucket).CACertRef(
				builder.ForSecretKeySelector("cacert-secret", "ca.crt").Result(),
			).Result(),
			getter: NewObjectBackupStoreGetter(velerotest.NewFakeCredentialsFileStore("", nil)),
			wantConfig: map[string]string{
				"bucket": "bucket",
				"prefix": "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objStore := newInMemoryObjectStore(bucket)
			objStoreGetter := &objectStoreGetter{provider: objStore}

			_, err := tc.getter.Get(tc.location, objStoreGetter, velerotest.NewLogger())
			require.NoError(t, err)
			require.Equal(t, tc.wantConfig, objStore.Config)
		})
	}
}

func TestGetBackupVolumeInfos(t *testing.T) {
	tests := []struct {
		name           string
		volumeInfo     []*volume.BackupVolumeInfo
		volumeInfoStr  string
		expectedErr    string
		expectedResult []*volume.BackupVolumeInfo
	}{
		{
			name: "No VolumeInfos, expect no error.",
		},
		{
			name: "Valid BackupVolumeInfo, should pass.",
			volumeInfo: []*volume.BackupVolumeInfo{
				{
					PVCName:           "pvcName",
					PVName:            "pvName",
					Skipped:           true,
					SnapshotDataMoved: false,
				},
			},
			expectedResult: []*volume.BackupVolumeInfo{
				{
					PVCName:           "pvcName",
					PVName:            "pvName",
					Skipped:           true,
					SnapshotDataMoved: false,
				},
			},
		},
		{
			name:          "Invalid BackupVolumeInfo string, should also pass.",
			volumeInfoStr: `[{"abc": "123", "def": "456", "pvcName": "pvcName"}]`,
			expectedResult: []*volume.BackupVolumeInfo{
				{
					PVCName: "pvcName",
				},
			},
		},
	}

	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.volumeInfo != nil {
				obj := new(bytes.Buffer)
				gzw := gzip.NewWriter(obj)

				require.NoError(t, json.NewEncoder(gzw).Encode(tc.volumeInfo))
				require.NoError(t, gzw.Close())
				harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-volumeinfo.json.gz", obj)
			}

			if tc.volumeInfoStr != "" {
				obj := new(bytes.Buffer)
				gzw := gzip.NewWriter(obj)
				_, err := gzw.Write([]byte(tc.volumeInfoStr))
				require.NoError(t, err)

				require.NoError(t, gzw.Close())
				harness.objectStore.PutObject(harness.bucket, "backups/test-backup/test-backup-volumeinfo.json.gz", obj)
			}

			result, err := harness.GetBackupVolumeInfos("test-backup")
			if tc.expectedErr != "" {
				require.Equal(t, tc.expectedErr, err.Error())
			} else {
				if err != nil {
					fmt.Println(err.Error())
				}
				require.NoError(t, err)
			}

			if len(tc.expectedResult) > 0 {
				require.Equal(t, tc.expectedResult, result)
			}
		})
	}
}
func TestGetRestoreResults(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// file not found should not error
	_, err := harness.GetRestoreResults("test-restore")
	require.NoError(t, err)

	// file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "restores/test-restore/restore-test-restore-results.gz", newStringReadSeeker("foo"))
	_, err = harness.GetRestoreResults("test-restore")
	require.Error(t, err)

	// file containing gzipped json data should return correctly
	contents := map[string]results.Result{
		"warnings": {Cluster: []string{"cluster warning"}},
		"errors":   {Namespaces: map[string][]string{"test-ns": {"namespace error"}}},
	}
	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(contents))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "restores/test-restore/restore-test-restore-results.gz", obj))
	res, err := harness.GetRestoreResults("test-restore")

	require.NoError(t, err)
	assert.Equal(t, contents["warnings"], res["warnings"])
	assert.Equal(t, contents["errors"], res["errors"])
}

func TestGetRestoredResourceList(t *testing.T) {
	harness := newObjectBackupStoreTestHarness("test-bucket", "")

	// file not found should not error
	_, err := harness.GetRestoredResourceList("test-restore")
	require.NoError(t, err)

	// file containing invalid data should error
	harness.objectStore.PutObject(harness.bucket, "restores/test-restore/restore-test-restore-resource-list.json.gz", newStringReadSeeker("foo"))
	_, err = harness.GetRestoredResourceList("test-restore")
	require.Error(t, err)

	// file containing gzipped json data should return correctly
	list := map[string][]string{
		"pod": {"test-ns/pod1(created)", "test-ns/pod2(skipped)"},
	}
	obj := new(bytes.Buffer)
	gzw := gzip.NewWriter(obj)

	require.NoError(t, json.NewEncoder(gzw).Encode(list))
	require.NoError(t, gzw.Close())
	require.NoError(t, harness.objectStore.PutObject(harness.bucket, "restores/test-restore/restore-test-restore-resource-list.json.gz", obj))
	res, err := harness.GetRestoredResourceList("test-restore")

	require.NoError(t, err)
	assert.Equal(t, list["pod"], res["pod"])
}

func TestPutBackupVolumeInfos(t *testing.T) {
	tests := []struct {
		name         string
		prefix       string
		expectedErr  string
		expectedKeys []string
	}{
		{
			name:        "normal case",
			expectedErr: "",
			expectedKeys: []string{
				"backups/backup-1/backup-1-volumeinfo.json.gz",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := newObjectBackupStoreTestHarness("foo", tc.prefix)

			volumeInfos := []*volume.BackupVolumeInfo{
				{
					PVCName: "test",
				},
			}

			buf := new(bytes.Buffer)
			gzw := gzip.NewWriter(buf)
			defer gzw.Close()

			require.NoError(t, json.NewEncoder(gzw).Encode(volumeInfos))
			bufferContent := buf.Bytes()

			err := harness.PutBackupVolumeInfos("backup-1", buf)

			velerotest.AssertErrorMatches(t, tc.expectedErr, err)
			assert.Len(t, harness.objectStore.Data[harness.bucket], len(tc.expectedKeys))
			for _, key := range tc.expectedKeys {
				assert.Contains(t, harness.objectStore.Data[harness.bucket], key)
				assert.Equal(t, harness.objectStore.Data[harness.bucket][key], bufferContent)
			}
		})
	}
}

func encodeToBytes(obj runtime.Object) []byte {
	res, err := encode.Encode(obj, "json")
	if err != nil {
		panic(err)
	}
	return res
}

type stringReadSeeker struct {
	*strings.Reader
}

func newStringReadSeeker(s string) *stringReadSeeker {
	return &stringReadSeeker{
		Reader: strings.NewReader(s),
	}
}

func (srs *stringReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

type errorReader struct{}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, errors.New("error readers return errors")
}
