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

package kopialib

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/maintenance"
	"github.com/kopia/kopia/repo/manifest"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend"
	repomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend/mocks"
	storagemocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend/mocks"

	"github.com/cockroachdb/errors"
)

type comparableError struct {
	message string
}

func (ce *comparableError) Error() string {
	return ce.message
}

func (ce *comparableError) Is(err error) bool {
	return err.Error() == ce.message
}

func TestCreateBackupRepo(t *testing.T) {
	testCases := []struct {
		name         string
		backendStore *storagemocks.Store
		repoOptions  udmrepo.RepoOptions
		connectErr   error
		setupError   error
		returnStore  *storagemocks.Storage
		storeListErr error
		getBlobErr   error
		listBlobErr  error
		expectedErr  string
	}{
		{
			name: "storage setup fail, invalid type",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
			},
			expectedErr: "error to setup backend storage: error to find storage type",
		},
		{
			name: "storage setup fail, backend store steup fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			setupError:   errors.New("fake-setup-error"),
			expectedErr:  "error to setup backend storage: error to setup storage: fake-setup-error",
		},
		{
			name: "storage connect fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			connectErr:   errors.New("fake-connect-error"),
			expectedErr:  "error to connect to storage: fake-connect-error",
		},
		{
			name: "create repository error, exist blobs",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			listBlobErr: &comparableError{
				message: "has data",
			},
			expectedErr: "error to create repo with storage: error to ensure repository storage empty: found existing data in storage location",
		},
		{
			name: "create repository error, error list blobs",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			listBlobErr:  errors.New("fake-list-blob-error"),
			expectedErr:  "error to create repo with storage: error to ensure repository storage empty: error to list blobs: fake-list-blob-error",
		},
		{
			name: "create repository error, initialize error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			getBlobErr:   errors.New("fake-list-blob-error-01"),
			expectedErr:  "error to create repo with storage: error to initialize repository: unexpected error when checking for format blob: fake-list-blob-error-01",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := velerotest.NewLogger()
			backendStores = []kopiaBackendStore{
				{udmrepo.StorageTypeAzure, "fake store", tc.backendStore},
				{udmrepo.StorageTypeFs, "fake store", tc.backendStore},
				{udmrepo.StorageTypeGcs, "fake store", tc.backendStore},
				{udmrepo.StorageTypeS3, "fake store", tc.backendStore},
			}

			if tc.backendStore != nil {
				tc.backendStore.On("Connect", mock.Anything, mock.Anything, mock.Anything).Return(tc.returnStore, tc.connectErr)
				tc.backendStore.On("Setup", mock.Anything, mock.Anything, mock.Anything).Return(tc.setupError)
			}

			if tc.returnStore != nil {
				tc.returnStore.On("ListBlobs", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.listBlobErr)
				tc.returnStore.On("GetBlob", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.getBlobErr)
			}

			err := CreateBackupRepo(t.Context(), tc.repoOptions, logger)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestConnectBackupRepo(t *testing.T) {
	testCases := []struct {
		name         string
		backendStore *storagemocks.Store
		repoOptions  udmrepo.RepoOptions
		connectErr   error
		setupError   error
		returnStore  *storagemocks.Storage
		getBlobErr   error
		expectedErr  string
	}{
		{
			name:        "invalid config file",
			expectedErr: "invalid config file path",
		},
		{
			name: "storage setup fail, invalid type",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
			},
			expectedErr: "error to setup backend storage: error to find storage type",
		},
		{
			name: "storage setup fail, backend store steup fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			setupError:   errors.New("fake-setup-error"),
			expectedErr:  "error to setup backend storage: error to setup storage: fake-setup-error",
		},
		{
			name: "storage connect fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			connectErr:   errors.New("fake-connect-error"),
			expectedErr:  "error to connect to storage: fake-connect-error",
		},
		{
			name: "connect repository error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			getBlobErr:   errors.New("fake-get-blob-error"),
			expectedErr:  "error to connect repo with storage: error to connect to repository: unable to read format blob: fake-get-blob-error",
		},
	}

	logger := velerotest.NewLogger()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backendStores = []kopiaBackendStore{
				{udmrepo.StorageTypeAzure, "fake store", tc.backendStore},
				{udmrepo.StorageTypeFs, "fake store", tc.backendStore},
				{udmrepo.StorageTypeGcs, "fake store", tc.backendStore},
				{udmrepo.StorageTypeS3, "fake store", tc.backendStore},
			}

			if tc.backendStore != nil {
				tc.backendStore.On("Connect", mock.Anything, mock.Anything, mock.Anything).Return(tc.returnStore, tc.connectErr)
				tc.backendStore.On("Setup", mock.Anything, mock.Anything, mock.Anything).Return(tc.setupError)
			}

			if tc.returnStore != nil {
				tc.returnStore.On("GetBlob", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.getBlobErr)
			}

			err := ConnectBackupRepo(t.Context(), tc.repoOptions, logger)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestGetRepositoryStatus(t *testing.T) {
	testCases := []struct {
		name           string
		backendStore   *storagemocks.Store
		repoOptions    udmrepo.RepoOptions
		connectErr     error
		setupError     error
		returnStore    *storagemocks.Storage
		retFuncGetBlob func(context.Context, blob.ID, int64, int64, blob.OutputBuffer) error
		expected       RepoStatus
		expectedErr    string
	}{
		{
			name: "storage setup fail, invalid type",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
			},
			expected:    RepoStatusUnknown,
			expectedErr: "error to setup backend storage: error to find storage type",
		},
		{
			name: "storage setup fail, backend store steup fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			setupError:   errors.New("fake-setup-error"),
			expected:     RepoStatusUnknown,
			expectedErr:  "error to setup backend storage: error to setup storage: fake-setup-error",
		},
		{
			name: "storage connect fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			connectErr:   errors.New("fake-connect-error"),
			expected:     RepoStatusUnknown,
			expectedErr:  "error to connect to storage: fake-connect-error",
		},
		{
			name: "storage not exist",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			connectErr:   backend.ErrStoreNotExist,
			expected:     RepoStatusSystemNotCreated,
		},
		{
			name: "get repo blob error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(context.Context, blob.ID, int64, int64, blob.OutputBuffer) error {
				return errors.New("fake-get-blob-error")
			},
			expected:    RepoStatusUnknown,
			expectedErr: "error reading format blob: fake-get-blob-error",
		},
		{
			name: "no repo blob",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(context.Context, blob.ID, int64, int64, blob.OutputBuffer) error {
				return blob.ErrBlobNotFound
			},
			expected: RepoStatusSystemNotCreated,
		},
		{
			name: "wrong repo format",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(ctx context.Context, id blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				output.Write([]byte("fake-buffer"))
				return nil
			},
			expected:    RepoStatusCorrupted,
			expectedErr: "invalid format blob: invalid character 'k' in literal false (expecting 'l')",
		},
		{
			name: "get udm repo blob error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				if blobID == udmRepoBlobID {
					return errors.New("fake-get-blob-error")
				} else {
					output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[],"keyAlgo":"","encryption":""}`))
					return nil
				}
			},
			expected:    RepoStatusUnknown,
			expectedErr: "error reading udm repo blob: fake-get-blob-error",
		},
		{
			name: "no udm repo blob",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				if blobID == udmRepoBlobID {
					return blob.ErrBlobNotFound
				} else {
					output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[],"keyAlgo":"","encryption":""}`))
					return nil
				}
			},
			expected: RepoStatusNotInitialized,
		},
		{
			name: "wrong udm repo metadata",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				if blobID == udmRepoBlobID {
					output.Write([]byte("fake-buffer"))
				} else {
					output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[],"keyAlgo":"","encryption":""}`))
				}

				return nil
			},
			expected:    RepoStatusCorrupted,
			expectedErr: "invalid udm repo blob: invalid character 'k' in literal false (expecting 'l')",
		},
		{
			name: "wrong unique id",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				if blobID == udmRepoBlobID {
					output.Write([]byte(`{"uniqueID":[4,5,6]}`))
				} else {
					output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[1,2,3],"keyAlgo":"","encryption":""}`))
				}

				return nil
			},
			expected:    RepoStatusCorrupted,
			expectedErr: "unique ID doesn't match: [4 5 6]([1 2 3])",
		},
		{
			name: "succeed",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
				StorageType:    udmrepo.StorageTypeAzure,
			},
			backendStore: new(storagemocks.Store),
			returnStore:  new(storagemocks.Storage),
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				if blobID == udmRepoBlobID {
					output.Write([]byte(`{"uniqueID":[1,2,3]}`))
				} else {
					output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[1,2,3],"keyAlgo":"","encryption":""}`))
				}

				return nil
			},
			expected: RepoStatusCreated,
		},
	}

	logger := velerotest.NewLogger()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backendStores = []kopiaBackendStore{
				{udmrepo.StorageTypeAzure, "fake store", tc.backendStore},
				{udmrepo.StorageTypeFs, "fake store", tc.backendStore},
				{udmrepo.StorageTypeGcs, "fake store", tc.backendStore},
				{udmrepo.StorageTypeS3, "fake store", tc.backendStore},
			}

			if tc.backendStore != nil {
				tc.backendStore.On("Connect", mock.Anything, mock.Anything, mock.Anything).Return(tc.returnStore, tc.connectErr)
				tc.backendStore.On("Setup", mock.Anything, mock.Anything, mock.Anything).Return(tc.setupError)
			}

			if tc.returnStore != nil {
				tc.returnStore.On("GetBlob", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.retFuncGetBlob)
			}

			status, err := GetRepositoryStatus(t.Context(), tc.repoOptions, logger)

			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
			}

			assert.Equal(t, tc.expected, status)
		})
	}
}

func TestWriteInitParameters(t *testing.T) {
	var directRpo *repomocks.MockRepository
	assertFullMaintIntervalEqual := func(expected, actual *maintenance.Params) bool {
		return assert.Equal(t, expected.FullCycle.Interval, actual.FullCycle.Interval)
	}
	testCases := []struct {
		name                 string
		repoOptions          udmrepo.RepoOptions
		returnRepo           *repomocks.MockRepository
		returnRepoWriter     *repomocks.MockRepositoryWriter
		repoOpen             func(context.Context, string, string, *repo.Options) (repo.Repository, error)
		newRepoWriterError   error
		replaceManifestError error
		getParam             func(context.Context, repo.Repository) (*maintenance.Params, error)
		// expected replacemanifest params to be received by maintenance.SetParams, and therefore writeInitParameters
		expectedReplaceManifestsParams *maintenance.Params
		// allows for asserting only certain fields are set as expected
		assertReplaceManifestsParams func(*maintenance.Params, *maintenance.Params) bool
		mockNewWriter                bool
		mockClientOptions            bool
		expectedErr                  string
	}{
		{
			name: "repo open fail, repo not exist",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return nil, os.ErrNotExist
			},
			expectedErr: "error to open repo, repo doesn't exist: file does not exist",
		},
		{
			name: "repo open fail, other error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return nil, errors.New("fake-repo-open-error")
			},
			expectedErr: "error to open repo: fake-repo-open-error",
		},
		{
			name: "get params error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			getParam: func(context.Context, repo.Repository) (*maintenance.Params, error) {
				return nil, errors.New("fake-get-param-error")
			},
			returnRepo:  repomocks.NewMockRepository(t),
			expectedErr: "error getting existing maintenance params: fake-get-param-error",
		},
		{
			name: "existing param with identical owner",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			getParam: func(context.Context, repo.Repository) (*maintenance.Params, error) {
				return &maintenance.Params{
					Owner: "default@default",
				}, nil
			},
			returnRepo: repomocks.NewMockRepository(t),
		},
		{
			name: "existing param with different owner",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			getParam: func(context.Context, repo.Repository) (*maintenance.Params, error) {
				return &maintenance.Params{
					Owner: "fake-owner",
				}, nil
			},
			returnRepo:       repomocks.NewMockRepository(t),
			returnRepoWriter: repomocks.NewMockRepositoryWriter(t),
			expectedReplaceManifestsParams: &maintenance.Params{
				FullCycle: maintenance.CycleParams{
					Interval: udmrepo.NormalGCInterval,
				},
			},
			mockNewWriter:                true,
			mockClientOptions:            true,
			assertReplaceManifestsParams: assertFullMaintIntervalEqual,
		},
		{
			name: "write session fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo:         repomocks.NewMockRepository(t),
			mockNewWriter:      true,
			newRepoWriterError: errors.New("fake-new-writer-error"),
			expectedErr:        "error to init write repo parameters: unable to create writer: fake-new-writer-error",
		},
		{
			name: "set repo param fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo:           repomocks.NewMockRepository(t),
			returnRepoWriter:     repomocks.NewMockRepositoryWriter(t),
			mockNewWriter:        true,
			mockClientOptions:    true,
			replaceManifestError: errors.New("fake-replace-manifest-error"),
			expectedErr:          "error to init write repo parameters: error to set maintenance params: put manifest: fake-replace-manifest-error",
		},
		{
			name: "repo with maintenance interval has expected params",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				StorageOptions: map[string]string{
					udmrepo.StoreOptionKeyFullMaintenanceInterval: string(udmrepo.FastGC),
				},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo:        repomocks.NewMockRepository(t),
			returnRepoWriter:  repomocks.NewMockRepositoryWriter(t),
			mockNewWriter:     true,
			mockClientOptions: true,
			expectedReplaceManifestsParams: &maintenance.Params{
				FullCycle: maintenance.CycleParams{
					Interval: udmrepo.FastGCInterval,
				},
			},
			assertReplaceManifestsParams: assertFullMaintIntervalEqual,
		},
		{
			name: "repo with empty maintenance interval has expected params",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				StorageOptions: map[string]string{
					udmrepo.StoreOptionKeyFullMaintenanceInterval: string(""),
				},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo:        repomocks.NewMockRepository(t),
			returnRepoWriter:  repomocks.NewMockRepositoryWriter(t),
			mockNewWriter:     true,
			mockClientOptions: true,
			expectedReplaceManifestsParams: &maintenance.Params{
				FullCycle: maintenance.CycleParams{
					Interval: udmrepo.NormalGCInterval,
				},
			},
			assertReplaceManifestsParams: assertFullMaintIntervalEqual,
		},
		{
			name: "repo with invalid maintenance interval has expected errors",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				StorageOptions: map[string]string{
					udmrepo.StoreOptionKeyFullMaintenanceInterval: string("foo"),
				},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo:       repomocks.NewMockRepository(t),
			returnRepoWriter: repomocks.NewMockRepositoryWriter(t),
			mockNewWriter:    true,
			expectedErr:      "error to init write repo parameters: invalid full maintenance interval option foo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := velerotest.NewLogger()
			ctx := t.Context()

			if tc.repoOpen != nil {
				kopiaRepoOpen = tc.repoOpen
			}

			if tc.returnRepo != nil {
				directRpo = tc.returnRepo
			}

			if tc.returnRepo != nil {
				if tc.mockNewWriter {
					tc.returnRepo.On("NewWriter", mock.Anything, mock.Anything).Return(ctx, tc.returnRepoWriter, tc.newRepoWriterError)
				}

				if tc.mockClientOptions {
					tc.returnRepo.On("ClientOptions").Return(repo.ClientOptions{})
				}

				tc.returnRepo.On("Close", mock.Anything).Return(nil)
			}

			if tc.returnRepoWriter != nil {
				tc.returnRepoWriter.On("Close", mock.Anything).Return(nil)
				if tc.replaceManifestError != nil {
					tc.returnRepoWriter.On("ReplaceManifests", mock.Anything, mock.Anything, mock.Anything).Return(manifest.ID(""), tc.replaceManifestError)
				}
				if tc.expectedReplaceManifestsParams != nil {
					tc.returnRepoWriter.On("ReplaceManifests", mock.Anything, mock.AnythingOfType("map[string]string"), mock.AnythingOfType("*maintenance.Params")).Return(manifest.ID(""), nil)
					tc.returnRepoWriter.On("Flush", mock.Anything).Return(nil)
				}
			}

			if tc.getParam != nil {
				funcGetParam = tc.getParam
			} else {
				funcGetParam = func(ctx context.Context, rep repo.Repository) (*maintenance.Params, error) {
					return &maintenance.Params{}, nil
				}
			}

			err := writeInitParameters(ctx, tc.repoOptions, logger)

			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
			}
			if tc.expectedReplaceManifestsParams != nil {
				actualReplaceManifestsParams, converted := tc.returnRepoWriter.Calls[0].Arguments.Get(2).(*maintenance.Params)
				assert.True(t, converted)
				tc.assertReplaceManifestsParams(tc.expectedReplaceManifestsParams, actualReplaceManifestsParams)
			}
		})
	}
}

func TestWriteUdmRepoMetadata(t *testing.T) {
	testCases := []struct {
		name            string
		retFuncGetBlob  func(context.Context, blob.ID, int64, int64, blob.OutputBuffer) error
		retFuncPutBlob  func(context.Context, blob.ID, blob.Bytes, blob.PutOptions) error
		replaceMetadata *udmRepoMetadata
		expectedErr     string
	}{
		{
			name: "get repo blob error",
			retFuncGetBlob: func(context.Context, blob.ID, int64, int64, blob.OutputBuffer) error {
				return errors.New("fake-get-blob-error")
			},
			expectedErr: "error reading format blob: fake-get-blob-error",
		},
		{
			name: "wrong repo format",
			retFuncGetBlob: func(ctx context.Context, id blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				output.Write([]byte("fake-buffer"))
				return nil
			},
			expectedErr: "invalid format blob: invalid character 'k' in literal false (expecting 'l')",
		},
		{
			name: "put udm repo metadata blob error",
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[],"keyAlgo":"","encryption":""}`))
				return nil
			},
			retFuncPutBlob: func(context.Context, blob.ID, blob.Bytes, blob.PutOptions) error {
				return errors.New("fake-put-blob-error")
			},
			expectedErr: "error writing udm repo metadata: fake-put-blob-error",
		},
		{
			name: "succeed",
			retFuncGetBlob: func(ctx context.Context, blobID blob.ID, offset int64, length int64, output blob.OutputBuffer) error {
				output.Write([]byte(`{"tool":"","buildVersion":"","buildInfo":"","uniqueID":[],"keyAlgo":"","encryption":""}`))
				return nil
			},
			retFuncPutBlob: func(context.Context, blob.ID, blob.Bytes, blob.PutOptions) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := new(storagemocks.Storage)
			if tc.retFuncGetBlob != nil {
				storage.On("GetBlob", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.retFuncGetBlob)
			}

			if tc.retFuncPutBlob != nil {
				storage.On("PutBlob", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.retFuncPutBlob)
			}

			err := writeUdmRepoMetadata(t.Context(), storage)

			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

type testRecv struct {
	buffer []byte
}

func (r *testRecv) Write(p []byte) (n int, err error) {
	r.buffer = append(r.buffer, p...)
	return len(p), nil
}

func TestByteBuffer(t *testing.T) {
	buffer := &byteBuffer{}
	written, err := buffer.Write([]byte("12345"))
	require.NoError(t, err)
	require.Equal(t, 5, written)

	written, err = buffer.Write([]byte("67890"))
	require.NoError(t, err)
	require.Equal(t, 5, written)
	require.Equal(t, 10, buffer.Length())

	recv := &testRecv{}
	copied, err := buffer.WriteTo(recv)
	require.NoError(t, err)
	require.Equal(t, int64(10), copied)
	require.Equal(t, []byte("1234567890"), recv.buffer)

	buffer.Reset()
	require.Zero(t, buffer.Length())
}

func TestByteBufferReader(t *testing.T) {
	buffer := &byteBufferReader{buffer: []byte("123456789012345678901234567890")}
	off, err := buffer.Seek(100, io.SeekStart)
	require.Equal(t, int64(-1), off)
	require.EqualError(t, err, "invalid seek")
	require.Zero(t, buffer.pos)

	off, err = buffer.Seek(-100, io.SeekEnd)
	require.Equal(t, int64(-1), off)
	require.EqualError(t, err, "invalid seek")
	require.Zero(t, buffer.pos)

	off, err = buffer.Seek(3, io.SeekCurrent)
	require.Equal(t, int64(3), off)
	require.NoError(t, err)
	require.Equal(t, 3, buffer.pos)

	output := make([]byte, 6)
	read, err := buffer.Read(output)
	require.NoError(t, err)
	require.Equal(t, 6, read)
	require.Equal(t, 9, buffer.pos)
	require.Equal(t, []byte("456789"), output)

	off, err = buffer.Seek(21, io.SeekStart)
	require.Equal(t, int64(21), off)
	require.NoError(t, err)
	require.Equal(t, 21, buffer.pos)

	output = make([]byte, 6)
	read, err = buffer.Read(output)
	require.NoError(t, err)
	require.Equal(t, 6, read)
	require.Equal(t, 27, buffer.pos)
	require.Equal(t, []byte("234567"), output)

	output = make([]byte, 6)
	read, err = buffer.Read(output)
	require.NoError(t, err)
	require.Equal(t, 3, read)
	require.Equal(t, 30, buffer.pos)
	require.Equal(t, []byte{'8', '9', '0', 0, 0, 0}, output)

	output = make([]byte, 6)
	read, err = buffer.Read(output)
	require.Zero(t, read)
	require.Equal(t, io.EOF, err)

	err = buffer.Close()
	require.NoError(t, err)
}
