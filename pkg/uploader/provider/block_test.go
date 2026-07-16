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

package provider

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/credentials/mocks"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	udmrepomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/mocks"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/uploader/block"
)

func TestNewBlockUploaderProvider(t *testing.T) {
	requestorType := "testRequestor"
	ctx := t.Context()
	backupRepo := repository.NewBackupRepository(velerov1api.DefaultNamespace, repository.BackupRepositoryKey{VolumeNamespace: "fake-volume-ns-02", BackupLocation: "fake-bsl-02", RepositoryType: "fake-repository-type-02"})
	mockLog := logrus.New()

	testCases := []struct {
		name                  string
		mockCredGetter        *mocks.SecretStore
		mockBackupRepoService udmrepo.BackupRepoService
		expectedError         string
	}{
		{
			name: "Success",
			mockCredGetter: func() *mocks.SecretStore {
				mockCredGetter := &mocks.SecretStore{}
				mockCredGetter.On("Get", mock.Anything).Return("test", nil)
				return mockCredGetter
			}(),
			mockBackupRepoService: func() udmrepo.BackupRepoService {
				backupRepoService := &udmrepomocks.BackupRepoService{}
				var backupRepo udmrepo.BackupRepo
				backupRepoService.On("Open", t.Context(), mock.Anything).Return(backupRepo, nil)
				return backupRepoService
			}(),
			expectedError: "",
		},
		{
			name: "Error to get repo options",
			mockCredGetter: func() *mocks.SecretStore {
				mockCredGetter := &mocks.SecretStore{}
				mockCredGetter.On("Get", mock.Anything).Return("test", errors.New("failed to get password"))
				return mockCredGetter
			}(),
			mockBackupRepoService: func() udmrepo.BackupRepoService {
				backupRepoService := &udmrepomocks.BackupRepoService{}
				var backupRepo udmrepo.BackupRepo
				backupRepoService.On("Open", t.Context(), mock.Anything).Return(backupRepo, nil)
				return backupRepoService
			}(),
			expectedError: "error to get repo options",
		},
		{
			name: "Error open repository service",
			mockCredGetter: func() *mocks.SecretStore {
				mockCredGetter := &mocks.SecretStore{}
				mockCredGetter.On("Get", mock.Anything).Return("test", nil)
				return mockCredGetter
			}(),
			mockBackupRepoService: func() udmrepo.BackupRepoService {
				backupRepoService := &udmrepomocks.BackupRepoService{}
				var backupRepo udmrepo.BackupRepo
				backupRepoService.On("Open", t.Context(), mock.Anything).Return(backupRepo, errors.New("failed to init repository"))
				return backupRepoService
			}(),
			expectedError: "Failed to find backup repository",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credGetter := &credentials.CredentialGetter{FromSecret: tc.mockCredGetter}
			BackupRepoServiceCreateFunc = func(string, logrus.FieldLogger) udmrepo.BackupRepoService {
				return tc.mockBackupRepoService
			}
			_, err := NewBlockUploaderProvider(requestorType, ctx, credGetter, backupRepo, mockLog)

			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			tc.mockCredGetter.AssertExpectations(t)
		})
	}
}

func TestBlockProviderClose(t *testing.T) {
	mockBRepo := udmrepomocks.NewBackupRepo(t)
	mockBRepo.On("Close", mock.Anything).Return(nil)

	bp := &blockProvider{
		bkRepo: mockBRepo,
	}

	err := bp.Close(t.Context())
	require.NoError(t, err)
	mockBRepo.AssertExpectations(t)
}

type blockMockProgressUpdater struct {
	lastProgress *uploader.Progress
	callCount    int
}

func (u *blockMockProgressUpdater) UpdateProgress(p *uploader.Progress) {
	u.lastProgress = p
	u.callCount++
}

func TestBlockProviderGetPassword(t *testing.T) {
	testCases := []struct {
		name           string
		emptySecret    bool
		credGetterFunc func(*mocks.SecretStore, *corev1api.SecretKeySelector)
		expectError    bool
		expectedPass   string
	}{
		{
			name: "valid credentials interface",
			credGetterFunc: func(ss *mocks.SecretStore, selector *corev1api.SecretKeySelector) {
				ss.On("Get", selector).Return("test", nil)
			},
			expectError:  false,
			expectedPass: "test",
		},
		{
			name:         "empty from secret",
			emptySecret:  true,
			expectError:  true,
			expectedPass: "",
		},
		{
			name: "ErrorGettingPassword",
			credGetterFunc: func(ss *mocks.SecretStore, selector *corev1api.SecretKeySelector) {
				ss.On("Get", selector).Return("", errors.New("error getting password"))
			},
			expectError:  true,
			expectedPass: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credGetter := &credentials.CredentialGetter{}
			mockCredGetter := &mocks.SecretStore{}
			if !tc.emptySecret {
				credGetter.FromSecret = mockCredGetter
			}
			repoKeySelector := &corev1api.SecretKeySelector{LocalObjectReference: corev1api.LocalObjectReference{Name: "velero-repo-credentials"}, Key: "repository-password"}

			if tc.credGetterFunc != nil {
				tc.credGetterFunc(mockCredGetter, repoKeySelector)
			}

			bp := &blockProvider{
				credGetter: credGetter,
			}

			password, err := bp.GetPassword(nil)
			if tc.expectError {
				require.Error(t, err, "Expected an error")
			} else {
				require.NoError(t, err, "Expected no error")
			}

			assert.Equal(t, tc.expectedPass, password, "Expected password to match")
		})
	}
}

func TestBlockProviderRunBackup(t *testing.T) {
	const requestorType = "test-requestor"

	testCases := []struct {
		name             string
		path             string
		realSource       string
		tags             map[string]string
		updater          uploader.ProgressUpdater
		mockBackupResult uploader.SnapshotInfo
		mockBackupErr    error
		expectedID       string
		expectedSize     int64
		expectedIncrSize int64
		expectError      bool
		expectedErrStr   string
		skipMock         bool
		checkCaptures    func(*testing.T, string, map[string]string)
	}{
		{
			name:           "nil updater returns error",
			path:           "/dev/sda",
			updater:        nil,
			expectError:    true,
			expectedErrStr: "backup progress updater is invalid",
			skipMock:       true,
		},
		{
			name:           "empty path returns error",
			path:           "",
			updater:        &FakeBackupProgressUpdater{},
			expectError:    true,
			expectedErrStr: "path is empty",
			skipMock:       true,
		},
		{
			name:    "success returns correct snapshot info and updates progress",
			path:    "/dev/sda",
			updater: &blockMockProgressUpdater{},
			mockBackupResult: uploader.SnapshotInfo{
				ID:              "snap-001",
				Size:            1024,
				IncrementalSize: 512,
			},
			expectedID:       "snap-001",
			expectedSize:     1024,
			expectedIncrSize: 512,
		},
		{
			name:    "canceled backup returns ErrorCanceled with partial snapshot info",
			path:    "/dev/sda",
			updater: &FakeBackupProgressUpdater{},
			mockBackupResult: uploader.SnapshotInfo{
				ID:              "snap-canceled",
				Size:            2048,
				IncrementalSize: 1024,
			},
			mockBackupErr:    block.ErrCanceled,
			expectedID:       "snap-canceled",
			expectedSize:     2048,
			expectedIncrSize: 1024,
			expectError:      true,
			expectedErrStr:   "uploader is canceled",
		},
		{
			name:           "generic backup error is wrapped",
			path:           "/dev/sda",
			updater:        &FakeBackupProgressUpdater{},
			mockBackupErr:  errors.New("disk I/O error"),
			expectError:    true,
			expectedErrStr: "Failed to run block backup",
		},
		{
			name:             "nil tags are initialized with required tags",
			path:             "/dev/sda",
			tags:             nil,
			updater:          &FakeBackupProgressUpdater{},
			mockBackupResult: uploader.SnapshotInfo{ID: "snap-tags"},
			expectedID:       "snap-tags",
			checkCaptures: func(t *testing.T, _ string, tags map[string]string) {
				t.Helper()
				assert.Equal(t, requestorType, tags[uploader.SnapshotRequesterTag])
				assert.Equal(t, uploader.BlockType, tags[uploader.SnapshotUploaderTag])
			},
		},
		{
			name:             "non-empty realSource is prefixed with requestorType and BlockType",
			path:             "/dev/sda",
			realSource:       "my-volume",
			updater:          &FakeBackupProgressUpdater{},
			mockBackupResult: uploader.SnapshotInfo{ID: "snap-source"},
			expectedID:       "snap-source",
			checkCaptures: func(t *testing.T, realSource string, _ map[string]string) {
				t.Helper()
				assert.Equal(t, requestorType+"/"+uploader.BlockType+"/my-volume", realSource)
			},
		},
		{
			name:             "empty realSource is passed through unchanged",
			path:             "/dev/sda",
			realSource:       "",
			updater:          &FakeBackupProgressUpdater{},
			mockBackupResult: uploader.SnapshotInfo{ID: "snap-nosource"},
			expectedID:       "snap-nosource",
			checkCaptures: func(t *testing.T, realSource string, _ map[string]string) {
				t.Helper()
				assert.Empty(t, realSource)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockBRepo := udmrepomocks.NewBackupRepo(t)

			var capturedRealSrc string
			var capturedTags map[string]string

			if !tc.skipMock {
				blockBackupFunc = func(_ context.Context, _ block.Uploader, _ udmrepo.BackupRepo, _ string, realSource string, _ cbtservice.SourceInfo, _ bool, _ string, _ cbtservice.Service, _ map[string]string, tags map[string]string, _ logrus.FieldLogger) (uploader.SnapshotInfo, bool, error) {
					capturedRealSrc = realSource
					capturedTags = tags
					return tc.mockBackupResult, false, tc.mockBackupErr
				}
			}

			bp := &blockProvider{
				requestorType: requestorType,
				bkRepo:        mockBRepo,
				log:           logrus.New(),
			}

			snapshotID, isEmpty, size, incrSize, err := bp.RunBackup(
				t.Context(),
				tc.path,
				tc.realSource,
				tc.tags,
				false,
				"",
				CBTParam{},
				uploader.PersistentVolumeBlock,
				map[string]string{},
				tc.updater,
			)

			assert.Equal(t, tc.expectedID, snapshotID)
			assert.Equal(t, tc.expectedSize, size)
			assert.Equal(t, tc.expectedIncrSize, incrSize)

			if tc.expectError {
				require.Error(t, err)
				if tc.expectedErrStr != "" {
					require.ErrorContains(t, err, tc.expectedErrStr)
				}
			} else {
				require.NoError(t, err)
				assert.False(t, isEmpty)
				if mu, ok := tc.updater.(*blockMockProgressUpdater); ok {
					assert.Equal(t, 1, mu.callCount)
					require.NotNil(t, mu.lastProgress)
					assert.Equal(t, tc.expectedSize, mu.lastProgress.TotalBytes)
					assert.Equal(t, tc.expectedSize, mu.lastProgress.BytesDone)
				}
			}

			if tc.checkCaptures != nil {
				tc.checkCaptures(t, capturedRealSrc, capturedTags)
			}
		})
	}
}

func TestBlockProviderRunRestore(t *testing.T) {
	testCases := []struct {
		name            string
		snapshotID      string
		volumePath      string
		updater         uploader.ProgressUpdater
		mockRestoreSize int64
		mockRestoreErr  error
		expectedSize    int64
		expectError     bool
		expectedErrStr  string
		checkCaptures   func(*testing.T, string, string)
	}{
		{
			name:           "nil updater returns error",
			updater:        nil,
			expectError:    true,
			expectedErrStr: "restore progress updater is invalid",
		},
		{
			name:            "success returns size and updates progress",
			snapshotID:      "snap-001",
			volumePath:      "/dev/sdb",
			updater:         &blockMockProgressUpdater{},
			mockRestoreSize: 4096,
			expectedSize:    4096,
		},
		{
			name:           "canceled restore returns ErrorCanceled",
			snapshotID:     "snap-canceled",
			volumePath:     "/dev/sdb",
			updater:        &FakeRestoreProgressUpdater{},
			mockRestoreErr: block.ErrCanceled,
			expectError:    true,
			expectedErrStr: "uploader is canceled",
		},
		{
			name:           "generic restore error is wrapped",
			snapshotID:     "snap-error",
			volumePath:     "/dev/sdb",
			updater:        &FakeRestoreProgressUpdater{},
			mockRestoreErr: errors.New("disk read error"),
			expectError:    true,
			expectedErrStr: "Failed to run block restore",
		},
		{
			name:            "snapshotID and volumePath are forwarded to restore func",
			snapshotID:      "snap-fwd",
			volumePath:      "/dev/sdc",
			updater:         &FakeRestoreProgressUpdater{},
			mockRestoreSize: 512,
			expectedSize:    512,
			checkCaptures: func(t *testing.T, snapshotID, volumePath string) {
				t.Helper()
				assert.Equal(t, "snap-fwd", snapshotID)
				assert.Equal(t, "/dev/sdc", volumePath)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockBRepo := udmrepomocks.NewBackupRepo(t)

			var capturedSnapshotID string
			var capturedVolumePath string

			blockRestoreFunc = func(_ context.Context, _ block.Uploader, _ udmrepo.BackupRepo, snapshotID string, volumePath string, _ map[string]string, _ logrus.FieldLogger) (int64, error) {
				capturedSnapshotID = snapshotID
				capturedVolumePath = volumePath
				return tc.mockRestoreSize, tc.mockRestoreErr
			}

			bp := &blockProvider{
				bkRepo: mockBRepo,
				log:    logrus.New(),
			}

			size, err := bp.RunRestore(
				t.Context(),
				tc.snapshotID,
				tc.volumePath,
				uploader.PersistentVolumeBlock,
				map[string]string{},
				tc.updater,
			)

			if tc.expectError {
				require.Error(t, err)
				if tc.expectedErrStr != "" {
					require.ErrorContains(t, err, tc.expectedErrStr)
				}
				assert.Equal(t, int64(0), size)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSize, size)
				if mu, ok := tc.updater.(*blockMockProgressUpdater); ok {
					assert.Equal(t, 1, mu.callCount)
					require.NotNil(t, mu.lastProgress)
					assert.Equal(t, tc.expectedSize, mu.lastProgress.TotalBytes)
					assert.Equal(t, tc.expectedSize, mu.lastProgress.BytesDone)
				}
			}

			if tc.checkCaptures != nil {
				tc.checkCaptures(t, capturedSnapshotID, capturedVolumePath)
			}
		})
	}
}
