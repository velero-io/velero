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
	"sync"
	"testing"
	"time"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/snapshot/upload"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/credentials/mocks"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository"
	udmrepo "github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	udmrepomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/mocks"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/uploader/kopia"
	"github.com/vmware-tanzu/velero/pkg/util"
)

type FakeBackupProgressUpdater struct {
	PodVolumeBackup *velerov1api.PodVolumeBackup
	Log             logrus.FieldLogger
	Ctx             context.Context
	Cli             client.Client
}

func (f *FakeBackupProgressUpdater) UpdateProgress(p *uploader.Progress) {}

type FakeRestoreProgressUpdater struct {
	PodVolumeRestore *velerov1api.PodVolumeRestore
	Log              logrus.FieldLogger
	Ctx              context.Context
	Cli              client.Client
}

func (f *FakeRestoreProgressUpdater) UpdateProgress(p *uploader.Progress) {}

func TestRunBackup(t *testing.T) {
	testCases := []struct {
		name           string
		hookBackupFunc func(ctx context.Context, fsUploader kopia.SnapshotUploader, repoWriter repo.RepositoryWriter, sourcePath string, realSource string, forceFull bool, parentSnapshot string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, tags map[string]string, log logrus.FieldLogger) (*uploader.SnapshotInfo, bool, error)
		volMode        uploader.PersistentVolumeMode
		notError       bool
	}{
		{
			name: "success to backup",
			hookBackupFunc: func(ctx context.Context, fsUploader kopia.SnapshotUploader, repoWriter repo.RepositoryWriter, sourcePath string, realSource string, forceFull bool, parentSnapshot string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, tags map[string]string, log logrus.FieldLogger) (*uploader.SnapshotInfo, bool, error) {
				return &uploader.SnapshotInfo{}, false, nil
			},
			notError: true,
		},
		{
			name: "get error to backup",
			hookBackupFunc: func(ctx context.Context, fsUploader kopia.SnapshotUploader, repoWriter repo.RepositoryWriter, sourcePath string, realSource string, forceFull bool, parentSnapshot string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, tags map[string]string, log logrus.FieldLogger) (*uploader.SnapshotInfo, bool, error) {
				return &uploader.SnapshotInfo{}, false, errors.New("failed to backup")
			},
			notError: false,
		},
		{
			name: "success to backup block mode volume",
			hookBackupFunc: func(ctx context.Context, fsUploader kopia.SnapshotUploader, repoWriter repo.RepositoryWriter, sourcePath string, realSource string, forceFull bool, parentSnapshot string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, tags map[string]string, log logrus.FieldLogger) (*uploader.SnapshotInfo, bool, error) {
				return &uploader.SnapshotInfo{}, false, nil
			},
			volMode:  uploader.PersistentVolumeBlock,
			notError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockBRepo := udmrepomocks.NewBackupRepo(t)
			mockBRepo.On("GetAdvancedFeatures").Return(udmrepo.AdvancedFeatureInfo{})

			var kp kopiaProvider
			kp.log = logrus.New()
			kp.bkRepo = mockBRepo
			updater := FakeBackupProgressUpdater{PodVolumeBackup: &velerov1api.PodVolumeBackup{}, Log: kp.log, Ctx: t.Context(), Cli: fake.NewClientBuilder().WithScheme(util.VeleroScheme).Build()}

			if tc.volMode == "" {
				tc.volMode = uploader.PersistentVolumeFilesystem
			}
			kopiaBackupFunc = tc.hookBackupFunc
			_, _, _, _, err := kp.RunBackup(t.Context(), "var", "", nil, false, "", CBTParam{}, tc.volMode, map[string]string{}, &updater)
			if tc.notError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRunRestore(t *testing.T) {
	testCases := []struct {
		name            string
		hookRestoreFunc func(ctx context.Context, rep repo.RepositoryWriter, progress *kopia.Progress, snapshotID, dest string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, log logrus.FieldLogger, cancleCh chan struct{}) (int64, int32, error)
		notError        bool
		volMode         uploader.PersistentVolumeMode
	}{
		{
			name: "normal restore",
			hookRestoreFunc: func(ctx context.Context, rep repo.RepositoryWriter, progress *kopia.Progress, snapshotID, dest string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, log logrus.FieldLogger, cancleCh chan struct{}) (int64, int32, error) {
				return 0, 0, nil
			},
			notError: true,
		},
		{
			name: "normal block mode restore",
			hookRestoreFunc: func(ctx context.Context, rep repo.RepositoryWriter, progress *kopia.Progress, snapshotID, dest string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, log logrus.FieldLogger, cancleCh chan struct{}) (int64, int32, error) {
				return 0, 0, nil
			},
			volMode:  uploader.PersistentVolumeBlock,
			notError: true,
		},
		{
			name: "failed to restore",
			hookRestoreFunc: func(ctx context.Context, rep repo.RepositoryWriter, progress *kopia.Progress, snapshotID, dest string, volMode uploader.PersistentVolumeMode, uploaderCfg map[string]string, log logrus.FieldLogger, cancleCh chan struct{}) (int64, int32, error) {
				return 0, 0, errors.New("failed to restore")
			},
			notError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var kp kopiaProvider
			kp.log = logrus.New()
			updater := FakeRestoreProgressUpdater{PodVolumeRestore: &velerov1api.PodVolumeRestore{}, Log: kp.log, Ctx: t.Context(), Cli: fake.NewClientBuilder().WithScheme(util.VeleroScheme).Build()}

			if tc.volMode == "" {
				tc.volMode = uploader.PersistentVolumeFilesystem
			}
			kopiaRestoreFunc = tc.hookRestoreFunc
			_, err := kp.RunRestore(t.Context(), "", "/var", tc.volMode, map[string]string{}, &updater)
			if tc.notError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestCheckContext(t *testing.T) {
	testCases := []struct {
		name          string
		finishChan    chan struct{}
		restoreChan   chan struct{}
		uploader      *upload.Uploader
		expectCancel  bool
		expectBackup  bool
		expectRestore bool
	}{
		{
			name:          "FinishChan",
			finishChan:    make(chan struct{}),
			restoreChan:   make(chan struct{}),
			uploader:      &upload.Uploader{},
			expectCancel:  false,
			expectBackup:  false,
			expectRestore: false,
		},
		{
			name:          "nil uploader",
			finishChan:    make(chan struct{}),
			restoreChan:   make(chan struct{}),
			uploader:      nil,
			expectCancel:  true,
			expectBackup:  false,
			expectRestore: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var wg sync.WaitGroup
			wg.Add(1)

			if tc.expectBackup {
				go func() {
					wg.Wait()
					tc.restoreChan <- struct{}{}
				}()
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			go func() {
				time.Sleep(100 * time.Millisecond)
				cancel()
				wg.Done()
			}()

			kp := &kopiaProvider{log: logrus.New()}
			kp.CheckContext(ctx, tc.finishChan, tc.restoreChan, tc.uploader)

			if tc.expectCancel && tc.uploader != nil {
				t.Error("Expected the uploader to be canceled")
			}

			if tc.expectBackup && tc.uploader == nil && len(tc.restoreChan) > 0 {
				t.Error("Expected the restore channel to be closed")
			}
		})
	}
}

func TestGetPassword(t *testing.T) {
	testCases := []struct {
		name           string
		empytSecret    bool
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
			empytSecret:  true,
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
			// Mock CredentialGetter
			credGetter := &credentials.CredentialGetter{}
			mockCredGetter := &mocks.SecretStore{}
			if !tc.empytSecret {
				credGetter.FromSecret = mockCredGetter
			}
			repoKeySelector := &corev1api.SecretKeySelector{LocalObjectReference: corev1api.LocalObjectReference{Name: "velero-repo-credentials"}, Key: "repository-password"}

			if tc.credGetterFunc != nil {
				tc.credGetterFunc(mockCredGetter, repoKeySelector)
			}

			kp := &kopiaProvider{
				credGetter: credGetter,
			}

			password, err := kp.GetPassword(nil)
			if tc.expectError {
				require.Error(t, err, "Expected an error")
			} else {
				require.NoError(t, err, "Expected no error")
			}

			assert.Equal(t, tc.expectedPass, password, "Expected password to match")
		})
	}
}

type MockCredentialGetter struct {
	mock.Mock
}

func (m *MockCredentialGetter) GetCredentials() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

// MockRepoSvc is a mock implementation of the RepoService interface.
type MockRepoSvc struct {
	mock.Mock
}

func (m *MockRepoSvc) Open(ctx context.Context, opts udmrepo.RepoOptions) (udmrepo.BackupRepo, error) {
	args := m.Called(ctx, opts)
	return args.Get(0).(udmrepo.BackupRepo), args.Error(1)
}

func TestNewKopiaUploaderProvider(t *testing.T) {
	requestorType := "testRequestor"
	ctx := t.Context()
	backupRepo := repository.NewBackupRepository(velerov1api.DefaultNamespace, repository.BackupRepositoryKey{VolumeNamespace: "fake-volume-ns-02", BackupLocation: "fake-bsl-02", RepositoryType: "fake-repository-type-02"})
	mockLog := logrus.New()

	// Define test cases
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
			expectedError: "Failed to find kopia repository",
		},
	}

	// Iterate through test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credGetter := &credentials.CredentialGetter{FromSecret: tc.mockCredGetter}
			BackupRepoServiceCreateFunc = func(string, logrus.FieldLogger) udmrepo.BackupRepoService {
				return tc.mockBackupRepoService
			}
			// Call the function being tested.
			_, err := NewKopiaUploaderProvider(requestorType, ctx, credGetter, backupRepo, mockLog)

			// Assertions
			if tc.expectedError != "" {
				require.ErrorContains(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			// Verify that the expected methods were called on the mocks.
			tc.mockCredGetter.AssertExpectations(t)
		})
	}
}
