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
	"testing"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/credentials/mocks"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	udmrepomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/mocks"
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
