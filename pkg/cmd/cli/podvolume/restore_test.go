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

package podvolume

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	cacheMock "github.com/velero-io/velero/pkg/cmd/cli/datamover/mocks"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func fakeCreateRestoreDataPathServiceWithErr(_ *podVolumeRestore) (dataPathService, error) {
	return nil, errors.New("fake-create-data-path-error")
}

func fakeCreateRestoreDataPathService(_ *podVolumeRestore) (dataPathService, error) {
	return frHelper, nil
}

func TestRunRestoreDataPath(t *testing.T) {
	tests := []struct {
		name                        string
		pvrName                     string
		createDataPathFail          bool
		initDataPathErr             error
		runCancelableDataPathErr    error
		runCancelableDataPathResult string
		expectedMessage             string
		expectedSucceed             bool
	}{
		{
			name:               "create data path failed",
			pvrName:            "fake-name",
			createDataPathFail: true,
			expectedMessage:    "Failed to create data path service for PVR fake-name: fake-create-data-path-error",
		},
		{
			name:            "init data path failed",
			pvrName:         "fake-name",
			initDataPathErr: errors.New("fake-init-data-path-error"),
			expectedMessage: "Failed to init data path service for PVR fake-name: fake-init-data-path-error",
		},
		{
			name:                     "run data path failed",
			pvrName:                  "fake-name",
			runCancelableDataPathErr: errors.New("fake-run-data-path-error"),
			expectedMessage:          "Failed to run data path service for PVR fake-name: fake-run-data-path-error",
		},
		{
			name:                        "succeed",
			pvrName:                     "fake-name",
			runCancelableDataPathResult: "fake-run-data-path-result",
			expectedMessage:             "fake-run-data-path-result",
			expectedSucceed:             true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frHelper = &fakeRunHelper{
				initErr:                     test.initDataPathErr,
				runCancelableDataPathErr:    test.runCancelableDataPathErr,
				runCancelableDataPathResult: test.runCancelableDataPathResult,
			}

			if test.createDataPathFail {
				funcCreateDataPathRestore = fakeCreateRestoreDataPathServiceWithErr
			} else {
				funcCreateDataPathRestore = fakeCreateRestoreDataPathService
			}

			funcExitWithMessage = frHelper.ExitWithMessage

			s := &podVolumeRestore{
				logger:     velerotest.NewLogger(),
				cancelFunc: func() {},
				config: podVolumeRestoreConfig{
					pvrName: test.pvrName,
				},
			}

			s.runDataPath()

			assert.Equal(t, test.expectedMessage, frHelper.exitMessage)
			assert.Equal(t, test.expectedSucceed, frHelper.succeed)
		})
	}
}

func TestCreateRestoreDataPathService(t *testing.T) {
	tests := []struct {
		name            string
		fileStoreErr    error
		secretStoreErr  error
		mockGetInformer bool
		getInformerErr  error
		expectedError   string
	}{
		{
			name:          "create credential file store error",
			fileStoreErr:  errors.New("fake-file-store-error"),
			expectedError: "error to create credential file store: fake-file-store-error",
		},
		{
			name:           "create credential secret store",
			secretStoreErr: errors.New("fake-secret-store-error"),
			expectedError:  "error to create credential secret store: fake-secret-store-error",
		},
		{
			name:            "get informer error",
			mockGetInformer: true,
			getInformerErr:  errors.New("fake-get-informer-error"),
			expectedError:   "error to get controller-runtime informer from manager: fake-get-informer-error",
		},
		{
			name:            "succeed",
			mockGetInformer: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fcHelper := &fakeCreateDataPathServiceHelper{
				fileStoreErr:   test.fileStoreErr,
				secretStoreErr: test.secretStoreErr,
			}

			funcNewCredentialFileStore = fcHelper.NewNamespacedFileStore
			funcNewCredentialSecretStore = fcHelper.NewNamespacedSecretStore

			cache := cacheMock.NewCache(t)
			if test.mockGetInformer {
				cache.On("GetInformer", mock.Anything, mock.Anything).Return(nil, test.getInformerErr)
			}

			funcExitWithMessage = frHelper.ExitWithMessage

			s := &podVolumeRestore{
				cache: cache,
			}

			_, err := s.createDataPathService()

			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
