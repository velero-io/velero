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

package datamover

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	ctlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	cacheMock "github.com/vmware-tanzu/velero/pkg/cmd/cli/datamover/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

func TestNewBackupCommandCBTSANameFlag(t *testing.T) {
	f := factorymocks.NewFactory(t)
	cmd := NewBackupCommand(f)

	cbtSAFlag := cmd.Flags().Lookup("cbt-sa-name")
	require.NotNil(t, cbtSAFlag)
	assert.Empty(t, cbtSAFlag.DefValue)

	err := cmd.Flags().Parse([]string{"--cbt-sa-name", "velero-cbt-sa"})
	require.NoError(t, err)

	flagValue, err := cmd.Flags().GetString("cbt-sa-name")
	require.NoError(t, err)
	assert.Equal(t, "velero-cbt-sa", flagValue)
}

func fakeCreateDataPathServiceWithErr(_ *dataMoverBackup) (dataPathService, error) {
	return nil, errors.New("fake-create-data-path-error")
}

var frHelper *fakeRunHelper

func fakeCreateDataPathService(_ *dataMoverBackup) (dataPathService, error) {
	return frHelper, nil
}

type fakeRunHelper struct {
	initErr                     error
	runCancelableDataPathErr    error
	runCancelableDataPathResult string
	exitMessage                 string
	succeed                     bool
}

func (fr *fakeRunHelper) Init() error {
	return fr.initErr
}

func (fr *fakeRunHelper) RunCancelableDataPath(_ context.Context) (string, error) {
	if fr.runCancelableDataPathErr != nil {
		return "", fr.runCancelableDataPathErr
	} else {
		return fr.runCancelableDataPathResult, nil
	}
}

func (fr *fakeRunHelper) Shutdown() {

}

func (fr *fakeRunHelper) ExitWithMessage(logger logrus.FieldLogger, succeed bool, message string, a ...any) {
	fr.succeed = succeed
	fr.exitMessage = fmt.Sprintf(message, a...)
}

func TestRunDataPath(t *testing.T) {
	tests := []struct {
		name                        string
		duName                      string
		createDataPathFail          bool
		initDataPathErr             error
		runCancelableDataPathErr    error
		runCancelableDataPathResult string
		expectedMessage             string
		expectedSucceed             bool
	}{
		{
			name:               "create data path failed",
			duName:             "fake-name",
			createDataPathFail: true,
			expectedMessage:    "Failed to create data path service for DataUpload fake-name: fake-create-data-path-error",
		},
		{
			name:            "init data path failed",
			duName:          "fake-name",
			initDataPathErr: errors.New("fake-init-data-path-error"),
			expectedMessage: "Failed to init data path service for DataUpload fake-name: fake-init-data-path-error",
		},
		{
			name:                     "run data path failed",
			duName:                   "fake-name",
			runCancelableDataPathErr: errors.New("fake-run-data-path-error"),
			expectedMessage:          "Failed to run data path service for DataUpload fake-name: fake-run-data-path-error",
		},
		{
			name:                        "succeed",
			duName:                      "fake-name",
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
				funcCreateDataPathService = fakeCreateDataPathServiceWithErr
			} else {
				funcCreateDataPathService = fakeCreateDataPathService
			}

			funcExitWithMessage = frHelper.ExitWithMessage

			s := &dataMoverBackup{
				logger:     velerotest.NewLogger(),
				cancelFunc: func() {},
				config: dataMoverBackupConfig{
					duName: test.duName,
				},
				cbtService: cbtservice.Service(nil),
			}

			s.runDataPath()

			assert.Equal(t, test.expectedMessage, frHelper.exitMessage)
			assert.Equal(t, test.expectedSucceed, frHelper.succeed)
		})
	}
}

type fakeCreateDataPathServiceHelper struct {
	fileStoreErr   error
	secretStoreErr error
}

func (fc *fakeCreateDataPathServiceHelper) NewNamespacedFileStore(_ ctlclient.Client, _ string, _ string, _ filesystem.Interface) (credentials.FileStore, error) {
	return nil, fc.fileStoreErr
}

func (fc *fakeCreateDataPathServiceHelper) NewNamespacedSecretStore(_ ctlclient.Client, _ string) (credentials.SecretStore, error) {
	return nil, fc.secretStoreErr
}

func TestCreateDataPathService(t *testing.T) {
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

			s := &dataMoverBackup{
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
