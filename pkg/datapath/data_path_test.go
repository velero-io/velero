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

package datapath

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/uploader/provider"
	providerMock "github.com/vmware-tanzu/velero/pkg/uploader/provider/mocks"
)

func TestAsyncBackup(t *testing.T) {
	var asyncErr error
	var asyncResult Result
	finish := make(chan struct{})
	var failErr = errors.New("fake-fail-error")
	tests := []struct {
		name         string
		uploaderProv provider.Provider
		callbacks    Callbacks
		err          error
		result       Result
		path         string
	}{
		{
			name: "async backup fail",
			callbacks: Callbacks{
				OnCompleted: nil,
				OnCancelled: nil,
				OnFailed: func(ctx context.Context, namespace string, job string, err error) {
					asyncErr = failErr
					asyncResult = Result{}
					finish <- struct{}{}
				},
			},
			err: failErr,
		},
		{
			name: "async backup cancel",
			callbacks: Callbacks{
				OnCompleted: nil,
				OnFailed:    nil,
				OnCancelled: func(ctx context.Context, namespace string, job string) {
					asyncErr = provider.ErrorCanceled
					asyncResult = Result{}
					finish <- struct{}{}
				},
			},
			err: provider.ErrorCanceled,
		},
		{
			name: "async backup complete",
			callbacks: Callbacks{
				OnFailed:    nil,
				OnCancelled: nil,
				OnCompleted: func(ctx context.Context, namespace string, job string, result Result) {
					asyncResult = result
					asyncErr = nil
					finish <- struct{}{}
				},
			},
			result: Result{
				Backup: BackupResult{
					SnapshotID:    "fake-snapshot",
					EmptySnapshot: false,
					Source:        AccessPoint{ByPath: "fake-path"},
					TotalBytes:    1000,
				},
			},
			path: "fake-path",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dp := newGeneralDataPath("job-1", "test", nil, "velero", Callbacks{}, velerotest.NewLogger()).(*generalDataPath)
			mockProvider := providerMock.NewProvider(t)
			mockProvider.On("RunBackup", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(test.result.Backup.SnapshotID, test.result.Backup.EmptySnapshot, test.result.Backup.TotalBytes, test.result.Backup.IncrementalBytes, test.err)
			mockProvider.On("Close", mock.Anything).Return(nil)
			dp.uploaderProv = mockProvider
			dp.initialized = true
			dp.callbacks = test.callbacks

			err := dp.StartBackup(AccessPoint{ByPath: test.path}, map[string]string{}, &BackupStartParam{})
			require.NoError(t, err)

			<-finish

			// Ensure the goroutine finishes so deferred fs.close executes, satisfying mock expectations.
			dp.wgDataPath.Wait()

			assert.Equal(t, test.err, asyncErr)
			assert.Equal(t, test.result, asyncResult)
		})
	}

	close(finish)
}

func TestAsyncRestore(t *testing.T) {
	var asyncErr error
	var asyncResult Result
	finish := make(chan struct{})
	var failErr = errors.New("fake-fail-error")
	tests := []struct {
		name         string
		uploaderProv provider.Provider
		callbacks    Callbacks
		err          error
		result       Result
		path         string
		snapshot     string
	}{
		{
			name: "async restore fail",
			callbacks: Callbacks{
				OnCompleted: nil,
				OnCancelled: nil,
				OnFailed: func(ctx context.Context, namespace string, job string, err error) {
					asyncErr = failErr
					asyncResult = Result{}
					finish <- struct{}{}
				},
			},
			err: failErr,
		},
		{
			name: "async restore cancel",
			callbacks: Callbacks{
				OnCompleted: nil,
				OnFailed:    nil,
				OnCancelled: func(ctx context.Context, namespace string, job string) {
					asyncErr = provider.ErrorCanceled
					asyncResult = Result{}
					finish <- struct{}{}
				},
			},
			err: provider.ErrorCanceled,
		},
		{
			name: "async restore complete",
			callbacks: Callbacks{
				OnFailed:    nil,
				OnCancelled: nil,
				OnCompleted: func(ctx context.Context, namespace string, job string, result Result) {
					asyncResult = result
					asyncErr = nil
					finish <- struct{}{}
				},
			},
			result: Result{
				Restore: RestoreResult{
					Target:     AccessPoint{ByPath: "fake-path"},
					TotalBytes: 1000,
				},
			},
			path:     "fake-path",
			snapshot: "fake-snapshot",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dp := newGeneralDataPath("job-1", "test", nil, "velero", Callbacks{}, velerotest.NewLogger()).(*generalDataPath)
			mockProvider := providerMock.NewProvider(t)
			mockProvider.On("RunRestore", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(test.result.Restore.TotalBytes, test.err)
			mockProvider.On("Close", mock.Anything).Return(nil)
			dp.uploaderProv = mockProvider
			dp.initialized = true
			dp.callbacks = test.callbacks

			err := dp.StartRestore(test.snapshot, AccessPoint{ByPath: test.path}, map[string]string{})
			require.NoError(t, err)

			<-finish

			// Ensure the goroutine finishes so deferred fs.close executes, satisfying mock expectations.
			dp.wgDataPath.Wait()

			assert.Equal(t, asyncErr, test.err)
			assert.Equal(t, asyncResult, test.result)
		})
	}

	close(finish)
}
