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
	"fmt"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientFake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	datapathmockes "github.com/vmware-tanzu/velero/pkg/datapath/mocks"
	"github.com/vmware-tanzu/velero/pkg/uploader"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestOnDataDownloadFailed(t *testing.T) {
	dataDownloadName := "fake-data-download"
	bt := &backupMsTestHelper{}

	bs := &RestoreMicroService{
		dataDownloadName: dataDownloadName,
		dataPathMgr:      datapath.NewManager(1),
		eventRecorder:    bt,
		resultSignal:     make(chan dataPathResult),
		logger:           velerotest.NewLogger(),
	}

	expectedErr := "Data path for data download fake-data-download failed: fake-error"
	expectedEventReason := datapath.EventReasonFailed
	expectedEventMsg := "Data path for data download fake-data-download failed, error fake-error"

	go bs.OnDataDownloadFailed(t.Context(), velerov1api.DefaultNamespace, dataDownloadName, errors.New("fake-error"))

	result := <-bs.resultSignal
	require.EqualError(t, result.err, expectedErr)
	assert.Equal(t, expectedEventReason, bt.EventReason())
	assert.Equal(t, expectedEventMsg, bt.EventMessage())
}

func TestOnDataDownloadCancelled(t *testing.T) {
	dataDownloadName := "fake-data-download"
	bt := &backupMsTestHelper{}

	bs := &RestoreMicroService{
		dataDownloadName: dataDownloadName,
		dataPathMgr:      datapath.NewManager(1),
		eventRecorder:    bt,
		resultSignal:     make(chan dataPathResult),
		logger:           velerotest.NewLogger(),
	}

	expectedErr := datapath.ErrCancelled
	expectedEventReason := datapath.EventReasonCancelled
	expectedEventMsg := "Data path for data download fake-data-download canceled"

	go bs.OnDataDownloadCancelled(t.Context(), velerov1api.DefaultNamespace, dataDownloadName)

	result := <-bs.resultSignal
	require.EqualError(t, result.err, expectedErr)
	assert.Equal(t, expectedEventReason, bt.EventReason())
	assert.Equal(t, expectedEventMsg, bt.EventMessage())
}

func TestOnDataDownloadCompleted(t *testing.T) {
	tests := []struct {
		name                string
		expectedErr         string
		expectedEventReason string
		expectedEventMsg    string
		marshalErr          error
		marshallStr         string
	}{
		{
			name:        "marshal fail",
			marshalErr:  errors.New("fake-marshal-error"),
			expectedErr: "Failed to marshal restore result {{ } 0}: fake-marshal-error",
		},
		{
			name:                "succeed",
			marshallStr:         "fake-complete-string",
			expectedEventReason: datapath.EventReasonCompleted,
			expectedEventMsg:    "fake-complete-string",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataDownloadName := "fake-data-download"

			bt := &backupMsTestHelper{
				marshalErr:   test.marshalErr,
				marshalBytes: []byte(test.marshallStr),
			}

			bs := &RestoreMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: bt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewLogger(),
			}

			funcMarshal = bt.Marshal

			go bs.OnDataDownloadCompleted(t.Context(), velerov1api.DefaultNamespace, dataDownloadName, datapath.Result{})

			result := <-bs.resultSignal
			if test.marshalErr != nil {
				assert.EqualError(t, result.err, test.expectedErr)
			} else {
				require.NoError(t, result.err)
				assert.Equal(t, test.expectedEventReason, bt.EventReason())
				assert.Equal(t, test.expectedEventMsg, bt.EventMessage())
			}
		})
	}
}

func TestOnDataDownloadProgress(t *testing.T) {
	tests := []struct {
		name                string
		expectedEventReason string
		expectedEventMsg    string
		marshalErr          error
		marshallStr         string
	}{
		{
			name:       "marshal fail",
			marshalErr: errors.New("fake-marshal-error"),
		},
		{
			name:                "succeed",
			marshallStr:         "fake-progress-string",
			expectedEventReason: datapath.EventReasonProgress,
			expectedEventMsg:    "fake-progress-string",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataDownloadName := "fake-data-download"

			bt := &backupMsTestHelper{
				marshalErr:   test.marshalErr,
				marshalBytes: []byte(test.marshallStr),
			}

			bs := &RestoreMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: bt,
				logger:        velerotest.NewLogger(),
			}

			funcMarshal = bt.Marshal

			bs.OnDataDownloadProgress(t.Context(), velerov1api.DefaultNamespace, dataDownloadName, &uploader.Progress{})

			if test.marshalErr != nil {
				assert.False(t, bt.withEvent)
			} else {
				assert.True(t, bt.withEvent)
				assert.Equal(t, test.expectedEventReason, bt.EventReason())
				assert.Equal(t, test.expectedEventMsg, bt.EventMessage())
			}
		})
	}
}

func TestCancelDataDownload(t *testing.T) {
	tests := []struct {
		name                string
		expectedEventReason string
		expectedEventMsg    string
		expectedErr         string
	}{
		{
			name:                "no fs restore",
			expectedEventReason: datapath.EventReasonStopped,
			expectedEventMsg:    "Data path for fake-data-download exited without start",
			expectedErr:         datapath.ErrCancelled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataDownloadName := "fake-data-download"
			dd := builder.ForDataDownload(velerov1api.DefaultNamespace, dataDownloadName).Result()

			bt := &backupMsTestHelper{}

			bs := &RestoreMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: bt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewLogger(),
			}

			go bs.cancelDataDownload(dd)

			result := <-bs.resultSignal

			require.EqualError(t, result.err, test.expectedErr)
			assert.True(t, bt.withEvent)
			assert.Equal(t, test.expectedEventReason, bt.EventReason())
			assert.Equal(t, test.expectedEventMsg, bt.EventMessage())
		})
	}
}

func TestRunCancelableRestore(t *testing.T) {
	dataDownloadName := "fake-data-download"
	dd := builder.ForDataDownload(velerov1api.DefaultNamespace, dataDownloadName).Phase(velerov2alpha1api.DataDownloadPhaseNew).Result()
	ddInProgress := builder.ForDataDownload(velerov1api.DefaultNamespace, dataDownloadName).Phase(velerov2alpha1api.DataDownloadPhaseInProgress).Result()
	ctxTimeout, cancel := context.WithTimeout(t.Context(), time.Second)

	tests := []struct {
		name             string
		ctx              context.Context
		result           *dataPathResult
		dataPathMgr      *datapath.Manager
		kubeClientObj    []runtime.Object
		initErr          error
		startErr         error
		dataPathStarted  bool
		expectedEventMsg string
		expectedErr      string
	}{
		{
			name:        "no dd",
			ctx:         ctxTimeout,
			expectedErr: "error waiting for dd: context deadline exceeded",
		},
		{
			name:          "dd not in in-progress",
			ctx:           ctxTimeout,
			kubeClientObj: []runtime.Object{dd},
			expectedErr:   "error waiting for dd: context deadline exceeded",
		},
		{
			name:          "create data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{ddInProgress},
			dataPathMgr:   datapath.NewManager(0),
			expectedErr:   "error to create data path: Concurrent number exceeds",
		},
		{
			name:          "init data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{ddInProgress},
			initErr:       errors.New("fake-init-error"),
			expectedErr:   "error to initialize data path: fake-init-error",
		},
		{
			name:          "start data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{ddInProgress},
			startErr:      errors.New("fake-start-error"),
			expectedErr:   "error starting data path restore: fake-start-error",
		},
		{
			name:             "data path timeout",
			ctx:              ctxTimeout,
			kubeClientObj:    []runtime.Object{ddInProgress},
			dataPathStarted:  true,
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", dataDownloadName),
			expectedErr:      "timed out waiting for fs restore to complete",
		},
		{
			name:            "data path returns error",
			ctx:             t.Context(),
			kubeClientObj:   []runtime.Object{ddInProgress},
			dataPathStarted: true,
			result: &dataPathResult{
				err: errors.New("fake-data-path-error"),
			},
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", dataDownloadName),
			expectedErr:      "fake-data-path-error",
		},
		{
			name:            "succeed",
			ctx:             t.Context(),
			kubeClientObj:   []runtime.Object{ddInProgress},
			dataPathStarted: true,
			result: &dataPathResult{
				result: "fake-succeed-result",
			},
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", dataDownloadName),
		},
	}

	scheme := runtime.NewScheme()
	velerov2alpha1api.AddToScheme(scheme)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClientBuilder := clientFake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(scheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			bt := &backupMsTestHelper{}

			rs := &RestoreMicroService{
				namespace:        velerov1api.DefaultNamespace,
				dataDownloadName: dataDownloadName,
				ctx:              t.Context(),
				client:           fakeClient,
				dataPathMgr:      datapath.NewManager(1),
				eventRecorder:    bt,
				resultSignal:     make(chan dataPathResult),
				logger:           velerotest.NewLogger(),
			}

			if test.ctx != nil {
				rs.ctx = test.ctx
			}

			if test.dataPathMgr != nil {
				rs.dataPathMgr = test.dataPathMgr
			}

			datapath.VGDPCreator = func(string, string, kbclient.Client, string, datapath.Callbacks, logrus.FieldLogger) datapath.AsyncBR {
				fsBR := datapathmockes.NewAsyncBR(t)
				if test.initErr != nil {
					fsBR.On("Init", mock.Anything, mock.Anything).Return(test.initErr)
				}

				if test.startErr != nil {
					fsBR.On("Init", mock.Anything, mock.Anything).Return(nil)
					fsBR.On("StartRestore", mock.Anything, mock.Anything, mock.Anything).Return(test.startErr)
				}

				if test.dataPathStarted {
					fsBR.On("Init", mock.Anything, mock.Anything).Return(nil)
					fsBR.On("StartRestore", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				}

				return fsBR
			}

			if test.result != nil {
				go func() {
					time.Sleep(time.Millisecond * 500)
					rs.resultSignal <- *test.result
				}()
			}

			result, err := rs.RunCancelableDataPath(test.ctx)

			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.result.result, result)
			}

			if test.expectedEventMsg != "" {
				assert.True(t, bt.withEvent)
				assert.Equal(t, test.expectedEventMsg, bt.EventMessage())
			}
		})
	}

	cancel()
}
