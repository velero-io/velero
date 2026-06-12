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
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/uploader"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	clientFake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	datapathmockes "github.com/vmware-tanzu/velero/pkg/datapath/mocks"
)

type backupMsTestHelper struct {
	eventReason  string
	eventMsg     string
	marshalErr   error
	marshalBytes []byte
	withEvent    bool
	eventLock    sync.Mutex
}

func (bt *backupMsTestHelper) Event(_ runtime.Object, _ bool, reason string, message string, a ...any) {
	bt.eventLock.Lock()
	defer bt.eventLock.Unlock()

	bt.withEvent = true
	bt.eventReason = reason
	bt.eventMsg = fmt.Sprintf(message, a...)
}

func (bt *backupMsTestHelper) EndingEvent(_ runtime.Object, _ bool, reason string, message string, a ...any) {
	bt.eventLock.Lock()
	defer bt.eventLock.Unlock()

	bt.withEvent = true
	bt.eventReason = reason
	bt.eventMsg = fmt.Sprintf(message, a...)
}
func (bt *backupMsTestHelper) Shutdown() {}

func (bt *backupMsTestHelper) Marshal(v any) ([]byte, error) {
	if bt.marshalErr != nil {
		return nil, bt.marshalErr
	}

	return bt.marshalBytes, nil
}

func (bt *backupMsTestHelper) EventReason() string {
	bt.eventLock.Lock()
	defer bt.eventLock.Unlock()

	return bt.eventReason
}

func (bt *backupMsTestHelper) EventMessage() string {
	bt.eventLock.Lock()
	defer bt.eventLock.Unlock()

	return bt.eventMsg
}

func TestOnDataUploadFailed(t *testing.T) {
	dataUploadName := "fake-data-upload"
	bt := &backupMsTestHelper{}

	bs := &BackupMicroService{
		dataUploadName: dataUploadName,
		dataPathMgr:    datapath.NewManager(1),
		eventRecorder:  bt,
		resultSignal:   make(chan dataPathResult),
		logger:         velerotest.NewLogger(),
	}

	expectedErr := "Data path for data upload fake-data-upload failed: fake-error"
	expectedEventReason := datapath.EventReasonFailed
	expectedEventMsg := "Data path for data upload fake-data-upload failed, error fake-error"

	go bs.OnDataUploadFailed(t.Context(), velerov1api.DefaultNamespace, dataUploadName, errors.New("fake-error"))

	result := <-bs.resultSignal
	require.EqualError(t, result.err, expectedErr)
	assert.Equal(t, expectedEventReason, bt.EventReason())
	assert.Equal(t, expectedEventMsg, bt.EventMessage())
}

func TestOnDataUploadCancelled(t *testing.T) {
	dataUploadName := "fake-data-upload"
	bt := &backupMsTestHelper{}

	bs := &BackupMicroService{
		dataUploadName: dataUploadName,
		dataPathMgr:    datapath.NewManager(1),
		eventRecorder:  bt,
		resultSignal:   make(chan dataPathResult),
		logger:         velerotest.NewLogger(),
	}

	expectedErr := datapath.ErrCancelled
	expectedEventReason := datapath.EventReasonCancelled
	expectedEventMsg := "Data path for data upload fake-data-upload canceled"

	go bs.OnDataUploadCancelled(t.Context(), velerov1api.DefaultNamespace, dataUploadName)

	result := <-bs.resultSignal
	require.EqualError(t, result.err, expectedErr)
	assert.Equal(t, expectedEventReason, bt.EventReason())
	assert.Equal(t, expectedEventMsg, bt.EventMessage())
}

func TestOnDataUploadCompleted(t *testing.T) {
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
			expectedErr: "Failed to marshal backup result { false { } 0 0}: fake-marshal-error",
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
			dataUploadName := "fake-data-upload"

			bt := &backupMsTestHelper{
				marshalErr:   test.marshalErr,
				marshalBytes: []byte(test.marshallStr),
			}

			bs := &BackupMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: bt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewLogger(),
			}

			funcMarshal = bt.Marshal

			go bs.OnDataUploadCompleted(t.Context(), velerov1api.DefaultNamespace, dataUploadName, datapath.Result{})

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

func TestOnDataUploadProgress(t *testing.T) {
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
			expectedErr: "Failed to marshal backup result",
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
			dataUploadName := "fake-data-upload"

			bt := &backupMsTestHelper{
				marshalErr:   test.marshalErr,
				marshalBytes: []byte(test.marshallStr),
			}

			bs := &BackupMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: bt,
				logger:        velerotest.NewLogger(),
			}

			funcMarshal = bt.Marshal

			bs.OnDataUploadProgress(t.Context(), velerov1api.DefaultNamespace, dataUploadName, &uploader.Progress{})

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

func TestCancelDataUpload(t *testing.T) {
	tests := []struct {
		name                string
		expectedEventReason string
		expectedEventMsg    string
		expectedErr         string
	}{
		{
			name:                "no fs backup",
			expectedEventReason: datapath.EventReasonStopped,
			expectedEventMsg:    "Data path for fake-data-upload exited without start",
			expectedErr:         datapath.ErrCancelled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataUploadName := "fake-data-upload"
			du := builder.ForDataUpload(velerov1api.DefaultNamespace, dataUploadName).Result()

			bt := &backupMsTestHelper{}

			bs := &BackupMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: bt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewLogger(),
			}

			go bs.cancelDataUpload(du)

			result := <-bs.resultSignal

			require.EqualError(t, result.err, test.expectedErr)
			assert.True(t, bt.withEvent)
			assert.Equal(t, test.expectedEventReason, bt.EventReason())
			assert.Equal(t, test.expectedEventMsg, bt.EventMessage())
		})
	}
}

func TestRunCancelableDataPath(t *testing.T) {
	dataUploadName := "fake-data-upload"
	du := builder.ForDataUpload(velerov1api.DefaultNamespace, dataUploadName).Phase(velerov2alpha1api.DataUploadPhaseNew).Result()
	duInProgress := builder.ForDataUpload(velerov1api.DefaultNamespace, dataUploadName).Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result()
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
			name:        "no du",
			ctx:         ctxTimeout,
			expectedErr: "error waiting for du: context deadline exceeded",
		},
		{
			name:          "du not in in-progress",
			ctx:           ctxTimeout,
			kubeClientObj: []runtime.Object{du},
			expectedErr:   "error waiting for du: context deadline exceeded",
		},
		{
			name:          "create data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{duInProgress},
			dataPathMgr:   datapath.NewManager(0),
			expectedErr:   "error to create data path: Concurrent number exceeds",
		},
		{
			name:          "init data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{duInProgress},
			initErr:       errors.New("fake-init-error"),
			expectedErr:   "error to initialize data path: fake-init-error",
		},
		{
			name:          "start data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{duInProgress},
			startErr:      errors.New("fake-start-error"),
			expectedErr:   "error starting data path backup: fake-start-error",
		},
		{
			name:             "data path timeout",
			ctx:              ctxTimeout,
			kubeClientObj:    []runtime.Object{duInProgress},
			dataPathStarted:  true,
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", dataUploadName),
			expectedErr:      "timed out waiting for fs backup to complete",
		},
		{
			name:            "data path returns error",
			ctx:             t.Context(),
			kubeClientObj:   []runtime.Object{duInProgress},
			dataPathStarted: true,
			result: &dataPathResult{
				err: errors.New("fake-data-path-error"),
			},
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", dataUploadName),
			expectedErr:      "fake-data-path-error",
		},
		{
			name:            "succeed",
			ctx:             t.Context(),
			kubeClientObj:   []runtime.Object{duInProgress},
			dataPathStarted: true,
			result: &dataPathResult{
				result: "fake-succeed-result",
			},
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", dataUploadName),
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

			bs := &BackupMicroService{
				namespace:      velerov1api.DefaultNamespace,
				dataUploadName: dataUploadName,
				ctx:            t.Context(),
				client:         fakeClient,
				dataPathMgr:    datapath.NewManager(1),
				eventRecorder:  bt,
				resultSignal:   make(chan dataPathResult),
				logger:         velerotest.NewLogger(),
			}

			if test.ctx != nil {
				bs.ctx = test.ctx
			}

			if test.dataPathMgr != nil {
				bs.dataPathMgr = test.dataPathMgr
			}

			datapath.FSBRCreator = func(string, string, kbclient.Client, string, datapath.Callbacks, logrus.FieldLogger) datapath.AsyncBR {
				fsBR := datapathmockes.NewAsyncBR(t)
				if test.initErr != nil {
					fsBR.On("Init", mock.Anything, mock.Anything).Return(test.initErr)
				}

				if test.startErr != nil {
					fsBR.On("Init", mock.Anything, mock.Anything).Return(nil)
					fsBR.On("StartBackup", mock.Anything, mock.Anything, mock.Anything).Return(test.startErr)
				}

				if test.dataPathStarted {
					fsBR.On("Init", mock.Anything, mock.Anything).Return(nil)
					fsBR.On("StartBackup", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				}

				return fsBR
			}

			if test.result != nil {
				go func() {
					time.Sleep(time.Millisecond * 500)
					bs.resultSignal <- *test.result
				}()
			}

			result, err := bs.RunCancelableDataPath(test.ctx)

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
