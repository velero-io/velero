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
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
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

	velerotest "github.com/vmware-tanzu/velero/pkg/test"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	datapathmockes "github.com/vmware-tanzu/velero/pkg/datapath/mocks"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type restoreMsTestHelper struct {
	eventReason        string
	eventMsg           string
	marshalErr         error
	marshalBytes       []byte
	withEvent          bool
	eventLock          sync.Mutex
	writeCompletionErr error
}

func (rt *restoreMsTestHelper) Event(_ runtime.Object, _ bool, reason string, message string, a ...any) {
	rt.eventLock.Lock()
	defer rt.eventLock.Unlock()

	rt.withEvent = true
	rt.eventReason = reason
	rt.eventMsg = fmt.Sprintf(message, a...)
}

func (rt *restoreMsTestHelper) EndingEvent(_ runtime.Object, _ bool, reason string, message string, a ...any) {
	rt.eventLock.Lock()
	defer rt.eventLock.Unlock()

	rt.withEvent = true
	rt.eventReason = reason
	rt.eventMsg = fmt.Sprintf(message, a...)
}
func (rt *restoreMsTestHelper) Shutdown() {}

func (rt *restoreMsTestHelper) Marshal(v any) ([]byte, error) {
	if rt.marshalErr != nil {
		return nil, rt.marshalErr
	}

	return rt.marshalBytes, nil
}

func (rt *restoreMsTestHelper) EventReason() string {
	rt.eventLock.Lock()
	defer rt.eventLock.Unlock()

	return rt.eventReason
}

func (rt *restoreMsTestHelper) EventMessage() string {
	rt.eventLock.Lock()
	defer rt.eventLock.Unlock()

	return rt.eventMsg
}

func (rt *restoreMsTestHelper) WriteCompletionMark(*velerov1api.PodVolumeRestore, datapath.RestoreResult, logrus.FieldLogger) error {
	return rt.writeCompletionErr
}

func TestOnPvrFailed(t *testing.T) {
	pvrName := "fake-pvr"
	rt := &restoreMsTestHelper{}

	rs := &RestoreMicroService{
		pvrName:       pvrName,
		dataPathMgr:   datapath.NewManager(1),
		eventRecorder: rt,
		resultSignal:  make(chan dataPathResult),
		logger:        velerotest.NewLogger(),
	}

	expectedErr := "Data path for PVR fake-pvr failed: fake-error"
	expectedEventReason := datapath.EventReasonFailed
	expectedEventMsg := "Data path for PVR fake-pvr failed, error fake-error"

	go rs.OnPvrFailed(t.Context(), velerov1api.DefaultNamespace, pvrName, errors.New("fake-error"))

	result := <-rs.resultSignal
	require.EqualError(t, result.err, expectedErr)
	assert.Equal(t, expectedEventReason, rt.EventReason())
	assert.Equal(t, expectedEventMsg, rt.EventMessage())
}

func TestPvrCancelled(t *testing.T) {
	pvrName := "fake-pvr"
	rt := &restoreMsTestHelper{}

	rs := RestoreMicroService{
		pvrName:       pvrName,
		dataPathMgr:   datapath.NewManager(1),
		eventRecorder: rt,
		resultSignal:  make(chan dataPathResult),
		logger:        velerotest.NewLogger(),
	}

	expectedErr := datapath.ErrCancelled
	expectedEventReason := datapath.EventReasonCancelled
	expectedEventMsg := "Data path for PVR fake-pvr canceled"

	go rs.OnPvrCancelled(t.Context(), velerov1api.DefaultNamespace, pvrName)

	result := <-rs.resultSignal
	require.EqualError(t, result.err, expectedErr)
	assert.Equal(t, expectedEventReason, rt.EventReason())
	assert.Equal(t, expectedEventMsg, rt.EventMessage())
}

func TestOnPvrCompleted(t *testing.T) {
	tests := []struct {
		name                string
		expectedErr         string
		expectedEventReason string
		expectedEventMsg    string
		marshalErr          error
		marshallStr         string
		writeCompletionErr  error
		expectedLog         string
	}{
		{
			name:        "marshal fail",
			marshalErr:  errors.New("fake-marshal-error"),
			expectedErr: "error marshaling restore result {{ } 0}: fake-marshal-error",
		},
		{
			name:                "succeed",
			marshallStr:         "fake-complete-string",
			expectedEventReason: datapath.EventReasonCompleted,
			expectedEventMsg:    "fake-complete-string",
		},
		{
			name:                "succeed but write completion mark fail",
			marshallStr:         "fake-complete-string",
			writeCompletionErr:  errors.New("fake-write-completion-error"),
			expectedEventReason: datapath.EventReasonCompleted,
			expectedEventMsg:    "fake-complete-string",
			expectedLog:         "Failed to write completion mark, restored pod may failed to start",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pvrName := "fake-pvr"

			rt := &restoreMsTestHelper{
				marshalErr:         test.marshalErr,
				marshalBytes:       []byte(test.marshallStr),
				writeCompletionErr: test.writeCompletionErr,
			}

			logBuffer := []string{}

			rs := &RestoreMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: rt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewMultipleLogger(&logBuffer),
			}

			funcMarshal = rt.Marshal
			funcWriteCompletionMark = rt.WriteCompletionMark

			go rs.OnPvrCompleted(t.Context(), velerov1api.DefaultNamespace, pvrName, datapath.Result{})

			result := <-rs.resultSignal
			if test.marshalErr != nil {
				assert.EqualError(t, result.err, test.expectedErr)
			} else {
				require.NoError(t, result.err)
				assert.Equal(t, test.expectedEventReason, rt.EventReason())
				assert.Equal(t, test.expectedEventMsg, rt.EventMessage())

				if test.expectedLog != "" {
					assert.Contains(t, logBuffer[0], test.expectedLog)
				}
			}
		})
	}
}

func TestOnPvrProgress(t *testing.T) {
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
			expectedErr: "Failed to marshal restore result",
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
			pvrName := "fake-pvr"

			rt := &restoreMsTestHelper{
				marshalErr:   test.marshalErr,
				marshalBytes: []byte(test.marshallStr),
			}

			rs := &RestoreMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: rt,
				logger:        velerotest.NewLogger(),
			}

			funcMarshal = rt.Marshal

			rs.OnPvrProgress(t.Context(), velerov1api.DefaultNamespace, pvrName, &uploader.Progress{})

			if test.marshalErr != nil {
				assert.False(t, rt.withEvent)
			} else {
				assert.True(t, rt.withEvent)
				assert.Equal(t, test.expectedEventReason, rt.EventReason())
				assert.Equal(t, test.expectedEventMsg, rt.EventMessage())
			}
		})
	}
}

func TestCancelPodVolumeRestore(t *testing.T) {
	tests := []struct {
		name                string
		expectedEventReason string
		expectedEventMsg    string
		expectedErr         string
	}{
		{
			name:                "no fs restore",
			expectedEventReason: datapath.EventReasonStopped,
			expectedEventMsg:    "Data path for fake-pvr exited without start",
			expectedErr:         datapath.ErrCancelled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pvrName := "fake-pvr"
			pvr := builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Result()

			rt := &restoreMsTestHelper{}

			rs := &RestoreMicroService{
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: rt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewLogger(),
			}

			go rs.cancelPodVolumeRestore(pvr)

			result := <-rs.resultSignal

			require.EqualError(t, result.err, test.expectedErr)
			assert.True(t, rt.withEvent)
			assert.Equal(t, test.expectedEventReason, rt.EventReason())
			assert.Equal(t, test.expectedEventMsg, rt.EventMessage())
		})
	}
}

func TestRunCancelableDataPathRestore(t *testing.T) {
	pvrName := "fake-pvr"
	pvr := builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseNew).Result()
	pvrInProgress := builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result()
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
			name:        "no pvr",
			ctx:         ctxTimeout,
			expectedErr: "error waiting for PVR: context deadline exceeded",
		},
		{
			name:          "pvr not in in-progress",
			ctx:           ctxTimeout,
			kubeClientObj: []runtime.Object{pvr},
			expectedErr:   "error waiting for PVR: context deadline exceeded",
		},
		{
			name:          "create data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{pvrInProgress},
			dataPathMgr:   datapath.NewManager(0),
			expectedErr:   "error to create data path: Concurrent number exceeds",
		},
		{
			name:          "init data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{pvrInProgress},
			initErr:       errors.New("fake-init-error"),
			expectedErr:   "error to initialize data path: fake-init-error",
		},
		{
			name:          "start data path fail",
			ctx:           t.Context(),
			kubeClientObj: []runtime.Object{pvrInProgress},
			startErr:      errors.New("fake-start-error"),
			expectedErr:   "error starting data path restore: fake-start-error",
		},
		{
			name:             "data path timeout",
			ctx:              ctxTimeout,
			kubeClientObj:    []runtime.Object{pvrInProgress},
			dataPathStarted:  true,
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", pvrName),
			expectedErr:      "timed out waiting for fs restore to complete",
		},
		{
			name:            "data path returns error",
			ctx:             t.Context(),
			kubeClientObj:   []runtime.Object{pvrInProgress},
			dataPathStarted: true,
			result: &dataPathResult{
				err: errors.New("fake-data-path-error"),
			},
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", pvrName),
			expectedErr:      "fake-data-path-error",
		},
		{
			name:            "succeed",
			ctx:             t.Context(),
			kubeClientObj:   []runtime.Object{pvrInProgress},
			dataPathStarted: true,
			result: &dataPathResult{
				result: "fake-succeed-result",
			},
			expectedEventMsg: fmt.Sprintf("Data path for %s stopped", pvrName),
		},
	}

	scheme := runtime.NewScheme()
	velerov1api.AddToScheme(scheme)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClientBuilder := clientFake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(scheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			rt := &restoreMsTestHelper{}

			rs := &RestoreMicroService{
				namespace:     velerov1api.DefaultNamespace,
				pvrName:       pvrName,
				ctx:           t.Context(),
				client:        fakeClient,
				dataPathMgr:   datapath.NewManager(1),
				eventRecorder: rt,
				resultSignal:  make(chan dataPathResult),
				logger:        velerotest.NewLogger(),
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
				assert.True(t, rt.withEvent)
				assert.Equal(t, test.expectedEventMsg, rt.EventMessage())
			}
		})
	}

	cancel()
}

func TestWriteCompletionMark(t *testing.T) {
	tests := []struct {
		name          string
		pvr           *velerov1api.PodVolumeRestore
		result        datapath.RestoreResult
		funcRemoveAll func(string) error
		funcMkdirAll  func(string, os.FileMode) error
		funcWriteFile func(string, []byte, os.FileMode) error
		expectedErr   string
		expectedLog   string
	}{
		{
			name:        "no volume path",
			result:      datapath.RestoreResult{},
			expectedErr: "target volume is empty in restore result",
		},
		{
			name: "no owner reference",
			result: datapath.RestoreResult{
				Target: datapath.AccessPoint{
					ByPath: "fake-volume-path",
				},
			},
			pvr: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, "fake-pvr").Result(),
			funcRemoveAll: func(string) error {
				return nil
			},
			expectedErr: "error finding restore UID",
		},
		{
			name: "mkdir fail",
			result: datapath.RestoreResult{
				Target: datapath.AccessPoint{
					ByPath: "fake-volume-path",
				},
			},
			pvr: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, "fake-pvr").OwnerReference([]metav1.OwnerReference{
				{
					UID: "fake-uid",
				},
			}).Result(),
			funcRemoveAll: func(string) error {
				return nil
			},
			funcMkdirAll: func(string, os.FileMode) error {
				return errors.New("fake-mk-dir-error")
			},
			expectedErr: "error creating .velero directory for done file: fake-mk-dir-error",
		},
		{
			name: "write file fail",
			result: datapath.RestoreResult{
				Target: datapath.AccessPoint{
					ByPath: "fake-volume-path",
				},
			},
			pvr: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, "fake-pvr").OwnerReference([]metav1.OwnerReference{
				{
					UID: "fake-uid",
				},
			}).Result(),
			funcRemoveAll: func(string) error {
				return nil
			},
			funcMkdirAll: func(string, os.FileMode) error {
				return nil
			},
			funcWriteFile: func(string, []byte, os.FileMode) error {
				return errors.New("fake-write-file-error")
			},
			expectedErr: "error writing done file: fake-write-file-error",
		},
		{
			name: "succeed",
			result: datapath.RestoreResult{
				Target: datapath.AccessPoint{
					ByPath: "fake-volume-path",
				},
			},
			pvr: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, "fake-pvr").OwnerReference([]metav1.OwnerReference{
				{
					UID: "fake-uid",
				},
			}).Result(),
			funcRemoveAll: func(string) error {
				return nil
			},
			funcMkdirAll: func(string, os.FileMode) error {
				return nil
			},
			funcWriteFile: func(string, []byte, os.FileMode) error {
				return nil
			},
		},
		{
			name: "succeed but previous dir is not removed",
			result: datapath.RestoreResult{
				Target: datapath.AccessPoint{
					ByPath: "fake-volume-path",
				},
			},
			pvr: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, "fake-pvr").OwnerReference([]metav1.OwnerReference{
				{
					UID: "fake-uid",
				},
			}).Result(),
			funcRemoveAll: func(string) error {
				return errors.New("fake-remove-dir-error")
			},
			funcMkdirAll: func(string, os.FileMode) error {
				return nil
			},
			funcWriteFile: func(string, []byte, os.FileMode) error {
				return nil
			},
			expectedLog: "Failed to remove .velero directory from directory fake-volume-path",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.funcRemoveAll != nil {
				funcRemoveAll = test.funcRemoveAll
			}

			if test.funcMkdirAll != nil {
				funcMkdirAll = test.funcMkdirAll
			}

			if test.funcWriteFile != nil {
				funcWriteFile = test.funcWriteFile
			}

			logBuffer := ""
			err := writeCompletionMark(test.pvr, test.result, velerotest.NewSingleLogger(&logBuffer))

			if test.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.expectedErr)
			}

			if test.expectedLog != "" {
				assert.Contains(t, logBuffer, test.expectedLog)
			}
		})
	}
}
