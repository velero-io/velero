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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubeclientfake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/velero-io/velero/pkg/builder"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/uploader"
	"github.com/velero-io/velero/pkg/util/logging"
)

func TestReEnsureThisPod(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		thisPod       string
		kubeClientObj []runtime.Object
		expectChan    bool
		expectErr     string
	}{
		{
			name:      "get pod error",
			thisPod:   "fak-pod-1",
			expectErr: "error getting this pod fak-pod-1: pods \"fak-pod-1\" not found",
		},
		{
			name:      "get pod not in terminated state",
			namespace: "velero",
			thisPod:   "fake-pod-1",
			kubeClientObj: []runtime.Object{
				builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodRunning).Result(),
			},
		},
		{
			name:      "get pod succeed state",
			namespace: "velero",
			thisPod:   "fake-pod-1",
			kubeClientObj: []runtime.Object{
				builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			},
			expectChan: true,
		},
		{
			name:      "get pod failed state",
			namespace: "velero",
			thisPod:   "fake-pod-1",
			kubeClientObj: []runtime.Object{
				builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodFailed).Result(),
			},
			expectChan: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			corev1api.AddToScheme(scheme)
			fakeClientBuilder := fake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(scheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			ms := &microServiceBRWatcher{
				namespace: test.namespace,
				thisPod:   test.thisPod,
				client:    fakeClient,
				podCh:     make(chan *corev1api.Pod, 2),
				log:       velerotest.NewLogger(),
			}

			err := ms.reEnsureThisPod(t.Context())
			if test.expectErr != "" {
				assert.EqualError(t, err, test.expectErr)
			} else {
				if test.expectChan {
					require.Len(t, ms.podCh, 1)
					pod := <-ms.podCh
					assert.Equal(t, test.thisPod, pod.Name)
				}
			}
		})
	}
}

type startWatchFake struct {
	terminationMessage string
	redirectErr        error
	complete           bool
	failed             bool
	failedErr          error
	canceled           bool
	progress           int
}

func (sw *startWatchFake) getPodContainerTerminateMessage(pod *corev1api.Pod, container string) string {
	return sw.terminationMessage
}

func (sw *startWatchFake) redirectDataMoverLogs(ctx context.Context, kubeClient kubernetes.Interface, namespace string, thisPod string, thisContainer string, logger logrus.FieldLogger) error {
	return sw.redirectErr
}

func (sw *startWatchFake) getResultFromMessage(_ string, _ string, _ logrus.FieldLogger) Result {
	return Result{}
}

func (sw *startWatchFake) OnCompleted(ctx context.Context, namespace string, task string, result Result) {
	sw.complete = true
}

func (sw *startWatchFake) OnFailed(ctx context.Context, namespace string, task string, err error) {
	sw.failed = true
	sw.failedErr = err
}

func (sw *startWatchFake) OnCancelled(ctx context.Context, namespace string, task string) {
	sw.canceled = true
}

func (sw *startWatchFake) OnProgress(ctx context.Context, namespace string, task string, progress *uploader.Progress) {
	sw.progress++
}

type insertEvent struct {
	event *corev1api.Event
	after time.Duration
	delay time.Duration
}

func TestStartWatch(t *testing.T) {
	originalTerminationMessage := funcGetPodTerminationMessage
	originalRedirectLog := funcRedirectLog
	originalResult := funcGetResultFromMessage
	originalTimeout := eventWaitTimeout
	t.Cleanup(func() {
		funcGetPodTerminationMessage = originalTerminationMessage
		funcRedirectLog = originalRedirectLog
		funcGetResultFromMessage = originalResult
		eventWaitTimeout = originalTimeout
	})
	tests := []struct {
		name                 string
		namespace            string
		thisPod              string
		thisContainer        string
		terminationMessage   string
		redirectLogErr       error
		insertPod            *corev1api.Pod
		insertEventsBefore   []insertEvent
		insertEventsAfter    []insertEvent
		ctxCancel            bool
		expectStartEvent     bool
		expectTerminateEvent bool
		expectComplete       bool
		expectCancel         bool
		expectFail           bool
		expectFailMsg        string
		expectProgress       int
	}{
		{
			name:          "exit from ctx",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			ctxCancel:     true,
		},
		{
			name:          "completed with rantional sequence",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonCompleted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
					delay: time.Second,
				},
			},
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectComplete:       true,
			expectProgress:       1,
		},
		{
			name:          "completed",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonCompleted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
				},
			},
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectComplete:       true,
			expectProgress:       1,
		},
		{
			name:          "completed with redirect error",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonCompleted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
				},
			},
			redirectLogErr:       errors.New("fake-error"),
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectComplete:       true,
			expectProgress:       1,
		},
		{
			name:          "complete but terminated event not received in time",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
			},
			insertEventsAfter: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
					after: time.Second * 6,
				},
			},
			expectStartEvent: true,
			expectComplete:   true,
			expectProgress:   1,
		},
		{
			name:          "complete but terminated event not received immediately",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
			},
			insertEventsAfter: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonCompleted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
					delay: time.Second,
				},
			},
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectComplete:       true,
			expectProgress:       1,
		},
		{
			name:          "completed with progress",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodSucceeded).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonProgress, Message: "fake-progress-1"},
				},
				{
					event: &corev1api.Event{Reason: EventReasonProgress, Message: "fake-progress-2"},
				},
				{
					event: &corev1api.Event{Reason: EventReasonCompleted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
					delay: time.Second,
				},
			},
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectComplete:       true,
			expectProgress:       3,
		},
		{
			name:          "failed",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodFailed).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonCancelled},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
				},
			},
			terminationMessage:   "fake-termination-message-1",
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectFail:           true,
		},
		{
			name:               "pod crash",
			thisPod:            "fak-pod-1",
			thisContainer:      "fake-container-1",
			insertPod:          builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodFailed).Result(),
			terminationMessage: "fake-termination-message-2",
			expectFail:         true,
		},
		{
			name:          "canceled",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodFailed).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonCancelled},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
				},
			},
			terminationMessage:   fmt.Sprintf("Failed to init data path service for DataUpload %s: %v", "fake-du-name", errors.New(ErrCancelled)),
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectCancel:         true,
		},
		{
			name:          "evicted",
			thisPod:       "fak-pod-1",
			thisContainer: "fake-container-1",
			insertPod:     builder.ForPod("velero", "fake-pod-1").Phase(corev1api.PodFailed).Result(),
			insertEventsBefore: []insertEvent{
				{
					event: &corev1api.Event{Reason: EventReasonStarted},
				},
				{
					event: &corev1api.Event{Reason: EventReasonEvicted, Message: "fake-evicted-message"},
				},
				{
					event: &corev1api.Event{Reason: EventReasonStopped},
				},
			},
			expectStartEvent:     true,
			expectTerminateEvent: true,
			expectFail:           true,
			expectFailMsg:        "data path pod was evicted, message: fake-evicted-message",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			eventWaitTimeout = time.Second * 5

			sw := startWatchFake{
				terminationMessage: test.terminationMessage,
				redirectErr:        test.redirectLogErr,
			}
			funcGetPodTerminationMessage = sw.getPodContainerTerminateMessage
			funcRedirectLog = sw.redirectDataMoverLogs
			funcGetResultFromMessage = sw.getResultFromMessage

			ms := &microServiceBRWatcher{
				ctx:           ctx,
				namespace:     test.namespace,
				thisPod:       test.thisPod,
				thisContainer: test.thisContainer,
				podCh:         make(chan *corev1api.Pod, 2),
				eventCh:       make(chan *corev1api.Event, 10),
				log:           velerotest.NewLogger(),
				callbacks: Callbacks{
					OnCompleted: sw.OnCompleted,
					OnFailed:    sw.OnFailed,
					OnCancelled: sw.OnCancelled,
					OnProgress:  sw.OnProgress,
				},
			}

			ms.startWatch()

			if test.ctxCancel {
				cancel()
			}

			for _, ev := range test.insertEventsBefore {
				if ev.after != 0 {
					time.Sleep(ev.after)
				}

				ms.eventCh <- ev.event

				if ev.delay != 0 {
					time.Sleep(ev.delay)
				}
			}

			if test.insertPod != nil {
				ms.podCh <- test.insertPod
			}

			for _, ev := range test.insertEventsAfter {
				if ev.after != 0 {
					time.Sleep(ev.after)
				}

				ms.eventCh <- ev.event

				if ev.delay != 0 {
					time.Sleep(ev.delay)
				}
			}

			ms.wgWatcher.Wait()

			assert.Equal(t, test.expectStartEvent, ms.startedFromEvent.Load())
			assert.Equal(t, test.expectTerminateEvent, ms.terminatedFromEvent.Load())
			assert.Equal(t, test.expectComplete, sw.complete)
			assert.Equal(t, test.expectCancel, sw.canceled)
			assert.Equal(t, test.expectFail, sw.failed)
			if test.expectFailMsg != "" {
				require.EqualError(t, sw.failedErr, test.expectFailMsg)
			}
			assert.Equal(t, test.expectProgress, sw.progress)

			cancel()
		})
	}
}

func TestGetResultFromMessage(t *testing.T) {
	tests := []struct {
		name         string
		taskType     string
		message      string
		expectResult Result
	}{
		{
			name:         "error to unmarshall backup result",
			taskType:     TaskTypeBackup,
			message:      "fake-message",
			expectResult: Result{},
		},
		{
			name:         "error to unmarshall restore result",
			taskType:     TaskTypeRestore,
			message:      "fake-message",
			expectResult: Result{},
		},
		{
			name:     "succeed to unmarshall backup result",
			taskType: TaskTypeBackup,
			message:  "{\"snapshotID\":\"fake-snapshot-id\",\"emptySnapshot\":true,\"source\":{\"byPath\":\"fake-path-1\",\"volumeMode\":\"Block\"}}",
			expectResult: Result{
				Backup: BackupResult{
					SnapshotID:    "fake-snapshot-id",
					EmptySnapshot: true,
					Source: AccessPoint{
						ByPath:  "fake-path-1",
						VolMode: uploader.PersistentVolumeBlock,
					},
				},
			},
		},
		{
			// An old data mover (release-1.17 and earlier) predates IncrementalBytes and
			// never writes the key at all -- this pins that its absence unmarshals to nil
			// ("not measured"), not a zero value.
			name:     "old mover message omits incrementalBytes -> nil",
			taskType: TaskTypeBackup,
			message:  "{\"snapshotID\":\"fake-snapshot-id\",\"emptySnapshot\":false,\"source\":{\"byPath\":\"fake-path-1\",\"volumeMode\":\"Block\"}}",
			expectResult: Result{
				Backup: BackupResult{
					SnapshotID: "fake-snapshot-id",
					Source: AccessPoint{
						ByPath:  "fake-path-1",
						VolMode: uploader.PersistentVolumeBlock,
					},
					IncrementalBytes: nil,
				},
			},
		},
		{
			// A current mover reports a genuine zero explicitly -- this pins that the key
			// being present with value 0 unmarshals to a non-nil pointer to 0 ("measured
			// zero"), distinguishing it from the omitted-key case above.
			name:     "current mover reports measured zero incrementalBytes -> non-nil zero",
			taskType: TaskTypeBackup,
			message:  "{\"snapshotID\":\"fake-snapshot-id\",\"emptySnapshot\":false,\"source\":{\"byPath\":\"fake-path-1\",\"volumeMode\":\"Block\"},\"incrementalBytes\":0}",
			expectResult: Result{
				Backup: BackupResult{
					SnapshotID: "fake-snapshot-id",
					Source: AccessPoint{
						ByPath:  "fake-path-1",
						VolMode: uploader.PersistentVolumeBlock,
					},
					IncrementalBytes: ptr.To(int64(0)),
				},
			},
		},
		{
			name:     "succeed to unmarshall restore result",
			taskType: TaskTypeRestore,
			message:  "{\"target\":{\"byPath\":\"fake-path-2\",\"volumeMode\":\"Filesystem\"}}",
			expectResult: Result{
				Restore: RestoreResult{
					Target: AccessPoint{
						ByPath:  "fake-path-2",
						VolMode: uploader.PersistentVolumeFilesystem,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := getResultFromMessage(test.taskType, test.message, velerotest.NewLogger())
			assert.Equal(t, test.expectResult, result)
		})
	}
}

func TestGetProgressFromMessage(t *testing.T) {
	tests := []struct {
		name           string
		message        string
		expectProgress uploader.Progress
	}{
		{
			name:           "error to unmarshall progress",
			message:        "fake-message",
			expectProgress: uploader.Progress{},
		},
		{
			name:    "succeed to unmarshall progress",
			message: "{\"totalBytes\":1000,\"doneBytes\":200}",
			expectProgress: uploader.Progress{
				TotalBytes: 1000,
				BytesDone:  200,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			progress := getProgressFromMessage(test.message, velerotest.NewLogger())
			assert.Equal(t, test.expectProgress, *progress)
		})
	}
}

type redirectFake struct {
	logFile       *os.File
	createTempErr error
	getPodLogErr  error
	logMessage    string
}

func (rf *redirectFake) fakeCreateTempFile(_ string, _ string) (*os.File, error) {
	if rf.createTempErr != nil {
		return nil, rf.createTempErr
	}

	return rf.logFile, nil
}

func (rf *redirectFake) fakeCollectPodLogs(_ context.Context, _ corev1client.CoreV1Interface, _ string, _ string, _ string, output io.Writer) error {
	if rf.getPodLogErr != nil {
		return rf.getPodLogErr
	}

	_, err := output.Write([]byte(rf.logMessage))

	return err
}

func TestRedirectDataMoverLogs(t *testing.T) {
	logFileName := path.Join(os.TempDir(), "test-logger-file.log")

	var buffer string

	tests := []struct {
		name          string
		thisPod       string
		logMessage    string
		logger        logrus.FieldLogger
		createTempErr error
		collectLogErr error
		expectErr     string
	}{
		{
			name:          "error to create temp file",
			thisPod:       "fake-pod",
			createTempErr: errors.New("fake-create-temp-error"),
			logger:        velerotest.NewLogger(),
			expectErr:     "error to create temp file for data mover pod log: fake-create-temp-error",
		},
		{
			name:          "error to collect pod log",
			thisPod:       "fake-pod",
			collectLogErr: errors.New("fake-collect-log-error"),
			logger:        velerotest.NewLogger(),
			expectErr:     fmt.Sprintf("error to collect logs to %s for data mover pod fake-pod: fake-collect-log-error", logFileName),
		},
		{
			name:       "succeed",
			thisPod:    "fake-pod",
			logMessage: "fake-log-message-01\nfake-log-message-02\nfake-log-message-03\n",
			logger:     velerotest.NewSingleLoggerWithHooks(&buffer, logging.DefaultHooks(true)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buffer = ""

			logFile, err := os.Create(logFileName)
			require.NoError(t, err)

			rf := redirectFake{
				logFile:       logFile,
				createTempErr: test.createTempErr,
				getPodLogErr:  test.collectLogErr,
				logMessage:    test.logMessage,
			}

			funcCreateTemp = rf.fakeCreateTempFile
			funcCollectPodLogs = rf.fakeCollectPodLogs

			fakeKubeClient := kubeclientfake.NewSimpleClientset()

			err = redirectDataMoverLogs(t.Context(), fakeKubeClient, "", test.thisPod, "", test.logger)
			if test.expectErr != "" {
				assert.EqualError(t, err, test.expectErr)
			} else {
				require.NoError(t, err)

				assert.Contains(t, buffer, test.logMessage)
			}
		})
	}
}

func TestWatcherPodDeletion(t *testing.T) {
	for _, tombstone := range []bool{false, true} {
		t.Run(fmt.Sprint(tombstone), func(t *testing.T) {
			ms, handler := newPodHandlerTestWatcher(t)
			pod := builder.ForPod("velero", "pod").Phase(corev1api.PodRunning).Result()
			var obj any = pod
			if tombstone {
				obj = cache.DeletedFinalStateUnknown{Obj: pod}
			}
			handler.OnDelete("invalid deletion object")
			handler.OnDelete(cache.DeletedFinalStateUnknown{Obj: "invalid tombstone"})
			handler.OnDelete(builder.ForPod("other", "pod").Result())
			handler.OnDelete(builder.ForPod("velero", "other").Result())
			for _, phase := range []corev1api.PodPhase{corev1api.PodSucceeded, corev1api.PodFailed} {
				terminalPod := builder.ForPod("velero", "pod").Phase(phase).Result()
				var terminalObj any = terminalPod
				if tombstone {
					terminalObj = cache.DeletedFinalStateUnknown{Obj: terminalPod}
				}
				handler.OnDelete(terminalObj)
			}
			handler.OnUpdate(pod, pod)
			require.Empty(t, ms.podCh)
			handler.OnDelete(obj)
			got := <-ms.podCh
			assert.Equal(t, corev1api.PodFailed, got.Status.Phase)
			assert.Equal(t, "data path pod was deleted before completion", got.Status.Message)
			assert.Equal(t, corev1api.PodRunning, pod.Status.Phase)
		})
	}
}

func TestWatcherPodNotificationOnce(t *testing.T) {
	for _, first := range []string{"initial check", "update", "delete", "concurrent"} {
		t.Run(first, func(t *testing.T) {
			ms, handler := newPodHandlerTestWatcher(t)
			pod := builder.ForPod("velero", "pod").Phase(corev1api.PodSucceeded).Result()
			require.NoError(t, ms.client.Status().Update(t.Context(), pod))
			switch first {
			case "initial check":
				require.NoError(t, ms.reEnsureThisPod(t.Context()))
			case "update":
				handler.OnUpdate(pod, pod)
			case "delete":
				handler.OnDelete(cache.DeletedFinalStateUnknown{Obj: builder.ForPod("velero", "pod").Phase(corev1api.PodRunning).Result()})
			}
			var wg sync.WaitGroup
			errs := make(chan error, 20)
			for i := 0; i < 20; i++ {
				wg.Add(3)
				go func() { defer wg.Done(); handler.OnUpdate(pod, pod) }()
				go func() {
					defer wg.Done()
					handler.OnDelete(builder.ForPod("velero", "pod").Phase(corev1api.PodRunning).Result())
				}()
				go func() { defer wg.Done(); errs <- ms.reEnsureThisPod(t.Context()) }()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("duplicate pod observations blocked before watcher start")
			}
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
			require.Len(t, ms.podCh, 1)
			got := <-ms.podCh
			if first == "concurrent" {
				assert.Contains(t, []corev1api.PodPhase{corev1api.PodSucceeded, corev1api.PodFailed}, got.Status.Phase)
			} else if first == "delete" {
				assert.Equal(t, corev1api.PodFailed, got.Status.Phase)
			} else {
				assert.Equal(t, corev1api.PodSucceeded, got.Status.Phase)
			}
			// Consuming the notification must not allow later duplicates through.
			handler.OnUpdate(pod, pod)
			handler.OnDelete(pod)
			require.NoError(t, ms.reEnsureThisPod(t.Context()))
			assert.Empty(t, ms.podCh)
		})
	}
}

// Capture the handlers registered by Init so tests exercise informer callbacks.
type watcherTestInformer struct {
	ctrlcache.Informer
	handler cache.ResourceEventHandler
}

func (i *watcherTestInformer) AddEventHandler(h cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = h
	return nil, nil
}

type watcherTestCache struct {
	ctrlcache.Cache
	events, pods *watcherTestInformer
}

func (c *watcherTestCache) GetInformer(_ context.Context, obj client.Object, _ ...ctrlcache.InformerGetOption) (ctrlcache.Informer, error) {
	if _, ok := obj.(*corev1api.Pod); ok {
		return c.pods, nil
	}
	return c.events, nil
}

type watcherTestManager struct {
	manager.Manager
	cache ctrlcache.Cache
}

func (m *watcherTestManager) GetCache() ctrlcache.Cache { return m.cache }
func newPodHandlerTestWatcher(t *testing.T) (*microServiceBRWatcher, cache.ResourceEventHandler) {
	t.Helper()
	c := &watcherTestCache{events: &watcherTestInformer{}, pods: &watcherTestInformer{}}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1api.AddToScheme(scheme))
	pod := builder.ForPod("velero", "pod").Phase(corev1api.PodRunning).Result()
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	ms := newMicroServiceBRWatcher(cl, nil, &watcherTestManager{cache: c}, TaskTypeBackup, "task", "velero", "pod", "container", "task", Callbacks{}, velerotest.NewLogger()).(*microServiceBRWatcher)
	require.NoError(t, ms.Init(t.Context(), nil))
	t.Cleanup(func() { ms.Close(context.Background()) })
	return ms, c.pods.handler
}

func TestWatcherInitialPodMissing(t *testing.T) {
	c := &watcherTestCache{events: &watcherTestInformer{}, pods: &watcherTestInformer{}}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1api.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	ms := newMicroServiceBRWatcher(cl, nil, &watcherTestManager{cache: c}, TaskTypeBackup, "task", "velero", "pod", "container", "task", Callbacks{}, velerotest.NewLogger()).(*microServiceBRWatcher)
	defer ms.Close(t.Context())
	require.EqualError(t, ms.Init(t.Context(), nil), "error getting this pod pod: pods \"pod\" not found")
	assert.Empty(t, ms.podCh)
}

func TestWatcherEventSendUnblockedByClose(t *testing.T) {
	for _, update := range []bool{false, true} {
		t.Run(fmt.Sprintf("update=%t", update), func(t *testing.T) {
			ms, _ := newPodHandlerTestWatcher(t)
			handler := ms.eventInformer.(*watcherTestInformer).handler
			evt := &corev1api.Event{InvolvedObject: corev1api.ObjectReference{Namespace: "velero", Name: "task"}}
			for i := 0; i < cap(ms.eventCh); i++ {
				handler.OnAdd(evt, false)
			}
			done := make(chan struct{})
			go func() {
				if update {
					handler.OnUpdate(evt, evt)
				} else {
					handler.OnAdd(evt, false)
				}
				close(done)
			}()
			ms.Close(t.Context())
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("event handler remained blocked after Close")
			}
			assert.Len(t, ms.eventCh, cap(ms.eventCh))
		})
	}
}

func TestWatcherPodDeletionCallsOnFailed(t *testing.T) {
	originalRedirectLog := funcRedirectLog
	originalTerminationMessage := funcGetPodTerminationMessage
	originalTimeout := eventWaitTimeout
	t.Cleanup(func() {
		funcRedirectLog = originalRedirectLog
		funcGetPodTerminationMessage = originalTerminationMessage
		eventWaitTimeout = originalTimeout
	})
	stub := &startWatchFake{}
	funcRedirectLog = stub.redirectDataMoverLogs
	funcGetPodTerminationMessage = stub.getPodContainerTerminateMessage
	eventWaitTimeout = 10 * time.Millisecond
	for _, tombstone := range []bool{false, true} {
		for _, stoppedEvent := range []bool{false, true} {
			t.Run(fmt.Sprintf("tombstone=%t/stopped=%t", tombstone, stoppedEvent), func(t *testing.T) {
				ms, handler := newPodHandlerTestWatcher(t)
				calls := 0
				ms.callbacks.OnFailed = func(ctx context.Context, namespace, task string, err error) {
					assert.NoError(t, ctx.Err())
					assert.Equal(t, "velero", namespace)
					assert.Equal(t, "task", task)
					assert.EqualError(t, err, "data path pod was deleted before completion")
					calls++
				}
				ms.callbacks.OnCompleted = func(context.Context, string, string, Result) { t.Error("unexpected completion") }
				ms.callbacks.OnCancelled = func(context.Context, string, string) { t.Error("unexpected cancellation") }
				ms.callbacks.OnProgress = func(context.Context, string, string, *uploader.Progress) { t.Error("unexpected progress") }
				ms.eventCh <- &corev1api.Event{Reason: EventReasonStarted}
				if stoppedEvent {
					ms.eventCh <- &corev1api.Event{Reason: EventReasonStopped}
				}
				ms.startWatch()
				pod := builder.ForPod("velero", "pod").Phase(corev1api.PodRunning).Result()
				var obj any = pod
				if tombstone {
					obj = cache.DeletedFinalStateUnknown{Obj: pod}
				}
				handler.OnDelete(obj)
				handler.OnDelete(obj)
				done := make(chan struct{})
				go func() { ms.wgWatcher.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("watcher did not exit after deletion")
				}
				assert.Equal(t, 1, calls)
			})
		}
	}
}
