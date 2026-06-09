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

package kube

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	clientTesting "k8s.io/client-go/testing"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"

	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

func TestEnsureDeletePod(t *testing.T) {
	podObject := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-pod",
		},
	}

	podObjectWithFinalizer := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "fake-ns",
			Name:       "fake-pod",
			Finalizers: []string{"fake-finalizer-1", "fake-finalizer-2"},
		},
	}

	tests := []struct {
		name      string
		clientObj []runtime.Object
		podName   string
		namespace string
		reactors  []reactor
		err       string
	}{
		{
			name:      "delete fail",
			podName:   "fake-pod",
			namespace: "fake-ns",
			err:       "error to delete pod fake-pod: pods \"fake-pod\" not found",
		},
		{
			name:      "wait timeout",
			podName:   "fake-pod",
			namespace: "fake-ns",
			clientObj: []runtime.Object{podObjectWithFinalizer},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, nil
					},
				},
			},
			err: "timeout to assure pod fake-pod is deleted, finalizers in pod [fake-finalizer-1 fake-finalizer-2]",
		},
		{
			name:      "wait timeout, no finalizer",
			podName:   "fake-pod",
			namespace: "fake-ns",
			clientObj: []runtime.Object{podObject},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, nil
					},
				},
			},
			err: "timeout to assure pod fake-pod is deleted, finalizers in pod []",
		},
		{
			name:      "wait fail",
			podName:   "fake-pod",
			namespace: "fake-ns",
			clientObj: []runtime.Object{podObject},
			reactors: []reactor{
				{
					verb:     "get",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-get-error")
					},
				},
			},
			err: "error to assure pod is deleted, fake-pod: error to get pod fake-pod: fake-get-error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeKubeClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			var kubeClient kubernetes.Interface = fakeKubeClient

			err := EnsureDeletePod(t.Context(), kubeClient.CoreV1(), test.podName, test.namespace, time.Millisecond)
			if err != nil {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsPodRunning(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1api.Pod
		err  string
	}{
		{
			name: "pod is nil",
			err:  "invalid input pod",
		},
		{
			name: "pod is not scheduled",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Status: corev1api.PodStatus{
					Phase: "fake-phase",
				},
			},
			err: "pod is not scheduled, name=fake-pod, namespace=fake-ns, phase=fake-phase",
		},
		{
			name: "pod is not running",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: "fake-phase",
				},
			},
			err: "pod is not in the expected status, name=fake-pod, namespace=fake-ns, phase=fake-phase: pod is not running",
		},
		{
			name: "pod is being deleted",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "fake-ns",
					Name:              "fake-pod",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodRunning,
				},
			},
			err: "pod is being terminated, name=fake-pod, namespace=fake-ns, phase=Running",
		},
		{
			name: "success",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodRunning,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := IsPodRunning(test.pod)
			if err != nil {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsPodScheduled(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1api.Pod
		err  string
	}{
		{
			name: "pod is nil",
			err:  "invalid input pod",
		},
		{
			name: "pod is not scheduled",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Status: corev1api.PodStatus{
					Phase: "fake-phase",
				},
			},
			err: "pod is not scheduled, name=fake-pod, namespace=fake-ns, phase=fake-phase",
		},
		{
			name: "pod is not running or pending",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: "fake-phase",
				},
			},
			err: "pod is not in the expected status, name=fake-pod, namespace=fake-ns, phase=fake-phase: pod is not running or pending",
		},
		{
			name: "pod is being deleted",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "fake-ns",
					Name:              "fake-pod",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodRunning,
				},
			},
			err: "pod is being terminated, name=fake-pod, namespace=fake-ns, phase=Running",
		},
		{
			name: "success on running",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodRunning,
				},
			},
		},
		{
			name: "success on pending",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodPending,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := IsPodScheduled(test.pod)
			if err != nil {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeletePodIfAny(t *testing.T) {
	tests := []struct {
		name          string
		podName       string
		podNamespace  string
		kubeClientObj []runtime.Object
		kubeReactors  []reactor
		logMessage    string
		logLevel      string
		logError      string
	}{
		{
			name:         "get fail",
			podName:      "fake-pod",
			podNamespace: "fake-namespace",
			logMessage:   "Abort deleting pod, it doesn't exist fake-namespace/fake-pod",
			logLevel:     "level=debug",
		},
		{
			name:         "delete fail",
			podName:      "fake-pod",
			podNamespace: "fake-namespace",
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			logMessage: "Failed to delete pod fake-namespace/fake-pod",
			logLevel:   "level=error",
			logError:   "error=fake-delete-error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			for _, reactor := range test.kubeReactors {
				fakeKubeClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			var kubeClient kubernetes.Interface = fakeKubeClient

			logMessage := ""
			DeletePodIfAny(t.Context(), kubeClient.CoreV1(), test.podName, test.podNamespace, velerotest.NewSingleLogger(&logMessage))

			if len(test.logMessage) > 0 {
				assert.Contains(t, logMessage, test.logMessage)
			}

			if len(test.logLevel) > 0 {
				assert.Contains(t, logMessage, test.logLevel)
			}

			if len(test.logError) > 0 {
				assert.Contains(t, logMessage, test.logError)
			}
		})
	}
}

func TestIsPodUnrecoverable(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1api.Pod
		want bool
	}{
		{
			name: "pod is in failed state",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					Phase: corev1api.PodFailed,
				},
			},
			want: true,
		},
		{
			name: "pod is in unknown state",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					Phase: corev1api.PodUnknown,
				},
			},
			want: true,
		},
		{
			name: "container image pull failure",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{State: corev1api.ContainerState{Waiting: &corev1api.ContainerStateWaiting{Reason: "ImagePullBackOff"}}},
					},
				},
			},
			want: true,
		},
		{
			name: "container image pull failure with different reason",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{State: corev1api.ContainerState{Waiting: &corev1api.ContainerStateWaiting{Reason: "ErrImageNeverPull"}}},
					},
				},
			},
			want: true,
		},
		{
			name: "container image pull failure with different reason",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{State: corev1api.ContainerState{Waiting: &corev1api.ContainerStateWaiting{Reason: "OtherReason"}}},
					},
				},
			},
			want: false,
		},
		{
			name: "pod is normal",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					Phase: corev1api.PodRunning,
					ContainerStatuses: []corev1api.ContainerStatus{
						{Ready: true, State: corev1api.ContainerState{Running: &corev1api.ContainerStateRunning{}}},
					},
				},
			},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := IsPodUnrecoverable(test.pod, velerotest.NewLogger())
			assert.Equal(t, test.want, got)
		})
	}
}

func TestGetPodTerminateMessage(t *testing.T) {
	tests := []struct {
		name    string
		pod     *corev1api.Pod
		message string
	}{
		{
			name: "empty message when no container status",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					Phase: corev1api.PodFailed,
				},
			},
		},
		{
			name: "empty message when no termination status",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Waiting: &corev1api.ContainerStateWaiting{Reason: "ImagePullBackOff"}}},
					},
				},
			},
		},
		{
			name: "empty message when no termination message",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Reason: "fake-reason"}}},
					},
				},
			},
		},
		{
			name: "with termination message",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-1"}}},
						{Name: "container-2", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-2"}}},
						{Name: "container-3", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-3"}}},
					},
				},
			},
			message: "message-1/message-2/message-3/",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := GetPodTerminateMessage(test.pod)
			assert.Equal(t, test.message, message)
		})
	}
}

func TestGetPodContainerTerminateMessage(t *testing.T) {
	tests := []struct {
		name      string
		pod       *corev1api.Pod
		container string
		message   string
	}{
		{
			name: "empty message when no container status",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					Phase: corev1api.PodFailed,
				},
			},
		},
		{
			name: "empty message when no termination status",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Waiting: &corev1api.ContainerStateWaiting{Reason: "ImagePullBackOff"}}},
					},
				},
			},
			container: "container-1",
		},
		{
			name: "empty message when no termination message",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Reason: "fake-reason"}}},
					},
				},
			},
			container: "container-1",
		},
		{
			name: "not matched container name",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-1"}}},
						{Name: "container-2", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-2"}}},
						{Name: "container-3", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-3"}}},
					},
				},
			},
			container: "container-0",
		},
		{
			name: "with termination message",
			pod: &corev1api.Pod{
				Status: corev1api.PodStatus{
					ContainerStatuses: []corev1api.ContainerStatus{
						{Name: "container-1", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-1"}}},
						{Name: "container-2", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-2"}}},
						{Name: "container-3", State: corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{Message: "message-3"}}},
					},
				},
			},
			container: "container-2",
			message:   "message-2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := GetPodContainerTerminateMessage(test.pod, test.container)
			assert.Equal(t, test.message, message)
		})
	}
}

type fakePodLog struct {
	getError        error
	readError       error
	beginWriteError error
	endWriteError   error
	writeError      error
	logMessage      string
	outputMessage   string
	readPos         int
}

func (fp *fakePodLog) GetPodLogReader(ctx context.Context, podGetter corev1client.CoreV1Interface, pod string, namespace string, logOptions *corev1api.PodLogOptions) (io.ReadCloser, error) {
	if fp.getError != nil {
		return nil, fp.getError
	}

	return fp, nil
}

func (fp *fakePodLog) Read(p []byte) (n int, err error) {
	if fp.readError != nil {
		return -1, fp.readError
	}

	if fp.readPos == len(fp.logMessage) {
		return 0, io.EOF
	}

	copy(p, []byte(fp.logMessage))
	fp.readPos += len(fp.logMessage)

	return len(fp.logMessage), nil
}

func (fp *fakePodLog) Close() error {
	return nil
}

func (fp *fakePodLog) Write(p []byte) (n int, err error) {
	message := string(p)
	if strings.Contains(message, "begin pod logs") {
		if fp.beginWriteError != nil {
			return -1, fp.beginWriteError
		}
	} else if strings.Contains(message, "end pod logs") {
		if fp.endWriteError != nil {
			return -1, fp.endWriteError
		}
	} else {
		if fp.writeError != nil {
			return -1, fp.writeError
		}
	}

	fp.outputMessage += message

	return len(message), nil
}

func TestCollectPodLogs(t *testing.T) {
	tests := []struct {
		name            string
		pod             string
		container       string
		getError        error
		readError       error
		beginWriteError error
		endWriteError   error
		writeError      error
		readMessage     string
		message         string
		expectErr       string
	}{
		{
			name:            "error to write begin indicator",
			beginWriteError: errors.New("fake-write-error-01"),
			expectErr:       "error to write begin pod log indicator: fake-write-error-01",
		},
		{
			name:      "error to get log",
			pod:       "fake-pod",
			container: "fake-container",
			getError:  errors.New("fake-get-error"),
			message:   "***************************begin pod logs[fake-pod/fake-container]***************************\nNo present log retrieved, err: fake-get-error\n***************************end pod logs[fake-pod/fake-container]***************************\n",
		},
		{
			name:      "error to read pod log",
			pod:       "fake-pod",
			container: "fake-container",
			readError: errors.New("fake-read-error"),
			expectErr: "error to copy input: fake-read-error",
		},
		{
			name:        "error to write pod log",
			pod:         "fake-pod",
			container:   "fake-container",
			writeError:  errors.New("fake-write-error-03"),
			readMessage: "fake pod message 01\n fake pod message 02\n fake pod message 03\n",
			expectErr:   "error to copy input: fake-write-error-03",
		},
		{
			name:          "error to write end indicator",
			pod:           "fake-pod",
			container:     "fake-container",
			endWriteError: errors.New("fake-write-error-02"),
			readMessage:   "fake pod message 01\n fake pod message 02\n fake pod message 03\n",
			expectErr:     "error to write end pod log indicator: fake-write-error-02",
		},
		{
			name:        "succeed",
			pod:         "fake-pod",
			container:   "fake-container",
			readMessage: "fake pod message 01\n fake pod message 02\n fake pod message 03\n",
			message:     "***************************begin pod logs[fake-pod/fake-container]***************************\nfake pod message 01\n fake pod message 02\n fake pod message 03\n***************************end pod logs[fake-pod/fake-container]***************************\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fp := &fakePodLog{
				getError:        test.getError,
				readError:       test.readError,
				beginWriteError: test.beginWriteError,
				endWriteError:   test.endWriteError,
				writeError:      test.writeError,
				logMessage:      test.readMessage,
			}
			podLogReaderGetter = fp.GetPodLogReader

			err := CollectPodLogs(t.Context(), nil, test.pod, "", test.container, fp)
			if test.expectErr != "" {
				assert.EqualError(t, err, test.expectErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, fp.outputMessage, test.message)
			}
		})
	}
}

func TestToSystemAffinity(t *testing.T) {
	tests := []struct {
		name           string
		loadAffinity   *LoadAffinity
		volumeTopology *corev1api.NodeSelector
		expected       *corev1api.Affinity
	}{
		{
			name: "loadAffinity is nil",
		},
		{
			name:         "loadAffinity is empty",
			loadAffinity: &LoadAffinity{},
		},
		{
			name: "with match label",
			loadAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"key-1": "value-1",
					},
				},
			},
			expected: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-1",
										Values:   []string{"value-1"},
										Operator: corev1api.NodeSelectorOpIn,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with match expression",
			loadAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"key-2": "value-2",
					},
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "key-3",
							Values:   []string{"value-3-1", "value-3-2"},
							Operator: metav1.LabelSelectorOpNotIn,
						},
						{
							Key:      "key-4",
							Values:   []string{"value-4-1", "value-4-2", "value-4-3"},
							Operator: metav1.LabelSelectorOpDoesNotExist,
						},
					},
				},
			},
			expected: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-2",
										Values:   []string{"value-2"},
										Operator: corev1api.NodeSelectorOpIn,
									},
									{
										Key:      "key-3",
										Values:   []string{"value-3-1", "value-3-2"},
										Operator: corev1api.NodeSelectorOpNotIn,
									},
									{
										Key:      "key-4",
										Values:   []string{"value-4-1", "value-4-2", "value-4-3"},
										Operator: corev1api.NodeSelectorOpDoesNotExist,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with multiple match labels are sorted by key",
			loadAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"key-c": "value-c",
						"key-a": "value-a",
						"key-b": "value-b",
					},
				},
			},
			expected: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-a",
										Values:   []string{"value-a"},
										Operator: corev1api.NodeSelectorOpIn,
									},
									{
										Key:      "key-b",
										Values:   []string{"value-b"},
										Operator: corev1api.NodeSelectorOpIn,
									},
									{
										Key:      "key-c",
										Values:   []string{"value-c"},
										Operator: corev1api.NodeSelectorOpIn,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with olume topology",
			volumeTopology: &corev1api.NodeSelector{
				NodeSelectorTerms: []corev1api.NodeSelectorTerm{
					{
						MatchExpressions: []corev1api.NodeSelectorRequirement{
							{
								Key:      "key-5",
								Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
							{
								Key:      "key-6",
								Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
						},
					},
					{
						MatchExpressions: []corev1api.NodeSelectorRequirement{
							{
								Key:      "key-7",
								Values:   []string{"value-7-1", "value-7-2", "value-7-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
							{
								Key:      "key-8",
								Values:   []string{"value-8-1", "value-8-2", "value-8-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
						},
					},
					{
						MatchFields: []corev1api.NodeSelectorRequirement{
							{
								Key:      "key-9",
								Values:   []string{"value-9-1", "value-9-2", "value-9-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
							{
								Key:      "key-a",
								Values:   []string{"value-a-1", "value-a-2", "value-a-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
						},
					},
				},
			},
			expected: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-5",
										Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-6",
										Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
								},
							},
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-7",
										Values:   []string{"value-7-1", "value-7-2", "value-7-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-8",
										Values:   []string{"value-8-1", "value-8-2", "value-8-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
								},
							},
							{
								MatchFields: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-9",
										Values:   []string{"value-9-1", "value-9-2", "value-9-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-a",
										Values:   []string{"value-a-1", "value-a-2", "value-a-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "with match expression and volume topology",
			loadAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"key-2": "value-2",
					},
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "key-3",
							Values:   []string{"value-3-1", "value-3-2"},
							Operator: metav1.LabelSelectorOpNotIn,
						},
						{
							Key:      "key-4",
							Values:   []string{"value-4-1", "value-4-2", "value-4-3"},
							Operator: metav1.LabelSelectorOpDoesNotExist,
						},
					},
				},
			},
			volumeTopology: &corev1api.NodeSelector{
				NodeSelectorTerms: []corev1api.NodeSelectorTerm{
					{
						MatchExpressions: []corev1api.NodeSelectorRequirement{
							{
								Key:      "key-5",
								Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
							{
								Key:      "key-6",
								Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
						},
					},
					{
						MatchExpressions: []corev1api.NodeSelectorRequirement{
							{
								Key:      "key-7",
								Values:   []string{"value-7-1", "value-7-2", "value-7-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
							{
								Key:      "key-8",
								Values:   []string{"value-8-1", "value-8-2", "value-8-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
						},
					},
					{
						MatchFields: []corev1api.NodeSelectorRequirement{
							{
								Key:      "key-9",
								Values:   []string{"value-9-1", "value-9-2", "value-9-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
							{
								Key:      "key-a",
								Values:   []string{"value-a-1", "value-a-2", "value-a-3"},
								Operator: corev1api.NodeSelectorOpGt,
							},
						},
					},
				},
			},
			expected: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-5",
										Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-6",
										Values:   []string{"value-5-1", "value-5-2", "value-5-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-2",
										Values:   []string{"value-2"},
										Operator: corev1api.NodeSelectorOpIn,
									},
									{
										Key:      "key-3",
										Values:   []string{"value-3-1", "value-3-2"},
										Operator: corev1api.NodeSelectorOpNotIn,
									},
									{
										Key:      "key-4",
										Values:   []string{"value-4-1", "value-4-2", "value-4-3"},
										Operator: corev1api.NodeSelectorOpDoesNotExist,
									},
								},
							},
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-7",
										Values:   []string{"value-7-1", "value-7-2", "value-7-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-8",
										Values:   []string{"value-8-1", "value-8-2", "value-8-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-2",
										Values:   []string{"value-2"},
										Operator: corev1api.NodeSelectorOpIn,
									},
									{
										Key:      "key-3",
										Values:   []string{"value-3-1", "value-3-2"},
										Operator: corev1api.NodeSelectorOpNotIn,
									},
									{
										Key:      "key-4",
										Values:   []string{"value-4-1", "value-4-2", "value-4-3"},
										Operator: corev1api.NodeSelectorOpDoesNotExist,
									},
								},
							},
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-2",
										Values:   []string{"value-2"},
										Operator: corev1api.NodeSelectorOpIn,
									},
									{
										Key:      "key-3",
										Values:   []string{"value-3-1", "value-3-2"},
										Operator: corev1api.NodeSelectorOpNotIn,
									},
									{
										Key:      "key-4",
										Values:   []string{"value-4-1", "value-4-2", "value-4-3"},
										Operator: corev1api.NodeSelectorOpDoesNotExist,
									},
								},
								MatchFields: []corev1api.NodeSelectorRequirement{
									{
										Key:      "key-9",
										Values:   []string{"value-9-1", "value-9-2", "value-9-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
									{
										Key:      "key-a",
										Values:   []string{"value-a-1", "value-a-2", "value-a-3"},
										Operator: corev1api.NodeSelectorOpGt,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			affinity := ToSystemAffinity(test.loadAffinity, test.volumeTopology)
			assert.True(t, reflect.DeepEqual(affinity, test.expected))
		})
	}
}

func TestDiagnosePod(t *testing.T) {
	testCases := []struct {
		name     string
		pod      *corev1api.Pod
		events   *corev1api.EventList
		expected string
	}{
		{
			name: "pod with all info but event",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-pod",
					Namespace: "fake-ns",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodPending,
					Conditions: []corev1api.PodCondition{
						{
							Type:    corev1api.PodInitialized,
							Status:  corev1api.ConditionTrue,
							Reason:  "fake-reason-1",
							Message: "fake-message-1",
						},
						{
							Type:    corev1api.PodScheduled,
							Status:  corev1api.ConditionFalse,
							Reason:  "fake-reason-2",
							Message: "fake-message-2",
						},
					},
					Message: "fake-message-3",
				},
			},
			expected: "Pod fake-ns/fake-pod, phase Pending, node name fake-node, message fake-message-3\nPod condition Initialized, status True, reason fake-reason-1, message fake-message-1\nPod condition PodScheduled, status False, reason fake-reason-2, message fake-message-2\n",
		},
		{
			name: "pod with all info and empty event list",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-pod",
					Namespace: "fake-ns",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodPending,
					Conditions: []corev1api.PodCondition{
						{
							Type:    corev1api.PodInitialized,
							Status:  corev1api.ConditionTrue,
							Reason:  "fake-reason-1",
							Message: "fake-message-1",
						},
						{
							Type:    corev1api.PodScheduled,
							Status:  corev1api.ConditionFalse,
							Reason:  "fake-reason-2",
							Message: "fake-message-2",
						},
					},
					Message: "fake-message-3",
				},
			},
			events:   &corev1api.EventList{},
			expected: "Pod fake-ns/fake-pod, phase Pending, node name fake-node, message fake-message-3\nPod condition Initialized, status True, reason fake-reason-1, message fake-message-1\nPod condition PodScheduled, status False, reason fake-reason-2, message fake-message-2\n",
		},
		{
			name: "pod with all info and events",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-pod",
					Namespace: "fake-ns",
					UID:       "fake-pod-uid",
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
				Status: corev1api.PodStatus{
					Phase: corev1api.PodPending,
					Conditions: []corev1api.PodCondition{
						{
							Type:    corev1api.PodInitialized,
							Status:  corev1api.ConditionTrue,
							Reason:  "fake-reason-1",
							Message: "fake-message-1",
						},
						{
							Type:    corev1api.PodScheduled,
							Status:  corev1api.ConditionFalse,
							Reason:  "fake-reason-2",
							Message: "fake-message-2",
						},
					},
					Message: "fake-message-3",
				},
			},
			events: &corev1api.EventList{Items: []corev1api.Event{
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-uid-1"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-1",
					Message:        "message-1",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-uid-2"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-2",
					Message:        "message-2",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-3",
					Message:        "message-3",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Type:           corev1api.EventTypeNormal,
					Reason:         "reason-4",
					Message:        "message-4",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Type:           corev1api.EventTypeNormal,
					Reason:         "reason-5",
					Message:        "message-5",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-6",
					Message:        "message-6",
				},
			}},
			expected: "Pod fake-ns/fake-pod, phase Pending, node name fake-node, message fake-message-3\nPod condition Initialized, status True, reason fake-reason-1, message fake-message-1\nPod condition PodScheduled, status False, reason fake-reason-2, message fake-message-2\nPod event reason reason-3, message message-3\nPod event reason reason-6, message message-6\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diag := DiagnosePod(tc.pod, tc.events)
			assert.Equal(t, tc.expected, diag)
		})
	}
}

type exitWithMessageMock struct {
	createErr error
	writeFail bool
	filePath  string
	exitCode  int
}

func (em *exitWithMessageMock) Exit(code int) {
	em.exitCode = code
}

func (em *exitWithMessageMock) CreateFile(name string) (*os.File, error) {
	if em.createErr != nil {
		return nil, em.createErr
	}

	if em.writeFail {
		return os.OpenFile(em.filePath, os.O_CREATE|os.O_RDONLY, 0500)
	} else {
		return os.Create(em.filePath)
	}
}

func TestExitPodWithMessage(t *testing.T) {
	tests := []struct {
		name             string
		message          string
		succeed          bool
		args             []any
		createErr        error
		writeFail        bool
		expectedExitCode int
		expectedMessage  string
	}{
		{
			name:             "create pod file failed",
			createErr:        errors.New("fake-create-file-error"),
			succeed:          true,
			expectedExitCode: 1,
		},
		{
			name:             "write pod file failed",
			writeFail:        true,
			succeed:          true,
			expectedExitCode: 1,
		},
		{
			name:    "not succeed",
			message: "fake-message-1, arg-1 %s, arg-2 %v, arg-3 %v",
			args: []any{
				"arg-1-1",
				10,
				false,
			},
			expectedExitCode: 1,
			expectedMessage:  fmt.Sprintf("fake-message-1, arg-1 %s, arg-2 %v, arg-3 %v", "arg-1-1", 10, false),
		},
		{
			name:    "not succeed",
			message: "fake-message-2, arg-1 %s, arg-2 %v, arg-3 %v",
			args: []any{
				"arg-1-2",
				20,
				true,
			},
			succeed:         true,
			expectedMessage: fmt.Sprintf("fake-message-2, arg-1 %s, arg-2 %v, arg-3 %v", "arg-1-2", 20, true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			podFile := filepath.Join(os.TempDir(), uuid.NewString())

			em := exitWithMessageMock{
				createErr: test.createErr,
				writeFail: test.writeFail,
				filePath:  podFile,
			}

			funcExit = em.Exit
			funcCreateFile = em.CreateFile

			ExitPodWithMessage(velerotest.NewLogger(), test.succeed, test.message, test.args...)

			assert.Equal(t, test.expectedExitCode, em.exitCode)

			if test.createErr == nil && !test.writeFail {
				reader, err := os.Open(podFile)
				require.NoError(t, err)

				message, err := io.ReadAll(reader)
				require.NoError(t, err)

				reader.Close()

				assert.Equal(t, test.expectedMessage, string(message))
			}
		})
	}
}

func TestGetLoadAffinityByStorageClass(t *testing.T) {
	tests := []struct {
		name             string
		affinityList     []*LoadAffinity
		scName           string
		expectedAffinity *LoadAffinity
	}{
		{
			name: "get global affinity",
			affinityList: []*LoadAffinity{
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/arch",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"amd64"},
							},
						},
					},
					StorageClass: "storage-class-01",
				},
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"Linux"},
							},
						},
					},
				},
			},
			scName: "",
			expectedAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/os",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"Linux"},
						},
					},
				},
			},
		},
		{
			name: "get affinity for StorageClass but only global affinity exists",
			affinityList: []*LoadAffinity{
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"Linux"},
							},
						},
					},
				},
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/arch",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"amd64"},
							},
						},
					},
				},
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"Windows"},
							},
						},
					},
				},
			},
			scName: "storage-class-01",
			expectedAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/os",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"Linux"},
						},
					},
				},
			},
		},
		{
			name: "get affinity for StorageClass",
			affinityList: []*LoadAffinity{
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/control-plane=",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{""},
							},
						},
					},
				},
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"Linux"},
							},
						},
					},
					StorageClass: "storage-class-01",
				},
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/arch",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"amd64"},
							},
						},
					},
					StorageClass: "invalid-storage-class",
				},
			},
			scName: "storage-class-01",
			expectedAffinity: &LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/os",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"Linux"},
						},
					},
				},
				StorageClass: "storage-class-01",
			},
		},
		{
			name: "Cannot find a match Affinity",
			affinityList: []*LoadAffinity{
				{
					NodeSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/arch",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"amd64"},
							},
						},
					},
					StorageClass: "invalid-storage-class",
				},
			},
			scName:           "storage-class-01",
			expectedAffinity: nil,
		},
		{
			name:             "affinityList is nil",
			affinityList:     nil,
			scName:           "storage-class-01",
			expectedAffinity: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetLoadAffinityByStorageClass(test.affinityList, test.scName, velerotest.NewLogger())

			assert.Equal(t, test.expectedAffinity, result)
		})
	}
}
