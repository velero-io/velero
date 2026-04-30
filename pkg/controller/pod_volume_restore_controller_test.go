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

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgofake "k8s.io/client-go/kubernetes/fake"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	datapathmockes "github.com/vmware-tanzu/velero/pkg/datapath/mocks"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	exposermockes "github.com/vmware-tanzu/velero/pkg/exposer/mocks"
	"github.com/vmware-tanzu/velero/pkg/restorehelper"
	"github.com/vmware-tanzu/velero/pkg/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestShouldProcess(t *testing.T) {
	controllerNode := "foo"

	tests := []struct {
		name            string
		obj             *velerov1api.PodVolumeRestore
		pod             *corev1api.Pod
		shouldProcessed bool
	}{
		{
			name: "InProgress phase pvr should not be processed",
			obj: &velerov1api.PodVolumeRestore{
				Status: velerov1api.PodVolumeRestoreStatus{
					Phase: velerov1api.PodVolumeRestorePhaseInProgress,
				},
			},
			shouldProcessed: false,
		},
		{
			name: "Completed phase pvr should not be processed",
			obj: &velerov1api.PodVolumeRestore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "pvr-1",
				},
				Status: velerov1api.PodVolumeRestoreStatus{
					Phase: velerov1api.PodVolumeRestorePhaseCompleted,
				},
			},
			shouldProcessed: false,
		},
		{
			name: "Failed phase pvr should not be processed",
			obj: &velerov1api.PodVolumeRestore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "pvr-1",
				},
				Status: velerov1api.PodVolumeRestoreStatus{
					Phase: velerov1api.PodVolumeRestorePhaseFailed,
				},
			},
			shouldProcessed: false,
		},
		{
			name: "Unable to get pvr's pod should not be processed",
			obj: &velerov1api.PodVolumeRestore{
				Spec: velerov1api.PodVolumeRestoreSpec{
					Pod: corev1api.ObjectReference{
						Namespace: "ns-1",
						Name:      "pod-1",
					},
				},
				Status: velerov1api.PodVolumeRestoreStatus{
					Phase: "",
				},
			},
			shouldProcessed: false,
		},
		{
			name: "Empty phase pvr with pod on node not running init container should not be processed",
			obj: &velerov1api.PodVolumeRestore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "pvr-1",
				},
				Spec: velerov1api.PodVolumeRestoreSpec{
					Pod: corev1api.ObjectReference{
						Namespace: "ns-1",
						Name:      "pod-1",
					},
				},
				Status: velerov1api.PodVolumeRestoreStatus{
					Phase: "",
				},
			},
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					NodeName: controllerNode,
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{
						{
							State: corev1api.ContainerState{},
						},
					},
				},
			},
			shouldProcessed: false,
		},
		{
			name: "Empty phase pvr with pod on node running init container should be enqueued",
			obj: &velerov1api.PodVolumeRestore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "pvr-1",
				},
				Spec: velerov1api.PodVolumeRestoreSpec{
					Pod: corev1api.ObjectReference{
						Namespace: "ns-1",
						Name:      "pod-1",
					},
				},
				Status: velerov1api.PodVolumeRestoreStatus{
					Phase: "",
				},
			},
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					NodeName: controllerNode,
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{
									StartedAt: metav1.Time{Time: time.Now()},
								},
							},
						},
					},
				},
			},
			shouldProcessed: true,
		},
	}

	for _, ts := range tests {
		t.Run(ts.name, func(t *testing.T) {
			ctx := t.Context()

			var objs []runtime.Object
			if ts.obj != nil {
				objs = append(objs, ts.obj)
			}
			if ts.pod != nil {
				objs = append(objs, ts.pod)
			}
			cli := test.NewFakeControllerRuntimeClient(t, objs...)

			c := &PodVolumeRestoreReconciler{
				logger: logrus.New(),
				client: cli,
				clock:  &clocks.RealClock{},
			}

			shouldProcess, _, _ := shouldProcess(ctx, c.client, c.logger, ts.obj)
			require.Equal(t, ts.shouldProcessed, shouldProcess)
		})
	}
}

func TestIsInitContainerRunning(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1api.Pod
		expected bool
	}{
		{
			name: "pod with no init containers should return false",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
			},
			expected: false,
		},
		{
			name: "pod with running init container that's not restore init should return false",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: "non-restore-init",
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "pod with running init container that's not first should still work",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: "non-restore-init",
						},
						{
							Name: restorehelper.WaitInitContainer,
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}},
							},
						},
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "pod with init container as first initContainer that's not running should return false",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
						{
							Name: "non-restore-init",
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{
						{
							State: corev1api.ContainerState{},
						},
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "pod with running init container as first initContainer should return true",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
						{
							Name: "non-restore-init",
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}},
							},
						},
						{
							State: corev1api.ContainerState{
								Running: &corev1api.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "pod with init container with empty InitContainerStatuses should return 0",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
					},
				},
				Status: corev1api.PodStatus{
					InitContainerStatuses: []corev1api.ContainerStatus{},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, isInitContainerRunning(test.pod))
		})
	}
}

func TestGetInitContainerIndex(t *testing.T) {
	tests := []struct {
		name     string
		pod      *corev1api.Pod
		expected int
	}{
		{
			name: "init container is not present return -1",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
			},
			expected: -1,
		},
		{
			name: "pod with no init container return -1",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: "non-restore-init",
						},
					},
				},
			},
			expected: -1,
		},
		{
			name: "pod with container as second initContainern should return 1",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: "non-restore-init",
						},
						{
							Name: restorehelper.WaitInitContainer,
						},
					},
				},
			},
			expected: 1,
		},
		{
			name: "pod with init container as first initContainer should return 0",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
						{
							Name: "non-restore-init",
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "pod with init container as first initContainer should return 0",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pod-1",
				},
				Spec: corev1api.PodSpec{
					InitContainers: []corev1api.Container{
						{
							Name: restorehelper.WaitInitContainer,
						},
						{
							Name: "non-restore-init",
						},
					},
				},
			},
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, getInitContainerIndex(test.pod))
		})
	}
}

func TestFindPVRForTargetPod(t *testing.T) {
	pod := &corev1api.Pod{}
	pod.UID = "uid"

	scheme := runtime.NewScheme()
	scheme.AddKnownTypes(velerov1api.SchemeGroupVersion, &velerov1api.PodVolumeRestore{}, &velerov1api.PodVolumeRestoreList{})
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme)

	// no matching PVR
	reconciler := &PodVolumeRestoreReconciler{
		client: clientBuilder.Build(),
		logger: logrus.New(),
	}
	requests := reconciler.findPVRForTargetPod(t.Context(), pod)
	assert.Empty(t, requests)

	// contain one matching PVR
	reconciler.client = clientBuilder.WithLists(&velerov1api.PodVolumeRestoreList{
		Items: []velerov1api.PodVolumeRestore{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pvr1",
					Labels: map[string]string{
						velerov1api.PodUIDLabel: string(pod.GetUID()),
					},
				},
				Spec: velerov1api.PodVolumeRestoreSpec{UploaderType: uploader.KopiaType},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pvr2",
					Labels: map[string]string{
						velerov1api.PodUIDLabel: "non-matching-uid",
					},
				},
			},
		},
	}).Build()
	requests = reconciler.findPVRForTargetPod(t.Context(), pod)
	assert.Len(t, requests, 1)
}

const pvrName string = "pvr-1"

func pvrBuilder() *builder.PodVolumeRestoreBuilder {
	return builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).
		BackupStorageLocation("bsl-loc").
		SnapshotID("test-snapshot-id")
}

func initPodVolumeRestoreReconciler(objects []runtime.Object, cliObj []client.Object, needError ...bool) (*PodVolumeRestoreReconciler, error) {
	var errs = make([]error, 6)
	for k, isError := range needError {
		if k == 0 && isError {
			errs[0] = fmt.Errorf("Get error")
		} else if k == 1 && isError {
			errs[1] = fmt.Errorf("Create error")
		} else if k == 2 && isError {
			errs[2] = fmt.Errorf("Update error")
		} else if k == 3 && isError {
			errs[3] = fmt.Errorf("Patch error")
		} else if k == 4 && isError {
			errs[4] = apierrors.NewConflict(velerov1api.Resource("podvolumerestore"), pvrName, errors.New("conflict"))
		} else if k == 5 && isError {
			errs[5] = fmt.Errorf("List error")
		}
	}
	return initPodVolumeRestoreReconcilerWithError(objects, cliObj, errs...)
}

func initPodVolumeRestoreReconcilerWithError(objects []runtime.Object, cliObj []client.Object, needError ...error) (*PodVolumeRestoreReconciler, error) {
	scheme := runtime.NewScheme()
	err := velerov1api.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}

	err = corev1api.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}

	fakeClient := &FakeClient{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(cliObj...).Build(),
	}

	for k := range needError {
		if k == 0 {
			fakeClient.getError = needError[0]
		} else if k == 1 {
			fakeClient.createError = needError[1]
		} else if k == 2 {
			fakeClient.updateError = needError[2]
		} else if k == 3 {
			fakeClient.patchError = needError[3]
		} else if k == 4 {
			fakeClient.updateConflict = needError[4]
		} else if k == 5 {
			fakeClient.listError = needError[5]
		}
	}

	var fakeKubeClient *clientgofake.Clientset
	if len(objects) != 0 {
		fakeKubeClient = clientgofake.NewSimpleClientset(objects...)
	} else {
		fakeKubeClient = clientgofake.NewSimpleClientset()
	}

	fakeFS := velerotest.NewFakeFileSystem()
	pathGlob := fmt.Sprintf("/host_pods/%s/volumes/*/%s", "test-uid", "test-pvc")
	_, err = fakeFS.Create(pathGlob)
	if err != nil {
		return nil, err
	}

	dataPathMgr := datapath.NewManager(1)

	return NewPodVolumeRestoreReconciler(
		fakeClient,
		nil,
		fakeKubeClient,
		dataPathMgr,
		nil,
		"test-node",
		time.Minute*5,
		time.Minute,
		nil,
		nil,
		corev1api.ResourceRequirements{},
		velerotest.NewLogger(),
		"",
		false,
		nil,
		nil, // podLabels
		nil, // podAnnotations
	), nil
}

func TestPodVolumeRestoreReconcile(t *testing.T) {
	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: appsv1api.SchemeGroupVersion.String(),
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Image: "fake-image",
						},
					},
				},
			},
		},
	}

	node := builder.ForNode("fake-node").Labels(map[string]string{kube.NodeOSLabel: kube.NodeOSLinux}).Result()

	tests := []struct {
		name                     string
		pvr                      *velerov1api.PodVolumeRestore
		notCreatePVR             bool
		targetPod                *corev1api.Pod
		dataMgr                  *datapath.Manager
		needErrs                 []bool
		needCreateFSBR           bool
		needDelete               bool
		sportTime                *metav1.Time
		mockExposeErr            *bool
		isGetExposeErr           bool
		isGetExposeNil           bool
		isPeekExposeErr          bool
		isNilExposer             bool
		notNilExpose             bool
		notMockCleanUp           bool
		mockInit                 bool
		mockInitErr              error
		mockStart                bool
		mockStartErr             error
		mockCancel               bool
		mockClose                bool
		needExclusiveUpdateError error
		constrained              bool
		preserveEmptyUploader    bool
		expected                 *velerov1api.PodVolumeRestore
		expectDeleted            bool
		expectCancelRecord       bool
		expectedResult           *ctrl.Result
		expectedErr              string
		expectDataPath           bool
	}{
		{
			name:         "pvr not found",
			pvr:          pvrBuilder().Result(),
			notCreatePVR: true,
		},
		{
			name: "pvr not created in velero default namespace",
			pvr:  builder.ForPodVolumeRestore("test-ns", pvrName).Result(),
		},
		{
			name:        "get dd fail",
			pvr:         builder.ForPodVolumeRestore("test-ns", pvrName).Result(),
			needErrs:    []bool{true, false, false, false},
			expectedErr: "Get error",
		},
		{
			name:     "add finalizer to pvr",
			pvr:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Result(),
			expected: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:        "add finalizer to pvr failed",
			pvr:         builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Result(),
			needErrs:    []bool{false, false, true, false},
			expectedErr: "error updating PVR velero/pvr-1: Update error",
		},
		{
			name:       "pvr is under deletion",
			pvr:        builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Result(),
			needDelete: true,
			expected:   builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Result(),
		},
		{
			name:        "pvr is under deletion but cancel failed",
			pvr:         builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Result(),
			needErrs:    []bool{false, false, true, false},
			needDelete:  true,
			expectedErr: "error updating PVR velero/pvr-1: Update error",
		},
		{
			name:          "pvr is under deletion and in terminal state",
			pvr:           builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Phase(velerov1api.PodVolumeRestorePhaseFailed).Result(),
			sportTime:     &metav1.Time{Time: time.Now()},
			needDelete:    true,
			expectDeleted: true,
		},
		{
			name:        "pvr is under deletion and in terminal state, but remove finalizer failed",
			pvr:         builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Phase(velerov1api.PodVolumeRestorePhaseFailed).Result(),
			needErrs:    []bool{false, false, true, false},
			needDelete:  true,
			expectedErr: "error updating PVR velero/pvr-1: Update error",
		},
		{
			name:               "delay cancel negative for others",
			pvr:                builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhasePrepared).Result(),
			sportTime:          &metav1.Time{Time: time.Now()},
			expectCancelRecord: true,
		},
		{
			name:               "delay cancel negative for inProgress",
			pvr:                builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			sportTime:          &metav1.Time{Time: time.Now().Add(-time.Minute * 58)},
			expectCancelRecord: true,
		},
		{
			name:      "delay cancel affirmative for others",
			pvr:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhasePrepared).Result(),
			sportTime: &metav1.Time{Time: time.Now().Add(-time.Minute * 5)},
			expected:  builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Result(),
		},
		{
			name:      "delay cancel affirmative for inProgress",
			pvr:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			sportTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
			expected:  builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Result(),
		},
		{
			name:               "delay cancel failed",
			pvr:                builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			needErrs:           []bool{false, false, true, false},
			sportTime:          &metav1.Time{Time: time.Now().Add(-time.Hour)},
			expected:           builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			expectCancelRecord: true,
		},
		{
			name: "Unknown pvr status",
			pvr:  builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase("Unknown").Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:           "new pvb but constrained",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).PodNamespace("test-ns").PodName("test-pod").Result(),
			targetPod:      builder.ForPod("test-ns", "test-pod").InitContainers(&corev1api.Container{Name: restorehelper.WaitInitContainer}).InitContainerState(corev1api.ContainerState{Running: &corev1api.ContainerStateRunning{}}).Result(),
			constrained:    true,
			expected:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Result(),
			expectedResult: &ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
		},
		{
			name:        "new pvr but accept failed",
			pvr:         builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).PodNamespace("test-ns").PodName("test-pod").Result(),
			targetPod:   builder.ForPod("test-ns", "test-pod").InitContainers(&corev1api.Container{Name: restorehelper.WaitInitContainer}).InitContainerState(corev1api.ContainerState{Running: &corev1api.ContainerStateRunning{}}).Result(),
			needErrs:    []bool{false, false, true, false},
			expected:    builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Result(),
			expectedErr: "error accepting PVR pvr-1: error updating PVR velero/pvr-1: Update error",
		},
		{
			name:               "pvr is cancel on accepted",
			pvr:                builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Result(),
			expectCancelRecord: true,
			expected:           builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Result(),
		},
		{
			name:          "pvr expose failed",
			pvr:           builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).PodNamespace("test-ns").PodName("test-pod").Finalizers([]string{PodVolumeFinalizer}).Result(),
			targetPod:     builder.ForPod("test-ns", "test-pod").InitContainers(&corev1api.Container{Name: restorehelper.WaitInitContainer}).InitContainerState(corev1api.ContainerState{Running: &corev1api.ContainerStateRunning{}}).Result(),
			mockExposeErr: boolptr.True(),
			expected:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Phase(velerov1api.PodVolumeRestorePhaseFailed).Message("error to expose PVR").Result(),
			expectedErr:   "Error to expose restore exposer",
		},
		{
			name:           "pvr succeeds for accepted",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).PodNamespace("test-ns").PodName("test-pod").Finalizers([]string{PodVolumeFinalizer}).Result(),
			mockExposeErr:  boolptr.False(),
			notMockCleanUp: true,
			targetPod:      builder.ForPod("test-ns", "test-pod").InitContainers(&corev1api.Container{Name: restorehelper.WaitInitContainer}).InitContainerState(corev1api.ContainerState{Running: &corev1api.ContainerStateRunning{}}).Result(),
			expected:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Finalizers([]string{PodVolumeFinalizer}).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Result(),
		},
		{
			name:     "prepare timeout on accepted",
			pvr:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Finalizers([]string{PodVolumeFinalizer}).AcceptedTimestamp(&metav1.Time{Time: time.Now().Add(-time.Minute * 30)}).Result(),
			expected: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseFailed).Finalizers([]string{PodVolumeFinalizer}).Phase(velerov1api.PodVolumeRestorePhaseFailed).Message("timeout on preparing PVR").Result(),
		},
		{
			name:            "peek error on accepted",
			pvr:             builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Finalizers([]string{PodVolumeFinalizer}).Result(),
			isPeekExposeErr: true,
			expected:        builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Finalizers([]string{PodVolumeFinalizer}).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Message("found a PVR velero/pvr-1 with expose error: fake-peek-error. mark it as cancel").Result(),
		},
		{
			name:     "cancel on pvr",
			pvr:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Node("test-node").Result(),
			expected: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Finalizers([]string{PodVolumeFinalizer}).Cancel(true).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Result(),
		},
		{
			name:           "Failed to get restore expose on prepared",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			isGetExposeErr: true,
			expected:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseFailed).Finalizers([]string{PodVolumeFinalizer}).Message("exposed PVR is not ready").Result(),
			expectedErr:    "Error to get PVR exposer",
		},
		{
			name:           "Get nil restore expose on prepared",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			isGetExposeNil: true,
			expected:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseFailed).Finalizers([]string{PodVolumeFinalizer}).Message("exposed PVR is not ready").Result(),
			expectedErr:    "no expose result is available for the current node",
		},
		{
			name:           "Error in data path is concurrent limited",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			dataMgr:        datapath.NewManager(0),
			notNilExpose:   true,
			notMockCleanUp: true,
			expectedResult: &ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
		},
		{
			name:         "data path init error",
			pvr:          builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			mockInit:     true,
			mockInitErr:  errors.New("fake-data-path-init-error"),
			mockClose:    true,
			notNilExpose: true,
			expected:     builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseFailed).Finalizers([]string{PodVolumeFinalizer}).Message("error initializing data path").Result(),
			expectedErr:  "error initializing asyncBR: fake-data-path-init-error",
		},
		{
			name:           "Unable to update status to in progress for pvr",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			needErrs:       []bool{false, false, true, false},
			mockInit:       true,
			mockClose:      true,
			notNilExpose:   true,
			notMockCleanUp: true,
			expected:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:         "data path start error",
			pvr:          builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			mockInit:     true,
			mockStart:    true,
			mockStartErr: errors.New("fake-data-path-start-error"),
			mockClose:    true,
			notNilExpose: true,
			expected:     builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseFailed).Finalizers([]string{PodVolumeFinalizer}).Message("error starting data path").Result(),
			expectedErr:  "error starting async restore for pod test-name, volume test-pvc: fake-data-path-start-error",
		},
		{
			name:           "Prepare succeeds",
			pvr:            builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhasePrepared).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			mockInit:       true,
			mockStart:      true,
			notNilExpose:   true,
			notMockCleanUp: true,
			expectDataPath: true,
			expected:       builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:     "In progress pvr is not handled by the current node",
			pvr:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Finalizers([]string{PodVolumeFinalizer}).Result(),
			expected: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:     "In progress pvr is not set as cancel",
			pvr:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			expected: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:     "Cancel pvr in progress with empty FSBR",
			pvr:      builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Cancel(true).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			expected: builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseCanceled).Cancel(true).Finalizers([]string{PodVolumeFinalizer}).Result(),
		},
		{
			name:               "Cancel pvr in progress and patch pvr error",
			pvr:                builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Cancel(true).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			needErrs:           []bool{false, false, true, false},
			needCreateFSBR:     true,
			expected:           builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Cancel(true).Finalizers([]string{PodVolumeFinalizer}).Result(),
			expectedErr:        "error updating PVR velero/pvr-1: Update error",
			expectCancelRecord: true,
			expectDataPath:     true,
		},
		{
			name:               "Cancel pvr in progress succeeds",
			pvr:                builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Cancel(true).Finalizers([]string{PodVolumeFinalizer}).Node("test-node").Result(),
			needCreateFSBR:     true,
			mockCancel:         true,
			expected:           builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Phase(velerov1api.PodVolumeRestorePhaseCanceling).Cancel(true).Finalizers([]string{PodVolumeFinalizer}).Result(),
			expectDataPath:     true,
			expectCancelRecord: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.preserveEmptyUploader && test.pvr != nil && test.pvr.Spec.UploaderType == "" {
				test.pvr.Spec.UploaderType = uploader.KopiaType
			}
			if !test.preserveEmptyUploader && test.expected != nil && test.expected.Spec.UploaderType == "" {
				test.expected.Spec.UploaderType = uploader.KopiaType
			}

			objs := []runtime.Object{daemonSet, node}

			ctlObj := []client.Object{}
			if test.targetPod != nil {
				ctlObj = append(ctlObj, test.targetPod)
			}

			r, err := initPodVolumeRestoreReconciler(objs, ctlObj, test.needErrs...)
			require.NoError(t, err)

			if !test.notCreatePVR {
				err = r.client.Create(t.Context(), test.pvr)
				require.NoError(t, err)
			}

			if test.needDelete {
				err = r.client.Delete(t.Context(), test.pvr)
				require.NoError(t, err)
			}

			if test.dataMgr != nil {
				r.dataPathMgr = test.dataMgr
			} else {
				r.dataPathMgr = datapath.NewManager(1)
			}

			if test.sportTime != nil {
				r.cancelledPVR[test.pvr.Name] = test.sportTime.Time
			}

			if test.constrained {
				r.vgdpCounter = &exposer.VgdpCounter{}
			}

			funcExclusiveUpdatePodVolumeRestore = exclusiveUpdatePodVolumeRestore
			if test.needExclusiveUpdateError != nil {
				funcExclusiveUpdatePodVolumeRestore = func(context.Context, kbclient.Client, *velerov1api.PodVolumeRestore, func(*velerov1api.PodVolumeRestore)) (bool, error) {
					return false, test.needExclusiveUpdateError
				}
			}

			datapath.MicroServiceBRWatcherCreator = func(kbclient.Client, kubernetes.Interface, manager.Manager, string, string,
				string, string, string, string, datapath.Callbacks, logrus.FieldLogger) datapath.AsyncBR {
				asyncBR := datapathmockes.NewAsyncBR(t)
				if test.mockInit {
					asyncBR.On("Init", mock.Anything, mock.Anything).Return(test.mockInitErr)
				}

				if test.mockStart {
					asyncBR.On("StartRestore", mock.Anything, mock.Anything, mock.Anything).Return(test.mockStartErr)
				}

				if test.mockCancel {
					asyncBR.On("Cancel").Return()
				}

				if test.mockClose {
					asyncBR.On("Close", mock.Anything).Return()
				}

				return asyncBR
			}

			if test.mockExposeErr != nil || test.isGetExposeErr || test.isGetExposeNil || test.isPeekExposeErr || test.isNilExposer || test.notNilExpose {
				if test.isNilExposer {
					r.exposer = nil
				} else {
					r.exposer = func() exposer.PodVolumeExposer {
						ep := exposermockes.NewMockPodVolumeExposer(t)
						if test.mockExposeErr != nil {
							if boolptr.IsSetToTrue(test.mockExposeErr) {
								ep.On("Expose", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("Error to expose restore exposer"))
							} else {
								ep.On("Expose", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
							}
						} else if test.notNilExpose {
							hostingPod := builder.ForPod("test-ns", "test-name").Volumes(&corev1api.Volume{Name: "test-pvc"}).Result()
							hostingPod.ObjectMeta.SetUID("test-uid")
							ep.On("GetExposed", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&exposer.ExposeResult{ByPod: exposer.ExposeByPod{HostingPod: hostingPod, VolumeName: "test-pvc"}}, nil)
						} else if test.isGetExposeErr {
							ep.On("GetExposed", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("Error to get PVR exposer"))
						} else if test.isGetExposeNil {
							ep.On("GetExposed", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
						} else if test.isPeekExposeErr {
							ep.On("PeekExposed", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("fake-peek-error"))
							ep.On("DiagnoseExpose", mock.Anything, mock.Anything).Return("")
						}

						if !test.notMockCleanUp {
							ep.On("CleanUp", mock.Anything, mock.Anything).Return()
						}
						return ep
					}()
				}
			}

			if test.needCreateFSBR {
				if fsBR := r.dataPathMgr.GetAsyncBR(test.pvr.Name); fsBR == nil {
					_, err := r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, nil, nil, datapath.TaskTypeRestore, test.pvr.Name, pVBRRequestor,
						velerov1api.DefaultNamespace, "", "", datapath.Callbacks{OnCancelled: r.OnDataPathCancelled}, false, velerotest.NewLogger())
					require.NoError(t, err)
				}
			}

			actualResult, err := r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: velerov1api.DefaultNamespace,
					Name:      test.pvr.Name,
				},
			})

			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}

			if test.expectedResult != nil {
				assert.Equal(t, test.expectedResult.Requeue, actualResult.Requeue)
				assert.Equal(t, test.expectedResult.RequeueAfter, actualResult.RequeueAfter)
			}

			pvr := velerov1api.PodVolumeRestore{}
			err = r.client.Get(ctx, kbclient.ObjectKey{
				Name:      test.pvr.Name,
				Namespace: test.pvr.Namespace,
			}, &pvr)

			if test.expected != nil || test.expectDeleted {
				if test.expectDeleted {
					assert.True(t, apierrors.IsNotFound(err))
				} else {
					require.NoError(t, err)

					assert.Equal(t, test.expected.Status.Phase, pvr.Status.Phase)
					assert.Contains(t, pvr.Status.Message, test.expected.Status.Message)
					assert.Equal(t, test.expected.Finalizers, pvr.Finalizers)
					assert.Equal(t, test.expected.Spec.Cancel, pvr.Spec.Cancel)
				}
			}

			if !test.expectDataPath {
				assert.Nil(t, r.dataPathMgr.GetAsyncBR(test.pvr.Name))
			} else {
				assert.NotNil(t, r.dataPathMgr.GetAsyncBR(test.pvr.Name))
			}

			if test.expectCancelRecord {
				assert.Contains(t, r.cancelledPVR, test.pvr.Name)
			} else {
				assert.Empty(t, r.cancelledPVR)
			}

			if isPVRInFinalState(&pvr) || pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseInProgress {
				assert.NotContains(t, pvr.Labels, exposer.ExposeOnGoingLabel)
			} else if pvr.Status.Phase == velerov1api.PodVolumeRestorePhaseAccepted {
				assert.Contains(t, pvr.Labels, exposer.ExposeOnGoingLabel)
			}
		})
	}
}

func TestPodVolumeRestoreSetupExposeParam(t *testing.T) {
	// common objects for all cases
	node := builder.ForNode("worker-1").Labels(map[string]string{kube.NodeOSLabel: kube.NodeOSLinux}).Result()

	basePVR := pvrBuilder().Result()
	basePVR.Status.Node = "worker-1"
	basePVR.Spec.Pod.Namespace = "app-ns"
	basePVR.Spec.Pod.Name = "app-pod"
	basePVR.Spec.Volume = "data-vol"

	type args struct {
		customLabels      map[string]string
		customAnnotations map[string]string
	}
	type want struct {
		labels      map[string]string
		annotations map[string]string
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "label has customize values",
			args: args{
				customLabels:      map[string]string{"custom-label": "label-value"},
				customAnnotations: nil,
			},
			want: want{
				labels: map[string]string{
					velerov1api.PVRLabel: basePVR.Name,
					"custom-label":       "label-value",
				},
				annotations: map[string]string{},
			},
		},
		{
			name: "label has no customize values",
			args: args{
				customLabels:      nil,
				customAnnotations: nil,
			},
			want: want{
				labels:      map[string]string{velerov1api.PVRLabel: basePVR.Name},
				annotations: map[string]string{},
			},
		},
		{
			name: "annotation has customize values",
			args: args{
				customLabels:      nil,
				customAnnotations: map[string]string{"custom-annotation": "annotation-value"},
			},
			want: want{
				labels:      map[string]string{velerov1api.PVRLabel: basePVR.Name},
				annotations: map[string]string{"custom-annotation": "annotation-value"},
			},
		},
		{
			name: "annotation has no customize values",
			args: args{
				customLabels:      map[string]string{"another-label": "lval"},
				customAnnotations: nil,
			},
			want: want{
				labels: map[string]string{
					velerov1api.PVRLabel: basePVR.Name,
					"another-label":      "lval",
				},
				annotations: map[string]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fake clients per case
			fakeCRClient := velerotest.NewFakeControllerRuntimeClient(t, node, basePVR.DeepCopy())
			fakeKubeClient := clientgofake.NewSimpleClientset(node)

			// Reconciler config per case
			preparingTimeout := time.Minute * 3
			resourceTimeout := time.Minute * 10
			podRes := corev1api.ResourceRequirements{}
			r := NewPodVolumeRestoreReconciler(
				fakeCRClient,
				nil,
				fakeKubeClient,
				datapath.NewManager(1),
				nil,
				"test-node",
				preparingTimeout,
				resourceTimeout,
				nil, // backupRepoConfigs
				nil, // cacheVolumeConfigs -> keep nil so CacheVolume is nil
				podRes,
				velerotest.NewLogger(),
				"restore-priority",
				true,
				nil, // repoConfigMgr (unused when cacheVolumeConfigs is nil)
				tt.args.customLabels,
				tt.args.customAnnotations,
			)

			// Act
			got := r.setupExposeParam(basePVR)

			// Core fields
			assert.Equal(t, exposer.PodVolumeExposeTypeRestore, got.Type)
			assert.Equal(t, basePVR.Spec.Pod.Namespace, got.ClientNamespace)
			assert.Equal(t, basePVR.Spec.Pod.Name, got.ClientPodName)
			assert.Equal(t, basePVR.Spec.Volume, got.ClientPodVolume)

			// Labels/Annotations
			assert.Equal(t, tt.want.labels, got.HostingPodLabels)
			assert.Equal(t, tt.want.annotations, got.HostingPodAnnotations)
		})
	}
}

func TestOnPodVolumeRestoreFailed(t *testing.T) {
	for _, getErr := range []bool{true, false} {
		ctx := t.Context()
		needErrs := []bool{getErr, false, false, false}
		r, err := initPodVolumeRestoreReconciler(nil, []client.Object{}, needErrs...)
		require.NoError(t, err)

		pvr := pvrBuilder().Result()
		namespace := pvr.Namespace
		pvrName := pvr.Name

		require.NoError(t, r.client.Create(ctx, pvr))
		r.OnDataPathFailed(ctx, namespace, pvrName, fmt.Errorf("Failed to handle %v", pvrName))
		updatedPVR := &velerov1api.PodVolumeRestore{}
		if getErr {
			require.Error(t, r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, updatedPVR))
			assert.NotEqual(t, velerov1api.PodVolumeRestorePhaseFailed, updatedPVR.Status.Phase)
			assert.True(t, updatedPVR.Status.StartTimestamp.IsZero())
		} else {
			require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, updatedPVR))
			assert.Equal(t, velerov1api.PodVolumeRestorePhaseFailed, updatedPVR.Status.Phase)
			assert.True(t, updatedPVR.Status.StartTimestamp.IsZero())
		}
	}
}

func TestOnPodVolumeRestoreCancelled(t *testing.T) {
	for _, getErr := range []bool{true, false} {
		ctx := t.Context()
		needErrs := []bool{getErr, false, false, false}
		r, err := initPodVolumeRestoreReconciler(nil, nil, needErrs...)
		require.NoError(t, err)

		pvr := pvrBuilder().Result()
		namespace := pvr.Namespace
		pvrName := pvr.Name

		require.NoError(t, r.client.Create(ctx, pvr))
		r.OnDataPathCancelled(ctx, namespace, pvrName)
		updatedPVR := &velerov1api.PodVolumeRestore{}
		if getErr {
			require.Error(t, r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, updatedPVR))
			assert.NotEqual(t, velerov1api.PodVolumeRestorePhaseFailed, updatedPVR.Status.Phase)
			assert.True(t, updatedPVR.Status.StartTimestamp.IsZero())
		} else {
			require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, updatedPVR))
			assert.Equal(t, velerov1api.PodVolumeRestorePhaseCanceled, updatedPVR.Status.Phase)
			assert.False(t, updatedPVR.Status.StartTimestamp.IsZero())
			assert.False(t, updatedPVR.Status.CompletionTimestamp.IsZero())
		}
	}
}

func TestOnPodVolumeRestoreCompleted(t *testing.T) {
	tests := []struct {
		name            string
		emptyFSBR       bool
		isGetErr        bool
		rebindVolumeErr bool
	}{
		{
			name:            "PVR complete",
			emptyFSBR:       false,
			isGetErr:        false,
			rebindVolumeErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			needErrs := []bool{test.isGetErr, false, false, false}
			r, err := initPodVolumeRestoreReconciler(nil, []client.Object{}, needErrs...)
			r.exposer = func() exposer.PodVolumeExposer {
				ep := exposermockes.NewMockPodVolumeExposer(t)
				ep.On("CleanUp", mock.Anything, mock.Anything).Return()
				return ep
			}()

			require.NoError(t, err)
			pvr := builder.ForPodVolumeRestore(velerov1api.DefaultNamespace, pvrName).Result()
			namespace := pvr.Namespace
			ddName := pvr.Name

			require.NoError(t, r.client.Create(ctx, pvr))
			r.OnDataPathCompleted(ctx, namespace, ddName, datapath.Result{})
			updatedDD := &velerov1api.PodVolumeRestore{}
			if test.isGetErr {
				require.Error(t, r.client.Get(ctx, types.NamespacedName{Name: ddName, Namespace: namespace}, updatedDD))
				assert.Equal(t, velerov1api.PodVolumeRestorePhase(""), updatedDD.Status.Phase)
				assert.True(t, updatedDD.Status.CompletionTimestamp.IsZero())
			} else {
				require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: ddName, Namespace: namespace}, updatedDD))
				assert.Equal(t, velerov1api.PodVolumeRestorePhaseCompleted, updatedDD.Status.Phase)
				assert.False(t, updatedDD.Status.CompletionTimestamp.IsZero())
			}
		})
	}
}

func TestOnPodVolumeRestoreProgress(t *testing.T) {
	totalBytes := int64(1024)
	bytesDone := int64(512)
	tests := []struct {
		name     string
		pvr      *velerov1api.PodVolumeRestore
		progress uploader.Progress
		needErrs []bool
	}{
		{
			name: "patch in progress phase success",
			pvr:  pvrBuilder().Result(),
			progress: uploader.Progress{
				TotalBytes: totalBytes,
				BytesDone:  bytesDone,
			},
		},
		{
			name:     "failed to get pvr",
			pvr:      pvrBuilder().Result(),
			needErrs: []bool{true, false, false, false},
		},
		{
			name:     "failed to patch pvr",
			pvr:      pvrBuilder().Result(),
			needErrs: []bool{false, false, true, false},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()

			r, err := initPodVolumeRestoreReconciler(nil, []client.Object{}, test.needErrs...)
			require.NoError(t, err)
			defer func() {
				r.client.Delete(ctx, test.pvr, &kbclient.DeleteOptions{})
			}()

			pvr := pvrBuilder().Result()
			namespace := pvr.Namespace
			pvrName := pvr.Name

			require.NoError(t, r.client.Create(t.Context(), pvr))

			// Create a Progress object
			progress := &uploader.Progress{
				TotalBytes: totalBytes,
				BytesDone:  bytesDone,
			}

			r.OnDataPathProgress(ctx, namespace, pvrName, progress)
			if len(test.needErrs) != 0 && !test.needErrs[0] {
				updatedPVR := &velerov1api.PodVolumeRestore{}
				require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: pvrName, Namespace: namespace}, updatedPVR))
				assert.Equal(t, test.progress.TotalBytes, updatedPVR.Status.Progress.TotalBytes)
				assert.Equal(t, test.progress.BytesDone, updatedPVR.Status.Progress.BytesDone)
			}
		})
	}
}

func TestFindPVBForRestorePod(t *testing.T) {
	needErrs := []bool{false, false, false, false}
	r, err := initPodVolumeRestoreReconciler(nil, []client.Object{}, needErrs...)
	require.NoError(t, err)
	tests := []struct {
		name      string
		pvr       *velerov1api.PodVolumeRestore
		pod       *corev1api.Pod
		checkFunc func(*velerov1api.PodVolumeRestore, []reconcile.Request)
	}{
		{
			name: "find pvr for pod",
			pvr:  pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, pvrName).Labels(map[string]string{velerov1api.PVRLabel: pvrName}).Status(corev1api.PodStatus{Phase: corev1api.PodRunning}).Result(),
			checkFunc: func(pvr *velerov1api.PodVolumeRestore, requests []reconcile.Request) {
				// Assert that the function returns a single request
				assert.Len(t, requests, 1)
				// Assert that the request contains the correct namespaced name
				assert.Equal(t, pvr.Namespace, requests[0].Namespace)
				assert.Equal(t, pvr.Name, requests[0].Name)
			},
		}, {
			name: "no selected label found for pod",
			pvr:  pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, pvrName).Result(),
			checkFunc: func(pvr *velerov1api.PodVolumeRestore, requests []reconcile.Request) {
				// Assert that the function returns a single request
				assert.Empty(t, requests)
			},
		}, {
			name: "no matched pod",
			pvr:  pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, pvrName).Labels(map[string]string{velerov1api.PVRLabel: "non-existing-pvr"}).Result(),
			checkFunc: func(pvr *velerov1api.PodVolumeRestore, requests []reconcile.Request) {
				assert.Empty(t, requests)
			},
		},
		{
			name: "pvr not accept",
			pvr:  pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, pvrName).Labels(map[string]string{velerov1api.PVRLabel: pvrName}).Result(),
			checkFunc: func(pvr *velerov1api.PodVolumeRestore, requests []reconcile.Request) {
				assert.Empty(t, requests)
			},
		},
		{
			name: "invalid uploader type",
			pvr:  pvrBuilder().UploaderType("restic").Phase(velerov1api.PodVolumeRestorePhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, pvrName).Labels(map[string]string{velerov1api.PVRLabel: pvrName}).Status(corev1api.PodStatus{Phase: corev1api.PodRunning}).Result(),
			checkFunc: func(pvr *velerov1api.PodVolumeRestore, requests []reconcile.Request) {
				assert.Empty(t, requests)
			},
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		assert.NoError(t, r.client.Create(ctx, test.pod))
		assert.NoError(t, r.client.Create(ctx, test.pvr))
		// Call the findSnapshotRestoreForPod function
		requests := r.findPVRForRestorePod(t.Context(), test.pod)
		test.checkFunc(test.pvr, requests)
		r.client.Delete(ctx, test.pvr, &kbclient.DeleteOptions{})
		if test.pod != nil {
			r.client.Delete(ctx, test.pod, &kbclient.DeleteOptions{})
		}
	}
}

func TestOnPVRPrepareTimeout(t *testing.T) {
	tests := []struct {
		name     string
		pvr      *velerov1api.PodVolumeRestore
		needErrs []error
		expected *velerov1api.PodVolumeRestore
	}{
		{
			name:     "update fail",
			pvr:      pvrBuilder().Result(),
			needErrs: []error{nil, nil, fmt.Errorf("fake-update-error"), nil},
			expected: pvrBuilder().Result(),
		},
		{
			name:     "update interrupted",
			pvr:      pvrBuilder().Result(),
			needErrs: []error{nil, nil, &fakeAPIStatus{metav1.StatusReasonConflict}, nil},
			expected: pvrBuilder().Result(),
		},
		{
			name:     "succeed",
			pvr:      pvrBuilder().Result(),
			needErrs: []error{nil, nil, nil, nil},
			expected: pvrBuilder().Phase(velerov1api.PodVolumeRestorePhaseFailed).Result(),
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		r, err := initPodVolumeRestoreReconcilerWithError(nil, []client.Object{}, test.needErrs...)
		require.NoError(t, err)

		err = r.client.Create(ctx, test.pvr)
		require.NoError(t, err)

		r.onPrepareTimeout(ctx, test.pvr)

		pvr := velerov1api.PodVolumeRestore{}
		_ = r.client.Get(ctx, kbclient.ObjectKey{
			Name:      test.pvr.Name,
			Namespace: test.pvr.Namespace,
		}, &pvr)

		assert.Equal(t, test.expected.Status.Phase, pvr.Status.Phase)
	}
}

func TestTryCancelPVR(t *testing.T) {
	tests := []struct {
		name        string
		pvr         *velerov1api.PodVolumeRestore
		needErrs    []error
		succeeded   bool
		expectedErr string
	}{
		{
			name:     "update fail",
			pvr:      pvrBuilder().Result(),
			needErrs: []error{nil, nil, fmt.Errorf("fake-update-error"), nil},
		},
		{
			name:     "cancel by others",
			pvr:      pvrBuilder().Result(),
			needErrs: []error{nil, nil, &fakeAPIStatus{metav1.StatusReasonConflict}, nil},
		},
		{
			name:      "succeed",
			pvr:       pvrBuilder().Result(),
			needErrs:  []error{nil, nil, nil, nil},
			succeeded: true,
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		r, err := initPodVolumeRestoreReconcilerWithError(nil, []client.Object{}, test.needErrs...)
		require.NoError(t, err)

		err = r.client.Create(ctx, test.pvr)
		require.NoError(t, err)

		r.tryCancelPodVolumeRestore(ctx, test.pvr, "")

		if test.expectedErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, test.expectedErr)
		}
	}
}

func TestUpdatePVRWithRetry(t *testing.T) {
	namespacedName := types.NamespacedName{
		Name:      pvrName,
		Namespace: "velero",
	}

	// Define test cases
	testCases := []struct {
		Name      string
		needErrs  []bool
		noChange  bool
		ExpectErr bool
	}{
		{
			Name: "SuccessOnFirstAttempt",
		},
		{
			Name:      "Error get",
			needErrs:  []bool{true, false, false, false, false},
			ExpectErr: true,
		},
		{
			Name:      "Error update",
			needErrs:  []bool{false, false, true, false, false},
			ExpectErr: true,
		},
		{
			Name:     "no change",
			noChange: true,
			needErrs: []bool{false, false, true, false, false},
		},
		{
			Name:      "Conflict with error timeout",
			needErrs:  []bool{false, false, false, false, true},
			ExpectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(t.Context(), time.Second*5)
			defer cancelFunc()
			r, err := initPodVolumeRestoreReconciler(nil, []client.Object{}, tc.needErrs...)
			require.NoError(t, err)
			err = r.client.Create(ctx, pvrBuilder().Result())
			require.NoError(t, err)
			updateFunc := func(pvr *velerov1api.PodVolumeRestore) bool {
				if tc.noChange {
					return false
				}

				pvr.Spec.Cancel = true

				return true
			}
			err = UpdatePVRWithRetry(ctx, r.client, namespacedName, velerotest.NewLogger().WithField("name", tc.Name), updateFunc)
			if tc.ExpectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttemptPVRResume(t *testing.T) {
	tests := []struct {
		name           string
		pvrs           []velerov1api.PodVolumeRestore
		pvr            *velerov1api.PodVolumeRestore
		needErrs       []bool
		resumeErr      error
		acceptedPvrs   []string
		preparedPvrs   []string
		cancelledPvrs  []string
		inProgressPvrs []string
		expectedError  string
	}{
		{
			name: "Other pvr",
			pvr:  pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhasePrepared).Result(),
		},
		{
			name: "Other pvr",
			pvr:  pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseAccepted).Result(),
		},
		{
			name:           "InProgress pvr, not the current node",
			pvr:            pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			inProgressPvrs: []string{pvrName},
		},
		{
			name:           "InProgress pvr, no resume error",
			pvr:            pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Node("node-1").Result(),
			inProgressPvrs: []string{pvrName},
		},
		{
			name:           "InProgress pvr, resume error, cancel error",
			pvr:            pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Node("node-1").Result(),
			resumeErr:      errors.New("fake-resume-error"),
			needErrs:       []bool{false, false, true, false, false, false},
			inProgressPvrs: []string{pvrName},
		},
		{
			name:           "InProgress pvr, resume error, cancel succeed",
			pvr:            pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhaseInProgress).Node("node-1").Result(),
			resumeErr:      errors.New("fake-resume-error"),
			cancelledPvrs:  []string{pvrName},
			inProgressPvrs: []string{pvrName},
		},
		{
			name:          "Error",
			needErrs:      []bool{false, false, false, false, false, true},
			pvr:           pvrBuilder().UploaderType(uploader.KopiaType).Phase(velerov1api.PodVolumeRestorePhasePrepared).Result(),
			expectedError: "error to list PVRs: List error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			r, err := initPodVolumeRestoreReconciler(nil, []client.Object{}, test.needErrs...)
			r.nodeName = "node-1"
			require.NoError(t, err)
			defer func() {
				r.client.Delete(ctx, test.pvr, &kbclient.DeleteOptions{})
			}()

			require.NoError(t, r.client.Create(ctx, test.pvr))

			dt := &pvbResumeTestHelper{
				resumeErr: test.resumeErr,
			}

			funcResumeCancellableDataBackup = dt.resumeCancellableDataPath

			// Run the test
			err = r.AttemptPVRResume(ctx, r.logger.WithField("name", test.name), test.pvr.Namespace)

			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)

				for _, pvrName := range test.cancelledPvrs {
					pvr := &velerov1api.PodVolumeRestore{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: pvrName}, pvr)
					require.NoError(t, err)
					assert.True(t, pvr.Spec.Cancel)
				}

				for _, pvrName := range test.acceptedPvrs {
					pvr := &velerov1api.PodVolumeRestore{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: pvrName}, pvr)
					require.NoError(t, err)
					assert.Equal(t, velerov1api.PodVolumeRestorePhaseAccepted, pvr.Status.Phase)
				}

				for _, pvrName := range test.preparedPvrs {
					pvr := &velerov1api.PodVolumeRestore{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: pvrName}, pvr)
					require.NoError(t, err)
					assert.Equal(t, velerov1api.PodVolumeRestorePhasePrepared, pvr.Status.Phase)
				}
			}
		})
	}
}

func TestResumeCancellablePodVolumeRestore(t *testing.T) {
	tests := []struct {
		name             string
		pvrs             []velerov1api.PodVolumeRestore
		pvr              *velerov1api.PodVolumeRestore
		getExposeErr     error
		exposeResult     *exposer.ExposeResult
		createWatcherErr error
		initWatcherErr   error
		startWatcherErr  error
		mockInit         bool
		mockStart        bool
		mockClose        bool
		expectedError    string
	}{
		{
			name:          "get expose failed",
			pvr:           pvrBuilder().Phase(velerov1api.PodVolumeRestorePhaseInProgress).Result(),
			getExposeErr:  errors.New("fake-expose-error"),
			expectedError: fmt.Sprintf("error to get exposed PVR %s: fake-expose-error", pvrName),
		},
		{
			name:          "no expose",
			pvr:           pvrBuilder().Phase(velerov1api.PodVolumeRestorePhaseAccepted).Node("node-1").Result(),
			expectedError: fmt.Sprintf("no expose result is available for the current node for PVR %s", pvrName),
		},
		{
			name: "watcher init error",
			pvr:  pvrBuilder().Phase(velerov1api.PodVolumeRestorePhaseAccepted).Node("node-1").Result(),
			exposeResult: &exposer.ExposeResult{
				ByPod: exposer.ExposeByPod{
					HostingPod: &corev1api.Pod{},
				},
			},
			mockInit:       true,
			mockClose:      true,
			initWatcherErr: errors.New("fake-init-watcher-error"),
			expectedError:  fmt.Sprintf("error to init asyncBR watcher for PVR %s: fake-init-watcher-error", pvrName),
		},
		{
			name: "start watcher error",
			pvr:  pvrBuilder().Phase(velerov1api.PodVolumeRestorePhaseAccepted).Node("node-1").Result(),
			exposeResult: &exposer.ExposeResult{
				ByPod: exposer.ExposeByPod{
					HostingPod: &corev1api.Pod{},
				},
			},
			mockInit:        true,
			mockStart:       true,
			mockClose:       true,
			startWatcherErr: errors.New("fake-start-watcher-error"),
			expectedError:   fmt.Sprintf("error to resume asyncBR watcher for PVR %s: fake-start-watcher-error", pvrName),
		},
		{
			name: "succeed",
			pvr:  pvrBuilder().Phase(velerov1api.PodVolumeRestorePhaseAccepted).Node("node-1").Result(),
			exposeResult: &exposer.ExposeResult{
				ByPod: exposer.ExposeByPod{
					HostingPod: &corev1api.Pod{},
				},
			},
			mockInit:  true,
			mockStart: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			r, err := initPodVolumeRestoreReconciler(nil, []client.Object{})
			r.nodeName = "node-1"
			require.NoError(t, err)

			mockAsyncBR := datapathmockes.NewAsyncBR(t)

			if test.mockInit {
				mockAsyncBR.On("Init", mock.Anything, mock.Anything).Return(test.initWatcherErr)
			}

			if test.mockStart {
				mockAsyncBR.On("StartRestore", mock.Anything, mock.Anything, mock.Anything).Return(test.startWatcherErr)
			}

			if test.mockClose {
				mockAsyncBR.On("Close", mock.Anything).Return()
			}

			dt := &pvbResumeTestHelper{
				getExposeErr: test.getExposeErr,
				exposeResult: test.exposeResult,
				asyncBR:      mockAsyncBR,
			}

			r.exposer = dt

			datapath.MicroServiceBRWatcherCreator = dt.newMicroServiceBRWatcher

			err = r.resumeCancellableDataPath(ctx, test.pvr, velerotest.NewLogger())
			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
			}
		})
	}
}
