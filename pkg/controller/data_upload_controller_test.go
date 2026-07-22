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

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotFake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/fake"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgofake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/clock"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/datapath"
	datapathmocks "github.com/vmware-tanzu/velero/pkg/datapath/mocks"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const dataUploadName = "dataupload-1"

const fakeSnapshotType velerov2alpha1api.SnapshotType = "fake-snapshot"

type FakeClient struct {
	kbclient.Client
	getError       error
	createError    error
	updateError    error
	patchError     error
	updateConflict error
	listError      error
	getErrorMap    map[string]error // key: object kind or name
}

func (c *FakeClient) Get(ctx context.Context, key kbclient.ObjectKey, obj kbclient.Object, opts ...kbclient.GetOption) error {
	if c.getError != nil {
		return c.getError
	}

	// Check if there's a specific error for this object type
	if c.getErrorMap != nil {
		objType := fmt.Sprintf("%T", obj)
		if err, ok := c.getErrorMap[objType]; ok {
			return err
		}

		// Check if there's a specific error for this object name
		if err, ok := c.getErrorMap[key.Name]; ok {
			return err
		}
	}

	return c.Client.Get(ctx, key, obj)
}

func (c *FakeClient) Create(ctx context.Context, obj kbclient.Object, opts ...kbclient.CreateOption) error {
	if c.createError != nil {
		return c.createError
	}

	return c.Client.Create(ctx, obj, opts...)
}

func (c *FakeClient) Update(ctx context.Context, obj kbclient.Object, opts ...kbclient.UpdateOption) error {
	if c.updateError != nil {
		return c.updateError
	}

	if c.updateConflict != nil {
		return c.updateConflict
	}

	return c.Client.Update(ctx, obj, opts...)
}

func (c *FakeClient) Patch(ctx context.Context, obj kbclient.Object, patch kbclient.Patch, opts ...kbclient.PatchOption) error {
	if c.patchError != nil {
		return c.patchError
	}

	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *FakeClient) List(ctx context.Context, list kbclient.ObjectList, opts ...kbclient.ListOption) error {
	if c.listError != nil {
		return c.listError
	}

	return c.Client.List(ctx, list, opts...)
}

func initDataUploaderReconciler(needError ...bool) (*DataUploadReconciler, error) {
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
			errs[4] = apierrors.NewConflict(velerov2alpha1api.Resource("dataupload"), dataUploadName, errors.New("conflict"))
		} else if k == 5 && isError {
			errs[5] = fmt.Errorf("List error")
		}
	}

	return initDataUploaderReconcilerWithError(errs...)
}

func initDataUploaderReconcilerWithError(needError ...error) (*DataUploadReconciler, error) {
	vscName := "fake-vsc"
	vsObject := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-volume-snapshot",
			Namespace: "fake-ns",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &vscName,
			ReadyToUse:                     boolptr.True(),
			RestoreSize:                    &resource.Quantity{},
		},
	}
	var restoreSize int64
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-vsc",
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			RestoreSize: &restoreSize,
		},
	}

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

	dataPathMgr := datapath.NewManager(1)

	now, err := time.Parse(time.RFC1123, time.RFC1123)
	if err != nil {
		return nil, err
	}
	now = now.Local()
	scheme := runtime.NewScheme()
	err = velerov1api.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = velerov2alpha1api.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = corev1api.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = snapshotv1api.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}

	fakeClient := &FakeClient{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(vsObject, node).Build(),
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

	fakeSnapshotClient := snapshotFake.NewSimpleClientset(vsObject, vscObj)
	fakeKubeClient := clientgofake.NewSimpleClientset(daemonSet, node)

	return NewDataUploadReconciler(
		fakeClient,
		nil,
		fakeKubeClient,
		fakeSnapshotClient.SnapshotV1(),
		dataPathMgr,
		nil,
		nil,
		map[string]velerotypes.BackupPVC{},
		corev1api.ResourceRequirements{},
		testclocks.NewFakeClock(now),
		"test-node",
		time.Minute*5,
		velerotest.NewLogger(),
		metrics.NewServerMetrics(),
		"",  // dataMovePriorityClass
		nil, // podLabels
		nil, // podAnnotations
		nil,
	), nil
}

func dataUploadBuilder() *builder.DataUploadBuilder {
	csi := &velerov2alpha1api.CSISnapshotSpec{
		SnapshotClass:  "csi-azuredisk-vsc",
		StorageClass:   "default",
		VolumeSnapshot: "fake-volume-snapshot",
	}
	return builder.ForDataUpload(velerov1api.DefaultNamespace, dataUploadName).
		BackupStorageLocation("bsl-loc").
		DataMover("velero").
		SnapshotType("CSI").SourceNamespace("fake-ns").SourcePVC("test-pvc").CSISnapshot(csi)
}

type fakeSnapshotExposer struct {
	kubeClient      kbclient.Client
	clock           clock.WithTickerAndDelayedExecution
	ambiguousNodeOS bool
	peekErr         error
	exposeErr       error
	getErr          error
	getNil          bool
}

func (f *fakeSnapshotExposer) Expose(ctx context.Context, ownerObject corev1api.ObjectReference, param any) error {
	if f.exposeErr != nil {
		return f.exposeErr
	}

	return nil
}

func (f *fakeSnapshotExposer) GetExposed(ctx context.Context, du corev1api.ObjectReference, tm time.Duration, para any) (*exposer.ExposeResult, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}

	if f.getNil {
		return nil, nil
	}

	pod := &corev1api.Pod{}

	nodeOS := "linux"
	pNodeOS := &nodeOS
	if f.ambiguousNodeOS {
		pNodeOS = nil
	}
	return &exposer.ExposeResult{ByPod: exposer.ExposeByPod{HostingPod: pod, VolumeName: dataUploadName, NodeOS: pNodeOS}}, nil
}

func (f *fakeSnapshotExposer) PeekExposed(ctx context.Context, ownerObject corev1api.ObjectReference) error {
	return f.peekErr
}

func (f *fakeSnapshotExposer) DiagnoseExpose(context.Context, corev1api.ObjectReference) string {
	return ""
}

func (f *fakeSnapshotExposer) CleanUp(context.Context, corev1api.ObjectReference, string, string) {
}

type fakeFSBR struct {
	kubeClient kbclient.Client
	clock      clock.WithTickerAndDelayedExecution
	initErr    error
	startErr   error
}

func (f *fakeFSBR) Init(ctx context.Context, param any) error {
	return f.initErr
}

func (f *fakeFSBR) StartBackup(source datapath.AccessPoint, uploaderConfigs map[string]string, param any) error {
	return f.startErr
}

func (f *fakeFSBR) StartRestore(snapshotID string, target datapath.AccessPoint, uploaderConfigs map[string]string, param any) error {
	return nil
}

func (b *fakeFSBR) Cancel() {
}

func (b *fakeFSBR) Close(ctx context.Context) {
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name                     string
		du                       *velerov2alpha1api.DataUpload
		notCreateDU              bool
		needDelete               bool
		sportTime                *metav1.Time
		pod                      *corev1api.Pod
		pvc                      *corev1api.PersistentVolumeClaim
		snapshotExposerList      map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer
		dataMgr                  *datapath.Manager
		needCreateFSBR           bool
		needExclusiveUpdateError error
		expected                 *velerov2alpha1api.DataUpload
		expectDeleted            bool
		expectCancelRecord       bool
		needErrs                 []bool
		ambiguousNodeOS          bool
		peekErr                  error
		exposeErr                error
		getExposeErr             error
		getExposeNil             bool
		fsBRInitErr              error
		fsBRStartErr             error
		constrained              bool
		expectedErr              string
		expectedResult           *ctrl.Result
		expectDataPath           bool
	}{
		{
			name:        "du not found",
			du:          dataUploadBuilder().Result(),
			notCreateDU: true,
		},
		{
			name: "du not created in velero default namespace",
			du:   builder.ForDataUpload("test-ns", dataUploadName).Result(),
		},
		{
			name:        "get du fail",
			du:          dataUploadBuilder().Result(),
			needErrs:    []bool{true, false, false, false},
			expectedErr: "getting DataUpload: Get error",
		},
		{
			name: "du is not for built-in dm",
			du:   dataUploadBuilder().DataMover("other").Result(),
		},
		{
			name:     "add finalizer to du",
			du:       dataUploadBuilder().Result(),
			expected: dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
		},
		{
			name:        "add finalizer to du failed",
			du:          dataUploadBuilder().Result(),
			needErrs:    []bool{false, false, true, false},
			expectedErr: "error updating dataupload with error velero/dataupload-1: Update error",
		},
		{
			name:       "du is under deletion",
			du:         dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			needDelete: true,
			expected:   dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Result(),
		},
		{
			name:        "du is under deletion but cancel failed",
			du:          dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			needErrs:    []bool{false, false, true, false},
			needDelete:  true,
			expectedErr: "error updating dataupload with error velero/dataupload-1: Update error",
		},
		{
			name:          "du is under deletion and in terminal state",
			du:            dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseFailed).Result(),
			sportTime:     &metav1.Time{Time: time.Now()},
			needDelete:    true,
			expectDeleted: true,
		},
		{
			name:        "du is under deletion and in terminal state, but remove finalizer failed",
			du:          dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseFailed).Result(),
			needErrs:    []bool{false, false, true, false},
			needDelete:  true,
			expectedErr: "error updating dataupload with error velero/dataupload-1: Update error",
		},
		{
			name:               "delay cancel negative for others",
			du:                 dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhasePrepared).Result(),
			sportTime:          &metav1.Time{Time: time.Now()},
			expectCancelRecord: true,
		},
		{
			name:               "delay cancel negative for inProgress",
			du:                 dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result(),
			sportTime:          &metav1.Time{Time: time.Now().Add(-time.Minute * 58)},
			expectCancelRecord: true,
		},
		{
			name:      "delay cancel affirmative for others",
			du:        dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhasePrepared).Result(),
			sportTime: &metav1.Time{Time: time.Now().Add(-time.Minute * 5)},
			expected:  dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseCanceled).Result(),
		},
		{
			name:      "delay cancel affirmative for inProgress",
			du:        dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result(),
			sportTime: &metav1.Time{Time: time.Now().Add(-time.Hour)},
			expected:  dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseCanceled).Result(),
		},
		{
			name:               "delay cancel failed",
			du:                 dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result(),
			needErrs:           []bool{false, false, true, false},
			sportTime:          &metav1.Time{Time: time.Now().Add(-time.Hour)},
			expected:           dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result(),
			expectCancelRecord: true,
		},
		{
			name: "Unknown data upload status",
			du:   dataUploadBuilder().Phase("Unknown").Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
		},
		{
			name:        "Unknown type of snapshot exposer is not initialized",
			du:          dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).SnapshotType("unknown type").Result(),
			expected:    dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseFailed).Result(),
			expectedErr: "unknown type type of snapshot exposer is not exist",
		},
		{
			name:               "du is cancel on new",
			du:                 dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Result(),
			expectCancelRecord: true,
			expected:           dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseCanceled).Result(),
		},
		{
			name:           "new du but constrained",
			du:             dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			constrained:    true,
			expected:       dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectedResult: &ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
		},
		{
			name:                     "new du but accept failed",
			du:                       dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			needExclusiveUpdateError: errors.New("exclusive-update-error"),
			expected:                 dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectedErr:              "error accepting the data upload dataupload-1: exclusive-update-error",
		},
		{
			name:        "du is accepted but setup expose param failed on getting PVC",
			du:          dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expected:    dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseFailed).Message("failed to set exposer parameters").Result(),
			expectedErr: "failed to get PVC fake-ns/test-pvc: persistentvolumeclaims \"test-pvc\" not found",
		},
		{
			name:        "du expose failed",
			du:          dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).SnapshotType(fakeSnapshotType).Result(),
			pvc:         builder.ForPersistentVolumeClaim("fake-ns", "test-pvc").Result(),
			exposeErr:   errors.New("fake-expose-error"),
			expected:    dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseFailed).Message("error exposing snapshot").Result(),
			expectedErr: "fake-expose-error",
		},
		{
			name:     "du succeeds for accepted",
			du:       dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).SnapshotType(fakeSnapshotType).Result(),
			pvc:      builder.ForPersistentVolumeClaim("fake-ns", "test-pvc").VolumeName("test-pv").Result(),
			expected: dataUploadBuilder().Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseAccepted).Result(),
		},
		{
			name:     "prepare timeout on accepted",
			du:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Finalizers([]string{DataUploadDownloadFinalizer}).AcceptedTimestamp(&metav1.Time{Time: time.Now().Add(-time.Minute * 30)}).Result(),
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseFailed).Message("timeout on preparing data upload").Result(),
		},
		{
			name:     "peek error on accepted",
			du:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			peekErr:  errors.New("fake-peak-error"),
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseCanceled).Finalizers([]string{DataUploadDownloadFinalizer}).Phase(velerov2alpha1api.DataUploadPhaseCanceled).Message("found a du velero/dataupload-1 with expose error: fake-peak-error. mark it as cancel").Result(),
		},
		{
			name:     "cancel on prepared",
			du:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Cancel(true).Result(),
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseCanceled).Finalizers([]string{DataUploadDownloadFinalizer}).Cancel(true).Phase(velerov2alpha1api.DataUploadPhaseCanceled).Result(),
		},
		{
			name:         "Failed to get snapshot expose on prepared",
			du:           dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			getExposeErr: errors.New("fake-get-error"),
			expected:     dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Finalizers([]string{DataUploadDownloadFinalizer}).Message("exposed snapshot is not ready: fake-get-error").Result(),
			expectedErr:  "fake-get-error",
		},
		{
			name:         "Get nil restore expose on prepared",
			du:           dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			getExposeNil: true,
			expected:     dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Finalizers([]string{DataUploadDownloadFinalizer}).Message("exposed snapshot is not ready").Result(),
			expectedErr:  "no expose result is available for the current node",
		},
		{
			name:            "Dataupload should fail if expose returns ambiguous nodeOS",
			du:              dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			ambiguousNodeOS: true,
			expected:        dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectedErr:     "unsupported ambiguous node OS",
		},
		{
			name:           "Error in data path is concurrent limited",
			du:             dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			dataMgr:        datapath.NewManager(0),
			expectedResult: &ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
		},
		{
			name:        "data path init error",
			du:          dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			fsBRInitErr: errors.New("fake-data-path-init-error"),
			expected:    dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Finalizers([]string{DataUploadDownloadFinalizer}).Message("error initializing data path").Result(),
			expectedErr: "error initializing asyncBR: fake-data-path-init-error",
		},
		{
			name:           "Unable to update status to in progress for data upload",
			du:             dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			needErrs:       []bool{false, false, true, false},
			expected:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectedResult: &ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
		},
		{
			name:         "data path start error",
			du:           dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			fsBRStartErr: errors.New("fake-data-path-start-error"),
			expected:     dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Finalizers([]string{DataUploadDownloadFinalizer}).Message("error starting data path").Result(),
			expectedErr:  "error starting async backup for pod , volume dataupload-1: fake-data-path-start-error",
		},
		{
			name:           "Prepare succeeds",
			du:             dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).SnapshotType(fakeSnapshotType).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			expected:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectDataPath: true,
		},
		{
			name:     "In progress du is not handled by the current node",
			du:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
		},
		{
			name:     "In progress du is not set as cancel",
			du:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
		},
		{
			name:     "Cancel data upload in progress with empty FSBR",
			du:       dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Cancel(true).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseCanceled).Cancel(true).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
		},
		{
			name:               "Cancel data upload in progress and patch data upload error",
			du:                 dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Cancel(true).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			needErrs:           []bool{false, false, true, false},
			needCreateFSBR:     true,
			expected:           dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Cancel(true).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectedErr:        "error updating dataupload with error velero/dataupload-1: Update error",
			expectCancelRecord: true,
			expectDataPath:     true,
		},
		{
			name:               "Cancel data upload in progress succeeds",
			du:                 dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Cancel(true).Finalizers([]string{DataUploadDownloadFinalizer}).Node("test-node").Result(),
			needCreateFSBR:     true,
			expected:           dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseCanceling).Cancel(true).Finalizers([]string{DataUploadDownloadFinalizer}).Result(),
			expectDataPath:     true,
			expectCancelRecord: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := initDataUploaderReconciler(test.needErrs...)
			require.NoError(t, err)

			if !test.notCreateDU {
				err = r.client.Create(t.Context(), test.du)
				require.NoError(t, err)
			}

			if test.needDelete {
				err = r.client.Delete(t.Context(), test.du)
				require.NoError(t, err)
			}

			if test.pod != nil {
				err = r.client.Create(ctx, test.pod)
				require.NoError(t, err)
			}

			if test.pvc != nil {
				err = r.client.Create(ctx, test.pvc)
				require.NoError(t, err)

				// Create the corresponding PV if PVC references one
				if test.pvc.Spec.VolumeName != "" {
					pv := builder.ForPersistentVolume(test.pvc.Spec.VolumeName).
						CSI("csi.driver", "test-volume-id").
						ClaimRef(test.pvc.Namespace, test.pvc.Name).Result()
					err = r.client.Create(ctx, pv)
					require.NoError(t, err)
				}
			}

			if test.dataMgr != nil {
				r.dataPathMgr = test.dataMgr
			} else {
				r.dataPathMgr = datapath.NewManager(1)
			}

			if test.sportTime != nil {
				r.cancelledDataUpload[test.du.Name] = test.sportTime.Time
			}

			if test.constrained {
				r.vgdpCounter = &exposer.VgdpCounter{}
			}

			if test.du.Spec.SnapshotType == fakeSnapshotType {
				r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{fakeSnapshotType: &fakeSnapshotExposer{r.client, r.Clock, test.ambiguousNodeOS, test.peekErr, test.exposeErr, test.getExposeErr, test.getExposeNil}}
			} else if test.du.Spec.SnapshotType == velerov2alpha1api.SnapshotTypeCSI {
				r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger())}
			}

			funcExclusiveUpdateDataUpload = exclusiveUpdateDataUpload
			if test.needExclusiveUpdateError != nil {
				funcExclusiveUpdateDataUpload = func(context.Context, kbclient.Client, *velerov2alpha1api.DataUpload, func(*velerov2alpha1api.DataUpload)) (bool, error) {
					return false, test.needExclusiveUpdateError
				}
			}

			datapath.MicroServiceBRWatcherCreator = func(kbclient.Client, kubernetes.Interface, manager.Manager, string, string, string, string, string, string, datapath.Callbacks, logrus.FieldLogger) datapath.AsyncBR {
				return &fakeFSBR{
					kubeClient: r.client,
					clock:      r.Clock,
					initErr:    test.fsBRInitErr,
					startErr:   test.fsBRStartErr,
				}
			}

			if test.needCreateFSBR {
				if fsBR := r.dataPathMgr.GetAsyncBR(test.du.Name); fsBR == nil {
					_, err := r.dataPathMgr.CreateMicroServiceBRWatcher(ctx, r.client, nil, nil, datapath.TaskTypeBackup, test.du.Name, velerov1api.DefaultNamespace, "", "", "", datapath.Callbacks{OnCancelled: r.OnDataUploadCancelled}, false, velerotest.NewLogger())
					require.NoError(t, err)
				}
			}

			actualResult, err := r.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: velerov1api.DefaultNamespace,
					Name:      test.du.Name,
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

			du := velerov2alpha1api.DataUpload{}
			err = r.client.Get(ctx, kbclient.ObjectKey{
				Name:      test.du.Name,
				Namespace: test.du.Namespace,
			}, &du)

			if test.expected != nil || test.expectDeleted {
				if test.expectDeleted {
					assert.True(t, apierrors.IsNotFound(err))
				} else {
					require.NoError(t, err)

					assert.Equal(t, test.expected.Status.Phase, du.Status.Phase)
					assert.Contains(t, du.Status.Message, test.expected.Status.Message)
					assert.Equal(t, du.Finalizers, test.expected.Finalizers)
					assert.Equal(t, du.Spec.Cancel, test.expected.Spec.Cancel)
				}
			}

			if !test.expectDataPath {
				assert.Nil(t, r.dataPathMgr.GetAsyncBR(test.du.Name))
			} else {
				assert.NotNil(t, r.dataPathMgr.GetAsyncBR(test.du.Name))
			}

			if test.expectCancelRecord {
				assert.Contains(t, r.cancelledDataUpload, test.du.Name)
			} else {
				assert.Empty(t, r.cancelledDataUpload)
			}

			if isDataUploadInFinalState(&du) || du.Status.Phase == velerov2alpha1api.DataUploadPhaseInProgress {
				assert.NotContains(t, du.Labels, exposer.ExposeOnGoingLabel)
			} else if du.Status.Phase == velerov2alpha1api.DataUploadPhaseAccepted {
				assert.Contains(t, du.Labels, exposer.ExposeOnGoingLabel)
			}
		})
	}
}

func TestOnDataUploadCancelled(t *testing.T) {
	ctx := t.Context()
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)
	// Create a DataUpload object
	du := dataUploadBuilder().Result()
	namespace := du.Namespace
	duName := du.Name
	// Add the DataUpload object to the fake client
	require.NoError(t, r.client.Create(ctx, du))

	r.OnDataUploadCancelled(ctx, namespace, duName)
	updatedDu := &velerov2alpha1api.DataUpload{}
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, updatedDu))
	assert.Equal(t, velerov2alpha1api.DataUploadPhaseCanceled, updatedDu.Status.Phase)
	assert.False(t, updatedDu.Status.CompletionTimestamp.IsZero())
	assert.False(t, updatedDu.Status.StartTimestamp.IsZero())
}

func TestOnDataUploadProgress(t *testing.T) {
	totalBytes := int64(1024)
	bytesDone := int64(512)
	tests := []struct {
		name     string
		du       *velerov2alpha1api.DataUpload
		progress uploader.Progress
		needErrs []bool
	}{
		{
			name: "patch in progress phase success",
			du:   dataUploadBuilder().Result(),
			progress: uploader.Progress{
				TotalBytes: totalBytes,
				BytesDone:  bytesDone,
			},
		},
		{
			name:     "failed to get dataupload",
			du:       dataUploadBuilder().Result(),
			needErrs: []bool{true, false, false, false},
		},
		{
			name:     "failed to patch dataupload",
			du:       dataUploadBuilder().Result(),
			needErrs: []bool{false, false, true, false},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()

			r, err := initDataUploaderReconciler(test.needErrs...)
			require.NoError(t, err)
			defer func() {
				r.client.Delete(ctx, test.du, &kbclient.DeleteOptions{})
			}()
			// Create a DataUpload object
			du := dataUploadBuilder().Result()
			namespace := du.Namespace
			duName := du.Name
			// Add the DataUpload object to the fake client
			require.NoError(t, r.client.Create(t.Context(), du))

			// Create a Progress object
			progress := &uploader.Progress{
				TotalBytes: totalBytes,
				BytesDone:  bytesDone,
			}

			// Call the OnDataUploadProgress function
			r.OnDataUploadProgress(ctx, namespace, duName, progress)
			if len(test.needErrs) != 0 && !test.needErrs[0] {
				// Get the updated DataUpload object from the fake client
				updatedDu := &velerov2alpha1api.DataUpload{}
				require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, updatedDu))
				// Assert that the DataUpload object has been updated with the progress
				assert.Equal(t, test.progress.TotalBytes, updatedDu.Status.Progress.TotalBytes)
				assert.Equal(t, test.progress.BytesDone, updatedDu.Status.Progress.BytesDone)
			}
		})
	}
}

func TestOnDataUploadFailed(t *testing.T) {
	ctx := t.Context()
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)

	// Create a DataUpload object
	du := dataUploadBuilder().Result()
	namespace := du.Namespace
	duName := du.Name
	// Add the DataUpload object to the fake client
	require.NoError(t, r.client.Create(ctx, du))
	r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger())}
	r.OnDataUploadFailed(ctx, namespace, duName, fmt.Errorf("Failed to handle %v", duName))
	updatedDu := &velerov2alpha1api.DataUpload{}
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, updatedDu))
	assert.Equal(t, velerov2alpha1api.DataUploadPhaseFailed, updatedDu.Status.Phase)
	assert.False(t, updatedDu.Status.CompletionTimestamp.IsZero())
	assert.False(t, updatedDu.Status.StartTimestamp.IsZero())
}

func TestOnDataUploadCompleted(t *testing.T) {
	ctx := t.Context()
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)
	// Create a DataUpload object
	du := dataUploadBuilder().Result()
	namespace := du.Namespace
	duName := du.Name
	// Add the DataUpload object to the fake client
	require.NoError(t, r.client.Create(ctx, du))
	r.snapshotExposerList = map[velerov2alpha1api.SnapshotType]exposer.SnapshotExposer{velerov2alpha1api.SnapshotTypeCSI: exposer.NewCSISnapshotExposer(r.kubeClient, r.csiSnapshotClient, velerotest.NewLogger())}
	r.OnDataUploadCompleted(ctx, namespace, duName, datapath.Result{
		Backup: datapath.BackupResult{
			SnapshotID: "fake-id",
			Source: datapath.AccessPoint{
				ByPath: "fake-path",
			},
		},
	})
	updatedDu := &velerov2alpha1api.DataUpload{}
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: duName, Namespace: namespace}, updatedDu))
	assert.Equal(t, velerov2alpha1api.DataUploadPhaseCompleted, updatedDu.Status.Phase)
	assert.False(t, updatedDu.Status.CompletionTimestamp.IsZero())
	assert.Equal(t, "fake-id", updatedDu.Status.SnapshotID)
	assert.Equal(t, "fake-path", updatedDu.Status.Path)
}

func TestFindDataUploadForPod(t *testing.T) {
	r, err := initDataUploaderReconciler()
	require.NoError(t, err)
	tests := []struct {
		name      string
		du        *velerov2alpha1api.DataUpload
		pod       *corev1api.Pod
		checkFunc func(*velerov2alpha1api.DataUpload, []reconcile.Request)
	}{
		{
			name: "find dataUpload for pod",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, dataUploadName).Labels(map[string]string{velerov1api.DataUploadLabel: dataUploadName}).Status(corev1api.PodStatus{Phase: corev1api.PodRunning}).Result(),
			checkFunc: func(du *velerov2alpha1api.DataUpload, requests []reconcile.Request) {
				// Assert that the function returns a single request
				assert.Len(t, requests, 1)
				// Assert that the request contains the correct namespaced name
				assert.Equal(t, du.Namespace, requests[0].Namespace)
				assert.Equal(t, du.Name, requests[0].Name)
			},
		}, {
			name: "no selected label found for pod",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, dataUploadName).Result(),
			checkFunc: func(du *velerov2alpha1api.DataUpload, requests []reconcile.Request) {
				// Assert that the function returns a single request
				assert.Empty(t, requests)
			},
		}, {
			name: "no matched pod",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, dataUploadName).Labels(map[string]string{velerov1api.DataUploadLabel: "non-existing-dataupload"}).Result(),
			checkFunc: func(du *velerov2alpha1api.DataUpload, requests []reconcile.Request) {
				assert.Empty(t, requests)
			},
		},
		{
			name: "dataUpload not accepte",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result(),
			pod:  builder.ForPod(velerov1api.DefaultNamespace, dataUploadName).Labels(map[string]string{velerov1api.DataUploadLabel: dataUploadName}).Result(),
			checkFunc: func(du *velerov2alpha1api.DataUpload, requests []reconcile.Request) {
				assert.Empty(t, requests)
			},
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		assert.NoError(t, r.client.Create(ctx, test.pod))
		assert.NoError(t, r.client.Create(ctx, test.du))
		// Call the findDataUploadForPod function
		requests := r.findDataUploadForPod(t.Context(), test.pod)
		test.checkFunc(test.du, requests)
		r.client.Delete(ctx, test.du, &kbclient.DeleteOptions{})
		if test.pod != nil {
			r.client.Delete(ctx, test.pod, &kbclient.DeleteOptions{})
		}
	}
}

type fakeAPIStatus struct {
	reason metav1.StatusReason
}

func (f *fakeAPIStatus) Status() metav1.Status {
	return metav1.Status{
		Reason: f.reason,
	}
}

func (f *fakeAPIStatus) Error() string {
	return string(f.reason)
}

func TestAcceptDataUpload(t *testing.T) {
	tests := []struct {
		name        string
		du          *velerov2alpha1api.DataUpload
		needErrs    []error
		succeeded   bool
		expectedErr string
	}{
		{
			name:        "update fail",
			du:          dataUploadBuilder().Result(),
			needErrs:    []error{nil, nil, fmt.Errorf("fake-update-error"), nil},
			expectedErr: "fake-update-error",
		},
		{
			name:     "accepted by others",
			du:       dataUploadBuilder().Result(),
			needErrs: []error{nil, nil, &fakeAPIStatus{metav1.StatusReasonConflict}, nil},
		},
		{
			name:      "succeed",
			du:        dataUploadBuilder().Result(),
			needErrs:  []error{nil, nil, nil, nil},
			succeeded: true,
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		r, err := initDataUploaderReconcilerWithError(test.needErrs...)
		require.NoError(t, err)

		err = r.client.Create(ctx, test.du)
		require.NoError(t, err)

		succeeded, err := r.acceptDataUpload(ctx, test.du)
		assert.Equal(t, test.succeeded, succeeded)
		if test.expectedErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, test.expectedErr)
		}
	}
}

func TestOnDuPrepareTimeout(t *testing.T) {
	tests := []struct {
		name     string
		du       *velerov2alpha1api.DataUpload
		needErrs []error
		expected *velerov2alpha1api.DataUpload
	}{
		{
			name:     "update fail",
			du:       dataUploadBuilder().Result(),
			needErrs: []error{nil, nil, fmt.Errorf("fake-update-error"), nil},
			expected: dataUploadBuilder().Result(),
		},
		{
			name:     "update interrupted",
			du:       dataUploadBuilder().Result(),
			needErrs: []error{nil, nil, &fakeAPIStatus{metav1.StatusReasonConflict}, nil},
			expected: dataUploadBuilder().Result(),
		},
		{
			name:     "succeed",
			du:       dataUploadBuilder().Result(),
			needErrs: []error{nil, nil, nil, nil},
			expected: dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseFailed).Result(),
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		r, err := initDataUploaderReconcilerWithError(test.needErrs...)
		require.NoError(t, err)

		err = r.client.Create(ctx, test.du)
		require.NoError(t, err)

		r.onPrepareTimeout(ctx, test.du)

		du := velerov2alpha1api.DataUpload{}
		_ = r.client.Get(ctx, kbclient.ObjectKey{
			Name:      test.du.Name,
			Namespace: test.du.Namespace,
		}, &du)

		assert.Equal(t, test.expected.Status.Phase, du.Status.Phase)
	}
}

func TestTryCancelDataUpload(t *testing.T) {
	tests := []struct {
		name        string
		dd          *velerov2alpha1api.DataUpload
		needErrs    []error
		succeeded   bool
		expectedErr string
	}{
		{
			name:     "update fail",
			dd:       dataUploadBuilder().Result(),
			needErrs: []error{nil, nil, fmt.Errorf("fake-update-error"), nil},
		},
		{
			name:     "cancel by others",
			dd:       dataUploadBuilder().Result(),
			needErrs: []error{nil, nil, &fakeAPIStatus{metav1.StatusReasonConflict}, nil},
		},
		{
			name:      "succeed",
			dd:        dataUploadBuilder().Result(),
			needErrs:  []error{nil, nil, nil, nil},
			succeeded: true,
		},
	}
	for _, test := range tests {
		ctx := t.Context()
		r, err := initDataUploaderReconcilerWithError(test.needErrs...)
		require.NoError(t, err)

		err = r.client.Create(ctx, test.dd)
		require.NoError(t, err)

		r.tryCancelDataUpload(ctx, test.dd, "")

		if test.expectedErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, test.expectedErr)
		}
	}
}

func TestUpdateDataUploadWithRetry(t *testing.T) {
	namespacedName := types.NamespacedName{
		Name:      dataUploadName,
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
			r, err := initDataUploaderReconciler(tc.needErrs...)
			require.NoError(t, err)
			err = r.client.Create(ctx, dataUploadBuilder().Result())
			require.NoError(t, err)
			updateFunc := func(dataDownload *velerov2alpha1api.DataUpload) bool {
				if tc.noChange {
					return false
				}

				dataDownload.Spec.Cancel = true
				return true
			}
			err = UpdateDataUploadWithRetry(ctx, r.client, namespacedName, velerotest.NewLogger().WithField("name", tc.Name), updateFunc)
			if tc.ExpectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type duResumeTestHelper struct {
	resumeErr    error
	getExposeErr error
	exposeResult *exposer.ExposeResult
	asyncBR      datapath.AsyncBR
}

func (dt *duResumeTestHelper) resumeCancellableDataPath(_ *DataUploadReconciler, _ context.Context, _ *velerov2alpha1api.DataUpload, _ logrus.FieldLogger) error {
	return dt.resumeErr
}

func (dt *duResumeTestHelper) Expose(context.Context, corev1api.ObjectReference, any) error {
	return nil
}

func (dt *duResumeTestHelper) GetExposed(context.Context, corev1api.ObjectReference, time.Duration, any) (*exposer.ExposeResult, error) {
	return dt.exposeResult, dt.getExposeErr
}

func (dt *duResumeTestHelper) PeekExposed(context.Context, corev1api.ObjectReference) error {
	return nil
}

func (dt *duResumeTestHelper) DiagnoseExpose(context.Context, corev1api.ObjectReference) string {
	return ""
}

func (dt *duResumeTestHelper) CleanUp(context.Context, corev1api.ObjectReference, string, string) {}

func (dt *duResumeTestHelper) newMicroServiceBRWatcher(kbclient.Client, kubernetes.Interface, manager.Manager, string, string, string, string, string, string,
	datapath.Callbacks, logrus.FieldLogger) datapath.AsyncBR {
	return dt.asyncBR
}

func TestAttemptDataUploadResume(t *testing.T) {
	tests := []struct {
		name                  string
		dataUploads           []velerov2alpha1api.DataUpload
		du                    *velerov2alpha1api.DataUpload
		needErrs              []bool
		acceptedDataUploads   []string
		prepareddDataUploads  []string
		cancelledDataUploads  []string
		inProgressDataUploads []string
		resumeErr             error
		expectedError         string
	}{
		{
			name: "Other DataUpload",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).Result(),
		},
		{
			name:                  "InProgress DataUpload, not the current node",
			du:                    dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Result(),
			inProgressDataUploads: []string{dataUploadName},
		},
		{
			name:                  "InProgress DataUpload, resume error and update error",
			du:                    dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Node("node-1").Result(),
			needErrs:              []bool{false, false, true, false, false, false},
			resumeErr:             errors.New("fake-resume-error"),
			inProgressDataUploads: []string{dataUploadName},
		},
		{
			name:                  "InProgress DataUpload, resume error and update succeed",
			du:                    dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Node("node-1").Result(),
			resumeErr:             errors.New("fake-resume-error"),
			cancelledDataUploads:  []string{dataUploadName},
			inProgressDataUploads: []string{dataUploadName},
		},
		{
			name:                  "InProgress DataUpload and resume succeed",
			du:                    dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).Node("node-1").Result(),
			inProgressDataUploads: []string{dataUploadName},
		},
		{
			name:          "Error",
			needErrs:      []bool{false, false, false, false, false, true},
			du:            dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhasePrepared).Result(),
			expectedError: "error to list datauploads: List error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			r, err := initDataUploaderReconciler(test.needErrs...)
			r.nodeName = "node-1"
			require.NoError(t, err)

			assert.NoError(t, r.client.Create(ctx, test.du))

			dt := &duResumeTestHelper{
				resumeErr: test.resumeErr,
			}

			funcResumeCancellableDataBackup = dt.resumeCancellableDataPath

			// Run the test
			err = r.AttemptDataUploadResume(ctx, r.logger.WithField("name", test.name), test.du.Namespace)

			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
			} else {
				assert.NoError(t, err)

				// Verify DataUploads marked as Canceled
				for _, duName := range test.cancelledDataUploads {
					dataUpload := &velerov2alpha1api.DataUpload{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: duName}, dataUpload)
					require.NoError(t, err)
					assert.True(t, dataUpload.Spec.Cancel)
				}
				// Verify DataUploads marked as Accepted
				for _, duName := range test.acceptedDataUploads {
					dataUpload := &velerov2alpha1api.DataUpload{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: duName}, dataUpload)
					require.NoError(t, err)
					assert.Equal(t, velerov2alpha1api.DataUploadPhaseAccepted, dataUpload.Status.Phase)
				}
				// Verify DataUploads marked as Prepared
				for _, duName := range test.prepareddDataUploads {
					dataUpload := &velerov2alpha1api.DataUpload{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: duName}, dataUpload)
					require.NoError(t, err)
					assert.Equal(t, velerov2alpha1api.DataUploadPhasePrepared, dataUpload.Status.Phase)
				}
				// Verify DataUploads marked as InProgress
				for _, duName := range test.inProgressDataUploads {
					dataUpload := &velerov2alpha1api.DataUpload{}
					err := r.client.Get(t.Context(), types.NamespacedName{Namespace: "velero", Name: duName}, dataUpload)
					require.NoError(t, err)
					assert.Equal(t, velerov2alpha1api.DataUploadPhaseInProgress, dataUpload.Status.Phase)
				}
			}
		})
	}
}

func TestResumeCancellableBackup(t *testing.T) {
	tests := []struct {
		name             string
		dataUploads      []velerov2alpha1api.DataUpload
		du               *velerov2alpha1api.DataUpload
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
			name:          "not find exposer",
			du:            dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).SnapshotType("").Result(),
			expectedError: fmt.Sprintf("error to find exposer for du %s", dataUploadName),
		},
		{
			name:          "get expose failed",
			du:            dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseInProgress).SnapshotType(velerov2alpha1api.SnapshotTypeCSI).Result(),
			getExposeErr:  errors.New("fake-expose-error"),
			expectedError: fmt.Sprintf("error to get exposed snapshot for du %s: fake-expose-error", dataUploadName),
		},
		{
			name:          "no expose",
			du:            dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Node("node-1").Result(),
			expectedError: fmt.Sprintf("expose info missed for du %s", dataUploadName),
		},
		{
			name: "watcher init error",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Node("node-1").Result(),
			exposeResult: &exposer.ExposeResult{
				ByPod: exposer.ExposeByPod{
					HostingPod: &corev1api.Pod{},
				},
			},
			mockInit:       true,
			mockClose:      true,
			initWatcherErr: errors.New("fake-init-watcher-error"),
			expectedError:  fmt.Sprintf("error to init asyncBR watcher for du %s: fake-init-watcher-error", dataUploadName),
		},
		{
			name: "start watcher error",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Node("node-1").Result(),
			exposeResult: &exposer.ExposeResult{
				ByPod: exposer.ExposeByPod{
					HostingPod: &corev1api.Pod{},
				},
			},
			mockInit:        true,
			mockStart:       true,
			mockClose:       true,
			startWatcherErr: errors.New("fake-start-watcher-error"),
			expectedError:   fmt.Sprintf("error to resume asyncBR watcher for du %s: fake-start-watcher-error", dataUploadName),
		},
		{
			name: "succeed",
			du:   dataUploadBuilder().Phase(velerov2alpha1api.DataUploadPhaseAccepted).Node("node-1").Result(),
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
			r, err := initDataUploaderReconciler()
			r.nodeName = "node-1"
			require.NoError(t, err)

			mockAsyncBR := datapathmocks.NewAsyncBR(t)

			if test.mockInit {
				mockAsyncBR.On("Init", mock.Anything, mock.Anything).Return(test.initWatcherErr)
			}

			if test.mockStart {
				mockAsyncBR.On("StartBackup", mock.Anything, mock.Anything, mock.Anything).Return(test.startWatcherErr)
			}

			if test.mockClose {
				mockAsyncBR.On("Close", mock.Anything).Return()
			}

			dt := &duResumeTestHelper{
				getExposeErr: test.getExposeErr,
				exposeResult: test.exposeResult,
				asyncBR:      mockAsyncBR,
			}

			r.snapshotExposerList[velerov2alpha1api.SnapshotTypeCSI] = dt

			datapath.MicroServiceBRWatcherCreator = dt.newMicroServiceBRWatcher

			err = r.resumeCancellableDataPath(ctx, test.du, velerotest.NewLogger())
			if test.expectedError != "" {
				assert.EqualError(t, err, test.expectedError)
			}
		})
	}
}

func TestDataUploadSetupExposeParam(t *testing.T) {
	// Common objects for all cases
	fileMode := corev1api.PersistentVolumeFilesystem
	node := builder.ForNode("worker-1").Labels(map[string]string{kube.NodeOSLabel: kube.NodeOSLinux}).Result()

	pvc := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app-ns",
			Name:      "test-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "test-pv",
			VolumeMode: &fileMode,
			Resources: corev1api.VolumeResourceRequirements{
				Requests: corev1api.ResourceList{
					corev1api.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	pv := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pv",
		},
	}

	baseDataUpload := dataUploadBuilder().Result()
	baseDataUpload.Spec.SourceNamespace = "app-ns"
	baseDataUpload.Spec.SourcePVC = "test-pvc"
	baseDataUpload.Namespace = velerov1api.DefaultNamespace
	baseDataUpload.Spec.OperationTimeout = metav1.Duration{Duration: time.Minute * 10}

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
					velerov1api.DataUploadLabel: baseDataUpload.Name,
					"custom-label":              "label-value",
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
				labels:      map[string]string{velerov1api.DataUploadLabel: baseDataUpload.Name},
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
				labels:      map[string]string{velerov1api.DataUploadLabel: baseDataUpload.Name},
				annotations: map[string]string{"custom-annotation": "annotation-value"},
			},
		},
		{
			name: "both label and annotation have customize values",
			args: args{
				customLabels:      map[string]string{"custom-label": "label-value"},
				customAnnotations: map[string]string{"custom-annotation": "annotation-value"},
			},
			want: want{
				labels: map[string]string{
					velerov1api.DataUploadLabel: baseDataUpload.Name,
					"custom-label":              "label-value",
				},
				annotations: map[string]string{"custom-annotation": "annotation-value"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fake clients per case
			fakeCRClient := velerotest.NewFakeControllerRuntimeClient(t, pvc, pv, node, baseDataUpload.DeepCopy())
			fakeKubeClient := clientgofake.NewSimpleClientset(node)

			// Reconciler config per case
			preparingTimeout := time.Minute * 3
			podRes := corev1api.ResourceRequirements{}
			r := NewDataUploadReconciler(
				fakeCRClient,
				nil,
				fakeKubeClient,
				nil, // snapshotClient (unused in setupExposeParam)
				datapath.NewManager(1),
				nil, // dataPathMgr
				nil, // exposer (unused in setupExposeParam)
				map[string]velerotypes.BackupPVC{},
				podRes,
				testclocks.NewFakeClock(time.Now()),
				"test-node",
				preparingTimeout,
				velerotest.NewLogger(),
				metrics.NewServerMetrics(),
				"upload-priority",
				tt.args.customLabels,
				tt.args.customAnnotations,
				nil,
			)

			// Act
			got, err := r.setupExposeParam(baseDataUpload)

			// Assert no error
			require.NoError(t, err)
			require.NotNil(t, got)

			// Type assertion to CSISnapshotExposeParam
			csiParam, ok := got.(*exposer.CSISnapshotExposeParam)
			require.True(t, ok, "expected CSISnapshotExposeParam type")

			// Labels and Annotations
			assert.Equal(t, tt.want.labels, csiParam.HostingPodLabels)
			assert.Equal(t, tt.want.annotations, csiParam.HostingPodAnnotations)
		})
	}
}
