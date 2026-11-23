/*
Copyright the Velero contributors.

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
	"testing"
	"time"

	v2 "github.com/velero-io/velero/pkg/plugin/velero/backupitemaction/v2"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/itemoperation"
	"github.com/velero-io/velero/pkg/itemoperationmap"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/metrics"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"
	"github.com/velero-io/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/velero-io/velero/pkg/plugin/mocks"
	"github.com/velero-io/velero/pkg/plugin/velero"
	biav2mocks "github.com/velero-io/velero/pkg/plugin/velero/mocks/backupitemaction/v2"
	velerotest "github.com/velero-io/velero/pkg/test"
)

var (
	pluginManager = &pluginmocks.Manager{}
	backupStore   = &persistencemocks.BackupStore{}
	bia           = &biav2mocks.BackupItemAction{}
)

func mockBackupOperationsReconciler(fakeClient kbclient.Client, fakeClock *testclocks.FakeClock, freq time.Duration) *backupOperationsReconciler {
	abor := NewBackupOperationsReconciler(
		logrus.StandardLogger(),
		fakeClient,
		freq,
		func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
		NewFakeSingleObjectBackupStoreGetter(backupStore),
		metrics.NewServerMetrics(),
		itemoperationmap.NewBackupItemOperationsMap(),
	)
	abor.clock = fakeClock
	return abor
}

func TestBackupOperationsReconcile(t *testing.T) {
	fakeClock := testclocks.NewFakeClock(time.Now())
	metav1Now := metav1.NewTime(fakeClock.Now())

	defaultBackupLocation := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Result()

	tests := []struct {
		name              string
		backup            *velerov1api.Backup
		backupOperations  []*itemoperation.BackupOperation
		backupLocation    *velerov1api.BackupStorageLocation
		operationComplete bool
		operationErr      string
		expectError       bool
		expectPhase       velerov1api.BackupPhase
	}{
		{
			name: "WaitingForPluginOperations backup with completed operations is Finalizing",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").
				StorageLocation("default").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-11")).
				Phase(velerov1api.BackupPhaseWaitingForPluginOperations).Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			expectPhase:       velerov1api.BackupPhaseFinalizing,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-11",
						BackupUID:        "foo-11",
						BackupItemAction: "foo-11",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-11",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseNew,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperations backup with incomplete operations is still incomplete",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").
				StorageLocation("default").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-12")).
				Phase(velerov1api.BackupPhaseWaitingForPluginOperations).Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: false,
			expectPhase:       velerov1api.BackupPhaseWaitingForPluginOperations,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-12",
						BackupUID:        "foo-12",
						BackupItemAction: "foo-12",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-12",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseNew,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperations backup with completed failed operations is FinalizingPartiallyFailed",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-13").
				StorageLocation("default").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-13")).
				Phase(velerov1api.BackupPhaseWaitingForPluginOperations).Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			operationErr:      "failed",
			expectPhase:       velerov1api.BackupPhaseFinalizingPartiallyFailed,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-13",
						BackupUID:        "foo-13",
						BackupItemAction: "foo-13",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-13",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseNew,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperationsPartiallyFailed backup with completed operations is FinalizingPartiallyFailed",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-14").
				StorageLocation("default").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-14")).
				Phase(velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed).Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			expectPhase:       velerov1api.BackupPhaseFinalizingPartiallyFailed,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-14",
						BackupUID:        "foo-14",
						BackupItemAction: "foo-14",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-14",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseNew,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperationsPartiallyFailed backup with incomplete operations is still incomplete",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-15").
				StorageLocation("default").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-15")).
				Phase(velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed).Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: false,
			expectPhase:       velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-15",
						BackupUID:        "foo-15",
						BackupItemAction: "foo-15",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-15",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseNew,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperationsPartiallyFailed backup with completed failed operations is FinalizingPartiallyFailed",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-16").
				StorageLocation("default").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-16")).
				Phase(velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed).Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			operationErr:      "failed",
			expectPhase:       velerov1api.BackupPhaseFinalizingPartiallyFailed,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-16",
						BackupUID:        "foo-16",
						BackupItemAction: "foo-16",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-16",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseNew,
						Created: &metav1Now,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.backup == nil {
				return
			}

			initObjs := []runtime.Object{}
			initObjs = append(initObjs, test.backup)

			if test.backupLocation != nil {
				initObjs = append(initObjs, test.backupLocation)
			}

			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)
			reconciler := mockBackupOperationsReconciler(fakeClient, fakeClock, defaultBackupOperationsFrequency)
			pluginManager.On("CleanupClients").Return(nil)
			backupStore.On("GetBackupItemOperations", test.backup.Name).Return(test.backupOperations, nil)
			backupStore.On("PutBackupItemOperations", mock.Anything, mock.Anything).Return(nil)
			backupStore.On("PutBackupMetadata", mock.Anything, mock.Anything).Return(nil)
			for _, operation := range test.backupOperations {
				bia.On("Name").Return("test")
				bia.On("Progress", operation.Spec.OperationID, mock.Anything).
					Return(velero.OperationProgress{
						Completed: test.operationComplete,
						Err:       test.operationErr,
					}, nil)
				pluginManager.On("GetBackupItemActionV2", operation.Spec.BackupItemAction).Return(bia, nil)
			}
			_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: test.backup.Namespace, Name: test.backup.Name}})
			gotErr := err != nil
			assert.Equal(t, test.expectError, gotErr)

			backupAfter := velerov1api.Backup{}
			err = fakeClient.Get(t.Context(), types.NamespacedName{
				Namespace: test.backup.Namespace,
				Name:      test.backup.Name,
			}, &backupAfter)

			require.NoError(t, err)
			assert.Equal(t, test.expectPhase, backupAfter.Status.Phase)
		})
	}
}

func TestWrapErrMsg(t *testing.T) {
	bia2 := &biav2mocks.BackupItemAction{}
	bia2.On("Name").Return("test-bia")
	cases := []struct {
		name     string
		inputErr string
		plugin   v2.BackupItemAction
		expect   string
	}{
		{
			name:     "empty error message",
			inputErr: "",
			plugin:   bia2,
			expect:   "plugin: test-bia",
		},
		{
			name:     "nil bia",
			inputErr: "some error happened",
			plugin:   nil,
			expect:   "some error happened, plugin: unknown",
		},
		{
			name:     "regular error and bia",
			inputErr: "some error happened",
			plugin:   bia2,
			expect:   "some error happened, plugin: test-bia",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := wrapErrMsg(test.inputErr, test.plugin)
			assert.Equal(t, test.expect, got)
		})
	}
}
