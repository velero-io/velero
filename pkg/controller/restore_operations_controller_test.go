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
	riav2mocks "github.com/velero-io/velero/pkg/plugin/velero/mocks/restoreitemaction/v2"
	velerotest "github.com/velero-io/velero/pkg/test"
)

var (
	restorePluginManager = &pluginmocks.Manager{}
	restoreBackupStore   = &persistencemocks.BackupStore{}
	ria                  = &riav2mocks.RestoreItemAction{}
)

func mockRestoreOperationsReconciler(fakeClient kbclient.Client, fakeClock *testclocks.FakeClock, freq time.Duration) *restoreOperationsReconciler {
	abor := NewRestoreOperationsReconciler(
		logrus.StandardLogger(),
		velerov1api.DefaultNamespace,
		fakeClient,
		freq,
		func(logrus.FieldLogger) clientmgmt.Manager { return restorePluginManager },
		NewFakeSingleObjectBackupStoreGetter(restoreBackupStore),
		metrics.NewServerMetrics(),
		itemoperationmap.NewRestoreItemOperationsMap(),
	)
	abor.clock = fakeClock
	return abor
}

func TestRestoreOperationsReconcile(t *testing.T) {
	fakeClock := testclocks.NewFakeClock(time.Now())
	metav1Now := metav1.NewTime(fakeClock.Now())

	defaultBackupLocation := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Result()

	tests := []struct {
		name              string
		restore           *velerov1api.Restore
		restoreOperations []*itemoperation.RestoreOperation
		backup            *velerov1api.Backup
		backupLocation    *velerov1api.BackupStorageLocation
		operationComplete bool
		operationErr      string
		expectError       bool
		expectPhase       velerov1api.RestorePhase
	}{
		{
			name: "WaitingForPluginOperations restore with completed operations is Completed",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-11").
				Backup("backup-1").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-11")).
				Phase(velerov1api.RestorePhaseWaitingForPluginOperations).Result(),
			backup:            defaultBackup().StorageLocation("default").Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			expectPhase:       velerov1api.RestorePhaseFinalizing,
			restoreOperations: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-11",
						RestoreUID:        "foo-11",
						RestoreItemAction: "foo-11",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-11",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseInProgress,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperations restore with incomplete operations is still incomplete",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-12").
				Backup("backup-1").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-12")).
				Phase(velerov1api.RestorePhaseWaitingForPluginOperations).Result(),
			backup:            defaultBackup().StorageLocation("default").Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: false,
			expectPhase:       velerov1api.RestorePhaseWaitingForPluginOperations,
			restoreOperations: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-12",
						RestoreUID:        "foo-12",
						RestoreItemAction: "foo-12",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-12",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseInProgress,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperations restore with completed failed operations is PartiallyFailed",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-13").
				Backup("backup-1").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-13")).
				Phase(velerov1api.RestorePhaseWaitingForPluginOperations).Result(),
			backup:            defaultBackup().StorageLocation("default").Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			operationErr:      "failed",
			expectPhase:       velerov1api.RestorePhaseFinalizingPartiallyFailed,
			restoreOperations: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-13",
						RestoreUID:        "foo-13",
						RestoreItemAction: "foo-13",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-13",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseInProgress,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperationsPartiallyFailed restore with completed operations is PartiallyFailed",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-14").
				Backup("backup-1").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-14")).
				Phase(velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed).Result(),
			backup:            defaultBackup().StorageLocation("default").Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			expectPhase:       velerov1api.RestorePhaseFinalizingPartiallyFailed,
			restoreOperations: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-14",
						RestoreUID:        "foo-14",
						RestoreItemAction: "foo-14",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-14",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseInProgress,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperationsPartiallyFailed restore with incomplete operations is still incomplete",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-15").
				Backup("backup-1").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-15")).
				Phase(velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed).Result(),
			backup:            defaultBackup().StorageLocation("default").Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: false,
			expectPhase:       velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed,
			restoreOperations: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-15",
						RestoreUID:        "foo-15",
						RestoreItemAction: "foo-15",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-15",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseInProgress,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "WaitingForPluginOperationsPartiallyFailed restore with completed failed operations is PartiallyFailed",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-16").
				Backup("backup-1").
				ItemOperationTimeout(60 * time.Minute).
				ObjectMeta(builder.WithUID("foo-16")).
				Phase(velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed).Result(),
			backup:            defaultBackup().StorageLocation("default").Result(),
			backupLocation:    defaultBackupLocation,
			operationComplete: true,
			operationErr:      "failed",
			expectPhase:       velerov1api.RestorePhaseFinalizingPartiallyFailed,
			restoreOperations: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-16",
						RestoreUID:        "foo-16",
						RestoreItemAction: "foo-16",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						OperationID: "operation-16",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseInProgress,
						Created: &metav1Now,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.restore == nil {
				return
			}

			initObjs := []runtime.Object{}
			initObjs = append(initObjs, test.restore)
			initObjs = append(initObjs, test.backup)

			if test.backupLocation != nil {
				initObjs = append(initObjs, test.backupLocation)
			}

			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)
			reconciler := mockRestoreOperationsReconciler(fakeClient, fakeClock, defaultRestoreOperationsFrequency)
			restorePluginManager.On("CleanupClients").Return(nil)
			restoreBackupStore.On("GetRestoreItemOperations", test.restore.Name).Return(test.restoreOperations, nil)
			restoreBackupStore.On("PutRestoreItemOperations", mock.Anything, mock.Anything).Return(nil)
			restoreBackupStore.On("PutRestoreMetadata", mock.Anything, mock.Anything).Return(nil)
			for _, operation := range test.restoreOperations {
				ria.On("Progress", operation.Spec.OperationID, mock.Anything).
					Return(velero.OperationProgress{
						Completed: test.operationComplete,
						Err:       test.operationErr,
					}, nil)
				restorePluginManager.On("GetRestoreItemActionV2", operation.Spec.RestoreItemAction).Return(ria, nil)
			}

			_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: test.restore.Namespace, Name: test.restore.Name}})
			gotErr := err != nil
			assert.Equal(t, test.expectError, gotErr)

			restoreAfter := velerov1api.Restore{}
			err = fakeClient.Get(t.Context(), types.NamespacedName{
				Namespace: test.restore.Namespace,
				Name:      test.restore.Name,
			}, &restoreAfter)

			require.NoError(t, err)
			assert.Equal(t, test.expectPhase, restoreAfter.Status.Phase)
		})
	}
}
