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
	"bytes"
	"fmt"
	"io"
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

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	persistencemocks "github.com/vmware-tanzu/velero/pkg/persistence/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	pluginmocks "github.com/vmware-tanzu/velero/pkg/plugin/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func mockBackupFinalizerReconciler(fakeClient kbclient.Client, fakeGlobalClient kbclient.Client, fakeClock *testclocks.FakeClock) (*backupFinalizerReconciler, *fakeBackupper) {
	backupper := new(fakeBackupper)
	return NewBackupFinalizerReconciler(
		fakeClient,
		fakeGlobalClient,
		fakeClock,
		backupper,
		func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
		NewBackupTracker(),
		NewFakeSingleObjectBackupStoreGetter(backupStore),
		logrus.StandardLogger(),
		metrics.NewServerMetrics(),
		10*time.Minute,
	), backupper
}
func TestBackupFinalizerReconcile(t *testing.T) {
	fakeClock := testclocks.NewFakeClock(time.Now())
	metav1Now := metav1.NewTime(fakeClock.Now())

	defaultBackupLocation := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Result()

	tests := []struct {
		name                string
		backup              *velerov1api.Backup
		backupOperations    []*itemoperation.BackupOperation
		backupLocation      *velerov1api.BackupStorageLocation
		enableCSI           bool
		expectError         bool
		expectPhase         velerov1api.BackupPhase
		expectedCompletedVS int
	}{
		{
			name: "Finalizing backup is completed",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-1").
				StorageLocation("default").
				ObjectMeta(builder.WithUID("foo")).
				StartTimestamp(fakeClock.Now()).
				Phase(velerov1api.BackupPhaseFinalizing).Result(),
			backupLocation: defaultBackupLocation,
			expectPhase:    velerov1api.BackupPhaseCompleted,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-1",
						BackupUID:        "foo",
						BackupItemAction: "foo",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1",
						},
						PostOperationItems: []velero.ResourceIdentifier{
							{
								GroupResource: kuberesource.Secrets,
								Namespace:     "ns-1",
								Name:          "secret-1",
							},
						},
						OperationID: "operation-1",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseCompleted,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "FinalizingPartiallyFailed backup is partially failed",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-2").
				StorageLocation("default").
				ObjectMeta(builder.WithUID("foo")).
				StartTimestamp(fakeClock.Now()).
				Phase(velerov1api.BackupPhaseFinalizingPartiallyFailed).Result(),
			backupLocation: defaultBackupLocation,
			expectPhase:    velerov1api.BackupPhasePartiallyFailed,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-2",
						BackupUID:        "foo",
						BackupItemAction: "foo",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-2",
							Name:          "pod-2",
						},
						PostOperationItems: []velero.ResourceIdentifier{
							{
								GroupResource: kuberesource.Secrets,
								Namespace:     "ns-2",
								Name:          "secret-2",
							},
						},
						OperationID: "operation-2",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseCompleted,
						Created: &metav1Now,
					},
				},
			},
		},
		{
			name: "Test calculate backup.Status.BackupItemOperationsCompleted",
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "backup-3").
				StorageLocation("default").
				ObjectMeta(builder.WithUID("foo")).
				StartTimestamp(fakeClock.Now()).
				WithStatus(velerov1api.BackupStatus{
					StartTimestamp:              &metav1Now,
					CompletionTimestamp:         &metav1Now,
					CSIVolumeSnapshotsAttempted: 1,
					Phase:                       velerov1api.BackupPhaseFinalizing,
				}).
				Result(),
			backupLocation:      defaultBackupLocation,
			enableCSI:           true,
			expectPhase:         velerov1api.BackupPhaseCompleted,
			expectedCompletedVS: 1,
			backupOperations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName:       "backup-3",
						BackupUID:        "foo",
						BackupItemAction: "foo",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.VolumeSnapshots,
							Namespace:     "ns-1",
							Name:          "vs-1",
						},
						PostOperationItems: []velero.ResourceIdentifier{
							{
								GroupResource: kuberesource.Secrets,
								Namespace:     "ns-1",
								Name:          "secret-1",
							},
						},
						OperationID: "operation-3",
					},
					Status: itemoperation.OperationStatus{
						Phase:   itemoperation.OperationPhaseCompleted,
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

			if test.enableCSI {
				features.Enable(velerov1api.CSIFeatureFlag)
				defer features.Enable()
			}

			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)

			fakeGlobalClient := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)

			reconciler, backupper := mockBackupFinalizerReconciler(fakeClient, fakeGlobalClient, fakeClock)
			pluginManager.On("CleanupClients").Return(nil)
			backupStore.On("GetBackupItemOperations", test.backup.Name).Return(test.backupOperations, nil)
			backupStore.On("GetBackupContents", mock.Anything).Return(io.NopCloser(bytes.NewReader([]byte("hello world"))), nil)
			backupStore.On("PutBackupContents", mock.Anything, mock.Anything).Return(nil)
			backupStore.On("PutBackupMetadata", mock.Anything, mock.Anything).Return(nil)
			backupStore.On("GetBackupVolumeInfos", mock.Anything).Return(nil, nil)
			backupStore.On("PutBackupVolumeInfos", mock.Anything, mock.Anything).Return(nil)
			pluginManager.On("GetBackupItemActionsV2").Return(nil, nil)
			backupper.On("FinalizeBackup", mock.Anything, mock.Anything, mock.Anything, mock.Anything, framework.BackupItemActionResolverV2{}, mock.Anything, mock.Anything).Return(nil)
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
			assert.Equal(t, test.expectedCompletedVS, backupAfter.Status.CSIVolumeSnapshotsCompleted)
		})
	}
}

func TestBackupFinalizerReconcile_PutBackupMetadataFail(t *testing.T) {
	tests := []struct {
		name         string
		initialPhase velerov1api.BackupPhase
	}{
		{
			name:         "Finalizing backup stays Finalizing when PutBackupMetadata fails",
			initialPhase: velerov1api.BackupPhaseFinalizing,
		},
		{
			name:         "FinalizingPartiallyFailed backup stays FinalizingPartiallyFailed when PutBackupMetadata fails",
			initialPhase: velerov1api.BackupPhaseFinalizingPartiallyFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClock := testclocks.NewFakeClock(time.Now())
			defaultBackupLocation := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Result()

			backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup-meta-fail").
				StorageLocation("default").
				ObjectMeta(builder.WithUID("foo")).
				StartTimestamp(fakeClock.Now()).
				Phase(test.initialPhase).Result()

			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, backup, defaultBackupLocation)
			fakeGlobalClient := velerotest.NewFakeControllerRuntimeClient(t, backup, defaultBackupLocation)

			// Use local mocks to avoid interference with other tests
			localPluginManager := &pluginmocks.Manager{}
			localBackupStore := &persistencemocks.BackupStore{}

			backupper := new(fakeBackupper)
			reconciler := NewBackupFinalizerReconciler(
				fakeClient,
				fakeGlobalClient,
				fakeClock,
				backupper,
				func(logrus.FieldLogger) clientmgmt.Manager { return localPluginManager },
				NewBackupTracker(),
				NewFakeSingleObjectBackupStoreGetter(localBackupStore),
				logrus.StandardLogger(),
				metrics.NewServerMetrics(),
				10*time.Minute,
			)

			localPluginManager.On("CleanupClients").Return(nil)
			localBackupStore.On("GetBackupItemOperations", backup.Name).Return(nil, nil)
			// PutBackupMetadata fails
			localBackupStore.On("PutBackupMetadata", mock.Anything, mock.Anything).Return(fmt.Errorf("object lock prevented upload"))
			localBackupStore.On("GetBackupVolumeInfos", mock.Anything).Return(nil, nil)
			localBackupStore.On("PutBackupVolumeInfos", mock.Anything, mock.Anything).Return(nil)

			_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: backup.Namespace, Name: backup.Name}})
			require.Error(t, err, "reconcile should return error when PutBackupMetadata fails")

			backupAfter := velerov1api.Backup{}
			err = fakeClient.Get(t.Context(), types.NamespacedName{
				Namespace: backup.Namespace,
				Name:      backup.Name,
			}, &backupAfter)
			require.NoError(t, err)
			assert.Equal(t, test.initialPhase, backupAfter.Status.Phase,
				"backup phase should remain %s when PutBackupMetadata fails", test.initialPhase)
			assert.Nil(t, backupAfter.Status.CompletionTimestamp,
				"CompletionTimestamp should not be set when PutBackupMetadata fails")
		})
	}
}

func TestBackupFinalizerReconcile_PutBackupContentsFail(t *testing.T) {
	fakeClock := testclocks.NewFakeClock(time.Now())
	metav1Now := metav1.NewTime(fakeClock.Now())
	defaultBackupLocation := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "default").Result()

	backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup-contents-fail").
		StorageLocation("default").
		ObjectMeta(builder.WithUID("foo")).
		StartTimestamp(fakeClock.Now()).
		Phase(velerov1api.BackupPhaseFinalizing).Result()

	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, backup, defaultBackupLocation)
	fakeGlobalClient := velerotest.NewFakeControllerRuntimeClient(t, backup, defaultBackupLocation)

	localPluginManager := &pluginmocks.Manager{}
	localBackupStore := &persistencemocks.BackupStore{}

	backupper := new(fakeBackupper)
	reconciler := NewBackupFinalizerReconciler(
		fakeClient,
		fakeGlobalClient,
		fakeClock,
		backupper,
		func(logrus.FieldLogger) clientmgmt.Manager { return localPluginManager },
		NewBackupTracker(),
		NewFakeSingleObjectBackupStoreGetter(localBackupStore),
		logrus.StandardLogger(),
		metrics.NewServerMetrics(),
		10*time.Minute,
	)

	operations := []*itemoperation.BackupOperation{
		{
			Spec: itemoperation.BackupOperationSpec{
				BackupName:       "backup-contents-fail",
				BackupUID:        "foo",
				BackupItemAction: "foo",
				ResourceIdentifier: velero.ResourceIdentifier{
					GroupResource: kuberesource.Pods,
					Namespace:     "ns-1",
					Name:          "pod-1",
				},
				OperationID: "operation-1",
			},
			Status: itemoperation.OperationStatus{
				Phase:   itemoperation.OperationPhaseCompleted,
				Created: &metav1Now,
			},
		},
	}

	localPluginManager.On("CleanupClients").Return(nil)
	localPluginManager.On("GetBackupItemActionsV2").Return(nil, nil)
	localBackupStore.On("GetBackupItemOperations", backup.Name).Return(operations, nil)
	localBackupStore.On("GetBackupContents", mock.Anything).Return(io.NopCloser(bytes.NewReader([]byte("hello world"))), nil)
	localBackupStore.On("PutBackupMetadata", mock.Anything, mock.Anything).Return(nil)
	// PutBackupContents fails
	localBackupStore.On("PutBackupContents", mock.Anything, mock.Anything).Return(fmt.Errorf("object lock prevented upload"))
	localBackupStore.On("GetBackupVolumeInfos", mock.Anything).Return(nil, nil)
	localBackupStore.On("PutBackupVolumeInfos", mock.Anything, mock.Anything).Return(nil)
	backupper.On("FinalizeBackup", mock.Anything, mock.Anything, mock.Anything, mock.Anything, framework.BackupItemActionResolverV2{}, mock.Anything, mock.Anything).Return(nil)

	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: backup.Namespace, Name: backup.Name}})
	require.Error(t, err, "reconcile should return error when PutBackupContents fails")

	backupAfter := velerov1api.Backup{}
	err = fakeClient.Get(t.Context(), types.NamespacedName{
		Namespace: backup.Namespace,
		Name:      backup.Name,
	}, &backupAfter)
	require.NoError(t, err)
	assert.Equal(t, velerov1api.BackupPhaseFinalizing, backupAfter.Status.Phase,
		"backup phase should remain Finalizing when PutBackupContents fails")
	assert.Nil(t, backupAfter.Status.CompletionTimestamp,
		"CompletionTimestamp should not be set when PutBackupContents fails")
}
