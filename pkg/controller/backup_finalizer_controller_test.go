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
	"io"
	"testing"
	"time"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
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
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
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

func TestBackupFinalizerReconcileRunsTerminalVGSCleanup(t *testing.T) {
	backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup-1").
		ObjectMeta(builder.WithUID("backup-uid"), builder.WithAnnotations(velerov1api.VolumeGroupSnapshotBackupAnnotation, "true")).
		Phase(velerov1api.BackupPhaseCompleted).Result()
	client := velerotest.NewFakeControllerRuntimeClient(t, backup)
	reconciler := &backupFinalizerReconciler{
		client:         client,
		globalCRClient: velerotest.NewFakeControllerRuntimeClient(t, backup),
		log:            logrus.New(),
	}

	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: backup.Namespace,
		Name:      backup.Name,
	}})
	require.NoError(t, err)

	updated := &velerov1api.Backup{}
	require.NoError(t, client.Get(t.Context(), kbclient.ObjectKeyFromObject(backup), updated))
	require.Empty(t, updated.Finalizers)
	require.Equal(t, "true", updated.Annotations[velerov1api.VolumeGroupSnapshotCleanupCompletedAnnotation])
}

func TestBackupFinalizerReconcileCleansVGSAfterFailedBackup(t *testing.T) {
	contentName := "group-content"
	backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup-failed").
		ObjectMeta(builder.WithUID("backup-uid"), builder.WithAnnotations(velerov1api.VolumeGroupSnapshotBackupAnnotation, "true")).
		Phase(velerov1api.BackupPhaseFailed).Result()
	group := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "group",
			Namespace: "app",
			UID:       "group-uid",
			Labels: map[string]string{
				velerov1api.BackupNameLabel: "backup-failed",
				velerov1api.BackupUIDLabel:  "backup-uid",
			},
		},
		Status: &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{
			BoundVolumeGroupSnapshotContentName: &contentName,
		},
	}
	content := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: contentName},
		Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
			VolumeGroupSnapshotRef: corev1api.ObjectReference{
				Name:      group.Name,
				Namespace: group.Namespace,
				UID:       group.UID,
			},
		},
	}
	client := velerotest.NewFakeControllerRuntimeClient(t, backup)
	globalClient := velerotest.NewFakeControllerRuntimeClientWithVGS(t, group, content)
	reconciler := &backupFinalizerReconciler{
		client:         client,
		globalCRClient: globalClient,
		log:            logrus.New(),
	}

	_, err := reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: backup.Namespace,
		Name:      backup.Name,
	}})
	require.NoError(t, err)

	updated := &velerov1api.Backup{}
	require.NoError(t, client.Get(t.Context(), kbclient.ObjectKeyFromObject(backup), updated))
	_, err = csi.GetVGS(t.Context(), globalClient, group.Namespace, group.Name)
	require.Error(t, err)
	_, err = csi.GetVGSC(t.Context(), globalClient, contentName)
	require.Error(t, err)
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
