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
	"fmt"
	"syscall"
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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/hook"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	persistencemocks "github.com/vmware-tanzu/velero/pkg/persistence/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/vmware-tanzu/velero/pkg/plugin/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	pkgUtilKubeMocks "github.com/vmware-tanzu/velero/pkg/util/kube/mocks"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

func TestRestoreFinalizerReconcile(t *testing.T) {
	defaultStorageLocation := builder.ForBackupStorageLocation("velero", "default").Provider("myCloud").Bucket("bucket").Result()
	now, err := time.Parse(time.RFC1123Z, time.RFC1123Z)
	require.NoError(t, err)
	now = now.Local()
	timestamp := metav1.NewTime(now)
	assert.NotNil(t, timestamp)

	rfrTests := []struct {
		name                  string
		restore               *velerov1api.Restore
		backup                *velerov1api.Backup
		location              *velerov1api.BackupStorageLocation
		expectError           bool
		expectPhase           velerov1api.RestorePhase
		expectWarningsCnt     int
		expectErrsCnt         int
		statusCompare         bool
		expectedCompletedTime *metav1.Time
	}{
		{
			name:          "Restore is not awaiting finalization, skip",
			restore:       builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Phase(velerov1api.RestorePhaseInProgress).Result(),
			expectError:   false,
			expectPhase:   velerov1api.RestorePhaseInProgress,
			statusCompare: false,
		},
		{
			name:                  "Upon completion of all finalization tasks in the 'FinalizingPartiallyFailed' phase, the restore process transit to the 'PartiallyFailed' phase.",
			restore:               builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Phase(velerov1api.RestorePhaseFinalizingPartiallyFailed).Backup("backup-1").Result(),
			backup:                defaultBackup().StorageLocation("default").Result(),
			location:              defaultStorageLocation,
			expectError:           false,
			expectPhase:           velerov1api.RestorePhasePartiallyFailed,
			statusCompare:         true,
			expectedCompletedTime: &timestamp,
			expectWarningsCnt:     0,
			expectErrsCnt:         0,
		},
		{
			name:                  "Upon completion of all finalization tasks in the 'Finalizing' phase, the restore process transit to the 'Completed' phase.",
			restore:               builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Phase(velerov1api.RestorePhaseFinalizing).Backup("backup-1").Result(),
			backup:                defaultBackup().StorageLocation("default").Result(),
			location:              defaultStorageLocation,
			expectError:           false,
			expectPhase:           velerov1api.RestorePhaseCompleted,
			statusCompare:         true,
			expectedCompletedTime: &timestamp,
			expectWarningsCnt:     0,
			expectErrsCnt:         0,
		},
		{
			name:        "Backup not exist",
			restore:     builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Phase(velerov1api.RestorePhaseFinalizing).Backup("backup-2").Result(),
			expectError: false,
		},
		{
			name:          "Restore not exist",
			restore:       builder.ForRestore("unknown", "restore-1").Phase(velerov1api.RestorePhaseFinalizing).Result(),
			expectError:   false,
			statusCompare: false,
		},
	}

	for _, test := range rfrTests {
		t.Run(test.name, func(t *testing.T) {
			if test.restore == nil {
				return
			}

			var (
				fakeClient    = velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
				logger        = velerotest.NewLogger()
				pluginManager = &pluginmocks.Manager{}
				backupStore   = &persistencemocks.BackupStore{}
			)

			defer func() {
				// reset defaultStorageLocation resourceVersion
				defaultStorageLocation.ObjectMeta.ResourceVersion = ""
			}()

			r := NewRestoreFinalizerReconciler(
				logger,
				velerov1api.DefaultNamespace,
				fakeClient,
				func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
				NewFakeSingleObjectBackupStoreGetter(backupStore),
				metrics.NewServerMetrics(),
				fakeClient,
				hook.NewMultiHookTracker(),
				10*time.Minute,
			)
			r.clock = testclocks.NewFakeClock(now)

			if test.restore != nil && test.restore.Namespace == velerov1api.DefaultNamespace {
				require.NoError(t, r.Client.Create(t.Context(), test.restore))
				backupStore.On("GetRestoredResourceList", test.restore.Name).Return(map[string][]string{}, nil)
				backupStore.On("GetRestoreItemOperations", test.restore.Name).Return([]*itemoperation.RestoreOperation{}, nil)
			}
			if test.backup != nil {
				require.NoError(t, r.Client.Create(t.Context(), test.backup))
				backupStore.On("GetBackupVolumeInfos", test.backup.Name).Return(nil, nil)
				pluginManager.On("GetRestoreItemActionsV2").Return(nil, nil)
				pluginManager.On("CleanupClients")
			}
			if test.location != nil {
				require.NoError(t, r.Client.Create(t.Context(), test.location))
			}

			_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: test.restore.Namespace,
				Name:      test.restore.Name,
			}})

			assert.Equal(t, test.expectError, err != nil)
			if test.expectError {
				return
			}

			if test.statusCompare {
				restoreAfter := velerov1api.Restore{}
				err = fakeClient.Get(t.Context(), types.NamespacedName{
					Namespace: test.restore.Namespace,
					Name:      test.restore.Name,
				}, &restoreAfter)

				require.NoError(t, err)

				assert.Equal(t, test.expectPhase, restoreAfter.Status.Phase)
				assert.Equal(t, test.expectErrsCnt, restoreAfter.Status.Errors)
				assert.Equal(t, test.expectWarningsCnt, restoreAfter.Status.Warnings)
				require.True(t, test.expectedCompletedTime.Equal(restoreAfter.Status.CompletionTimestamp))
			}
		})
	}
}

func TestUpdateResult(t *testing.T) {
	var (
		fakeClient    = velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
		logger        = velerotest.NewLogger()
		pluginManager = &pluginmocks.Manager{}
		backupStore   = &persistencemocks.BackupStore{}
	)

	r := NewRestoreFinalizerReconciler(
		logger,
		velerov1api.DefaultNamespace,
		fakeClient,
		func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
		NewFakeSingleObjectBackupStoreGetter(backupStore),
		metrics.NewServerMetrics(),
		fakeClient,
		hook.NewMultiHookTracker(),
		10*time.Minute,
	)
	restore := builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Result()
	res := map[string]results.Result{"warnings": {}, "errors": {}}

	backupStore.On("GetRestoreResults", restore.Name).Return(res, nil)
	backupStore.On("PutRestoreResults", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err := r.updateResults(backupStore, restore, &results.Result{}, &results.Result{})
	require.NoError(t, err)
}

func TestPatchDynamicPVWithVolumeInfo(t *testing.T) {
	tests := []struct {
		name             string
		volumeInfo       []*volume.BackupVolumeInfo
		restoredPVCNames map[string]struct{}
		restore          *velerov1api.Restore
		restoredPVC      []*corev1api.PersistentVolumeClaim
		restoredPV       []*corev1api.PersistentVolume
		expectedPatch    map[string]volume.PVInfo
		expectedErrNum   int
	}{
		{
			name:           "no applicable volumeInfo",
			volumeInfo:     []*volume.BackupVolumeInfo{{BackupMethod: "VeleroNativeSnapshot", PVCName: "pvc1"}},
			restore:        builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			expectedPatch:  nil,
			expectedErrNum: 0,
		},
		{
			name:           "no restored PVC",
			volumeInfo:     []*volume.BackupVolumeInfo{{BackupMethod: "PodVolumeBackup", PVCName: "pvc1"}},
			restore:        builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			expectedPatch:  nil,
			expectedErrNum: 0,
		},
		{
			name: "no applicable pv patch",
			volumeInfo: []*volume.BackupVolumeInfo{{
				BackupMethod: "PodVolumeBackup",
				PVCName:      "pvc1",
				PVName:       "pv1",
				PVCNamespace: "ns1",
				PVInfo: &volume.PVInfo{
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			}},
			restore:          builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			restoredPVCNames: map[string]struct{}{"ns1/pvc1": {}},
			restoredPV: []*corev1api.PersistentVolume{
				builder.ForPersistentVolume("new-pv1").ObjectMeta(builder.WithLabels("label1", "label1-val")).ClaimRef("ns1", "pvc1").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).Result()},
			restoredPVC: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns1", "pvc1").VolumeName("new-pv1").Phase(corev1api.ClaimBound).Result(),
			},
			expectedPatch:  nil,
			expectedErrNum: 0,
		},
		{
			name: "an applicable pv patch",
			volumeInfo: []*volume.BackupVolumeInfo{{
				BackupMethod: "PodVolumeBackup",
				PVCName:      "pvc1",
				PVName:       "pv1",
				PVCNamespace: "ns1",
				PVInfo: &volume.PVInfo{
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			}},
			restore:          builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			restoredPVCNames: map[string]struct{}{"ns1/pvc1": {}},
			restoredPV: []*corev1api.PersistentVolume{
				builder.ForPersistentVolume("new-pv1").ClaimRef("ns1", "pvc1").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result()},
			restoredPVC: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns1", "pvc1").VolumeName("new-pv1").Phase(corev1api.ClaimBound).Result(),
			},
			expectedPatch: map[string]volume.PVInfo{"new-pv1": {
				ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
				Labels:        map[string]string{"label1": "label1-val"},
			}},
			expectedErrNum: 0,
		},
		{
			name: "a mapped namespace restore",
			volumeInfo: []*volume.BackupVolumeInfo{{
				BackupMethod: "PodVolumeBackup",
				PVCName:      "pvc1",
				PVName:       "pv1",
				PVCNamespace: "ns2",
				PVInfo: &volume.PVInfo{
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			}},
			restore:          builder.ForRestore(velerov1api.DefaultNamespace, "restore").NamespaceMappings("ns2", "ns1").Result(),
			restoredPVCNames: map[string]struct{}{"ns1/pvc1": {}},
			restoredPV: []*corev1api.PersistentVolume{
				builder.ForPersistentVolume("new-pv1").ClaimRef("ns1", "pvc1").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result()},
			restoredPVC: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns1", "pvc1").VolumeName("new-pv1").Phase(corev1api.ClaimBound).Result(),
			},
			expectedPatch: map[string]volume.PVInfo{"new-pv1": {
				ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
				Labels:        map[string]string{"label1": "label1-val"},
			}},
			expectedErrNum: 0,
		},
		{
			name: "two applicable pv patches",
			volumeInfo: []*volume.BackupVolumeInfo{{
				BackupMethod: "PodVolumeBackup",
				PVCName:      "pvc1",
				PVName:       "pv1",
				PVCNamespace: "ns1",
				PVInfo: &volume.PVInfo{
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			},
				{
					BackupMethod: "CSISnapshot",
					PVCName:      "pvc2",
					PVName:       "pv2",
					PVCNamespace: "ns2",
					PVInfo: &volume.PVInfo{
						ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
						Labels:        map[string]string{"label2": "label2-val"},
					},
				},
			},
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			restoredPVCNames: map[string]struct{}{
				"ns1/pvc1": {},
				"ns2/pvc2": {},
			},
			restoredPV: []*corev1api.PersistentVolume{
				builder.ForPersistentVolume("new-pv1").ClaimRef("ns1", "pvc1").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				builder.ForPersistentVolume("new-pv2").ClaimRef("ns2", "pvc2").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			},
			restoredPVC: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns1", "pvc1").VolumeName("new-pv1").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolumeClaim("ns2", "pvc2").VolumeName("new-pv2").Phase(corev1api.ClaimBound).Result(),
			},
			expectedPatch: map[string]volume.PVInfo{
				"new-pv1": {
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
				"new-pv2": {
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label2": "label2-val"},
				},
			},
			expectedErrNum: 0,
		},
		{
			name: "an applicable pv patch with bound error",
			volumeInfo: []*volume.BackupVolumeInfo{{
				BackupMethod: "PodVolumeBackup",
				PVCName:      "pvc1",
				PVName:       "pv1",
				PVCNamespace: "ns1",
				PVInfo: &volume.PVInfo{
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			}},
			restore:          builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			restoredPVCNames: map[string]struct{}{"ns1/pvc1": {}},
			restoredPV: []*corev1api.PersistentVolume{
				builder.ForPersistentVolume("new-pv1").ClaimRef("ns2", "pvc2").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result()},
			restoredPVC: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns1", "pvc1").VolumeName("new-pv1").Phase(corev1api.ClaimBound).Result(),
			},
			expectedErrNum: 1,
		},
		{
			name: "two applicable pv patches with an error",
			volumeInfo: []*volume.BackupVolumeInfo{{
				BackupMethod: "PodVolumeBackup",
				PVCName:      "pvc1",
				PVName:       "pv1",
				PVCNamespace: "ns1",
				PVInfo: &volume.PVInfo{
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			},
				{
					BackupMethod: "CSISnapshot",
					PVCName:      "pvc2",
					PVName:       "pv2",
					PVCNamespace: "ns2",
					PVInfo: &volume.PVInfo{
						ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
						Labels:        map[string]string{"label2": "label2-val"},
					},
				},
			},
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			restoredPVCNames: map[string]struct{}{
				"ns1/pvc1": {},
				"ns2/pvc2": {},
			},
			restoredPV: []*corev1api.PersistentVolume{
				builder.ForPersistentVolume("new-pv1").ClaimRef("ns1", "pvc1").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				builder.ForPersistentVolume("new-pv2").ClaimRef("ns3", "pvc3").Phase(corev1api.VolumeBound).ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			},
			restoredPVC: []*corev1api.PersistentVolumeClaim{
				builder.ForPersistentVolumeClaim("ns1", "pvc1").VolumeName("new-pv1").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolumeClaim("ns2", "pvc2").VolumeName("new-pv2").Phase(corev1api.ClaimBound).Result(),
			},
			expectedPatch: map[string]volume.PVInfo{
				"new-pv1": {
					ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
					Labels:        map[string]string{"label1": "label1-val"},
				},
			},
			expectedErrNum: 1,
		},
	}

	for _, tc := range tests {
		var (
			fakeClient = velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
			logger     = velerotest.NewLogger()
		)
		ctx := &finalizerContext{
			logger:          logger,
			crClient:        fakeClient,
			restore:         tc.restore,
			restoredPVCList: tc.restoredPVCNames,
			volumeInfo:      tc.volumeInfo,
		}

		for _, pv := range tc.restoredPV {
			require.NoError(t, ctx.crClient.Create(t.Context(), pv))
		}
		for _, pvc := range tc.restoredPVC {
			require.NoError(t, ctx.crClient.Create(t.Context(), pvc))
		}

		errs := ctx.patchDynamicPVWithVolumeInfo()
		if tc.expectedErrNum > 0 {
			assert.Len(t, errs.Namespaces, tc.expectedErrNum)
		}

		for pvName, expectedPVInfo := range tc.expectedPatch {
			pv := &corev1api.PersistentVolume{}
			err := ctx.crClient.Get(t.Context(), crclient.ObjectKey{Name: pvName}, pv)
			require.NoError(t, err)

			assert.Equal(t, expectedPVInfo.ReclaimPolicy, string(pv.Spec.PersistentVolumeReclaimPolicy))
			assert.Equal(t, expectedPVInfo.Labels, pv.Labels)
		}
	}
}

func TestWaitRestoreExecHook(t *testing.T) {
	hookTracker1 := hook.NewMultiHookTracker()
	restoreName1 := "restore1"

	hookTracker2 := hook.NewMultiHookTracker()
	restoreName2 := "restore2"
	hookTracker2.Add(restoreName2, "ns", "pod", "con1", "s1", "h1", "", 0)
	hookTracker2.Record(restoreName2, "ns", "pod", "con1", "s1", "h1", "", 0, false, nil)

	hookTracker3 := hook.NewMultiHookTracker()
	restoreName3 := "restore3"
	podNs, podName, container, source, hookName := "ns", "pod", "con1", "s1", "h1"
	hookFailed, hookErr := true, fmt.Errorf("hook failed")
	hookTracker3.Add(restoreName3, podNs, podName, container, source, hookName, hook.PhasePre, 0)

	// hookTracker4: an entry that is added but never recorded. This
	// reproduces the hang that motivated the resourceTimeout guard —
	// without the timeout, WaitRestoreExecHook would block forever.
	hookTracker4 := hook.NewMultiHookTracker()
	restoreName4 := "restore4"
	hookTracker4.Add(restoreName4, "ns", "pod", "con1", "s1", "h1", hook.PhasePre, 0)

	tests := []struct {
		name                   string
		hookTracker            *hook.MultiHookTracker
		restore                *velerov1api.Restore
		expectedHooksAttempted int
		expectedHooksFailed    int
		expectedHookErrs       int
		waitSec                int
		podName                string
		podNs                  string
		Container              string
		Source                 string
		hookName               string
		hookFailed             bool
		hookErr                error
		resourceTimeout        time.Duration
		expectTimeoutErr       bool
	}{
		{
			name:                   "no restore exec hooks",
			hookTracker:            hookTracker1,
			restore:                builder.ForRestore(velerov1api.DefaultNamespace, restoreName1).Result(),
			expectedHooksAttempted: 0,
			expectedHooksFailed:    0,
			expectedHookErrs:       0,
		},
		{
			name:                   "1 restore exec hook having been executed",
			hookTracker:            hookTracker2,
			restore:                builder.ForRestore(velerov1api.DefaultNamespace, restoreName2).Result(),
			expectedHooksAttempted: 1,
			expectedHooksFailed:    0,
			expectedHookErrs:       0,
		},
		{
			name:                   "1 restore exec hook to be executed",
			hookTracker:            hookTracker3,
			restore:                builder.ForRestore(velerov1api.DefaultNamespace, restoreName3).Result(),
			waitSec:                2,
			expectedHooksAttempted: 1,
			expectedHooksFailed:    1,
			expectedHookErrs:       1,
			podName:                podName,
			podNs:                  podNs,
			Container:              container,
			Source:                 source,
			hookName:               hookName,
			hookFailed:             hookFailed,
			hookErr:                hookErr,
		},
		{
			name:                   "hook never recorded should timeout instead of hanging",
			hookTracker:            hookTracker4,
			restore:                builder.ForRestore(velerov1api.DefaultNamespace, restoreName4).Result(),
			expectedHooksAttempted: 0,
			expectedHooksFailed:    0,
			expectedHookErrs:       1,
			resourceTimeout:        3 * time.Second,
			expectTimeoutErr:       true,
		},
	}

	for _, tc := range tests {
		var (
			fakeClient = velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
			logger     = velerotest.NewLogger()
		)
		ctx := &finalizerContext{
			logger:           logger,
			crClient:         fakeClient,
			restore:          tc.restore,
			multiHookTracker: tc.hookTracker,
			resourceTimeout:  tc.resourceTimeout,
		}
		require.NoError(t, ctx.crClient.Create(t.Context(), tc.restore))

		if tc.waitSec > 0 {
			go func() {
				time.Sleep(time.Second * time.Duration(tc.waitSec))
				tc.hookTracker.Record(tc.restore.Name, tc.podNs, tc.podName, tc.Container, tc.Source, tc.hookName, hook.PhasePre, 0, tc.hookFailed, tc.hookErr)
			}()
		}

		errs := ctx.WaitRestoreExecHook()
		if tc.expectTimeoutErr {
			// The poll should be bounded by resourceTimeout and surface
			// a timeout error rather than hanging the reconciler.
			assert.NotEmpty(t, errs.Namespaces, "expected timeout error but got none")
			continue
		}
		assert.Len(t, errs.Namespaces, tc.expectedHookErrs)

		updated := &velerov1api.Restore{}
		err := ctx.crClient.Get(t.Context(), crclient.ObjectKey{Namespace: velerov1api.DefaultNamespace, Name: tc.restore.Name}, updated)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedHooksAttempted, updated.Status.HookStatus.HooksAttempted)
		assert.Equal(t, tc.expectedHooksFailed, updated.Status.HookStatus.HooksFailed)
	}
}

// test finishprocessing with mocks of kube client to simulate connection refused
func Test_restoreFinalizerReconciler_finishProcessing(t *testing.T) {
	type args struct {
		// mockClientActions simulate different client errors
		mockClientActions func(*pkgUtilKubeMocks.Client)
		// return bool indicating if the client method was called as expected
		mockClientAsserts func(*pkgUtilKubeMocks.Client) bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "restore failed to patch status, should retry on connection refused",
			args: args{
				mockClientActions: func(client *pkgUtilKubeMocks.Client) {
					client.On("Patch", mock.Anything, mock.Anything, mock.Anything).Return(syscall.ECONNREFUSED).Once()
					client.On("Patch", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				},
				mockClientAsserts: func(client *pkgUtilKubeMocks.Client) bool {
					return client.AssertNumberOfCalls(t, "Patch", 2)
				},
			},
		},
		{
			name: "restore failed to patch status, retry on connection refused until max retries",
			args: args{
				mockClientActions: func(client *pkgUtilKubeMocks.Client) {
					client.On("Patch", mock.Anything, mock.Anything, mock.Anything).Return(syscall.ECONNREFUSED)
				},
				mockClientAsserts: func(client *pkgUtilKubeMocks.Client) bool {
					return len(client.Calls) > 2
				},
			},
			wantErr: true,
		},
		{
			name: "restore patch status ok, should not retry",
			args: args{
				mockClientActions: func(client *pkgUtilKubeMocks.Client) {
					client.On("Patch", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				},
				mockClientAsserts: func(client *pkgUtilKubeMocks.Client) bool {
					return client.AssertNumberOfCalls(t, "Patch", 1)
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := pkgUtilKubeMocks.NewClient(t)
			// mock client actions
			tt.args.mockClientActions(client)
			r := &restoreFinalizerReconciler{
				Client:          client,
				metrics:         metrics.NewServerMetrics(),
				clock:           testclocks.NewFakeClock(time.Now()),
				resourceTimeout: 1 * time.Second,
			}
			restore := builder.ForRestore(velerov1api.DefaultNamespace, "restoreName").Result()
			if err := r.finishProcessing(velerov1api.RestorePhaseInProgress, restore, restore); (err != nil) != tt.wantErr {
				t.Errorf("restoreFinalizerReconciler.finishProcessing() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.args.mockClientAsserts(client) {
				t.Errorf("mockClientAsserts() failed")
			}
		})
	}
}

func TestRestoreOperationList(t *testing.T) {
	var empty []*itemoperation.RestoreOperation
	tests := []struct {
		name         string
		items        []*itemoperation.RestoreOperation
		inputPVCNS   string
		inputPVCName string
		expected     []*itemoperation.RestoreOperation
	}{
		{
			name:         "no restore operations",
			items:        []*itemoperation.RestoreOperation{},
			inputPVCNS:   "ns-1",
			inputPVCName: "pvc-1",
			expected:     empty,
		},
		{
			name: "one operation with matched info and a nil element",
			items: []*itemoperation.RestoreOperation{
				nil,
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-1",
						RestoreUID:        "uid-1",
						RestoreItemAction: "velero.io/csi-pvc-restorer",
						OperationID:       "dd-abbb048d-7036-4855-bf50-ebba978b59a6.2426dd0e-b863-4222b5b2b",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{
								Group:    "",
								Resource: "persistentvolumeclaims",
							},
							Namespace: "ns-1",
							Name:      "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{
						Phase:          itemoperation.OperationPhaseCompleted,
						OperationUnits: "Byte",
						Description:    "Completed",
					},
				},
			},
			inputPVCNS:   "ns-1",
			inputPVCName: "pvc-1",
			expected: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-1",
						RestoreUID:        "uid-1",
						RestoreItemAction: "velero.io/csi-pvc-restorer",
						OperationID:       "dd-abbb048d-7036-4855-bf50-ebba978b59a6.2426dd0e-b863-4222b5b2b",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{
								Group:    "",
								Resource: "persistentvolumeclaims",
							},
							Namespace: "ns-1",
							Name:      "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{
						Phase:          itemoperation.OperationPhaseCompleted,
						OperationUnits: "Byte",
						Description:    "Completed",
					},
				},
			},
		},
		{
			name: "one operation with incorrect resource type",
			items: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName:       "restore-1",
						RestoreUID:        "uid-1",
						RestoreItemAction: "velero.io/csi-pvc-restorer",
						OperationID:       "dd-abbb048d-7036-4855-bf50-ebba978b59a6.2426dd0e-b863-4222b5b2b",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: schema.GroupResource{
								Group:    "",
								Resource: "configmaps",
							},
							Namespace: "ns-1",
							Name:      "pvc-1",
						},
					},
					Status: itemoperation.OperationStatus{
						Phase:          itemoperation.OperationPhaseCompleted,
						OperationUnits: "Byte",
						Description:    "Completed",
					},
				},
			},
			inputPVCNS:   "ns-1",
			inputPVCName: "pvc-1",
			expected:     empty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := restoreItemOperationList{
				items: tt.items,
			}
			assert.Equal(t, tt.expected, l.SelectByPVC(tt.inputPVCNS, tt.inputPVCName))
		})
	}
}

func TestCleanupStubVGSC(t *testing.T) {
	snapshotHandle1 := "snap-handle-1"
	snapshotHandle2 := "snap-handle-2"

	tests := []struct {
		name              string
		restore           *velerov1api.Restore
		existingVGSCs     []*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent
		existingVSCs      []*snapshotv1api.VolumeSnapshotContent
		expectedRemaining int
		expectedWarnings  bool
	}{
		{
			name:              "no stub VGSCs to clean up",
			restore:           builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Result(),
			existingVGSCs:     nil,
			expectedRemaining: 0,
			expectedWarnings:  false,
		},
		{
			name:    "single stub VGSC deleted after VSCs are ready",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Result(),
			existingVGSCs: []*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vgsc-stub-1",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
						Driver: "rbd.csi.ceph.com",
						Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{
							GroupSnapshotHandles: &volumegroupsnapshotv1beta2.GroupSnapshotHandles{
								VolumeGroupSnapshotHandle: "vgs-handle-1",
								VolumeSnapshotHandles:     []string{snapshotHandle1},
							},
						},
					},
				},
			},
			existingVSCs: []*snapshotv1api.VolumeSnapshotContent{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-1",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						Driver:         "rbd.csi.ceph.com",
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
						Source: snapshotv1api.VolumeSnapshotContentSource{
							SnapshotHandle: &snapshotHandle1,
						},
						VolumeSnapshotRef: corev1api.ObjectReference{
							Name:      "vs-1",
							Namespace: "ns-1",
						},
					},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						ReadyToUse: boolptr.True(),
					},
				},
			},
			expectedRemaining: 0,
			expectedWarnings:  false,
		},
		{
			name:    "multiple stub VGSCs deleted",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Result(),
			existingVGSCs: []*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vgsc-stub-1",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
						Driver: "rbd.csi.ceph.com",
						Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{
							GroupSnapshotHandles: &volumegroupsnapshotv1beta2.GroupSnapshotHandles{
								VolumeGroupSnapshotHandle: "vgs-handle-1",
								VolumeSnapshotHandles:     []string{snapshotHandle1},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vgsc-stub-2",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
						Driver: "rbd.csi.ceph.com",
						Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{
							GroupSnapshotHandles: &volumegroupsnapshotv1beta2.GroupSnapshotHandles{
								VolumeGroupSnapshotHandle: "vgs-handle-2",
								VolumeSnapshotHandles:     []string{snapshotHandle2},
							},
						},
					},
				},
			},
			existingVSCs: []*snapshotv1api.VolumeSnapshotContent{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-1",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						Driver:         "rbd.csi.ceph.com",
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
						Source: snapshotv1api.VolumeSnapshotContentSource{
							SnapshotHandle: &snapshotHandle1,
						},
						VolumeSnapshotRef: corev1api.ObjectReference{
							Name:      "vs-1",
							Namespace: "ns-1",
						},
					},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						ReadyToUse: boolptr.True(),
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-2",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						Driver:         "rbd.csi.ceph.com",
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
						Source: snapshotv1api.VolumeSnapshotContentSource{
							SnapshotHandle: &snapshotHandle2,
						},
						VolumeSnapshotRef: corev1api.ObjectReference{
							Name:      "vs-2",
							Namespace: "ns-1",
						},
					},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						ReadyToUse: boolptr.True(),
					},
				},
			},
			expectedRemaining: 0,
			expectedWarnings:  false,
		},
		{
			name:    "VGSCs from different restore are not deleted",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Result(),
			existingVGSCs: []*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vgsc-stub-mine",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
						Driver: "rbd.csi.ceph.com",
						Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vgsc-stub-other",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-2",
						},
					},
					Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
						Driver: "rbd.csi.ceph.com",
						Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{},
					},
				},
			},
			expectedRemaining: 1,
			expectedWarnings:  false,
		},
		{
			name:    "VGSC deleted even when no snapshot handles in spec",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Result(),
			existingVGSCs: []*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vgsc-stub-empty",
						Labels: map[string]string{
							velerov1api.RestoreNameLabel: "restore-1",
						},
					},
					Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
						Driver: "rbd.csi.ceph.com",
						Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{},
					},
				},
			},
			expectedRemaining: 0,
			expectedWarnings:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
			logger := velerotest.NewLogger()

			ctx := &finalizerContext{
				logger:          logger,
				crClient:        fakeClient,
				restore:         tc.restore,
				resourceTimeout: 10 * time.Second,
			}

			for _, vgsc := range tc.existingVGSCs {
				require.NoError(t, fakeClient.Create(t.Context(), vgsc))
			}
			for _, vsc := range tc.existingVSCs {
				require.NoError(t, fakeClient.Create(t.Context(), vsc))
			}

			warnings := ctx.cleanupStubVGSC()

			if tc.expectedWarnings {
				assert.False(t, warnings.IsEmpty())
			} else {
				assert.True(t, warnings.IsEmpty(), "expected no warnings")
			}

			remainingList := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentList{}
			require.NoError(t, fakeClient.List(t.Context(), remainingList))
			assert.Len(t, remainingList.Items, tc.expectedRemaining)

			// Verify remaining VGSCs don't belong to this restore
			for _, remaining := range remainingList.Items {
				assert.NotEqual(t, tc.restore.Name, remaining.Labels[velerov1api.RestoreNameLabel],
					"VGSC %s should have been deleted", remaining.Name)
			}
		})
	}
}
