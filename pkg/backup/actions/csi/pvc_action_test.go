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

package csi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vmware-tanzu/velero/pkg/kuberesource"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/vmware-tanzu/velero/pkg/label"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

const testDriver = "csi.example.com"

// errorInjectingClient is a wrapper around a normal client that injects an error
// when a specific resource type (VolumeSnapshot) is created.
type errorInjectingClient struct {
	crclient.Client
}

// Create overrides the embedded client's Create method.
func (c *errorInjectingClient) Create(ctx context.Context, obj crclient.Object, opts ...crclient.CreateOption) error {
	// Check if the object being created is a VolumeSnapshot.
	if _, ok := obj.(*snapshotv1api.VolumeSnapshot); ok {
		// If it is, return our injected error instead of proceeding.
		return errors.New("injected error on create")
	}
	// For all other object types, call the original, embedded Create method.
	return c.Client.Create(ctx, obj, opts...)
}

func TestExecute(t *testing.T) {
	boolTrue := true
	tests := []struct {
		name               string
		backup             *velerov1api.Backup
		pvc                *corev1api.PersistentVolumeClaim
		pv                 *corev1api.PersistentVolume
		sc                 *storagev1api.StorageClass
		vsClass            *snapshotv1api.VolumeSnapshotClass
		operationID        string
		expectedErr        error
		expectErr          bool // Use bool for cases where we just need to check for any error
		expectedBackup     *velerov1api.Backup
		expectedDataUpload *velerov2alpha1.DataUpload
		expectedPVC        *corev1api.PersistentVolumeClaim
		resourcePolicy     *corev1api.ConfigMap
		extraObjects       []runtime.Object
		failVSCreate       bool
		skipVSReadyUpdate  bool // New flag to control VS readiness
	}{
		{
			name:   "Skip PVC BIA when backup is in finalizing phase",
			backup: builder.ForBackup("velero", "test").Phase(velerov1api.BackupPhaseFinalizing).Result(),
		},
		{
			name:         "Fail when creating volumesnapshot returns error",
			backup:       builder.ForBackup("velero", "test").CSISnapshotTimeout(1 * time.Minute).Result(),
			pvc:          builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
			pv:           builder.ForPersistentVolume("testPV").CSI("hostpath", "testVolume").Result(),
			sc:           builder.ForStorageClass("testSC").Provisioner("hostpath").Result(),
			vsClass:      builder.ForVolumeSnapshotClass("testVSClass").Driver("hostpath").ObjectMeta(builder.WithLabels(velerov1api.VolumeSnapshotClassSelectorLabel, "")).Result(),
			failVSCreate: true,
			expectedErr:  errors.New("error creating volume snapshot: injected error on create"),
		},
		{
			name:              "Fail when waiting for VolumeSnapshot to be ready times out",
			backup:            builder.ForBackup("velero", "test").CSISnapshotTimeout(20 * time.Millisecond).Result(), // Short timeout
			pvc:               builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
			pv:                builder.ForPersistentVolume("testPV").CSI("hostpath", "testVolume").Result(),
			sc:                builder.ForStorageClass("testSC").Provisioner("hostpath").Result(),
			vsClass:           builder.ForVolumeSnapshotClass("testVSClass").Driver("hostpath").ObjectMeta(builder.WithLabels(velerov1api.VolumeSnapshotClassSelectorLabel, "")).Result(),
			skipVSReadyUpdate: true, // This will cause the timeout
			expectErr:         true, // Expect an error, but the exact message can vary
		},
		{
			name:    "Test SnapshotMoveData",
			backup:  builder.ForBackup("velero", "test").SnapshotMoveData(true).CSISnapshotTimeout(1 * time.Minute).Result(),
			pvc:     builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
			pv:      builder.ForPersistentVolume("testPV").CSI("hostpath", "testVolume").Result(),
			sc:      builder.ForStorageClass("testSC").Provisioner("hostpath").Result(),
			vsClass: builder.ForVolumeSnapshotClass("testVSClass").Driver("hostpath").ObjectMeta(builder.WithLabels(velerov1api.VolumeSnapshotClassSelectorLabel, "")).Result(),
			extraObjects: []runtime.Object{
				&appsv1api.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "velero", Name: "node-agent"},
					Status:     appsv1api.DaemonSetStatus{NumberReady: 3},
				},
			},
			operationID: ".",
			expectedDataUpload: &velerov2alpha1.DataUpload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Namespace:    "velero",
					Labels: map[string]string{
						velerov1api.BackupNameLabel:       "test",
						velerov1api.BackupUIDLabel:        "",
						velerov1api.PVCUIDLabel:           "",
						velerov1api.AsyncOperationIDLabel: "du-.",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "velero.io/v1",
							Kind:       "Backup",
							Name:       "test",
							UID:        "",
							Controller: &boolTrue,
						},
					},
				},
				Spec: velerov2alpha1.DataUploadSpec{
					SnapshotType: velerov2alpha1.SnapshotTypeCSI,
					CSISnapshot: &velerov2alpha1.CSISnapshotSpec{
						VolumeSnapshot: "",
						StorageClass:   "testSC",
						SnapshotClass:  "testVSClass",
					},
					SourcePVC:        "testPVC",
					SourceNamespace:  "velero",
					OperationTimeout: metav1.Duration{Duration: 1 * time.Minute},
				},
			},
		},
		{
			name:    "Verify PVC is modified as expected",
			backup:  builder.ForBackup("velero", "test").SnapshotMoveData(true).CSISnapshotTimeout(1 * time.Minute).Result(),
			pvc:     builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
			pv:      builder.ForPersistentVolume("testPV").CSI("hostpath", "testVolume").Result(),
			sc:      builder.ForStorageClass("testSC").Provisioner("hostpath").Result(),
			vsClass: builder.ForVolumeSnapshotClass("tescVSClass").Driver("hostpath").ObjectMeta(builder.WithLabels(velerov1api.VolumeSnapshotClassSelectorLabel, "")).Result(),
			extraObjects: []runtime.Object{
				&appsv1api.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "velero", Name: "node-agent"},
					Status:     appsv1api.DaemonSetStatus{NumberReady: 3},
				},
			},
			operationID: ".",
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").
				ObjectMeta(builder.WithAnnotations(velerov1api.MustIncludeAdditionalItemAnnotation, "true", velerov1api.DataUploadNameAnnotation, "velero/"),
					builder.WithLabels(velerov1api.BackupNameLabel, "test")).
				VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
		},
		{
			name:              "Test SnapshotMoveData without node-agent",
			backup:            builder.ForBackup("velero", "test").SnapshotMoveData(true).CSISnapshotTimeout(1 * time.Minute).Result(),
			pvc:               builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
			pv:                builder.ForPersistentVolume("testPV").CSI("hostpath", "testVolume").Result(),
			sc:                builder.ForStorageClass("testSC").Provisioner("hostpath").Result(),
			vsClass:           builder.ForVolumeSnapshotClass("testVSClass").Driver("hostpath").ObjectMeta(builder.WithLabels(velerov1api.VolumeSnapshotClassSelectorLabel, "")).Result(),
			expectErr:         true,
			skipVSReadyUpdate: true,
		},
		{
			name:           "Test ResourcePolicy",
			backup:         builder.ForBackup("velero", "test").ResourcePolicies("resourcePolicy").SnapshotVolumes(false).CSISnapshotTimeout(time.Duration(3600) * time.Second).Result(),
			resourcePolicy: builder.ForConfigMap("velero", "resourcePolicy").Data("policy", "{\"version\":\"v1\", \"volumePolicies\":[{\"conditions\":{\"csi\": {}},\"action\":{\"type\":\"snapshot\"}}]}").Result(),
			pvc:            builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").StorageClass("testSC").Phase(corev1api.ClaimBound).Result(),
			pv:             builder.ForPersistentVolume("testPV").CSI("hostpath", "testVolume").Result(),
			sc:             builder.ForStorageClass("testSC").Provisioner("hostpath").Result(),
			vsClass:        builder.ForVolumeSnapshotClass("tescVSClass").Driver("hostpath").ObjectMeta(builder.WithLabels(velerov1api.VolumeSnapshotClassSelectorLabel, "")).Result(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.Level = logrus.DebugLevel
			objects := make([]runtime.Object, 0)
			if tc.pvc != nil {
				objects = append(objects, tc.pvc)
			}
			if tc.pv != nil {
				objects = append(objects, tc.pv)
			}
			if tc.sc != nil {
				objects = append(objects, tc.sc)
			}
			if tc.vsClass != nil {
				objects = append(objects, tc.vsClass)
			}
			if tc.resourcePolicy != nil {
				objects = append(objects, tc.resourcePolicy)
			}
			objects = append(objects, tc.extraObjects...)

			var crClient crclient.Client
			if tc.failVSCreate {
				realFakeClient := velerotest.NewFakeControllerRuntimeClient(t, objects...)
				crClient = &errorInjectingClient{Client: realFakeClient}
			} else {
				crClient = velerotest.NewFakeControllerRuntimeClient(t, objects...)
			}

			pvcBIA := pvcBackupItemAction{
				log:      logger,
				crClient: crClient,
			}

			pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&tc.pvc)
			require.NoError(t, err)

			var reconcileErrCh chan error
			if tc.pvc != nil && !tc.failVSCreate && !tc.skipVSReadyUpdate {
				reconcileErrCh = make(chan error, 1)
				go func() {
					var vsList snapshotv1api.VolumeSnapshotList
					err := wait.PollUntilContextTimeout(t.Context(), 1*time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
						if err := pvcBIA.crClient.List(ctx, &vsList, &crclient.ListOptions{Namespace: tc.pvc.Namespace}); err != nil {
							return false, err
						}
						if len(vsList.Items) == 0 {
							return false, nil
						}

						return true, nil
					})

					if err != nil {
						reconcileErrCh <- err
						return
					}

					vscName := "testVSC"
					handleName := "testHandle"
					vsc := builder.ForVolumeSnapshotContent("testVSC").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &handleName}).Result()
					err = pvcBIA.crClient.Create(t.Context(), vsc)
					if err != nil {
						reconcileErrCh <- err
						return
					}

					readyToUse := true
					vsList.Items[0].Status = &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
						ReadyToUse:                     &readyToUse,
					}
					err = pvcBIA.crClient.Update(t.Context(), &vsList.Items[0])
					reconcileErrCh <- err
				}()
			}

			resultUnstructed, _, _, _, err := pvcBIA.Execute(&unstructured.Unstructured{Object: pvcMap}, tc.backup)

			if tc.expectedErr != nil {
				require.EqualError(t, err, tc.expectedErr.Error())
			} else if tc.expectErr {
				require.Error(t, err)
				// On timeout failure, check that the cleanup logic was called
				if tc.skipVSReadyUpdate {
					vsList := new(snapshotv1api.VolumeSnapshotList)
					errList := crClient.List(t.Context(), vsList, &crclient.ListOptions{Namespace: tc.pvc.Namespace})
					require.NoError(t, errList)
					require.Empty(t, vsList.Items, "VolumeSnapshot should have been cleaned up after readiness check failed")
				}
			} else {
				require.NoError(t, err)
			}

			if reconcileErrCh != nil {
				require.NoError(t, <-reconcileErrCh)
			}

			if tc.expectedDataUpload != nil {
				dataUploadList := new(velerov2alpha1.DataUploadList)
				err := crClient.List(t.Context(), dataUploadList, &crclient.ListOptions{LabelSelector: labels.SelectorFromSet(map[string]string{velerov1api.BackupNameLabel: tc.backup.Name})})
				require.NoError(t, err)
				require.Len(t, dataUploadList.Items, 1)
				require.Empty(t, cmp.Diff(tc.expectedDataUpload, &dataUploadList.Items[0], cmpopts.IgnoreFields(velerov2alpha1.DataUpload{}, "TypeMeta", "ResourceVersion", "Name", "Spec.CSISnapshot.VolumeSnapshot")))
			}

			if tc.expectedPVC != nil {
				resultPVC := new(corev1api.PersistentVolumeClaim)
				runtime.DefaultUnstructuredConverter.FromUnstructured(resultUnstructed.UnstructuredContent(), resultPVC)
				require.True(t, cmp.Equal(tc.expectedPVC, resultPVC, cmpopts.IgnoreFields(corev1api.PersistentVolumeClaim{}, "ResourceVersion", "Annotations", "Labels")))
			}
		})
	}
}

func TestProgress(t *testing.T) {
	currentTime := time.Now()
	tests := []struct {
		name             string
		backup           *velerov1api.Backup
		dataUpload       *velerov2alpha1.DataUpload
		operationID      string
		expectedErr      string
		expectedProgress velero.OperationProgress
	}{
		{
			name:        "DataUpload cannot be found",
			backup:      builder.ForBackup("velero", "test").Result(),
			operationID: "testing",
			expectedErr: "not found DataUpload for operationID testing",
		},
		{
			name:   "DataUpload in different namespace is not found",
			backup: builder.ForBackup("velero", "test").Result(),
			dataUpload: &velerov2alpha1.DataUpload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: "v2alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "other-namespace",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
				Status: velerov2alpha1.DataUploadStatus{
					Phase: velerov2alpha1.DataUploadPhaseFailed,
				},
			},
			operationID: "testing",
			expectedErr: "not found DataUpload for operationID testing",
		},
		{
			name:   "DataUpload is found",
			backup: builder.ForBackup("velero", "test").Result(),
			dataUpload: &velerov2alpha1.DataUpload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: "v2alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
				Status: velerov2alpha1.DataUploadStatus{
					Phase: velerov2alpha1.DataUploadPhaseFailed,
					Progress: shared.DataMoveOperationProgress{
						BytesDone:  1000,
						TotalBytes: 1000,
					},
					StartTimestamp:      &metav1.Time{Time: currentTime},
					CompletionTimestamp: &metav1.Time{Time: currentTime},
					Message:             "Testing error",
				},
			},
			operationID: "testing",
			expectedProgress: velero.OperationProgress{
				Completed:      true,
				Err:            "Testing error",
				NCompleted:     1000,
				NTotal:         1000,
				OperationUnits: "Bytes",
				Description:    "Failed",
				Started:        currentTime,
				Updated:        currentTime,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger := logrus.New()

			pvcBIA := pvcBackupItemAction{
				log:      logger,
				crClient: crClient,
			}

			if tc.dataUpload != nil {
				err := crClient.Create(t.Context(), tc.dataUpload)
				require.NoError(t, err)
			}

			progress, err := pvcBIA.Progress(tc.operationID, tc.backup)
			if tc.expectedErr != "" {
				require.Equal(t, tc.expectedErr, err.Error())
			}
			require.True(t, cmp.Equal(tc.expectedProgress, progress, cmpopts.IgnoreFields(velero.OperationProgress{}, "Started", "Updated")))
		})
	}
}

func TestCancel(t *testing.T) {
	tests := []struct {
		name               string
		backup             *velerov1api.Backup
		dataUpload         *velerov2alpha1.DataUpload
		operationID        string
		expectedErr        string
		expectedDataUpload velerov2alpha1.DataUpload
	}{
		{
			name:   "Cancel DataUpload",
			backup: builder.ForBackup("velero", "test").Result(),
			dataUpload: &velerov2alpha1.DataUpload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
			},
			operationID: "testing",
			expectedDataUpload: velerov2alpha1.DataUpload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
				Spec: velerov2alpha1.DataUploadSpec{
					Cancel: true,
				},
			},
		},
		{
			name:        "DataUpload cannot be found",
			backup:      builder.ForBackup("velero", "test").Result(),
			operationID: "testing",
			expectedErr: "not found DataUpload for operationID testing",
		},
		{
			name:   "DataUpload in different namespace is not found",
			backup: builder.ForBackup("velero", "test").Result(),
			dataUpload: &velerov2alpha1.DataUpload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "other-namespace",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
			},
			operationID: "testing",
			expectedErr: "not found DataUpload for operationID testing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger := logrus.New()

			pvcBIA := pvcBackupItemAction{
				log:      logger,
				crClient: crClient,
			}

			if tc.dataUpload != nil {
				err := crClient.Create(t.Context(), tc.dataUpload)
				require.NoError(t, err)
			}

			err := pvcBIA.Cancel(tc.operationID, tc.backup)
			if tc.expectedErr != "" {
				require.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)

				du := new(velerov2alpha1.DataUpload)
				err = crClient.Get(t.Context(), crclient.ObjectKey{Namespace: tc.dataUpload.Namespace, Name: tc.dataUpload.Name}, du)
				require.NoError(t, err)

				require.Empty(t, cmp.Diff(tc.expectedDataUpload, *du, cmpopts.IgnoreFields(velerov2alpha1.DataUpload{}, "TypeMeta", "ResourceVersion")))
			}
		})
	}
}

func TestPVCAppliesTo(t *testing.T) {
	p := pvcBackupItemAction{
		log: logrus.StandardLogger(),
	}
	selector, err := p.AppliesTo()

	require.NoError(t, err)

	require.Equal(
		t,
		velero.ResourceSelector{
			IncludedResources: []string{"persistentvolumeclaims"},
		},
		selector,
	)
}

func TestNewPVCBackupItemAction(t *testing.T) {
	logger := logrus.StandardLogger()
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewPvcBackupItemAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	f1 := &factorymocks.Factory{}
	f1.On("KubebuilderClient").Return(crClient, nil)
	plugin1 := NewPvcBackupItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}

func TestListGroupedPVCs(t *testing.T) {
	tests := []struct {
		name        string
		namespace   string
		labelKey    string
		groupValue  string
		pvcs        []corev1api.PersistentVolumeClaim
		expectCount int
		expectError bool
	}{
		{
			name:       "Match single PVC with label",
			namespace:  "ns1",
			labelKey:   "vgs-key",
			groupValue: "group-a",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc1",
						Namespace: "ns1",
						Labels: map[string]string{
							"vgs-key": "group-a",
						},
					},
				},
			},
			expectCount: 1,
		},
		{
			name:       "No matching PVCs",
			namespace:  "ns1",
			labelKey:   "vgs-key",
			groupValue: "group-b",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc1",
						Namespace: "ns1",
						Labels: map[string]string{
							"vgs-key": "group-a",
						},
					},
				},
			},
			expectCount: 0,
		},
		{
			name:       "Match multiple PVCs",
			namespace:  "ns1",
			labelKey:   "vgs-key",
			groupValue: "group-a",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc1",
						Namespace: "ns1",
						Labels:    map[string]string{"vgs-key": "group-a"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc2",
						Namespace: "ns1",
						Labels:    map[string]string{"vgs-key": "group-a"},
					},
				},
			},
			expectCount: 2,
		},
		{
			name:       "Different namespace",
			namespace:  "ns2",
			labelKey:   "vgs-key",
			groupValue: "group-a",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc1",
						Namespace: "ns1",
						Labels:    map[string]string{"vgs-key": "group-a"},
					},
				},
			},
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			for i := range tt.pvcs {
				objs = append(objs, &tt.pvcs[i])
			}
			client := velerotest.NewFakeControllerRuntimeClient(t, objs...)

			action := &pvcBackupItemAction{
				log:      logrus.New(),
				crClient: client,
			}

			result, err := action.listGroupedPVCs(t.Context(), tt.namespace, tt.labelKey, tt.groupValue)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, result, tt.expectCount)
			}
		})
	}
}

func TestFilterPVCsByVolumePolicy(t *testing.T) {
	tests := []struct {
		name            string
		pvcs            []corev1api.PersistentVolumeClaim
		pvs             []corev1api.PersistentVolume
		volumePolicyStr string
		expectCount     int
		expectError     bool
	}{
		{
			name: "All PVCs should be included when no volume policy",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: "ns-1"},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-1",
						StorageClassName: ptr.To("sc-1"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-2", Namespace: "ns-1"},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-2",
						StorageClassName: ptr.To("sc-1"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver-1"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver-1"},
						},
					},
				},
			},
			expectCount: 2,
		},
		{
			name: "Filter out NFS PVC by volume policy",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-csi", Namespace: "ns-1"},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-csi",
						StorageClassName: ptr.To("sc-1"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-nfs", Namespace: "ns-1"},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-nfs",
						StorageClassName: ptr.To("sc-nfs"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-csi"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							NFS: &corev1api.NFSVolumeSource{
								Server: "nfs-server",
								Path:   "/export",
							},
						},
					},
				},
			},
			volumePolicyStr: `
version: v1
volumePolicies:
- conditions:
    nfs: {}
  action:
    type: skip
`,
			expectCount: 1,
		},
		{
			name: "All PVCs filtered out by volume policy",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-nfs-1", Namespace: "ns-1"},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-nfs-1",
						StorageClassName: ptr.To("sc-nfs"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-nfs-2", Namespace: "ns-1"},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-nfs-2",
						StorageClassName: ptr.To("sc-nfs"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs-1"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							NFS: &corev1api.NFSVolumeSource{
								Server: "nfs-server",
								Path:   "/export/1",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs-2"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							NFS: &corev1api.NFSVolumeSource{
								Server: "nfs-server",
								Path:   "/export/2",
							},
						},
					},
				},
			},
			volumePolicyStr: `
version: v1
volumePolicies:
- conditions:
    nfs: {}
  action:
    type: skip
`,
			expectCount: 0,
		},
		{
			name: "Filter out non-CSI PVCs from mixed driver group",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc-linstor",
						Namespace: "ns-1",
						Labels:    map[string]string{"app.kubernetes.io/instance": "myapp"},
					},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-linstor",
						StorageClassName: ptr.To("sc-linstor"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pvc-nfs",
						Namespace: "ns-1",
						Labels:    map[string]string{"app.kubernetes.io/instance": "myapp"},
					},
					Spec: corev1api.PersistentVolumeClaimSpec{
						VolumeName:       "pv-nfs",
						StorageClassName: ptr.To("sc-nfs"),
					},
					Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-linstor"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "linstor.csi.linbit.com"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							NFS: &corev1api.NFSVolumeSource{
								Server: "nfs-server",
								Path:   "/export",
							},
						},
					},
				},
			},
			volumePolicyStr: `
version: v1
volumePolicies:
- conditions:
    nfs: {}
  action:
    type: skip
`,
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for i := range tt.pvs {
				objs = append(objs, &tt.pvs[i])
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, objs...)

			backup := &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupSpec{},
			}

			// Add volume policy ConfigMap if specified
			if tt.volumePolicyStr != "" {
				cm := &corev1api.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "volume-policy",
						Namespace: "velero",
					},
					Data: map[string]string{
						"volume-policy": tt.volumePolicyStr,
					},
				}
				require.NoError(t, client.Create(t.Context(), cm))

				backup.Spec.ResourcePolicy = &corev1api.TypedLocalObjectReference{
					Kind: "ConfigMap",
					Name: "volume-policy",
				}
			}

			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			// Create a VolumeHelper using the same method the plugin would use
			vh, err := action.getOrCreateVolumeHelper(backup)
			require.NoError(t, err)
			require.NotNil(t, vh)

			// Test with the pre-created VolumeHelper
			result, err := action.filterPVCsByVolumePolicy(tt.pvcs, vh)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, result, tt.expectCount)

				// For mixed driver scenarios, verify filtered result can determine single CSI driver
				if tt.name == "Filter out non-CSI PVCs from mixed driver group" && len(result) > 0 {
					driver, err := action.determineCSIDriver(result)
					require.NoError(t, err, "After filtering, determineCSIDriver should not fail with multiple drivers error")
					require.Equal(t, "linstor.csi.linbit.com", driver, "Should have the Linstor driver after filtering out NFS")
				}
			}
		})
	}
}

// TestFilterPVCsByVolumePolicyWithVolumeHelper tests filterPVCsByVolumePolicy when a
// pre-created VolumeHelper is passed (non-nil). This exercises the cached path used
// by the CSI PVC BIA plugin for better performance.
func TestFilterPVCsByVolumePolicyWithVolumeHelper(t *testing.T) {
	// Create test PVCs and PVs
	pvcs := []corev1api.PersistentVolumeClaim{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pvc-csi", Namespace: "ns-1"},
			Spec: corev1api.PersistentVolumeClaimSpec{
				VolumeName:       "pv-csi",
				StorageClassName: ptr.To("sc-csi"),
			},
			Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pvc-nfs", Namespace: "ns-1"},
			Spec: corev1api.PersistentVolumeClaimSpec{
				VolumeName:       "pv-nfs",
				StorageClassName: ptr.To("sc-nfs"),
			},
			Status: corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
		},
	}

	pvs := []corev1api.PersistentVolume{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-csi"},
			Spec: corev1api.PersistentVolumeSpec{
				PersistentVolumeSource: corev1api.PersistentVolumeSource{
					CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs"},
			Spec: corev1api.PersistentVolumeSpec{
				PersistentVolumeSource: corev1api.PersistentVolumeSource{
					NFS: &corev1api.NFSVolumeSource{
						Server: "nfs-server",
						Path:   "/export",
					},
				},
			},
		},
	}

	// Create fake client with PVs
	objs := []runtime.Object{}
	for i := range pvs {
		objs = append(objs, &pvs[i])
	}
	client := velerotest.NewFakeControllerRuntimeClient(t, objs...)

	// Create backup with volume policy that skips NFS volumes
	volumePolicyStr := `
version: v1
volumePolicies:
- conditions:
    nfs: {}
  action:
    type: skip
`
	cm := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "volume-policy",
			Namespace: "velero",
		},
		Data: map[string]string{
			"volume-policy": volumePolicyStr,
		},
	}
	require.NoError(t, client.Create(t.Context(), cm))

	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backup",
			Namespace: "velero",
		},
		Spec: velerov1api.BackupSpec{
			ResourcePolicy: &corev1api.TypedLocalObjectReference{
				Kind: "ConfigMap",
				Name: "volume-policy",
			},
		},
	}

	action := &pvcBackupItemAction{
		log:      velerotest.NewLogger(),
		crClient: client,
	}

	// Create a VolumeHelper using the same method the plugin would use
	vh, err := action.getOrCreateVolumeHelper(backup)
	require.NoError(t, err)
	require.NotNil(t, vh)

	// Test with the pre-created VolumeHelper (non-nil path)
	result, err := action.filterPVCsByVolumePolicy(pvcs, vh)
	require.NoError(t, err)

	// Should filter out the NFS PVC, leaving only the CSI PVC
	require.Len(t, result, 1)
	require.Equal(t, "pvc-csi", result[0].Name)
}

func TestDetermineCSIDriver(t *testing.T) {
	tests := []struct {
		name           string
		pvcs           []corev1api.PersistentVolumeClaim
		pvs            []corev1api.PersistentVolume
		expectError    bool
		expectedDriver string
	}{
		{
			name: "Single PVC with CSI PV",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: "ns-1"},
					Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
					Status:     corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver"},
						},
					},
				},
			},
			expectedDriver: "csi-driver",
		},
		{
			name: "Multiple PVCs with same CSI driver",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: "ns-1"},
					Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
					Status:     corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-2", Namespace: "ns-1"},
					Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: "pv-2"},
					Status:     corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver"},
						},
					},
				},
			},
			expectedDriver: "csi-driver",
		},
		{
			name: "PV not CSI provisioned",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: "ns-1"},
					Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
					Status:     corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
					Spec:       corev1api.PersistentVolumeSpec{},
				},
			},
			expectError: true,
		},
		{
			name: "Multiple PVCs with different CSI drivers",
			pvcs: []corev1api.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: "ns-1"},
					Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
					Status:     corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-2", Namespace: "ns-1"},
					Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: "pv-2"},
					Status:     corev1api.PersistentVolumeClaimStatus{Phase: corev1api.ClaimBound},
				},
			},
			pvs: []corev1api.PersistentVolume{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver-1"},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{Driver: "csi-driver-2"},
						},
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var initObjs []runtime.Object
			for i := range tt.pvcs {
				pvc := tt.pvcs[i]
				initObjs = append(initObjs, &pvc)
			}
			for i := range tt.pvs {
				pv := tt.pvs[i]
				initObjs = append(initObjs, &pv)
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)
			action := &pvcBackupItemAction{
				log:      logrus.New(),
				crClient: client,
			}

			driver, err := action.determineCSIDriver(tt.pvcs)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedDriver, driver)
			}
		})
	}
}

func TestDetermineVGSClass(t *testing.T) {
	tests := []struct {
		name             string
		backup           *velerov1api.Backup
		pvc              *corev1api.PersistentVolumeClaim
		existingVGSClass []volumegroupsnapshotv1beta2.VolumeGroupSnapshotClass
		expectError      bool
		expectResult     string
	}{
		{
			name: "PVC annotation override",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						velerov1api.VolumeGroupSnapshotClassAnnotationPVC: "pvc-class",
					},
				},
			},
			backup:       &velerov1api.Backup{},
			expectResult: "pvc-class",
		},
		{
			name: "Backup annotation override",
			pvc:  &corev1api.PersistentVolumeClaim{},
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						fmt.Sprintf("%s%s", velerov1api.VolumeGroupSnapshotClassAnnotationBackupPrefix, testDriver): "backup-class",
					},
				},
			},
			expectResult: "backup-class",
		},
		{
			name:   "Default label-based match",
			pvc:    &corev1api.PersistentVolumeClaim{},
			backup: &velerov1api.Backup{},
			existingVGSClass: []volumegroupsnapshotv1beta2.VolumeGroupSnapshotClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "default-class",
						Labels: map[string]string{velerov1api.VolumeGroupSnapshotClassDefaultLabel: "true"},
					},
					Driver: testDriver,
				},
			},
			expectResult: "default-class",
		},
		{
			name:        "No matching VGS class",
			pvc:         &corev1api.PersistentVolumeClaim{},
			backup:      &velerov1api.Backup{},
			expectError: true,
		},
		{
			name:   "Multiple matching VGS classes",
			pvc:    &corev1api.PersistentVolumeClaim{},
			backup: &velerov1api.Backup{},
			existingVGSClass: []volumegroupsnapshotv1beta2.VolumeGroupSnapshotClass{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "class1",
						Labels: map[string]string{velerov1api.VolumeGroupSnapshotClassDefaultLabel: "true"},
					},
					Driver: testDriver,
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "class2",
						Labels: map[string]string{velerov1api.VolumeGroupSnapshotClassDefaultLabel: "true"},
					},
					Driver: testDriver,
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var initObjs []runtime.Object
			for _, vgsClass := range tt.existingVGSClass {
				vgsClassCopy := vgsClass
				initObjs = append(initObjs, &vgsClassCopy)
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)
			logger := logrus.New()
			require.NoError(t, volumegroupsnapshotv1beta2.AddToScheme(client.Scheme()))

			action := &pvcBackupItemAction{crClient: client, log: logger}

			result, err := action.determineVGSClass(t.Context(), testDriver, tt.backup, tt.pvc)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectResult, result)
			}
		})
	}
}

func TestCreateVolumeGroupSnapshot(t *testing.T) {
	testNamespace := "test-ns"
	testLabelKey := "velero.io/test-vgs-label"
	testLabelValue := "group-1"
	testVGSClass := "test-class"
	testBackup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-backup",
			UID:  "test-uid",
		},
	}
	testPVC := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pvc",
			Namespace: testNamespace,
			Labels: map[string]string{
				testLabelKey: testLabelValue,
			},
		},
	}

	crClient := velerotest.NewFakeControllerRuntimeClient(t)
	log := logrus.New()
	action := &pvcBackupItemAction{
		log:      log,
		crClient: crClient,
	}

	vgs, err := action.createVolumeGroupSnapshot(t.Context(), testBackup, testPVC, testLabelKey, testLabelValue, testVGSClass)
	require.NoError(t, err)
	require.NotNil(t, vgs)

	// Verify VGS fields
	assert.Equal(t, testNamespace, vgs.Namespace)
	assert.NotEmpty(t, vgs.GenerateName)
	assert.Equal(t, testVGSClass, *vgs.Spec.VolumeGroupSnapshotClassName)
	assert.NotNil(t, vgs.Spec.Source.Selector)
	assert.Equal(t, testLabelValue, vgs.Spec.Source.Selector.MatchLabels[testLabelKey])
	assert.Equal(t, testLabelValue, vgs.Labels[testLabelKey])
	assert.Equal(t, label.GetValidName(testBackup.Name), vgs.Labels[velerov1api.BackupNameLabel])
	assert.Equal(t, string(testBackup.UID), vgs.Labels[velerov1api.BackupUIDLabel])

	// Check that it exists in fake client
	retrieved := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
	err = crClient.Get(t.Context(), crclient.ObjectKey{Name: vgs.Name, Namespace: vgs.Namespace}, retrieved)
	require.NoError(t, err)
}

func TestWaitForVGSAssociatedVS(t *testing.T) {
	vgs := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vgs",
			Namespace: "test-ns",
			UID:       types.UID("1234-5678-uuid"),
		},
	}

	makeVS := func(name string, hasStatus bool, hasVGSName bool, owned bool, pvcName string) *snapshotv1api.VolumeSnapshot {
		var refs []metav1.OwnerReference
		if owned {
			refs = []metav1.OwnerReference{
				{
					APIVersion: "groupsnapshot.storage.k8s.io/v1beta2",
					Kind:       "VolumeGroupSnapshot",
					Name:       vgs.Name,
					UID:        vgs.UID,
				},
			}
		}

		vs := &snapshotv1api.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       vgs.Namespace,
				OwnerReferences: refs,
			},
			Spec: snapshotv1api.VolumeSnapshotSpec{
				Source: snapshotv1api.VolumeSnapshotSource{
					PersistentVolumeClaimName: ptr.To(pvcName),
				},
			},
		}

		if hasStatus {
			vs.Status = &snapshotv1api.VolumeSnapshotStatus{}
			if hasVGSName {
				vs.Status.VolumeGroupSnapshotName = ptr.To(vgs.Name)
			}
		}

		return vs
	}

	makePVC := func(name string) corev1api.PersistentVolumeClaim {
		return corev1api.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: vgs.Namespace,
			},
		}
	}

	tests := []struct {
		name        string
		vsList      []*snapshotv1api.VolumeSnapshot
		groupedPVCs []corev1api.PersistentVolumeClaim
		expectErr   bool
		expectVSMap int
	}{
		{
			name: "all owned VS have VGS name",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs1", true, true, true, "pvc1"),
				makeVS("vs2", true, true, true, "pvc2"),
			},
			groupedPVCs: []corev1api.PersistentVolumeClaim{
				makePVC("pvc1"),
				makePVC("pvc2"),
			},
			expectErr:   false,
			expectVSMap: 2,
		},
		{
			name: "one owned VS missing VGS name",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs1", true, true, true, "pvc1"),
				makeVS("vs2", true, false, true, "pvc2"),
			},
			groupedPVCs: []corev1api.PersistentVolumeClaim{
				makePVC("pvc1"),
				makePVC("pvc2"),
			},
			expectErr: true,
		},
		{
			name: "owned VS has no status",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs1", false, false, true, "pvc1"),
			},
			groupedPVCs: []corev1api.PersistentVolumeClaim{
				makePVC("pvc1"),
			},
			expectErr: true,
		},
		{
			name: "unrelated VS ignored",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs1", true, true, false, "pvc1"),
			},
			groupedPVCs: []corev1api.PersistentVolumeClaim{
				makePVC("pvc1"),
			},
			expectErr: true,
		},
		{
			name: "no owned VS present",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs1", true, true, false, "pvc1"),
			},
			groupedPVCs: []corev1api.PersistentVolumeClaim{
				makePVC("pvc1"),
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, vgs)
			for _, vs := range tt.vsList {
				objs = append(objs, vs)
			}
			for _, pvc := range tt.groupedPVCs {
				objs = append(objs, &pvc)
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, objs...)
			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			vsMap, err := action.waitForVGSAssociatedVS(t.Context(), tt.groupedPVCs, vgs, 2*time.Second)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(vsMap) != tt.expectVSMap {
					t.Errorf("expected vsMap length %d, got %d", tt.expectVSMap, len(vsMap))
				}
			}
		})
	}
}

func TestUpdateVGSCreatedVS(t *testing.T) {
	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "backup-1",
			UID:  "backup-uid-123",
		},
	}

	vgs := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vgs",
			Namespace: "ns",
			UID:       "vgs-uid-123",
		},
	}

	makeVS := func(name string, withVGSOwner bool, vgsNamePtr *string, pvcName string) *snapshotv1api.VolumeSnapshot {
		var refs []metav1.OwnerReference
		if withVGSOwner {
			refs = []metav1.OwnerReference{
				{
					APIVersion: "groupsnapshot.storage.k8s.io/v1beta2",
					Kind:       "VolumeGroupSnapshot",
					Name:       vgs.Name,
					UID:        vgs.UID,
				},
			}
		}
		return &snapshotv1api.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				Namespace:       vgs.Namespace,
				OwnerReferences: refs,
				Finalizers: []string{
					VolumeSnapshotFinalizerGroupProtection,
					VolumeSnapshotFinalizerSourceProtection,
				},
			},
			Status: &snapshotv1api.VolumeSnapshotStatus{
				ReadyToUse:              ptr.To(true),
				VolumeGroupSnapshotName: vgsNamePtr,
			},
			Spec: snapshotv1api.VolumeSnapshotSpec{
				Source: snapshotv1api.VolumeSnapshotSource{
					PersistentVolumeClaimName: ptr.To(pvcName),
				},
			},
		}
	}

	tests := []struct {
		name                    string
		vs                      *snapshotv1api.VolumeSnapshot
		expectOwnerCleared      bool
		expectFinalizersCleared bool
		expectLabelPatched      bool
	}{
		{
			name:                    "should update owned VS",
			vs:                      makeVS("vs-owned", true, ptr.To(vgs.Name), "pvc-1"),
			expectOwnerCleared:      true,
			expectFinalizersCleared: true,
			expectLabelPatched:      true,
		},
		{
			name:                    "should skip VS not owned by VGS",
			vs:                      makeVS("vs-unowned", false, nil, "pvc-1"),
			expectOwnerCleared:      false,
			expectFinalizersCleared: false,
			expectLabelPatched:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := velerotest.NewFakeControllerRuntimeClient(t, vgs, tt.vs)
			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			// Build vsMap using the PVC name from the VS
			vsMap := map[string]*snapshotv1api.VolumeSnapshot{
				*tt.vs.Spec.Source.PersistentVolumeClaimName: tt.vs,
			}

			err := action.updateVGSCreatedVS(t.Context(), vsMap, vgs, backup)
			require.NoError(t, err)

			// Fetch updated VS
			updated := &snapshotv1api.VolumeSnapshot{}
			err = client.Get(t.Context(), crclient.ObjectKey{Name: tt.vs.Name, Namespace: tt.vs.Namespace}, updated)
			require.NoError(t, err)

			if tt.expectOwnerCleared {
				assert.Empty(t, updated.OwnerReferences, "expected ownerReferences to be cleared")
			} else {
				assert.Equal(t, tt.vs.OwnerReferences, updated.OwnerReferences, "expected ownerReferences to remain unchanged")
			}

			if tt.expectFinalizersCleared {
				assert.Empty(t, updated.Finalizers, "expected finalizers to be cleared")
			} else {
				assert.Equal(t, tt.vs.Finalizers, updated.Finalizers, "expected finalizers to remain unchanged")
			}

			if tt.expectLabelPatched {
				assert.Equal(t, "backup-1", updated.Labels[velerov1api.BackupNameLabel])
				assert.Equal(t, "backup-uid-123", updated.Labels[velerov1api.BackupUIDLabel])
			} else {
				assert.Nil(t, updated.Labels, "expected no labels to be patched")
			}
		})
	}
}

func TestPatchVGSCDeletionPolicy(t *testing.T) {
	tests := []struct {
		name           string
		initialPolicy  snapshotv1api.DeletionPolicy
		expectedPolicy snapshotv1api.DeletionPolicy
		expectPatch    bool
		expectErr      bool
	}{
		{
			name:           "patches Delete to Retain",
			initialPolicy:  snapshotv1api.VolumeSnapshotContentDelete,
			expectedPolicy: snapshotv1api.VolumeSnapshotContentRetain,
			expectPatch:    true,
		},
		{
			name:           "no patch if already Retain",
			initialPolicy:  snapshotv1api.VolumeSnapshotContentRetain,
			expectedPolicy: snapshotv1api.VolumeSnapshotContentRetain,
			expectPatch:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vgsc := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{Name: "test-vgsc"},
				Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
					DeletionPolicy: tt.initialPolicy,
				},
			}
			vgs := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vgs",
					Namespace: "ns",
				},
				Status: &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{
					BoundVolumeGroupSnapshotContentName: ptr.To("test-vgsc"),
				},
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, vgs, vgsc)
			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			err := action.patchVGSCDeletionPolicy(t.Context(), vgs)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			updated := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
			err = client.Get(t.Context(), crclient.ObjectKey{Name: "test-vgsc"}, updated)
			require.NoError(t, err)
			require.Equal(t, tt.expectedPolicy, updated.Spec.DeletionPolicy)
		})
	}
}

func TestDeleteVGSAndVGSC(t *testing.T) {
	makeVGS := func(name, namespace string, boundVGSCName *string) *volumegroupsnapshotv1beta2.VolumeGroupSnapshot {
		return &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Status: &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{
				BoundVolumeGroupSnapshotContentName: boundVGSCName,
			},
		}
	}

	makeVGSC := func(name string) *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent {
		return &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
	}

	tests := []struct {
		name             string
		vgs              *volumegroupsnapshotv1beta2.VolumeGroupSnapshot
		existingVGSC     *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent
		expectVGSCDelete bool
		expectVGSDelete  bool
	}{
		{
			name:             "deletes both VGSC and VGS",
			vgs:              makeVGS("test-vgs", "ns", ptr.To("test-vgsc")),
			existingVGSC:     makeVGSC("test-vgsc"),
			expectVGSCDelete: true,
			expectVGSDelete:  true,
		},
		{
			name:             "VGSC not found, still deletes VGS",
			vgs:              makeVGS("test-vgs", "ns", ptr.To("missing-vgsc")),
			existingVGSC:     nil,
			expectVGSCDelete: false,
			expectVGSDelete:  true,
		},
		{
			name:             "no BoundVGSCName set, only deletes VGS",
			vgs:              makeVGS("test-vgs", "ns", nil),
			existingVGSC:     nil,
			expectVGSCDelete: false,
			expectVGSDelete:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tt.vgs)
			if tt.existingVGSC != nil {
				objs = append(objs, tt.existingVGSC)
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, objs...)
			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			err := action.deleteVGSAndVGSC(t.Context(), tt.vgs)
			require.NoError(t, err)

			// Check VGSC is deleted
			if tt.expectVGSCDelete {
				got := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
				err = client.Get(t.Context(), crclient.ObjectKey{Name: "test-vgsc"}, got)
				assert.True(t, apierrors.IsNotFound(err), "expected VGSC to be deleted")
			}

			// Check VGS is deleted
			gotVGS := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
			err = client.Get(t.Context(), crclient.ObjectKey{Name: "test-vgs", Namespace: "ns"}, gotVGS)
			assert.True(t, apierrors.IsNotFound(err), "expected VGS to be deleted")
		})
	}
}

func TestFindExistingVSForBackup(t *testing.T) {
	backupUID := types.UID("backup-uid-123")
	backupName := "backup-1"
	pvcName := "pvc-1"
	namespace := "ns"

	makeVS := func(name, pvc string, match bool) *snapshotv1api.VolumeSnapshot {
		labels := map[string]string{}
		if match {
			labels[velerov1api.BackupNameLabel] = label.GetValidName(backupName)
			labels[velerov1api.BackupUIDLabel] = string(backupUID)
		}
		return &snapshotv1api.VolumeSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    labels,
			},
			Spec: snapshotv1api.VolumeSnapshotSpec{
				Source: snapshotv1api.VolumeSnapshotSource{
					PersistentVolumeClaimName: ptr.To(pvc),
				},
			},
		}
	}

	tests := []struct {
		name       string
		vsList     []*snapshotv1api.VolumeSnapshot
		expectName string
		expectNil  bool
	}{
		{
			name: "should find matching VS",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs-match", pvcName, true),
			},
			expectName: "vs-match",
			expectNil:  false,
		},
		{
			name: "should skip VS with non-matching labels",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs-nolabel", pvcName, false),
			},
			expectNil: true,
		},
		{
			name: "should skip VS with different PVC name",
			vsList: []*snapshotv1api.VolumeSnapshot{
				makeVS("vs-other-pvc", "other-pvc", true),
			},
			expectNil: true,
		},
		{
			name:      "should return nil if VS list is empty",
			vsList:    []*snapshotv1api.VolumeSnapshot{},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			for _, vs := range tt.vsList {
				objs = append(objs, vs)
			}

			client := velerotest.NewFakeControllerRuntimeClient(t, objs...)
			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			vs, err := action.findExistingVSForBackup(t.Context(), backupUID, backupName, pvcName, namespace)
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, vs)
			} else {
				require.NotNil(t, vs)
				assert.Equal(t, tt.expectName, vs.Name)
			}
		})
	}
}

func TestWaitForVGSCBinding(t *testing.T) {
	makeVGS := func(name string, withStatus bool) *volumegroupsnapshotv1beta2.VolumeGroupSnapshot {
		vgs := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "ns",
			},
		}
		if withStatus {
			contentName := "vgsc-123"
			vgs.Status = &volumegroupsnapshotv1beta2.VolumeGroupSnapshotStatus{
				BoundVolumeGroupSnapshotContentName: &contentName,
			}
		}
		return vgs
	}

	tests := []struct {
		name      string
		vgs       *volumegroupsnapshotv1beta2.VolumeGroupSnapshot
		expectErr bool
	}{
		{
			name:      "status is already bound",
			vgs:       makeVGS("vgs1", true),
			expectErr: false,
		},
		{
			name:      "status is nil",
			vgs:       makeVGS("vgs2", false),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := velerotest.NewFakeControllerRuntimeClient(t, tt.vgs.DeepCopy())

			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			err := action.waitForVGSCBinding(t.Context(), tt.vgs, 1*time.Second)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, tt.vgs.Status)
				require.NotNil(t, tt.vgs.Status.BoundVolumeGroupSnapshotContentName)
				require.Equal(t, "vgsc-123", *tt.vgs.Status.BoundVolumeGroupSnapshotContentName)
			}
		})
	}
}

func TestGetVGSByLabels(t *testing.T) {
	labelKey := "velero.io/backup-name"
	labelVal := "backup-123"
	testLabels := map[string]string{labelKey: labelVal}

	makeVGS := func(name string, labels map[string]string) *volumegroupsnapshotv1beta2.VolumeGroupSnapshot {
		return &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "test-ns",
				Labels:    labels,
			},
		}
	}

	tests := []struct {
		name        string
		vgsObjects  []runtime.Object
		expectError string
		expectName  string
	}{
		{
			name: "exactly one matching VGS",
			vgsObjects: []runtime.Object{
				makeVGS("vgs1", testLabels),
			},
			expectName: "vgs1",
		},
		{
			name:        "no matching VGS",
			vgsObjects:  []runtime.Object{},
			expectError: "no VolumeGroupSnapshot found matching labels",
		},
		{
			name: "multiple matching VGS",
			vgsObjects: []runtime.Object{
				makeVGS("vgs1", testLabels),
				makeVGS("vgs2", testLabels),
			},
			expectError: "multiple VolumeGroupSnapshots found matching labels",
		},
		{
			name:        "client list error",
			vgsObjects:  []runtime.Object{},
			expectError: "failed to list VolumeGroupSnapshots by labels",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client crclient.Client
			if tt.name == "client list error" {
				// Inject a client that always errors on List
				client = &failingClient{}
			} else {
				client = velerotest.NewFakeControllerRuntimeClient(t, tt.vgsObjects...)
			}

			action := &pvcBackupItemAction{
				log:      velerotest.NewLogger(),
				crClient: client,
			}

			vgs, err := action.getVGSByLabels(t.Context(), "test-ns", testLabels)

			if tt.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.expectError) {
					t.Errorf("expected error containing '%s', got: %v", tt.expectError, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if vgs == nil || vgs.Name != tt.expectName {
					t.Errorf("expected VGS name %s, got %v", tt.expectName, vgs)
				}
			}
		})
	}
}

// failingClient is a dummy client that fails on List
type failingClient struct {
	crclient.Client
}

func (f *failingClient) List(ctx context.Context, list crclient.ObjectList, opts ...crclient.ListOption) error {
	return fmt.Errorf("simulated list error")
}

func TestHasOwnerReference(t *testing.T) {
	vgs := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vgs",
			Namespace: "test-ns",
			UID:       types.UID("1234-uid"),
		},
	}

	tests := []struct {
		name     string
		ownerRef metav1.OwnerReference
		expect   bool
	}{
		{
			name: "match kind, apiversion, uid",
			ownerRef: metav1.OwnerReference{
				Kind:       kuberesource.VGSKind,
				APIVersion: volumegroupsnapshotv1beta2.GroupName + "/" + volumegroupsnapshotv1beta2.SchemeGroupVersion.Version,
				UID:        vgs.UID,
			},
			expect: true,
		},
		{
			name: "mismatch kind",
			ownerRef: metav1.OwnerReference{
				Kind:       "other-kind",
				APIVersion: volumegroupsnapshotv1beta2.GroupName + "/" + volumegroupsnapshotv1beta2.SchemeGroupVersion.Version,
				UID:        vgs.UID,
			},
			expect: false,
		},
		{
			name: "mismatch apiversion",
			ownerRef: metav1.OwnerReference{
				Kind:       kuberesource.VGSKind,
				APIVersion: "wrong.group/v1",
				UID:        vgs.UID,
			},
			expect: false,
		},
		{
			name: "mismatch uid",
			ownerRef: metav1.OwnerReference{
				Kind:       kuberesource.VGSKind,
				APIVersion: volumegroupsnapshotv1beta2.GroupName + "/" + volumegroupsnapshotv1beta2.SchemeGroupVersion.Version,
				UID:        "wrong-uid",
			},
			expect: false,
		},
		{
			name:     "no owner references",
			ownerRef: metav1.OwnerReference{},
			expect:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &metav1.ObjectMeta{
				Name:      "dummy",
				Namespace: "test-ns",
			}

			if tt.name != "no owner references" {
				obj.OwnerReferences = []metav1.OwnerReference{tt.ownerRef}
			}

			found := hasOwnerReference(obj, vgs)
			assert.Equal(t, tt.expect, found)
		})
	}
}

func TestPVCRequestSize(t *testing.T) {
	logger := logrus.New()

	tests := []struct {
		name         string
		pvcInitial   *corev1api.PersistentVolumeClaim // Use full PVC to allow for nil Requests
		restoreSize  string
		expectedSize string
	}{
		{
			name: "UpdateRequired: PVC request is lower than restore size",
			pvcInitial: func() *corev1api.PersistentVolumeClaim {
				pvc := builder.ForPersistentVolumeClaim("velero", "testPVC").Result()
				pvc.Spec.Resources.Requests = corev1api.ResourceList{
					corev1api.ResourceStorage: resource.MustParse("1Gi"),
				}
				return pvc
			}(),
			restoreSize:  "2Gi",
			expectedSize: "2Gi",
		},
		{
			name: "NoUpdateRequired: PVC request is larger than restore size",
			pvcInitial: func() *corev1api.PersistentVolumeClaim {
				pvc := builder.ForPersistentVolumeClaim("velero", "testPVC").Result()
				pvc.Spec.Resources.Requests = corev1api.ResourceList{
					corev1api.ResourceStorage: resource.MustParse("3Gi"),
				}
				return pvc
			}(),
			restoreSize:  "2Gi",
			expectedSize: "3Gi",
		},
		{
			name: "PVC has no initial storage request",
			pvcInitial: func() *corev1api.PersistentVolumeClaim {
				pvc := builder.ForPersistentVolumeClaim("velero", "testPVC").Result()
				pvc.Spec.Resources.Requests = corev1api.ResourceList{} // Empty request list
				return pvc
			}(),
			restoreSize:  "2Gi",
			expectedSize: "2Gi",
		},
		{
			name: "PVC has no initial Resources.Requests map",
			pvcInitial: func() *corev1api.PersistentVolumeClaim {
				pvc := builder.ForPersistentVolumeClaim("velero", "testPVC").Result()
				pvc.Spec.Resources.Requests = nil // This will trigger the line to be covered
				return pvc
			}(),
			restoreSize:  "2Gi",
			expectedSize: "2Gi",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a VolumeSnapshotContent with restore size
			rsQty := resource.MustParse(tc.restoreSize)

			vsc := &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testVSC",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					RestoreSize: ptr.To(rsQty.Value()),
				},
			}

			// Call the function under test
			pvc := tc.pvcInitial
			setPVCRequestSizeToVSRestoreSize(pvc, vsc, logger)

			// Verify that the PVC storage request is updated as expected.
			updatedSize := pvc.Spec.Resources.Requests[corev1api.ResourceStorage]
			expected := resource.MustParse(tc.expectedSize)
			// Corrected line below:
			require.Equal(t, 0, expected.Cmp(updatedSize), "Expected size %s, but got %s", expected.String(), updatedSize.String())
		})
	}
}

// TestGetOrCreateVolumeHelper tests the VolumeHelper and PVC-to-Pod cache behavior.
// Since plugin instances are unique per backup (created via newPluginManager and
// cleaned up via CleanupClients at backup completion), we verify that the pvcPodCache
// is properly initialized and reused across calls.
func TestGetOrCreateVolumeHelper(t *testing.T) {
	client := velerotest.NewFakeControllerRuntimeClient(t)
	action := &pvcBackupItemAction{
		log:      velerotest.NewLogger(),
		crClient: client,
	}
	backup := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backup",
			Namespace: "velero",
			UID:       types.UID("test-uid-1"),
		},
	}

	// Initially, pvcPodCache should be nil
	require.Nil(t, action.pvcPodCache, "pvcPodCache should be nil initially")

	// Get VolumeHelper first time - should create new cache and VolumeHelper
	vh1, err := action.getOrCreateVolumeHelper(backup)
	require.NoError(t, err)
	require.NotNil(t, vh1)

	// pvcPodCache should now be initialized
	require.NotNil(t, action.pvcPodCache, "pvcPodCache should be initialized after first call")
	cache1 := action.pvcPodCache

	// Get VolumeHelper second time - should reuse the same cache
	vh2, err := action.getOrCreateVolumeHelper(backup)
	require.NoError(t, err)
	require.NotNil(t, vh2)

	// The pvcPodCache should be the same instance
	require.Same(t, cache1, action.pvcPodCache, "Expected same pvcPodCache instance on repeated calls")
}
