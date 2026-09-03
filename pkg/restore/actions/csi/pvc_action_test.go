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
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotFake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/fake"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

func TestResetPVCSpec(t *testing.T) {
	fileMode := corev1api.PersistentVolumeFilesystem
	blockMode := corev1api.PersistentVolumeBlock

	testCases := []struct {
		name   string
		pvc    corev1api.PersistentVolumeClaim
		vsName string
	}{
		{
			name: "should reset expected fields in pvc using file mode volumes",
			pvc: corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadOnlyMany, corev1api.ReadWriteMany, corev1api.ReadWriteOnce},
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
							"baz": "qux",
						},
					},
					Resources: corev1api.VolumeResourceRequirements{
						Requests: corev1api.ResourceList{
							corev1api.ResourceCPU: resource.Quantity{
								Format: resource.DecimalExponent,
							},
						},
					},
					VolumeName: "should-be-removed",
					VolumeMode: &fileMode,
				},
			},
			vsName: "test-vs",
		},
		{
			name: "should reset expected fields in pvc using block mode volumes",
			pvc: corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadOnlyMany, corev1api.ReadWriteMany, corev1api.ReadWriteOnce},
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
							"baz": "qux",
						},
					},
					Resources: corev1api.VolumeResourceRequirements{
						Requests: corev1api.ResourceList{
							corev1api.ResourceCPU: resource.Quantity{
								Format: resource.DecimalExponent,
							},
						},
					},
					VolumeName: "should-be-removed",
					VolumeMode: &blockMode,
				},
			},
			vsName: "test-vs",
		},
		{
			name: "should overwrite existing DataSource per reset parameters",
			pvc: corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadOnlyMany, corev1api.ReadWriteMany, corev1api.ReadWriteOnce},
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"foo": "bar",
							"baz": "qux",
						},
					},
					Resources: corev1api.VolumeResourceRequirements{
						Requests: corev1api.ResourceList{
							corev1api.ResourceCPU: resource.Quantity{
								Format: resource.DecimalExponent,
							},
						},
					},
					VolumeName: "should-be-removed",
					VolumeMode: &fileMode,
					DataSource: &corev1api.TypedLocalObjectReference{
						Kind: "something-that-does-not-exist",
						Name: "not-found",
					},
					DataSourceRef: &corev1api.TypedObjectReference{
						Kind: "something-that-does-not-exist",
						Name: "not-found",
					},
				},
			},
			vsName: "test-vs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.pvc.DeepCopy()
			resetPVCSourceToVolumeSnapshot(&tc.pvc, tc.vsName)

			assert.Equalf(t, tc.pvc.Name, before.Name, "unexpected change to Object.Name, Want: %s; Got %s", before.Name, tc.pvc.Name)
			assert.Equalf(t, tc.pvc.Namespace, before.Namespace, "unexpected change to Object.Namespace, Want: %s; Got %s", before.Namespace, tc.pvc.Namespace)
			assert.Equalf(t, tc.pvc.Spec.AccessModes, before.Spec.AccessModes, "unexpected Spec.AccessModes, Want: %v; Got: %v", before.Spec.AccessModes, tc.pvc.Spec.AccessModes)
			assert.Equalf(t, tc.pvc.Spec.Selector, before.Spec.Selector, "unexpected change to Spec.Selector, Want: %s; Got: %s", before.Spec.Selector.String(), tc.pvc.Spec.Selector.String())
			assert.Equalf(t, tc.pvc.Spec.Resources, before.Spec.Resources, "unexpected change to Spec.Resources, Want: %s; Got: %s", before.Spec.Resources.String(), tc.pvc.Spec.Resources.String())
			assert.Emptyf(t, tc.pvc.Spec.VolumeName, "expected change to Spec.VolumeName missing, Want: \"\"; Got: %s", tc.pvc.Spec.VolumeName)
			assert.Equalf(t, *tc.pvc.Spec.VolumeMode, *before.Spec.VolumeMode, "expected change to Spec.VolumeName missing, Want: \"\"; Got: %s", tc.pvc.Spec.VolumeName)
			assert.NotNil(t, tc.pvc.Spec.DataSource, "expected change to Spec.DataSource missing")
			assert.Equalf(t, "VolumeSnapshot", tc.pvc.Spec.DataSource.Kind, "expected change to Spec.DataSource.Kind missing, Want: VolumeSnapshot, Got: %s", tc.pvc.Spec.DataSource.Kind)
			assert.Equalf(t, tc.pvc.Spec.DataSource.Name, tc.vsName, "expected change to Spec.DataSource.Name missing, Want: %s, Got: %s", tc.vsName, tc.pvc.Spec.DataSource.Name)
		})
	}
}

func TestProgress(t *testing.T) {
	currentTime := time.Now()
	tests := []struct {
		name             string
		restore          *velerov1api.Restore
		dataDownload     *velerov2alpha1.DataDownload
		operationID      string
		expectedErr      string
		expectedProgress velero.OperationProgress
	}{
		{
			name:        "DataDownload cannot be found",
			restore:     builder.ForRestore("velero", "test").Result(),
			operationID: "testing",
			expectedErr: "didn't find DataDownload",
		},
		{
			name:    "DataDownload is not in the expected namespace",
			restore: builder.ForRestore("velero", "test").Result(),
			dataDownload: &velerov2alpha1.DataDownload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataUpload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "invalid-namespace",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
			},
			operationID: "testing",
			expectedErr: "didn't find DataDownload",
		},
		{
			name:    "DataUpload is found",
			restore: builder.ForRestore("velero", "test").Result(),
			dataDownload: &velerov2alpha1.DataDownload{
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
				Status: velerov2alpha1.DataDownloadStatus{
					Phase: velerov2alpha1.DataDownloadPhaseFailed,
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
		t.Run(tc.name, func(*testing.T) {
			pvcRIA := pvcRestoreItemAction{
				log:      logrus.New(),
				crClient: velerotest.NewFakeControllerRuntimeClient(t),
			}
			if tc.dataDownload != nil {
				err := pvcRIA.crClient.Create(t.Context(), tc.dataDownload)
				require.NoError(t, err)
			}

			progress, err := pvcRIA.Progress(tc.operationID, tc.restore)
			if tc.expectedErr != "" {
				require.Equal(t, tc.expectedErr, err.Error())
				return
			}

			require.NoError(t, err)
			require.True(t, cmp.Equal(tc.expectedProgress, progress, cmpopts.IgnoreFields(velero.OperationProgress{}, "Started", "Updated")))
		})
	}
}

func TestCancel(t *testing.T) {
	tests := []struct {
		name                 string
		restore              *velerov1api.Restore
		dataDownload         *velerov2alpha1.DataDownload
		operationID          string
		expectedErr          string
		expectedDataDownload velerov2alpha1.DataDownload
	}{
		{
			name:    "Cancel DataUpload",
			restore: builder.ForRestore("velero", "test").Result(),
			dataDownload: &velerov2alpha1.DataDownload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataDownload",
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
			expectedErr: "",
			expectedDataDownload: velerov2alpha1.DataDownload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataDownload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
				Spec: velerov2alpha1.DataDownloadSpec{
					Cancel: true,
				},
			},
		},
		{
			name:         "Cannot find DataUpload",
			restore:      builder.ForRestore("velero", "test").Result(),
			dataDownload: nil,
			operationID:  "testing",
			expectedErr:  "didn't find DataDownload",
			expectedDataDownload: velerov2alpha1.DataDownload{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DataDownload",
					APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "testing",
					Labels: map[string]string{
						velerov1api.AsyncOperationIDLabel: "testing",
					},
				},
				Spec: velerov2alpha1.DataDownloadSpec{
					Cancel: true,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			pvcRIA := pvcRestoreItemAction{
				log:      logrus.New(),
				crClient: velerotest.NewFakeControllerRuntimeClient(t),
			}
			if tc.dataDownload != nil {
				err := pvcRIA.crClient.Create(t.Context(), tc.dataDownload)
				require.NoError(t, err)
			}

			err := pvcRIA.Cancel(tc.operationID, tc.restore)
			if tc.expectedErr != "" {
				require.Equal(t, tc.expectedErr, err.Error())
				return
			}
			require.NoError(t, err)

			resultDataDownload := new(velerov2alpha1.DataDownload)
			err = pvcRIA.crClient.Get(t.Context(), crclient.ObjectKey{Namespace: tc.dataDownload.Namespace, Name: tc.dataDownload.Name}, resultDataDownload)
			require.NoError(t, err)

			require.Empty(t, cmp.Diff(tc.expectedDataDownload, *resultDataDownload, cmpopts.IgnoreFields(velerov2alpha1.DataDownload{}, "TypeMeta", "ResourceVersion", "Name")))
		})
	}
}

func TestExecute(t *testing.T) {
	vsName := util.GenerateSha256FromRestoreUIDAndVsName("restoreUID", "vsName")
	tests := []struct {
		name                 string
		backup               *velerov1api.Backup
		restore              *velerov1api.Restore
		pvc                  *corev1api.PersistentVolumeClaim
		pv                   *corev1api.PersistentVolume
		pvcFromBackup        *corev1api.PersistentVolumeClaim
		vs                   *snapshotv1api.VolumeSnapshot
		dataUploadResult     *corev1api.ConfigMap
		expectedErr          string
		expectedDataDownload *velerov2alpha1.DataDownload
		expectedPVC          *corev1api.PersistentVolumeClaim
		preCreatePVC         bool
		kubeClientObj        []runtime.Object
		crObjects            []runtime.Object
		snapshotClientObj    []runtime.Object
	}{
		{
			name:        "Don't restore PV",
			backup:      builder.ForBackup("velero", "testBackup").Result(),
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").RestorePVs(false).Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName")).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName")).VolumeName("").Result(),
		},
		{
			name:        "restore's backup cannot be found",
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName")).Result(),
			expectedErr: "fail to get backup for restore: backups.velero.io \"testBackup\" not found",
		},
		{
			name:    "Restore from VolumeSnapshot",
			backup:  builder.ForBackup("velero", "testBackup").Result(),
			restore: builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("restoreUID")).Backup("testBackup").Result(),
			pvc: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName")).
				RequestResource(map[corev1api.ResourceName]resource.Quantity{corev1api.ResourceStorage: resource.MustParse("10Gi")}).
				DataSource(&corev1api.TypedLocalObjectReference{APIGroup: &snapshotv1api.SchemeGroupVersion.Group, Kind: "VolumeSnapshot", Name: "testVS"}).
				DataSourceRef(&corev1api.TypedObjectReference{APIGroup: &snapshotv1api.SchemeGroupVersion.Group, Kind: "VolumeSnapshot", Name: "testVS"}).
				Result(),
			vs: builder.ForVolumeSnapshot("velero", vsName).ObjectMeta(
				builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi"),
			).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(
				velerov1api.VolumeSnapshotLabel, "vsName",
				velerov1api.MustIncludeAdditionalItemRestoreAnnotation, "true",
			)).Result(),
		},
		{
			name:    "Restore from VolumeSnapshot with nil PVC annotations",
			backup:  builder.ForBackup("velero", "testBackup").Result(),
			restore: builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("restoreUID")).Backup("testBackup").Result(),
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testPVC",
					Namespace: "velero",
				},
			},
			pvcFromBackup: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName")).Result(),
			vs: builder.ForVolumeSnapshot("velero", vsName).ObjectMeta(
				builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi"),
			).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(
				velerov1api.MustIncludeAdditionalItemRestoreAnnotation, "true",
			)).Result(),
		},
		{
			name:    "Restore from VolumeSnapshot without volume-snapshot-name annotation",
			backup:  builder.ForBackup("velero", "testBackup").Result(),
			restore: builder.ForRestore("velero", "testRestore").Backup("testBackup").Result(),
			pvc:     builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", AnnSelectedNode, "node1")).Result(),
			vs:      builder.ForVolumeSnapshot("velero", "testVS").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi")).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(
				velerov1api.VolumeSnapshotLabel, "vsName",
				AnnSelectedNode, "node1",
				velerov1api.MustIncludeAdditionalItemRestoreAnnotation, "true",
			)).Result(),
		},
		{
			name:        "DataUploadResult cannot be found",
			backup:      builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").Result(),
			expectedErr: "fail get DataUploadResult for restore: testRestore: no DataUpload result cm found with labels velero.io/pvc-namespace-name=velero.testPVC,velero.io/restore-uid=,velero.io/resource-usage=DataUpload",
		},
		{
			name:             "Restore from DataUploadResult",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			expectedPVC:      builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", "velero.io/csi-volumesnapshot-restore-size", "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			expectedDataDownload: builder.ForDataDownload("velero", "name").TargetVolume(velerov2alpha1.TargetVolumeSpec{PVC: "testPVC", Namespace: "velero"}).
				ObjectMeta(builder.WithOwnerReference([]metav1.OwnerReference{{APIVersion: velerov1api.SchemeGroupVersion.String(), Kind: "Restore", Name: "testRestore", UID: "uid", Controller: boolptr.True()}}),
					builder.WithLabelsMap(map[string]string{velerov1api.AsyncOperationIDLabel: "dd-uid.", velerov1api.RestoreNameLabel: "testRestore", velerov1api.RestoreUIDLabel: "uid"}),
					builder.WithGenerateName("testRestore-")).Result(),
		},
		{
			name:             "Restore from DataUploadResult with long source PVC namespace and name",
			backup:           builder.ForBackup("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testRestore").Backup("testBackup").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "kibishii-data-kibishii-deployment-0").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			dataUploadResult: builder.ForConfigMap("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testCM").Data("uid", "{}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "migre209d0da-49c7-45ba-8d5a-3e59fd591ec1.kibishii-data-ki152333", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			expectedPVC:      builder.ForPersistentVolumeClaim("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "kibishii-data-kibishii-deployment-0").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", "velero.io/csi-volumesnapshot-restore-size", "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
		},
		{
			name:    "PVC had no DataUploadNameLabel annotation",
			backup:  builder.ForBackup("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testBackup").SnapshotMoveData(true).Result(),
			restore: builder.ForRestore("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testRestore").Backup("testBackup").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:     builder.ForPersistentVolumeClaim("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "kibishii-data-kibishii-deployment-0").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi")).Result(),
		},
		{
			name:         "Restore a PVC that already exists.",
			backup:       builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:      builder.ForRestore("velero", "testRestore").Backup("testBackup").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:          builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			preCreatePVC: true,
		},
		{
			name:         "Restore a PVC that already exists in the mapping namespace",
			backup:       builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:      builder.ForRestore("velero", "testRestore").Backup("testBackup").NamespaceMappings("velero", "restore").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:          builder.ForPersistentVolumeClaim("restore", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			preCreatePVC: true,
		},
		{
			name:             "PVC exists and in-place restore set",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").ExistingVolumeDataPolicy(string(velerov1api.VolumeDataPolicyTypeFull)).ItemOperationTimeout(time.Minute * 10).ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			pv:               builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			preCreatePVC:     true,
			kubeClientObj: []runtime.Object{
				builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			},
			expectedDataDownload: func() *velerov2alpha1.DataDownload {
				d := builder.ForDataDownload("velero", "name").TargetVolume(velerov2alpha1.TargetVolumeSpec{PVC: "testPVC", Namespace: "velero", PV: "testPV"}).
					ObjectMeta(builder.WithOwnerReference([]metav1.OwnerReference{{APIVersion: velerov1api.SchemeGroupVersion.String(), Kind: "Restore", Name: "testRestore", UID: "uid", Controller: boolptr.True()}}),
						builder.WithLabelsMap(map[string]string{velerov1api.AsyncOperationIDLabel: "dd-uid.", velerov1api.RestoreNameLabel: "testRestore", velerov1api.RestoreUIDLabel: "uid"}),
						builder.WithGenerateName("testRestore-")).Result()
				d.Spec.RestoreType = "full"
				return d
			}(),
		},
		{
			name:             "PVC exists and in-place incremental restore set, createVolumeSnapshot fails",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").ExistingVolumeDataPolicy(string(velerov1api.VolumeDataPolicyTypeIncremental)).ItemOperationTimeout(time.Minute * 10).ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			pv:               builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{\"DataMover\":\"velero-block\", \"SnapshotClass\":\"test-snapclass\"}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			preCreatePVC:     true,
			kubeClientObj: []runtime.Object{
				builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			},
			expectedDataDownload: func() *velerov2alpha1.DataDownload {
				d := builder.ForDataDownload("velero", "name").TargetVolume(velerov2alpha1.TargetVolumeSpec{PVC: "testPVC", Namespace: "velero", PV: "testPV"}).
					ObjectMeta(builder.WithOwnerReference([]metav1.OwnerReference{{APIVersion: velerov1api.SchemeGroupVersion.String(), Kind: "Restore", Name: "testRestore", UID: "uid", Controller: boolptr.True()}}),
						builder.WithLabelsMap(map[string]string{velerov1api.AsyncOperationIDLabel: "dd-uid.", velerov1api.RestoreNameLabel: "testRestore", velerov1api.RestoreUIDLabel: "uid"}),
						builder.WithGenerateName("testRestore-")).Result()
				d.Spec.RestoreType = "full"
				d.Spec.DataMover = "velero-block"
				return d
			}(),
		},
		{
			name:             "PVC exists and in-place incremental restore set with namespace mapping, existing PVC created from VolumeSnapshot",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").NamespaceMappings("velero", "restore").ExistingVolumeDataPolicy(string(velerov1api.VolumeDataPolicyTypeIncremental)).ItemOperationTimeout(time.Minute * 10).ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			pv:               builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{\"DataMover\":\"velero-block\", \"SnapshotClass\":\"test-snapclass\"}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			kubeClientObj: []runtime.Object{
				builder.ForPersistentVolumeClaim("restore", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).DataSource(&corev1api.TypedLocalObjectReference{APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group), Kind: "VolumeSnapshot", Name: "source-snap"}).Result(),
				builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			},
			crObjects: []runtime.Object{
				builder.ForPersistentVolumeClaim("restore", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).DataSource(&corev1api.TypedLocalObjectReference{APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group), Kind: "VolumeSnapshot", Name: "source-snap"}).Result(),
				builder.ForVolumeSnapshot("restore", "source-snap").Status().BoundVolumeSnapshotContentName("source-vsc").ReadyToUse(true).Result(),
				builder.ForVolumeSnapshotContent("source-vsc").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: ptr.To("handle-1")}).Result(),
			},
			snapshotClientObj: []runtime.Object{
				builder.ForVolumeSnapshot("restore", "source-snap").Status().ReadyToUse(true).Result(),
			},
			expectedDataDownload: func() *velerov2alpha1.DataDownload {
				d := builder.ForDataDownload("velero", "name").TargetVolume(velerov2alpha1.TargetVolumeSpec{PVC: "testPVC", Namespace: "restore", PV: "testPV"}).
					ObjectMeta(builder.WithOwnerReference([]metav1.OwnerReference{{APIVersion: velerov1api.SchemeGroupVersion.String(), Kind: "Restore", Name: "testRestore", UID: "uid", Controller: boolptr.True()}}),
						builder.WithLabelsMap(map[string]string{velerov1api.AsyncOperationIDLabel: "dd-uid.", velerov1api.RestoreNameLabel: "testRestore", velerov1api.RestoreUIDLabel: "uid"}),
						builder.WithGenerateName("testRestore-")).Result()
				d.Spec.RestoreType = "incremental"
				d.Spec.DataMover = "velero-block"
				d.Spec.CSISnapshot = &velerov2alpha1.CSISnapshotSpec{
					VolumeSnapshot:          "source-snap",
					VolumeSnapshotNamespace: "restore",
					CleanUp:                 false,
				}
				return d
			}(),
		},
		{
			name:             "PVC exists and in-place incremental restore set with namespace mapping, existing PVC not created from VolumeSnapshot",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").NamespaceMappings("velero", "restore").ExistingVolumeDataPolicy(string(velerov1api.VolumeDataPolicyTypeIncremental)).ItemOperationTimeout(time.Minute * 10).ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			pv:               builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{\"DataMover\":\"velero-block\", \"SnapshotClass\":\"test-snapclass\"}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			kubeClientObj: []runtime.Object{
				builder.ForPersistentVolumeClaim("restore", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
				builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			},
			crObjects: []runtime.Object{
				builder.ForPersistentVolumeClaim("restore", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			},
			expectedErr: "ExistingVolumeDataPolicy is in-place incremental restore, data mover is velero-block and namespace-mapping is set, but the existing PVC restore/testPVC is not created from a VolumeSnapshot, fail the restore",
		},
		{
			name:             "PVC exists and in-place incremental restore set with namespace mapping, VolumeSnapshot get fails",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").NamespaceMappings("velero", "restore").ExistingVolumeDataPolicy(string(velerov1api.VolumeDataPolicyTypeIncremental)).ItemOperationTimeout(time.Minute * 10).ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			pv:               builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{\"DataMover\":\"velero-block\", \"SnapshotClass\":\"test-snapclass\"}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			kubeClientObj: []runtime.Object{
				builder.ForPersistentVolumeClaim("restore", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).DataSource(&corev1api.TypedLocalObjectReference{APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group), Kind: "VolumeSnapshot", Name: "missing-vs"}).Result(),
				builder.ForPersistentVolume("testPV").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
			},
			crObjects: []runtime.Object{
				builder.ForPersistentVolumeClaim("restore", "testPVC").VolumeName("testPV").Phase(corev1api.ClaimBound).ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName", velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).DataSource(&corev1api.TypedLocalObjectReference{APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group), Kind: "VolumeSnapshot", Name: "missing-vs"}).Result(),
			},
			expectedErr: "fail to get VolumeSnapshot restore/missing-vs: volumesnapshots.snapshot.storage.k8s.io \"missing-vs\" not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			object := make([]runtime.Object, 0)
			if tc.backup != nil {
				object = append(object, tc.backup)
			}

			if tc.vs != nil {
				object = append(object, tc.vs)
			}

			if tc.pv != nil {
				object = append(object, tc.pv)
			}

			input := new(velero.RestoreItemActionExecuteInput)

			if tc.pvc != nil {
				pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvc)
				require.NoError(t, err)

				input.Item = &unstructured.Unstructured{Object: pvcMap}
				if tc.pvcFromBackup != nil {
					pvcFromBackupMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvcFromBackup)
					require.NoError(t, err)
					input.ItemFromBackup = &unstructured.Unstructured{Object: pvcFromBackupMap}
				} else {
					input.ItemFromBackup = &unstructured.Unstructured{Object: pvcMap}
				}
				input.Restore = tc.restore
			}
			if tc.preCreatePVC {
				object = append(object, tc.pvc)
			}

			if tc.dataUploadResult != nil {
				object = append(object, tc.dataUploadResult)
			}
			object = append(object, tc.crObjects...)

			pvcRIA := pvcRestoreItemAction{
				log:               logrus.New(),
				crClient:          velerotest.NewFakeControllerRuntimeClient(t, object...),
				kubeClient:        fake.NewSimpleClientset(tc.kubeClientObj...),
				csiSnapshotClient: snapshotFake.NewSimpleClientset(tc.snapshotClientObj...).SnapshotV1(),
			}

			output, err := pvcRIA.Execute(input)
			if tc.expectedErr != "" {
				require.Equal(t, tc.expectedErr, err.Error())
				return
			}
			require.NoError(t, err)

			if tc.expectedPVC != nil {
				pvc := new(corev1api.PersistentVolumeClaim)
				err := runtime.DefaultUnstructuredConverter.FromUnstructured(output.UpdatedItem.UnstructuredContent(), pvc)
				require.NoError(t, err)
				require.Equal(t, tc.expectedPVC.GetObjectMeta(), pvc.GetObjectMeta())
				if tc.name == "Restore from VolumeSnapshot" {
					require.Equal(t, "true", pvc.GetAnnotations()[velerov1api.MustIncludeAdditionalItemRestoreAnnotation])
					require.Len(t, output.AdditionalItems, 1)
					require.Equal(t, "volumesnapshots.snapshot.storage.k8s.io", output.AdditionalItems[0].GroupResource.String())
					require.Equal(t, "vsName", output.AdditionalItems[0].Name)
				}
				if pvc.Spec.Selector != nil && pvc.Spec.Selector.MatchLabels != nil {
					// This is used for long name and namespace case.
					if len(tc.pvc.Namespace+"."+tc.pvc.Name) >= validation.DNS1035LabelMaxLength {
						require.Contains(t, pvc.Spec.Selector.MatchLabels[velerov1api.DynamicPVRestoreLabel], label.GetValidName(tc.pvc.Namespace + "." + tc.pvc.Name)[:56])
					} else {
						require.Contains(t, pvc.Spec.Selector.MatchLabels[velerov1api.DynamicPVRestoreLabel], tc.pvc.Namespace+"."+tc.pvc.Name)
					}
				}
			}
			if tc.expectedDataDownload != nil {
				dataDownloadList := new(velerov2alpha1.DataDownloadList)
				err := pvcRIA.crClient.List(t.Context(), dataDownloadList, &crclient.ListOptions{
					LabelSelector: labels.SelectorFromSet(tc.expectedDataDownload.Labels),
				})
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.expectedDataDownload, &dataDownloadList.Items[0], cmpopts.IgnoreFields(velerov2alpha1.DataDownload{}, "TypeMeta", "ResourceVersion", "Name")))
			}
		})
	}
}

// TestPrepareForInplaceRestoreSelectedNode verifies that prepareForInplaceRestore captures
// the selected-node annotation from the existing PVC into the Velero-internal carrier
// annotation (not the Kubernetes annotation) on the target PVC, before deleting the PVC.
func TestPrepareForInplaceRestoreSelectedNode(t *testing.T) {
	tests := []struct {
		name              string
		existingPVC       *corev1api.PersistentVolumeClaim
		expectedCarrier   string
		expectCarrierSet  bool
		expectKubeAnnoSet bool
	}{
		{
			name: "existing PVC with selected-node sets carrier annotation only",
			existingPVC: builder.ForPersistentVolumeClaim("ns-1", "pvc-1").
				ObjectMeta(builder.WithAnnotations(AnnSelectedNode, "node-1")).
				VolumeName("pv-1").
				Phase(corev1api.ClaimBound).Result(),
			expectedCarrier:   "node-1",
			expectCarrierSet:  true,
			expectKubeAnnoSet: false,
		},
		{
			name: "existing PVC without selected-node sets neither annotation",
			existingPVC: builder.ForPersistentVolumeClaim("ns-1", "pvc-1").
				VolumeName("pv-1").
				Phase(corev1api.ClaimBound).Result(),
			expectCarrierSet:  false,
			expectKubeAnnoSet: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pv := builder.ForPersistentVolume("pv-1").Result()
			kubeClient := fake.NewSimpleClientset(tc.existingPVC, pv)
			pvcRIA := pvcRestoreItemAction{
				log:        logrus.New(),
				crClient:   velerotest.NewFakeControllerRuntimeClient(t, pv),
				kubeClient: kubeClient,
			}

			targetPVC := builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result()
			returnedPV, err := pvcRIA.deleteExistingPVC(
				t.Context(), logrus.New().WithField("test", tc.name),
				targetPVC, tc.existingPVC, time.Minute)
			require.NoError(t, err)
			require.Equal(t, "pv-1", returnedPV.Name)

			carrier, carrierOK := targetPVC.Annotations[velerov1api.InplaceRestoreSelectedNodeAnnotation]
			require.Equal(t, tc.expectCarrierSet, carrierOK)
			if tc.expectCarrierSet {
				require.Equal(t, tc.expectedCarrier, carrier)
			}
			_, kubeAnnoOK := targetPVC.Annotations[AnnSelectedNode]
			require.Equal(t, tc.expectKubeAnnoSet, kubeAnnoOK)
		})
	}
}

// TestExecuteInplaceRestore exercises the public Execute() entry for an in-place restore
// with an existing PVC: the carrier annotation must be emitted on the returned item, the
// Kubernetes selected-node annotation must not be set by this RIA, the existing PVC must be
// deleted, and a DataDownload with the in-place restoreType must be created.
func TestExecuteInplaceRestore(t *testing.T) {
	existingPVC := builder.ForPersistentVolumeClaim("velero", "testPVC").
		ObjectMeta(builder.WithAnnotations(AnnSelectedNode, "node-1")).
		VolumeName("testPV").
		Phase(corev1api.ClaimBound).Result()
	existingPV := builder.ForPersistentVolume("testPV").Result()
	backup := builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result()
	restore := builder.ForRestore("velero", "testRestore").Backup("testBackup").
		ObjectMeta(builder.WithUID("uid")).ExistingVolumeDataPolicy("full").Result()
	pvcFromBackup := builder.ForPersistentVolumeClaim("velero", "testPVC").
		ObjectMeta(builder.WithAnnotations(
			velerov1api.VolumeSnapshotLabel, "vsName",
			velerov1api.DataUploadNameAnnotation, "velero/testDU",
		)).Result()
	dataUploadResult := builder.ForConfigMap("velero", "testCM").Data("uid", "{}").
		ObjectMeta(builder.WithLabels(
			velerov1api.RestoreUIDLabel, "uid",
			velerov1api.PVCNamespaceNameLabel, "velero.testPVC",
			velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)),
		)).Result()

	pvcRIA := pvcRestoreItemAction{
		log:        logrus.New(),
		crClient:   velerotest.NewFakeControllerRuntimeClient(t, existingPVC, existingPV, backup, dataUploadResult),
		kubeClient: fake.NewSimpleClientset(existingPVC, existingPV),
	}

	pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvcFromBackup.DeepCopy())
	require.NoError(t, err)
	pvcFromBackupMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvcFromBackup)
	require.NoError(t, err)

	output, err := pvcRIA.Execute(&velero.RestoreItemActionExecuteInput{
		Item:           &unstructured.Unstructured{Object: pvcMap},
		ItemFromBackup: &unstructured.Unstructured{Object: pvcFromBackupMap},
		Restore:        restore,
	})
	require.NoError(t, err)

	updatedPVC := new(corev1api.PersistentVolumeClaim)
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(
		output.UpdatedItem.UnstructuredContent(), updatedPVC))

	// Carrier annotation carries the captured value; the Kubernetes annotation is not set by this RIA.
	require.Equal(t, "node-1", updatedPVC.Annotations[velerov1api.InplaceRestoreSelectedNodeAnnotation])
	require.NotContains(t, updatedPVC.Annotations, AnnSelectedNode)

	// The existing PVC is deleted so the exposer can bind a temporary PVC to the PV.
	_, err = pvcRIA.kubeClient.CoreV1().PersistentVolumeClaims("velero").Get(t.Context(), "testPVC", metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))

	// A DataDownload with the in-place restoreType referencing the existing PV is created.
	dataDownloadList := new(velerov2alpha1.DataDownloadList)
	require.NoError(t, pvcRIA.crClient.List(t.Context(), dataDownloadList, &crclient.ListOptions{}))
	require.Len(t, dataDownloadList.Items, 1)
	require.Equal(t, "full", dataDownloadList.Items[0].Spec.RestoreType)
	require.Equal(t, "testPV", dataDownloadList.Items[0].Spec.TargetVolume.PV)
}

// TestExecuteInplaceRestorePreflight verifies the RIA fails the item without
// side effects when the pre-flight check fails. The in-use semantics are
// covered by the pkg/restore/inplace unit tests.
func TestExecuteInplaceRestorePreflight(t *testing.T) {
	newPodUsingPVC := func(phase corev1api.PodPhase) *corev1api.Pod {
		pod := builder.ForPod("velero", "consumer-pod").
			Volumes(builder.ForVolume("data").PersistentVolumeClaimSource("testPVC").Result()).
			Result()
		pod.Status.Phase = phase
		return pod
	}

	tests := []struct {
		name        string
		pod         *corev1api.Pod
		expectBlock bool
	}{
		{
			name: "no pod, restore proceeds",
		},
		{
			name:        "active pod blocks the restore",
			pod:         newPodUsingPVC(corev1api.PodRunning),
			expectBlock: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			existingPVC := builder.ForPersistentVolumeClaim("velero", "testPVC").
				VolumeName("testPV").
				Phase(corev1api.ClaimBound).Result()
			existingPV := builder.ForPersistentVolume("testPV").Result()
			backup := builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result()
			restore := builder.ForRestore("velero", "testRestore").Backup("testBackup").
				ObjectMeta(builder.WithUID("uid")).ExistingVolumeDataPolicy("full").Result()
			pvcFromBackup := builder.ForPersistentVolumeClaim("velero", "testPVC").
				ObjectMeta(builder.WithAnnotations(
					velerov1api.VolumeSnapshotLabel, "vsName",
					velerov1api.DataUploadNameAnnotation, "velero/testDU",
				)).Result()
			dataUploadResult := builder.ForConfigMap("velero", "testCM").Data("uid", "{}").
				ObjectMeta(builder.WithLabels(
					velerov1api.RestoreUIDLabel, "uid",
					velerov1api.PVCNamespaceNameLabel, "velero.testPVC",
					velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)),
				)).Result()

			crObjects := []runtime.Object{existingPVC, existingPV, backup, dataUploadResult}
			kubeObjects := []runtime.Object{existingPVC, existingPV}
			if tc.pod != nil {
				crObjects = append(crObjects, tc.pod)
				kubeObjects = append(kubeObjects, tc.pod)
			}

			pvcRIA := pvcRestoreItemAction{
				log:        logrus.New(),
				crClient:   velerotest.NewFakeControllerRuntimeClient(t, crObjects...),
				kubeClient: fake.NewSimpleClientset(kubeObjects...),
			}

			pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvcFromBackup.DeepCopy())
			require.NoError(t, err)
			pvcFromBackupMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvcFromBackup)
			require.NoError(t, err)

			_, err = pvcRIA.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: pvcMap},
				ItemFromBackup: &unstructured.Unstructured{Object: pvcFromBackupMap},
				Restore:        restore,
			})

			gotPVC, getErr := pvcRIA.kubeClient.CoreV1().PersistentVolumeClaims("velero").Get(t.Context(), "testPVC", metav1.GetOptions{})
			dataDownloadList := new(velerov2alpha1.DataDownloadList)
			require.NoError(t, pvcRIA.crClient.List(t.Context(), dataDownloadList, &crclient.ListOptions{}))

			if tc.expectBlock {
				require.Error(t, err)
				require.Contains(t, err.Error(), "pre-flight check failed")
				require.Contains(t, err.Error(), "consumer-pod")
				// No side effects: PVC untouched with the original volumeName,
				// PV reclaim policy not patched, no DataDownload created.
				require.NoError(t, getErr)
				require.Equal(t, "testPV", gotPVC.Spec.VolumeName)
				gotPV, pvErr := pvcRIA.kubeClient.CoreV1().PersistentVolumes().Get(t.Context(), "testPV", metav1.GetOptions{})
				require.NoError(t, pvErr)
				require.Equal(t, existingPV.Spec.PersistentVolumeReclaimPolicy, gotPV.Spec.PersistentVolumeReclaimPolicy)
				require.Empty(t, dataDownloadList.Items)
			} else {
				require.NoError(t, err)
				// The in-place restore proceeded: the existing PVC is deleted
				// and a DataDownload is created.
				require.True(t, apierrors.IsNotFound(getErr))
				require.Len(t, dataDownloadList.Items, 1)
			}
		})
	}
}
func TestExecuteInplaceIncrementalRestoreWithNamespaceMapping(t *testing.T) {
	existingPVC := builder.ForPersistentVolumeClaim("restore-ns", "testPVC").
		ObjectMeta(builder.WithAnnotations(AnnSelectedNode, "node-1")).
		VolumeName("testPV").
		Phase(corev1api.ClaimBound).
		DataSource(&corev1api.TypedLocalObjectReference{
			APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
			Kind:     "VolumeSnapshot",
			Name:     "existing-snap",
		}).Result()
	existingPV := builder.ForPersistentVolume("testPV").Result()
	existingVS := builder.ForVolumeSnapshot("restore-ns", "existing-snap").
		Status().BoundVolumeSnapshotContentName("existing-vsc").ReadyToUse(true).Result()
	existingVSC := builder.ForVolumeSnapshotContent("existing-vsc").
		Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: ptr.To("snap-handle-1")}).Result()

	backup := builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result()
	restore := builder.ForRestore("velero", "testRestore").Backup("testBackup").
		NamespaceMappings("velero", "restore-ns").
		ExistingVolumeDataPolicy("incremental").
		ObjectMeta(builder.WithUID("uid")).Result()
	pvcFromBackup := builder.ForPersistentVolumeClaim("velero", "testPVC").
		ObjectMeta(builder.WithAnnotations(
			velerov1api.VolumeSnapshotLabel, "vsName",
			velerov1api.DataUploadNameAnnotation, "velero/testDU",
		)).Result()
	dataUploadResult := builder.ForConfigMap("velero", "testCM").
		Data("uid", "{\"DataMover\":\"velero-block\", \"SnapshotClass\":\"test-snapclass\"}").
		ObjectMeta(builder.WithLabels(
			velerov1api.RestoreUIDLabel, "uid",
			velerov1api.PVCNamespaceNameLabel, "velero.testPVC",
			velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)),
		)).Result()

	pvcRIA := pvcRestoreItemAction{
		log:               logrus.New(),
		crClient:          velerotest.NewFakeControllerRuntimeClient(t, existingPVC, existingPV, existingVS, existingVSC, backup, dataUploadResult),
		kubeClient:        fake.NewSimpleClientset(existingPVC, existingPV),
		csiSnapshotClient: snapshotFake.NewSimpleClientset(existingVS).SnapshotV1(),
	}

	pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvcFromBackup.DeepCopy())
	require.NoError(t, err)
	pvcFromBackupMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvcFromBackup)
	require.NoError(t, err)

	output, err := pvcRIA.Execute(&velero.RestoreItemActionExecuteInput{
		Item:           &unstructured.Unstructured{Object: pvcMap},
		ItemFromBackup: &unstructured.Unstructured{Object: pvcFromBackupMap},
		Restore:        restore,
	})
	require.NoError(t, err)

	updatedPVC := new(corev1api.PersistentVolumeClaim)
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(
		output.UpdatedItem.UnstructuredContent(), updatedPVC))

	// Carrier annotation carries the captured value; the Kubernetes annotation is not set by this RIA.
	require.Equal(t, "node-1", updatedPVC.Annotations[velerov1api.InplaceRestoreSelectedNodeAnnotation])
	require.NotContains(t, updatedPVC.Annotations, AnnSelectedNode)

	// The existing PVC in the mapped namespace is deleted so the exposer can bind a temporary PVC to the PV.
	_, err = pvcRIA.kubeClient.CoreV1().PersistentVolumeClaims("restore-ns").Get(t.Context(), "testPVC", metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))

	// A DataDownload with the incremental restoreType, velero-block data mover, and cleanUp=false is created.
	dataDownloadList := new(velerov2alpha1.DataDownloadList)
	require.NoError(t, pvcRIA.crClient.List(t.Context(), dataDownloadList, &crclient.ListOptions{}))
	require.Len(t, dataDownloadList.Items, 1)
	require.Equal(t, "incremental", dataDownloadList.Items[0].Spec.RestoreType)
	require.Equal(t, "velero-block", dataDownloadList.Items[0].Spec.DataMover)
	require.Equal(t, "testPV", dataDownloadList.Items[0].Spec.TargetVolume.PV)
	require.Equal(t, "restore-ns", dataDownloadList.Items[0].Spec.TargetVolume.Namespace)
	require.NotNil(t, dataDownloadList.Items[0].Spec.CSISnapshot)
	require.Equal(t, "existing-snap", dataDownloadList.Items[0].Spec.CSISnapshot.VolumeSnapshot)
	require.Equal(t, "restore-ns", dataDownloadList.Items[0].Spec.CSISnapshot.VolumeSnapshotNamespace)
	require.False(t, dataDownloadList.Items[0].Spec.CSISnapshot.CleanUp)
}

func TestNewDataDownload(t *testing.T) {
	restore := builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("uid")).Result()
	backup := builder.ForBackup("velero", "testBackup").CSISnapshotTimeout(10 * time.Minute).Result()
	dataUploadResult := &velerov2alpha1.DataUploadResult{
		BackupStorageLocation: "bsl",
		DataMover:             "velero-block",
		SnapshotID:            "snap-id",
		SnapshotSize:          1024,
		SourceNamespace:       "source-ns",
		NodeOS:                "linux",
		FSType:                "ext4",
	}
	pvc := builder.ForPersistentVolumeClaim("velero", "testPVC").Result()
	pv := builder.ForPersistentVolume("testPV").Result()
	vs := builder.ForVolumeSnapshot("velero", "testVS").Result()

	t.Run("volumeSnapshot is nil", func(t *testing.T) {
		dd := newDataDownload(restore, backup, dataUploadResult, pvc, pv, "restore-ns", "op-id", "full", nil, false)
		require.NotNil(t, dd)
		assert.Equal(t, "restore-ns", dd.Spec.TargetVolume.Namespace)
		assert.Equal(t, "testPVC", dd.Spec.TargetVolume.PVC)
		assert.Equal(t, "testPV", dd.Spec.TargetVolume.PV)
		assert.Equal(t, "full", dd.Spec.RestoreType)
		assert.Nil(t, dd.Spec.CSISnapshot)
	})

	t.Run("volumeSnapshot with cleanUp false", func(t *testing.T) {
		dd := newDataDownload(restore, backup, dataUploadResult, pvc, pv, "restore-ns", "op-id", "incremental", vs, false)
		require.NotNil(t, dd)
		assert.Equal(t, "incremental", dd.Spec.RestoreType)
		require.NotNil(t, dd.Spec.CSISnapshot)
		assert.Equal(t, "testVS", dd.Spec.CSISnapshot.VolumeSnapshot)
		assert.Equal(t, "velero", dd.Spec.CSISnapshot.VolumeSnapshotNamespace)
		assert.False(t, dd.Spec.CSISnapshot.CleanUp)
	})

	t.Run("volumeSnapshot with cleanUp true", func(t *testing.T) {
		dd := newDataDownload(restore, backup, dataUploadResult, pvc, pv, "restore-ns", "op-id", "incremental", vs, true)
		require.NotNil(t, dd)
		assert.Equal(t, "incremental", dd.Spec.RestoreType)
		require.NotNil(t, dd.Spec.CSISnapshot)
		assert.Equal(t, "testVS", dd.Spec.CSISnapshot.VolumeSnapshot)
		assert.Equal(t, "velero", dd.Spec.CSISnapshot.VolumeSnapshotNamespace)
		assert.True(t, dd.Spec.CSISnapshot.CleanUp)
	})

	t.Run("pv is nil", func(t *testing.T) {
		dd := newDataDownload(restore, backup, dataUploadResult, pvc, nil, "restore-ns", "op-id", "full", nil, false)
		require.NotNil(t, dd)
		assert.Empty(t, dd.Spec.TargetVolume.PV)
	})
}

func TestPVCAppliesTo(t *testing.T) {
	p := pvcRestoreItemAction{
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

func TestNewPvcRestoreItemAction(t *testing.T) {
	logger := logrus.StandardLogger()
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewPvcRestoreItemAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	f1 := &factorymocks.Factory{}
	f1.On("KubebuilderClient").Return(crClient, nil)
	f1.On("KubeClient").Return(nil, nil)
	f1.On("ClientConfig").Return(&rest.Config{}, nil)
	plugin1 := NewPvcRestoreItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}

func TestIsCreatedFromSnapshot(t *testing.T) {
	wrongGroup := "other.group.io"
	crossNS := "cross-ns"

	tests := []struct {
		name              string
		pvc               *corev1api.PersistentVolumeClaim
		crObjects         []runtime.Object
		snapshotObjects   []runtime.Object
		timeout           time.Duration
		expectedFound     bool
		expectedVSName    string
		expectedVSNS      string
		expectedErrSubstr string
	}{
		{
			name: "dataSource and dataSourceRef are nil",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSource is not VolumeSnapshot Kind",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:     "PersistentVolumeClaim",
						Name:     "source-pvc",
					},
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSource has nil APIGroup",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: nil,
						Kind:     "VolumeSnapshot",
						Name:     "source-vs",
					},
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSource has wrong APIGroup",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: &wrongGroup,
						Kind:     "VolumeSnapshot",
						Name:     "source-vs",
					},
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSourceRef is not VolumeSnapshot Kind",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSourceRef: &corev1api.TypedObjectReference{
						APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:     "PersistentVolumeClaim",
						Name:     "source-pvc",
					},
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSourceRef has nil APIGroup",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSourceRef: &corev1api.TypedObjectReference{
						APIGroup: nil,
						Kind:     "VolumeSnapshot",
						Name:     "source-vs",
					},
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSourceRef has wrong APIGroup",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSourceRef: &corev1api.TypedObjectReference{
						APIGroup: &wrongGroup,
						Kind:     "VolumeSnapshot",
						Name:     "source-vs",
					},
				},
			},
			expectedFound: false,
		},
		{
			name: "dataSource VolumeSnapshot not found in crClient",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:     "VolumeSnapshot",
						Name:     "missing-vs",
					},
				},
			},
			expectedFound:     false,
			expectedErrSubstr: "fail to get VolumeSnapshot test-ns/missing-vs",
		},
		{
			name: "dataSource VolumeSnapshot exists but VSC handle not ready",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:     "VolumeSnapshot",
						Name:     "unready-vsc-vs",
					},
				},
			},
			crObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "unready-vsc-vs").Result(),
			},
			timeout:           0,
			expectedFound:     false,
			expectedErrSubstr: "failed to wait for VolumeSnapshotContent of VolumeSnapshot test-ns/unready-vsc-vs",
		},
		{
			name: "dataSource VolumeSnapshot VSC handle ready but snapshot not ready in csiSnapshotClient",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:     "VolumeSnapshot",
						Name:     "ready-vsc-vs",
					},
				},
			},
			crObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "ready-vsc-vs").Status().BoundVolumeSnapshotContentName("ready-vsc").ReadyToUse(true).Result(),
				builder.ForVolumeSnapshotContent("ready-vsc").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: ptr.To("handle-1")}).Result(),
			},
			snapshotObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "ready-vsc-vs").Status().ReadyToUse(false).Result(),
			},
			timeout:           0,
			expectedFound:     false,
			expectedErrSubstr: "failed to wait for VolumeSnapshot test-ns/ready-vsc-vs to become Ready",
		},
		{
			name: "dataSource VolumeSnapshot is fully ready (same namespace)",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSource: &corev1api.TypedLocalObjectReference{
						APIGroup: ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:     "VolumeSnapshot",
						Name:     "ready-vs",
					},
				},
			},
			crObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "ready-vs").Status().BoundVolumeSnapshotContentName("ready-vsc").ReadyToUse(true).Result(),
				builder.ForVolumeSnapshotContent("ready-vsc").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: ptr.To("handle-1")}).Result(),
			},
			snapshotObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "ready-vs").Status().ReadyToUse(true).Result(),
			},
			timeout:        0,
			expectedFound:  true,
			expectedVSName: "ready-vs",
			expectedVSNS:   "test-ns",
		},
		{
			name: "dataSourceRef VolumeSnapshot is fully ready (cross namespace)",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSourceRef: &corev1api.TypedObjectReference{
						APIGroup:  ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:      "VolumeSnapshot",
						Name:      "cross-vs",
						Namespace: &crossNS,
					},
				},
			},
			crObjects: []runtime.Object{
				builder.ForVolumeSnapshot("cross-ns", "cross-vs").Status().BoundVolumeSnapshotContentName("cross-vsc").ReadyToUse(true).Result(),
				builder.ForVolumeSnapshotContent("cross-vsc").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: ptr.To("handle-2")}).Result(),
			},
			snapshotObjects: []runtime.Object{
				builder.ForVolumeSnapshot("cross-ns", "cross-vs").Status().ReadyToUse(true).Result(),
			},
			timeout:        0,
			expectedFound:  true,
			expectedVSName: "cross-vs",
			expectedVSNS:   "cross-ns",
		},
		{
			name: "dataSourceRef VolumeSnapshot is fully ready (nil namespace falls back to pvc namespace)",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pvc",
					Namespace: "test-ns",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					DataSourceRef: &corev1api.TypedObjectReference{
						APIGroup:  ptr.To(snapshotv1api.SchemeGroupVersion.Group),
						Kind:      "VolumeSnapshot",
						Name:      "same-ns-vs",
						Namespace: nil,
					},
				},
			},
			crObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "same-ns-vs").Status().BoundVolumeSnapshotContentName("same-ns-vsc").ReadyToUse(true).Result(),
				builder.ForVolumeSnapshotContent("same-ns-vsc").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: ptr.To("handle-3")}).Result(),
			},
			snapshotObjects: []runtime.Object{
				builder.ForVolumeSnapshot("test-ns", "same-ns-vs").Status().ReadyToUse(true).Result(),
			},
			timeout:        0,
			expectedFound:  true,
			expectedVSName: "same-ns-vs",
			expectedVSNS:   "test-ns",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			p := &pvcRestoreItemAction{
				log:               logger,
				crClient:          velerotest.NewFakeControllerRuntimeClient(t, tc.crObjects...),
				csiSnapshotClient: snapshotFake.NewSimpleClientset(tc.snapshotObjects...).SnapshotV1(),
			}

			entry := logrus.NewEntry(logger)
			vs, ok, err := p.isCreatedFromSnapshot(t.Context(), entry, tc.pvc, tc.timeout)

			if tc.expectedErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrSubstr)
				assert.False(t, ok)
				assert.Nil(t, vs)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectedFound, ok)
			if tc.expectedFound {
				require.NotNil(t, vs)
				assert.Equal(t, tc.expectedVSName, vs.Name)
				assert.Equal(t, tc.expectedVSNS, vs.Namespace)
			} else {
				assert.Nil(t, vs)
			}
		})
	}
}
