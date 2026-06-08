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
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
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
		vs                   *snapshotv1api.VolumeSnapshot
		dataUploadResult     *corev1api.ConfigMap
		expectedErr          string
		expectedDataDownload *velerov2alpha1.DataDownload
		expectedPVC          *corev1api.PersistentVolumeClaim
		preCreatePVC         bool
	}{
		{
			name:        "Don't restore PV",
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").RestorePVs(false).Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").VolumeName("").Result(),
		},
		{
			name:        "restore's backup cannot be found",
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").Result(),
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
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotLabel, "vsName")).Result(),
		},
		{
			name:        "Restore from VolumeSnapshot without volume-snapshot-name annotation",
			backup:      builder.ForBackup("velero", "testBackup").Result(),
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(AnnSelectedNode, "node1")).Result(),
			vs:          builder.ForVolumeSnapshot("velero", "testVS").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi")).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(AnnSelectedNode, "node1")).Result(),
		},
		{
			name:        "DataUploadResult cannot be found",
			backup:      builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:     builder.ForRestore("velero", "testRestore").Backup("testBackup").Result(),
			pvc:         builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			expectedPVC: builder.ForPersistentVolumeClaim("velero", "testPVC").Result(),
			expectedErr: "fail get DataUploadResult for restore: testRestore: no DataUpload result cm found with labels velero.io/pvc-namespace-name=velero.testPVC,velero.io/restore-uid=,velero.io/resource-usage=DataUpload",
		},
		{
			name:             "Restore from DataUploadResult",
			backup:           builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("velero", "testRestore").Backup("testBackup").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			dataUploadResult: builder.ForConfigMap("velero", "testCM").Data("uid", "{}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "velero.testPVC", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			expectedPVC:      builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations("velero.io/csi-volumesnapshot-restore-size", "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			expectedDataDownload: builder.ForDataDownload("velero", "name").TargetVolume(velerov2alpha1.TargetVolumeSpec{PVC: "testPVC", Namespace: "velero"}).
				ObjectMeta(builder.WithOwnerReference([]metav1.OwnerReference{{APIVersion: velerov1api.SchemeGroupVersion.String(), Kind: "Restore", Name: "testRestore", UID: "uid", Controller: boolptr.True()}}),
					builder.WithLabelsMap(map[string]string{velerov1api.AsyncOperationIDLabel: "dd-uid.", velerov1api.RestoreNameLabel: "testRestore", velerov1api.RestoreUIDLabel: "uid"}),
					builder.WithGenerateName("testRestore-")).Result(),
		},
		{
			name:             "Restore from DataUploadResult with long source PVC namespace and name",
			backup:           builder.ForBackup("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testBackup").SnapshotMoveData(true).Result(),
			restore:          builder.ForRestore("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testRestore").Backup("testBackup").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:              builder.ForPersistentVolumeClaim("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "kibishii-data-kibishii-deployment-0").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			dataUploadResult: builder.ForConfigMap("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "testCM").Data("uid", "{}").ObjectMeta(builder.WithLabels(velerov1api.RestoreUIDLabel, "uid", velerov1api.PVCNamespaceNameLabel, "migre209d0da-49c7-45ba-8d5a-3e59fd591ec1.kibishii-data-ki152333", velerov1api.ResourceUsageLabel, label.GetValidName(string(velerov1api.VeleroResourceUsageDataUploadResult)))).Result(),
			expectedPVC:      builder.ForPersistentVolumeClaim("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1", "kibishii-data-kibishii-deployment-0").ObjectMeta(builder.WithAnnotations("velero.io/csi-volumesnapshot-restore-size", "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
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
			pvc:          builder.ForPersistentVolumeClaim("velero", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			preCreatePVC: true,
		},
		{
			name:         "Restore a PVC that already exists in the mapping namespace",
			backup:       builder.ForBackup("velero", "testBackup").SnapshotMoveData(true).Result(),
			restore:      builder.ForRestore("velero", "testRestore").Backup("testBackup").NamespaceMappings("velero", "restore").ObjectMeta(builder.WithUID("uid")).Result(),
			pvc:          builder.ForPersistentVolumeClaim("restore", "testPVC").ObjectMeta(builder.WithAnnotations(velerov1api.VolumeSnapshotRestoreSize, "10Gi", velerov1api.DataUploadNameAnnotation, "velero/")).Result(),
			preCreatePVC: true,
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

			input := new(velero.RestoreItemActionExecuteInput)

			if tc.pvc != nil {
				pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvc)
				require.NoError(t, err)

				input.Item = &unstructured.Unstructured{Object: pvcMap}
				input.ItemFromBackup = &unstructured.Unstructured{Object: pvcMap}
				input.Restore = tc.restore
			}
			if tc.preCreatePVC {
				object = append(object, tc.pvc)
			}

			if tc.dataUploadResult != nil {
				object = append(object, tc.dataUploadResult)
			}

			pvcRIA := pvcRestoreItemAction{
				log:      logrus.New(),
				crClient: velerotest.NewFakeControllerRuntimeClient(t, object...),
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
	plugin1 := NewPvcRestoreItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}
