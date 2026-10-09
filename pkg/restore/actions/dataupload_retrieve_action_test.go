/*
Copyright 2020 the Velero contributors.

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

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestDataUploadRetrieveActionExectue(t *testing.T) {
	scheme := runtime.NewScheme()
	velerov1.AddToScheme(scheme)
	corev1api.AddToScheme(scheme)

	tests := []struct {
		name                     string
		dataUpload               *velerov2alpha1.DataUpload
		restore                  *velerov1.Restore
		expectedDataUploadResult *corev1api.ConfigMap
		expectedErr              string
		runtimeScheme            *runtime.Scheme
		veleroObjs               []runtime.Object
	}{
		{
			name:          "error to find backup",
			dataUpload:    builder.ForDataUpload("velero", "testDU").SourceNamespace("testNamespace").SourcePVC("testPVC").Result(),
			restore:       builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("testingUID")).Backup("testBackup").Result(),
			runtimeScheme: scheme,
			expectedErr:   "error to get backup for restore testRestore: backups.velero.io \"testBackup\" not found",
		},
		{
			name:          "DataUploadRetrieve Action test",
			dataUpload:    builder.ForDataUpload("velero", "testDU").SourceNamespace("testNamespace").SourcePVC("testPVC").SnapshotID("fake-id").TotalBytes(1000).Result(),
			restore:       builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("testingUID")).Backup("testBackup").Result(),
			runtimeScheme: scheme,
			veleroObjs: []runtime.Object{
				builder.ForBackup("velero", "testBackup").StorageLocation("testLocation").Result(),
			},
			expectedDataUploadResult: builder.ForConfigMap("velero", "").ObjectMeta(builder.WithGenerateName("testDU-"), builder.WithLabels(velerov1.PVCNamespaceNameLabel, "testNamespace.testPVC", velerov1.RestoreUIDLabel, "testingUID", velerov1.ResourceUsageLabel, string(velerov1.VeleroResourceUsageDataUploadResult))).Data("testingUID", `{"backupStorageLocation":"testLocation","snapshotID":"fake-id","sourceNamespace":"testNamespace","snapshotSize":1000}`).Result(),
		},
		{
			name: "DataUploadRetrieve Action test with optional fields",
			dataUpload: func() *velerov2alpha1.DataUpload {
				du := builder.ForDataUpload("velero", "testDU").
					SourceNamespace("testNamespace").
					SourcePVC("testPVC").
					SnapshotID("fake-id").
					TotalBytes(1000).
					DataMover("velero").
					NodeOS("linux").
					CSISnapshot(&velerov2alpha1.CSISnapshotSpec{SnapshotClass: "testClass"}).
					Result()
				du.Status.DataMoverResult = &map[string]string{"key": "value"}
				du.Spec.SourceFSType = "ext4"
				return du
			}(),
			restore:       builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("testingUID")).Backup("testBackup").Result(),
			runtimeScheme: scheme,
			veleroObjs: []runtime.Object{
				builder.ForBackup("velero", "testBackup").StorageLocation("testLocation").Result(),
			},
			expectedDataUploadResult: builder.ForConfigMap("velero", "").ObjectMeta(builder.WithGenerateName("testDU-"), builder.WithLabels(velerov1.PVCNamespaceNameLabel, "testNamespace.testPVC", velerov1.RestoreUIDLabel, "testingUID", velerov1.ResourceUsageLabel, string(velerov1.VeleroResourceUsageDataUploadResult))).Data("testingUID", `{"backupStorageLocation":"testLocation","datamover":"velero","snapshotID":"fake-id","sourceNamespace":"testNamespace","dataMoverResult":{"key":"value"},"nodeOS":"linux","snapshotSize":1000,"fsType":"ext4","snapshotClass":"testClass"}`).Result(),
		},
		{
			name:          "Long source namespace and PVC name should also work",
			dataUpload:    builder.ForDataUpload("velero", "testDU").SourceNamespace("migre209d0da-49c7-45ba-8d5a-3e59fd591ec1").SourcePVC("kibishii-data-kibishii-deployment-0").Result(),
			restore:       builder.ForRestore("velero", "testRestore").ObjectMeta(builder.WithUID("testingUID")).Backup("testBackup").Result(),
			runtimeScheme: scheme,
			veleroObjs: []runtime.Object{
				builder.ForBackup("velero", "testBackup").StorageLocation("testLocation").Result(),
			},
			expectedDataUploadResult: builder.ForConfigMap("velero", "").ObjectMeta(builder.WithGenerateName("testDU-"), builder.WithLabels(velerov1.PVCNamespaceNameLabel, "migre209d0da-49c7-45ba-8d5a-3e59fd591ec1.kibishii-data-ki152333", velerov1.RestoreUIDLabel, "testingUID", velerov1.ResourceUsageLabel, string(velerov1.VeleroResourceUsageDataUploadResult))).Data("testingUID", `{"backupStorageLocation":"testLocation","sourceNamespace":"migre209d0da-49c7-45ba-8d5a-3e59fd591ec1"}`).Result(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := velerotest.NewLogger()

			fakeClientBuilder := fake.NewClientBuilder()
			if tc.runtimeScheme != nil {
				fakeClientBuilder = fakeClientBuilder.WithScheme(tc.runtimeScheme)
			}

			fakeClient := fakeClientBuilder.WithRuntimeObjects(tc.veleroObjs...).Build()

			var unstructuredDataUpload map[string]any
			if tc.dataUpload != nil {
				var err error
				unstructuredDataUpload, err = runtime.DefaultUnstructuredConverter.ToUnstructured(tc.dataUpload)
				require.NoError(t, err)
			}
			input := velero.RestoreItemActionExecuteInput{
				Restore:        tc.restore,
				ItemFromBackup: &unstructured.Unstructured{Object: unstructuredDataUpload},
			}

			action := NewDataUploadRetrieveAction(logger, fakeClient)
			_, err := action.Execute(&input)
			if tc.expectedErr != "" {
				require.Equal(t, tc.expectedErr, err.Error())
			} else {
				require.NoError(t, err)
			}

			if tc.expectedDataUploadResult != nil {
				var cmList corev1api.ConfigMapList
				err := fakeClient.List(t.Context(), &cmList, &client.ListOptions{
					LabelSelector: labels.SelectorFromSet(map[string]string{
						velerov1.RestoreUIDLabel:       "testingUID",
						velerov1.PVCNamespaceNameLabel: label.GetValidName(tc.dataUpload.Spec.SourceNamespace + "." + tc.dataUpload.Spec.SourcePVC),
					}),
				})

				require.NoError(t, err)
				require.Equal(t, tc.expectedDataUploadResult.Labels, cmList.Items[0].Labels)
				require.Equal(t, tc.expectedDataUploadResult.Data, cmList.Items[0].Data)
			}
		})
	}
}
