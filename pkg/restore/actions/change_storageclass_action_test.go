/*
Copyright 2019 the Velero contributors.

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

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// TestChangeStorageClassActionExecute runs the ChangeStorageClassAction's Execute
// method and validates that the item's storage class is modified (or not) as expected.
// Validation is done by comparing the result of the Execute method to the test case's
// desired result.
func TestChangeStorageClassActionExecute(t *testing.T) {
	tests := []struct {
		name              string
		pvOrPvcOrSTS      any
		configMap         *corev1api.ConfigMap
		storageClass      *storagev1api.StorageClass
		storageClassSlice []*storagev1api.StorageClass
		want              any
		wantErr           error
	}{
		{
			name:         "a valid mapping for a persistent volume is applied correctly",
			pvOrPvcOrSTS: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			storageClass: builder.ForStorageClass("storageclass-2").Result(),
			want:         builder.ForPersistentVolume("pv-1").StorageClass("storageclass-2").Result(),
		},
		{
			name:         "a valid mapping for a persistent volume claim is applied correctly",
			pvOrPvcOrSTS: builder.ForPersistentVolumeClaim("velero", "pvc-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			storageClass: builder.ForStorageClass("storageclass-2").Result(),
			want:         builder.ForPersistentVolumeClaim("velero", "pvc-1").StorageClass("storageclass-2").Result(),
		},
		{
			name:         "when no config map exists for the plugin, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/some-other-plugin", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			want: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when no storage class mappings exist in the plugin config map, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Result(),
			want: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when persistent volume has no storage class, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForPersistentVolume("pv-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			want: builder.ForPersistentVolume("pv-1").Result(),
		},
		{
			name:         "when persistent volume claim has no storage class, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForPersistentVolumeClaim("velero", "pvc-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			want: builder.ForPersistentVolumeClaim("velero", "pvc-1").Result(),
		},
		{
			name:         "when persistent volume's storage class has no mapping in the config map, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-3", "storageclass-4").
				Result(),
			want: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when persistent volume claim's storage class has no mapping in the config map, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForPersistentVolumeClaim("velero", "pvc-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-3", "storageclass-4").
				Result(),
			want: builder.ForPersistentVolumeClaim("velero", "pvc-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when persistent volume's storage class is mapped to a nonexistent storage class, an error is returned",
			pvOrPvcOrSTS: builder.ForPersistentVolume("pv-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "nonexistent-storage-class").
				Result(),
			wantErr: errors.New("error getting storage class nonexistent-storage-class from API: storageclasses.storage.k8s.io \"nonexistent-storage-class\" not found"),
		},
		{
			name:         "when persistent volume claim's storage class is mapped to a nonexistent storage class, an error is returned",
			pvOrPvcOrSTS: builder.ForPersistentVolumeClaim("velero", "pvc-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "nonexistent-storage-class").
				Result(),
			wantErr: errors.New("error getting storage class nonexistent-storage-class from API: storageclasses.storage.k8s.io \"nonexistent-storage-class\" not found"),
		},
		{
			name:         "when statefulset's VolumeClaimTemplates has only one pvc, a valid mapping for a statefulset is applied correctly",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			storageClass: builder.ForStorageClass("storageclass-2").Result(),
			want:         builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-2").Result(),
		},
		{
			name:         "when statefulset's VolumeClaimTemplates has more than one same pvc's storageClassName, a valid mapping for a statefulset is applied correctly",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1", "storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2", "storageclass-3", "storageclass-4").
				Result(),
			storageClass: builder.ForStorageClass("storageclass-2").Result(),
			want:         builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-2", "storageclass-2").Result(),
		},
		{
			name:         "when statefulset's VolumeClaimTemplates has more than one different pvc's storageClassName, a valid mapping for a statefulset is applied correctly",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1", "storageclass-2", "storageclass-3").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-a", "storageclass-2", "storageclass-b", "storageclass-3", "storageclass-c").
				Result(),
			storageClassSlice: builder.ForStorageClassSlice("storageclass-a", "storageclass-b", "storageclass-c").SliceResult(),
			want:              builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-a", "storageclass-b", "storageclass-c").Result(),
		},
		{
			name:         "when no config map exists for the plugin, the statefulset item is returned as-is",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/some-other-plugin", "RestoreItemAction")).
				Data("storageclass-1", "storageclass-2").
				Result(),
			want: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when no storage class mappings exist in the plugin config map, the statefulset item is returned as-is",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Result(),
			want: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when persistent volume claim has no storage class, the statefulset item is returned as-is",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Result(),
			want: builder.ForStatefulSet("velero", "sts-1").Result(),
		},
		{
			name:         "when statefulset's storage class has no mapping in the config map, the item is returned as-is",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-3", "storageclass-4").
				Result(),
			want: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
		},
		{
			name:         "when statefulset's storage class is mapped to a nonexistent storage class, an error is returned",
			pvOrPvcOrSTS: builder.ForStatefulSet("velero", "sts-1").StorageClass("storageclass-1").Result(),
			configMap: builder.ForConfigMap("velero", "change-storage-classs").
				ObjectMeta(builder.WithLabels("velero.io/plugin-config", "", "velero.io/change-storage-class", "RestoreItemAction")).
				Data("storageclass-1", "nonexistent-storage-class").
				Result(),
			wantErr: errors.New("error getting storage class nonexistent-storage-class from API: storageclasses.storage.k8s.io \"nonexistent-storage-class\" not found"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			a := NewChangeStorageClassAction(
				logrus.StandardLogger(),
				clientset.CoreV1().ConfigMaps("velero"),
				clientset.StorageV1().StorageClasses(),
			)

			// set up test data
			if tc.configMap != nil {
				_, err := clientset.CoreV1().ConfigMaps(tc.configMap.Namespace).Create(t.Context(), tc.configMap, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			if tc.storageClass != nil {
				_, err := clientset.StorageV1().StorageClasses().Create(t.Context(), tc.storageClass, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			if tc.storageClassSlice != nil {
				for _, storageClass := range tc.storageClassSlice {
					_, err := clientset.StorageV1().StorageClasses().Create(t.Context(), storageClass, metav1.CreateOptions{})
					require.NoError(t, err)
				}
			}

			unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvOrPvcOrSTS)
			require.NoError(t, err)

			input := &velero.RestoreItemActionExecuteInput{
				Item: &unstructured.Unstructured{
					Object: unstructuredMap,
				},
			}

			// execute method under test
			res, err := a.Execute(input)

			// validate for both error and non-error cases
			switch {
			case tc.wantErr != nil:
				require.EqualError(t, err, tc.wantErr.Error())
			default:
				require.NoError(t, err)

				wantUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.want)
				require.NoError(t, err)

				assert.Equal(t, &unstructured.Unstructured{Object: wantUnstructured}, res.UpdatedItem)
			}
		})
	}
}
