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

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util"
)

func TestVSCExecute(t *testing.T) {
	snapshotHandleName := "testHandle"
	newVscName := util.GenerateSha256FromRestoreUIDAndVsName("restoreUID", "vsName")
	tests := []struct {
		name          string
		item          runtime.Unstructured
		vsc           *snapshotv1api.VolumeSnapshotContent
		restore       *velerov1api.Restore
		expectErr     bool
		createVSC     bool
		expectedItems []velero.ResourceIdentifier
		expectedVSC   *snapshotv1api.VolumeSnapshotContent
	}{
		{
			name:      "Restore's RestorePVs is false",
			restore:   builder.ForRestore("velero", "restore").RestorePVs(false).Result(),
			expectErr: false,
		},
		{
			name: "Normal case, additional items should return    ",
			vsc: builder.ForVolumeSnapshotContent("test").
				ObjectMeta(builder.WithAnnotationsMap(
					map[string]string{
						velerov1api.PrefixedSecretNameAnnotation:      "name",
						velerov1api.PrefixedSecretNamespaceAnnotation: "namespace",
					},
				)).
				VolumeSnapshotRef("velero", "vsName", "vsUID").
				VolumeSnapshotClassName("vsClass").
				Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleName}).
				Result(),
			restore: builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restoreUID")).
				NamespaceMappings("velero", "restore").Result(),
			expectErr: false,
			expectedItems: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.Secrets,
					Namespace:     "namespace",
					Name:          "name",
				},
			},
			expectedVSC: builder.ForVolumeSnapshotContent(newVscName).
				ObjectMeta(builder.WithAnnotationsMap(
					map[string]string{
						velerov1api.PrefixedSecretNameAnnotation:      "name",
						velerov1api.PrefixedSecretNamespaceAnnotation: "namespace",
					},
				)).VolumeSnapshotRef("restore", newVscName, "").
				Source(snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: &snapshotHandleName}).
				DeletionPolicy(snapshotv1api.VolumeSnapshotContentRetain).
				Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleName}).
				Result(),
		},
		{
			name: "VSC exists in cluster, same as the normal case",
			vsc: builder.ForVolumeSnapshotContent("test").ObjectMeta(builder.WithAnnotationsMap(
				map[string]string{
					velerov1api.PrefixedSecretNameAnnotation:      "name",
					velerov1api.PrefixedSecretNamespaceAnnotation: "namespace",
				},
			)).VolumeSnapshotRef("velero", "vsName", "vsUID").
				Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleName}).Result(),
			restore: builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restoreUID")).
				NamespaceMappings("velero", "restore").Result(),
			createVSC: true,
			expectErr: false,
			expectedVSC: builder.ForVolumeSnapshotContent(newVscName).ObjectMeta(builder.WithAnnotationsMap(
				map[string]string{
					velerov1api.PrefixedSecretNameAnnotation:      "name",
					velerov1api.PrefixedSecretNamespaceAnnotation: "namespace",
				},
			)).VolumeSnapshotRef("restore", newVscName, "").
				Source(snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: &snapshotHandleName}).
				DeletionPolicy(snapshotv1api.VolumeSnapshotContentRetain).
				Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleName}).Result(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := volumeSnapshotContentRestoreItemAction{
				log:    logrus.StandardLogger(),
				client: velerotest.NewFakeControllerRuntimeClient(t),
			}

			if test.vsc != nil {
				vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.vsc)
				require.NoError(t, err)
				test.item = &unstructured.Unstructured{Object: vsMap}

				if test.createVSC {
					require.NoError(t, action.client.Create(t.Context(), test.vsc))
				}
			}

			output, err := action.Execute(
				&velero.RestoreItemActionExecuteInput{
					Item:           test.item,
					ItemFromBackup: test.item,
					Restore:        test.restore,
				},
			)

			if test.expectErr == false {
				require.NoError(t, err)
			}

			if test.expectedVSC != nil {
				vsc := new(snapshotv1api.VolumeSnapshotContent)
				require.NoError(t,
					runtime.DefaultUnstructuredConverter.FromUnstructured(
						output.UpdatedItem.UnstructuredContent(),
						vsc,
					),
				)

				require.Equal(t, test.expectedVSC, vsc)
			}

			if len(test.expectedItems) > 0 {
				require.Equal(t, test.expectedItems, output.AdditionalItems)
			}
		})
	}
}

func TestVSCAppliesTo(t *testing.T) {
	p := volumeSnapshotContentRestoreItemAction{
		log: logrus.StandardLogger(),
	}
	selector, err := p.AppliesTo()

	require.NoError(t, err)

	require.Equal(
		t,
		velero.ResourceSelector{
			IncludedResources: []string{"volumesnapshotcontents.snapshot.storage.k8s.io"},
		},
		selector,
	)
}

func TestNewVolumeSnapshotContentRestoreItemAction(t *testing.T) {
	logger := logrus.StandardLogger()
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewVolumeSnapshotContentRestoreItemAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	f1 := &factorymocks.Factory{}
	f1.On("KubebuilderClient").Return(crClient, nil)
	plugin1 := NewVolumeSnapshotContentRestoreItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}
