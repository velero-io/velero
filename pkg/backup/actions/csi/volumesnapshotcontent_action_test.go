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
	"testing"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestVSCExecute(t *testing.T) {
	tests := []struct {
		name          string
		item          runtime.Unstructured
		vsc           *snapshotv1api.VolumeSnapshotContent
		backup        *velerov1api.Backup
		expectErr     bool
		expectedItems []velero.ResourceIdentifier
	}{
		{
			name: "Invalid VolumeSnapshotContent",
			item: velerotest.UnstructuredOrDie(
				`
				{
					"apiVersion": "v1",
					"kind": "Pod",
					"metadata": {
						"namespace": "ns",
						"name": "foo"
					}
				}
				`,
			),
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: true,
		},
		{
			name: "Normal case, additional items should return",
			vsc: builder.ForVolumeSnapshotContent("test").ObjectMeta(builder.WithAnnotationsMap(
				map[string]string{
					velerov1api.PrefixedSecretNameAnnotation:      "name",
					velerov1api.PrefixedSecretNamespaceAnnotation: "namespace",
				},
			)).Result(),
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: false,
			expectedItems: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.Secrets,
					Namespace:     "namespace",
					Name:          "name",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := NewVolumeSnapshotContentBackupItemAction(logrus.StandardLogger())
			require.NoError(t, err)

			action := p.(*volumeSnapshotContentBackupItemAction)

			if test.vsc != nil {
				vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.vsc)
				require.NoError(t, err)
				test.item = &unstructured.Unstructured{Object: vsMap}
			}

			_, additionalItems, _, _, err := action.Execute(
				test.item,
				test.backup,
			)

			if test.expectErr == false {
				require.NoError(t, err)
			}

			if len(test.expectedItems) > 0 {
				require.Equal(t, test.expectedItems, additionalItems)
			}
		})
	}
}

func TestVSCAppliesTo(t *testing.T) {
	p := volumeSnapshotContentBackupItemAction{
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
