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
)

func TestVSClassExecute(t *testing.T) {
	tests := []struct {
		name          string
		item          runtime.Unstructured
		vsClass       *snapshotv1api.VolumeSnapshotClass
		backup        *velerov1api.Backup
		expectErr     bool
		expectedItems []velero.ResourceIdentifier
	}{
		{
			name:      "No Secret in the VS Class, no return additional items",
			vsClass:   builder.ForVolumeSnapshotClass("test").Result(),
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: false,
		},
		{
			name: "Normal case, additional items should return",
			vsClass: builder.ForVolumeSnapshotClass("test").ObjectMeta(builder.WithAnnotationsMap(
				map[string]string{
					velerov1api.PrefixedListSecretNameAnnotation:      "name",
					velerov1api.PrefixedListSecretNamespaceAnnotation: "namespace",
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
			p, err := NewVolumeSnapshotClassBackupItemAction(logrus.StandardLogger())
			require.NoError(t, err)

			action := p.(*volumeSnapshotClassBackupItemAction)

			if test.vsClass != nil {
				vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.vsClass)
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

func TestVSClassAppliesTo(t *testing.T) {
	p := volumeSnapshotClassBackupItemAction{
		log: logrus.StandardLogger(),
	}
	selector, err := p.AppliesTo()

	require.NoError(t, err)

	require.Equal(
		t,
		velero.ResourceSelector{
			IncludedResources: []string{"volumesnapshotclasses.snapshot.storage.k8s.io"},
		},
		selector,
	)
}
