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

package csi_test

import (
	"testing"

	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
)

func TestResolveVGSGroupVersion(t *testing.T) {
	tests := []struct {
		name        string
		served      []string
		expectVer   string
		expectErr   bool
		expectNoAPI bool
	}{
		{name: "v1 only", served: []string{"v1"}, expectVer: "v1"},
		{name: "v1beta1 only", served: []string{"v1beta1"}, expectVer: "v1beta1"},
		{name: "v1beta2 only", served: []string{"v1beta2"}, expectVer: "v1beta2"},
		{name: "all served prefers v1", served: []string{"v1beta1", "v1beta2", "v1"}, expectVer: "v1"},
		{name: "betas served prefers v1beta2", served: []string{"v1beta1", "v1beta2"}, expectVer: "v1beta2"},
		{name: "none served", served: nil, expectNoAPI: true},
		{name: "only unknown version", served: []string{"v2"}, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gv, err := csi.ResolveVGSGroupVersion(velerotest.VGSTestRESTMapper(tt.served...))

			switch {
			case tt.expectNoAPI:
				require.ErrorIs(t, err, csi.ErrVGSAPINotAvailable)
			case tt.expectErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
				assert.Equal(t, csi.VGSGroup, gv.Group)
				assert.Equal(t, tt.expectVer, gv.Version)
			}
		})
	}
}

// TestVGSHelpersRoundTrip exercises the unstructured-on-crClient helpers against a
// fake client whose RESTMapper serves the VGS API.
func TestVGSHelpersRoundTrip(t *testing.T) {
	className := "rbd-class"
	seedClass := &volumegroupsnapshotv1.VolumeGroupSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   className,
			Labels: map[string]string{"velero.io/csi-volumegroupsnapshot-class": "true"},
		},
		Driver: "rbd.csi.ceph.com",
	}
	c := velerotest.NewFakeControllerRuntimeClientWithVGS(t, seedClass)

	// List VGSClasses
	classes, err := csi.ListVGSClasses(t.Context(), c)
	require.NoError(t, err)
	require.Len(t, classes.Items, 1)
	assert.Equal(t, "rbd.csi.ceph.com", classes.Items[0].Driver)

	// Create + Get VGS
	created, err := csi.CreateVGS(t.Context(), c, &volumegroupsnapshotv1.VolumeGroupSnapshot{
		ObjectMeta: metav1.ObjectMeta{Name: "vgs-1", Namespace: "ns-1"},
		Spec:       volumegroupsnapshotv1.VolumeGroupSnapshotSpec{VolumeGroupSnapshotClassName: &className},
	})
	require.NoError(t, err)
	assert.Equal(t, "vgs-1", created.Name)

	got, err := csi.GetVGS(t.Context(), c, "ns-1", "vgs-1")
	require.NoError(t, err)
	require.NotNil(t, got.Spec.VolumeGroupSnapshotClassName)
	assert.Equal(t, className, *got.Spec.VolumeGroupSnapshotClassName)

	// Delete VGS
	require.NoError(t, csi.DeleteVGS(t.Context(), c, "ns-1", "vgs-1"))
	_, err = csi.GetVGS(t.Context(), c, "ns-1", "vgs-1")
	require.Error(t, err)
}

func TestVGSHelpersAPINotAvailable(t *testing.T) {
	// Fake client whose RESTMapper serves no VGS API.
	c := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithRESTMapper(velerotest.VGSTestRESTMapper()).
		Build()

	_, err := csi.ListVGSClasses(t.Context(), c)
	require.ErrorIs(t, err, csi.ErrVGSAPINotAvailable)
}
