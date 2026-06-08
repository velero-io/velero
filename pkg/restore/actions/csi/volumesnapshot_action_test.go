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
	"testing"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util"
)

var (
	testPVC       = "test-pvc"
	testSnapClass = "snap-class"
	randText      = "DEADFEED"
)

func TestResetVolumeSnapshotSpecForRestore(t *testing.T) {
	testCases := []struct {
		name    string
		vs      snapshotv1api.VolumeSnapshot
		vscName string
	}{
		{
			name: "should reset spec as expected",
			vs: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs",
					Namespace: "test-ns",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					Source: snapshotv1api.VolumeSnapshotSource{
						PersistentVolumeClaimName: &testPVC,
					},
					VolumeSnapshotClassName: &testSnapClass,
				},
			},
			vscName: "test-vsc",
		},
		{
			name: "should reset spec and overwriting value for Source.VolumeSnapshotContentName",
			vs: snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs",
					Namespace: "test-ns",
				},
				Spec: snapshotv1api.VolumeSnapshotSpec{
					Source: snapshotv1api.VolumeSnapshotSource{
						VolumeSnapshotContentName: &randText,
					},
					VolumeSnapshotClassName: &testSnapClass,
				},
			},
			vscName: "test-vsc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.vs.DeepCopy()
			resetVolumeSnapshotSpecForRestore(&tc.vs, &tc.vscName)

			assert.Equalf(t, tc.vs.Name, before.Name, "unexpected change to Object.Name, Want: %s; Got %s", before.Name, tc.vs.Name)
			assert.Equalf(t, tc.vs.Namespace, before.Namespace, "unexpected change to Object.Namespace, Want: %s; Got %s", before.Namespace, tc.vs.Namespace)
			assert.NotNil(t, tc.vs.Spec.Source)
			assert.Nil(t, tc.vs.Spec.Source.PersistentVolumeClaimName)
			assert.NotNil(t, tc.vs.Spec.Source.VolumeSnapshotContentName)
			assert.Equal(t, *tc.vs.Spec.Source.VolumeSnapshotContentName, tc.vscName)
			assert.Equalf(t, *tc.vs.Spec.VolumeSnapshotClassName, *before.Spec.VolumeSnapshotClassName, "unexpected value for Spec.VolumeSnapshotClassName, Want: %s, Got: %s",
				*tc.vs.Spec.VolumeSnapshotClassName, *before.Spec.VolumeSnapshotClassName)
			assert.Nil(t, tc.vs.Status)
		})
	}
}

func TestVSExecute(t *testing.T) {
	newVscName := util.GenerateSha256FromRestoreUIDAndVsName("restoreUID", "vsName")
	tests := []struct {
		name       string
		item       runtime.Unstructured
		vs         *snapshotv1api.VolumeSnapshot
		restore    *velerov1api.Restore
		expectErr  bool
		createVS   bool
		expectedVS *snapshotv1api.VolumeSnapshot
	}{
		{
			name:      "Restore's RestorePVs is false",
			restore:   builder.ForRestore("velero", "restore").RestorePVs(false).Result(),
			expectErr: false,
		},
		{
			name:      "VS doesn't have VSC in status",
			vs:        builder.ForVolumeSnapshot("ns", "name").ObjectMeta(builder.WithAnnotations("1", "1")).Status().Result(),
			restore:   builder.ForRestore("velero", "restore").NamespaceMappings("ns", "newNS").Result(),
			expectErr: true,
		},
		{
			name: "Normal case, VSC should be created",
			vs: builder.ForVolumeSnapshot("ns", "vsName").
				ObjectMeta(
					builder.WithAnnotationsMap(
						map[string]string{
							velerov1api.VolumeSnapshotHandleAnnotation: "vsc",
							velerov1api.DriverNameAnnotation:           "pd.csi.storage.gke.io",
						},
					),
				).
				SourceVolumeSnapshotContentName(newVscName).
				VolumeSnapshotClass("vscClass").
				Status().
				BoundVolumeSnapshotContentName("vscName").
				Result(),
			restore:    builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restoreUID")).Result(),
			expectErr:  false,
			expectedVS: builder.ForVolumeSnapshot("ns", "test").SourceVolumeSnapshotContentName(newVscName).Result(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := volumeSnapshotRestoreItemAction{
				log:      logrus.StandardLogger(),
				crClient: velerotest.NewFakeControllerRuntimeClient(t),
			}

			if test.vs != nil {
				vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.vs)
				require.NoError(t, err)
				test.item = &unstructured.Unstructured{Object: vsMap}

				if test.createVS == true {
					if newNS, ok := test.restore.Spec.NamespaceMapping[test.vs.Namespace]; ok {
						test.vs.SetNamespace(newNS)
					}
					require.NoError(t, p.crClient.Create(t.Context(), test.vs))
				}
			}

			result, err := p.Execute(
				&velero.RestoreItemActionExecuteInput{
					Item:           test.item,
					ItemFromBackup: test.item,
					Restore:        test.restore,
				},
			)

			if test.expectErr == false {
				require.NoError(t, err)
			}

			if test.expectedVS != nil {
				var vs snapshotv1api.VolumeSnapshot
				require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(
					result.UpdatedItem.UnstructuredContent(), &vs))
				require.Equal(t, test.expectedVS.Spec, vs.Spec)
			}
		})
	}
}

func TestVSAppliesTo(t *testing.T) {
	p := volumeSnapshotRestoreItemAction{
		log: logrus.StandardLogger(),
	}
	selector, err := p.AppliesTo()

	require.NoError(t, err)

	require.Equal(
		t,
		velero.ResourceSelector{
			IncludedResources: []string{"volumesnapshots.snapshot.storage.k8s.io"},
		},
		selector,
	)
}

func TestNewVolumeSnapshotRestoreItemAction(t *testing.T) {
	logger := logrus.StandardLogger()
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewVolumeSnapshotRestoreItemAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	f1 := &factorymocks.Factory{}
	f1.On("KubebuilderClient").Return(crClient, nil)
	plugin1 := NewVolumeSnapshotRestoreItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}

func TestEnsureStubVGSCExists(t *testing.T) {
	testDriver := "rbd.csi.ceph.com"
	testVGSHandle := "vgs-handle-123"
	testSnapshotHandle := "snap-handle-456"

	tests := []struct {
		name           string
		vs             *snapshotv1api.VolumeSnapshot
		restore        *velerov1api.Restore
		existingVGSC   *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent
		expectVGSC     bool
		expectErr      bool
		expectedHandle string
	}{
		{
			name: "VS without VolumeGroupSnapshotHandle annotation - no VGSC created",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs",
					Namespace: "test-ns",
					Annotations: map[string]string{
						velerov1api.VolumeSnapshotHandleAnnotation: testSnapshotHandle,
						velerov1api.DriverNameAnnotation:           testDriver,
					},
				},
			},
			restore:    builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restore-uid")).Result(),
			expectVGSC: false,
			expectErr:  false,
		},
		{
			name: "VS with VolumeGroupSnapshotHandle but no SnapshotHandle - no VGSC created",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs",
					Namespace: "test-ns",
					Annotations: map[string]string{
						velerov1api.VolumeGroupSnapshotHandleAnnotation: testVGSHandle,
						velerov1api.DriverNameAnnotation:                testDriver,
					},
				},
			},
			restore:    builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restore-uid")).Result(),
			expectVGSC: false,
			expectErr:  false,
		},
		{
			name: "VS with VolumeGroupSnapshotHandle but no Driver annotation - no VGSC created",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs",
					Namespace: "test-ns",
					Annotations: map[string]string{
						velerov1api.VolumeGroupSnapshotHandleAnnotation: testVGSHandle,
						velerov1api.VolumeSnapshotHandleAnnotation:      testSnapshotHandle,
					},
				},
			},
			restore:    builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restore-uid")).Result(),
			expectVGSC: false,
			expectErr:  false,
		},
		{
			name: "VS with all required annotations - VGSC should be created",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs",
					Namespace: "test-ns",
					Annotations: map[string]string{
						velerov1api.VolumeGroupSnapshotHandleAnnotation: testVGSHandle,
						velerov1api.VolumeSnapshotHandleAnnotation:      testSnapshotHandle,
						velerov1api.DriverNameAnnotation:                testDriver,
					},
				},
			},
			restore:        builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restore-uid")).Result(),
			expectVGSC:     true,
			expectErr:      false,
			expectedHandle: testSnapshotHandle,
		},
		{
			name: "VGSC already exists - should add snapshot handle",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-vs-2",
					Namespace: "test-ns",
					Annotations: map[string]string{
						velerov1api.VolumeGroupSnapshotHandleAnnotation: testVGSHandle,
						velerov1api.VolumeSnapshotHandleAnnotation:      "snap-handle-789",
						velerov1api.DriverNameAnnotation:                testDriver,
					},
				},
			},
			restore: builder.ForRestore("velero", "restore").ObjectMeta(builder.WithUID("restore-uid")).Result(),
			existingVGSC: &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: util.GenerateSha256FromRestoreUIDAndVsName("restore-uid", testVGSHandle),
				},
				Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
					Driver:         testDriver,
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
					Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{
						GroupSnapshotHandles: &volumegroupsnapshotv1beta2.GroupSnapshotHandles{
							VolumeGroupSnapshotHandle: testVGSHandle,
							VolumeSnapshotHandles:     []string{testSnapshotHandle},
						},
					},
				},
			},
			expectVGSC:     true,
			expectErr:      false,
			expectedHandle: "snap-handle-789",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)

			// Create existing VGSC if provided
			if tc.existingVGSC != nil {
				require.NoError(t, crClient.Create(context.Background(), tc.existingVGSC))
			}

			p := &volumeSnapshotRestoreItemAction{
				log:      logrus.StandardLogger(),
				crClient: crClient,
			}

			err := p.ensureStubVGSCExists(context.Background(), tc.vs, tc.restore)

			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check if VGSC was created/updated
			vgscName := util.GenerateSha256FromRestoreUIDAndVsName(string(tc.restore.UID), tc.vs.Annotations[velerov1api.VolumeGroupSnapshotHandleAnnotation])
			vgsc := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
			getErr := crClient.Get(context.Background(), crclient.ObjectKey{Name: vgscName}, vgsc)

			if tc.expectVGSC {
				require.NoError(t, getErr)
				require.NotNil(t, vgsc.Spec.Source.GroupSnapshotHandles)
				require.Contains(t, vgsc.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles, tc.expectedHandle)
			} else {
				// If no VGSC expected, it's okay if Get returns not found or if vgscName is empty
				if tc.vs.Annotations[velerov1api.VolumeGroupSnapshotHandleAnnotation] != "" {
					require.Error(t, getErr)
				}
			}
		})
	}
}

func TestAddSnapshotHandleToVGSC(t *testing.T) {
	testDriver := "rbd.csi.ceph.com"
	testVGSHandle := "vgs-handle-123"

	tests := []struct {
		name                    string
		existingHandles         []string
		nilGroupSnapshotHandles bool
		newHandle               string
		expectedHandles         []string
	}{
		{
			name:            "Add new handle to empty list",
			existingHandles: []string{},
			newHandle:       "snap-1",
			expectedHandles: []string{"snap-1"},
		},
		{
			name:            "Add new handle to existing list",
			existingHandles: []string{"snap-1"},
			newHandle:       "snap-2",
			expectedHandles: []string{"snap-1", "snap-2"},
		},
		{
			name:            "Handle already exists - no change",
			existingHandles: []string{"snap-1", "snap-2"},
			newHandle:       "snap-1",
			expectedHandles: []string{"snap-1", "snap-2"},
		},
		{
			name:                    "Nil GroupSnapshotHandles - should initialize and add",
			nilGroupSnapshotHandles: true,
			newHandle:               "snap-1",
			expectedHandles:         []string{"snap-1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)

			var source volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource
			if tc.nilGroupSnapshotHandles {
				source = volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{}
			} else {
				source = volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{
					GroupSnapshotHandles: &volumegroupsnapshotv1beta2.GroupSnapshotHandles{
						VolumeGroupSnapshotHandle: testVGSHandle,
						VolumeSnapshotHandles:     tc.existingHandles,
					},
				}
			}

			existingVGSC := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-vgsc",
				},
				Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
					Driver:         testDriver,
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
					Source:         source,
				},
			}
			require.NoError(t, crClient.Create(context.Background(), existingVGSC))

			// Re-fetch to get the created object with proper metadata
			fetchedVGSC := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
			require.NoError(t, crClient.Get(context.Background(), crclient.ObjectKey{Name: "test-vgsc"}, fetchedVGSC))

			p := &volumeSnapshotRestoreItemAction{
				log:      logrus.StandardLogger(),
				crClient: crClient,
			}

			err := p.addSnapshotHandleToVGSC(context.Background(), fetchedVGSC, tc.newHandle)
			require.NoError(t, err)

			// Verify the VGSC has expected handles
			updatedVGSC := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
			require.NoError(t, crClient.Get(context.Background(), crclient.ObjectKey{Name: "test-vgsc"}, updatedVGSC))
			require.ElementsMatch(t, tc.expectedHandles, updatedVGSC.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles)
		})
	}
}
