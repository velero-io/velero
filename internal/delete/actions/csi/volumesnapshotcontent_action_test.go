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
	"time"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
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
)

// fakeClientWithErrors wraps a real client and injects errors for specific operations.
type fakeClientWithErrors struct {
	crclient.Client
	getError    error
	patchError  error
	deleteError error
}

type fakeClientWithCallTracking struct {
	crclient.Client
	events *[]string
}

func (c *fakeClientWithCallTracking) Create(ctx context.Context, obj crclient.Object, opts ...crclient.CreateOption) error {
	*c.events = append(*c.events, "create")
	return c.Client.Create(ctx, obj, opts...)
}

func (c *fakeClientWithCallTracking) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	*c.events = append(*c.events, "delete")
	return c.Client.Delete(ctx, obj, opts...)
}

func (c *fakeClientWithErrors) Get(ctx context.Context, key crclient.ObjectKey, obj crclient.Object, opts ...crclient.GetOption) error {
	if c.getError != nil {
		return c.getError
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *fakeClientWithErrors) Patch(ctx context.Context, obj crclient.Object, patch crclient.Patch, opts ...crclient.PatchOption) error {
	if c.patchError != nil {
		return c.patchError
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *fakeClientWithErrors) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	if c.deleteError != nil {
		return c.deleteError
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestVSCExecute(t *testing.T) {
	snapshotHandleStr := "test"
	tests := []struct {
		name     string
		item     runtime.Unstructured
		vsc      *snapshotv1api.VolumeSnapshotContent
		backup   *velerov1api.Backup
		function func(
			ctx context.Context,
			vsc *snapshotv1api.VolumeSnapshotContent,
			client crclient.Client,
		) (bool, error)
		expectErr bool
	}{
		{
			name: "VolumeSnapshotContent doesn't have backup label",
			item: velerotest.UnstructuredOrDie(
				`
				{
					"apiVersion": "snapshot.storage.k8s.io/v1",
					"kind": "VolumeSnapshotContent",
					"metadata": {
						"namespace": "ns",
						"name": "foo"
					}
				}
				`,
			),
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: false,
		},
		{
			name:      "Normal case, VolumeSnapshot should be deleted",
			vsc:       builder.ForVolumeSnapshotContent("bar").ObjectMeta(builder.WithLabelsMap(map[string]string{velerov1api.BackupNameLabel: "backup"})).VolumeSnapshotClassName("volumesnapshotclass").Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleStr}).Result(),
			backup:    builder.ForBackup("velero", "backup").ObjectMeta(builder.WithAnnotationsMap(map[string]string{velerov1api.ResourceTimeoutAnnotation: "5s"})).Result(),
			expectErr: false,
			function: func(
				ctx context.Context,
				vsc *snapshotv1api.VolumeSnapshotContent,
				client crclient.Client,
			) (bool, error) {
				return true, nil
			},
		},
		{
			name:      "Error case, deletion fails",
			vsc:       builder.ForVolumeSnapshotContent("bar").ObjectMeta(builder.WithLabelsMap(map[string]string{velerov1api.BackupNameLabel: "backup"})).Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleStr}).Result(),
			backup:    builder.ForBackup("velero", "backup").ObjectMeta(builder.WithAnnotationsMap(map[string]string{velerov1api.ResourceTimeoutAnnotation: "5s"})).Result(),
			expectErr: true,
			function: func(
				ctx context.Context,
				vsc *snapshotv1api.VolumeSnapshotContent,
				client crclient.Client,
			) (bool, error) {
				return false, errors.Errorf("test error case")
			},
		},
		{
			name:      "Error case with CSI error, dangling VSC should be cleaned up",
			vsc:       builder.ForVolumeSnapshotContent("bar").ObjectMeta(builder.WithLabelsMap(map[string]string{velerov1api.BackupNameLabel: "backup"})).Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleStr}).Result(),
			backup:    builder.ForBackup("velero", "backup").ObjectMeta(builder.WithAnnotationsMap(map[string]string{velerov1api.ResourceTimeoutAnnotation: "5s"})).Result(),
			expectErr: true,
			function: func(
				ctx context.Context,
				vsc *snapshotv1api.VolumeSnapshotContent,
				client crclient.Client,
			) (bool, error) {
				return false, errors.Errorf("VolumeSnapshotContent %s has error: InvalidSnapshot.NotFound", vsc.Name)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger := logrus.StandardLogger()
			checkVSCReadiness = test.function

			p := volumeSnapshotContentDeleteItemAction{log: logger, crClient: crClient}

			if test.vsc != nil {
				vscMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(test.vsc)
				require.NoError(t, err)
				test.item = &unstructured.Unstructured{Object: vscMap}
			}

			err := p.Execute(
				&velero.DeleteItemActionExecuteInput{
					Item:   test.item,
					Backup: test.backup,
				},
			)

			if test.expectErr == false {
				require.NoError(t, err)
			}
		})
	}
}

func TestVSCAppliesTo(t *testing.T) {
	p := volumeSnapshotContentDeleteItemAction{
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

func TestNewVolumeSnapshotContentDeleteItemAction(t *testing.T) {
	logger := logrus.StandardLogger()
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewVolumeSnapshotContentDeleteItemAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	f1 := &factorymocks.Factory{}
	f1.On("KubebuilderClient").Return(crClient, nil)
	plugin1 := NewVolumeSnapshotContentDeleteItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}

func TestCheckVSCReadiness(t *testing.T) {
	tests := []struct {
		name      string
		vsc       *snapshotv1api.VolumeSnapshotContent
		createVSC bool
		expectErr bool
		ready     bool
	}{
		{
			name: "VSC not exist",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vsc-1",
					Namespace: "velero",
				},
			},
			createVSC: false,
			expectErr: true,
			ready:     false,
		},
		{
			name: "VSC not ready",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vsc-1",
					Namespace: "velero",
				},
			},
			createVSC: true,
			expectErr: false,
			ready:     false,
		},
		{
			name: "VSC has error from CSI driver",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vsc-1",
					Namespace: "velero",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					ReadyToUse: boolPtr(false),
					Error: &snapshotv1api.VolumeSnapshotError{
						Message: stringPtr("InvalidSnapshot.NotFound: The snapshot 'snap-0abc123' does not exist."),
					},
				},
			},
			createVSC: true,
			expectErr: true,
			ready:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			if test.createVSC {
				require.NoError(t, crClient.Create(t.Context(), test.vsc))
			}

			ready, err := checkVSCReadiness(t.Context(), test.vsc, crClient)
			require.Equal(t, test.ready, ready)
			if test.expectErr {
				require.Error(t, err)
			}
		})
	}
}

func TestVSCExecute_CreateSleepDeleteOrder(t *testing.T) {
	snapshotHandleStr := "test"
	vsc := builder.ForVolumeSnapshotContent("bar").
		ObjectMeta(builder.WithLabelsMap(map[string]string{velerov1api.BackupNameLabel: "backup"})).
		Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleStr}).
		Result()

	vscMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(vsc)
	require.NoError(t, err)

	events := make([]string, 0, 3)
	realClient := velerotest.NewFakeControllerRuntimeClient(t)
	trackingClient := &fakeClientWithCallTracking{Client: realClient, events: &events}

	originalSleep := sleepBetweenTempVSCCreateAndDelete
	t.Cleanup(func() {
		sleepBetweenTempVSCCreateAndDelete = originalSleep
	})

	sleepBetweenTempVSCCreateAndDelete = func(d time.Duration) {
		require.Equal(t, tempVSCCreateDeleteGap, d)
		events = append(events, "sleep")
	}

	p := volumeSnapshotContentDeleteItemAction{log: logrus.StandardLogger(), crClient: trackingClient}
	err = p.Execute(&velero.DeleteItemActionExecuteInput{
		Item:   &unstructured.Unstructured{Object: vscMap},
		Backup: builder.ForBackup("velero", "backup").Result(),
	})
	require.NoError(t, err)
	require.Equal(t, []string{"create", "sleep", "delete"}, events)
}

func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}
