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

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
		name           string
		item           runtime.Unstructured
		vsc            *snapshotv1api.VolumeSnapshotContent
		backup         *velerov1api.Backup
		preExistingVSC *snapshotv1api.VolumeSnapshotContent
		expectErr      bool
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
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: false,
		},
		{
			name:      "Original VSC exists in cluster, cleaned up directly",
			vsc:       builder.ForVolumeSnapshotContent("bar").ObjectMeta(builder.WithLabelsMap(map[string]string{velerov1api.BackupNameLabel: "backup"})).Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleStr}).Result(),
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: false,
			preExistingVSC: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{Name: "bar"},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy:    snapshotv1api.VolumeSnapshotContentRetain,
					Driver:            "disk.csi.azure.com",
					Source:            snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: stringPtr("snap-123")},
					VolumeSnapshotRef: corev1api.ObjectReference{Name: "vs-1", Namespace: "default"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger := logrus.StandardLogger()

			if test.preExistingVSC != nil {
				require.NoError(t, crClient.Create(t.Context(), test.preExistingVSC))
			}

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

func TestTryDeleteOriginalVSC(t *testing.T) {
	tests := []struct {
		name      string
		vscName   string
		existing  *snapshotv1api.VolumeSnapshotContent
		createIt  bool
		expectRet bool
	}{
		{
			name:      "VSC not found in cluster, returns false",
			vscName:   "not-found",
			expectRet: false,
		},
		{
			name:    "VSC found with Retain policy, patches and deletes",
			vscName: "legacy-vsc",
			existing: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{Name: "legacy-vsc"},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
					Driver:         "disk.csi.azure.com",
					Source: snapshotv1api.VolumeSnapshotContentSource{
						SnapshotHandle: stringPtr("snap-123"),
					},
					VolumeSnapshotRef: corev1api.ObjectReference{
						Name:      "vs-1",
						Namespace: "default",
					},
				},
			},
			createIt:  true,
			expectRet: true,
		},
		{
			name:    "VSC found with Delete policy already, just deletes",
			vscName: "already-delete-vsc",
			existing: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{Name: "already-delete-vsc"},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
					Driver:         "disk.csi.azure.com",
					Source: snapshotv1api.VolumeSnapshotContentSource{
						SnapshotHandle: stringPtr("snap-456"),
					},
					VolumeSnapshotRef: corev1api.ObjectReference{
						Name:      "vs-2",
						Namespace: "default",
					},
				},
			},
			createIt:  true,
			expectRet: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger := logrus.StandardLogger()
			p := &volumeSnapshotContentDeleteItemAction{
				log:      logger,
				crClient: crClient,
			}

			if test.createIt && test.existing != nil {
				require.NoError(t, crClient.Create(t.Context(), test.existing))
			}

			result := p.tryDeleteOriginalVSC(t.Context(), test.vscName)
			require.Equal(t, test.expectRet, result)

			// If cleanup succeeded, verify the VSC is gone
			if test.expectRet {
				err := crClient.Get(t.Context(), crclient.ObjectKey{Name: test.vscName},
					&snapshotv1api.VolumeSnapshotContent{})
				require.True(t, apierrors.IsNotFound(err),
					"VSC should have been deleted from cluster")
			}
		})
	}

	// Error injection tests for tryDeleteOriginalVSC
	t.Run("Get returns non-NotFound error, returns false", func(t *testing.T) {
		errClient := &fakeClientWithErrors{
			Client:   velerotest.NewFakeControllerRuntimeClient(t),
			getError: fmt.Errorf("connection refused"),
		}
		p := &volumeSnapshotContentDeleteItemAction{
			log:      logrus.StandardLogger(),
			crClient: errClient,
		}
		require.False(t, p.tryDeleteOriginalVSC(t.Context(), "some-vsc"))
	})

	t.Run("Patch fails, returns false", func(t *testing.T) {
		realClient := velerotest.NewFakeControllerRuntimeClient(t)
		vsc := &snapshotv1api.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "patch-fail-vsc"},
			Spec: snapshotv1api.VolumeSnapshotContentSpec{
				DeletionPolicy:    snapshotv1api.VolumeSnapshotContentRetain,
				Driver:            "disk.csi.azure.com",
				Source:            snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: stringPtr("snap-789")},
				VolumeSnapshotRef: corev1api.ObjectReference{Name: "vs-3", Namespace: "default"},
			},
		}
		require.NoError(t, realClient.Create(t.Context(), vsc))

		errClient := &fakeClientWithErrors{
			Client:     realClient,
			patchError: fmt.Errorf("patch forbidden"),
		}
		p := &volumeSnapshotContentDeleteItemAction{
			log:      logrus.StandardLogger(),
			crClient: errClient,
		}
		require.False(t, p.tryDeleteOriginalVSC(t.Context(), "patch-fail-vsc"))
	})

	t.Run("Delete fails, returns false", func(t *testing.T) {
		realClient := velerotest.NewFakeControllerRuntimeClient(t)
		vsc := &snapshotv1api.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{Name: "delete-fail-vsc"},
			Spec: snapshotv1api.VolumeSnapshotContentSpec{
				DeletionPolicy:    snapshotv1api.VolumeSnapshotContentDelete,
				Driver:            "disk.csi.azure.com",
				Source:            snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: stringPtr("snap-999")},
				VolumeSnapshotRef: corev1api.ObjectReference{Name: "vs-4", Namespace: "default"},
			},
		}
		require.NoError(t, realClient.Create(t.Context(), vsc))

		errClient := &fakeClientWithErrors{
			Client:      realClient,
			deleteError: fmt.Errorf("delete forbidden"),
		}
		p := &volumeSnapshotContentDeleteItemAction{
			log:      logrus.StandardLogger(),
			crClient: errClient,
		}
		require.False(t, p.tryDeleteOriginalVSC(t.Context(), "delete-fail-vsc"))
	})
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
