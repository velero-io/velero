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

	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
	csiutil "github.com/velero-io/velero/pkg/util/csi"
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
				ObjectMeta: metav1.ObjectMeta{
					Name: "bar",
					Labels: map[string]string{
						velerov1api.BackupNameLabel: "backup",
					},
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy:    snapshotv1api.VolumeSnapshotContentRetain,
					Driver:            "disk.csi.azure.com",
					Source:            snapshotv1api.VolumeSnapshotContentSource{SnapshotHandle: stringPtr("snap-123")},
					VolumeSnapshotRef: corev1api.ObjectReference{Name: "vs-1", Namespace: "default"},
				},
			},
		},
		{
			name:      "Original VSC exists in cluster without backup label, falls through to temp VSC flow",
			vsc:       builder.ForVolumeSnapshotContent("bar").ObjectMeta(builder.WithLabelsMap(map[string]string{velerov1api.BackupNameLabel: "backup"})).Status(&snapshotv1api.VolumeSnapshotContentStatus{SnapshotHandle: &snapshotHandleStr}).Result(),
			backup:    builder.ForBackup("velero", "backup").Result(),
			expectErr: false,
			preExistingVSC: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bar",
				},
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

func TestVSCExecuteGroupMember(t *testing.T) {
	driver := "rbd.csi.ceph.com"
	groupHandle := "group-handle"
	class := &volumegroupsnapshotv1.VolumeGroupSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{Name: "vgs-class"},
		Driver:     driver,
		Parameters: map[string]string{
			"csi.storage.k8s.io/group-snapshotter-secret-name":      "group-secret",
			"csi.storage.k8s.io/group-snapshotter-secret-namespace": "group-secret-ns",
		},
	}
	backup := builder.ForBackup("velero", "backup").Result()
	backup.UID = "backup-uid"

	memberItem := func(name, snapshotHandle string) *unstructured.Unstructured {
		vsc := &snapshotv1api.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: map[string]string{velerov1api.BackupNameLabel: "backup"},
			},
			Spec: snapshotv1api.VolumeSnapshotContentSpec{Driver: driver},
			Status: &snapshotv1api.VolumeSnapshotContentStatus{
				SnapshotHandle:            &snapshotHandle,
				VolumeGroupSnapshotHandle: &groupHandle,
			},
		}
		vscMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(vsc)
		require.NoError(t, err)
		return &unstructured.Unstructured{Object: vscMap}
	}

	crClient := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, class)
	p := volumeSnapshotContentDeleteItemAction{log: logrus.StandardLogger(), crClient: crClient}

	require.NoError(t, p.Execute(&velero.DeleteItemActionExecuteInput{
		Item:   memberItem("member-1", "handle-1"),
		Backup: backup,
	}))

	// No per-member temporary VolumeSnapshotContent is created for group
	// members, and no VolumeGroupSnapshotContent is created yet either: a
	// single DIA invocation only sees one tarball item and cannot know the
	// group's complete member list, which the CSI CRDs require before the
	// content can be created at all.
	vscList := &snapshotv1api.VolumeSnapshotContentList{}
	require.NoError(t, crClient.List(t.Context(), vscList))
	require.Empty(t, vscList.Items)
	vgscList := &volumegroupsnapshotv1.VolumeGroupSnapshotContentList{}
	require.NoError(t, crClient.List(t.Context(), vgscList))
	require.Empty(t, vgscList.Items)

	// Instead the member's handle is recorded as its own ConfigMap.
	memberCMs := &corev1api.ConfigMapList{}
	require.NoError(t, crClient.List(t.Context(), memberCMs, crclient.MatchingLabels(map[string]string{
		velerov1api.BackupUIDLabel:                 string(backup.UID),
		velerov1api.VolumeGroupSnapshotMemberLabel: "true",
	})))
	require.Len(t, memberCMs.Items, 1)
	assert.Contains(t, memberCMs.Items[0].Data["member"], `"groupSnapshotHandle":"group-handle"`)
	assert.Contains(t, memberCMs.Items[0].Data["member"], `"snapshotHandle":"handle-1"`)

	// A second member of the same group gets its own ConfigMap.
	require.NoError(t, p.Execute(&velero.DeleteItemActionExecuteInput{
		Item:   memberItem("member-2", "handle-2"),
		Backup: backup,
	}))
	require.NoError(t, crClient.List(t.Context(), memberCMs, crclient.MatchingLabels(map[string]string{
		velerov1api.BackupUIDLabel:                 string(backup.UID),
		velerov1api.VolumeGroupSnapshotMemberLabel: "true",
	})))
	require.Len(t, memberCMs.Items, 2)

	// Re-processing a member (e.g. a retried deletion attempt) is idempotent:
	// the same ConfigMap name is derived from the member's content name, so
	// AlreadyExists is treated as success rather than a duplicate.
	require.NoError(t, p.Execute(&velero.DeleteItemActionExecuteInput{
		Item:   memberItem("member-1", "handle-1"),
		Backup: backup,
	}))
	require.NoError(t, crClient.List(t.Context(), memberCMs, crclient.MatchingLabels(map[string]string{
		velerov1api.BackupUIDLabel:                 string(backup.UID),
		velerov1api.VolumeGroupSnapshotMemberLabel: "true",
	})))
	require.Len(t, memberCMs.Items, 2)

	// The Backup deletion controller's release step, run after all DIAs
	// finish, is what actually materializes the complete temporary
	// VolumeGroupSnapshotContent and releases the group — this is only
	// exercised end to end in pkg/util/csi, but the handoff point is the
	// member ConfigMaps asserted above.
	require.NoError(t, csiutil.ReleaseBackupVolumeGroupSnapshots(t.Context(), backup, crClient, logrus.StandardLogger()))
	require.NoError(t, crClient.List(t.Context(), memberCMs, crclient.MatchingLabels(map[string]string{
		velerov1api.BackupUIDLabel:                 string(backup.UID),
		velerov1api.VolumeGroupSnapshotMemberLabel: "true",
	})))
	require.Empty(t, memberCMs.Items)
}

// TestVSCExecuteGroupMemberWithLiveOriginalVSC covers the normal (non-legacy)
// CSI snapshot backup case: pkg/backup/actions/csi labels every original VSC
// with the backup name, group member or not, and it stays live in the
// cluster (held by the sidecar's own finalizer while its VolumeSnapshot
// exists) through backup deletion. The group-membership check must run
// before tryDeleteOriginalVSC, or this live, backup-labeled content would be
// matched and deleted there directly — the exact forbidden per-member
// DeleteSnapshot the rest of this fix exists to avoid.
func TestVSCExecuteGroupMemberWithLiveOriginalVSC(t *testing.T) {
	driver := "rbd.csi.ceph.com"
	groupHandle := "group-handle"
	snapshotHandle := "handle-1"
	backup := builder.ForBackup("velero", "backup").Result()
	backup.UID = "backup-uid"

	liveVSC := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "member-1",
			Labels: map[string]string{velerov1api.BackupNameLabel: "backup"},
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
			Driver:         driver,
			Source: snapshotv1api.VolumeSnapshotContentSource{
				SnapshotHandle: &snapshotHandle,
			},
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			SnapshotHandle:            &snapshotHandle,
			VolumeGroupSnapshotHandle: &groupHandle,
		},
	}

	crClient := velerotest.NewFakeControllerRuntimeClientWithVGS(t, backup, liveVSC.DeepCopy())
	p := volumeSnapshotContentDeleteItemAction{log: logrus.StandardLogger(), crClient: crClient}

	vscMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(liveVSC)
	require.NoError(t, err)

	require.NoError(t, p.Execute(&velero.DeleteItemActionExecuteInput{
		Item:   &unstructured.Unstructured{Object: vscMap},
		Backup: backup,
	}))

	// The live original VSC must be left untouched: neither deleted nor
	// patched to DeletionPolicy=Delete.
	existing := &snapshotv1api.VolumeSnapshotContent{}
	require.NoError(t, crClient.Get(t.Context(), crclient.ObjectKey{Name: "member-1"}, existing))
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentRetain, existing.Spec.DeletionPolicy)

	// The member's handle must be recorded for the group release step instead.
	memberCMs := &corev1api.ConfigMapList{}
	require.NoError(t, crClient.List(t.Context(), memberCMs, crclient.MatchingLabels(map[string]string{
		velerov1api.BackupUIDLabel:                 string(backup.UID),
		velerov1api.VolumeGroupSnapshotMemberLabel: "true",
	})))
	require.Len(t, memberCMs.Items, 1)
	assert.Contains(t, memberCMs.Items[0].Data["member"], `"groupSnapshotHandle":"group-handle"`)
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
		name       string
		vscName    string
		backupName string
		existing   *snapshotv1api.VolumeSnapshotContent
		createIt   bool
		expectRet  bool
	}{
		{
			name:       "VSC not found in cluster, returns false",
			vscName:    "not-found",
			backupName: "test-backup",
			expectRet:  false,
		},
		{
			name:       "VSC found in cluster without backup label, returns false",
			vscName:    "unlabeled-vsc",
			backupName: "test-backup",
			existing: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{Name: "unlabeled-vsc"},
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
			expectRet: false,
		},
		{
			name:       "VSC found with Retain policy and matching backup label, patches and deletes",
			vscName:    "legacy-vsc",
			backupName: "test-backup",
			existing: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "legacy-vsc",
					Labels: map[string]string{
						velerov1api.BackupNameLabel: "test-backup",
					},
				},
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
			name:       "VSC found with Delete policy and matching backup label, just deletes",
			vscName:    "already-delete-vsc",
			backupName: "test-backup",
			existing: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "already-delete-vsc",
					Labels: map[string]string{
						velerov1api.BackupNameLabel: "test-backup",
					},
				},
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

			result := p.tryDeleteOriginalVSC(t.Context(), test.vscName, test.backupName)
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
		require.False(t, p.tryDeleteOriginalVSC(t.Context(), "some-vsc", "test-backup"))
	})

	t.Run("Patch fails, returns false", func(t *testing.T) {
		realClient := velerotest.NewFakeControllerRuntimeClient(t)
		vsc := &snapshotv1api.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{
				Name: "patch-fail-vsc",
				Labels: map[string]string{
					velerov1api.BackupNameLabel: "test-backup",
				},
			},
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
		require.False(t, p.tryDeleteOriginalVSC(t.Context(), "patch-fail-vsc", "test-backup"))
	})

	t.Run("Delete fails, returns false", func(t *testing.T) {
		realClient := velerotest.NewFakeControllerRuntimeClient(t)
		vsc := &snapshotv1api.VolumeSnapshotContent{
			ObjectMeta: metav1.ObjectMeta{
				Name: "delete-fail-vsc",
				Labels: map[string]string{
					velerov1api.BackupNameLabel: "test-backup",
				},
			},
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
		require.False(t, p.tryDeleteOriginalVSC(t.Context(), "delete-fail-vsc", "test-backup"))
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
