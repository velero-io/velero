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

package datamover

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
	csiutil "github.com/velero-io/velero/pkg/util/csi"
)

func toUnstructured(t *testing.T, du *velerov2alpha1.DataUpload) runtime.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(du)
	require.NoError(t, err)
	return &unstructured.Unstructured{Object: m}
}

func newCompletedDataUpload(name, ownerBackup string) *velerov2alpha1.DataUpload {
	du := &velerov2alpha1.DataUpload{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov2alpha1.SchemeGroupVersion.String(),
			Kind:       "DataUpload",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      name,
		},
		Spec: velerov2alpha1.DataUploadSpec{
			SnapshotType:          velerov2alpha1.SnapshotTypeCSI,
			SourcePVC:             "my-pvc",
			SourceNamespace:       "app",
			BackupStorageLocation: "default",
			DataMover:             "velero",
		},
		Status: velerov2alpha1.DataUploadStatus{
			Phase:      velerov2alpha1.DataUploadPhaseCompleted,
			SnapshotID: "kopia-snapshot-id",
		},
	}
	if ownerBackup != "" {
		du.Labels = map[string]string{velerov1.BackupNameLabel: ownerBackup}
	}
	return du
}

func TestDataUploadDeleteActionAppliesTo(t *testing.T) {
	a := NewDataUploadDeleteAction(logrus.StandardLogger(), nil)
	selector, err := a.AppliesTo()
	require.NoError(t, err)
	require.Equal(t, velero.ResourceSelector{IncludedResources: []string{"datauploads.velero.io"}}, selector)
}

func TestDataUploadDeleteActionExecute(t *testing.T) {
	tests := []struct {
		name             string
		duName           string
		duOwnerBackup    string // value placed in velero.io/backup-name label on the DataUpload
		executingBackup  string // name of the Backup being deleted (input.Backup.Name)
		wantConfigMap    bool
		wantWarnContains string // substring expected in a warn-level log entry; empty means no warn expected
	}{
		{
			name:             "DataUpload owned by the executing backup creates a snapshot-info ConfigMap",
			duName:           "daily-backup-abcde",
			duOwnerBackup:    "daily-backup",
			executingBackup:  "daily-backup",
			wantConfigMap:    true,
			wantWarnContains: "",
		},
		{
			name:             "DataUpload owned by a different backup is skipped and a warning is logged",
			duName:           "daily-backup-abcde",
			duOwnerBackup:    "daily-backup",
			executingBackup:  "hourly-backup",
			wantConfigMap:    false,
			wantWarnContains: "velero namespace",
		},
		{
			name:             "DataUpload with no backup-name label is skipped and a warning is logged",
			duName:           "unlabeled-du",
			duOwnerBackup:    "",
			executingBackup:  "some-backup",
			wantConfigMap:    false,
			wantWarnContains: "cannot be verified",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger, hook := logrustest.NewNullLogger()
			logger.SetLevel(logrus.DebugLevel)
			action := NewDataUploadDeleteAction(logger, crClient)

			du := newCompletedDataUpload(tc.duName, tc.duOwnerBackup)
			backup := builder.ForBackup("velero", tc.executingBackup).StorageLocation("default").Result()

			err := action.Execute(&velero.DeleteItemActionExecuteInput{
				Item:   toUnstructured(t, du),
				Backup: backup,
			})
			require.NoError(t, err)

			cm := &corev1api.ConfigMap{}
			getErr := crClient.Get(t.Context(), crclient.ObjectKey{
				Namespace: backup.Namespace,
				Name:      fmt.Sprintf("%s-info", du.Name),
			}, cm)

			if tc.wantConfigMap {
				require.NoError(t, getErr, "expected snapshot-info ConfigMap to be created")
				assert.Equal(t, tc.executingBackup, cm.Labels[velerov1.BackupNameLabel])
				assert.Equal(t, "true", cm.Labels[velerov1.DataUploadSnapshotInfoLabel])
			} else {
				require.Error(t, getErr)
				assert.True(t, apierrors.IsNotFound(getErr),
					"expected no ConfigMap to be created for foreign DataUpload, but got: %v", getErr)
			}

			// The action must surface DataUploads it cannot generate a useful
			// snapshot-info ConfigMap for as warnings, so operators who
			// accidentally included the velero namespace in a backup (or
			// otherwise produced DataUploads without a verifiable owner) can
			// detect the misconfiguration from logs instead of having the
			// case silently swallowed.
			var sawWarn bool
			for _, entry := range hook.AllEntries() {
				if entry.Level == logrus.WarnLevel &&
					strings.Contains(entry.Message, tc.duName) &&
					(tc.wantWarnContains == "" || strings.Contains(entry.Message, tc.wantWarnContains)) {
					sawWarn = true
					break
				}
			}
			assert.Equal(t, tc.wantWarnContains != "", sawWarn,
				"unexpected warn log presence (wantContains=%q, got=%v); entries=%v",
				tc.wantWarnContains, sawWarn, hook.AllEntries())
		})
	}
}

// vscTrackingClient records the VolumeSnapshotContents created and deleted
// through it and can inject errors into those calls.
type vscTrackingClient struct {
	crclient.Client
	events    *[]string
	created   []*snapshotv1api.VolumeSnapshotContent
	createErr error
	deleteErr error
}

func (c *vscTrackingClient) Create(ctx context.Context, obj crclient.Object, opts ...crclient.CreateOption) error {
	if vsc, ok := obj.(*snapshotv1api.VolumeSnapshotContent); ok {
		*c.events = append(*c.events, "create")
		if c.createErr != nil {
			return c.createErr
		}
		c.created = append(c.created, vsc.DeepCopy())
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *vscTrackingClient) Delete(ctx context.Context, obj crclient.Object, opts ...crclient.DeleteOption) error {
	if _, ok := obj.(*snapshotv1api.VolumeSnapshotContent); ok {
		*c.events = append(*c.events, "delete")
		if c.deleteErr != nil {
			return c.deleteErr
		}
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestDataUploadDeleteActionRetainedSnapshot(t *testing.T) {
	retainedWithSecret := &velerov2alpha1.RetainedSnapshot{
		SnapshotHandle:          "0001-0009-rook-ceph-0000000000000001-snap",
		Driver:                  "rbd.csi.ceph.com",
		DeletionSecretName:      "rook-csi-rbd-provisioner",
		DeletionSecretNamespace: "rook-ceph",
	}

	tests := []struct {
		name            string
		retained        *velerov2alpha1.RetainedSnapshot
		executingBackup string
		existingCM      bool
		createErr       error
		deleteErr       error
		waitErr         error
		wantEvents      []string
		wantAnnotations map[string]string
		wantErr         string
	}{
		{
			name:            "retained snapshot is deleted through a temp VSC with Delete policy and the deletion secret",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			wantEvents:      []string{"create", "sleep", "delete", "wait"},
			wantAnnotations: map[string]string{
				csiutil.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csiutil.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
		},
		{
			name: "retained snapshot without deletion secret is deleted through a temp VSC without secret annotations",
			retained: &velerov2alpha1.RetainedSnapshot{
				SnapshotHandle: "snap-handle",
				Driver:         "hostpath.csi.k8s.io",
			},
			executingBackup: "daily-backup",
			wantEvents:      []string{"create", "sleep", "delete", "wait"},
		},
		{
			name:            "snapshot-info configmap left by a failed deletion does not stop the retry",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			existingCM:      true,
			wantEvents:      []string{"create", "sleep", "delete", "wait"},
			wantAnnotations: map[string]string{
				csiutil.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csiutil.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
		},
		{
			name:            "no retained snapshot creates no VSC",
			executingBackup: "daily-backup",
			wantEvents:      []string{},
		},
		{
			name:            "retained snapshot of a DataUpload owned by another backup is not deleted",
			retained:        retainedWithSecret,
			executingBackup: "hourly-backup",
			wantEvents:      []string{},
		},
		{
			name:            "retained snapshot without handle fails the deletion",
			retained:        &velerov2alpha1.RetainedSnapshot{Driver: "rbd.csi.ceph.com"},
			executingBackup: "daily-backup",
			wantEvents:      []string{},
			wantErr:         "invalid retained snapshot",
		},
		{
			name:            "failure to create the temp VSC fails the deletion",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			createErr:       errors.New("fake-create-error"),
			wantEvents:      []string{"create"},
			wantErr:         "fake-create-error",
		},
		{
			name:            "temp VSC already gone is not an error",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			deleteErr:       apierrors.NewNotFound(snapshotv1api.Resource("volumesnapshotcontents"), "vsc"),
			wantEvents:      []string{"create", "sleep", "delete", "wait"},
			wantAnnotations: map[string]string{
				csiutil.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csiutil.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
		},
		{
			name:            "slow snapshot deletion by the CSI driver does not fail the deletion",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			waitErr:         csiutil.ErrTempVSCDeletionPending,
			wantEvents:      []string{"create", "sleep", "delete", "wait"},
			wantAnnotations: map[string]string{
				csiutil.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csiutil.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
		},
		{
			name:            "error waiting for the temp VSC fails the deletion",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			waitErr:         errors.New("fake-wait-error"),
			wantEvents:      []string{"create", "sleep", "delete", "wait"},
			wantAnnotations: map[string]string{
				csiutil.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csiutil.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
			wantErr: "fake-wait-error",
		},
		{
			name:            "failure to delete the temp VSC fails the deletion",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			deleteErr:       errors.New("fake-delete-error"),
			wantEvents:      []string{"create", "sleep", "delete"},
			wantAnnotations: map[string]string{
				csiutil.VSCDeletionSecretNameAnnotation:      "rook-csi-rbd-provisioner",
				csiutil.VSCDeletionSecretNamespaceAnnotation: "rook-ceph",
			},
			wantErr: "fake-delete-error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := []string{}
			originalSleep := csiutil.SleepBetweenTempVSCCreateAndDelete
			t.Cleanup(func() { csiutil.SleepBetweenTempVSCCreateAndDelete = originalSleep })
			csiutil.SleepBetweenTempVSCCreateAndDelete = func(time.Duration) { events = append(events, "sleep") }
			originalWait := csiutil.WaitTempVSCDeleted
			t.Cleanup(func() { csiutil.WaitTempVSCDeleted = originalWait })
			csiutil.WaitTempVSCDeleted = func(context.Context, crclient.Client, string, time.Duration, logrus.FieldLogger) error {
				events = append(events, "wait")
				return tc.waitErr
			}

			crClient := &vscTrackingClient{
				Client:    velerotest.NewFakeControllerRuntimeClient(t),
				events:    &events,
				createErr: tc.createErr,
				deleteErr: tc.deleteErr,
			}
			action := NewDataUploadDeleteAction(velerotest.NewLogger(), crClient)

			du := newCompletedDataUpload("daily-backup-abcde", "daily-backup")
			du.Status.RetainedSnapshot = tc.retained
			backup := builder.ForBackup("velero", tc.executingBackup).StorageLocation("default").Result()
			if tc.existingCM {
				require.NoError(t, crClient.Create(t.Context(), genConfigmap(backup, *du)))
			}

			err := action.Execute(&velero.DeleteItemActionExecuteInput{
				Item:   toUnstructured(t, du),
				Backup: backup,
			})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantEvents, events)

			if len(tc.wantEvents) < 3 {
				return
			}
			require.Len(t, crClient.created, 1)
			vsc := crClient.created[0]
			assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, vsc.Spec.DeletionPolicy)
			require.NotNil(t, vsc.Spec.Source.SnapshotHandle)
			assert.Equal(t, tc.retained.SnapshotHandle, *vsc.Spec.Source.SnapshotHandle)
			assert.Nil(t, vsc.Spec.Source.VolumeHandle)
			assert.Equal(t, tc.retained.Driver, vsc.Spec.Driver)
			assert.Nil(t, vsc.Spec.VolumeSnapshotClassName)
			assert.NotEmpty(t, vsc.Spec.VolumeSnapshotRef.Name)
			assert.NotEmpty(t, vsc.Spec.VolumeSnapshotRef.Namespace)
			assert.Equal(t, tc.wantAnnotations, vsc.Annotations)
			assert.Equal(t, "daily-backup", vsc.Labels[velerov1.BackupNameLabel])
			assert.Equal(t, []string{csiutil.VSCBoundProtectionFinalizer}, vsc.Finalizers)
		})
	}
}
