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
	"fmt"
	"strings"
	"testing"

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
	retainedsnapshot "github.com/velero-io/velero/pkg/util/retainedsnapshot"
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

// TestDataUploadDeleteActionGathersRetainedSnapshotRecords proves the gather
// behavior of section 5: a DataUpload carrying a record contributes an entry to
// the sharded family, keyed by the DataUpload name whatever its phase, and the
// gather merges into a family an earlier attempt left behind.
func TestDataUploadDeleteActionGathersRetainedSnapshotRecords(t *testing.T) {
	record := &velerov2alpha1.RetainedCSIStorageSnapshot{
		CSISnapshotHandle: "0001-0009-rook-ceph-0000000000000001-snap",
		Driver:            "rbd.csi.ceph.com",
	}
	backup := builder.ForBackup("velero", "daily-backup").StorageLocation("default").Result()
	backup.UID = "daily-uid"

	tests := []struct {
		name         string
		phase        velerov2alpha1.DataUploadPhase
		repeat       bool
		wantEntries  int
		wantSnapshot string
	}{
		{
			name:         "a completed DataUpload with a record contributes an entry",
			phase:        velerov2alpha1.DataUploadPhaseCompleted,
			wantEntries:  1,
			wantSnapshot: "0001-0009-rook-ceph-0000000000000001-snap",
		},
		{
			// Section 3 clears the record only after the backup content is
			// gone, so a surviving record means the snapshot was never
			// released, whatever the DataUpload's final phase.
			name:         "a failed DataUpload with a record also contributes an entry",
			phase:        velerov2alpha1.DataUploadPhaseFailed,
			wantEntries:  1,
			wantSnapshot: "0001-0009-rook-ceph-0000000000000001-snap",
		},
		{
			name:        "a DataUpload without a record contributes nothing",
			phase:       velerov2alpha1.DataUploadPhaseCompleted,
			wantEntries: 0,
		},
		{
			// The family is written create-or-update: an existing map from an
			// earlier, failed attempt of the same deletion is merged into,
			// never rejected.
			name:         "a repeated gather merges into the existing family",
			phase:        velerov2alpha1.DataUploadPhaseCompleted,
			repeat:       true,
			wantEntries:  1,
			wantSnapshot: "0001-0009-rook-ceph-0000000000000001-snap",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			action := NewDataUploadDeleteAction(velerotest.NewLogger(), crClient)

			du := newCompletedDataUpload("daily-backup-abcde", "daily-backup")
			du.Status.Phase = tc.phase
			if tc.wantSnapshot != "" {
				du.Status.RetainedCSIStorageSnapshot = record
			}
			input := &velero.DeleteItemActionExecuteInput{
				Item:   toUnstructured(t, du),
				Backup: backup,
			}

			require.NoError(t, action.Execute(input))
			if tc.repeat {
				require.NoError(t, action.Execute(input))
			}

			family, err := retainedsnapshot.LoadFamily(t.Context(), crClient, backup)
			require.NoError(t, err)
			assert.Equal(t, tc.wantEntries, family.PendingEntries())
			if tc.wantSnapshot != "" {
				entry, ok := family.Entry("daily-backup-abcde")
				require.True(t, ok)
				assert.Equal(t, tc.wantSnapshot, entry.CSISnapshotHandle)
				assert.True(t, entry.Trusted, "a record from DataUpload status is trusted")
			}
		})
	}
}

// TestDataUploadDeleteActionGathersUnrecordedRetainedSnapshot proves the
// pre-rollback gather: a completed velero-block CSI DataUpload whose
// VolumeSnapshotClass still exists with deletionPolicy Retain contributes an
// entry identifying the repository snapshot, so the backup-deletion controller
// can resolve the handle from its cbt-change-id tag before the repository data
// is deleted. The class is looked up in the cluster where the deletion runs,
// and the deletion secret is taken from the class parameters.
func TestDataUploadDeleteActionGathersUnrecordedRetainedSnapshot(t *testing.T) {
	retainClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta:     metav1.ObjectMeta{Name: "retain-class"},
		Driver:         "rbd.csi.ceph.com",
		DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
		Parameters: map[string]string{
			velerov1.PrefixedSecretNameAnnotation:      "rook-csi-rbd-provisioner",
			velerov1.PrefixedSecretNamespaceAnnotation: "rook-ceph",
		},
	}
	deleteClass := retainClass.DeepCopy()
	deleteClass.Name = "delete-class"
	deleteClass.DeletionPolicy = snapshotv1api.VolumeSnapshotContentDelete

	backup := builder.ForBackup("velero", "daily-backup").StorageLocation("default").Result()
	backup.UID = "daily-uid"

	tests := []struct {
		name       string
		mutate     func(du *velerov2alpha1.DataUpload)
		wantEntry  bool
		wantSecret bool
	}{
		{
			name:       "a Retain class contributes an entry identifying the repository snapshot",
			wantEntry:  true,
			wantSecret: true,
		},
		{
			name:      "a Delete class kept nothing, no entry",
			mutate:    func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.SnapshotClass = "delete-class" },
			wantEntry: false,
		},
		{
			name:      "a class that no longer exists is left for manual cleanup",
			mutate:    func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.SnapshotClass = "missing-class" },
			wantEntry: false,
		},
		{
			name:      "the vSphere change ID is not a snapshot handle",
			mutate:    func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.Driver = "csi.vsphere.vmware.com" },
			wantEntry: false,
		},
		{
			name:      "the file system data mover never retains",
			mutate:    func(du *velerov2alpha1.DataUpload) { du.Spec.DataMover = "velero" },
			wantEntry: false,
		},
		{
			name:      "a DataUpload that did not complete kept nothing",
			mutate:    func(du *velerov2alpha1.DataUpload) { du.Status.Phase = velerov2alpha1.DataUploadPhaseFailed },
			wantEntry: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t, retainClass, deleteClass)
			action := NewDataUploadDeleteAction(velerotest.NewLogger(), crClient)

			du := newCompletedDataUpload("daily-backup-abcde", "daily-backup")
			du.Spec.DataMover = "velero-block"
			du.Spec.CSISnapshot = &velerov2alpha1.CSISnapshotSpec{Driver: "rbd.csi.ceph.com", SnapshotClass: "retain-class"}
			if tc.mutate != nil {
				tc.mutate(du)
			}

			require.NoError(t, action.Execute(&velero.DeleteItemActionExecuteInput{
				Item:   toUnstructured(t, du),
				Backup: backup,
			}))

			family, err := retainedsnapshot.LoadFamily(t.Context(), crClient, backup)
			require.NoError(t, err)
			if !tc.wantEntry {
				assert.Zero(t, family.PendingEntries())
				return
			}
			entry, ok := family.Entry("daily-backup-abcde")
			require.True(t, ok)
			assert.Empty(t, entry.CSISnapshotHandle, "the handle is resolved later, from the repository snapshot tag")
			assert.Equal(t, "rbd.csi.ceph.com", entry.Driver)
			assert.False(t, entry.Trusted, "a tarball-sourced record is not trusted")
			require.NotNil(t, entry.Snapshot)
			assert.Equal(t, "kopia-snapshot-id", entry.Snapshot.SnapshotID)
			if tc.wantSecret {
				require.NotNil(t, entry.DeletionSecretRef)
				assert.Equal(t, "rook-csi-rbd-provisioner", entry.DeletionSecretRef.Name)
			}
		})
	}
}
