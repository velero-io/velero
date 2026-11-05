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
		existingCMs     bool
		wantData        map[string]string
		wantErr         string
	}{
		{
			name:            "retained snapshot is passed to the backup deletion controller with the deletion secret",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			wantData: map[string]string{
				"snapshotHandle":          "0001-0009-rook-ceph-0000000000000001-snap",
				"driver":                  "rbd.csi.ceph.com",
				"deletionSecretName":      "rook-csi-rbd-provisioner",
				"deletionSecretNamespace": "rook-ceph",
			},
		},
		{
			name: "retained snapshot without deletion secret is passed without the secret",
			retained: &velerov2alpha1.RetainedSnapshot{
				SnapshotHandle: "snap-handle",
				Driver:         "hostpath.csi.k8s.io",
			},
			executingBackup: "daily-backup",
			wantData: map[string]string{
				"snapshotHandle": "snap-handle",
				"driver":         "hostpath.csi.k8s.io",
			},
		},
		{
			name:            "configmaps left by a failed deletion do not stop the retry",
			retained:        retainedWithSecret,
			executingBackup: "daily-backup",
			existingCMs:     true,
			wantData: map[string]string{
				"snapshotHandle":          "0001-0009-rook-ceph-0000000000000001-snap",
				"driver":                  "rbd.csi.ceph.com",
				"deletionSecretName":      "rook-csi-rbd-provisioner",
				"deletionSecretNamespace": "rook-ceph",
			},
		},
		{
			name:            "no retained snapshot creates no configmap",
			executingBackup: "daily-backup",
		},
		{
			name:            "retained snapshot of a DataUpload owned by another backup is not passed",
			retained:        retainedWithSecret,
			executingBackup: "hourly-backup",
		},
		{
			name:            "retained snapshot without handle fails the deletion",
			retained:        &velerov2alpha1.RetainedSnapshot{Driver: "rbd.csi.ceph.com"},
			executingBackup: "daily-backup",
			wantErr:         "invalid retained snapshot",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			action := NewDataUploadDeleteAction(velerotest.NewLogger(), crClient)

			du := newCompletedDataUpload("daily-backup-abcde", "daily-backup")
			du.Status.RetainedSnapshot = tc.retained
			backup := builder.ForBackup("velero", tc.executingBackup).StorageLocation("default").Result()
			if tc.existingCMs {
				require.NoError(t, crClient.Create(t.Context(), genConfigmap(backup, *du)))
				cm, err := genRetainedSnapshotConfigmap(backup, *du)
				require.NoError(t, err)
				require.NoError(t, crClient.Create(t.Context(), cm))
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

			cms := &corev1api.ConfigMapList{}
			require.NoError(t, crClient.List(t.Context(), cms, crclient.MatchingLabels{velerov1.DataUploadRetainedSnapshotLabel: "true"}))
			if tc.wantData == nil {
				assert.Empty(t, cms.Items)
				return
			}
			require.Len(t, cms.Items, 1)
			cm := cms.Items[0]
			assert.Equal(t, "velero", cm.Namespace)
			assert.Equal(t, "daily-backup-abcde-retained-snapshot", cm.Name)
			assert.Equal(t, "daily-backup", cm.Labels[velerov1.BackupNameLabel])
			assert.Equal(t, tc.wantData, cm.Data)

			vscs := &snapshotv1api.VolumeSnapshotContentList{}
			require.NoError(t, crClient.List(t.Context(), vscs))
			assert.Empty(t, vscs.Items, "the retained snapshot must not be deleted by the DeleteItemAction")
		})
	}
}

func TestDataUploadDeleteActionUnrecordedRetainedSnapshot(t *testing.T) {
	retainClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta:     metav1.ObjectMeta{Name: "retain-class"},
		Driver:         "rbd.csi.ceph.com",
		DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
		Parameters: map[string]string{
			velerov1.PrefixedSecretNameAnnotation:      "rook-csi-rbd-provisioner",
			velerov1.PrefixedSecretNamespaceAnnotation: "rook-ceph",
		},
	}
	deleteClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta:     metav1.ObjectMeta{Name: "delete-class"},
		Driver:         "rbd.csi.ceph.com",
		DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
	}
	templateClass := retainClass.DeepCopy()
	templateClass.Name = "template-class"
	templateClass.Parameters[velerov1.PrefixedSecretNameAnnotation] = "${volumesnapshotcontent.name}"

	tests := []struct {
		name     string
		mutate   func(du *velerov2alpha1.DataUpload)
		wantData map[string]string
	}{
		{
			name: "completed block data mover upload under a Retain class reads the handle from the repository snapshot",
			wantData: map[string]string{
				"snapshotHandle":          "",
				"driver":                  "rbd.csi.ceph.com",
				"deletionSecretName":      "rook-csi-rbd-provisioner",
				"deletionSecretNamespace": "rook-ceph",
				"volumeNamespace":         "app",
				"backupStorageLocation":   "default",
				"snapshotID":              "kopia-snapshot-id",
				"repositoryType":          "kopia",
				"uploaderType":            "velero-block",
				"source":                  "app/my-pvc",
				"repoIdentifier":          "",
			},
		},
		{
			name:   "Delete class",
			mutate: func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.SnapshotClass = "delete-class" },
		},
		{
			name:   "class no longer exists",
			mutate: func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.SnapshotClass = "missing-class" },
		},
		{
			name:   "deletion secret named by a template",
			mutate: func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.SnapshotClass = "template-class" },
		},
		{
			name:   "vSphere CSI driver, whose change ID is not the snapshot handle",
			mutate: func(du *velerov2alpha1.DataUpload) { du.Spec.CSISnapshot.Driver = "csi.vsphere.vmware.com" },
		},
		{
			name:   "file system data mover",
			mutate: func(du *velerov2alpha1.DataUpload) { du.Spec.DataMover = "velero-fs" },
		},
		{
			name:   "failed upload",
			mutate: func(du *velerov2alpha1.DataUpload) { du.Status.Phase = velerov2alpha1.DataUploadPhaseFailed },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t, retainClass, deleteClass, templateClass)
			action := NewDataUploadDeleteAction(velerotest.NewLogger(), crClient)

			du := newCompletedDataUpload("daily-backup-abcde", "daily-backup")
			du.Spec.DataMover = "velero-block"
			du.Spec.CSISnapshot = &velerov2alpha1.CSISnapshotSpec{Driver: "rbd.csi.ceph.com", SnapshotClass: "retain-class"}
			if tc.mutate != nil {
				tc.mutate(du)
			}
			backup := builder.ForBackup("velero", "daily-backup").StorageLocation("default").Result()

			require.NoError(t, action.Execute(&velero.DeleteItemActionExecuteInput{Item: toUnstructured(t, du), Backup: backup}))

			cms := &corev1api.ConfigMapList{}
			require.NoError(t, crClient.List(t.Context(), cms, crclient.MatchingLabels{velerov1.DataUploadRetainedSnapshotLabel: "true"}))
			if tc.wantData == nil {
				assert.Empty(t, cms.Items)
				return
			}
			require.Len(t, cms.Items, 1)
			assert.Equal(t, "daily-backup-abcde-retained-snapshot", cms.Items[0].Name)
			assert.Equal(t, tc.wantData, cms.Items[0].Data)
		})
	}
}
