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

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
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
		name            string
		duName          string
		duOwnerBackup   string // value placed in velero.io/backup-name label on the DataUpload
		executingBackup string // name of the Backup being deleted (input.Backup.Name)
		wantConfigMap   bool
		wantWarn        bool // whether a warn-level log about a foreign DataUpload is expected
	}{
		{
			name:            "DataUpload owned by the executing backup creates a snapshot-info ConfigMap",
			duName:          "daily-backup-abcde",
			duOwnerBackup:   "daily-backup",
			executingBackup: "daily-backup",
			wantConfigMap:   true,
			wantWarn:        false,
		},
		{
			name:            "DataUpload owned by a different backup is skipped and a warning is logged",
			duName:          "daily-backup-abcde",
			duOwnerBackup:   "daily-backup",
			executingBackup: "hourly-backup",
			wantConfigMap:   false,
			wantWarn:        true,
		},
		{
			name:            "DataUpload with no backup-name label falls through (legacy behavior preserved)",
			duName:          "legacy-du",
			duOwnerBackup:   "",
			executingBackup: "some-backup",
			wantConfigMap:   true,
			wantWarn:        false,
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

			// The action must surface foreign-backup DataUploads as warnings so
			// operators who accidentally included the velero namespace in a
			// backup can detect the misconfiguration from logs, instead of
			// having the case silently swallowed.
			var sawForeignWarn bool
			for _, entry := range hook.AllEntries() {
				if entry.Level == logrus.WarnLevel &&
					strings.Contains(entry.Message, "velero namespace") &&
					strings.Contains(entry.Message, tc.duName) {
					sawForeignWarn = true
					break
				}
			}
			assert.Equal(t, tc.wantWarn, sawForeignWarn,
				"unexpected foreign-backup warn log presence (want=%v, got=%v); entries=%v",
				tc.wantWarn, sawForeignWarn, hook.AllEntries())
		})
	}
}
