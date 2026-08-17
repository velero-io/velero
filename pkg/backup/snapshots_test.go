/*
Copyright The Velero Contributors.

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

package backup

import (
	"testing"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/features"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

func TestGetBackupCSIResources(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, snapshotv1api.AddToScheme(scheme))
	require.NoError(t, velerov1api.AddToScheme(scheme))

	tests := []struct {
		name                 string
		backup               *velerov1api.Backup
		csiFeatureEnabled    bool
		existingObjects      []kbclient.Object
		wantSnapshots        int
		wantSnapshotContents int
		wantSnapshotClasses  int
	}{
		{
			name: "SnapshotMoveData is true, skip CSI resources",
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{Name: "test-backup"},
				Spec: velerov1api.BackupSpec{
					SnapshotMoveData: boolptr.True(),
				},
			},
			csiFeatureEnabled: true,
			existingObjects: []kbclient.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vs-1",
						Namespace: "ns-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						VolumeSnapshotClassName: func(s string) *string { return &s }("vsc-class-1"),
					},
				},
				&snapshotv1api.VolumeSnapshotClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-class-1",
					},
				},
			},
			wantSnapshots:        0,
			wantSnapshotContents: 0,
			wantSnapshotClasses:  0,
		},
		{
			name: "CSIFeatureFlag is false, skip CSI resources",
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{Name: "test-backup"},
				Spec: velerov1api.BackupSpec{
					SnapshotMoveData: boolptr.False(),
				},
			},
			csiFeatureEnabled: false,
			existingObjects: []kbclient.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vs-1",
						Namespace: "ns-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						VolumeSnapshotClassName: func(s string) *string { return &s }("vsc-class-1"),
					},
				},
				&snapshotv1api.VolumeSnapshotClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-class-1",
					},
				},
			},
			wantSnapshots:        0,
			wantSnapshotContents: 0,
			wantSnapshotClasses:  0,
		},
		{
			name: "CSIFeatureFlag enabled, retrieve CSI resources",
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{Name: "test-backup"},
				Spec: velerov1api.BackupSpec{
					SnapshotMoveData: boolptr.False(),
				},
			},
			csiFeatureEnabled: true,
			existingObjects: []kbclient.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vs-1",
						Namespace: "ns-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						VolumeSnapshotClassName: func(s string) *string { return &s }("vsc-class-1"),
					},
				},
				&snapshotv1api.VolumeSnapshotClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-class-1",
					},
				},
			},
			wantSnapshots:        1,
			wantSnapshotContents: 1,
			wantSnapshotClasses:  1,
		},
		{
			name: "CSIFeatureFlag enabled, multiple contents referencing same class",
			backup: &velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{Name: "test-backup"},
				Spec: velerov1api.BackupSpec{
					SnapshotMoveData: boolptr.False(),
				},
			},
			csiFeatureEnabled: true,
			existingObjects: []kbclient.Object{
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-1",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						VolumeSnapshotClassName: func(s string) *string { return &s }("vsc-class-1"),
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-2",
						Labels: map[string]string{
							velerov1api.BackupNameLabel: "test-backup",
						},
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						VolumeSnapshotClassName: func(s string) *string { return &s }("vsc-class-1"),
					},
				},
				&snapshotv1api.VolumeSnapshotClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "vsc-class-1",
					},
				},
			},
			wantSnapshots:        0,
			wantSnapshotContents: 2,
			wantSnapshotClasses:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer features.NewFeatureFlagSet()

			if tc.csiFeatureEnabled {
				features.Enable(velerov1api.CSIFeatureFlag)
			} else {
				features.Disable(velerov1api.CSIFeatureFlag)
			}

			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.existingObjects...).Build()
			logger := velerotest.NewLogger()

			snaps, contents, classes := GetBackupCSIResources(client, client, tc.backup, logger)

			assert.Len(t, snaps, tc.wantSnapshots)
			assert.Len(t, contents, tc.wantSnapshotContents)
			assert.Len(t, classes, tc.wantSnapshotClasses)

			// If we expect CSI resources to be pulled, ensure the attempts count was updated on the backup object
			if tc.csiFeatureEnabled && !boolptr.IsSetToTrue(tc.backup.Spec.SnapshotMoveData) {
				assert.Equal(t, tc.wantSnapshots, tc.backup.Status.CSIVolumeSnapshotsAttempted)
			} else {
				assert.Equal(t, 0, tc.backup.Status.CSIVolumeSnapshotsAttempted)
			}
		})
	}
}
