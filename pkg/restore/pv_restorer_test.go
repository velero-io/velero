/*
Copyright 2019 the Velero contributors.

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

package restore

import (
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/internal/volume"
	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	providermocks "github.com/vmware-tanzu/velero/pkg/plugin/velero/mocks/volumesnapshotter/v1"
	vsv1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/volumesnapshotter/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func defaultBackup() *builder.BackupBuilder {
	return builder.ForBackup(api.DefaultNamespace, "backup-1")
}

func TestExecutePVAction_NoSnapshotRestores(t *testing.T) {
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t)
	tests := []struct {
		name            string
		obj             *unstructured.Unstructured
		restore         *api.Restore
		backup          *api.Backup
		volumeSnapshots []*volume.Snapshot
		locations       []*api.VolumeSnapshotLocation
		expectedErr     bool
		expectedErrIs   error
		expectedRes     *unstructured.Unstructured
	}{
		{
			name:        "no name should error",
			obj:         newTestUnstructured().WithMetadata().Unstructured,
			restore:     builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedErr: true,
		},
		{
			name:        "ensure spec.storageClassName is retained",
			obj:         newTestUnstructured().WithName("pv-1").WithAnnotations("a", "b").WithSpec("storageClassName", "someOtherField").Unstructured,
			restore:     builder.ForRestore(api.DefaultNamespace, "").RestorePVs(false).Result(),
			backup:      defaultBackup().Phase(api.BackupPhaseInProgress).Result(),
			expectedRes: newTestUnstructured().WithAnnotations("a", "b").WithName("pv-1").WithSpec("storageClassName", "someOtherField").Unstructured,
		},
		{
			name:        "if backup.spec.snapshotVolumes is false, ignore restore.spec.restorePVs and return early",
			obj:         newTestUnstructured().WithName("pv-1").WithAnnotations("a", "b").WithSpec("claimRef", "storageClassName", "someOtherField").Unstructured,
			restore:     builder.ForRestore(api.DefaultNamespace, "").RestorePVs(true).Result(),
			backup:      defaultBackup().Phase(api.BackupPhaseInProgress).SnapshotVolumes(false).Result(),
			expectedRes: newTestUnstructured().WithName("pv-1").WithAnnotations("a", "b").WithSpec("claimRef", "storageClassName", "someOtherField").Unstructured,
		},
		{
			name:    "restore.spec.restorePVs=false, return early",
			obj:     newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
			restore: builder.ForRestore(api.DefaultNamespace, "").RestorePVs(false).Result(),
			backup:  defaultBackup().Phase(api.BackupPhaseInProgress).Result(),
			volumeSnapshots: []*volume.Snapshot{
				newSnapshot("pv-1", "loc-1", "gp", "az-1", "snap-1", 1000),
			},
			locations: []*api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-1").Result(),
			},
			expectedErr: false,
			expectedRes: newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
		},
		{
			name:    "volumeSnapshots is empty: return early",
			obj:     newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
			restore: builder.ForRestore(api.DefaultNamespace, "").RestorePVs(true).Result(),
			backup:  defaultBackup().Result(),
			locations: []*api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-1").Result(),
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-2").Result(),
			},
			volumeSnapshots: []*volume.Snapshot{},
			expectedRes:     newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
		},
		{
			name:    "volumeSnapshots doesn't have a snapshot for PV: return early",
			obj:     newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
			restore: builder.ForRestore(api.DefaultNamespace, "").RestorePVs(true).Result(),
			backup:  defaultBackup().Result(),
			locations: []*api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-1").Result(),
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-2").Result(),
			},
			volumeSnapshots: []*volume.Snapshot{
				newSnapshot("non-matching-pv-1", "loc-1", "type-1", "az-1", "snap-1", 1),
				newSnapshot("non-matching-pv-2", "loc-2", "type-2", "az-2", "snap-2", 2),
			},
			expectedRes: newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
		},
		{
			name:            "no snapshot and Delete reclaim policy: return errPVNeedsReprovisioning",
			obj:             newTestUnstructured().WithName("pv-1").WithSpec().WithSpecField("persistentVolumeReclaimPolicy", "Delete").Unstructured,
			restore:         builder.ForRestore(api.DefaultNamespace, "").RestorePVs(true).Result(),
			backup:          defaultBackup().Result(),
			volumeSnapshots: []*volume.Snapshot{},
			expectedErr:     true,
			expectedErrIs:   errPVNeedsReprovisioning,
		},
		{
			name:            "no snapshot and Retain reclaim policy: return PV as-is",
			obj:             newTestUnstructured().WithName("pv-1").WithSpec().WithSpecField("persistentVolumeReclaimPolicy", "Retain").Unstructured,
			restore:         builder.ForRestore(api.DefaultNamespace, "").RestorePVs(true).Result(),
			backup:          defaultBackup().Result(),
			volumeSnapshots: []*volume.Snapshot{},
			expectedRes:     newTestUnstructured().WithName("pv-1").WithSpec().WithSpecField("persistentVolumeReclaimPolicy", "Retain").Unstructured,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &pvRestorer{
				logger:         velerotest.NewLogger(),
				restorePVs:     tc.restore.Spec.RestorePVs,
				kbclient:       velerotest.NewFakeControllerRuntimeClient(t),
				volInfoTracker: volume.NewRestoreVolInfoTracker(tc.restore, logrus.New(), fakeClient),
			}
			if tc.backup != nil {
				r.backup = tc.backup
			}

			for _, loc := range tc.locations {
				require.NoError(t, r.kbclient.Create(t.Context(), loc))
			}

			res, err := r.executePVAction(tc.obj)
			switch tc.expectedErr {
			case true:
				assert.Nil(t, res)
				require.Error(t, err)
				if tc.expectedErrIs != nil {
					assert.Equal(t, tc.expectedErrIs, err)
				}
			case false:
				assert.Equal(t, tc.expectedRes, res)
				assert.NoError(t, err)
			}
		})
	}
}

func TestExecutePVAction_SnapshotRestores(t *testing.T) {
	tests := []struct {
		name               string
		obj                *unstructured.Unstructured
		restore            *api.Restore
		backup             *api.Backup
		volumeSnapshots    []*volume.Snapshot
		locations          []*api.VolumeSnapshotLocation
		expectedProvider   string
		expectedSnapshotID string
		expectedVolumeType string
		expectedVolumeAZ   string
		expectedVolumeIOPS *int64
		expectedSnapshot   *volume.Snapshot
	}{
		{
			name:    "backup with a matching volume.Snapshot for PV executes restore",
			obj:     newTestUnstructured().WithName("pv-1").WithSpec().Unstructured,
			restore: builder.ForRestore(api.DefaultNamespace, "").RestorePVs(true).Result(),
			backup:  defaultBackup().Result(),
			locations: []*api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-1").Provider("provider-1").Result(),
				builder.ForVolumeSnapshotLocation(api.DefaultNamespace, "loc-2").Provider("provider-2").Result(),
			},
			volumeSnapshots: []*volume.Snapshot{
				newSnapshot("pv-1", "loc-1", "type-1", "az-1", "snap-1", 1),
				newSnapshot("pv-2", "loc-2", "type-2", "az-2", "snap-2", 2),
			},
			expectedProvider:   "provider-1",
			expectedSnapshotID: "snap-1",
			expectedVolumeType: "type-1",
			expectedVolumeAZ:   "az-1",
			expectedVolumeIOPS: int64Ptr(1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				logger                  = velerotest.NewLogger()
				volumeSnapshotter       = new(providermocks.VolumeSnapshotter)
				volumeSnapshotterGetter = providerToVolumeSnapshotterMap(map[string]vsv1.VolumeSnapshotter{
					tc.expectedProvider: volumeSnapshotter,
				})
				fakeClient = velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
			)

			for _, loc := range tc.locations {
				require.NoError(t, fakeClient.Create(t.Context(), loc))
			}

			r := &pvRestorer{
				logger:                  logger,
				backup:                  tc.backup,
				volumeSnapshots:         tc.volumeSnapshots,
				kbclient:                fakeClient,
				volumeSnapshotterGetter: volumeSnapshotterGetter,
				volInfoTracker:          volume.NewRestoreVolInfoTracker(tc.restore, logger, fakeClient),
			}

			volumeSnapshotter.On("Init", mock.Anything).Return(nil)
			volumeSnapshotter.On("CreateVolumeFromSnapshot", tc.expectedSnapshotID, tc.expectedVolumeType, tc.expectedVolumeAZ, tc.expectedVolumeIOPS).Return("volume-1", nil)
			volumeSnapshotter.On("SetVolumeID", tc.obj, "volume-1").Return(tc.obj, nil)

			_, err := r.executePVAction(tc.obj)
			require.NoError(t, err)

			volumeSnapshotter.AssertExpectations(t)
		})
	}
}

type providerToVolumeSnapshotterMap map[string]vsv1.VolumeSnapshotter

func (g providerToVolumeSnapshotterMap) GetVolumeSnapshotter(provider string) (vsv1.VolumeSnapshotter, error) {
	bs, ok := g[provider]
	if !ok {
		return nil, errors.New("volume snapshotter not found for provider")
	}
	return bs, nil
}

func newSnapshot(pvName, location, volumeType, volumeAZ, snapshotID string, volumeIOPS int64) *volume.Snapshot {
	return &volume.Snapshot{
		Spec: volume.SnapshotSpec{
			PersistentVolumeName: pvName,
			Location:             location,
			VolumeType:           volumeType,
			VolumeAZ:             volumeAZ,
			VolumeIOPS:           &volumeIOPS,
		},
		Status: volume.SnapshotStatus{
			ProviderSnapshotID: snapshotID,
		},
	}
}

func int64Ptr(val int) *int64 {
	r := int64(val)
	return &r
}

type testUnstructured struct {
	*unstructured.Unstructured
}

func newTestUnstructured() *testUnstructured {
	obj := &testUnstructured{
		Unstructured: &unstructured.Unstructured{
			Object: make(map[string]any),
		},
	}

	return obj
}

func (obj *testUnstructured) WithMetadata(fields ...string) *testUnstructured {
	return obj.withMap("metadata", fields...)
}

func (obj *testUnstructured) WithSpec(fields ...string) *testUnstructured {
	if _, found := obj.Object["spec"]; found {
		panic("spec already set - you probably didn't mean to do this twice!")
	}
	return obj.withMap("spec", fields...)
}

func (obj *testUnstructured) WithStatus(fields ...string) *testUnstructured {
	return obj.withMap("status", fields...)
}

func (obj *testUnstructured) WithMetadataField(field string, value any) *testUnstructured {
	return obj.withMapEntry("metadata", field, value)
}

func (obj *testUnstructured) WithSpecField(field string, value any) *testUnstructured {
	return obj.withMapEntry("spec", field, value)
}

func (obj *testUnstructured) WithStatusField(field string, value any) *testUnstructured {
	return obj.withMapEntry("status", field, value)
}

func (obj *testUnstructured) WithAnnotations(fields ...string) *testUnstructured {
	vals := map[string]string{}
	for _, field := range fields {
		vals[field] = "foo"
	}

	return obj.WithAnnotationValues(vals)
}

func (obj *testUnstructured) WithAnnotationValues(fieldVals map[string]string) *testUnstructured {
	annotations := make(map[string]any)
	for field, val := range fieldVals {
		annotations[field] = val
	}

	obj = obj.WithMetadataField("annotations", annotations)

	return obj
}

func (obj *testUnstructured) WithName(name string) *testUnstructured {
	return obj.WithMetadataField("name", name)
}

func (obj *testUnstructured) withMap(name string, fields ...string) *testUnstructured {
	m := make(map[string]any)
	obj.Object[name] = m

	for _, field := range fields {
		m[field] = "foo"
	}

	return obj
}

func (obj *testUnstructured) withMapEntry(mapName, field string, value any) *testUnstructured {
	var m map[string]any

	if res, ok := obj.Unstructured.Object[mapName]; !ok {
		m = make(map[string]any)
		obj.Unstructured.Object[mapName] = m
	} else {
		m = res.(map[string]any)
	}

	m[field] = value

	return obj
}
