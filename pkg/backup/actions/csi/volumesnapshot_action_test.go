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
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestVSExecute(t *testing.T) {
	snapshotHandle := "handle"

	tests := []struct {
		name                    string
		backup                  *velerov1api.Backup
		vs                      *snapshotv1api.VolumeSnapshot
		vsc                     *snapshotv1api.VolumeSnapshotContent
		expectedErr             string
		expectedAdditionalItems []velero.ResourceIdentifier
		expectedItemToUpdate    []velero.ResourceIdentifier
	}{
		{
			name: "Normal case",
			backup: builder.ForBackup("velero", "backup").
				Phase(velerov1api.BackupPhaseInProgress).Result(),
			vs: builder.ForVolumeSnapshot("velero", "vs").
				ObjectMeta(builder.WithLabels(
					velerov1api.BackupNameLabel, "backup")).
				VolumeSnapshotClass("class").Status().
				BoundVolumeSnapshotContentName("vsc").Result(),
			vsc: builder.ForVolumeSnapshotContent("vsc").Status(
				&snapshotv1api.VolumeSnapshotContentStatus{
					SnapshotHandle: &snapshotHandle,
				},
			).Result(),
			expectedErr: "",
			expectedAdditionalItems: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.VolumeSnapshotClasses,
					Name:          "class",
				},
				{
					GroupResource: kuberesource.VolumeSnapshotContents,
					Name:          "vsc",
				},
			},
			expectedItemToUpdate: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.VolumeSnapshots,
					Namespace:     "velero",
					Name:          "vs",
				},
				{
					GroupResource: kuberesource.VolumeSnapshotContents,
					Name:          "vsc",
				},
			},
		},
		{
			name: "VS not have VSClass",
			backup: builder.ForBackup("velero", "backup").
				Phase(velerov1api.BackupPhaseInProgress).Result(),
			vs: builder.ForVolumeSnapshot("velero", "vs").
				ObjectMeta(builder.WithLabels(
					velerov1api.BackupNameLabel, "backup")).
				Status().
				BoundVolumeSnapshotContentName("vsc").Result(),
			vsc: builder.ForVolumeSnapshotContent("vsc").Status(
				&snapshotv1api.VolumeSnapshotContentStatus{
					SnapshotHandle: &snapshotHandle,
				},
			).Result(),
			expectedErr: "",
			expectedAdditionalItems: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.VolumeSnapshotContents,
					Name:          "vsc",
				},
			},
			expectedItemToUpdate: []velero.ResourceIdentifier{
				{
					GroupResource: kuberesource.VolumeSnapshots,
					Namespace:     "velero",
					Name:          "vs",
				},
				{
					GroupResource: kuberesource.VolumeSnapshotContents,
					Name:          "vsc",
				},
			},
		},
		{
			name: "Backup in finalizing phase - skip VSC lookup",
			backup: builder.ForBackup("velero", "backup").
				Phase(velerov1api.BackupPhaseFinalizing).Result(),
			vs: builder.ForVolumeSnapshot("velero", "vs").
				ObjectMeta(builder.WithLabels(
					velerov1api.BackupNameLabel, "backup")).
				Status().
				BoundVolumeSnapshotContentName("vsc").Result(),
			vsc:                     nil, // VSC won't be created/fetched
			expectedErr:             "",
			expectedAdditionalItems: nil,
			expectedItemToUpdate:    nil,
		},
		{
			name: "Backup in finalizing partially failed phase - skip VSC lookup",
			backup: builder.ForBackup("velero", "backup").
				Phase(velerov1api.BackupPhaseFinalizingPartiallyFailed).Result(),
			vs: builder.ForVolumeSnapshot("velero", "vs").
				ObjectMeta(builder.WithLabels(
					velerov1api.BackupNameLabel, "backup")).
				Status().
				BoundVolumeSnapshotContentName("vsc").Result(),
			vsc:                     nil, // VSC won't be created/fetched
			expectedErr:             "",
			expectedAdditionalItems: nil,
			expectedItemToUpdate:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			vsBIA := volumeSnapshotBackupItemAction{
				log:      logrus.New(),
				crClient: velerotest.NewFakeControllerRuntimeClient(t, tc.vs),
			}

			item, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.vs)
			require.NoError(t, err)

			if tc.vsc != nil {
				require.NoError(t, vsBIA.crClient.Create(t.Context(), tc.vsc))
			}

			_, additionalItems, _, itemToUpdate, err := vsBIA.Execute(&unstructured.UnstructuredList{Object: item}, tc.backup)
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.expectedErr, err.Error())
			}

			require.ElementsMatch(t, tc.expectedAdditionalItems, additionalItems)
			require.ElementsMatch(t, tc.expectedItemToUpdate, itemToUpdate)
		})
	}
}

func TestVSProgress(t *testing.T) {
	errorStr := "error"
	readyToUse := true
	tests := []struct {
		name             string
		backup           *velerov1api.Backup
		vs               *snapshotv1api.VolumeSnapshot
		vsc              *snapshotv1api.VolumeSnapshotContent
		operationID      string
		expectedErr      bool
		expectedProgress *velero.OperationProgress
	}{
		{
			name:        "Empty OperationID",
			operationID: "",
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: true,
		},
		{
			name:        "OperationID doesn't have slash",
			operationID: "invalid",
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: true,
		},
		{
			name:        "OperationID doesn't have valid timestamp",
			operationID: "ns/name/invalid",
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: true,
		},
		{
			name:        "OperationID represents VS does not exist",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: true,
		},
		{
			name:        "VS status is nil",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs:          builder.ForVolumeSnapshot("ns", "name").Result(),
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: false,
		},
		{
			name:        "VS status has error, no prior annotation, no CSISnapshotErrorTimeout configured",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				StatusError(snapshotv1api.VolumeSnapshotError{
					Message: &errorStr,
				}).Result(),
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: false,
		},
		{
			name:        "VS status has error, within CSISnapshotErrorTimeout (recent start time)",
			operationID: "ns/name/" + time.Now().Format(time.RFC3339),
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				StatusError(snapshotv1api.VolumeSnapshotError{
					Message: &errorStr,
				}).Result(),
			backup:      builder.ForBackup("velero", "backup").CSISnapshotErrorTimeout(10 * time.Minute).Result(),
			expectedErr: false,
		},
		{
			name:        "VS status has persistent error beyond CSISnapshotErrorTimeout",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				StatusError(snapshotv1api.VolumeSnapshotError{
					Message: &errorStr,
				}).Result(),
			backup:      builder.ForBackup("velero", "backup").CSISnapshotErrorTimeout(10 * time.Minute).Result(),
			expectedErr: false,
			expectedProgress: &velero.OperationProgress{
				Completed: true,
				Err:       fmt.Sprintf("VolumeSnapshot ns/name has a persistent error: %s", errorStr),
			},
		},
		{
			name:        "Fail to get VSC",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				ReadyToUse(true).BoundVolumeSnapshotContentName("vsc").Result(),
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: true,
		},
		{
			name:        "VSC status is nil",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				ReadyToUse(true).BoundVolumeSnapshotContentName("vsc").Result(),
			vsc:         builder.ForVolumeSnapshotContent("vsc").Result(),
			backup:      builder.ForBackup("velero", "backup").Result(),
			expectedErr: false,
		},
		{
			name:        "VSC is ReadyToUse",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				ReadyToUse(true).BoundVolumeSnapshotContentName("vsc").Result(),
			vsc: builder.ForVolumeSnapshotContent("vsc").
				Status(&snapshotv1api.VolumeSnapshotContentStatus{
					ReadyToUse: &readyToUse,
				}).Result(),
			backup:           builder.ForBackup("velero", "backup").Result(),
			expectedErr:      false,
			expectedProgress: &velero.OperationProgress{Completed: true},
		},
		{
			name:        "VSC status has error within CSISnapshotErrorTimeout",
			operationID: "ns/name/" + time.Now().Format(time.RFC3339),
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				ReadyToUse(true).BoundVolumeSnapshotContentName("vsc").Result(),
			vsc: builder.ForVolumeSnapshotContent("vsc").
				Status(&snapshotv1api.VolumeSnapshotContentStatus{
					Error: &snapshotv1api.VolumeSnapshotError{
						Message: &errorStr,
					},
				}).Result(),
			backup:      builder.ForBackup("velero", "backup").CSISnapshotErrorTimeout(10 * time.Minute).Result(),
			expectedErr: false,
		},
		{
			name:        "VSC status has persistent error beyond CSISnapshotErrorTimeout",
			operationID: "ns/name/2024-04-11T18:49:00+08:00",
			vs: builder.ForVolumeSnapshot("ns", "name").Status().
				ReadyToUse(true).BoundVolumeSnapshotContentName("vsc").Result(),
			vsc: builder.ForVolumeSnapshotContent("vsc").
				Status(&snapshotv1api.VolumeSnapshotContentStatus{
					Error: &snapshotv1api.VolumeSnapshotError{
						Message: &errorStr,
					},
				}).Result(),
			backup:      builder.ForBackup("velero", "backup").CSISnapshotErrorTimeout(10 * time.Minute).Result(),
			expectedErr: false,
			expectedProgress: &velero.OperationProgress{
				Completed: true,
				Err:       fmt.Sprintf("VolumeSnapshotContent vsc has a persistent error: %s", errorStr),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(*testing.T) {
			crClient := velerotest.NewFakeControllerRuntimeClient(t)
			logger := logrus.New()

			vsBIA := volumeSnapshotBackupItemAction{
				log:      logger,
				crClient: crClient,
			}

			if tc.vs != nil {
				err := crClient.Create(t.Context(), tc.vs)
				require.NoError(t, err)
			}

			if tc.vsc != nil {
				require.NoError(t, crClient.Create(t.Context(), tc.vsc))
			}

			progress, err := vsBIA.Progress(tc.operationID, tc.backup)
			if tc.expectedErr == false {
				require.NoError(t, err)
			}

			if tc.expectedProgress != nil {
				require.True(
					t,
					cmp.Equal(
						*tc.expectedProgress,
						progress,
						cmpopts.IgnoreFields(
							velero.OperationProgress{},
							"Started",
							"Updated",
						),
					),
				)
			}
		})
	}
}

func TestVSAppliesTo(t *testing.T) {
	p := volumeSnapshotBackupItemAction{
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

func TestNewVolumeSnapshotBackupItemAction(t *testing.T) {
	logger := logrus.StandardLogger()
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("KubebuilderClient").Return(nil, fmt.Errorf(""))
	plugin := NewVolumeSnapshotBackupItemAction(f)
	_, err := plugin(logger)
	require.Error(t, err)

	f1 := &factorymocks.Factory{}
	f1.On("KubebuilderClient").Return(crClient, nil)
	plugin1 := NewVolumeSnapshotBackupItemAction(f1)
	_, err1 := plugin1(logger)
	require.NoError(t, err1)
}
