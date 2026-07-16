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

package podvolume

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/repository"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestGetVolumesRepositoryType(t *testing.T) {
	testCases := []struct {
		name        string
		volumes     map[string]volumeBackupInfo
		expected    string
		expectedErr string
		prefixOnly  bool
	}{
		{
			name:        "empty volume",
			expectedErr: "empty volume list",
		},
		{
			name: "empty repository type, first one",
			volumes: map[string]volumeBackupInfo{
				"volume1": {"fake-snapshot-id-1", 0, "fake-uploader-1", ""},
				"volume2": {"", 0, "", "fake-type"},
			},
			expectedErr: "empty repository type found among volume snapshots, snapshot ID fake-snapshot-id-1, uploader fake-uploader-1",
		},
		{
			name: "empty repository type, last one",
			volumes: map[string]volumeBackupInfo{
				"volume1": {"", 0, "", "fake-type"},
				"volume2": {"", 0, "", "fake-type"},
				"volume3": {"fake-snapshot-id-3", 0, "fake-uploader-3", ""},
			},
			expectedErr: "empty repository type found among volume snapshots, snapshot ID fake-snapshot-id-3, uploader fake-uploader-3",
		},
		{
			name: "empty repository type, middle one",
			volumes: map[string]volumeBackupInfo{
				"volume1": {"", 0, "", "fake-type"},
				"volume2": {"fake-snapshot-id-2", 0, "fake-uploader-2", ""},
				"volume3": {"", 0, "", "fake-type"},
			},
			expectedErr: "empty repository type found among volume snapshots, snapshot ID fake-snapshot-id-2, uploader fake-uploader-2",
		},
		{
			name: "mismatch repository type",
			volumes: map[string]volumeBackupInfo{
				"volume1": {"", 0, "", "fake-type1"},
				"volume2": {"fake-snapshot-id-2", 0, "fake-uploader-2", "fake-type2"},
			},
			prefixOnly:  true,
			expectedErr: "multiple repository type in one backup",
		},
		{
			name: "success",
			volumes: map[string]volumeBackupInfo{
				"volume1": {"", 0, "", "fake-type"},
				"volume2": {"", 0, "", "fake-type"},
				"volume3": {"", 0, "", "fake-type"},
			},
			expected: "fake-type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := getVolumesRepositoryType(tc.volumes)
			assert.Equal(t, tc.expected, actual)

			if err != nil {
				if tc.prefixOnly {
					errMsg := err.Error()
					if len(errMsg) >= len(tc.expectedErr) {
						errMsg = errMsg[0:len(tc.expectedErr)]
					}

					assert.Equal(t, tc.expectedErr, errMsg)
				} else {
					assert.EqualError(t, err, tc.expectedErr)
				}
			}
		})
	}
}

func createNodeAgentDaemonset() *appsv1api.DaemonSet {
	ds := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-agent",
			Namespace: velerov1api.DefaultNamespace,
		},
	}

	return ds
}

func createPVRObj(fail bool, index int) *velerov1api.PodVolumeRestore {
	pvrObj := &velerov1api.PodVolumeRestore{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1api.SchemeGroupVersion.String(),
			Kind:       "PodVolumeRestore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      fmt.Sprintf("fake-pvr-%d", index),
		},
	}

	if fail {
		pvrObj.Status.Phase = velerov1api.PodVolumeRestorePhaseFailed
		pvrObj.Status.Message = "fake-message"
	} else {
		pvrObj.Status.Phase = velerov1api.PodVolumeRestorePhaseCompleted
	}

	return pvrObj
}

type expectError struct {
	err        string
	prefixOnly bool
}

func TestRestorePodVolumes(t *testing.T) {
	scheme := runtime.NewScheme()
	velerov1api.AddToScheme(scheme)
	corev1api.AddToScheme(scheme)

	ctxWithCancel, cancel := context.WithCancel(t.Context())
	defer cancel()

	failedPVR := createPVRObj(true, 1)
	completedPVR := createPVRObj(false, 1)

	tests := []struct {
		name            string
		ctx             context.Context
		bsl             string
		kubeClientObj   []runtime.Object
		ctlClientObj    []runtime.Object
		veleroClientObj []runtime.Object
		veleroReactors  []reactor
		runtimeScheme   *runtime.Scheme
		retPVRs         []*velerov1api.PodVolumeRestore
		pvbs            []*velerov1api.PodVolumeBackup
		restoredPod     *corev1api.Pod
		sourceNamespace string
		errs            []expectError
	}{
		{
			name:        "no volume to restore",
			pvbs:        []*velerov1api.PodVolumeBackup{},
			restoredPod: createPodObj(false, false, false, 1),
		},
		{
			name: "node-agent is not running",
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
				createPVBObj(true, true, 2, "kopia"),
			},
			restoredPod:     createPodObj(false, false, false, 2),
			sourceNamespace: "fake-ns",
			errs: []expectError{
				{
					err: "error to check node agent status: daemonset not found",
				},
			},
		},
		{
			name: "ensure repo fail",
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
				createPVBObj(true, true, 2, "kopia"),
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentDaemonset(),
			},
			restoredPod:     createPodObj(false, false, false, 2),
			sourceNamespace: "fake-ns",
			runtimeScheme:   scheme,
			errs: []expectError{
				{
					err: "wrong parameters, namespace \"fake-ns\", backup storage location \"\", repository type \"kopia\"",
				},
			},
		},
		{
			name: "get pvc fail",
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
				createPVBObj(true, true, 2, "kopia"),
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentDaemonset(),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			restoredPod:     createPodObj(true, true, true, 2),
			sourceNamespace: "fake-ns",
			bsl:             "fake-bsl",
			runtimeScheme:   scheme,
			errs: []expectError{
				{
					err: "error getting persistent volume claim for volume: persistentvolumeclaims \"fake-pvc-1\" not found",
				},
				{
					err: "error getting persistent volume claim for volume: persistentvolumeclaims \"fake-pvc-2\" not found",
				},
			},
		},
		{
			name: "create pvb fail",
			ctx:  ctxWithCancel,
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentDaemonset(),
				createPVCObj(1),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			restoredPod:     createPodObj(true, true, true, 1),
			sourceNamespace: "fake-ns",
			bsl:             "fake-bsl",
			runtimeScheme:   scheme,
			errs: []expectError{
				{
					err: "timed out waiting for all PodVolumeRestores to complete",
				},
			},
		},
		{
			name: "create pvb fail",
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentDaemonset(),
				createPVCObj(1),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			restoredPod:     createPodObj(true, true, true, 1),
			sourceNamespace: "fake-ns",
			bsl:             "fake-bsl",
			runtimeScheme:   scheme,
			retPVRs: []*velerov1api.PodVolumeRestore{
				failedPVR,
			},
			errs: []expectError{
				{
					err: "pod volume restore failed: fake-message",
				},
			},
		},
		{
			name: "node-agent pod is not running",
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentDaemonset(),
				createNodeObj(),
				createPVCObj(1),
				createPodObj(true, true, true, 1),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			restoredPod:     createPodObj(true, true, true, 1),
			sourceNamespace: "fake-ns",
			bsl:             "fake-bsl",
			runtimeScheme:   scheme,
			errs: []expectError{
				{
					err: "node-agent pod is not running in node fake-node-name: daemonset pod not found in node fake-node-name",
				},
			},
		},
		{
			name: "complete",
			pvbs: []*velerov1api.PodVolumeBackup{
				createPVBObj(true, true, 1, "kopia"),
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentDaemonset(),
				createNodeObj(),
				createPVCObj(1),
				createPodObj(true, true, true, 1),
				createNodeAgentPodObj(true),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			restoredPod:     createPodObj(true, true, true, 1),
			sourceNamespace: "fake-ns",
			bsl:             "fake-bsl",
			runtimeScheme:   scheme,
			retPVRs: []*velerov1api.PodVolumeRestore{
				completedPVR,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if test.ctx != nil {
				ctx = test.ctx
			}

			objClient := append(test.ctlClientObj, test.kubeClientObj...)
			objClient = append(objClient, test.veleroClientObj...)

			fakeCRClient := velerotest.NewFakeControllerRuntimeClient(t, objClient...)

			fakeKubeClient := kubefake.NewSimpleClientset(test.kubeClientObj...)
			var kubeClient kubernetes.Interface = fakeKubeClient

			// This test verifies restore behavior itself, not informer sync/watch.
			pvrInformer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &velerov1api.PodVolumeRestore{}, 0, cache.Indexers{})

			ensurer := repository.NewEnsurer(fakeCRClient, velerotest.NewLogger(), time.Millisecond)

			restoreObj := builder.ForRestore(velerov1api.DefaultNamespace, "fake-restore").Result()

			rs := newRestorer(ctx, repository.NewRepoLocker(), ensurer, pvrInformer, kubeClient, fakeCRClient, restoreObj, velerotest.NewLogger())

			go func() {
				if test.ctx != nil {
					time.Sleep(time.Second)
					cancel()
				} else if test.retPVRs != nil {
					time.Sleep(time.Second)
					for _, pvr := range test.retPVRs {
						rs.results[resultsKey(test.restoredPod.Namespace, test.restoredPod.Name)] <- pvr
					}
				}
			}()

			errs := rs.RestorePodVolumes(RestoreData{
				Restore:          restoreObj,
				Pod:              test.restoredPod,
				PodVolumeBackups: test.pvbs,
				SourceNamespace:  test.sourceNamespace,
				BackupLocation:   test.bsl,
			}, volume.NewRestoreVolInfoTracker(restoreObj, logrus.New(), fakeCRClient))

			if errs == nil {
				assert.Nil(t, test.errs)
			} else {
				for i := 0; i < len(errs); i++ {
					if test.errs[i].prefixOnly {
						errMsg := errs[i].Error()
						if len(errMsg) >= len(test.errs[i].err) {
							errMsg = errMsg[0:len(test.errs[i].err)]
						}

						assert.Equal(t, test.errs[i].err, errMsg)
					} else {
						for i := 0; i < len(errs); i++ {
							j := 0
							for ; j < len(test.errs); j++ {
								err := errs[i].Error()
								if err == test.errs[j].err {
									break
								}
							}
							assert.Less(t, j, len(test.errs))
						}
					}
				}
			}
		})
	}
}
