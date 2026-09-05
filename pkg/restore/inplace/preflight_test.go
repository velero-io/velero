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

package inplace

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/vmware-tanzu/velero/pkg/restorehelper"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func podUsingPVC(name, pvcName string, phase corev1api.PodPhase, terminating bool) *corev1api.Pod {
	pod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			UID:       types.UID(name + "-uid"),
		},
		Spec: corev1api.PodSpec{
			Volumes: []corev1api.Volume{
				{
					Name: "data",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: pvcName,
						},
					},
				},
			},
		},
		Status: corev1api.PodStatus{Phase: phase},
	}
	if terminating {
		now := metav1.Now()
		pod.DeletionTimestamp = &now
		pod.Finalizers = []string{"fake-finalizer"}
	}
	return pod
}

// gatedPod adds the restore-wait init container (as injected by the
// PodVolumeRestoreAction RIA, carrying the restore UID in args) to the pod.
// terminated simulates the gate having already been released.
func gatedPod(pod *corev1api.Pod, restoreUID string, terminated bool) *corev1api.Pod {
	pod.Spec.InitContainers = append([]corev1api.Container{{
		Name: restorehelper.WaitInitContainer,
		Args: []string{restoreUID},
	}}, pod.Spec.InitContainers...)
	status := corev1api.ContainerStatus{
		Name:  restorehelper.WaitInitContainer,
		State: corev1api.ContainerState{Running: &corev1api.ContainerStateRunning{}},
	}
	if terminated {
		status.State = corev1api.ContainerState{Terminated: &corev1api.ContainerStateTerminated{}}
	}
	pod.Status.InitContainerStatuses = []corev1api.ContainerStatus{status}
	return pod
}

func TestCheckPVCNotInUse(t *testing.T) {
	tests := []struct {
		name          string
		pods          []*corev1api.Pod
		pvc           *corev1api.PersistentVolumeClaim
		restoreUID    types.UID
		expectPass    bool
		expectMessage []string
		expectError   string
	}{
		{
			name:        "nil PVC returns error",
			expectError: "pvc cannot be nil",
		},
		{
			name:       "no pods, check passes",
			expectPass: true,
		},
		{
			name:          "active pod blocks with the delete hint",
			pods:          []*corev1api.Pod{podUsingPVC("pod-1", "pvc-1", corev1api.PodRunning, false)},
			expectMessage: []string{"pod-1 (Running)", "delete the workloads"},
		},
		{
			name:          "unknown-phase pod blocks (node may be unreachable)",
			pods:          []*corev1api.Pod{podUsingPVC("pod-1", "pvc-1", corev1api.PodUnknown, false)},
			expectMessage: []string{"pod-1 (Unknown)"},
		},
		{
			name:          "terminating pod blocks with the wait hint",
			pods:          []*corev1api.Pod{podUsingPVC("pod-1", "pvc-1", corev1api.PodRunning, true)},
			expectMessage: []string{"pod-1 (Running, terminating)", "retry after they are fully removed"},
		},
		{
			name: "terminal-phase pods do not block",
			pods: []*corev1api.Pod{
				podUsingPVC("pod-1", "pvc-1", corev1api.PodSucceeded, false),
				podUsingPVC("pod-2", "pvc-1", corev1api.PodFailed, false),
			},
			expectPass: true,
		},
		{
			name:       "pod using another PVC does not block",
			pods:       []*corev1api.Pod{podUsingPVC("pod-1", "other-pvc", corev1api.PodRunning, false)},
			expectPass: true,
		},
		{
			name: "pods gated by this restore do not block, other pods still do",
			pods: []*corev1api.Pod{
				gatedPod(podUsingPVC("restored-pod-1", "pvc-1", corev1api.PodPending, false), "restore-uid", false),
				gatedPod(podUsingPVC("restored-pod-2", "pvc-1", corev1api.PodPending, false), "restore-uid", false),
				podUsingPVC("other-pod", "pvc-1", corev1api.PodRunning, false),
			},
			restoreUID:    "restore-uid",
			expectMessage: []string{"[other-pod (Running)]"},
		},
		{
			name: "multiple pods gated by this restore pass the check",
			pods: []*corev1api.Pod{
				gatedPod(podUsingPVC("restored-pod-1", "pvc-1", corev1api.PodPending, false), "restore-uid", false),
				gatedPod(podUsingPVC("restored-pod-2", "pvc-1", corev1api.PodPending, false), "restore-uid", false),
			},
			restoreUID: "restore-uid",
			expectPass: true,
		},
		{
			name: "pod gated by a different restore still blocks",
			pods: []*corev1api.Pod{
				gatedPod(podUsingPVC("old-restored-pod", "pvc-1", corev1api.PodPending, false), "old-restore-uid", false),
			},
			restoreUID:    "restore-uid",
			expectMessage: []string{"[old-restored-pod (Pending)]"},
		},
		{
			name: "pod whose restore-wait already terminated still blocks",
			pods: []*corev1api.Pod{
				gatedPod(podUsingPVC("released-pod", "pvc-1", corev1api.PodRunning, false), "restore-uid", true),
			},
			restoreUID:    "restore-uid",
			expectMessage: []string{"[released-pod (Running)]"},
		},
		{
			name: "gated pod without init container status yet passes the check",
			pods: []*corev1api.Pod{
				func() *corev1api.Pod {
					pod := gatedPod(podUsingPVC("new-pod", "pvc-1", corev1api.PodPending, false), "restore-uid", false)
					pod.Status.InitContainerStatuses = nil
					return pod
				}(),
			},
			restoreUID: "restore-uid",
			expectPass: true,
		},
		{
			name: "empty restore UID exempts nothing",
			pods: []*corev1api.Pod{
				gatedPod(podUsingPVC("restored-pod", "pvc-1", corev1api.PodPending, false), "", false),
			},
			restoreUID:    "",
			expectMessage: []string{"[restored-pod (Pending)]"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for _, pod := range tc.pods {
				objs = append(objs, pod)
			}
			cli := velerotest.NewFakeControllerRuntimeClient(t, objs...)

			pvc := tc.pvc
			if pvc == nil && tc.name != "nil PVC returns error" {
				pvc = &corev1api.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: "default"},
				}
			}

			err := CheckPVCNotInUse(t.Context(), cli, pvc, tc.restoreUID)
			if tc.expectError != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.expectError)
				return
			}
			if tc.expectPass {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "pre-flight check failed")
			for _, fragment := range tc.expectMessage {
				assert.Contains(t, err.Error(), fragment)
			}
		})
	}
}

func TestCheckPVCBoundToBackedUpPV(t *testing.T) {
	pvc := func(namespace, pvName string, phase corev1api.PersistentVolumeClaimPhase) *corev1api.PersistentVolumeClaim {
		return &corev1api.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "pvc-1", Namespace: namespace},
			Spec:       corev1api.PersistentVolumeClaimSpec{VolumeName: pvName},
			Status:     corev1api.PersistentVolumeClaimStatus{Phase: phase},
		}
	}

	tests := []struct {
		name           string
		existingPVC    *corev1api.PersistentVolumeClaim
		backedUpPVName string
		expectError    string
	}{
		{
			name:           "nil existing PVC returns error",
			existingPVC:    nil,
			backedUpPVName: "pv-1",
			expectError:    "existing PVC cannot be nil",
		},
		{
			name:           "bound to the backed-up PV, check passes",
			existingPVC:    pvc("default", "pv-1", corev1api.ClaimBound),
			backedUpPVName: "pv-1",
		},
		{
			name:           "bound to a different PV, check fails",
			existingPVC:    pvc("default", "pv-other", corev1api.ClaimBound),
			backedUpPVName: "pv-1",
			expectError:    "is bound to PV pv-other, but was bound to PV pv-1 at backup time",
		},
		{
			name:           "PVC not bound, check fails",
			existingPVC:    pvc("default", "", corev1api.ClaimPending),
			backedUpPVName: "pv-1",
			expectError:    "is not bound (phase Pending)",
		},
		{
			name:           "different PV in a different namespace, check passes",
			existingPVC:    pvc("mapped-ns", "pv-other", corev1api.ClaimBound),
			backedUpPVName: "pv-1",
		},
		{
			name:           "backed-up PV name unknown, check passes",
			existingPVC:    pvc("default", "pv-other", corev1api.ClaimBound),
			backedUpPVName: "",
		},
		{
			name:           "different namespace but PVC not bound, check still fails",
			existingPVC:    pvc("mapped-ns", "", corev1api.ClaimLost),
			backedUpPVName: "pv-1",
			expectError:    "is not bound (phase Lost)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPVCBoundToBackedUpPV(tc.existingPVC, tc.backedUpPVName, "default")
			if tc.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectError)
		})
	}
}
