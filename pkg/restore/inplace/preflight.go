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

// Package inplace holds the pre-flight checks for in-place volume data
// restores. The checks must pass before Velero performs any side effect on
// the existing PVC/PV.
package inplace

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/restorehelper"
)

// CheckPVCNotInUse verifies the target PVC is not used by any active pod,
// aligned with the pvc-protection controller semantics: terminal-phase pods
// (Succeeded/Failed) don't block; all other phases do, and terminating pods
// are flagged so the message can hint the user to wait.
//
// Pods gated by this restore's restore-wait init container are exempted: on
// the file system restore path the restored pods must mount the PVC for the
// node-agent to restore the data, and an RWX PVC may be mounted by several of
// them. Such a pod cannot write to the volume since its workload containers
// are blocked until this restore's PodVolumeRestores complete (see
// gatedByThisRestore). Any other pod, including one gated by a different
// restore whose release timing is out of our control, still blocks.
func CheckPVCNotInUse(
	ctx context.Context,
	cli crclient.Client,
	pvc *corev1api.PersistentVolumeClaim,
	restoreUID types.UID,
) error {
	if pvc == nil {
		return errors.New("pvc cannot be nil")
	}

	podList := new(corev1api.PodList)
	if err := cli.List(ctx, podList, &crclient.ListOptions{Namespace: pvc.Namespace}); err != nil {
		return errors.Wrapf(err, "failed to check whether PVC %s/%s is in use: failed to list pods in namespace %s", pvc.Namespace, pvc.Name, pvc.Namespace)
	}

	podsInUse := []string{}
	terminatingOnly := true
	for i := range podList.Items {
		pod := &podList.Items[i]
		if !podUsesPVC(pod, pvc.Name) ||
			pod.Status.Phase == corev1api.PodSucceeded || pod.Status.Phase == corev1api.PodFailed ||
			gatedByThisRestore(pod, restoreUID) {
			continue
		}
		state := string(pod.Status.Phase)
		if pod.DeletionTimestamp != nil {
			state += ", terminating"
		} else {
			terminatingOnly = false
		}
		podsInUse = append(podsInUse, fmt.Sprintf("%s (%s)", pod.Name, state))
	}
	if len(podsInUse) == 0 {
		return nil
	}

	hint := "delete the workloads consuming the PVC and retry"
	if terminatingOnly {
		hint = "the pod(s) are terminating; retry after they are fully removed"
	}
	return errors.Errorf("in-place restore pre-flight check failed, skipping volume data restore: PVC %s/%s is still in use by pod(s) [%s]: %s",
		pvc.Namespace, pvc.Name, strings.Join(podsInUse, ", "), hint)
}

func podUsesPVC(pod *corev1api.Pod, pvcName string) bool {
	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil && vol.PersistentVolumeClaim.ClaimName == pvcName {
			return true
		}
	}
	return false
}

// gatedByThisRestore reports whether the pod is blocked by the restore-wait
// init container injected by this restore, identified by the restore UID in
// the init container's args. Such a pod cannot write to the volume: its
// workload containers won't start until this restore's PodVolumeRestores
// complete and write the done signal. A terminated init container means the
// gate is already open, so the pod is no longer exempted. Pods gated by a
// different restore are not exempted either, since their release timing is
// unrelated to this restore.
func gatedByThisRestore(pod *corev1api.Pod, restoreUID types.UID) bool {
	if restoreUID == "" {
		return false
	}

	idx := -1
	for i, c := range pod.Spec.InitContainers {
		if c.Name == restorehelper.WaitInitContainer {
			if len(c.Args) == 0 || c.Args[0] != string(restoreUID) {
				return false
			}
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}

	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.Name == restorehelper.WaitInitContainer {
			return cs.State.Terminated == nil
		}
	}
	// Statuses not populated yet: the init container hasn't run, so the gate
	// is still closed.
	return true
}

// CheckPVCBoundToBackedUpPV verifies the existing PVC is still bound to the
// same PV it was bound to at backup time. An in-place restore onto a
// different volume is unsafe: an incremental (CBT) restore computes deltas
// against a different volume lineage, and even a full restore would patch and
// write into a volume unrelated to the backup. The PV comparison is skipped
// when the PVC is restored into a different namespace, where it is necessarily
// bound to a different PV (the documented cross-namespace clone-and-restore
// workflow), and when the backed-up PV name is unknown.
func CheckPVCBoundToBackedUpPV(existingPVC *corev1api.PersistentVolumeClaim, backedUpPVName, sourceNamespace string) error {
	if existingPVC == nil {
		return errors.New("existing PVC cannot be nil")
	}
	if existingPVC.Status.Phase != corev1api.ClaimBound {
		return errors.Errorf("in-place restore pre-flight check failed, skipping volume data restore: PVC %s/%s is not bound (phase %s)",
			existingPVC.Namespace, existingPVC.Name, existingPVC.Status.Phase)
	}
	if existingPVC.Namespace != sourceNamespace || backedUpPVName == "" || existingPVC.Spec.VolumeName == backedUpPVName {
		return nil
	}
	return errors.Errorf("in-place restore pre-flight check failed, skipping volume data restore: PVC %s/%s is bound to PV %s, but was bound to PV %s at backup time",
		existingPVC.Namespace, existingPVC.Name, existingPVC.Spec.VolumeName, backedUpPVName)
}
