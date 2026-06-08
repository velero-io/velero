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

package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	storagev1api "k8s.io/api/storage/v1"
	storagev1 "k8s.io/client-go/kubernetes/typed/storage/v1"
)

const (
	waitInternal = 2 * time.Second
)

// DeletePVAndPVCIfAny deletes PVC and delete the bound PV if it exists and log an error when the deletion fails.
// It first sets the reclaim policy of the PV to Delete, then PV will be deleted automatically when PVC is deleted.
// If ensureTimeout is not 0, it waits until the PVC is deleted or timeout.
func DeletePVAndPVCIfAny(ctx context.Context, client corev1client.CoreV1Interface, pvcName, pvcNamespace string, ensureTimeout time.Duration, log logrus.FieldLogger) {
	pvcObj, err := client.PersistentVolumeClaims(pvcNamespace).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Debugf("Abort deleting PV and PVC, for related PVC doesn't exist, %s/%s", pvcNamespace, pvcName)
			return
		} else {
			log.Warnf("failed to get pvc %s/%s with err %v", pvcNamespace, pvcName, err)
			return
		}
	}

	if pvcObj.Spec.VolumeName == "" {
		log.Warnf("failed to delete PV, for related PVC %s/%s has no bind volume name", pvcNamespace, pvcName)
	} else {
		pvObj, err := client.PersistentVolumes().Get(ctx, pvcObj.Spec.VolumeName, metav1.GetOptions{})
		if err != nil {
			log.Warnf("failed to delete PV %s with err %v", pvcObj.Spec.VolumeName, err)
		} else {
			_, err = SetPVReclaimPolicy(ctx, client, pvObj, corev1api.PersistentVolumeReclaimDelete)
			if err != nil {
				log.Warnf("failed to set reclaim policy of PV %s to delete with err %v", pvObj.Name, err)
			}
		}
	}

	if err := EnsureDeletePVC(ctx, client, pvcName, pvcNamespace, ensureTimeout); err != nil {
		log.Warnf("failed to delete pvc %s/%s with err %v", pvcNamespace, pvcName, err)
	}

	if err := EnsurePVDeleted(ctx, client, pvcObj.Spec.VolumeName, ensureTimeout); err != nil {
		log.Warnf("pv %s was not removed with err %v", pvcObj.Spec.VolumeName, err)
	}
}

// WaitPVCBound wait for binding of a PVC specified by name and returns the bound PV object
func WaitPVCBound(ctx context.Context, pvcGetter corev1client.CoreV1Interface,
	pvGetter corev1client.CoreV1Interface, pvc string, namespace string, timeout time.Duration) (*corev1api.PersistentVolume, error) {
	var updated *corev1api.PersistentVolumeClaim
	err := wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		tmpPVC, err := pvcGetter.PersistentVolumeClaims(namespace).Get(ctx, pvc, metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrapf(err, "error to get pvc %s/%s", namespace, pvc)
		}

		if tmpPVC.Spec.VolumeName == "" {
			return false, nil
		}

		updated = tmpPVC

		return true, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "error to wait for rediness of PVC")
	}

	pv, err := pvGetter.PersistentVolumes().Get(ctx, updated.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error to get PV")
	}

	return pv, err
}

// DeletePVIfAny deletes a PV by name if it exists, and log an error when the deletion fails
func DeletePVIfAny(ctx context.Context, pvGetter corev1client.CoreV1Interface, pvName string, log logrus.FieldLogger) {
	err := pvGetter.PersistentVolumes().Delete(ctx, pvName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Debugf("Abort deleting PV, it doesn't exist, %s", pvName)
		} else {
			log.WithError(err).Errorf("Failed to delete PV %s", pvName)
		}
	}
}

// EnsureDeletePVC asserts the existence of a PVC by name, deletes it and waits for its disappearance and returns errors on any failure
// If timeout is 0, it doesn't wait and return nil
func EnsureDeletePVC(ctx context.Context, pvcGetter corev1client.CoreV1Interface, pvcName string, namespace string, timeout time.Duration) error {
	err := pvcGetter.PersistentVolumeClaims(namespace).Delete(ctx, pvcName, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "error to delete pvc %s", pvcName)
	}

	if timeout == 0 {
		return nil
	}

	var updated *corev1api.PersistentVolumeClaim
	err = wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		pvc, err := pvcGetter.PersistentVolumeClaims(namespace).Get(ctx, pvcName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			return false, errors.Wrapf(err, "error to get pvc %s", pvcName)
		}

		updated = pvc
		return false, nil
	})

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Errorf("timeout to assure pvc %s is deleted, finalizers in pvc %v", pvcName, updated.Finalizers)
		} else {
			return errors.Wrapf(err, "error to ensure pvc deleted for %s", pvcName)
		}
	}

	return nil
}

// EnsurePVDeleted ensures a PV has been deleted. This function is supposed to be called after EnsureDeletePVC
// If timeout is 0, it doesn't wait and return nil
func EnsurePVDeleted(ctx context.Context, pvGetter corev1client.CoreV1Interface, pvName string, timeout time.Duration) error {
	if timeout == 0 {
		return nil
	}

	err := wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		_, err := pvGetter.PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			return false, errors.Wrapf(err, "error to get pv %s", pvName)
		}

		return false, nil
	})

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Errorf("timeout to assure pv %s is deleted", pvName)
		} else {
			return errors.Wrapf(err, "error to ensure pv is deleted for %s", pvName)
		}
	}

	return nil
}

// RebindPVC rebinds a PVC by modifying its VolumeName to the specific PV
func RebindPVC(ctx context.Context, pvcGetter corev1client.CoreV1Interface,
	pvc *corev1api.PersistentVolumeClaim, pv string) (*corev1api.PersistentVolumeClaim, error) {
	origBytes, err := json.Marshal(pvc)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling original PVC")
	}

	updated := pvc.DeepCopy()
	updated.Spec.VolumeName = pv
	delete(updated.Annotations, KubeAnnBindCompleted)
	delete(updated.Annotations, KubeAnnBoundByController)

	updatedBytes, err := json.Marshal(updated)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling updated PV")
	}

	patchBytes, err := jsonpatch.CreateMergePatch(origBytes, updatedBytes)
	if err != nil {
		return nil, errors.Wrap(err, "error creating json merge patch for PV")
	}

	updated, err = pvcGetter.PersistentVolumeClaims(pvc.Namespace).Patch(ctx, pvc.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error patching PVC")
	}

	return updated, nil
}

// ResetPVBinding resets the binding info of a PV and adds the required labels so as to make it ready for binding
func ResetPVBinding(ctx context.Context, pvGetter corev1client.CoreV1Interface, pv *corev1api.PersistentVolume,
	labels map[string]string, pvc *corev1api.PersistentVolumeClaim) (*corev1api.PersistentVolume, error) {
	origBytes, err := json.Marshal(pv)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling original PV")
	}

	updated := pv.DeepCopy()
	updated.Spec.ClaimRef = &corev1api.ObjectReference{
		Kind:      pvc.Kind,
		Namespace: pvc.Namespace,
		Name:      pvc.Name,
	}
	delete(updated.Annotations, KubeAnnBoundByController)

	if labels != nil {
		if updated.Labels == nil {
			updated.Labels = make(map[string]string)
		}

		for k, v := range labels {
			if _, ok := updated.Labels[k]; !ok {
				updated.Labels[k] = v
			}
		}
	}

	updatedBytes, err := json.Marshal(updated)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling updated PV")
	}

	patchBytes, err := jsonpatch.CreateMergePatch(origBytes, updatedBytes)
	if err != nil {
		return nil, errors.Wrap(err, "error creating json merge patch for PV")
	}

	updated, err = pvGetter.PersistentVolumes().Patch(ctx, pv.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error patching PV")
	}

	return updated, nil
}

// SetPVReclaimPolicy sets the specified reclaim policy to a PV
func SetPVReclaimPolicy(ctx context.Context, pvGetter corev1client.CoreV1Interface, pv *corev1api.PersistentVolume,
	policy corev1api.PersistentVolumeReclaimPolicy) (*corev1api.PersistentVolume, error) {
	if pv.Spec.PersistentVolumeReclaimPolicy == policy {
		return nil, nil
	}

	origBytes, err := json.Marshal(pv)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling original PV")
	}

	updated := pv.DeepCopy()
	updated.Spec.PersistentVolumeReclaimPolicy = policy

	updatedBytes, err := json.Marshal(updated)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling updated PV")
	}

	patchBytes, err := jsonpatch.CreateMergePatch(origBytes, updatedBytes)
	if err != nil {
		return nil, errors.Wrap(err, "error creating json merge patch for PV")
	}

	updated, err = pvGetter.PersistentVolumes().Patch(ctx, pv.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error patching PV")
	}

	return updated, nil
}

// WaitPVCConsumed waits for a PVC to be consumed by a pod so that the selected node is set by the pod scheduling; or does
// nothing if the consuming doesn't affect the PV provision.
// The latest PVC and the selected node will be returned.
func WaitPVCConsumed(
	ctx context.Context,
	pvcGetter corev1client.CoreV1Interface,
	pvc string, namespace string,
	storageClient storagev1.StorageV1Interface,
	timeout time.Duration,
	ignoreConsume bool,
) (string, *corev1api.PersistentVolumeClaim, error) {
	selectedNode := ""
	var updated *corev1api.PersistentVolumeClaim
	var storageClass *storagev1api.StorageClass

	err := wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		tmpPVC, err := pvcGetter.PersistentVolumeClaims(namespace).Get(ctx, pvc, metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrapf(err, "error to get pvc %s/%s", namespace, pvc)
		}

		if !ignoreConsume {
			if tmpPVC.Spec.StorageClassName != nil && storageClass == nil {
				storageClass, err = storageClient.StorageClasses().Get(ctx, *tmpPVC.Spec.StorageClassName, metav1.GetOptions{})
				if err != nil {
					return false, errors.Wrapf(err, "error to get storage class %s", *tmpPVC.Spec.StorageClassName)
				}
			}

			if storageClass != nil {
				if storageClass.VolumeBindingMode != nil && *storageClass.VolumeBindingMode == storagev1api.VolumeBindingWaitForFirstConsumer {
					selectedNode = tmpPVC.Annotations[KubeAnnSelectedNode]
					if selectedNode == "" {
						return false, nil
					}
				}
			}
		}

		updated = tmpPVC

		return true, nil
	})

	if err != nil {
		return "", nil, errors.Wrap(err, "error to wait for PVC")
	}

	return selectedNode, updated, err
}

// WaitPVBound wait for binding of a PV specified by name and returns the bound PV object
func WaitPVBound(ctx context.Context, pvGetter corev1client.CoreV1Interface, pvName string, pvcName string, pvcNamespace string, timeout time.Duration) (*corev1api.PersistentVolume, error) {
	var updated *corev1api.PersistentVolume
	err := wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		tmpPV, err := pvGetter.PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrapf(err, "failed to get pv %s", pvName)
		}

		if tmpPV.Spec.ClaimRef == nil {
			return false, nil
		}

		if tmpPV.Status.Phase != corev1api.VolumeBound {
			return false, nil
		}

		if tmpPV.Spec.ClaimRef.Name != pvcName {
			return false, errors.Errorf("pv has been bound by unexpected pvc %s/%s", tmpPV.Spec.ClaimRef.Namespace, tmpPV.Spec.ClaimRef.Name)
		}

		if tmpPV.Spec.ClaimRef.Namespace != pvcNamespace {
			return false, errors.Errorf("pv has been bound by unexpected pvc %s/%s", tmpPV.Spec.ClaimRef.Namespace, tmpPV.Spec.ClaimRef.Name)
		}

		updated = tmpPV

		return true, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "error to wait for bound of PV")
	} else {
		return updated, nil
	}
}

// IsPVCBound returns true if the specified PVC has been bound
func IsPVCBound(pvc *corev1api.PersistentVolumeClaim) bool {
	return pvc.Spec.VolumeName != ""
}

// MakePodPVCAttachment returns the volume mounts and devices for a pod needed to attach a PVC
func MakePodPVCAttachment(volumeName string, volumeMode *corev1api.PersistentVolumeMode, readOnly bool) ([]corev1api.VolumeMount, []corev1api.VolumeDevice, string) {
	var volumeMounts []corev1api.VolumeMount
	var volumeDevices []corev1api.VolumeDevice
	volumePath := "/" + volumeName

	if volumeMode != nil && *volumeMode == corev1api.PersistentVolumeBlock {
		volumeDevices = []corev1api.VolumeDevice{{
			Name:       volumeName,
			DevicePath: volumePath,
		}}
	} else {
		volumeMounts = []corev1api.VolumeMount{{
			Name:      volumeName,
			MountPath: volumePath,
			ReadOnly:  readOnly,
		}}
	}

	return volumeMounts, volumeDevices, volumePath
}

// GetPVForPVC returns the PersistentVolume backing a PVC
// returns PV, error.
// PV will be nil on error
func GetPVForPVC(
	pvc *corev1api.PersistentVolumeClaim,
	crClient crclient.Client,
) (*corev1api.PersistentVolume, error) {
	if pvc.Spec.VolumeName == "" {
		return nil, errors.Errorf("PVC %s/%s has no volume backing this claim", pvc.Namespace, pvc.Name)
	}
	if pvc.Status.Phase != corev1api.ClaimBound {
		return nil, errors.Errorf("PVC %s/%s is in phase %v and is not bound to a volume",
			pvc.Namespace, pvc.Name, pvc.Status.Phase)
	}

	pv := &corev1api.PersistentVolume{}
	err := crClient.Get(
		context.TODO(),
		crclient.ObjectKey{Name: pvc.Spec.VolumeName},
		pv,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get PV %s for PVC %s/%s",
			pvc.Spec.VolumeName, pvc.Namespace, pvc.Name)
	}
	return pv, nil
}

func GetPVCForPodVolume(vol *corev1api.Volume, pod *corev1api.Pod, crClient crclient.Client) (*corev1api.PersistentVolumeClaim, error) {
	if vol.PersistentVolumeClaim == nil {
		return nil, errors.Errorf("volume %s/%s has no PVC associated with it", pod.Namespace, vol.Name)
	}
	pvc := &corev1api.PersistentVolumeClaim{}
	err := crClient.Get(
		context.TODO(),
		crclient.ObjectKey{Name: vol.PersistentVolumeClaim.ClaimName, Namespace: pod.Namespace},
		pvc,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get PVC %s for Volume %s/%s",
			vol.PersistentVolumeClaim.ClaimName, pod.Namespace, vol.Name)
	}

	return pvc, nil
}

func DiagnosePVC(pvc *corev1api.PersistentVolumeClaim, events *corev1api.EventList) string {
	var diag strings.Builder
	_, _ = fmt.Fprintf(&diag, "PVC %s/%s, phase %s, binding to %s\n", pvc.Namespace, pvc.Name, pvc.Status.Phase, pvc.Spec.VolumeName)

	if events != nil {
		for _, e := range events.Items {
			if e.InvolvedObject.UID == pvc.UID && e.Type == corev1api.EventTypeWarning {
				_, _ = fmt.Fprintf(&diag, "PVC event reason %s, message %s\n", e.Reason, e.Message)
			}
		}
	}

	return diag.String()
}

func DiagnosePV(pv *corev1api.PersistentVolume) string {
	diag := fmt.Sprintf("PV %s, phase %s, reason %s, message %s\n", pv.Name, pv.Status.Phase, pv.Status.Reason, pv.Status.Message)
	return diag
}

func GetPVCAttachingNodeOS(pvc *corev1api.PersistentVolumeClaim, nodeClient corev1client.CoreV1Interface,
	storageClient storagev1.StorageV1Interface, log logrus.FieldLogger) string {
	var nodeOS string
	var scFsType string

	if pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode == corev1api.PersistentVolumeBlock {
		log.Infof("Use linux node for block mode PVC %s/%s", pvc.Namespace, pvc.Name)
		return NodeOSLinux
	}

	if pvc.Spec.VolumeName == "" {
		log.Warnf("PVC %s/%s is not bound to a PV", pvc.Namespace, pvc.Name)
	}

	if pvc.Spec.StorageClassName == nil {
		log.Warnf("PVC %s/%s is not with storage class", pvc.Namespace, pvc.Name)
	}

	nodeName := ""
	if pvc.Spec.VolumeName != "" {
		if n, err := GetPVAttachedNode(context.Background(), pvc.Spec.VolumeName, storageClient); err != nil {
			log.WithError(err).Warnf("Failed to get attached node for PVC %s/%s", pvc.Namespace, pvc.Name)
		} else {
			nodeName = n
		}
	}

	if nodeName == "" {
		if value := pvc.Annotations[KubeAnnSelectedNode]; value != "" {
			nodeName = value
		}
	}

	if nodeName != "" {
		if os, err := GetNodeOS(context.Background(), nodeName, nodeClient); err != nil {
			log.WithError(err).Warnf("Failed to get os from node %s for PVC %s/%s", nodeName, pvc.Namespace, pvc.Name)
		} else {
			nodeOS = os
		}
	}

	if pvc.Spec.StorageClassName != nil {
		if sc, err := storageClient.StorageClasses().Get(context.Background(), *pvc.Spec.StorageClassName, metav1.GetOptions{}); err != nil {
			log.WithError(err).Warnf("Failed to get storage class %s for PVC %s/%s", *pvc.Spec.StorageClassName, pvc.Namespace, pvc.Name)
		} else if sc.Parameters != nil {
			scFsType = strings.ToLower(sc.Parameters["csi.storage.k8s.io/fstype"])
		}
	}

	if nodeOS != "" {
		log.Infof("Deduced node os %s from selected/attached node for PVC %s/%s (fsType %s)", nodeOS, pvc.Namespace, pvc.Name, scFsType)
		return nodeOS
	}

	if scFsType == "ntfs" {
		log.Infof("Deduced Windows node os from fsType %s for PVC %s/%s", scFsType, pvc.Namespace, pvc.Name)
		return NodeOSWindows
	}

	if scFsType != "" {
		log.Infof("Deduced linux node os from fsType %s for PVC %s/%s", scFsType, pvc.Namespace, pvc.Name)
		return NodeOSLinux
	}

	log.Warnf("Cannot deduce node os for PVC %s/%s, default to linux", pvc.Namespace, pvc.Name)
	return NodeOSLinux
}

func GetPVAttachedNode(ctx context.Context, pv string, storageClient storagev1.StorageV1Interface) (string, error) {
	vaList, err := storageClient.VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "error listing volumeattachment")
	}

	for _, va := range vaList.Items {
		if va.Spec.Source.PersistentVolumeName != nil && *va.Spec.Source.PersistentVolumeName == pv {
			return va.Spec.NodeName, nil
		}
	}

	return "", nil
}

func GetPVAttachedNodes(ctx context.Context, pv string, storageClient storagev1.StorageV1Interface) ([]string, error) {
	vaList, err := storageClient.VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error listing volumeattachment")
	}

	nodes := []string{}
	for _, va := range vaList.Items {
		if va.Spec.Source.PersistentVolumeName != nil && *va.Spec.Source.PersistentVolumeName == pv {
			nodes = append(nodes, va.Spec.NodeName)
		}
	}

	return nodes, nil
}

func GetVolumeTopology(ctx context.Context, volumeClient corev1client.CoreV1Interface, storageClient storagev1.StorageV1Interface, pvName string, scName string) (*corev1api.NodeSelector, error) {
	if pvName == "" || scName == "" {
		return nil, errors.Errorf("invalid parameter, pv %s, sc %s", pvName, scName)
	}

	sc, err := storageClient.StorageClasses().Get(ctx, scName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error getting storage class %s", scName)
	}

	if sc.VolumeBindingMode == nil || *sc.VolumeBindingMode != storagev1api.VolumeBindingWaitForFirstConsumer {
		return nil, nil
	}

	pv, err := volumeClient.PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "error getting PV %s", pvName)
	}

	if pv.Spec.NodeAffinity == nil {
		return nil, nil
	}

	return pv.Spec.NodeAffinity.Required, nil
}
