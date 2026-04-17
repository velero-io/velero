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
	"time"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	storagev1api "k8s.io/api/storage/v1"
	storagev1 "k8s.io/client-go/kubernetes/typed/storage/v1"
)

const (
	waitInternal = 2 * time.Second
)

// DeletePVAndPVCIfAny deletes PVC and delete the bound PV if it exists and log an error when the deletion fails
// We first set the reclaim policy of the PV to Delete, then PV will be deleted automatically when PVC is deleted.
func DeletePVAndPVCIfAny(ctx context.Context, client corev1client.CoreV1Interface, pvcName, pvcNamespace string, log logrus.FieldLogger) {
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

	if err := client.PersistentVolumeClaims(pvcNamespace).Delete(ctx, pvcName, metav1.DeleteOptions{}); err != nil {
		log.Warnf("failed to delete pvc %s/%s with err %v", pvcNamespace, pvcName, err)
	}
}

// WaitPVCBound wait for binding of a PVC specified by name and returns the bound PV object
func WaitPVCBound(ctx context.Context, pvcGetter corev1client.CoreV1Interface,
	pvGetter corev1client.CoreV1Interface, pvc string, namespace string, timeout time.Duration) (*corev1api.PersistentVolume, error) {
	var updated *corev1api.PersistentVolumeClaim
	err := wait.PollImmediate(waitInternal, timeout, func() (bool, error) {
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
func EnsureDeletePVC(ctx context.Context, pvcGetter corev1client.CoreV1Interface, pvc string, namespace string, timeout time.Duration) error {
	err := pvcGetter.PersistentVolumeClaims(namespace).Delete(ctx, pvc, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrapf(err, "error to delete pvc %s", pvc)
	}

	err = wait.PollImmediate(waitInternal, timeout, func() (bool, error) {
		_, err := pvcGetter.PersistentVolumeClaims(namespace).Get(ctx, pvc, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			return false, errors.Wrapf(err, "error to get pvc %s", pvc)
		}

		return false, nil
	})

	if err != nil {
		return errors.Wrapf(err, "error to retrieve pvc info for %s", pvc)
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
func WaitPVCConsumed(ctx context.Context, pvcGetter corev1client.CoreV1Interface, pvc string, namespace string,
	storageClient storagev1.StorageV1Interface, timeout time.Duration) (string, *corev1api.PersistentVolumeClaim, error) {
	selectedNode := ""
	var updated *corev1api.PersistentVolumeClaim
	var storageClass *storagev1api.StorageClass
	err := wait.PollImmediate(waitInternal, timeout, func() (bool, error) {
		tmpPVC, err := pvcGetter.PersistentVolumeClaims(namespace).Get(ctx, pvc, metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrapf(err, "error to get pvc %s/%s", namespace, pvc)
		}

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
	err := wait.PollImmediate(waitInternal, timeout, func() (bool, error) {
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
func MakePodPVCAttachment(volumeName string, volumeMode *corev1api.PersistentVolumeMode) ([]corev1api.VolumeMount, []corev1api.VolumeDevice) {
	var volumeMounts []corev1api.VolumeMount = nil
	var volumeDevices []corev1api.VolumeDevice = nil

	if volumeMode != nil && *volumeMode == corev1api.PersistentVolumeBlock {
		volumeDevices = []corev1api.VolumeDevice{{
			Name:       volumeName,
			DevicePath: "/" + volumeName,
		}}
	} else {
		volumeMounts = []corev1api.VolumeMount{{
			Name:      volumeName,
			MountPath: "/" + volumeName,
		}}
	}

	return volumeMounts, volumeDevices
}
