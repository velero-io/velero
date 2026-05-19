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

package csi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotter "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/typed/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/stringptr"
	"github.com/vmware-tanzu/velero/pkg/util/stringslice"
)

const (
	waitInternal                          = 2 * time.Second
	volumeSnapshotContentProtectFinalizer = "velero.io/volume-snapshot-content-protect-finalizer"
)

// WaitVolumeSnapshotReady waits a VS to become ready to use until the timeout reaches
func WaitVolumeSnapshotReady(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	volumeSnapshot string,
	volumeSnapshotNS string,
	timeout time.Duration,
	log logrus.FieldLogger,
) (*snapshotv1api.VolumeSnapshot, error) {
	var updated *snapshotv1api.VolumeSnapshot
	errMessage := sets.NewString()

	err := wait.PollUntilContextTimeout(
		ctx,
		waitInternal,
		timeout,
		true,
		func(ctx context.Context) (bool, error) {
			tmpVS, err := snapshotClient.VolumeSnapshots(volumeSnapshotNS).Get(
				ctx, volumeSnapshot, metav1.GetOptions{})
			if err != nil {
				return false, errors.Wrapf(
					err,
					"error to get VolumeSnapshot %s/%s",
					volumeSnapshotNS, volumeSnapshot,
				)
			}

			if tmpVS.Status == nil {
				return false, nil
			}

			if tmpVS.Status.Error != nil {
				errMessage.Insert(stringptr.GetString(tmpVS.Status.Error.Message))
			}

			if !boolptr.IsSetToTrue(tmpVS.Status.ReadyToUse) {
				return false, nil
			}

			updated = tmpVS
			return true, nil
		},
	)

	if wait.Interrupted(err) {
		err = errors.Errorf(
			"volume snapshot is not ready until timeout, errors: %v",
			errMessage.List(),
		)
	}

	if errMessage.Len() > 0 {
		log.Warnf("Some errors happened during waiting for ready snapshot, errors: %v",
			errMessage.List())
	}

	return updated, err
}

// GetVolumeSnapshotContentForVolumeSnapshot returns the VolumeSnapshotContent
// object associated with the VolumeSnapshot.
func GetVolumeSnapshotContentForVolumeSnapshot(
	volSnap *snapshotv1api.VolumeSnapshot,
	snapshotClient snapshotter.SnapshotV1Interface,
) (*snapshotv1api.VolumeSnapshotContent, error) {
	if volSnap.Status == nil || volSnap.Status.BoundVolumeSnapshotContentName == nil {
		return nil, errors.Errorf("invalid snapshot info in volume snapshot %s", volSnap.Name)
	}

	vsc, err := snapshotClient.VolumeSnapshotContents().Get(
		context.TODO(),
		*volSnap.Status.BoundVolumeSnapshotContentName,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "error getting volume snapshot content from API")
	}

	return vsc, nil
}

// RetainVSC updates the VSC's deletion policy to Retain and then return the update VSC
func RetainVSC(ctx context.Context, snapshotClient snapshotter.SnapshotV1Interface,
	vsc *snapshotv1api.VolumeSnapshotContent) (*snapshotv1api.VolumeSnapshotContent, error) {
	if vsc.Spec.DeletionPolicy == snapshotv1api.VolumeSnapshotContentRetain {
		return vsc, nil
	}

	return patchVSC(ctx, snapshotClient, vsc, func(updated *snapshotv1api.VolumeSnapshotContent) {
		updated.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain
	})
}

// DeleteVolumeSnapshotContentIfAny deletes a VSC by name if it exists,
// and log an error when the deletion fails.
func DeleteVolumeSnapshotContentIfAny(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vscName string, log logrus.FieldLogger,
) {
	err := snapshotClient.VolumeSnapshotContents().Delete(ctx, vscName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Debugf("Abort deleting VSC, it doesn't exist %s", vscName)
		} else {
			log.WithError(err).Errorf("Failed to delete volume snapshot content %s", vscName)
		}
	}
}

// EnsureDeleteVS asserts the existence of a VS by name, deletes it and waits for its
// disappearance and returns errors on any failure.
func EnsureDeleteVS(ctx context.Context, snapshotClient snapshotter.SnapshotV1Interface,
	vsName string, vsNamespace string, timeout time.Duration) error {
	err := snapshotClient.VolumeSnapshots(vsNamespace).Delete(ctx, vsName, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrap(err, "error to delete volume snapshot")
	}

	var updated *snapshotv1api.VolumeSnapshot
	err = wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		vs, err := snapshotClient.VolumeSnapshots(vsNamespace).Get(ctx, vsName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			return false, errors.Wrapf(err, "error to get VolumeSnapshot %s", vsName)
		}

		updated = vs
		return false, nil
	})

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Errorf("timeout to assure VolumeSnapshot %s is deleted, finalizers in VS %v", vsName, updated.Finalizers)
		} else {
			return errors.Wrapf(err, "error to assure VolumeSnapshot is deleted, %s", vsName)
		}
	}

	return nil
}

func RemoveVSCProtect(ctx context.Context, snapshotClient snapshotter.SnapshotV1Interface, vscName string, timeout time.Duration) error {
	err := wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		vsc, err := snapshotClient.VolumeSnapshotContents().Get(ctx, vscName, metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrapf(err, "error to get VolumeSnapshotContent %s", vscName)
		}

		vsc.Finalizers = stringslice.Except(vsc.Finalizers, volumeSnapshotContentProtectFinalizer)

		_, err = snapshotClient.VolumeSnapshotContents().Update(ctx, vsc, metav1.UpdateOptions{})
		if err == nil {
			return true, nil
		}

		if !apierrors.IsConflict(err) {
			return false, errors.Wrapf(err, "error to update VolumeSnapshotContent %s", vscName)
		}

		return false, nil
	})

	return err
}

// EnsureDeleteVSC asserts the existence of a VSC by name, deletes it and waits for its
// disappearance and returns errors on any failure.
func EnsureDeleteVSC(ctx context.Context, snapshotClient snapshotter.SnapshotV1Interface,
	vscName string, timeout time.Duration) error {
	err := snapshotClient.VolumeSnapshotContents().Delete(ctx, vscName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "error to delete volume snapshot content")
	}

	var updated *snapshotv1api.VolumeSnapshotContent
	err = wait.PollUntilContextTimeout(ctx, waitInternal, timeout, true, func(ctx context.Context) (bool, error) {
		vsc, err := snapshotClient.VolumeSnapshotContents().Get(ctx, vscName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			return false, errors.Wrapf(err, "error to get VolumeSnapshotContent %s", vscName)
		}

		updated = vsc
		return false, nil
	})

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.Errorf("timeout to assure VolumeSnapshotContent %s is deleted, finalizers in VSC %v", vscName, updated.Finalizers)
		} else {
			return errors.Wrapf(err, "error to assure VolumeSnapshotContent is deleted, %s", vscName)
		}
	}

	return nil
}

// DeleteVolumeSnapshotIfAny deletes a VS by name if it exists,
// and log an error when the deletion fails
func DeleteVolumeSnapshotIfAny(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vsName string,
	vsNamespace string,
	log logrus.FieldLogger,
) {
	err := snapshotClient.VolumeSnapshots(vsNamespace).Delete(ctx, vsName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Debugf(
				"Abort deleting volume snapshot, it doesn't exist %s/%s",
				vsNamespace, vsName)
		} else {
			log.WithError(err).Errorf(
				"Failed to delete volume snapshot %s/%s", vsNamespace, vsName)
		}
	}
}

func patchVSC(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vsc *snapshotv1api.VolumeSnapshotContent,
	updateFunc func(*snapshotv1api.VolumeSnapshotContent),
) (*snapshotv1api.VolumeSnapshotContent, error) {
	origBytes, err := json.Marshal(vsc)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling original VSC")
	}

	updated := vsc.DeepCopy()
	updateFunc(updated)

	updatedBytes, err := json.Marshal(updated)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling updated VSC")
	}

	patchBytes, err := jsonpatch.CreateMergePatch(origBytes, updatedBytes)
	if err != nil {
		return nil, errors.Wrap(err, "error creating json merge patch for VSC")
	}

	patched, err := snapshotClient.VolumeSnapshotContents().Patch(ctx, vsc.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error patching VSC")
	}

	return patched, nil
}

func GetVolumeSnapshotClass(
	storageClass *storagev1api.StorageClass,
	backup *velerov1api.Backup,
	pvc *corev1api.PersistentVolumeClaim,
	log logrus.FieldLogger,
	crClient crclient.Client,
) (*snapshotv1api.VolumeSnapshotClass, error) {
	snapshotClasses := new(snapshotv1api.VolumeSnapshotClassList)
	err := crClient.List(context.TODO(), snapshotClasses)
	if err != nil {
		return nil, errors.Wrap(err, "error listing VolumeSnapshotClass")
	}
	// If a snapshot class is set for provider in PVC annotations, use that
	snapshotClass, err := GetVolumeSnapshotClassFromPVCAnnotationsForDriver(
		pvc, storageClass.Provisioner, snapshotClasses,
	)
	if err != nil {
		log.Debugf("Didn't find VolumeSnapshotClass from PVC annotations: %v", err)
	}
	if snapshotClass != nil {
		return snapshotClass, nil
	}

	// If there is no annotation in PVC, attempt to fetch it from storageClass annotations
	snapshotClass, err = GetVolumeSnapshotClassFromStorageClassAnnotationsForDriver(storageClass, snapshotClasses)
	if err != nil {
		log.Debugf("Didn't find VolumeSnapshotClass from StorageClass annotations: %v", err)
	}
	if snapshotClass != nil {
		return snapshotClass, nil
	}

	// If there is no annotation in storageClass, attempt to fetch it from backup annotations
	snapshotClass, err = GetVolumeSnapshotClassFromBackupAnnotationsForDriver(
		backup, storageClass.Provisioner, snapshotClasses)
	if err != nil {
		log.Debugf("Didn't find VolumeSnapshotClass from Backup annotations: %v", err)
	}
	if snapshotClass != nil {
		return snapshotClass, nil
	}

	// fallback to default behavior of fetching snapshot class based on label
	snapshotClass, err = GetVolumeSnapshotClassForStorageClass(
		storageClass.Provisioner, snapshotClasses)
	if err != nil || snapshotClass == nil {
		return nil, errors.Wrap(err, "error getting VolumeSnapshotClass")
	}

	return snapshotClass, nil
}

func GetVolumeSnapshotClassFromPVCAnnotationsForDriver(
	pvc *corev1api.PersistentVolumeClaim,
	provisioner string,
	snapshotClasses *snapshotv1api.VolumeSnapshotClassList,
) (*snapshotv1api.VolumeSnapshotClass, error) {
	annotationKey := velerov1api.VolumeSnapshotClassDriverPVCAnnotation
	snapshotClassName, ok := pvc.ObjectMeta.Annotations[annotationKey]
	if !ok {
		return nil, nil
	}
	for _, sc := range snapshotClasses.Items {
		if strings.EqualFold(snapshotClassName, sc.ObjectMeta.Name) {
			if !strings.EqualFold(sc.Driver, provisioner) {
				return nil, errors.Errorf(
					"Incorrect VolumeSnapshotClass %s is not for driver %s",
					sc.ObjectMeta.Name, provisioner,
				)
			}
			return &sc, nil
		}
	}
	return nil, errors.Errorf(
		"No CSI VolumeSnapshotClass found with name %s for provisioner %s for PVC %s",
		snapshotClassName, provisioner, pvc.Name,
	)
}

func GetVolumeSnapshotClassFromStorageClassAnnotationsForDriver(storageClass *storagev1api.StorageClass, snapshotClasses *snapshotv1api.VolumeSnapshotClassList) (*snapshotv1api.VolumeSnapshotClass, error) {
	annotationKey := velerov1api.VolumeSnapshotClassDriverStorageClassAnnotation
	snapshotClassNameFromStorageClassAnnotation, ok := storageClass.ObjectMeta.Annotations[annotationKey]
	if !ok {
		return nil, nil
	}
	for _, sc := range snapshotClasses.Items {
		if strings.EqualFold(snapshotClassNameFromStorageClassAnnotation, sc.ObjectMeta.Name) {
			if !strings.EqualFold(sc.Driver, storageClass.Provisioner) {
				return nil, errors.Errorf("Incorrect volumesnapshotclass, snapshot class %s is not for driver %s", sc.ObjectMeta.Name, storageClass.Provisioner)
			}
			return &sc, nil
		}
	}
	return nil, errors.Errorf("No CSI VolumeSnapshotClass found with name %s for provisioner %s for StorageClass %s", snapshotClassNameFromStorageClassAnnotation, storageClass.Provisioner, storageClass.Name)
}

// GetVolumeSnapshotClassFromAnnotationsForDriver returns a
// VolumeSnapshotClass for the supplied volume provisioner/driver
// name from the annotation of the backup.
func GetVolumeSnapshotClassFromBackupAnnotationsForDriver(
	backup *velerov1api.Backup,
	provisioner string,
	snapshotClasses *snapshotv1api.VolumeSnapshotClassList,
) (*snapshotv1api.VolumeSnapshotClass, error) {
	annotationKey := fmt.Sprintf(
		"%s_%s",
		velerov1api.VolumeSnapshotClassDriverBackupAnnotationPrefix,
		strings.ToLower(provisioner),
	)
	snapshotClassName, ok := backup.ObjectMeta.Annotations[annotationKey]
	if !ok {
		return nil, nil
	}
	for _, sc := range snapshotClasses.Items {
		if strings.EqualFold(snapshotClassName, sc.ObjectMeta.Name) {
			if !strings.EqualFold(sc.Driver, provisioner) {
				return nil, errors.Errorf(
					"Incorrect VolumeSnapshotClass %s is not for driver %s for backup %s",
					sc.ObjectMeta.Name, provisioner, backup.Name,
				)
			}
			return &sc, nil
		}
	}
	return nil, errors.Errorf(
		"No CSI VolumeSnapshotClass found with name %s for driver %s for backup %s",
		snapshotClassName, provisioner, backup.Name,
	)
}

// GetVolumeSnapshotClassForStorageClass returns a VolumeSnapshotClass
// for the supplied volume provisioner/ driver name.
func GetVolumeSnapshotClassForStorageClass(
	provisioner string,
	snapshotClasses *snapshotv1api.VolumeSnapshotClassList,
) (*snapshotv1api.VolumeSnapshotClass, error) {
	n := 0
	var vsClass snapshotv1api.VolumeSnapshotClass
	// We pick the VolumeSnapshotClass that matches the CSI driver name
	// and has a 'velero.io/csi-volumesnapshot-class' label. This allows
	// multiple VolumeSnapshotClasses for the same driver with different
	// values for the other fields in the spec.
	for _, sc := range snapshotClasses.Items {
		_, hasLabelSelector := sc.Labels[velerov1api.VolumeSnapshotClassSelectorLabel]
		if sc.Driver == provisioner {
			n++
			vsClass = sc
			if hasLabelSelector {
				return &sc, nil
			}
		}
	}
	// not found by label, pick by annotation
	for _, sc := range snapshotClasses.Items {
		_, hasDefaultAnnotation := sc.Annotations[velerov1api.VolumeSnapshotClassKubernetesAnnotation]
		if sc.Driver == provisioner {
			vsClass = sc
			if hasDefaultAnnotation {
				return &sc, nil
			}
		}
	}
	// If there's only one volumesnapshotclass for the driver, return it.
	if n == 1 {
		return &vsClass, nil
	}
	return nil, fmt.Errorf(
		"failed to get VolumeSnapshotClass for provisioner %s: "+
			"ensure that the desired VolumeSnapshotClass has the %s label or %s annotation, "+
			"and that its driver matches the StorageClass provisioner",
		provisioner,
		velerov1api.VolumeSnapshotClassSelectorLabel,
		velerov1api.VolumeSnapshotClassKubernetesAnnotation,
	)
}

// IsVolumeSnapshotClassHasListerSecret returns whether a volumesnapshotclass has a snapshotlister secret
func IsVolumeSnapshotClassHasListerSecret(vc *snapshotv1api.VolumeSnapshotClass) bool {
	// https://github.com/kubernetes-csi/external-snapshotter/blob/master/pkg/utils/util.go#L59-L60
	// There is no release w/ these constants exported. Using the strings for now.
	_, nameExists := vc.Annotations[velerov1api.PrefixedListSecretNameAnnotation]
	_, nsExists := vc.Annotations[velerov1api.PrefixedListSecretNamespaceAnnotation]
	return nameExists && nsExists
}

// IsVolumeSnapshotContentHasDeleteSecret returns whether a volumesnapshotcontent has a deletesnapshot secret
func IsVolumeSnapshotContentHasDeleteSecret(vsc *snapshotv1api.VolumeSnapshotContent) bool {
	// https://github.com/kubernetes-csi/external-snapshotter/blob/master/pkg/utils/util.go#L56-L57
	// use exported constants in the next release
	_, nameExists := vsc.Annotations[velerov1api.PrefixedSecretNameAnnotation]
	_, nsExists := vsc.Annotations[velerov1api.PrefixedSecretNamespaceAnnotation]
	return nameExists && nsExists
}

// IsVolumeSnapshotExists returns whether a specific volumesnapshot object exists.
func IsVolumeSnapshotExists(
	ns,
	name string,
	crClient crclient.Client,
) bool {
	vs := new(snapshotv1api.VolumeSnapshot)
	err := crClient.Get(
		context.TODO(),
		crclient.ObjectKey{Namespace: ns, Name: name},
		vs,
	)

	return err == nil
}

func SetVolumeSnapshotContentDeletionPolicy(
	vscName string,
	crClient crclient.Client,
	policy snapshotv1api.DeletionPolicy,
) (*snapshotv1api.VolumeSnapshotContent, error) {
	vsc := new(snapshotv1api.VolumeSnapshotContent)
	if err := crClient.Get(context.TODO(), crclient.ObjectKey{Name: vscName}, vsc); err != nil {
		return nil, err
	}

	originVSC := vsc.DeepCopy()
	vsc.Spec.DeletionPolicy = policy

	return vsc, crClient.Patch(context.TODO(), vsc, crclient.MergeFrom(originVSC))
}

// CleanupVolumeSnapshot deletes the VolumeSnapshot and the associated VolumeSnapshotContent.  It will make sure the
// physical snapshot is also deleted.
func CleanupVolumeSnapshot(
	volSnap *snapshotv1api.VolumeSnapshot,
	crClient crclient.Client,
	log logrus.FieldLogger,
) {
	log.Infof("Deleting Volumesnapshot %s/%s", volSnap.Namespace, volSnap.Name)
	vs := new(snapshotv1api.VolumeSnapshot)
	err := crClient.Get(
		context.TODO(),
		crclient.ObjectKey{Name: volSnap.Name, Namespace: volSnap.Namespace},
		vs,
	)
	if err != nil {
		log.Debugf("Failed to get volumesnapshot %s/%s", volSnap.Namespace, volSnap.Name)
		return
	}

	if vs.Status != nil && vs.Status.BoundVolumeSnapshotContentName != nil {
		// we patch the DeletionPolicy of the VolumeSnapshotContent to set it to Delete.
		// This ensures that the volume snapshot in the storage provider is also deleted.
		_, err := SetVolumeSnapshotContentDeletionPolicy(
			*vs.Status.BoundVolumeSnapshotContentName,
			crClient,
			snapshotv1api.VolumeSnapshotContentDelete,
		)
		if err != nil {
			log.Debugf("Failed to patch DeletionPolicy of volume snapshot %s/%s",
				vs.Namespace, vs.Name)
		}
	}
	err = crClient.Delete(context.TODO(), vs)
	if err != nil {
		log.Debugf("Failed to delete volumesnapshot %s/%s: %v", vs.Namespace, vs.Name, err)
	} else {
		log.Infof("Deleted volumesnapshot with volumesnapshotContent %s/%s",
			vs.Namespace, vs.Name)
	}
}

func DeleteReadyVolumeSnapshot(
	vs snapshotv1api.VolumeSnapshot,
	client crclient.Client,
	logger logrus.FieldLogger,
) {
	logger.Infof("Deleting Volumesnapshot %s/%s", vs.Namespace, vs.Name)
	if vs.Status == nil ||
		vs.Status.BoundVolumeSnapshotContentName == nil ||
		len(*vs.Status.BoundVolumeSnapshotContentName) <= 0 {
		logger.Errorf("VolumeSnapshot %s/%s is not ready. This is not expected.",
			vs.Namespace, vs.Name)
		return
	}

	var vsc *snapshotv1api.VolumeSnapshotContent

	if vs.Status != nil && vs.Status.BoundVolumeSnapshotContentName != nil {
		var err error

		// Patch the DeletionPolicy of the VolumeSnapshotContent to set it to Retain.
		// This ensures that the volume snapshot in the storage provider is kept.
		if vsc, err = SetVolumeSnapshotContentDeletionPolicy(
			*vs.Status.BoundVolumeSnapshotContentName,
			client,
			snapshotv1api.VolumeSnapshotContentRetain,
		); err != nil {
			logger.Warnf("Failed to patch DeletionPolicy of VolumeSnapshot %s/%s",
				vs.Namespace, vs.Name)
			return
		}

		if err := client.Delete(context.TODO(), vsc); err != nil {
			logger.WithError(err).Warnf("Failed to delete the VolumeSnapshotContent %s", vsc.Name)
		}
	}
	if err := client.Delete(context.TODO(), &vs); err != nil {
		logger.WithError(err).Warnf("Failed to delete VolumeSnapshot %s", vs.Namespace+"/"+vs.Name)
	} else {
		logger.Infof("Deleted VolumeSnapshot %s and VolumeSnapshotContent %s",
			vs.Namespace+"/"+vs.Name, vsc.Name)
	}
}

// WaitUntilVSCHandleIsReady returns the VolumeSnapshotContent
// object associated with the volumesnapshot
func WaitUntilVSCHandleIsReady(
	volSnap *snapshotv1api.VolumeSnapshot,
	crClient crclient.Client,
	log logrus.FieldLogger,
	csiSnapshotTimeout time.Duration,
) (*snapshotv1api.VolumeSnapshotContent, error) {
	// We'll wait 10m for the VSC to be reconciled polling
	// every 5s unless backup's csiSnapshotTimeout is set
	interval := 5 * time.Second
	vsc := new(snapshotv1api.VolumeSnapshotContent)

	err := wait.PollUntilContextTimeout(
		context.Background(),
		interval,
		csiSnapshotTimeout,
		true,
		func(ctx context.Context) (bool, error) {
			vs := new(snapshotv1api.VolumeSnapshot)
			if err := crClient.Get(
				ctx,
				crclient.ObjectKeyFromObject(volSnap),
				vs,
			); err != nil {
				return false,
					errors.Wrapf(
						err,
						"failed to get volumesnapshot %s/%s",
						volSnap.Namespace, volSnap.Name,
					)
			}

			if vs.Status == nil || vs.Status.BoundVolumeSnapshotContentName == nil {
				log.Infof("Waiting for CSI driver to reconcile volumesnapshot %s/%s. Retrying in %ds",
					volSnap.Namespace, volSnap.Name, interval/time.Second)
				return false, nil
			}

			if err := crClient.Get(
				ctx,
				crclient.ObjectKey{
					Name: *vs.Status.BoundVolumeSnapshotContentName,
				},
				vsc,
			); err != nil {
				return false,
					errors.Wrapf(
						err,
						"failed to get VolumeSnapshotContent %s for VolumeSnapshot %s/%s",
						*vs.Status.BoundVolumeSnapshotContentName, vs.Namespace, vs.Name,
					)
			}

			// we need to wait for the VolumeSnapshotContent
			// to have a snapshot handle because during restore,
			// we'll use that snapshot handle as the source for
			// the VolumeSnapshotContent so it's statically
			// bound to the existing snapshot.
			if vsc.Status == nil ||
				vsc.Status.SnapshotHandle == nil {
				log.Infof(
					"Waiting for VolumeSnapshotContents %s to have snapshot handle. Retrying in %ds",
					vsc.Name, interval/time.Second)
				if vsc.Status != nil &&
					vsc.Status.Error != nil {
					log.Warnf("VolumeSnapshotContent %s has error: %v",
						vsc.Name, *vsc.Status.Error.Message)
				}
				return false, nil
			}

			return true, nil
		},
	)

	if err != nil {
		if wait.Interrupted(err) {
			if vsc != nil &&
				vsc.Status != nil &&
				vsc.Status.Error != nil {
				log.Errorf(
					"Timed out awaiting reconciliation of VolumeSnapshot, VolumeSnapshotContent %s has error: %v",
					vsc.Name, *vsc.Status.Error.Message)
				return nil,
					errors.Errorf("CSI got timed out with error: %v",
						*vsc.Status.Error.Message)
			} else {
				log.Errorf(
					"Timed out awaiting reconciliation of volumesnapshot %s/%s",
					volSnap.Namespace, volSnap.Name)
			}
		}
		return nil, err
	}

	return vsc, nil
}

func DiagnoseVS(vs *snapshotv1api.VolumeSnapshot, events *corev1api.EventList) string {
	vscName := ""
	readyToUse := false
	errMessage := ""

	if vs.Status != nil {
		if vs.Status.BoundVolumeSnapshotContentName != nil {
			vscName = *vs.Status.BoundVolumeSnapshotContentName
		}

		if vs.Status.ReadyToUse != nil {
			readyToUse = *vs.Status.ReadyToUse
		}

		if vs.Status.Error != nil && vs.Status.Error.Message != nil {
			errMessage = *vs.Status.Error.Message
		}
	}

	var diag strings.Builder
	_, _ = fmt.Fprintf(&diag, "VS %s/%s, bind to %s, readyToUse %v, errMessage %s\n", vs.Namespace, vs.Name, vscName, readyToUse, errMessage)

	if events != nil {
		for _, e := range events.Items {
			if e.InvolvedObject.UID == vs.UID && e.Type == corev1api.EventTypeWarning {
				_, _ = fmt.Fprintf(&diag, "VS event reason %s, message %s\n", e.Reason, e.Message)
			}
		}
	}

	return diag.String()
}

func DiagnoseVSC(vsc *snapshotv1api.VolumeSnapshotContent) string {
	handle := ""
	readyToUse := false
	errMessage := ""

	if vsc.Status != nil {
		if vsc.Status.SnapshotHandle != nil {
			handle = *vsc.Status.SnapshotHandle
		}

		if vsc.Status.ReadyToUse != nil {
			readyToUse = *vsc.Status.ReadyToUse
		}

		if vsc.Status.Error != nil && vsc.Status.Error.Message != nil {
			errMessage = *vsc.Status.Error.Message
		}
	}

	diag := fmt.Sprintf("VSC %s, readyToUse %v, errMessage %s, handle %s\n", vsc.Name, readyToUse, errMessage, handle)

	return diag
}

// GetVSCForVS returns the VolumeSnapshotContent object associated with the VolumeSnapshot.
func GetVSCForVS(
	ctx context.Context,
	vs *snapshotv1api.VolumeSnapshot,
	client crclient.Client,
) (*snapshotv1api.VolumeSnapshotContent, error) {
	if vs.Status == nil || vs.Status.BoundVolumeSnapshotContentName == nil {
		return nil, errors.Errorf("invalid snapshot info in volume snapshot %s", vs.Name)
	}

	vsc := new(snapshotv1api.VolumeSnapshotContent)

	if err := client.Get(
		ctx,
		crclient.ObjectKey{
			Name: *vs.Status.BoundVolumeSnapshotContentName,
		},
		vsc,
	); err != nil {
		return nil, errors.Wrap(err, "error getting volume snapshot content from API")
	}

	return vsc, nil
}
