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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	jsonpatch "github.com/evanphx/json-patch/v5"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotter "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/typed/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/util/boolptr"
	"github.com/velero-io/velero/pkg/util/kube"
	"github.com/velero-io/velero/pkg/util/stringptr"
	"github.com/velero-io/velero/pkg/util/stringslice"
)

const (
	waitInternal                          = 2 * time.Second
	volumeSnapshotContentProtectFinalizer = "velero.io/volume-snapshot-content-protect-finalizer"
	VolumeSnapshotInGroupFinalizer        = "snapshot.storage.kubernetes.io/volumesnapshot-in-group-protection"
	VolumeSnapshotAsSourceFinalizer       = "snapshot.storage.kubernetes.io/volumesnapshot-as-source-protection"
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
	ctx context.Context,
	volSnap *snapshotv1api.VolumeSnapshot,
	snapshotClient snapshotter.SnapshotV1Interface,
) (*snapshotv1api.VolumeSnapshotContent, error) {
	if volSnap.Status == nil || volSnap.Status.BoundVolumeSnapshotContentName == nil {
		return nil, errors.Errorf("invalid snapshot info in volume snapshot %s", volSnap.Name)
	}

	vsc, err := snapshotClient.VolumeSnapshotContents().Get(
		ctx,
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
	vs, err := snapshotClient.VolumeSnapshots(vsNamespace).Get(ctx, vsName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "checking VGS membership before deleting VolumeSnapshot")
	}
	if err == nil && vs.Status != nil && vs.Status.VolumeGroupSnapshotName != nil {
		// The external-snapshotter controller defers member deletion while the
		// parent VGS exists. Terminal VGS cleanup owns this deletion.
		return nil
	}
	err = snapshotClient.VolumeSnapshots(vsNamespace).Delete(ctx, vsName, metav1.DeleteOptions{})
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
			// updated is only set once the VS has been retrieved successfully, so it
			// is still nil when the deadline is exceeded before that happens, e.g.
			// when the first Get times out. No finalizers are available to report.
			if updated == nil {
				return errors.Errorf("timeout to assure VolumeSnapshot %s is deleted", vsName)
			}
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
	vsc, err := snapshotClient.VolumeSnapshotContents().Get(ctx, vscName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "checking VGS membership before deleting VolumeSnapshotContent")
	}
	if err == nil && vsc.Status != nil && vsc.Status.VolumeGroupSnapshotHandle != nil {
		// Group-member content is deleted by terminal VGS cleanup, not through
		// an individual VolumeSnapshotContent deletion.
		return nil
	}
	err = snapshotClient.VolumeSnapshotContents().Delete(ctx, vscName, metav1.DeleteOptions{})
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
			// updated is only set once the VSC has been retrieved successfully, so it
			// is still nil when the deadline is exceeded before that happens, e.g.
			// when the first Get times out. No finalizers are available to report.
			if updated == nil {
				return errors.Errorf("timeout to assure VolumeSnapshotContent %s is deleted", vscName)
			}
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
	vs, err := snapshotClient.VolumeSnapshots(vsNamespace).Get(ctx, vsName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		log.WithError(err).Warnf("Unable to check VGS membership for VolumeSnapshot %s/%s", vsNamespace, vsName)
		return
	}
	if err == nil && vs.Status != nil && vs.Status.VolumeGroupSnapshotName != nil {
		log.Warnf("Deferring deletion of VGS member VolumeSnapshot %s/%s until VGS cleanup", vsNamespace, vsName)
		return
	}
	err = snapshotClient.VolumeSnapshots(vsNamespace).Delete(ctx, vsName, metav1.DeleteOptions{})
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
	ctx context.Context,
	provisioner string,
	backup *velerov1api.Backup,
	pvc *corev1api.PersistentVolumeClaim,
	log logrus.FieldLogger,
	crClient crclient.Client,
	policySnapshotClass string,
) (*snapshotv1api.VolumeSnapshotClass, error) {
	snapshotClasses := new(snapshotv1api.VolumeSnapshotClassList)
	err := crClient.List(ctx, snapshotClasses)
	if err != nil {
		return nil, errors.Wrap(err, "error listing VolumeSnapshotClass")
	}
	// If a snapshot class is set for provider in PVC annotations, use that
	snapshotClass, err := GetVolumeSnapshotClassFromPVCAnnotationsForDriver(
		pvc, provisioner, snapshotClasses,
	)
	if err != nil {
		log.Debugf("Didn't find VolumeSnapshotClass from PVC annotations: %v", err)
	}
	if snapshotClass != nil {
		return snapshotClass, nil
	}

	// If a snapshot class is specified by volume policy, use that
	snapshotClass, err = GetVolumeSnapshotClassFromVolumePolicy(
		policySnapshotClass, provisioner, snapshotClasses)
	if err != nil {
		log.Debugf("Didn't find VolumeSnapshotClass from volume policy: %v", err)
	}
	if snapshotClass != nil {
		return snapshotClass, nil
	}

	// If there is no annotation in PVC, attempt to fetch it from backup annotations
	snapshotClass, err = GetVolumeSnapshotClassFromBackupAnnotationsForDriver(
		backup, provisioner, snapshotClasses)
	if err != nil {
		log.Debugf("Didn't find VolumeSnapshotClass from Backup annotations: %v", err)
	}
	if snapshotClass != nil {
		return snapshotClass, nil
	}

	// fallback to default behavior of fetching snapshot class based on label
	snapshotClass, err = GetVolumeSnapshotClassForStorageClass(
		provisioner, snapshotClasses)
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

// GetVolumeSnapshotClassFromVolumePolicy returns a VolumeSnapshotClass
// specified by a volume policy's snapshotClass parameter. If
// policySnapshotClass is empty, it returns nil (no match).
func GetVolumeSnapshotClassFromVolumePolicy(
	policySnapshotClass string,
	provisioner string,
	snapshotClasses *snapshotv1api.VolumeSnapshotClassList,
) (*snapshotv1api.VolumeSnapshotClass, error) {
	if policySnapshotClass == "" {
		return nil, nil
	}
	for _, sc := range snapshotClasses.Items {
		if strings.EqualFold(policySnapshotClass, sc.ObjectMeta.Name) {
			if !strings.EqualFold(sc.Driver, provisioner) {
				return nil, errors.Errorf(
					"VolumeSnapshotClass %s specified by volume policy is not for driver %s",
					sc.ObjectMeta.Name, provisioner,
				)
			}
			return &sc, nil
		}
	}
	return nil, errors.Errorf(
		"No CSI VolumeSnapshotClass found with name %s specified by volume policy for driver %s",
		policySnapshotClass, provisioner,
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
	ctx context.Context,
	ns,
	name string,
	crClient crclient.Client,
) bool {
	vs := new(snapshotv1api.VolumeSnapshot)
	err := crClient.Get(
		ctx,
		crclient.ObjectKey{Namespace: ns, Name: name},
		vs,
	)

	return err == nil
}

func SetVolumeSnapshotContentDeletionPolicy(
	ctx context.Context,
	vscName string,
	crClient crclient.Client,
	policy snapshotv1api.DeletionPolicy,
) (*snapshotv1api.VolumeSnapshotContent, error) {
	vsc := new(snapshotv1api.VolumeSnapshotContent)
	if err := crClient.Get(ctx, crclient.ObjectKey{Name: vscName}, vsc); err != nil {
		return nil, err
	}

	originVSC := vsc.DeepCopy()
	vsc.Spec.DeletionPolicy = policy

	return vsc, crClient.Patch(ctx, vsc, crclient.MergeFrom(originVSC))
}

// CleanupVolumeSnapshot deletes the VolumeSnapshot and the associated VolumeSnapshotContent.  It will make sure the
// physical snapshot is also deleted.
func CleanupVolumeSnapshot(
	ctx context.Context,
	volSnap *snapshotv1api.VolumeSnapshot,
	crClient crclient.Client,
	log logrus.FieldLogger,
) {
	log.Infof("Deleting Volumesnapshot %s/%s", volSnap.Namespace, volSnap.Name)
	vs := new(snapshotv1api.VolumeSnapshot)
	err := crClient.Get(
		ctx,
		crclient.ObjectKey{Name: volSnap.Name, Namespace: volSnap.Namespace},
		vs,
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Debugf("VolumeSnapshot %s/%s is already deleted", volSnap.Namespace, volSnap.Name)
		} else {
			log.WithError(err).Warnf("Failed to get volumesnapshot %s/%s; skipping cleanup", volSnap.Namespace, volSnap.Name)
		}
		return
	}
	if vs.Status != nil && vs.Status.VolumeGroupSnapshotName != nil {
		log.Warnf("Deferring deletion of VGS member VolumeSnapshot %s/%s until VGS cleanup", vs.Namespace, vs.Name)
		return
	}

	if vs.Status != nil && vs.Status.BoundVolumeSnapshotContentName != nil {
		// we patch the DeletionPolicy of the VolumeSnapshotContent to set it to Delete.
		// This ensures that the volume snapshot in the storage provider is also deleted.
		_, err := SetVolumeSnapshotContentDeletionPolicy(
			ctx,
			*vs.Status.BoundVolumeSnapshotContentName,
			crClient,
			snapshotv1api.VolumeSnapshotContentDelete,
		)
		if err != nil {
			log.Debugf("Failed to patch DeletionPolicy of volume snapshot %s/%s",
				vs.Namespace, vs.Name)
		}
	}
	err = crClient.Delete(ctx, vs)
	if err != nil {
		log.Debugf("Failed to delete volumesnapshot %s/%s: %v", vs.Namespace, vs.Name, err)
	} else {
		log.Infof("Deleted volumesnapshot with volumesnapshotContent %s/%s",
			vs.Namespace, vs.Name)
	}
}

func DeleteReadyVolumeSnapshot(
	ctx context.Context,
	vs snapshotv1api.VolumeSnapshot,
	client crclient.Client,
	logger logrus.FieldLogger,
) {
	current := new(snapshotv1api.VolumeSnapshot)
	if err := client.Get(ctx, crclient.ObjectKeyFromObject(&vs), current); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.WithError(err).Warnf("Failed to get VolumeSnapshot %s/%s; skipping cleanup", vs.Namespace, vs.Name)
		}
		return
	}
	vs = *current
	if vs.Status != nil && vs.Status.VolumeGroupSnapshotName != nil {
		logger.Warnf("Deferring deletion of VGS member VolumeSnapshot %s/%s until VGS cleanup", vs.Namespace, vs.Name)
		return
	}
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
			ctx,
			*vs.Status.BoundVolumeSnapshotContentName,
			client,
			snapshotv1api.VolumeSnapshotContentRetain,
		); err != nil {
			logger.Warnf("Failed to patch DeletionPolicy of VolumeSnapshot %s/%s",
				vs.Namespace, vs.Name)
			return
		}

		if err := client.Delete(ctx, vsc); err != nil {
			logger.WithError(err).Warnf("Failed to delete the VolumeSnapshotContent %s", vsc.Name)
		}
	}
	if err := client.Delete(ctx, &vs); err != nil {
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
	// We'll wait for the VSC to be reconciled, trying a fast poll interval first
	// before falling back to a slower poll interval for the full csiSnapshotTimeout.
	vsc := new(snapshotv1api.VolumeSnapshotContent)
	var interval time.Duration

	pollFunc := func(ctx context.Context) (bool, error) {
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
					vsc.Name, stringptr.GetString(vsc.Status.Error.Message))
			}
			return false, nil
		}

		return true, nil
	}

	var err error
	frequentPolling, err := strconv.ParseBool(os.Getenv("CSI_SNAPSHOT_EARLY_FREQUENT_POLLING"))

	if err == nil && frequentPolling {
		// The short interval for the first ten seconds is due to the fact that
		// Microsoft VSS backups have a hard-coded unfreeze call after 10 seconds,
		// so we need to minimize waiting time during the first 10 seconds.
		// First poll with a short interval and timeout.
		interval = 1 * time.Second
		timeout := 10 * time.Second
		err = wait.PollUntilContextTimeout(
			context.Background(),
			interval,
			timeout,
			true,
			pollFunc,
		)

		if err == nil {
			return vsc, nil
		}
		if !wait.Interrupted(err) {
			return nil, err
		}
	}

	// If the first poll timed out, poll with a longer interval and the full timeout.
	interval = 5 * time.Second
	err = wait.PollUntilContextTimeout(
		context.Background(),
		interval,
		csiSnapshotTimeout,
		true,
		pollFunc,
	)

	if err != nil {
		if wait.Interrupted(err) {
			if vsc != nil &&
				vsc.Status != nil &&
				vsc.Status.Error != nil {
				log.Errorf(
					"Timed out awaiting reconciliation of VolumeSnapshot, VolumeSnapshotContent %s has error: %v",
					vsc.Name, stringptr.GetString(vsc.Status.Error.Message))
				return nil,
					errors.Errorf("CSI got timed out with error: %v",
						stringptr.GetString(vsc.Status.Error.Message))
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

const (
	// VSCDeletionSecretNameAnnotation and VSCDeletionSecretNamespaceAnnotation are set by
	// the CSI snapshot controller on a VolumeSnapshotContent and name the secret the CSI
	// driver requires to delete the snapshot.
	VSCDeletionSecretNameAnnotation      = "snapshot.storage.kubernetes.io/deletion-secret-name"
	VSCDeletionSecretNamespaceAnnotation = "snapshot.storage.kubernetes.io/deletion-secret-namespace"

	// VSCBoundProtectionFinalizer is the CSI snapshot finalizer that keeps a
	// VolumeSnapshotContent until the CSI snapshotter has handled its deletion.
	VSCBoundProtectionFinalizer = "snapshot.storage.kubernetes.io/volumesnapshotcontent-bound-protection"

	// TempVSCStatusTimeout is how long to wait for the CSI snapshotter to set the
	// status of a temp VolumeSnapshotContent before deleting it.
	TempVSCStatusTimeout = 30 * time.Second

	// TempVSCDeleteTimeout is how long to wait for the CSI snapshotter to delete
	// the snapshot and remove the temp VolumeSnapshotContent.
	TempVSCDeleteTimeout = 30 * time.Second
)

// WaitTempVSCStatus is a variable so that tests can skip the wait.
var WaitTempVSCStatus = waitTempVSCStatus

// WaitTempVSCDeleted is a variable so that tests can skip the wait.
var WaitTempVSCDeleted = waitTempVSCDeleted

// ErrTempVSCDeletionPending is returned by WaitTempVSCDeleted when the temp
// VolumeSnapshotContent still exists at the timeout.
var ErrTempVSCDeletionPending = errors.New("temp VolumeSnapshotContent deletion is still pending")

// waitTempVSCStatus waits until the CSI snapshotter has set status.snapshotHandle
// of the temp VolumeSnapshotContent. When the VSC is deleted, the snapshotter only
// calls DeleteSnapshot if the status has the snapshot handle; otherwise it just
// removes the finalizer and the snapshot stays in the storage.
func waitTempVSCStatus(ctx context.Context, crClient crclient.Client, vsc *snapshotv1api.VolumeSnapshotContent, timeout time.Duration, log logrus.FieldLogger) error {
	var current *snapshotv1api.VolumeSnapshotContent
	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		got := &snapshotv1api.VolumeSnapshotContent{}
		if err := crClient.Get(ctx, crclient.ObjectKey{Name: vsc.Name}, got); err != nil {
			if apierrors.IsNotFound(err) {
				// An earlier attempt already deleted it.
				current = nil
				return true, nil
			}
			return false, err
		}
		current = got
		return got.Status != nil && got.Status.SnapshotHandle != nil, nil
	})
	if err == nil {
		return nil
	}
	if !wait.Interrupted(err) {
		return errors.Wrapf(err, "error getting temp VolumeSnapshotContent %s", vsc.Name)
	}
	if current != nil && current.Status != nil && current.Status.Error != nil && current.Status.Error.Message != nil {
		// The CSI snapshotter can't find the snapshot, e.g. because an earlier
		// attempt already deleted it. Deleting the VSC then only removes the VSC.
		log.Warnf("The CSI snapshotter can't get the status of snapshot %s through temp VolumeSnapshotContent %s: %s; "+
			"the snapshot may already be deleted, deleting the VolumeSnapshotContent", *vsc.Spec.Source.SnapshotHandle, vsc.Name, *current.Status.Error.Message)
		return nil
	}
	return errors.Errorf("the CSI snapshotter of driver %s didn't set the status of temp VolumeSnapshotContent %s within %v, check that it runs and handles the VolumeSnapshotContent",
		vsc.Spec.Driver, vsc.Name, timeout)
}

// waitTempVSCDeleted waits until the temp VolumeSnapshotContent is gone. Its
// finalizer is only removed once the CSI driver has deleted the snapshot. The CSI
// snapshotter reports a failed deletion only as an event on the VSC and keeps
// retrying, so at the timeout it returns the failure recorded during the wait,
// or ErrTempVSCDeletionPending if there is none and the deletion is just slow.
func waitTempVSCDeleted(ctx context.Context, crClient crclient.Client, name string, timeout time.Duration, log logrus.FieldLogger) error {
	start := time.Now()
	err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		err := crClient.Get(ctx, crclient.ObjectKey{Name: name}, &snapshotv1api.VolumeSnapshotContent{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
	if wait.Interrupted(err) {
		if deleteErr := snapshotDeleteErrorSince(ctx, crClient, name, start, log); deleteErr != nil {
			return deleteErr
		}
		return ErrTempVSCDeletionPending
	}
	return err
}

// snapshotDeleteErrorSince returns the failure of the latest SnapshotDeleteError
// event the CSI snapshotter recorded for the named VolumeSnapshotContent since
// the given time, or nil if there is none or the events cannot be listed. Events
// of a cluster scoped object are recorded in the default namespace.
func snapshotDeleteErrorSince(ctx context.Context, crClient crclient.Client, vscName string, since time.Time, log logrus.FieldLogger) error {
	events := &corev1api.EventList{}
	if err := crClient.List(ctx, events, crclient.InNamespace(metav1.NamespaceDefault)); err != nil {
		// The events only add detail to a pending deletion, don't fail on them.
		log.WithError(err).Warnf("Failed to list the events of VolumeSnapshotContent %s", vscName)
		return nil
	}

	// Allow for clock skew between Velero and the CSI snapshotter.
	since = since.Add(-5 * time.Second)
	var latest *corev1api.Event
	for i := range events.Items {
		event := &events.Items[i]
		if event.InvolvedObject.Kind != "VolumeSnapshotContent" || event.InvolvedObject.Name != vscName ||
			event.Reason != "SnapshotDeleteError" || event.LastTimestamp.Time.Before(since) {
			continue
		}
		if latest == nil || latest.LastTimestamp.Before(&event.LastTimestamp) {
			latest = event
		}
	}
	if latest == nil {
		return nil
	}

	return errors.Errorf("CSI snapshotter failed to delete the snapshot: %s, see the events of VolumeSnapshotContent %s and the CSI snapshotter logs",
		latest.Message, vscName)
}

// DeleteSnapshotByTempVSC deletes the storage snapshot referenced by
// vsc.Spec.Source.SnapshotHandle. It creates vsc as a statically provisioned
// VolumeSnapshotContent with DeletionPolicy Delete, bound to a placeholder
// VolumeSnapshot, and then deletes it so the CSI driver removes the snapshot.
// vsc must carry the snapshot handle, the driver and, if the driver requires
// them, the deletion secret annotations; everything else is overwritten.
func DeleteSnapshotByTempVSC(ctx context.Context, crClient crclient.Client, vsc *snapshotv1api.VolumeSnapshotContent, log logrus.FieldLogger) error {
	if vsc.Spec.Source.SnapshotHandle == nil || *vsc.Spec.Source.SnapshotHandle == "" {
		return errors.New("snapshot handle is empty")
	}

	// Name the temp VSC after the snapshot, so that a retry after a failed or
	// timed out deletion reuses the VSC left behind instead of adding another one.
	sum := sha256.Sum256([]byte(vsc.Spec.Driver + "/" + *vsc.Spec.Source.SnapshotHandle))
	id := hex.EncodeToString(sum[:16])

	vsc.Name = "vsc-" + id
	vsc.ResourceVersion = ""
	vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentDelete
	vsc.Spec.Source = snapshotv1api.VolumeSnapshotContentSource{
		SnapshotHandle: vsc.Spec.Source.SnapshotHandle,
	}
	vsc.Spec.VolumeSnapshotRef = corev1api.ObjectReference{
		APIVersion: snapshotv1api.SchemeGroupVersion.String(),
		Kind:       "VolumeSnapshot",
		Namespace:  "ns-" + id,
		Name:       "name-" + id,
	}
	// Make the deletion independent of the VolumeSnapshotClass, which may no
	// longer exist; the CSI driver reads the deletion secret from the annotations.
	vsc.Spec.VolumeSnapshotClassName = nil
	// The snapshot controller only adds this finalizer to a VSC bound to a
	// VolumeSnapshot, which the placeholder never is. Without it, the VSC is
	// removed as soon as it is deleted and the CSI snapshotter never calls
	// DeleteSnapshot. With it, the snapshotter sees the unbound VSC being deleted,
	// deletes the snapshot and then removes the finalizer.
	if !slices.Contains(vsc.Finalizers, VSCBoundProtectionFinalizer) {
		vsc.Finalizers = append(vsc.Finalizers, VSCBoundProtectionFinalizer)
	}

	if err := crClient.Create(ctx, vsc); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return errors.Wrapf(err, "error creating temp VolumeSnapshotContent %s", vsc.Name)
		}
		log.Infof("Temp VolumeSnapshotContent %s for snapshot %s already exists, reusing it", vsc.Name, *vsc.Spec.Source.SnapshotHandle)
	} else {
		log.Infof("Created temp VolumeSnapshotContent %s with DeletionPolicy=Delete for snapshot %s", vsc.Name, *vsc.Spec.Source.SnapshotHandle)
	}

	// Deleting the VSC before the CSI snapshotter has set its status would remove
	// the VSC without deleting the snapshot.
	if err := WaitTempVSCStatus(ctx, crClient, vsc, TempVSCStatusTimeout, log); err != nil {
		return errors.Wrapf(err, "error deleting snapshot %s with temp VolumeSnapshotContent %s", *vsc.Spec.Source.SnapshotHandle, vsc.Name)
	}

	if err := crClient.Delete(ctx, vsc); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error deleting temp VolumeSnapshotContent %s", vsc.Name)
	}

	if err := WaitTempVSCDeleted(ctx, crClient, vsc.Name, TempVSCDeleteTimeout, log); err != nil {
		if errors.Is(err, ErrTempVSCDeletionPending) {
			// The CSI snapshotter keeps the temp VSC and retries until the snapshot
			// is deleted, so a slow deletion still completes after this returns, and
			// a later deletion of the same snapshot reuses the VSC.
			log.Warnf("Snapshot %s is not deleted after %v, the CSI snapshotter keeps retrying and removes temp VolumeSnapshotContent %s when it succeeds; "+
				"if it stays, check the events of the VolumeSnapshotContent and the CSI snapshotter logs",
				*vsc.Spec.Source.SnapshotHandle, TempVSCDeleteTimeout, vsc.Name)
			return nil
		}
		return errors.Wrapf(err, "error deleting snapshot %s with temp VolumeSnapshotContent %s", *vsc.Spec.Source.SnapshotHandle, vsc.Name)
	}
	log.Infof("Deleted temp VolumeSnapshotContent %s, the CSI driver deleted snapshot %s", vsc.Name, *vsc.Spec.Source.SnapshotHandle)

	return nil
}

// GetRetainedSnapshot returns the snapshot that stays in the storage after vsc is
// deleted, or nil if the snapshot is deleted together with vsc.
func GetRetainedSnapshot(vsc *snapshotv1api.VolumeSnapshotContent) *velerov2alpha1api.RetainedSnapshot {
	if vsc == nil || vsc.Spec.DeletionPolicy != snapshotv1api.VolumeSnapshotContentRetain {
		return nil
	}

	handle := ""
	if vsc.Status != nil && vsc.Status.SnapshotHandle != nil {
		handle = *vsc.Status.SnapshotHandle
	} else if vsc.Spec.Source.SnapshotHandle != nil {
		handle = *vsc.Spec.Source.SnapshotHandle
	}
	if handle == "" {
		return nil
	}

	return &velerov2alpha1api.RetainedSnapshot{
		SnapshotHandle:          handle,
		Driver:                  vsc.Spec.Driver,
		DeletionSecretName:      vsc.Annotations[VSCDeletionSecretNameAnnotation],
		DeletionSecretNamespace: vsc.Annotations[VSCDeletionSecretNamespaceAnnotation],
		ManagedBy:               vsc.Labels[kube.VolumeSnapshotContentManagedByLabel],
	}
}

// DeleteRetainedSnapshot has the CSI driver delete a retained snapshot. A
// VolumeSnapshotContent labeled with the backup name label value
// backupNameLabel is rebuilt for the retained snapshot handle with
// DeletionPolicy Delete and then deleted.
func DeleteRetainedSnapshot(ctx context.Context, crClient crclient.Client, retained *velerov2alpha1api.RetainedSnapshot, backupNameLabel string, log logrus.FieldLogger) error {
	if retained.SnapshotHandle == "" || retained.Driver == "" {
		return errors.Errorf("invalid retained snapshot, handle %q, driver %q", retained.SnapshotHandle, retained.Driver)
	}

	handle := retained.SnapshotHandle
	vsc := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				velerov1api.BackupNameLabel: backupNameLabel,
			},
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			Driver: retained.Driver,
			Source: snapshotv1api.VolumeSnapshotContentSource{
				SnapshotHandle: &handle,
			},
		},
	}
	// A distributed CSI snapshotter only handles the VSCs of its own node.
	if retained.ManagedBy != "" {
		vsc.Labels[kube.VolumeSnapshotContentManagedByLabel] = retained.ManagedBy
	}
	if retained.DeletionSecretName != "" {
		vsc.Annotations = map[string]string{
			VSCDeletionSecretNameAnnotation:      retained.DeletionSecretName,
			VSCDeletionSecretNamespaceAnnotation: retained.DeletionSecretNamespace,
		}
	}

	return DeleteSnapshotByTempVSC(ctx, crClient, vsc, log)
}

// ReleaseRetainedVSC sets the deletion policy of the named VolumeSnapshotContent
// to Delete if it is Retain, so that deleting it or its VolumeSnapshot also
// makes the CSI driver delete the snapshot. A missing VSC is not an error.
func ReleaseRetainedVSC(ctx context.Context, snapshotClient snapshotter.SnapshotV1Interface, vscName string) error {
	vsc, err := snapshotClient.VolumeSnapshotContents().Get(ctx, vscName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return errors.Wrapf(err, "error getting VSC %s", vscName)
	}
	if vsc.Spec.DeletionPolicy != snapshotv1api.VolumeSnapshotContentRetain {
		return nil
	}

	_, err = patchVSC(ctx, snapshotClient, vsc, func(updated *snapshotv1api.VolumeSnapshotContent) {
		updated.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentDelete
	})
	return err
}
