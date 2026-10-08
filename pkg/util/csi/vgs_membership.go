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
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// VGSMembershipLabelPrefix reserves PVC labels used to select policy-approved
// group snapshot members. A separate key per Backup allows overlapping backups
// to select different members without overwriting each other's labels.
const VGSMembershipLabelPrefix = "velero.io/vgs-membership-"

// VGSMembershipLabelKey returns the PVC membership label reserved for a Backup.
func VGSMembershipLabelKey(backupUID types.UID) string {
	return VGSMembershipLabelPrefix + string(backupUID)
}

// MarkVGSMembers labels only the PVCs that passed the Backup's volume policies.
// The Backup must be marked for terminal cleanup before calling this function,
// so cleanup can recover labels even if labeling or VGS creation fails.
func MarkVGSMembers(ctx context.Context, client crclient.Client, backupUID types.UID, group string, pvcs []corev1api.PersistentVolumeClaim) error {
	key := VGSMembershipLabelKey(backupUID)
	for _, pvc := range pvcs {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &corev1api.PersistentVolumeClaim{}
			if err := client.Get(ctx, crclient.ObjectKeyFromObject(&pvc), current); err != nil {
				return err
			}
			if current.UID != pvc.UID {
				return errors.Errorf("PVC %s/%s was replaced while preparing group snapshot membership", pvc.Namespace, pvc.Name)
			}
			base := current.DeepCopy()
			if current.Labels == nil {
				current.Labels = map[string]string{}
			}
			current.Labels[key] = group
			return client.Patch(ctx, current, crclient.MergeFromWithOptions(base, crclient.MergeFromWithOptimisticLock{}))
		}); err != nil {
			return errors.Wrapf(err, "labeling VolumeGroupSnapshot member PVC %s/%s", pvc.Namespace, pvc.Name)
		}
	}
	return nil
}

// RemoveVGSMembershipLabels strips transient labels from objects being archived,
// including labels belonging to other backups running at the same time.
func RemoveVGSMembershipLabels(obj metav1.Object) {
	labels := obj.GetLabels()
	for key := range labels {
		if strings.HasPrefix(key, VGSMembershipLabelPrefix) {
			delete(labels, key)
		}
	}
	obj.SetLabels(labels)
}

func cleanupVGSMembershipLabels(ctx context.Context, backup *velerov1.Backup, client crclient.Client) error {
	if backup.Annotations[velerov1.VolumeGroupSnapshotBackupAnnotation] != "true" {
		return nil
	}
	key := VGSMembershipLabelKey(backup.UID)
	pvcs := &corev1api.PersistentVolumeClaimList{}
	if err := client.List(ctx, pvcs, crclient.HasLabels{key}); err != nil {
		return errors.Wrap(err, "listing VolumeGroupSnapshot member PVCs for cleanup")
	}
	for _, pvc := range pvcs.Items {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &corev1api.PersistentVolumeClaim{}
			if err := client.Get(ctx, crclient.ObjectKeyFromObject(&pvc), current); err != nil {
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}
			base := current.DeepCopy()
			delete(current.Labels, key)
			return client.Patch(ctx, current, crclient.MergeFromWithOptions(base, crclient.MergeFromWithOptimisticLock{}))
		}); err != nil {
			return errors.Wrapf(err, "removing VolumeGroupSnapshot membership label from PVC %s/%s", pvc.Namespace, pvc.Name)
		}
	}
	return nil
}
