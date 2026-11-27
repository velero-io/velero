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

	"github.com/cockroachdb/errors"
	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/util/retry"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/label"
	"github.com/velero-io/velero/pkg/util/boolptr"
	kubeutil "github.com/velero-io/velero/pkg/util/kube"
)

// CleanupBackupVolumeGroupSnapshots removes group snapshot API objects associated
// with a Backup. Cleanup is idempotent and errors are returned to the caller so
// normal Backup reconciliation or offline deletion cleanup can report them.
func CleanupBackupVolumeGroupSnapshots(ctx context.Context, backup *velerov1.Backup, client crclient.Client, log logrus.FieldLogger) error {
	if backup.UID == "" {
		return nil
	}

	var cleanupErrs []error
	// Content policies are settled before any object deletion. Data-mover
	// backups no longer need the backend snapshots once the data is in the
	// backup repository, so the group content and the member contents are
	// set to Delete: the external-snapshotter then releases the group and
	// all of its members through DeleteVolumeGroupSnapshot, or falls back to
	// per-member DeleteSnapshot calls for drivers that do not report group
	// membership on the contents (the same routing normal CSI deletion
	// relies on). Snapshot backups keep Retain so restores can still reach
	// the backend snapshots.
	vgscPolicy := snapshotv1.VolumeSnapshotContentRetain
	memberPolicy := snapshotv1.VolumeSnapshotContentRetain
	if boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
		vgscPolicy = snapshotv1.VolumeSnapshotContentDelete
		memberPolicy = snapshotv1.VolumeSnapshotContentDelete
	}
	groups, err := ListVGS(ctx, client, "", map[string]string{velerov1.BackupUIDLabel: string(backup.UID)})
	if err != nil {
		if errors.Is(err, ErrVGSAPINotAvailable) {
			return nil
		}
		cleanupErrs = append(cleanupErrs, errors.Wrap(err, "listing backup VolumeGroupSnapshots"))
	}
	contents, err := ListVGSC(ctx, client, map[string]string{velerov1.BackupUIDLabel: string(backup.UID)})
	if err != nil && !errors.Is(err, ErrVGSAPINotAvailable) {
		cleanupErrs = append(cleanupErrs, errors.Wrap(err, "listing backup VolumeGroupSnapshotContents"))
	}
	processedContents := map[string]struct{}{}
	if err == nil {
		for i := range contents.Items {
			content := &contents.Items[i]
			// Temporary contents created by the group release step are
			// released by ReleaseBackupVolumeGroupSnapshots; touching
			// their policy here would cancel the pending group deletion.
			if content.Labels[velerov1.VolumeGroupSnapshotTempContentLabel] == "true" {
				continue
			}
			if err := deleteVGSCWithPolicy(ctx, client, content.Name, nil, false, vgscPolicy); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			} else {
				processedContents[content.Name] = struct{}{}
			}
		}
	}

	memberContentNames := map[string]struct{}{}
	if groups != nil && len(groups.Items) > 0 {
		memberVS := &snapshotv1.VolumeSnapshotList{}
		if err := client.List(ctx, memberVS, crclient.MatchingLabels(map[string]string{velerov1.BackupUIDLabel: string(backup.UID)})); err != nil {
			cleanupErrs = append(cleanupErrs, errors.Wrap(err, "listing backup VolumeSnapshots"))
		}
		for i := range memberVS.Items {
			vs := &memberVS.Items[i]
			if vs.Status == nil || vs.Status.VolumeGroupSnapshotName == nil || vs.Status.BoundVolumeSnapshotContentName == nil {
				continue
			}
			memberContentNames[*vs.Status.BoundVolumeSnapshotContentName] = struct{}{}
		}
	}
	// Member VolumeSnapshotContents are discovered through the member
	// VolumeSnapshots' status because the contents themselves carry no Backup
	// labels. VGS members skip individual finalization while the parent
	// exists, so their content policy must be settled before VGS deletion:
	// once the VGS is gone, garbage collection removes the member
	// VolumeSnapshots and the external-snapshotter processes the contents
	// according to the policy settled above. The content objects themselves
	// are deleted here as well, mirroring ordinary CSI finalization where the
	// VolumeSnapshotContent is removed together with the VolumeSnapshot.
	memberCleanupFailed := false
	for contentName := range memberContentNames {
		if err := deleteMemberVSCWithPolicy(ctx, client, contentName, memberPolicy); err != nil {
			cleanupErrs = append(cleanupErrs, err)
			memberCleanupFailed = true
		}
	}

	if groups != nil {
		for i := range groups.Items {
			group := &groups.Items[i]
			if group.Status != nil && group.Status.BoundVolumeGroupSnapshotContentName != nil {
				contentName := *group.Status.BoundVolumeGroupSnapshotContentName
				_, processed := processedContents[contentName]
				// The label pass handles the normal path. This status-based fallback
				// recovers content when backup processing failed before labels were set.
				if !processed {
					content, err := GetVGSC(ctx, client, contentName)
					if err != nil && !apierrors.IsNotFound(err) {
						cleanupErrs = append(cleanupErrs, errors.Wrapf(err, "getting content of VolumeGroupSnapshot %s/%s", group.Namespace, group.Name))
						continue
					}
					if err == nil {
						ref := content.Spec.VolumeGroupSnapshotRef
						if ref.UID != group.UID || ref.Name != group.Name || ref.Namespace != group.Namespace {
							cleanupErrs = append(cleanupErrs, errors.Errorf("VolumeGroupSnapshotContent %s is not bound to %s/%s", content.Name, group.Namespace, group.Name))
						} else if err := deleteVGSCWithPolicy(ctx, client, contentName, backup, true, vgscPolicy); err != nil {
							cleanupErrs = append(cleanupErrs, err)
							continue
						}
					}
				}
			}

			if memberCleanupFailed {
				continue
			}
			log.Infof("Cleaning up VolumeGroupSnapshot %s/%s after backup finalization", group.Namespace, group.Name)
			if err := DeleteVGS(ctx, client, group.Namespace, group.Name); err != nil && !apierrors.IsNotFound(err) {
				cleanupErrs = append(cleanupErrs, errors.Wrapf(err, "deleting VolumeGroupSnapshot %s/%s", group.Namespace, group.Name))
			}
		}
	}
	return kubeerrs.NewAggregate(cleanupErrs)
}

// deleteMemberVSCWithPolicy settles a member VolumeSnapshotContent's
// DeletionPolicy and deletes the object. This does not itself release any
// backend snapshot: the policy only governs what the external-snapshotter
// does when the member VolumeSnapshot is garbage-collected after VGS
// deletion. Backend release for group members happens through the group
// content (deleteVGSCWithPolicy with Delete, or the temporary content
// released during Backup deletion); with Delete the sidecar may still delete
// a member individually on drivers that do not report group membership,
// while Retain guarantees no backend deletion, which snapshot backups depend
// on for restores. Deleting the content object mirrors ordinary CSI
// finalization, where the VolumeSnapshotContent is removed together with the
// VolumeSnapshot; the sidecar keeps the content finalizer while the member
// VolumeSnapshot still exists and releases it once the VGS is gone. Contents
// that are already gone are treated as settled.
func deleteMemberVSCWithPolicy(ctx context.Context, client crclient.Client, contentName string, policy snapshotv1.DeletionPolicy) error {
	if _, err := SetVolumeSnapshotContentDeletionPolicy(ctx, contentName, client, policy); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return errors.Wrapf(err, "setting DeletionPolicy %s for member VolumeSnapshotContent %s", policy, contentName)
	}
	if err := DeleteVolumeSnapshotContentObject(ctx, client, contentName); err != nil {
		return errors.Wrapf(err, "deleting member VolumeSnapshotContent %s", contentName)
	}
	return nil
}

// deleteVGSCWithPolicy patches a VolumeGroupSnapshotContent's DeletionPolicy
// and deletes the object. With the Delete policy, the external-snapshotter
// releases the group snapshot and all of its members through
// DeleteVolumeGroupSnapshot once the parent VGS is deleted; with Retain the
// backend snapshots are preserved, e.g. for snapshot backups whose restores
// depend on them. Deleting a bound content while its VGS still exists is
// safe: the sidecar holds the content finalizer until the VGS deletion
// completes and then acts according to the policy.
func deleteVGSCWithPolicy(ctx context.Context, client crclient.Client, contentName string, backup *velerov1.Backup, labelContent bool, policy snapshotv1.DeletionPolicy) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		content, err := GetVGSC(ctx, client, contentName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		if labelContent {
			kubeutil.AddLabels(&content.ObjectMeta, map[string]string{
				velerov1.BackupNameLabel: label.GetValidName(backup.Name),
				velerov1.BackupUIDLabel:  string(backup.UID),
			})
		}
		content.Spec.DeletionPolicy = policy
		if _, err := UpdateVGSC(ctx, client, content); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "setting DeletionPolicy %s on VolumeGroupSnapshotContent %s", policy, contentName)
	}
	if err := DeleteVGSC(ctx, client, contentName); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "deleting VolumeGroupSnapshotContent %s", contentName)
	}
	return nil
}
