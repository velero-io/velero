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

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/label"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

// CleanupBackupVolumeGroupSnapshots removes group snapshot API objects associated
// with a Backup. Cleanup is idempotent and errors are returned to the caller so
// normal Backup reconciliation or offline deletion cleanup can report them.
func CleanupBackupVolumeGroupSnapshots(ctx context.Context, backup *velerov1.Backup, client crclient.Client, log logrus.FieldLogger) error {
	if backup.UID == "" {
		return nil
	}

	var cleanupErrs []error
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
			if err := retainAndDeleteVGSC(ctx, client, content.Name, nil, false); err != nil {
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
	memberContents := &snapshotv1.VolumeSnapshotContentList{}
	if err := client.List(ctx, memberContents, crclient.MatchingLabels(map[string]string{velerov1.BackupUIDLabel: string(backup.UID)})); err != nil {
		cleanupErrs = append(cleanupErrs, errors.Wrap(err, "listing backup VolumeSnapshotContents"))
	}
	// VGS members skip individual finalization while the parent exists. Retain
	// their backend snapshots before VGS deletion even if a driver omitted the
	// member VolumeGroupSnapshotHandle status field.
	memberRetentionFailed := false
	for i := range memberContents.Items {
		content := &memberContents.Items[i]
		if _, isMember := memberContentNames[content.Name]; !isMember {
			continue
		}
		if content.Spec.DeletionPolicy == snapshotv1.VolumeSnapshotContentRetain {
			continue
		}
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current := &snapshotv1.VolumeSnapshotContent{}
			if err := client.Get(ctx, crclient.ObjectKeyFromObject(content), current); err != nil {
				return err
			}
			current.Spec.DeletionPolicy = snapshotv1.VolumeSnapshotContentRetain
			return client.Update(ctx, current)
		}); err != nil {
			cleanupErrs = append(cleanupErrs, errors.Wrapf(err, "retaining VolumeSnapshotContent %s", content.Name))
			memberRetentionFailed = true
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
						} else if err := retainAndDeleteVGSC(ctx, client, contentName, backup, true); err != nil {
							cleanupErrs = append(cleanupErrs, err)
							continue
						}
					}
				}
			}

			if memberRetentionFailed {
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

func retainAndDeleteVGSC(ctx context.Context, client crclient.Client, contentName string, backup *velerov1.Backup, labelContent bool) error {
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
		content.Spec.DeletionPolicy = snapshotv1.VolumeSnapshotContentRetain
		if _, err := UpdateVGSC(ctx, client, content); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "retaining VolumeGroupSnapshotContent %s", contentName)
	}
	if err := DeleteVGSC(ctx, client, contentName); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "deleting VolumeGroupSnapshotContent %s", contentName)
	}
	return nil
}
