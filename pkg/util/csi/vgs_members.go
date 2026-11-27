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
	"encoding/json"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/label"
	"github.com/velero-io/velero/pkg/util"
)

// tempVGSCCreateDeleteGap is the time waited between creating a temporary
// VolumeGroupSnapshotContent and deleting it, so the CSI snapshotter sidecar
// observes the content (and records its finalizer) before the deletion
// arrives. It mirrors tempVSCCreateDeleteGap used by the temporary
// VolumeSnapshotContent flow.
const tempVGSCCreateDeleteGap = 2 * time.Second

// sleepBetweenTempVGSCCreateAndDelete is injectable for tests.
var sleepBetweenTempVGSCCreateAndDelete = time.Sleep

// vgsMember is the payload of one member ConfigMap: one member handle of one
// VolumeGroupSnapshot, recorded by the VolumeSnapshotContent delete item
// action while processing one tarball item.
type vgsMember struct {
	Driver              string `json:"driver"`
	GroupSnapshotHandle string `json:"groupSnapshotHandle"`
	SnapshotHandle      string `json:"snapshotHandle,omitempty"`
}

// AccumulateVGSMembers records one VolumeGroupSnapshot member's handle for a
// backup being deleted, as its own small ConfigMap in the backup's namespace,
// named deterministically from the backup UID and the member
// VolumeSnapshotContent's name and labeled with BackupUIDLabel and
// VolumeGroupSnapshotMemberLabel.
//
// The VolumeSnapshotContent delete item action processes each member of a
// VolumeGroupSnapshot from the backup tarball in isolation, so it cannot
// build the complete member list of a group on its own. The CSI CRDs mark
// groupSnapshotHandles immutable and required, so a temporary
// VolumeGroupSnapshotContent releasing the group must be created once,
// complete — it can never be completed by a later update. One ConfigMap per
// member, created and never mutated, provides the missing cross-item view
// without needing to merge into shared state: ReleaseBackupVolumeGroupSnapshots
// lists every member ConfigMap for the backup and groups them in memory. This
// mirrors how pkg/datamover's DataUploadDeleteAction records one snapshot-info
// ConfigMap per DataUpload for deleteMovedSnapshots to aggregate later,
// and needs no ConfigMap RBAC beyond create/get/list/delete.
//
// The write is idempotent: if the ConfigMap already exists — because the
// Backup deletion controller reprocesses the tarball on a new deletion
// attempt after an earlier one failed — the existing entry is left as is.
func AccumulateVGSMembers(
	ctx context.Context,
	c crclient.Client,
	log logrus.FieldLogger,
	backup *velerov1.Backup,
	driver, groupSnapshotHandle, snapshotHandle, memberContentName string,
) error {
	if groupSnapshotHandle == "" {
		return nil
	}

	cm := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: backup.Namespace,
			Name:      vgsMemberConfigMapName(string(backup.UID), memberContentName),
			Labels: map[string]string{
				velerov1.BackupNameLabel:                label.GetValidName(backup.Name),
				velerov1.BackupUIDLabel:                 string(backup.UID),
				velerov1.VolumeGroupSnapshotMemberLabel: "true",
			},
		},
	}

	member := vgsMember{
		Driver:              driver,
		GroupSnapshotHandle: groupSnapshotHandle,
		SnapshotHandle:      snapshotHandle,
	}
	raw, err := json.Marshal(member)
	if err != nil {
		return errors.Wrap(err, "marshaling VGS member entry")
	}
	cm.Data = map[string]string{"member": string(raw)}

	if err := c.Create(ctx, cm); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Debugf("VGS member ConfigMap %s already exists, leaving it as recorded", cm.Name)
			return nil
		}
		return errors.Wrapf(err, "creating VGS member ConfigMap %s", cm.Name)
	}

	log.Debugf("Recorded member snapshot handle %s of group snapshot handle %s for backup %s",
		snapshotHandle, groupSnapshotHandle, backup.Name)
	return nil
}

// vgsMemberConfigMapName returns a deterministic name for a member's
// ConfigMap, derived from the backup UID and the member
// VolumeSnapshotContent's name, so a reprocessed tarball item creates the
// same ConfigMap rather than a duplicate.
func vgsMemberConfigMapName(backupUID, memberContentName string) string {
	return "velero-vgsm-" + util.GenerateSha256FromRestoreUIDAndVsName(backupUID, memberContentName)
}

// ReleaseBackupVolumeGroupSnapshots releases the backend group snapshots
// accumulated by the VolumeSnapshotContent delete item action. It lists the
// backup's VGS member ConfigMaps and groups them by group snapshot handle.
// For each group it creates one temporary static VolumeGroupSnapshotContent
// with the complete member handle list and deletionPolicy Delete, then
// deletes the content: this makes the CSI snapshotter sidecar call
// DeleteVolumeGroupSnapshot, which is the only operation the CSI spec allows
// for removing group member snapshots from the backend. The member
// ConfigMaps that contributed to a successfully released group are then
// deleted; this cleanup is best effort and does not fail the release, since a
// leftover member ConfigMap is inert — nothing reads it once Velero no
// longer has that backup's deletion to process.
//
// The function is idempotent: a group that fails to release keeps all of its
// member ConfigMaps, so a retried deletion attempt (a new DeleteBackupRequest
// for the same backup) has the full member list again, and a group that was
// already released is simply released again, which is a no-op for a CSI
// driver's idempotent DeleteVolumeGroupSnapshot.
func ReleaseBackupVolumeGroupSnapshots(
	ctx context.Context,
	backup *velerov1.Backup,
	client crclient.Client,
	log logrus.FieldLogger,
) error {
	if backup.UID == "" {
		return nil
	}

	cmList := &corev1api.ConfigMapList{}
	if err := client.List(ctx, cmList, crclient.InNamespace(backup.Namespace), crclient.MatchingLabels(map[string]string{
		velerov1.BackupUIDLabel:                 string(backup.UID),
		velerov1.VolumeGroupSnapshotMemberLabel: "true",
	})); err != nil {
		return errors.Wrapf(err, "listing VGS member ConfigMaps for backup %s", backup.Name)
	}
	if len(cmList.Items) == 0 {
		return nil
	}

	type group struct {
		driver          string
		snapshotHandles []string
		memberCMs       []*corev1api.ConfigMap
	}
	groups := map[string]*group{}
	for i := range cmList.Items {
		cm := &cmList.Items[i]
		member := vgsMember{}
		if err := json.Unmarshal([]byte(cm.Data["member"]), &member); err != nil {
			log.WithError(err).Warnf("Skipping unparsable VGS member ConfigMap %s", cm.Name)
			continue
		}
		g, ok := groups[member.GroupSnapshotHandle]
		if !ok {
			g = &group{driver: member.Driver}
			groups[member.GroupSnapshotHandle] = g
		}
		if member.SnapshotHandle != "" && !slices.Contains(g.snapshotHandles, member.SnapshotHandle) {
			g.snapshotHandles = append(g.snapshotHandles, member.SnapshotHandle)
		}
		g.memberCMs = append(g.memberCMs, cm)
	}

	// VolumeGroupSnapshotClasses are cluster-scoped and shared by every group
	// released below, so they are resolved once here instead of once per
	// group inside releaseVolumeGroupSnapshot: a backup with several distinct
	// VolumeGroupSnapshots would otherwise issue one identical List per
	// group. A list failure is non-fatal, matching the per-content fallback
	// this replaces: without it the released contents simply carry no
	// deletion-secret annotations.
	vgsClasses, err := ListVGSClasses(ctx, client)
	if err != nil {
		log.WithError(err).Warn("Failed to list VolumeGroupSnapshotClasses for group snapshot deletion secrets")
		vgsClasses = nil
	}

	var errs []error
	for groupSnapshotHandle, g := range groups {
		if err := releaseVolumeGroupSnapshot(ctx, client, log, backup, g.driver, groupSnapshotHandle, g.snapshotHandles, vgsClasses); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, cm := range g.memberCMs {
			if err := client.Delete(ctx, cm); err != nil && !apierrors.IsNotFound(err) {
				log.WithError(err).Warnf("Failed to delete VGS member ConfigMap %s after release", cm.Name)
			}
		}
	}
	return kubeerrs.NewAggregate(errs)
}

// releaseVolumeGroupSnapshot creates one temporary static
// VolumeGroupSnapshotContent for groupSnapshotHandle with the complete
// snapshotHandles list and deletes it, triggering DeleteVolumeGroupSnapshot.
// vgsClasses is resolved once by the caller and shared across every group
// released in the same ReleaseBackupVolumeGroupSnapshots call.
func releaseVolumeGroupSnapshot(
	ctx context.Context,
	client crclient.Client,
	log logrus.FieldLogger,
	backup *velerov1.Backup,
	driver, groupSnapshotHandle string,
	snapshotHandles []string,
	vgsClasses *volumegroupsnapshotv1.VolumeGroupSnapshotClassList,
) error {
	suffix := util.GenerateSha256FromRestoreUIDAndVsName(string(backup.UID), groupSnapshotHandle)
	contentName := "velero-tmp-vgsc-" + suffix
	labels := map[string]string{
		velerov1.BackupNameLabel:                     label.GetValidName(backup.Name),
		velerov1.BackupUIDLabel:                      string(backup.UID),
		velerov1.VolumeGroupSnapshotTempContentLabel: "true",
	}
	// The reference points at a VolumeGroupSnapshot that does not exist; the
	// CRD requires name and namespace to be set, and the sidecar processes
	// pre-provisioned content deletion without a bound VolumeGroupSnapshot.
	ref := corev1api.ObjectReference{
		Name:      "velero-tmp-vgs-" + suffix[:8],
		Namespace: backup.Namespace,
	}

	if _, err := CreateStaticVGSCForHandles(
		ctx, client, log, contentName, driver, groupSnapshotHandle, snapshotHandles,
		snapshotv1.VolumeSnapshotContentDelete, labels, ref, vgsClasses,
	); err != nil {
		return err
	}

	// Give the sidecar time to observe the content before deleting it,
	// mirroring the temporary VolumeSnapshotContent flow.
	sleepBetweenTempVGSCCreateAndDelete(tempVGSCCreateDeleteGap)

	log.Infof("Deleting temporary VolumeGroupSnapshotContent %s to release group snapshot %s", contentName, groupSnapshotHandle)
	if err := DeleteVGSC(ctx, client, contentName); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "deleting temporary VolumeGroupSnapshotContent %s", contentName)
	}
	return nil
}
