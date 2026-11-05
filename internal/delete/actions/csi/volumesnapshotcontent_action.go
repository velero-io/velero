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
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/pkg/client"
	plugincommon "github.com/velero-io/velero/pkg/plugin/framework/common"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/util/csi"
	kubeutil "github.com/velero-io/velero/pkg/util/kube"
)

// volumeSnapshotContentDeleteItemAction is a restore item action plugin for Velero
type volumeSnapshotContentDeleteItemAction struct {
	log      logrus.FieldLogger
	crClient crclient.Client
}

// AppliesTo returns information indicating
// VolumeSnapshotContentRestoreItemAction action should be invoked
// while restoring VolumeSnapshotContent.snapshot.storage.k8s.io resources
func (p *volumeSnapshotContentDeleteItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshotcontents.snapshot.storage.k8s.io"},
	}, nil
}

func (p *volumeSnapshotContentDeleteItemAction) Execute(
	input *velero.DeleteItemActionExecuteInput,
) error {
	p.log.Info("Starting VolumeSnapshotContentDeleteItemAction")

	var snapCont snapshotv1api.VolumeSnapshotContent
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.Item.UnstructuredContent(),
		&snapCont,
	); err != nil {
		return errors.Wrapf(err, "failed to convert VolumeSnapshotContent from unstructured")
	}

	// We don't want this DeleteItemAction plugin to delete
	// VolumeSnapshotContent taken outside of Velero.
	// So skip deleting VolumeSnapshotContent not have the backup name
	// in its labels.
	if !kubeutil.HasBackupLabel(&snapCont.ObjectMeta, input.Backup.Name) {
		p.log.Infof(
			"VolumeSnapshotContent %s was not taken by backup %s, skipping deletion",
			snapCont.Name,
			input.Backup.Name,
		)
		return nil
	}

	p.log.Infof("Deleting VolumeSnapshotContent %s", snapCont.Name)

	// Try to delete the original VSC from the cluster first.
	// This handles legacy (pre-1.15) backups where the original VSC
	// with DeletionPolicy=Retain still exists in the cluster.
	originalVSCName := snapCont.Name
	if cleaned := p.tryDeleteOriginalVSC(context.TODO(), originalVSCName, input.Backup.Name); cleaned {
		p.log.Infof("Successfully deleted original VolumeSnapshotContent %s from cluster, skipping temp VSC creation", originalVSCName)
		return nil
	}

	// create a temp VSC to trigger cloud snapshot deletion
	// (for backups where the original VSC no longer exists in cluster)
	snapCont.Spec.Source = snapshotv1api.VolumeSnapshotContentSource{
		SnapshotHandle: snapCont.Status.SnapshotHandle,
	}
	if err := csi.DeleteSnapshotByTempVSC(context.TODO(), p.crClient, &snapCont, p.log); err != nil {
		p.log.WithError(err).Errorf("Failed to delete snapshot of VolumeSnapshotContent %s", originalVSCName)
		return err
	}

	p.log.Infof("Successfully triggered deletion of VolumeSnapshotContent %s and its cloud snapshot", originalVSCName)
	return nil
}

// tryDeleteOriginalVSC attempts to find and delete the original VSC from
// the cluster (legacy pre-1.15 backups). It patches the DeletionPolicy to
// Delete so the CSI driver also removes the cloud snapshot, then deletes
// the VSC object itself.
// Returns true if the original VSC was found, carries the backup label, and deletion was initiated.
func (p *volumeSnapshotContentDeleteItemAction) tryDeleteOriginalVSC(
	ctx context.Context,
	vscName string,
	backupName string,
) bool {
	existing := new(snapshotv1api.VolumeSnapshotContent)
	if err := p.crClient.Get(ctx, crclient.ObjectKey{Name: vscName}, existing); err != nil {
		if apierrors.IsNotFound(err) {
			p.log.Debugf("Original VolumeSnapshotContent %s not found in cluster, will use temp VSC flow", vscName)
		} else {
			p.log.WithError(err).Warnf("Error looking up original VolumeSnapshotContent %s, will use temp VSC flow", vscName)
		}
		return false
	}

	if !kubeutil.HasBackupLabel(&existing.ObjectMeta, backupName) {
		p.log.Warnf(
			"Original VolumeSnapshotContent %s in cluster does not belong to backup %s, skipping direct deletion",
			vscName,
			backupName,
		)
		return false
	}

	p.log.Debugf("Found original VolumeSnapshotContent %s in cluster (legacy backup), cleaning up directly", vscName)

	// Patch DeletionPolicy to Delete so the CSI driver removes the cloud snapshot
	if existing.Spec.DeletionPolicy != snapshotv1api.VolumeSnapshotContentDelete {
		original := existing.DeepCopy()
		existing.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentDelete
		if err := p.crClient.Patch(ctx, existing, crclient.MergeFrom(original)); err != nil {
			p.log.WithError(err).Warnf("Failed to patch DeletionPolicy on original VSC %s, will use temp VSC flow", vscName)
			return false
		}
		p.log.Debugf("Patched DeletionPolicy to Delete on original VolumeSnapshotContent %s", vscName)
	}

	// Delete the original VSC — the CSI driver will clean up the cloud snapshot
	if err := p.crClient.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
		p.log.WithError(err).Warnf("Failed to delete original VolumeSnapshotContent %s, will use temp VSC flow", vscName)
		return false
	}

	p.log.Infof("Deleted original VolumeSnapshotContent %s with DeletionPolicy=Delete, CSI driver will remove cloud snapshot", vscName)
	return true
}

func NewVolumeSnapshotContentDeleteItemAction(
	f client.Factory,
) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}

		return &volumeSnapshotContentDeleteItemAction{
			log:      logger,
			crClient: crClient,
		}, nil
	}
}
