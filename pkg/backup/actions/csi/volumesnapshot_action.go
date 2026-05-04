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
	"fmt"
	"strings"
	"time"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/label"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

// volumeSnapshotBackupItemAction is a backup item action plugin to backup
// CSI VolumeSnapshot objects using Velero
type volumeSnapshotBackupItemAction struct {
	log      logrus.FieldLogger
	crClient crclient.Client
}

// AppliesTo returns information indicating that the
// VolumeSnapshotBackupItemAction should be invoked to
// backup VolumeSnapshots.
func (p *volumeSnapshotBackupItemAction) AppliesTo() (
	velero.ResourceSelector,
	error,
) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshots.snapshot.storage.k8s.io"},
	}, nil
}

// Execute backs up a CSI VolumeSnapshot object and captures, as labels and annotations,
// information from its associated VolumeSnapshotContents such as CSI driver name,
// storage snapshot handle and namespace and name of the snapshot delete secret, if any.
// It returns the VolumeSnapshotClass and the VolumeSnapshotContents as additional items
// to be backed up.
func (p *volumeSnapshotBackupItemAction) Execute(
	item runtime.Unstructured,
	backup *velerov1api.Backup,
) (
	runtime.Unstructured,
	[]velero.ResourceIdentifier,
	string,
	[]velero.ResourceIdentifier,
	error,
) {
	p.log.Infof("Executing VolumeSnapshotBackupItemAction")

	vs := new(snapshotv1api.VolumeSnapshot)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		item.UnstructuredContent(), vs); err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	if backup.Status.Phase == velerov1api.BackupPhaseFinalizing ||
		backup.Status.Phase == velerov1api.BackupPhaseFinalizingPartiallyFailed {
		p.log.
			WithField("Backup", fmt.Sprintf("%s/%s", backup.Namespace, backup.Name)).
			WithField("BackupPhase", backup.Status.Phase).Debugf("Cleaning VolumeSnapshots.")

		csi.DeleteReadyVolumeSnapshot(*vs, p.crClient, p.log)
		return item, nil, "", nil, nil
	}

	additionalItems := make([]velero.ResourceIdentifier, 0)

	if vs.Spec.VolumeSnapshotClassName != nil {
		// This is still needed to add the VolumeSnapshotClass to the backup.
		// The secret with VolumeSnapshotClass is still relevant to backup.
		additionalItems = append(
			additionalItems,
			velero.ResourceIdentifier{
				GroupResource: kuberesource.VolumeSnapshotClasses,
				Name:          *vs.Spec.VolumeSnapshotClassName,
			},
		)

		// Because async operation will update VolumeSnapshot during finalizing phase.
		// No matter what we do, VolumeSnapshotClass cannot be deleted. So skip it.
		// Just deleting VolumeSnapshotClass during restore and delete is enough.
	}

	p.log.Infof("Getting VolumesnapshotContent for Volumesnapshot %s/%s",
		vs.Namespace, vs.Name)

	ctx := context.TODO()

	vsc, err := csi.GetVSCForVS(ctx, vs, p.crClient)
	if err != nil {
		csi.CleanupVolumeSnapshot(vs, p.crClient, p.log)
		return nil, nil, "", nil, errors.WithStack(err)
	}

	annotations := make(map[string]string)

	if vsc != nil {
		// when we are backing up VolumeSnapshots created outside of velero, we
		// will not await VolumeSnapshot reconciliation and in this case
		// GetVolumeSnapshotContentForVolumeSnapshot may not find the associated
		// VolumeSnapshotContents to add to the backup.  This is not an error
		// encountered in the backup process. So we add the VolumeSnapshotContent
		// to the backup only if one is found.
		additionalItems = append(additionalItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.VolumeSnapshotContents,
			Name:          vsc.Name,
		})
		annotations[velerov1api.VSCDeletionPolicyAnnotation] = string(vsc.Spec.DeletionPolicy)

		if vsc.Status != nil {
			if vsc.Status.SnapshotHandle != nil {
				// Capture storage provider snapshot handle and CSI driver name
				// to be used on restore to create a static VolumeSnapshotContent
				// that will be the source of the VolumeSnapshot.
				annotations[velerov1api.VolumeSnapshotHandleAnnotation] = *vsc.Status.SnapshotHandle
				annotations[velerov1api.DriverNameAnnotation] = vsc.Spec.Driver
			}

			if vsc.Status.RestoreSize != nil {
				annotations[velerov1api.VolumeSnapshotRestoreSize] = resource.NewQuantity(
					*vsc.Status.RestoreSize, resource.BinarySI).String()
			}

			// Capture VolumeGroupSnapshotHandle to create stub VGSC during restore
			// for CSI drivers that populate this field (e.g., Ceph RBD).
			if vsc.Status.VolumeGroupSnapshotHandle != nil {
				annotations[velerov1api.VolumeGroupSnapshotHandleAnnotation] = *vsc.Status.VolumeGroupSnapshotHandle
			}
		}

		p.log.Infof("Patching VolumeSnapshotContent %s with velero BackupNameLabel",
			vsc.Name)
		// If we created the VolumeSnapshotContent object during this ongoing backup,
		// we would have created it with a DeletionPolicy of Retain.
		// But, we want to retain these VolumeSnapshotContent ONLY for the lifetime
		// of the backup. To that effect, during velero backup
		// deletion, we will update the DeletionPolicy of the VolumeSnapshotContent
		// and then delete the VolumeSnapshot object which will cascade delete the
		// VolumeSnapshotContent and the associated snapshot in the storage
		// provider (handled by the CSI driver and the CSI common controller).
		// However, in the event that the VolumeSnapshot object is deleted outside
		// of the backup deletion process, it is possible that the dynamically created
		// VolumeSnapshotContent object will be left as an orphaned and non-discoverable
		// resource in the cluster as well as in the storage provider. To avoid piling
		// up of such orphaned resources, we will want to discover and delete the
		// dynamically created VolumeSnapshotContent. We do that by adding
		// the "velero.io/backup-name" label on the VolumeSnapshotContent.
		// Further, we want to add this label only on VolumeSnapshotContents that
		// were created during an ongoing velero backup.
		originVSC := vsc.DeepCopy()
		kubeutil.AddLabels(
			&vsc.ObjectMeta,
			map[string]string{
				velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
			},
		)

		if vscPatchError := p.crClient.Patch(
			context.TODO(),
			vsc,
			crclient.MergeFrom(originVSC),
		); vscPatchError != nil {
			p.log.Warnf("Failed to patch VolumeSnapshotContent %s: %v",
				vsc.Name, vscPatchError)
		}
	}

	// Before applying the BIA v2, the in-cluster VS state is not persisted into backup.
	// After the change, because the final state of VS will be stored in backup as the
	// result of async operation result, need to patch the annotations into VS to work,
	// because restore will check the annotations information.
	originVS := vs.DeepCopy()
	kubeutil.AddAnnotations(&vs.ObjectMeta, annotations)
	if err := p.crClient.Patch(
		context.TODO(),
		vs,
		crclient.MergeFrom(originVS),
	); err != nil {
		p.log.Errorf("Fail to patch VolumeSnapshot: %s.", err.Error())
		return nil, nil, "", nil, errors.WithStack(err)
	}

	annotations[velerov1api.MustIncludeAdditionalItemAnnotation] = "true"
	// save newly applied annotations into the backed-up VolumeSnapshot item
	kubeutil.AddAnnotations(&vs.ObjectMeta, annotations)

	vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(vs)
	if err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	p.log.Infof("Returning from VolumeSnapshotBackupItemAction with %d additionalItems to backup",
		len(additionalItems))
	for _, ai := range additionalItems {
		p.log.Debugf("%s: %s", ai.GroupResource.String(), ai.Name)
	}

	operationID := ""
	var itemToUpdate []velero.ResourceIdentifier

	// Only return Async operation for VSC created for this backup.
	// The operationID is of the form <namespace>/<volumesnapshot-name>/<started-time>
	operationID = vs.Namespace + "/" + vs.Name + "/" + time.Now().Format(time.RFC3339)
	itemToUpdate = []velero.ResourceIdentifier{
		{
			GroupResource: kuberesource.VolumeSnapshots,
			Namespace:     vs.Namespace,
			Name:          vs.Name,
		},
		{
			GroupResource: kuberesource.VolumeSnapshotContents,
			Name:          vsc.Name,
		},
	}

	return &unstructured.Unstructured{Object: vsMap},
		additionalItems, operationID, itemToUpdate, nil
}

// Name returns the plugin's name.
func (p *volumeSnapshotBackupItemAction) Name() string {
	return "VolumeSnapshotBackupItemAction"
}

func (p *volumeSnapshotBackupItemAction) Progress(
	operationID string,
	backup *velerov1api.Backup,
) (velero.OperationProgress, error) {
	progress := velero.OperationProgress{}
	if operationID == "" {
		return progress, biav2.InvalidOperationIDError(operationID)
	}
	// The operationID is of the form <namespace>/<volumesnapshot-name>/<started-time>
	operationIDParts := strings.Split(operationID, "/")
	if len(operationIDParts) != 3 {
		p.log.Errorf("invalid operation ID %s", operationID)
		return progress, biav2.InvalidOperationIDError(operationID)
	}
	var err error
	if progress.Started, err = time.Parse(time.RFC3339, operationIDParts[2]); err != nil {
		p.log.Errorf("error parsing operation ID's StartedTime",
			"part into time %s: %s", operationID, err.Error())
		return progress, errors.WithStack(err)
	}

	vs := new(snapshotv1api.VolumeSnapshot)
	if err := p.crClient.Get(
		context.Background(),
		crclient.ObjectKey{
			Namespace: operationIDParts[0],
			Name:      operationIDParts[1],
		},
		vs); err != nil {
		p.log.Errorf("error getting volumesnapshot %s/%s: %s",
			operationIDParts[0], operationIDParts[1], err.Error())
		return progress, errors.WithStack(err)
	}

	if vs.Status == nil {
		p.log.Debugf("VolumeSnapshot %s/%s has an empty status. Skip progress update.", vs.Namespace, vs.Name)
		return progress, nil
	}

	if boolptr.IsSetToTrue(vs.Status.ReadyToUse) {
		p.log.Debugf("VolumeSnapshot %s/%s is ReadyToUse. Continue on querying corresponding VolumeSnapshotContent.",
			vs.Namespace, vs.Name)
	} else if vs.Status.Error != nil {
		errorMessage := ""
		if vs.Status.Error.Message != nil {
			errorMessage = *vs.Status.Error.Message
		}

		timeout := backup.Spec.CSISnapshotErrorTimeout.Duration
		if timeout > 0 && time.Since(progress.Started) >= timeout {
			p.log.Errorf(
				"VolumeSnapshot %s/%s has a persistent error beyond CSISnapshotErrorTimeout (%s): %s",
				vs.Namespace, vs.Name, timeout, errorMessage)
			progress.Completed = true
			progress.Updated = time.Now()
			progress.Err = fmt.Sprintf("VolumeSnapshot %s/%s has a persistent error: %s",
				vs.Namespace, vs.Name, errorMessage)
			return progress, nil
		}

		p.log.Warnf("VolumeSnapshot %s/%s has an error within the CSISnapshotErrorTimeout window: %s. Snapshot controller will retry later.",
			vs.Namespace, vs.Name, errorMessage)

		return progress, nil
	}

	if vs.Status != nil && vs.Status.BoundVolumeSnapshotContentName != nil {
		vsc := new(snapshotv1api.VolumeSnapshotContent)
		err := p.crClient.Get(
			context.Background(),
			crclient.ObjectKey{Name: *vs.Status.BoundVolumeSnapshotContentName},
			vsc,
		)
		if err != nil {
			p.log.Errorf("error getting VolumeSnapshotContent %s: %s",
				*vs.Status.BoundVolumeSnapshotContentName, err.Error())
			return progress, errors.WithStack(err)
		}

		if vsc.Status == nil {
			p.log.Debugf("VolumeSnapshotContent %s has an empty Status. Skip progress update.",
				vsc.Name)
			return progress, nil
		}

		now := time.Now()

		if boolptr.IsSetToTrue(vsc.Status.ReadyToUse) {
			progress.Completed = true
			progress.Updated = now
		} else if vsc.Status.Error != nil {
			errorMessage := ""
			if vsc.Status.Error.Message != nil {
				errorMessage = *vsc.Status.Error.Message
			}

			timeout := backup.Spec.CSISnapshotErrorTimeout.Duration
			if timeout > 0 && time.Since(progress.Started) >= timeout {
				p.log.Errorf(
					"VolumeSnapshotContent %s has a persistent error beyond CSISnapshotErrorTimeout (%s): %s",
					vsc.Name, timeout, errorMessage)
				progress.Completed = true
				progress.Updated = now
				progress.Err = fmt.Sprintf("VolumeSnapshotContent %s has a persistent error: %s",
					vsc.Name, errorMessage)
			} else {
				p.log.Warnf("VolumeSnapshotContent %s has an error within the CSISnapshotErrorTimeout window: %s. Snapshot controller will retry later.",
					vsc.Name, errorMessage)
			}
		}
	}

	return progress, nil
}

// Cancel is not implemented for VolumeSnapshotBackupItemAction
func (p *volumeSnapshotBackupItemAction) Cancel(
	operationID string,
	backup *velerov1api.Backup,
) error {
	// CSI Specification doesn't support canceling a snapshot creation.
	return nil
}

// NewVolumeSnapshotBackupItemAction returns
// VolumeSnapshotBackupItemAction instance.
func NewVolumeSnapshotBackupItemAction(
	f client.Factory,
) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		return &volumeSnapshotBackupItemAction{
			log:      logger,
			crClient: crClient,
		}, nil
	}
}
