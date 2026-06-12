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
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/client"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

// volumeSnapshotContentDeleteItemAction is a restore item action plugin for Velero
type volumeSnapshotContentDeleteItemAction struct {
	log      logrus.FieldLogger
	crClient crclient.Client
}

const tempVSCCreateDeleteGap = 2 * time.Second

var sleepBetweenTempVSCCreateAndDelete = time.Sleep

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
		p.log.Info(
			"VolumeSnapshotContent %s was not taken by backup %s, skipping deletion",
			snapCont.Name,
			input.Backup.Name,
		)
		return nil
	}

	p.log.Infof("Deleting VolumeSnapshotContent %s", snapCont.Name)

	uuid, err := uuid.NewRandom()
	if err != nil {
		p.log.WithError(err).Errorf("Fail to generate the UUID to create VSC %s", snapCont.Name)
		return errors.Wrapf(err, "Fail to generate the UUID to create VSC %s", snapCont.Name)
	}
	snapCont.Name = "vsc-" + uuid.String()

	snapCont.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentDelete

	snapCont.Spec.Source = snapshotv1api.VolumeSnapshotContentSource{
		SnapshotHandle: snapCont.Status.SnapshotHandle,
	}

	snapCont.Spec.VolumeSnapshotRef = corev1api.ObjectReference{
		APIVersion: snapshotv1api.SchemeGroupVersion.String(),
		Kind:       "VolumeSnapshot",
		Namespace:  "ns-" + string(snapCont.UID),
		Name:       "name-" + string(snapCont.UID),
	}

	snapCont.ResourceVersion = ""

	if snapCont.Spec.VolumeSnapshotClassName != nil {
		// Delete VolumeSnapshotClass from the VolumeSnapshotContent.
		// This is necessary to make the deletion independent of the VolumeSnapshotClass.
		snapCont.Spec.VolumeSnapshotClassName = nil
		p.log.Debugf("Deleted VolumeSnapshotClassName from VolumeSnapshotContent %s to make deletion independent of VolumeSnapshotClass",
			snapCont.Name)
	}

	if err := p.crClient.Create(context.TODO(), &snapCont); err != nil {
		return errors.Wrapf(err, "fail to create VolumeSnapshotContent %s", snapCont.Name)
	}

	// Add a small delay before delete to avoid create/delete race conditions in CSI controllers.
	sleepBetweenTempVSCCreateAndDelete(tempVSCCreateDeleteGap)

	// Delete the temp VSC immediately to trigger cloud snapshot removal.
	// The CSI driver will handle the actual cloud snapshot deletion.
	if err := p.crClient.Delete(
		context.TODO(),
		&snapCont,
	); err != nil && !apierrors.IsNotFound(err) {
		p.log.Infof("VolumeSnapshotContent %s not found", snapCont.Name)
		return err
	}

	return nil
}

var checkVSCReadiness = func(
	ctx context.Context,
	vsc *snapshotv1api.VolumeSnapshotContent,
	client crclient.Client,
) (bool, error) {
	tmpVSC := new(snapshotv1api.VolumeSnapshotContent)
	if err := client.Get(ctx, crclient.ObjectKeyFromObject(vsc), tmpVSC); err != nil {
		return false, errors.Wrapf(
			err, "failed to get VolumeSnapshotContent %s", vsc.Name,
		)
	}

	if tmpVSC.Status != nil && boolptr.IsSetToTrue(tmpVSC.Status.ReadyToUse) {
		return true, nil
	}

	// Fail fast on permanent CSI driver errors (e.g., InvalidSnapshot.NotFound)
	if tmpVSC.Status != nil && tmpVSC.Status.Error != nil && tmpVSC.Status.Error.Message != nil {
		return false, errors.Errorf(
			"VolumeSnapshotContent %s has error: %s", vsc.Name, *tmpVSC.Status.Error.Message,
		)
	}

	return false, nil
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
