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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
)

// volumeSnapshotContentRestoreItemAction is a restore item action
// plugin for Velero
type volumeSnapshotContentRestoreItemAction struct {
	log    logrus.FieldLogger
	client crclient.Client
}

// AppliesTo returns information indicating VolumeSnapshotContentRestoreItemAction
// action should be invoked while restoring
// volumesnapshotcontent.snapshot.storage.k8s.io resources
func (p *volumeSnapshotContentRestoreItemAction) AppliesTo() (
	velero.ResourceSelector, error,
) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshotcontents.snapshot.storage.k8s.io"},
	}, nil
}

// Execute restores a VolumeSnapshotContent object without modification
// returning the snapshot lister secret, if any, as additional items to restore.
func (p *volumeSnapshotContentRestoreItemAction) Execute(
	input *velero.RestoreItemActionExecuteInput,
) (*velero.RestoreItemActionExecuteOutput, error) {
	if boolptr.IsSetToFalse(input.Restore.Spec.RestorePVs) {
		p.log.Infof("Restore did not request for PVs to be restored %s/%s",
			input.Restore.Namespace, input.Restore.Name)
		return &velero.RestoreItemActionExecuteOutput{SkipRestore: true}, nil
	}

	p.log.Info("Starting VolumeSnapshotContentRestoreItemAction")

	var vsc snapshotv1api.VolumeSnapshotContent
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.Item.UnstructuredContent(), &vsc); err != nil {
		return &velero.RestoreItemActionExecuteOutput{},
			errors.Wrapf(err, "failed to convert input.Item from unstructured")
	}

	var vscFromBackup snapshotv1api.VolumeSnapshotContent
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.ItemFromBackup.UnstructuredContent(), &vscFromBackup); err != nil {
		return &velero.RestoreItemActionExecuteOutput{},
			errors.Errorf(err.Error(), "failed to convert input.ItemFromBackup from unstructured")
	}

	// If cross-namespace restore is configured, change the namespace
	// for VolumeSnapshot object to be restored
	newNamespace, ok := input.Restore.Spec.NamespaceMapping[vsc.Spec.VolumeSnapshotRef.Namespace]
	if ok {
		// Update the referenced VS namespace to the mapping one.
		vsc.Spec.VolumeSnapshotRef.Namespace = newNamespace
	}

	// Reset VSC name to align with VS.
	vsc.Name = util.GenerateSha256FromRestoreUIDAndVsName(
		string(input.Restore.UID), vscFromBackup.Spec.VolumeSnapshotRef.Name)
	// Also reset the referenced VS name.
	vsc.Spec.VolumeSnapshotRef.Name = vsc.Name

	// Reset the ResourceVersion and UID of referenced VolumeSnapshot.
	vsc.Spec.VolumeSnapshotRef.ResourceVersion = ""
	vsc.Spec.VolumeSnapshotRef.UID = ""

	// Set the DeletionPolicy to Retain to avoid VS deletion will not trigger snapshot deletion
	vsc.Spec.DeletionPolicy = snapshotv1api.VolumeSnapshotContentRetain

	if vscFromBackup.Status != nil && vscFromBackup.Status.SnapshotHandle != nil {
		vsc.Spec.Source.VolumeHandle = nil
		vsc.Spec.Source.SnapshotHandle = vscFromBackup.Status.SnapshotHandle
	} else {
		p.log.Errorf("fail to get snapshot handle from VSC %s status", vsc.Name)
		return nil, errors.Errorf("fail to get snapshot handle from VSC %s status", vsc.Name)
	}

	// Look up a VolumeSnapshotClass matching the driver for credential lookup.
	// Some CSI drivers (e.g., Ceph RBD) need credentials for snapshot verification.
	// Instead of keeping the original class name (which may not exist on target cluster),
	// we find a matching class by driver to make restore portable.
	vsc.Spec.VolumeSnapshotClassName = nil
	vscList := &snapshotv1api.VolumeSnapshotClassList{}
	if err := p.client.List(context.Background(), vscList); err == nil {
		for i := range vscList.Items {
			if vscList.Items[i].Driver == vsc.Spec.Driver {
				vsc.Spec.VolumeSnapshotClassName = &vscList.Items[i].Name
				p.log.Infof("Set VolumeSnapshotClassName to %s for VSC %s based on driver match",
					vscList.Items[i].Name, vsc.Name)
				break
			}
		}
	} else {
		p.log.Warnf("Failed to list VolumeSnapshotClasses: %v", err)
	}

	additionalItems := []velero.ResourceIdentifier{}
	if csi.IsVolumeSnapshotContentHasDeleteSecret(&vsc) {
		additionalItems = append(additionalItems,
			velero.ResourceIdentifier{
				GroupResource: schema.GroupResource{Group: "", Resource: "secrets"},
				Name:          vsc.Annotations[velerov1api.PrefixedSecretNameAnnotation],
				Namespace:     vsc.Annotations[velerov1api.PrefixedSecretNamespaceAnnotation],
			},
		)
	}

	vscMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&vsc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	p.log.Infof("Returning from VolumeSnapshotContentRestoreItemAction with %d additionalItems",
		len(additionalItems))
	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem:     &unstructured.Unstructured{Object: vscMap},
		AdditionalItems: additionalItems,
	}, nil
}

func (p *volumeSnapshotContentRestoreItemAction) Name() string {
	return "VolumeSnapshotContentRestoreItemAction"
}

func (p *volumeSnapshotContentRestoreItemAction) Progress(
	operationID string,
	restore *velerov1api.Restore,
) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

func (p *volumeSnapshotContentRestoreItemAction) Cancel(
	operationID string,
	restore *velerov1api.Restore,
) error {
	return nil
}

func (p *volumeSnapshotContentRestoreItemAction) AreAdditionalItemsReady(
	additionalItems []velero.ResourceIdentifier,
	restore *velerov1api.Restore,
) (bool, error) {
	return true, nil
}

func NewVolumeSnapshotContentRestoreItemAction(
	f client.Factory,
) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}

		return &volumeSnapshotContentRestoreItemAction{logger, crClient}, nil
	}
}
