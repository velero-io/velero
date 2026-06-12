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
	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/csi"
)

// volumeSnapshotClassRestoreItemAction is a Velero restore
// item action plugin for VolumeSnapshotClass
type volumeSnapshotClassRestoreItemAction struct {
	log logrus.FieldLogger
}

// AppliesTo returns information indicating that VolumeSnapshotClassRestoreItemAction
// should be invoked while restoring volumesnapshotclass.snapshot.storage.k8s.io resources.
func (p *volumeSnapshotClassRestoreItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshotclasses.snapshot.storage.k8s.io"},
	}, nil
}

// Execute restores VolumeSnapshotClass objects returning any
// snapshotlister secret as additional items to restore
func (p *volumeSnapshotClassRestoreItemAction) Execute(
	input *velero.RestoreItemActionExecuteInput,
) (*velero.RestoreItemActionExecuteOutput, error) {
	p.log.Info("Starting VolumeSnapshotClassRestoreItemAction")
	if boolptr.IsSetToFalse(input.Restore.Spec.RestorePVs) {
		p.log.Infof("Restore did not request for PVs to be restored %s/%s",
			input.Restore.Namespace, input.Restore.Name)
		return &velero.RestoreItemActionExecuteOutput{SkipRestore: true}, nil
	}
	var snapClass snapshotv1api.VolumeSnapshotClass

	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.Item.UnstructuredContent(), &snapClass); err != nil {
		return &velero.RestoreItemActionExecuteOutput{}, errors.Wrapf(err,
			"failed to convert input.Item from unstructured")
	}

	additionalItems := []velero.ResourceIdentifier{}
	if csi.IsVolumeSnapshotClassHasListerSecret(&snapClass) {
		additionalItems = append(additionalItems, velero.ResourceIdentifier{
			GroupResource: schema.GroupResource{Group: "", Resource: "secrets"},
			Name:          snapClass.Annotations[velerov1api.PrefixedListSecretNameAnnotation],
			Namespace:     snapClass.Annotations[velerov1api.PrefixedListSecretNamespaceAnnotation],
		})
	}

	p.log.Infof("Returning from VolumeSnapshotClassRestoreItemAction with %d additionalItems",
		len(additionalItems))

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem:     input.Item,
		AdditionalItems: additionalItems,
	}, nil
}

func (p *volumeSnapshotClassRestoreItemAction) Name() string {
	return "VolumeSnapshotClassRestoreItemAction"
}

func (p *volumeSnapshotClassRestoreItemAction) Progress(
	operationID string,
	restore *velerov1api.Restore,
) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

func (p *volumeSnapshotClassRestoreItemAction) Cancel(
	operationID string,
	restore *velerov1api.Restore,
) error {
	return nil
}

func (p *volumeSnapshotClassRestoreItemAction) AreAdditionalItemsReady(
	additionalItems []velero.ResourceIdentifier,
	restore *velerov1api.Restore,
) (bool, error) {
	return true, nil
}

func NewVolumeSnapshotClassRestoreItemAction(
	logger logrus.FieldLogger) (any, error) {
	return &volumeSnapshotClassRestoreItemAction{logger}, nil
}
