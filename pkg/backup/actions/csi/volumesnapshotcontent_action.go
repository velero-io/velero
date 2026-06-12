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
	"fmt"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	csiutil "github.com/vmware-tanzu/velero/pkg/util/csi"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

// volumeSnapshotContentBackupItemAction is a backup item action plugin to backup
// CSI VolumeSnapshotContent objects using Velero
type volumeSnapshotContentBackupItemAction struct {
	log logrus.FieldLogger
}

// AppliesTo returns information indicating that the
// VolumeSnapshotContentBackupItemAction action should be invoked to
// backup VolumeSnapshotContents.
func (p *volumeSnapshotContentBackupItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshotcontents.snapshot.storage.k8s.io"},
	}, nil
}

// Execute returns the unmodified VolumeSnapshotContent object along
// with the snapshot deletion secret, if any, from its annotation
// as additional items to backup.
func (p *volumeSnapshotContentBackupItemAction) Execute(
	item runtime.Unstructured,
	backup *velerov1api.Backup,
) (
	runtime.Unstructured,
	[]velero.ResourceIdentifier,
	string,
	[]velero.ResourceIdentifier,
	error,
) {
	p.log.Infof("Executing VolumeSnapshotContentBackupItemAction")

	if backup.Status.Phase == velerov1api.BackupPhaseFinalizing ||
		backup.Status.Phase == velerov1api.BackupPhaseFinalizingPartiallyFailed {
		p.log.WithField("Backup", fmt.Sprintf("%s/%s", backup.Namespace, backup.Name)).
			WithField("BackupPhase", backup.Status.Phase).
			Debug("Skipping VolumeSnapshotContentBackupItemAction",
				"as backup is in finalizing phase.")
		return item, nil, "", nil, nil
	}

	var snapCont snapshotv1api.VolumeSnapshotContent
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		item.UnstructuredContent(),
		&snapCont,
	); err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	additionalItems := []velero.ResourceIdentifier{}

	// we should backup the snapshot deletion secrets that may be referenced
	// in the VolumeSnapshotContent's annotation
	if csiutil.IsVolumeSnapshotContentHasDeleteSecret(&snapCont) {
		additionalItems = append(
			additionalItems,
			velero.ResourceIdentifier{
				GroupResource: kuberesource.Secrets,
				Name:          snapCont.Annotations[velerov1api.PrefixedSecretNameAnnotation],
				Namespace:     snapCont.Annotations[velerov1api.PrefixedSecretNamespaceAnnotation],
			})

		kubeutil.AddAnnotations(&snapCont.ObjectMeta, map[string]string{
			velerov1api.MustIncludeAdditionalItemAnnotation: "true",
		})
	}

	// Because async operation will update VolumeSnapshotContent during finalizing phase.
	// No matter what we do, VolumeSnapshotClass cannot be deleted. So skip it.
	// Just deleting VolumeSnapshotClass during restore and delete is enough.

	snapContMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&snapCont)
	if err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	p.log.Infof(
		"Returning from VolumeSnapshotContentBackupItemAction",
		"with %d additionalItems to backup",
		len(additionalItems),
	)
	return &unstructured.Unstructured{Object: snapContMap}, additionalItems, "", nil, nil
}

// Name returns the plugin's name.
func (p *volumeSnapshotContentBackupItemAction) Name() string {
	return "VolumeSnapshotContentBackupItemAction"
}

// Progress is not implemented for VolumeSnapshotContentBackupItemAction.
func (p *volumeSnapshotContentBackupItemAction) Progress(
	operationID string,
	backup *velerov1api.Backup,
) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

// Cancel is not implemented for VolumeSnapshotContentBackupItemAction.
func (p *volumeSnapshotContentBackupItemAction) Cancel(
	operationID string,
	backup *velerov1api.Backup,
) error {
	// CSI Specification doesn't support canceling a snapshot creation.
	return nil
}

// NewVolumeSnapshotContentBackupItemAction returns a
// VolumeSnapshotContentBackupItemAction instance.
func NewVolumeSnapshotContentBackupItemAction(
	logger logrus.FieldLogger,
) (any, error) {
	return &volumeSnapshotContentBackupItemAction{log: logger}, nil
}
