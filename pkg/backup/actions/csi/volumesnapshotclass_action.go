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
	"github.com/sirupsen/logrus"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	csiutil "github.com/vmware-tanzu/velero/pkg/util/csi"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

// volumeSnapshotClassBackupItemAction is a backup item action plugin to
// backup CSI VolumeSnapshotClass objects using Velero
type volumeSnapshotClassBackupItemAction struct {
	log logrus.FieldLogger
}

// AppliesTo returns information indicating that the
// VolumeSnapshotClassBackupItemAction action should be invoked
// to backup VolumeSnapshotClass.
func (p *volumeSnapshotClassBackupItemAction) AppliesTo() (
	velero.ResourceSelector,
	error,
) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshotclasses.snapshot.storage.k8s.io"},
	}, nil
}

// Execute backs up a VolumeSnapshotClass object and returns as additional
// items any snapshot lister secret that may be referenced in its annotations.
func (p *volumeSnapshotClassBackupItemAction) Execute(
	item runtime.Unstructured,
	backup *velerov1api.Backup,
) (
	runtime.Unstructured,
	[]velero.ResourceIdentifier,
	string,
	[]velero.ResourceIdentifier,
	error,
) {
	p.log.Infof("Executing VolumeSnapshotClassBackupItemAction")

	var snapClass snapshotv1api.VolumeSnapshotClass
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		item.UnstructuredContent(),
		&snapClass,
	); err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	additionalItems := []velero.ResourceIdentifier{}
	if csiutil.IsVolumeSnapshotClassHasListerSecret(&snapClass) {
		additionalItems = append(additionalItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.Secrets,
			Name:          snapClass.Annotations[velerov1api.PrefixedListSecretNameAnnotation],
			Namespace:     snapClass.Annotations[velerov1api.PrefixedListSecretNamespaceAnnotation],
		})

		kubeutil.AddAnnotations(&snapClass.ObjectMeta, map[string]string{
			velerov1api.MustIncludeAdditionalItemAnnotation: "true",
		})
	}

	snapClassMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&snapClass)
	if err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	p.log.Infof(
		"Returning from VolumeSnapshotClassBackupItemAction with %d additionalItems to backup",
		len(additionalItems),
	)
	return &unstructured.Unstructured{Object: snapClassMap}, additionalItems, "", nil, nil
}

// Name returns the plugin's name.
func (p *volumeSnapshotClassBackupItemAction) Name() string {
	return "VolumeSnapshotClassBackupItemAction"
}

// Progress is not implemented for VolumeSnapshotClassBackupItemAction
func (p *volumeSnapshotClassBackupItemAction) Progress(
	operationID string,
	backup *velerov1api.Backup,
) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

// Cancel is not implemented for VolumeSnapshotClassBackupItemAction
func (p *volumeSnapshotClassBackupItemAction) Cancel(
	operationID string,
	backup *velerov1api.Backup,
) error {
	return nil
}

// NewVolumeSnapshotClassBackupItemAction returns a
// VolumeSnapshotClassBackupItemAction instance.
func NewVolumeSnapshotClassBackupItemAction(logger logrus.FieldLogger) (any, error) {
	return &volumeSnapshotClassBackupItemAction{log: logger}, nil
}
