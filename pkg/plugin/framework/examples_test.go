/*
Copyright 2020 the Velero contributors.

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

package framework

import (
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/velero-io/velero/pkg/plugin/velero"
)

func ExampleNewServer_volumeSnapshotter() {
	NewServer(). // call the server
			RegisterVolumeSnapshotter("example.io/volumesnapshotter", newVolumeSnapshotter). // register the plugin with a valid name
			RegisterDeleteItemAction("example.io/delete-item-action", newDeleteItemAction).
			Serve() // serve the plugin
}

func newVolumeSnapshotter(logger logrus.FieldLogger) (any, error) {
	return &VolumeSnapshotter{FieldLogger: logger}, nil
}

type VolumeSnapshotter struct {
	FieldLogger logrus.FieldLogger
}

// Implement all methods for the VolumeSnapshotter interface...
func (b *VolumeSnapshotter) Init(config map[string]string) error {
	b.FieldLogger.Infof("VolumeSnapshotter.Init called")

	// ...

	return nil
}

func (b *VolumeSnapshotter) CreateVolumeFromSnapshot(snapshotID, volumeType, volumeAZ string, iops *int64) (volumeID string, err error) {
	b.FieldLogger.Infof("CreateVolumeFromSnapshot called")

	// ...

	return "volumeID", nil
}

func (b *VolumeSnapshotter) GetVolumeID(pv runtime.Unstructured) (string, error) {
	b.FieldLogger.Infof("GetVolumeID called")

	// ...

	return "volumeID", nil
}

func (b *VolumeSnapshotter) SetVolumeID(pv runtime.Unstructured, volumeID string) (runtime.Unstructured, error) {
	b.FieldLogger.Infof("SetVolumeID called")

	// ...

	return nil, nil
}

func (b *VolumeSnapshotter) GetVolumeInfo(volumeID, volumeAZ string) (string, *int64, error) {
	b.FieldLogger.Infof("GetVolumeInfo called")

	// ...

	return "volumeFilesystemType", nil, nil
}

func (b *VolumeSnapshotter) CreateSnapshot(volumeID, volumeAZ string, tags map[string]string) (snapshotID string, err error) {
	b.FieldLogger.Infof("CreateSnapshot called")

	// ...

	return "snapshotID", nil
}

func (b *VolumeSnapshotter) DeleteSnapshot(snapshotID string) error {
	b.FieldLogger.Infof("DeleteSnapshot called")

	// ...

	return nil
}

// Implement all methods for the DeleteItemAction interface

func newDeleteItemAction(logger logrus.FieldLogger) (any, error) {
	return DeleteItemAction{FieldLogger: logger}, nil
}

type DeleteItemAction struct {
	FieldLogger logrus.FieldLogger
}

func (d *DeleteItemAction) AppliesTo() (velero.ResourceSelector, error) {
	d.FieldLogger.Infof("AppliesTo called")

	// ...

	return velero.ResourceSelector{}, nil
}

func (d *DeleteItemAction) Execute(input *velero.DeleteItemActionExecuteInput) error {
	d.FieldLogger.Infof("Execute called")

	// ...

	return nil
}
