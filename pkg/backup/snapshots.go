/*
Copyright The Velero Contributors.

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

package backup

import (
	"context"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/features"
	"github.com/velero-io/velero/pkg/label"
	"github.com/velero-io/velero/pkg/util/boolptr"
)

// GetBackupCSIResources is used to get CSI snapshot related resources.
// Returns VolumeSnapshot, VolumeSnapshotContent, VolumeSnapshotClasses referenced
func GetBackupCSIResources(
	client kbclient.Client,
	globalCRClient kbclient.Client,
	backup *velerov1api.Backup,
	backupLog logrus.FieldLogger,
) (
	volumeSnapshots []snapshotv1api.VolumeSnapshot,
	volumeSnapshotContents []snapshotv1api.VolumeSnapshotContent,
	volumeSnapshotClasses []snapshotv1api.VolumeSnapshotClass,
) {
	if boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData) {
		backupLog.Info("backup SnapshotMoveData is set to true, skip VolumeSnapshot resource persistence.")
	} else if features.IsEnabled(velerov1api.CSIFeatureFlag) {
		selector := label.NewSelectorForBackup(backup.Name)
		vscList := &snapshotv1api.VolumeSnapshotContentList{}

		vsList := new(snapshotv1api.VolumeSnapshotList)
		err := globalCRClient.List(context.TODO(), vsList, &kbclient.ListOptions{
			LabelSelector: label.NewSelectorForBackup(backup.Name),
		})
		if err != nil {
			backupLog.Error(err)
		}
		volumeSnapshots = append(volumeSnapshots, vsList.Items...)

		if err := client.List(context.Background(), vscList, &kbclient.ListOptions{LabelSelector: selector}); err != nil {
			backupLog.Error(err)
		}
		if len(vscList.Items) >= 0 {
			volumeSnapshotContents = vscList.Items
		}

		vsClassSet := sets.NewString()
		for index := range volumeSnapshotContents {
			// persist the volumesnapshotclasses referenced by vsc
			if volumeSnapshotContents[index].Spec.VolumeSnapshotClassName != nil && !vsClassSet.Has(*volumeSnapshotContents[index].Spec.VolumeSnapshotClassName) {
				vsClass := &snapshotv1api.VolumeSnapshotClass{}
				if err := client.Get(context.TODO(), kbclient.ObjectKey{Name: *volumeSnapshotContents[index].Spec.VolumeSnapshotClassName}, vsClass); err != nil {
					backupLog.Error(err)
				} else {
					vsClassSet.Insert(*volumeSnapshotContents[index].Spec.VolumeSnapshotClassName)
					volumeSnapshotClasses = append(volumeSnapshotClasses, *vsClass)
				}
			}
		}
		backup.Status.CSIVolumeSnapshotsAttempted = len(volumeSnapshots)
	}

	return volumeSnapshots, volumeSnapshotContents, volumeSnapshotClasses
}
