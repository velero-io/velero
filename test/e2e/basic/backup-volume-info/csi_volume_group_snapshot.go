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

package basic

import (
	"fmt"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/providers"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

// volumeGroup is the value of the grouping label. The key is the one the
// Velero server groups by, velero.io/volume-group unless it was started with
// --volume-group-snapshot-label-key.
const volumeGroup = "volumeinfo"

// vgsPVCCount is how many PVCs share the group. Two is enough to tell a group
// snapshot from two independent ones.
const vgsPVCCount = 2

var CSIVolumeGroupSnapshotVolumeInfoTest func() = TestFunc(&CSIVolumeGroupSnapshotVolumeInfo{
	BackupVolumeInfo{
		SnapshotVolumes: true,
		TestCase: TestCase{
			CaseBaseName: "csi-vgs-volumeinfo",
			TestMsg: &TestMSG{
				Desc: "Test backup's VolumeInfo metadata content for the CSI VolumeGroupSnapshot case.",
				Text: "PVCs sharing the group label should be snapshotted by one VolumeGroupSnapshot, and the VolumeInfo should report the same VolumeGroupSnapshotHandle for each of them.",
			},
		},
	},
})

type CSIVolumeGroupSnapshotVolumeInfo struct {
	BackupVolumeInfo
}

// CreateResources replaces the base case's resources with PVCs that carry the
// grouping label, which is what makes Velero take a VolumeGroupSnapshot rather
// than one snapshot per volume.
func (c *CSIVolumeGroupSnapshotVolumeInfo) CreateResources() error {
	labels := map[string]string{
		"volume-info": "true",
	}

	if c.VeleroCfg.WorkerOS == common.WorkerOSWindows {
		labels["pod-security.kubernetes.io/enforce"] = "privileged"
		labels["pod-security.kubernetes.io/enforce-version"] = "latest"
	}

	namespace := c.CaseBaseName
	fmt.Printf("Creating namespace %s ...\n", namespace)
	if err := CreateNamespaceWithLabel(c.Ctx, c.Client, namespace, labels); err != nil {
		return errors.Wrapf(err, "failed to create namespace %s", namespace)
	}

	var vols []*corev1api.Volume
	for i := range vgsPVCCount {
		pvcName := fmt.Sprintf("vgs-pvc-%d", i)
		fmt.Printf("Creating PVC %s in namespace %s, in volume group %s ...\n", pvcName, namespace, volumeGroup)

		pvcBuilder := NewPVC(namespace, pvcName).
			WithLabels(map[string]string{velerov1api.DefaultVGSLabelKey: volumeGroup}).
			WithStorageClass(StorageClassName)
		if err := CreatePvc(c.Client, pvcBuilder); err != nil {
			return errors.Wrapf(err, "failed to create PVC %s", pvcName)
		}

		volumeName := fmt.Sprintf("vgs-pv-%d", i)
		vols = append(vols, CreateVolumes(pvcName, []string{volumeName})...)
	}

	// The PVCs only bind once something mounts them, so the deployment is what
	// gives the snapshots anything to snapshot.
	deployment := NewDeployment(
		c.CaseBaseName,
		namespace,
		1,
		labels,
		c.VeleroCfg.ImageRegistryProxy,
		c.VeleroCfg.WorkerOS,
	).WithVolume(vols).Result()

	deployment, err := CreateDeployment(c.Client.ClientGo, namespace, deployment)
	if err != nil {
		return errors.Wrapf(err, "failed to create deployment in namespace %s", namespace)
	}
	if err := WaitForReadyDeployment(c.Client.ClientGo, namespace, deployment.Name); err != nil {
		return errors.Wrapf(err, "failed to wait for the deployment in namespace %s", namespace)
	}
	return nil
}

func (c *CSIVolumeGroupSnapshotVolumeInfo) Verify() error {
	volumeInfo, err := GetVolumeInfo(
		c.VeleroCfg.ObjectStoreProvider,
		c.VeleroCfg.CloudCredentialsFile,
		c.VeleroCfg.BSLBucket,
		c.VeleroCfg.BSLPrefix,
		c.VeleroCfg.BSLConfig,
		c.BackupName,
		BackupObjectsPrefix+"/"+c.BackupName,
	)
	Expect(err).ToNot(HaveOccurred(), "Fail to get VolumeInfo metadata in the Backup Repository.")
	Expect(volumeInfo).To(HaveLen(vgsPVCCount))

	// Every volume in the group must report the same VolumeGroupSnapshotHandle.
	// One shared handle is what distinguishes a group snapshot from the volumes
	// having been snapshotted one by one.
	var groupHandle string
	for _, info := range volumeInfo {
		fmt.Printf("The VolumeInfo metadata content: %+v\n", *info)
		Expect(info.CSISnapshotInfo).NotTo(BeNil())
		Expect(info.CSISnapshotInfo.VolumeGroupSnapshotHandle).NotTo(BeEmpty(),
			fmt.Sprintf("PVC %s was not snapshotted by a VolumeGroupSnapshot", info.PVCName))

		if groupHandle == "" {
			groupHandle = info.CSISnapshotInfo.VolumeGroupSnapshotHandle
			continue
		}
		Expect(info.CSISnapshotInfo.VolumeGroupSnapshotHandle).To(Equal(groupHandle),
			"the volumes in the group were snapshotted by more than one VolumeGroupSnapshot")
	}
	return nil
}
