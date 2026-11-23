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
	"strings"
	"unicode"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	. "github.com/velero-io/velero/test"
	. "github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/common"
	. "github.com/velero-io/velero/test/util/k8s"
	. "github.com/velero-io/velero/test/util/providers"
	. "github.com/velero-io/velero/test/util/velero"
)

// volumeGroup is the value of the grouping label. The key is the one the
// Velero server groups by, velero.io/volume-group unless it was started with
// --volume-group-snapshot-label-key.
const volumeGroup = "volumeinfo"

// vgsPVCCount is how many PVCs share the group. Two is enough to tell a group
// snapshot from two independent ones.
const vgsPVCCount = 2

// vgsFileName is written into every grouped volume before the backup and read
// back after the restore.
const vgsFileName = "vgs-data"

var CSIVolumeGroupSnapshotVolumeInfoTest func() = TestFunc(&CSIVolumeGroupSnapshotVolumeInfo{
	BackupVolumeInfo: BackupVolumeInfo{
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

	// writtenContent maps a grouped volume's name to the content written into
	// it before the backup. Recorded at write time rather than recomputed in
	// Verify, so the check does not depend on the restored pod keeping the name
	// it had at backup time.
	writtenContent map[string]string
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

	// Populate every volume in the group. The shared base leaves some volumes
	// empty on purpose, to exercise the empty-PV data mover path, but here each
	// member needs content so that a group snapshot which restored only some of
	// its volumes is visible in Verify.
	podList, err := ListPods(c.Ctx, c.Client, namespace)
	if err != nil {
		return errors.Wrapf(err, "failed to list pods in namespace %s", namespace)
	}
	c.writtenContent = make(map[string]string, len(vols))
	for _, pod := range podList.Items {
		for _, vol := range vols {
			// CreateFileToPod ignores the content argument and writes a string
			// built from the namespace, pod and volume names, which is what
			// CreateFileContent returns. Record that same string so Verify can
			// compare against what is actually on disk.
			content := common.CreateFileContent(namespace, pod.Name, vol.Name)
			if err := CreateFileToPod(
				namespace,
				pod.Name,
				DefaultContainerName,
				vol.Name,
				vgsFileName,
				content,
				c.VeleroCfg.WorkerOS,
			); err != nil {
				return errors.Wrapf(err, "failed to write %s to volume %s of pod %s", vgsFileName, vol.Name, pod.Name)
			}
			c.writtenContent[vol.Name] = content
		}
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
		// CSISnapshotInfo is a pointer, so the line above prints its address. Print
		// the handle too, since it is what this case asserts on and a CI failure is
		// not diagnosable without it.
		fmt.Printf("PVC %s: VolumeGroupSnapshotHandle %q\n",
			info.PVCName, info.CSISnapshotInfo.VolumeGroupSnapshotHandle)
		Expect(info.CSISnapshotInfo.VolumeGroupSnapshotHandle).NotTo(BeEmpty(),
			fmt.Sprintf("PVC %s was not snapshotted by a VolumeGroupSnapshot", info.PVCName))

		if groupHandle == "" {
			groupHandle = info.CSISnapshotInfo.VolumeGroupSnapshotHandle
			continue
		}
		Expect(info.CSISnapshotInfo.VolumeGroupSnapshotHandle).To(Equal(groupHandle),
			"the volumes in the group were snapshotted by more than one VolumeGroupSnapshot")
	}

	// The metadata above only describes the backup. Check the restore as well:
	// every volume in the group must come back with the content written before
	// the backup, which is what shows the group snapshot was actually usable.
	namespace := c.CaseBaseName
	Expect(WaitForReadyDeployment(c.Client.ClientGo, namespace, c.CaseBaseName)).To(Succeed(),
		fmt.Sprintf("the deployment in namespace %s is not ready after the restore", namespace))

	Expect(c.writtenContent).To(HaveLen(vgsPVCCount),
		"CreateResources did not record what it wrote, so there is nothing to compare the restore against")

	podList, err := ListPods(c.Ctx, c.Client, namespace)
	Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("failed to list pods in namespace %s after the restore", namespace))

	podsChecked := 0
	for _, pod := range podList.Items {
		// A pod left over from before the restore may still be terminating.
		// Only the running one can be exec'd into.
		if pod.Status.Phase != corev1api.PodRunning {
			continue
		}
		podsChecked++

		restored := 0
		for _, vol := range pod.Spec.Volumes {
			expected, inGroup := c.writtenContent[vol.Name]
			if !inGroup {
				continue
			}
			content, _, err := ReadFileFromPodVolume(
				namespace,
				pod.Name,
				DefaultContainerName,
				vol.Name,
				vgsFileName,
				c.VeleroCfg.WorkerOS,
			)
			Expect(err).ToNot(HaveOccurred(),
				fmt.Sprintf("failed to read %s from volume %s of restored pod %s", vgsFileName, vol.Name, pod.Name))

			content = strings.TrimRightFunc(content, unicode.IsSpace)
			Expect(content).To(Equal(expected),
				fmt.Sprintf("volume %s did not come back with its contents.\n expected: %s\n got: %s", vol.Name, expected, content))
			restored++
		}
		Expect(restored).To(Equal(vgsPVCCount),
			fmt.Sprintf("pod %s came back with %d of the %d volumes in the group", pod.Name, restored, vgsPVCCount))
	}
	Expect(podsChecked).To(BeNumerically(">", 0),
		fmt.Sprintf("no running pod was restored into namespace %s, so nothing was verified", namespace))
	return nil
}
