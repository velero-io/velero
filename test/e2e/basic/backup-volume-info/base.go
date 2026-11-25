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
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"

	. "github.com/velero-io/velero/test"
	. "github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/common"
	. "github.com/velero-io/velero/test/util/common"
	. "github.com/velero-io/velero/test/util/k8s"
)

type BackupVolumeInfo struct {
	TestCase
	SnapshotVolumes          bool
	DefaultVolumesToFSBackup bool
	SnapshotMoveData         bool
	TimeoutDuration          time.Duration

	// restoredVolumes records what CreateResources put in each volume, so the
	// restore can be checked against it. Recorded at write time rather than
	// recomputed during verification: the content includes the pod name, and
	// rebuilding it from the restored pod would quietly depend on Velero
	// bringing the pod back under the name it had at backup time.
	restoredVolumes []volumeContent
}

// volumeContent is one volume as CreateResources left it. An empty FileName
// means the volume was deliberately left empty and must come back that way.
type volumeContent struct {
	VolumeName string
	FileName   string
	Content    string
}

func (v *BackupVolumeInfo) Init() error {
	v.TestCase.Init()
	v.CaseBaseName = v.CaseBaseName + v.UUIDgen
	v.BackupName = "backup-" + v.CaseBaseName
	v.RestoreName = "restore-" + v.CaseBaseName
	v.TimeoutDuration = 10 * time.Minute
	v.NamespacesTotal = 1

	v.VeleroCfg = VeleroCfg
	v.Client = *v.VeleroCfg.ClientToInstallVelero
	v.NSIncluded = &[]string{v.CaseBaseName}

	v.TestMsg = &TestMSG{
		Desc:      "Test backup's VolumeInfo metadata content",
		Text:      "The VolumeInfo should be generated based on the backup type",
		FailedMSG: "Failed to verify the backup VolumeInfo's content",
	}

	v.BackupArgs = []string{
		"backup", "create", v.BackupName,
		"--namespace", v.VeleroCfg.VeleroNamespace,
		"--include-namespaces", v.CaseBaseName,
		"--snapshot-volumes" + "=" + strconv.FormatBool(v.SnapshotVolumes),
		"--default-volumes-to-fs-backup" + "=" + strconv.FormatBool(v.DefaultVolumesToFSBackup),
		"--snapshot-move-data" + "=" + strconv.FormatBool(v.SnapshotMoveData),
		"--wait",
	}

	if v.SnapshotMoveData && v.VeleroCfg.DataMover != "" {
		v.BackupArgs = append(v.BackupArgs, "--data-mover", v.VeleroCfg.DataMover)
	}

	v.RestoreArgs = []string{
		"create", "--namespace", v.VeleroCfg.VeleroNamespace, "restore", v.RestoreName,
		"--from-backup", v.BackupName, "--wait",
	}
	return nil
}

func (v *BackupVolumeInfo) Start() error {
	if FeatureEnabled(v.VeleroCfg.Features, FeatureCSI) {
		if strings.Contains(v.CaseBaseName, "native-snapshot") {
			fmt.Printf("Skip native snapshot case %s when the CSI feature is enabled.\n", v.CaseBaseName)
			Skip("Skip native snapshot case due to CSI feature is enabled.")
		}
	} else {
		if strings.Contains(v.CaseBaseName, "csi") {
			fmt.Printf("Skip CSI related case %s when the CSI feature is not enabled.\n", v.CaseBaseName)
			Skip("Skip CSI cases due to CSI feature is not enabled.")
		}
	}
	v.TestCase.Start()
	return nil
}
func (v *BackupVolumeInfo) CreateResources() error {
	labels := map[string]string{
		"volume-info": "true",
	}

	if v.VeleroCfg.WorkerOS == common.WorkerOSWindows {
		labels["pod-security.kubernetes.io/enforce"] = "privileged"
		labels["pod-security.kubernetes.io/enforce-version"] = "latest"
	}

	for nsNum := 0; nsNum < v.NamespacesTotal; nsNum++ {
		fmt.Printf("Creating namespaces ...\n")
		createNSName := v.CaseBaseName
		if err := CreateNamespaceWithLabel(v.Ctx, v.Client, createNSName, labels); err != nil {
			return errors.Wrapf(err, "Failed to create namespace %s", createNSName)
		}

		// Create deployment
		fmt.Printf("Creating deployment in namespaces ...%s\n", createNSName)
		// Make sure PVC count is great than 3 to allow both empty volumes and file populated volumes exist per pod
		pvcCount := 4
		Expect(pvcCount).To(BeNumerically(">", 3))

		var vols []*corev1api.Volume
		for i := 0; i <= pvcCount-1; i++ {
			pvcName := fmt.Sprintf("volume-info-pvc-%d", i)
			pvc, err := CreatePVC(v.Client, createNSName, pvcName, StorageClassName, nil)
			Expect(err).To(Succeed())
			volumeName := fmt.Sprintf("volume-info-pv-%d", i)
			vols = append(vols, CreateVolumes(pvc.Name, []string{volumeName})...)
		}
		deployment := NewDeployment(
			v.CaseBaseName,
			createNSName,
			1,
			labels,
			v.VeleroCfg.ImageRegistryProxy,
			v.VeleroCfg.WorkerOS,
		).WithVolume(vols).Result()
		deployment, err := CreateDeployment(v.Client.ClientGo, createNSName, deployment)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to delete the namespace %q", createNSName))
		}
		err = WaitForReadyDeployment(v.Client.ClientGo, createNSName, deployment.Name)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to ensure job completion in namespace: %q", createNSName))
		}
		podList, err := ListPods(v.Ctx, v.Client, createNSName)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to list pods in namespace: %q with error %v", createNSName, err))

		for _, pod := range podList.Items {
			for i := 0; i <= pvcCount-1; i++ {
				// Hitting issue https://github.com/velero-io/velero/issues/7388
				// So populate data only to some of pods, leave other pods empty to verify empty PV datamover
				if i%2 == 0 {
					fileName := fmt.Sprintf("file-%s", pod.Name)
					content := CreateFileContent(createNSName, pod.Name, vols[i].Name)
					Expect(CreateFileToPod(
						createNSName,
						pod.Name,
						DefaultContainerName,
						vols[i].Name,
						fileName,
						content,
						v.VeleroCfg.WorkerOS,
					)).To(Succeed())
					v.restoredVolumes = append(v.restoredVolumes, volumeContent{
						VolumeName: vols[i].Name,
						FileName:   fileName,
						Content:    content,
					})
					continue
				}
				// Left empty on purpose. Record it anyway: a restore that loses
				// an empty volume, or fills one, is also wrong.
				v.restoredVolumes = append(v.restoredVolumes, volumeContent{
					VolumeName: vols[i].Name,
					FileName:   fmt.Sprintf("file-%s", pod.Name),
				})
			}
		}
	}
	return nil
}

// fileAbsent reports whether a failed read failed because the file is not
// there, as opposed to the read itself going wrong. cat and cmd's type word it
// differently, so both are matched.
func fileAbsent(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "no such file") ||
		strings.Contains(lower, "cannot find the file") ||
		strings.Contains(lower, "cannot find the path")
}

// VerifyRestoredVolumeContents checks the restore, not just the backup
// metadata. Every volume CreateResources populated must come back with its
// contents, and every volume it deliberately left empty must come back empty.
//
// The cases that call this restore into the namespace they backed up, so the
// workload is expected under the same name.
func (v *BackupVolumeInfo) VerifyRestoredVolumeContents(namespace string) error {
	Expect(v.restoredVolumes).ToNot(BeEmpty(),
		"CreateResources recorded no volumes, so there is nothing to check the restore against")

	Expect(WaitForReadyDeployment(v.Client.ClientGo, namespace, v.CaseBaseName)).To(Succeed(),
		fmt.Sprintf("the deployment in namespace %s is not ready after the restore", namespace))

	podList, err := ListPods(v.Ctx, v.Client, namespace)
	Expect(err).ToNot(HaveOccurred(),
		fmt.Sprintf("failed to list pods in namespace %s after the restore", namespace))

	expected := make(map[string]volumeContent, len(v.restoredVolumes))
	for _, vol := range v.restoredVolumes {
		expected[vol.VolumeName] = vol
	}

	podsChecked := 0
	for _, pod := range podList.Items {
		// A pod from before the restore may still be terminating, and only a
		// running one can be exec'd into.
		if pod.Status.Phase != corev1api.PodRunning {
			continue
		}
		podsChecked++

		checked := 0
		for _, vol := range pod.Spec.Volumes {
			want, ours := expected[vol.Name]
			if !ours {
				continue
			}
			checked++

			content, readStderr, readErr := ReadFileFromPodVolume(
				namespace, pod.Name, DefaultContainerName, vol.Name, want.FileName, v.VeleroCfg.WorkerOS,
			)
			if want.Content == "" {
				// Nothing was written here, so the read is expected to fail
				// because the file is absent. Checking the reason matters:
				// any other failure, an exec that could not reach the pod for
				// instance, would otherwise read as proof the volume is empty.
				Expect(readErr).To(HaveOccurred(),
					fmt.Sprintf("volume %s was left empty before the backup but came back with %q", vol.Name, content))
				Expect(fileAbsent(readStderr)).To(BeTrue(),
					fmt.Sprintf("reading %s from the empty volume %s failed for a reason other than the file being absent: %s",
						want.FileName, vol.Name, readStderr))
				continue
			}

			Expect(readErr).ToNot(HaveOccurred(),
				fmt.Sprintf("failed to read %s from volume %s of restored pod %s", want.FileName, vol.Name, pod.Name))
			Expect(strings.TrimRightFunc(content, unicode.IsSpace)).To(Equal(want.Content),
				fmt.Sprintf("volume %s did not come back with its contents", vol.Name))
		}
		Expect(checked).To(Equal(len(expected)),
			fmt.Sprintf("pod %s came back with %d of the %d volumes that were backed up", pod.Name, checked, len(expected)))
	}
	Expect(podsChecked).To(BeNumerically(">", 0),
		fmt.Sprintf("no running pod was restored into namespace %s, so nothing was verified", namespace))

	return nil
}

func (v *BackupVolumeInfo) Destroy() error {
	err := CleanupNamespaces(v.Ctx, v.Client, v.CaseBaseName)
	if err != nil {
		return errors.Wrap(err, "Could cleanup retrieve namespaces")
	}

	return WaitAllSelectedNSDeleted(v.Ctx, v.Client, "ns-test=true")
}
