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

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

type BackupVolumeInfo struct {
	TestCase
	SnapshotVolumes          bool
	DefaultVolumesToFSBackup bool
	SnapshotMoveData         bool
	TimeoutDuration          time.Duration
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

	v.RestoreArgs = []string{
		"create", "--namespace", v.VeleroCfg.VeleroNamespace, "restore", v.RestoreName,
		"--from-backup", v.BackupName, "--wait",
	}
	return nil
}

func (v *BackupVolumeInfo) Start() error {
	if strings.Contains(v.VeleroCfg.Features, FeatureCSI) {
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
				// Hitting issue https://github.com/vmware-tanzu/velero/issues/7388
				// So populate data only to some of pods, leave other pods empty to verify empty PV datamover
				if i%2 == 0 {
					Expect(CreateFileToPod(
						createNSName,
						pod.Name,
						DefaultContainerName,
						vols[i].Name,
						fmt.Sprintf("file-%s", pod.Name),
						CreateFileContent(createNSName, pod.Name, vols[i].Name),
						v.VeleroCfg.WorkerOS,
					)).To(Succeed())
				}
			}
		}
	}
	return nil
}

func (v *BackupVolumeInfo) Destroy() error {
	err := CleanupNamespaces(v.Ctx, v.Client, v.CaseBaseName)
	if err != nil {
		return errors.Wrap(err, "Could cleanup retrieve namespaces")
	}

	return WaitAllSelectedNSDeleted(v.Ctx, v.Client, "ns-test=true")
}
