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

package nodeagentconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	k8sutil "github.com/vmware-tanzu/velero/test/util/k8s"
	veleroutil "github.com/vmware-tanzu/velero/test/util/velero"
)

type NodeAgentConfigTestCase struct {
	TestCase
	nodeAgentConfigs       velerotypes.NodeAgentConfigs
	nodeAgentConfigMapName string
}

var LoadAffinities func() = TestFunc(&NodeAgentConfigTestCase{
	nodeAgentConfigs: velerotypes.NodeAgentConfigs{
		LoadAffinity: []*kube.LoadAffinity{
			{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"beta.kubernetes.io/arch": "amd64",
					},
				},
				StorageClass: test.StorageClassName,
			},
			{
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/arch": "amd64",
					},
				},
				StorageClass: test.StorageClassName2,
			},
		},
		BackupPVCConfig: map[string]velerotypes.BackupPVC{
			test.StorageClassName: {
				StorageClass: test.StorageClassName2,
			},
		},
		RestorePVCConfig: &velerotypes.RestorePVC{
			IgnoreDelayBinding: true,
		},
		PriorityClassName: test.PriorityClassNameForDataMover,
		// Explicitly add custom labels and annotations to be tested
		PodLabels: map[string]string{
			"spectrocloud.com/connection": "proxy", // Tests appending custom labels (Issue #9435)
			"azure.workload.identity/use": "true",  // Tests overwriting built-in labels
		},
		PodAnnotations: map[string]string{
			"test-data-mover-annotation": "true",
		},
	},
	nodeAgentConfigMapName: "node-agent-config",
})

func (n *NodeAgentConfigTestCase) Init() error {
	// generate random number as UUIDgen and set one default timeout duration
	n.TestCase.Init()

	// generate variable names based on CaseBaseName + UUIDgen
	n.CaseBaseName = "node-agent-config-" + n.UUIDgen
	n.BackupName = "backup-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName

	// generate namespaces by NamespacesTotal
	n.NamespacesTotal = 1
	n.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < n.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", n.CaseBaseName, nsNum)
		*n.NSIncluded = append(*n.NSIncluded, createNSName)
	}

	// assign values to the inner variable for specific case
	n.VeleroCfg.UseNodeAgent = true
	n.VeleroCfg.UseNodeAgentWindows = true

	// Need to verify the data mover pod content, so don't wait until backup completion.
	n.BackupArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "backup", n.BackupName,
		"--include-namespaces", strings.Join(*n.NSIncluded, ","),
		"--snapshot-volumes=true", "--snapshot-move-data",
	}

	// Need to verify the data mover pod content, so don't wait until restore completion.
	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore", n.RestoreName,
		"--from-backup", n.BackupName,
	}

	// Message output by ginkgo
	n.TestMsg = &TestMSG{
		Desc:      "Validate Node Agent ConfigMap configuration",
		FailedMSG: "Failed to apply and / or validate configuration in VGDP pod.",
		Text:      "Should be able to apply and validate configuration in VGDP pod.",
	}
	return nil
}

func (n *NodeAgentConfigTestCase) InstallVelero() error {
	// Because this test needs to use customized Node Agent ConfigMap,
	// need to uninstall and reinstall Velero.

	fmt.Println("Start to uninstall Velero")
	if err := veleroutil.VeleroUninstall(n.Ctx, n.VeleroCfg); err != nil {
		fmt.Printf("Fail to uninstall Velero: %s\n", err.Error())
		return err
	}

	result, err := json.Marshal(n.nodeAgentConfigs)
	if err != nil {
		return err
	}

	repoMaintenanceConfig := builder.ForConfigMap(n.VeleroCfg.VeleroNamespace, n.nodeAgentConfigMapName).
		Data("node-agent-config", string(result)).Result()

	n.VeleroCfg.NodeAgentConfigMap = n.nodeAgentConfigMapName

	return veleroutil.PrepareVelero(
		n.Ctx,
		n.CaseBaseName,
		n.VeleroCfg,
		repoMaintenanceConfig,
	)
}

func (n *NodeAgentConfigTestCase) CreateResources() error {
	for _, ns := range *n.NSIncluded {
		if err := k8sutil.CreateNamespace(n.Ctx, n.Client, ns); err != nil {
			fmt.Printf("Fail to create ns %s: %s\n", ns, err.Error())
			return err
		}

		pvc, err := k8sutil.CreatePVC(n.Client, ns, "volume-1", test.StorageClassName, nil)
		if err != nil {
			fmt.Printf("Fail to create PVC %s: %s\n", "volume-1", err.Error())
			return err
		}

		vols := k8sutil.CreateVolumes(pvc.Name, []string{"volume-1"})

		deployment := k8sutil.NewDeployment(
			n.CaseBaseName,
			(*n.NSIncluded)[0],
			1,
			map[string]string{"app": "test"},
			n.VeleroCfg.ImageRegistryProxy,
			n.VeleroCfg.WorkerOS,
		).WithVolume(vols).Result()

		deployment, err = k8sutil.CreateDeployment(n.Client.ClientGo, ns, deployment)
		if err != nil {
			fmt.Printf("Fail to create deployment %s: %s \n", deployment.Name, err.Error())
			return errors.Wrap(err, fmt.Sprintf("failed to create deployment: %s", err.Error()))
		}

		if err := k8sutil.WaitForReadyDeployment(n.Client.ClientGo, deployment.Namespace, deployment.Name); err != nil {
			fmt.Printf("Fail to create deployment %s: %s\n", n.CaseBaseName, err.Error())
			return err
		}
	}

	return nil
}

func (n *NodeAgentConfigTestCase) Backup() error {
	if err := veleroutil.VeleroCmdExec(n.Ctx, n.VeleroCfg.VeleroCLI, n.BackupArgs); err != nil {
		return err
	}

	backupPodList := new(corev1api.PodList)

	wait.PollUntilContextTimeout(n.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		duList := new(velerov2alpha1api.DataUploadList)
		if err := n.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
			n.Ctx,
			duList,
			&client.ListOptions{Namespace: n.VeleroCfg.VeleroNamespace},
		); err != nil {
			fmt.Printf("Fail to list DataUpload: %s\n", err.Error())
			return false, fmt.Errorf("Fail to list DataUpload: %w", err)
		} else {
			if len(duList.Items) <= 0 {
				fmt.Println("No DataUpload found yet. Continue polling.")
				return false, nil
			}
		}

		if err := n.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
			n.Ctx,
			backupPodList,
			&client.ListOptions{
				LabelSelector: labels.SelectorFromSet(map[string]string{
					velerov1api.DataUploadLabel: duList.Items[0].Name,
				}),
			}); err != nil {
			fmt.Printf("Fail to list backupPod %s\n", err.Error())
			return false, errors.Wrapf(err, "error to list backup pods")
		} else {
			if len(backupPodList.Items) <= 0 {
				fmt.Println("No backupPod found yet. Continue polling.")
				return false, nil
			}
		}

		return true, nil
	})

	fmt.Println("Start to verify backupPod content.")

	Expect(backupPodList.Items[0].Spec.PriorityClassName).To(Equal(n.nodeAgentConfigs.PriorityClassName))

	// In backup, only the second element of LoadAffinity array should be used.
	expectedLabelKey, _, ok := popFromMap(n.nodeAgentConfigs.LoadAffinity[1].NodeSelector.MatchLabels)
	Expect(ok).To(BeTrue(), "Expected LoadAffinity's MatchLabels should at least have one key-value pair")

	// From 1.18.1, Velero adds some default affinity in the backup/restore pod,
	// so we can't directly compare the whole affinity,
	// but we can verify if the expected affinity is contained in the pod affinity.
	Expect(backupPodList.Items[0].Spec.Affinity.String()).To(ContainSubstring(expectedLabelKey))

	// Verify PodLabels
	for k, v := range n.nodeAgentConfigs.PodLabels {
		Expect(backupPodList.Items[0].Labels[k]).To(Equal(v))
	}

	// Verify PodAnnotations
	for k, v := range n.nodeAgentConfigs.PodAnnotations {
		Expect(backupPodList.Items[0].Annotations[k]).To(Equal(v))
	}

	fmt.Println("backupPod content verification completed successfully.")

	wait.PollUntilContextTimeout(n.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		backup := new(velerov1api.Backup)
		if err := n.VeleroCfg.ClientToInstallVelero.Kubebuilder.Get(
			n.Ctx,
			client.ObjectKey{Namespace: n.VeleroCfg.VeleroNamespace, Name: n.BackupName},
			backup,
		); err != nil {
			return false, err
		}

		if backup.Status.Phase != velerov1api.BackupPhaseCompleted &&
			backup.Status.Phase != velerov1api.BackupPhaseFailed &&
			backup.Status.Phase != velerov1api.BackupPhasePartiallyFailed {
			fmt.Printf("backup status is %s. Continue polling until backup reach to a final state.\n", backup.Status.Phase)
			return false, nil
		}

		return true, nil
	})

	return nil
}

func (n *NodeAgentConfigTestCase) Restore() error {
	if err := veleroutil.VeleroCmdExec(n.Ctx, n.VeleroCfg.VeleroCLI, n.RestoreArgs); err != nil {
		return err
	}

	restorePodList := new(corev1api.PodList)

	wait.PollUntilContextTimeout(n.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		ddList := new(velerov2alpha1api.DataDownloadList)
		if err := n.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
			n.Ctx,
			ddList,
			&client.ListOptions{Namespace: n.VeleroCfg.VeleroNamespace},
		); err != nil {
			fmt.Printf("Fail to list DataDownload: %s\n", err.Error())
			return false, fmt.Errorf("Fail to list DataDownload %w", err)
		} else {
			if len(ddList.Items) <= 0 {
				fmt.Println("No DataDownload found yet. Continue polling.")
				return false, nil
			}
		}

		if err := n.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
			n.Ctx,
			restorePodList,
			&client.ListOptions{
				LabelSelector: labels.SelectorFromSet(map[string]string{
					velerov1api.DataDownloadLabel: ddList.Items[0].Name,
				}),
			}); err != nil {
			fmt.Printf("Fail to list restorePod %s\n", err.Error())
			return false, errors.Wrapf(err, "error to list restore pods")
		} else {
			if len(restorePodList.Items) <= 0 {
				fmt.Println("No restorePod found yet. Continue polling.")
				return false, nil
			}
		}

		return true, nil
	})

	fmt.Println("Start to verify restorePod content.")

	Expect(restorePodList.Items[0].Spec.PriorityClassName).To(Equal(n.nodeAgentConfigs.PriorityClassName))

	// In restore, only the first element of LoadAffinity array should be used.
	expectedLabelKey, _, ok := popFromMap(n.nodeAgentConfigs.LoadAffinity[0].NodeSelector.MatchLabels)
	Expect(ok).To(BeTrue(), "Expected LoadAffinity's MatchLabels should at least have one key-value pair")

	// From 1.18.1, Velero adds some default affinity in the backup/restore pod,
	// so we can't directly compare the whole affinity,
	// but we can verify if the expected affinity is contained in the pod affinity.
	Expect(restorePodList.Items[0].Spec.Affinity.String()).To(ContainSubstring(expectedLabelKey))

	// Verify PodLabels
	for k, v := range n.nodeAgentConfigs.PodLabels {
		Expect(restorePodList.Items[0].Labels[k]).To(Equal(v))
	}

	// Verify PodAnnotations
	for k, v := range n.nodeAgentConfigs.PodAnnotations {
		Expect(restorePodList.Items[0].Annotations[k]).To(Equal(v))
	}

	fmt.Println("restorePod content verification completed successfully.")

	wait.PollUntilContextTimeout(n.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		restore := new(velerov1api.Restore)
		if err := n.VeleroCfg.ClientToInstallVelero.Kubebuilder.Get(
			n.Ctx,
			client.ObjectKey{Namespace: n.VeleroCfg.VeleroNamespace, Name: n.RestoreName},
			restore,
		); err != nil {
			return false, err
		}

		if restore.Status.Phase != velerov1api.RestorePhaseCompleted &&
			restore.Status.Phase != velerov1api.RestorePhaseFailed &&
			restore.Status.Phase != velerov1api.RestorePhasePartiallyFailed {
			fmt.Printf("restore status is %s. Continue polling until restore reach to a final state.\n", restore.Status.Phase)
			return false, nil
		}

		return true, nil
	})

	return nil
}

func popFromMap[K comparable, V any](m map[K]V) (k K, v V, ok bool) {
	for key, val := range m {
		delete(m, key)
		return key, val, true
	}

	return
}
