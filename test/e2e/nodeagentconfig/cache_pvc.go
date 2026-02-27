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
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	k8sutil "github.com/vmware-tanzu/velero/test/util/k8s"
	veleroutil "github.com/vmware-tanzu/velero/test/util/velero"
)

type CachePVCTestCase struct {
	TestCase
	nodeAgentConfigMapName string
	repoConfigMapName      string
}

var CachePVCTest func() = TestFunc(&CachePVCTestCase{
	nodeAgentConfigMapName: "node-agent-config-cache",
	repoConfigMapName:      "backup-repo-config-cache",
})

func (c *CachePVCTestCase) Init() error {
	c.TestCase.Init()
	c.CaseBaseName = "cache-pvc-" + c.UUIDgen
	c.BackupName = "backup-" + c.CaseBaseName
	c.RestoreName = "restore-" + c.CaseBaseName
	c.NamespacesTotal = 1
	c.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < c.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", c.CaseBaseName, nsNum)
		*c.NSIncluded = append(*c.NSIncluded, createNSName)
	}

	c.VeleroCfg.UseNodeAgent = true
	c.VeleroCfg.UseNodeAgentWindows = true

	// Ensure Data Mover is used to trigger DataUpload/DataDownload pods
	c.BackupArgs = []string{
		"create", "--namespace", c.VeleroCfg.VeleroNamespace, "backup", c.BackupName,
		"--include-namespaces", strings.Join(*c.NSIncluded, ","),
		"--snapshot-volumes=true", "--snapshot-move-data",
	}

	c.RestoreArgs = []string{
		"create", "--namespace", c.VeleroCfg.VeleroNamespace, "restore", c.RestoreName,
		"--from-backup", c.BackupName,
	}

	c.TestMsg = &TestMSG{
		Desc:      "Validate dynamically provisioned Cache PVC for data mover pods",
		FailedMSG: "Failed to apply and validate cache PVC configuration in data mover pods.",
		Text:      "Should dynamically provision a Cache PVC for data mover restore pods to avoid node root FS exhaustion.",
	}
	return nil
}

func (c *CachePVCTestCase) InstallVelero() error {
	fmt.Println("Start to uninstall Velero")
	if err := veleroutil.VeleroUninstall(c.Ctx, c.VeleroCfg); err != nil {
		fmt.Printf("Fail to uninstall Velero: %s\n", err.Error())
		return err
	}

	// 1. Construct node-agent ConfigMap (Define Cache PVC StorageClass and trigger threshold)
	// Set residentThresholdInMB to 0 to force Velero to create a PVC even for tiny E2E test data.
	nodeAgentConfigJSON := fmt.Sprintf(`{"cachePVC": {"residentThresholdInMB": 0, "storageClass": "%s"}}`, test.StorageClassName)
	nodeAgentConfig := builder.ForConfigMap(c.VeleroCfg.VeleroNamespace, c.nodeAgentConfigMapName).
		Data("node-agent-config", nodeAgentConfigJSON).Result()

	// 2. Construct backup repository ConfigMap (Define cacheLimitMB)
	repoConfigJSON := `{"cacheLimitMB": 2048}` // Set 2GB cache limit
	repoConfig := builder.ForConfigMap(c.VeleroCfg.VeleroNamespace, c.repoConfigMapName).
		Data(test.UploaderTypeKopia, repoConfigJSON).Result()

	c.VeleroCfg.NodeAgentConfigMap = c.nodeAgentConfigMapName
	c.VeleroCfg.BackupRepoConfigMap = c.repoConfigMapName

	// Deploy Velero with the two Cache configuration ConfigMaps
	return veleroutil.PrepareVelero(c.Ctx, c.CaseBaseName, c.VeleroCfg, nodeAgentConfig, repoConfig)
}

func (c *CachePVCTestCase) CreateResources() error {
	for _, ns := range *c.NSIncluded {
		if err := k8sutil.CreateNamespace(c.Ctx, c.Client, ns); err != nil {
			return err
		}

		pvc, err := k8sutil.CreatePVC(c.Client, ns, "volume-1", test.StorageClassName, nil)
		if err != nil {
			return err
		}

		vols := k8sutil.CreateVolumes(pvc.Name, []string{"volume-1"})

		deployment := k8sutil.NewDeployment(
			c.CaseBaseName,
			ns,
			1,
			map[string]string{"app": "test"},
			c.VeleroCfg.ImageRegistryProxy,
			c.VeleroCfg.WorkerOS,
		).WithVolume(vols).Result()

		deployment, err = k8sutil.CreateDeployment(c.Client.ClientGo, ns, deployment)
		if err != nil {
			return errors.Wrap(err, "failed to create deployment")
		}

		if err := k8sutil.WaitForReadyDeployment(c.Client.ClientGo, deployment.Namespace, deployment.Name); err != nil {
			return err
		}
	}
	return nil
}

// verifyCacheVolumeInPod correctly verifies that the Pod mounted a dynamic PVC instead of an emptyDir
func (c *CachePVCTestCase) verifyCacheVolumeInPod(pod corev1api.Pod) error {
	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil {
			// Velero dynamically provisioned cache volumes typically have 'cache' in the name
			if strings.Contains(vol.PersistentVolumeClaim.ClaimName, "cache") || strings.Contains(vol.Name, "cache") {
				return nil // Success: Found the dynamically provisioned Cache PVC
			}
		}
	}
	return fmt.Errorf("Dynamically provisioned Cache PVC not found in pod %s, feature failed!", pod.Name)
}

func (c *CachePVCTestCase) Backup() error {
	if err := veleroutil.VeleroCmdExec(c.Ctx, c.VeleroCfg.VeleroCLI, c.BackupArgs); err != nil {
		return err
	}

	fmt.Println("Waiting for backup to complete...")

	// Wait for backup completion
	wait.PollUntilContextTimeout(c.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		backup := new(velerov1api.Backup)
		if err := c.VeleroCfg.ClientToInstallVelero.Kubebuilder.Get(
			c.Ctx,
			client.ObjectKey{Namespace: c.VeleroCfg.VeleroNamespace, Name: c.BackupName},
			backup,
		); err != nil {
			return false, err
		}

		if backup.Status.Phase != velerov1api.BackupPhaseCompleted &&
			backup.Status.Phase != velerov1api.BackupPhaseFailed &&
			backup.Status.Phase != velerov1api.BackupPhasePartiallyFailed {
			return false, nil
		}

		return true, nil
	})

	return nil
}

func (c *CachePVCTestCase) Restore() error {
	if err := veleroutil.VeleroCmdExec(c.Ctx, c.VeleroCfg.VeleroCLI, c.RestoreArgs); err != nil {
		return err
	}

	restorePodList := new(corev1api.PodList)

	wait.PollUntilContextTimeout(c.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		ddList := new(velerov2alpha1api.DataDownloadList)
		if err := c.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
			c.Ctx,
			ddList,
			&client.ListOptions{Namespace: c.VeleroCfg.VeleroNamespace},
		); err != nil {
			return false, err
		} else if len(ddList.Items) <= 0 {
			return false, nil
		}

		if err := c.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
			c.Ctx,
			restorePodList,
			&client.ListOptions{
				LabelSelector: labels.SelectorFromSet(map[string]string{
					velerov1api.DataDownloadLabel: ddList.Items[0].Name,
				}),
			}); err != nil {
			return false, err
		} else if len(restorePodList.Items) <= 0 {
			return false, nil
		}

		return true, nil
	})

	fmt.Println("Start to verify restore data mover pod content.")
	Expect(restorePodList.Items).ToNot(BeEmpty())

	// Ensure the Data Mover pod is using a true PVC for caching
	err := c.verifyCacheVolumeInPod(restorePodList.Items[0])
	Expect(err).To(Succeed(), "Injected Cache PVC should exist in DataDownload Pod")
	fmt.Println("Restore data mover pod content verification completed successfully.")

	// Wait for restore completion
	wait.PollUntilContextTimeout(c.Ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		restore := new(velerov1api.Restore)
		if err := c.VeleroCfg.ClientToInstallVelero.Kubebuilder.Get(
			c.Ctx,
			client.ObjectKey{Namespace: c.VeleroCfg.VeleroNamespace, Name: c.RestoreName},
			restore,
		); err != nil {
			return false, err
		}

		if restore.Status.Phase != velerov1api.RestorePhaseCompleted &&
			restore.Status.Phase != velerov1api.RestorePhaseFailed &&
			restore.Status.Phase != velerov1api.RestorePhasePartiallyFailed {
			return false, nil
		}

		return true, nil
	})

	return nil
}
