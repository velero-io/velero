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
	"context"
	"fmt"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

func APIExtensionsVersionsTest() {
	var (
		backupName, restoreName string
	)

	resourceName := "apiextensions.k8s.io"
	crdName := "rocknrollbands.music.example.io"
	label := "for=backup"
	srcCrdYaml := "testdata/enable_api_group_versions/case-a-source-v1beta1.yaml"
	BeforeEach(func() {
		if veleroCfg.DefaultClusterContext == "" && veleroCfg.StandbyClusterContext == "" {
			Skip("CRD with apiextension versions migration test needs 2 clusters")
		}
		veleroCfg = VeleroCfg
		Expect(KubectlConfigUseContext(context.Background(), veleroCfg.DefaultClusterContext)).To(Succeed())
		srcVersions, err := GetAPIVersions(veleroCfg.DefaultClient, resourceName)
		Expect(err).ToNot(HaveOccurred())
		dstVersions, err := GetAPIVersions(veleroCfg.StandbyClient, resourceName)
		Expect(err).ToNot(HaveOccurred())

		if !slices.Contains(srcVersions, "v1") {
			Skip("CRD with apiextension versions srcVersions should have v1")
		}
		if !slices.Contains(srcVersions, "v1beta1") {
			Skip("CRD with apiextension versions srcVersions should have v1beta1")
		}
		if !slices.Contains(dstVersions, "v1") {
			Skip("CRD with apiextension versions dstVersions should have v1")
		}
		if !(len(srcVersions) > 1 && len(dstVersions) == 1) {
			Skip("Source cluster should support apiextension v1 and v1beta1, destination cluster should only support apiextension v1")
		}
	})
	AfterEach(func() {
		By(fmt.Sprintf("Switch to default kubeconfig context %s", veleroCfg.DefaultClusterContext), func() {
			Expect(KubectlConfigUseContext(context.Background(), veleroCfg.DefaultClusterContext)).To(Succeed())
			veleroCfg.ClientToInstallVelero = veleroCfg.DefaultClient
		})

		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
			if InstallVelero {
				By("Uninstall Velero and delete CRD ", func() {
					ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
					defer ctxCancel()
					Expect(KubectlConfigUseContext(context.Background(), veleroCfg.DefaultClusterContext)).To(Succeed())
					Expect(VeleroUninstall(ctx, veleroCfg)).To(Succeed())
					Expect(DeleteCRDByName(context.Background(), crdName)).To(Succeed())

					Expect(KubectlConfigUseContext(context.Background(), veleroCfg.StandbyClusterContext)).To(Succeed())
					Expect(VeleroUninstall(ctx, veleroCfg)).To(Succeed())
					Expect(DeleteCRDByName(context.Background(), crdName)).To(Succeed())
				})
			}
		}
	})
	Context("When EnableAPIGroupVersions flag is set", func() {
		It("Enable API Group to B/R CRD APIExtensionsVersions", func() {
			backupName = "backup-" + UUIDgen.String()
			restoreName = "restore-" + UUIDgen.String()

			By(fmt.Sprintf("Install Velero in cluster-A (%s) to backup workload", veleroCfg.DefaultClusterContext), func() {
				Expect(KubectlConfigUseContext(context.Background(), veleroCfg.DefaultClusterContext)).To(Succeed())
				veleroCfg.Features = "EnableAPIGroupVersions"
				veleroCfg.UseVolumeSnapshots = false
				Expect(VeleroInstall(context.Background(), &veleroCfg, false)).To(Succeed())
			})

			By(fmt.Sprintf("Install CRD of apiextenstions v1beta1 in cluster-A (%s)", veleroCfg.DefaultClusterContext), func() {
				Expect(InstallCRD(context.Background(), srcCrdYaml)).To(Succeed())
				Expect(CRDShouldExist(context.Background(), crdName)).To(Succeed())
				Expect(WaitForCRDEstablished(crdName)).To(Succeed())
				Expect(AddLabelToCRD(context.Background(), crdName, label)).To(Succeed())
				// Velero server refresh api version data by discovery helper every 5 minutes
				time.Sleep(6 * time.Minute)
			})

			By("Backup CRD", func() {
				var BackupCfg BackupConfig
				BackupCfg.BackupName = backupName
				BackupCfg.IncludeResources = "crd"
				BackupCfg.IncludeClusterResources = true
				BackupCfg.Selector = label
				Expect(VeleroBackupNamespace(context.Background(), veleroCfg.VeleroCLI,
					veleroCfg.VeleroNamespace, BackupCfg)).To(Succeed(), func() string {
					RunDebug(context.Background(), veleroCfg.VeleroCLI,
						veleroCfg.VeleroNamespace, backupName, "")
					return "Fail to backup workload"
				})
			})

			By(fmt.Sprintf("Install Velero in cluster-B (%s) to restore workload", veleroCfg.StandbyClusterContext), func() {
				Expect(KubectlConfigUseContext(context.Background(), veleroCfg.StandbyClusterContext)).To(Succeed())
				veleroCfg.ClientToInstallVelero = veleroCfg.StandbyClient
				Expect(VeleroInstall(context.Background(), &veleroCfg, false)).To(Succeed())
			})

			By(fmt.Sprintf("Waiting for backups sync to Velero in cluster-B (%s)", veleroCfg.StandbyClusterContext), func() {
				Expect(WaitForBackupToBeCreated(context.Background(), backupName, 5*time.Minute, &veleroCfg)).To(Succeed())
			})

			By(fmt.Sprintf("CRD %s should not exist in cluster-B (%s)", crdName, veleroCfg.StandbyClusterContext), func() {
				Expect(CRDShouldNotExist(context.Background(), crdName)).To(Succeed(), "Error: CRD already exists in cluster B, clean it and re-run test")
			})

			By("Restore CRD", func() {
				Expect(VeleroRestore(context.Background(), veleroCfg.VeleroCLI,
					veleroCfg.VeleroNamespace, restoreName, backupName, "")).To(Succeed(), func() string {
					RunDebug(context.Background(), veleroCfg.VeleroCLI,
						veleroCfg.VeleroNamespace, "", restoreName)
					return "Fail to restore workload"
				})
			})

			By("Verify CRD restore ", func() {
				Expect(CRDShouldExist(context.Background(), crdName)).To(Succeed())
			})
		})
	})
}
