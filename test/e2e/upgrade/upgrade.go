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
package upgrade

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/kibishii"
	. "github.com/vmware-tanzu/velero/test/util/providers"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

var upgradeNamespace string
var veleroCfg VeleroConfig

func BackupUpgradeRestoreWithSnapshots() {
	veleroCfg = VeleroCfg
	for _, upgradeFromVelero := range GetVersionList(veleroCfg.UpgradeFromVeleroCLI, veleroCfg.UpgradeFromVeleroVersion) {
		BackupUpgradeRestoreTest(true, upgradeFromVelero)
	}
}

func BackupUpgradeRestoreWithFSBackup() {
	veleroCfg = VeleroCfg
	for _, upgradeFromVelero := range GetVersionList(veleroCfg.UpgradeFromVeleroCLI, veleroCfg.UpgradeFromVeleroVersion) {
		BackupUpgradeRestoreTest(false, upgradeFromVelero)
	}
}

func BackupUpgradeRestoreTest(useVolumeSnapshots bool, veleroCLI2Version VeleroCLI2Version) {
	var (
		backupName, restoreName string
		err                     error
	)

	BeforeEach(func() {
		veleroCfg = VeleroCfg
		veleroCfg.IsUpgradeTest = true
		UUIDgen, err = uuid.NewRandom()
		upgradeNamespace = "upgrade-" + UUIDgen.String()
		if !InstallVelero {
			Skip("Upgrade test should not be triggered if veleroCfg.InstallVelero is set to false")
		}
		if (len(veleroCfg.UpgradeFromVeleroVersion)) == 0 {
			Skip("An original velero version is required to run upgrade test, please run test with upgrade-from-velero-version=<version>")
		}
		if useVolumeSnapshots && veleroCfg.CloudProvider == Kind {
			Skip(fmt.Sprintf("Volume snapshots not supported on %s", Kind))
		}
		if veleroCfg.VeleroCLI == "" {
			Skip("VeleroCLI should be provide")
		}
		// need to uninstall Velero first in case of the affection of the existing global velero installation
		if InstallVelero {
			By("Uninstall Velero", func() {
				ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
				defer ctxCancel()
				Expect(VeleroUninstall(ctx, veleroCfg)).To(Succeed())
			})
		}
	})
	AfterEach(func() {
		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
			By(fmt.Sprintf("Delete sample workload namespace %s", upgradeNamespace), func() {
				DeleteNamespace(context.Background(), *veleroCfg.ClientToInstallVelero, upgradeNamespace, true)
			})
			if InstallVelero {
				By("Uninstall Velero", func() {
					ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
					defer ctxCancel()
					Expect(VeleroUninstall(ctx, veleroCfg)).To(Succeed())
				})
			}
		}
	})
	When("kibishii is the sample workload", func() {
		It("should be successfully backed up and restored to the default BackupStorageLocation", func() {
			flag.Parse()
			UUIDgen, err = uuid.NewRandom()
			Expect(err).To(Succeed())
			oneHourTimeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*60)
			defer ctxCancel()
			if veleroCLI2Version.VeleroCLI == "" {
				//Assume tag of velero server image is identical to velero CLI version
				//Download velero CLI if it's empty according to velero CLI version
				By(fmt.Sprintf("Install the expected old version Velero CLI (%s) for installing Velero",
					veleroCLI2Version.VeleroVersion), func() {
					veleroCLI2Version.VeleroCLI, err = InstallVeleroCLI(
						oneHourTimeout,
						veleroCLI2Version.VeleroVersion,
					)
					Expect(err).To(Succeed())
				})
			}
			veleroCfg.GCFrequency = ""
			By(fmt.Sprintf("Install the expected old version Velero (%s) for upgrade",
				veleroCLI2Version.VeleroVersion), func() {
				tmpCfgForOldVeleroInstall := veleroCfg
				tmpCfgForOldVeleroInstall.UpgradeFromVeleroVersion = veleroCLI2Version.VeleroVersion
				tmpCfgForOldVeleroInstall.VeleroCLI = veleroCLI2Version.VeleroCLI

				tmpCfgForOldVeleroInstall, err = SetImagesToDefaultValues(
					tmpCfgForOldVeleroInstall,
					veleroCLI2Version.VeleroVersion,
				)
				Expect(err).To(Succeed(), "Fail to set the images for upgrade-from Velero installation.")

				tmpCfgForOldVeleroInstall.UploaderType = ""
				version, err := GetVeleroVersion(oneHourTimeout, tmpCfgForOldVeleroInstall.VeleroCLI, true)
				Expect(err).To(Succeed(), "Fail to get Velero version")
				tmpCfgForOldVeleroInstall.VeleroVersion = version
				tmpCfgForOldVeleroInstall.UseVolumeSnapshots = useVolumeSnapshots

				tmpCfgForOldVeleroInstall.UseNodeAgent = !useVolumeSnapshots

				Expect(VeleroInstall(context.Background(), &tmpCfgForOldVeleroInstall, false)).To(Succeed())
				Expect(CheckVeleroVersion(context.Background(), tmpCfgForOldVeleroInstall.VeleroCLI,
					tmpCfgForOldVeleroInstall.UpgradeFromVeleroVersion)).To(Succeed())
			})

			backupName = "backup-" + UUIDgen.String()
			restoreName = "restore-" + UUIDgen.String()
			tmpCfg := veleroCfg
			tmpCfg.UpgradeFromVeleroCLI = veleroCLI2Version.VeleroCLI
			tmpCfg.UpgradeFromVeleroVersion = veleroCLI2Version.VeleroVersion

			By("Create namespace for sample workload", func() {
				Expect(CreateNamespace(oneHourTimeout, *veleroCfg.ClientToInstallVelero, upgradeNamespace)).To(Succeed(),
					fmt.Sprintf("Failed to create namespace %s to install Kibishii workload", upgradeNamespace))
			})

			By("Deploy sample workload of Kibishii", func() {
				Expect(KibishiiPrepareBeforeBackup(
					oneHourTimeout,
					*veleroCfg.ClientToInstallVelero,
					tmpCfg.CloudProvider,
					upgradeNamespace,
					tmpCfg.RegistryCredentialFile,
					tmpCfg.Features,
					tmpCfg.KibishiiDirectory,
					DefaultKibishiiData,
					tmpCfg.ImageRegistryProxy,
					veleroCfg.WorkerOS,
				)).To(Succeed())
			})

			By(fmt.Sprintf("Backup namespace %s", upgradeNamespace), func() {
				var BackupCfg BackupConfig
				BackupCfg.BackupName = backupName
				BackupCfg.Namespace = upgradeNamespace
				BackupCfg.BackupLocation = ""
				BackupCfg.UseVolumeSnapshots = useVolumeSnapshots
				BackupCfg.DefaultVolumesToFsBackup = !useVolumeSnapshots
				BackupCfg.Selector = ""
				Expect(VeleroBackupNamespace(oneHourTimeout, tmpCfg.UpgradeFromVeleroCLI,
					tmpCfg.VeleroNamespace, BackupCfg)).To(Succeed(), func() string {
					RunDebug(context.Background(), tmpCfg.UpgradeFromVeleroCLI, tmpCfg.VeleroNamespace,
						BackupCfg.BackupName, "")
					return "Fail to backup workload"
				})
			})

			if useVolumeSnapshots {
				if veleroCfg.HasVspherePlugin {
					By("Waiting for vSphere uploads to complete", func() {
						Expect(WaitForVSphereUploadCompletion(oneHourTimeout, time.Hour,
							upgradeNamespace, 2)).To(Succeed())
					})
				}
				var snapshotCheckPoint SnapshotCheckPoint
				snapshotCheckPoint.NamespaceBackedUp = upgradeNamespace
				By("Snapshot should be created in cloud object store", func() {
					backupVolumeInfo, err := GetVolumeInfo(
						veleroCfg.ObjectStoreProvider,
						veleroCfg.CloudCredentialsFile,
						veleroCfg.BSLBucket,
						veleroCfg.BSLPrefix,
						veleroCfg.BSLConfig,
						backupName,
						BackupObjectsPrefix+"/"+backupName,
					)
					Expect(err).NotTo(HaveOccurred(), "Failed to get volume info for backup")
					snapshotCheckPoint, err := BuildSnapshotCheckPointFromVolumeInfo(veleroCfg, backupVolumeInfo, 2, upgradeNamespace, backupName, KibishiiPVCNameList)
					Expect(err).NotTo(HaveOccurred(), "Fail to get snapshot checkpoint")
					Expect(CheckSnapshotsInProvider(
						veleroCfg,
						backupName,
						snapshotCheckPoint,
						false,
					)).To(Succeed())
				})
			}

			By(fmt.Sprintf("Simulating a disaster by removing namespace %s\n", upgradeNamespace), func() {
				Expect(DeleteNamespace(oneHourTimeout, *veleroCfg.ClientToInstallVelero, upgradeNamespace, true)).To(Succeed(),
					fmt.Sprintf("failed to delete namespace %s", upgradeNamespace))
			})

			if useVolumeSnapshots && veleroCfg.CloudProvider == Azure && strings.EqualFold(veleroCfg.Features, FeatureCSI) {
				// Upgrade test is not running daily since no CSI plugin v1.0 released, because builds before
				//   v1.0 have issues to fail upgrade case.
				By("Sleep 5 minutes to avoid snapshot recreated by unknown reason ", func() {
					time.Sleep(5 * time.Minute)
				})
			}
			// the snapshots of AWS may be still in pending status when do the restore, wait for a while
			// to avoid this https://github.com/vmware-tanzu/velero/issues/1799
			// TODO remove this after https://github.com/vmware-tanzu/velero/issues/3533 is fixed
			if tmpCfg.CloudProvider == AWS && useVolumeSnapshots {
				fmt.Println("Waiting 5 minutes to make sure the snapshots are ready...")
				time.Sleep(5 * time.Minute)
			}

			By(fmt.Sprintf("Upgrade Velero by CLI %s", tmpCfg.VeleroCLI), func() {
				tmpCfg.GCFrequency = ""
				tmpCfg.UseNodeAgent = !useVolumeSnapshots
				Expect(err).To(Succeed())
				Expect(VeleroInstall(context.Background(), &tmpCfg, false)).To(Succeed())
				Expect(CheckVeleroVersion(context.Background(), tmpCfg.VeleroCLI,
					tmpCfg.VeleroVersion)).To(Succeed())
			})

			// Wait for 70s to make sure the backups are synced after Velero reinstall
			time.Sleep(70 * time.Second)

			By(fmt.Sprintf("Restore %s", upgradeNamespace), func() {
				Expect(VeleroRestore(oneHourTimeout, tmpCfg.VeleroCLI,
					tmpCfg.VeleroNamespace, restoreName, backupName, "")).To(Succeed(), func() string {
					RunDebug(context.Background(), tmpCfg.VeleroCLI,
						tmpCfg.VeleroNamespace, "", restoreName)
					return "Fail to restore workload"
				})
			})

			By(fmt.Sprintf("Verify workload %s after restore ", upgradeNamespace), func() {
				Expect(KibishiiVerifyAfterRestore(
					*veleroCfg.ClientToInstallVelero,
					upgradeNamespace,
					oneHourTimeout,
					DefaultKibishiiData,
					"",
					veleroCfg.WorkerOS,
				)).To(Succeed(), "Fail to verify workload after restore")
			})
		})
	})
}
