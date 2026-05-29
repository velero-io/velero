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
package bslmgmt

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/kibishii"
	. "github.com/vmware-tanzu/velero/test/util/providers"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

const (
	// Please make sure length of this namespace should be shorter,
	// otherwise BackupRepositories name verification will be wrong
	// when making combination of BackupRepositories name(max length is 63)
	bslDeletionTestNs = "bsl-deletion"
)

func BslDeletionWithSnapshots() {
	BslDeletionTest(true)
}

func BslDeletionWithFSBackup() {
	BslDeletionTest(false)
}
func BslDeletionTest(useVolumeSnapshots bool) {
	var (
		veleroCfg VeleroConfig
	)
	veleroCfg = VeleroCfg
	veleroCfg.UseVolumeSnapshots = useVolumeSnapshots
	veleroCfg.UseNodeAgent = !useVolumeSnapshots
	less := func(a, b string) bool { return a < b }

	BeforeEach(func() {
		if useVolumeSnapshots && veleroCfg.CloudProvider == Kind {
			Skip(fmt.Sprintf("Volume snapshots not supported on %s", Kind))
		}
		var err error
		flag.Parse()
		UUIDgen, err = uuid.NewRandom()
		Expect(err).To(Succeed())
		if InstallVelero {
			Expect(PrepareVelero(context.Background(), "BSL Deletion", veleroCfg)).To(Succeed())
		}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("Clean backups after test", func() {
				veleroCfg.ClientToInstallVelero = veleroCfg.DefaultClient
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
			By(fmt.Sprintf("Delete sample workload namespace %s", bslDeletionTestNs), func() {
				Expect(DeleteNamespace(context.Background(), *veleroCfg.ClientToInstallVelero, bslDeletionTestNs,
					true)).To(Succeed(), fmt.Sprintf("failed to delete the namespace %q",
					bslDeletionTestNs))
			})
		}
	})

	When("kibishii is the sample workload", func() {
		It("Local backups and backup repos will be deleted once the corresponding backup storage location is deleted", func() {
			oneHourTimeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*60)
			defer ctxCancel()
			if veleroCfg.AdditionalBSLProvider == "" {
				Skip("no additional BSL provider given, not running multiple BackupStorageLocation with unique credentials tests")
			}

			if veleroCfg.AdditionalBSLBucket == "" {
				Skip("no additional BSL bucket given, not running multiple BackupStorageLocation with unique credentials tests")
			}

			if veleroCfg.AdditionalBSLCredentials == "" {
				Skip("no additional BSL credentials given, not running multiple BackupStorageLocation with unique credentials tests")
			}

			By(fmt.Sprintf("Add an additional plugin for provider %s", veleroCfg.AdditionalBSLProvider), func() {
				plugins, err := GetPlugins(context.TODO(), veleroCfg, false)
				Expect(err).To(Succeed())
				Expect(AddPlugins(plugins, veleroCfg)).To(Succeed())
			})

			additionalBsl := fmt.Sprintf("bsl-%s", UUIDgen)
			secretName := fmt.Sprintf("bsl-credentials-%s", UUIDgen)
			secretKey := fmt.Sprintf("creds-%s", veleroCfg.AdditionalBSLProvider)
			files := map[string]string{
				secretKey: veleroCfg.AdditionalBSLCredentials,
			}

			By(fmt.Sprintf("Create Secret for additional BSL %s", additionalBsl), func() {
				Expect(CreateSecretFromFiles(context.TODO(), *veleroCfg.ClientToInstallVelero, veleroCfg.VeleroNamespace, secretName, files)).To(Succeed())
			})

			By(fmt.Sprintf("Create additional BSL using credential %s", secretName), func() {
				Expect(VeleroCreateBackupLocation(context.TODO(),
					veleroCfg.VeleroCLI,
					veleroCfg.VeleroNamespace,
					additionalBsl,
					veleroCfg.AdditionalBSLProvider,
					veleroCfg.AdditionalBSLBucket,
					veleroCfg.AdditionalBSLPrefix,
					veleroCfg.AdditionalBSLConfig,
					secretName,
					secretKey,
				)).To(Succeed())
			})

			backupName1 := "backup1-" + UUIDgen.String()
			backupName2 := "backup2-" + UUIDgen.String()
			backupLocation1 := "default"
			backupLocation2 := additionalBsl
			podName1 := "kibishii-deployment-0"
			podName2 := "kibishii-deployment-1"

			label1 := "for=1"
			// TODO remove when issue https://github.com/vmware-tanzu/velero/issues/4724 is fixed
			//label2 := "for!=1"
			label2 := "for=2"
			By("Create namespace for sample workload", func() {
				Expect(CreateNamespace(oneHourTimeout, *veleroCfg.ClientToInstallVelero, bslDeletionTestNs)).To(Succeed())
			})

			By("Deploy sample workload of Kibishii", func() {
				Expect(KibishiiPrepareBeforeBackup(
					oneHourTimeout,
					*veleroCfg.ClientToInstallVelero,
					veleroCfg.CloudProvider,
					bslDeletionTestNs,
					veleroCfg.RegistryCredentialFile,
					veleroCfg.Features,
					veleroCfg.KibishiiDirectory,
					DefaultKibishiiData,
					veleroCfg.ImageRegistryProxy,
					veleroCfg.WorkerOS,
				)).To(Succeed())
			})

			// FS backup can not backup PV only, so pod need to be labeled also
			By("Label all 2 worker-pods of Kibishii", func() {
				Expect(AddLabelToPod(context.Background(), podName1, bslDeletionTestNs, label1)).To(Succeed())
				Expect(AddLabelToPod(context.Background(), "kibishii-deployment-1", bslDeletionTestNs, label2)).To(Succeed())
			})

			By("Get all 2 PVCs of Kibishii and label them separately ", func() {
				pvc, err := GetPvcByPVCName(context.Background(), bslDeletionTestNs, podName1)
				Expect(err).To(Succeed())
				fmt.Println(pvc)
				Expect(pvc).To(HaveLen(1))
				pvc1 := pvc[0]
				pvc, err = GetPvcByPVCName(context.Background(), bslDeletionTestNs, podName2)
				Expect(err).To(Succeed())
				fmt.Println(pvc)
				Expect(pvc).To(HaveLen(1))
				pvc2 := pvc[0]
				Expect(AddLabelToPvc(context.Background(), pvc1, bslDeletionTestNs, label1)).To(Succeed())
				Expect(AddLabelToPvc(context.Background(), pvc2, bslDeletionTestNs, label2)).To(Succeed())
			})

			var BackupCfg BackupConfig
			BackupCfg.BackupName = backupName1
			BackupCfg.Namespace = bslDeletionTestNs
			BackupCfg.BackupLocation = backupLocation1
			BackupCfg.UseVolumeSnapshots = useVolumeSnapshots
			BackupCfg.DefaultVolumesToFsBackup = !useVolumeSnapshots
			BackupCfg.Selector = label1
			By(fmt.Sprintf("Backup one of PV of sample workload by label-1 - Kibishii by the first BSL %s", backupLocation1), func() {
				// TODO currently, the upgrade case covers the upgrade path from 1.6 to main and the velero v1.6 doesn't support "debug" command
				// TODO move to "runDebug" after we bump up to 1.7 in the upgrade case
				Expect(VeleroBackupNamespace(oneHourTimeout, veleroCfg.VeleroCLI,
					veleroCfg.VeleroNamespace, BackupCfg)).To(Succeed(), func() string {
					RunDebug(context.Background(), veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, BackupCfg.BackupName, "")
					return "Fail to backup workload"
				})
			})

			BackupCfg.BackupName = backupName2
			BackupCfg.BackupLocation = backupLocation2
			BackupCfg.Selector = label2
			By(fmt.Sprintf("Back up the other one PV of sample workload with label-2 into the additional BSL %s", backupLocation2), func() {
				Expect(VeleroBackupNamespace(oneHourTimeout, veleroCfg.VeleroCLI,
					veleroCfg.VeleroNamespace, BackupCfg)).To(Succeed(), func() string {
					RunDebug(context.Background(), veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, BackupCfg.BackupName, "")
					return "Fail to backup workload"
				})
			})

			if useVolumeSnapshots {
				if veleroCfg.HasVspherePlugin {
					By("Waiting for vSphere uploads to complete", func() {
						Expect(WaitForVSphereUploadCompletion(oneHourTimeout, time.Hour,
							bslDeletionTestNs, 2)).To(Succeed())
					})
					By(fmt.Sprintf("Snapshot CR in backup %s should be created", backupName1), func() {
						Expect(SnapshotCRsCountShouldBe(context.Background(), bslDeletionTestNs,
							backupName1, 1)).To(Succeed())
					})
					By(fmt.Sprintf("Snapshot CR in backup %s should be created", backupName2), func() {
						Expect(SnapshotCRsCountShouldBe(context.Background(), bslDeletionTestNs,
							backupName2, 1)).To(Succeed())
					})
				}

				backupVolumeInfo, err := GetVolumeInfo(
					veleroCfg.ObjectStoreProvider,
					veleroCfg.CloudCredentialsFile,
					veleroCfg.BSLBucket,
					veleroCfg.BSLPrefix,
					veleroCfg.BSLConfig,
					backupName1,
					BackupObjectsPrefix+"/"+backupName1,
				)
				Expect(err).NotTo(HaveOccurred(), "Failed to get volume info for backup")

				if veleroCfg.CloudProvider != VanillaZFS {
					var snapshotCheckPoint SnapshotCheckPoint
					snapshotCheckPoint.NamespaceBackedUp = bslDeletionTestNs
					By(fmt.Sprintf("Snapshot of bsl %s should be created in cloud object store", backupLocation1), func() {
						snapshotCheckPoint, err = BuildSnapshotCheckPointFromVolumeInfo(
							veleroCfg,
							backupVolumeInfo,
							1,
							bslDeletionTestNs,
							backupName1,
							[]string{podName1},
						)
						Expect(err).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")
						Expect(CheckSnapshotsInProvider(
							veleroCfg,
							backupName1,
							snapshotCheckPoint,
							false,
						)).To(Succeed())
					})
					By(fmt.Sprintf("Snapshot of bsl %s should be created in cloud object store", backupLocation2), func() {
						snapshotCheckPoint, err = BuildSnapshotCheckPointFromVolumeInfo(
							veleroCfg,
							backupVolumeInfo,
							1,
							bslDeletionTestNs,
							backupName2,
							[]string{podName2},
						)
						Expect(err).NotTo(HaveOccurred(), "Fail to get snapshot checkpoint")

						Expect(CheckSnapshotsInProvider(
							veleroCfg,
							backupName2,
							snapshotCheckPoint,
							true,
						)).To(Succeed())
					})
				}
			} else {
				By(fmt.Sprintf("BackupRepositories for BSL %s should be created in Velero namespace", backupLocation1), func() {
					Expect(BackupRepositoriesCountShouldBe(context.Background(),
						veleroCfg.VeleroNamespace, bslDeletionTestNs+"-"+backupLocation1, 1)).To(Succeed())
				})
				By(fmt.Sprintf("BackupRepositories for BSL %s should be created in Velero namespace", backupLocation2), func() {
					Expect(BackupRepositoriesCountShouldBe(context.Background(),
						veleroCfg.VeleroNamespace, bslDeletionTestNs+"-"+backupLocation2, 1)).To(Succeed())
				})
			}

			By(fmt.Sprintf("Backup 1 %s should be created.", backupName1), func() {
				Expect(WaitForBackupToBeCreated(context.Background(),
					backupName1, 10*time.Minute, &veleroCfg)).To(Succeed())
			})

			By(fmt.Sprintf("Backup 2 %s should be created.", backupName2), func() {
				Expect(WaitForBackupToBeCreated(context.Background(),
					backupName2, 10*time.Minute, &veleroCfg)).To(Succeed())
			})

			backupsInBSL1, err := GetBackupsFromBsl(context.Background(), veleroCfg.VeleroCLI, backupLocation1)
			Expect(err).To(Succeed())
			backupsInBSL2, err := GetBackupsFromBsl(context.Background(), veleroCfg.VeleroCLI, backupLocation2)
			Expect(err).To(Succeed())
			backupsInBsl1AndBsl2 := append(backupsInBSL1, backupsInBSL2...)

			By(fmt.Sprintf("Get all backups from 2 BSLs %s before deleting one of them", backupLocation1), func() {
				backupsBeforeDel, err := GetAllBackups(context.Background(), veleroCfg.VeleroCLI)
				Expect(err).To(Succeed())
				Expect(cmp.Diff(backupsInBsl1AndBsl2, backupsBeforeDel, cmpopts.SortSlices(less))).Should(BeEmpty())

				By(fmt.Sprintf("Backup1 %s should exist in cloud object store before bsl deletion", backupName1), func() {
					Expect(ObjectsShouldBeInBucket(veleroCfg.ObjectStoreProvider, veleroCfg.CloudCredentialsFile,
						veleroCfg.BSLBucket, veleroCfg.BSLPrefix, veleroCfg.BSLConfig,
						backupName1, BackupObjectsPrefix)).To(Succeed())
				})

				By(fmt.Sprintf("Delete one of backup locations - %s", backupLocation1), func() {
					Expect(DeleteBslResource(context.Background(), veleroCfg.VeleroCLI, backupLocation1)).To(Succeed())
					Expect(WaitForBackupsToBeDeleted(context.Background(), backupsInBSL1, 10*time.Minute, &veleroCfg)).To(Succeed())
				})

				By("Get all backups from 2 BSLs after deleting one of them", func() {
					backupsAfterDel, err := GetAllBackups(context.Background(), veleroCfg.VeleroCLI)
					Expect(err).To(Succeed())
					// Default BSL is deleted, so backups in additional BSL should be left only
					Expect(cmp.Diff(backupsInBSL2, backupsAfterDel, cmpopts.SortSlices(less))).Should(BeEmpty())
				})
			})

			By(fmt.Sprintf("Backup1 %s should still exist in cloud object store after bsl deletion", backupName1), func() {
				Expect(ObjectsShouldBeInBucket(veleroCfg.ObjectStoreProvider, veleroCfg.CloudCredentialsFile,
					veleroCfg.BSLBucket, veleroCfg.BSLPrefix, veleroCfg.BSLConfig,
					backupName1, BackupObjectsPrefix)).To(Succeed())
			})

			// TODO: Choose additional BSL to be deleted as an new test case
			// By(fmt.Sprintf("Backup %s should still exist in cloud object store", backupName_2), func() {
			// 	Expect(ObjectsShouldBeInBucket(veleroCfg.ObjectStoreProvider, veleroCfg.AdditionalBSLCredentials,
			// 		veleroCfg.AdditionalBSLBucket, veleroCfg.AdditionalBSLPrefix, veleroCfg.AdditionalBSLConfig,
			// 		backupName_2, BackupObjectsPrefix)).To(Succeed())
			// })

			if useVolumeSnapshots {
				if veleroCfg.HasVspherePlugin {
					By(fmt.Sprintf("Snapshot in backup %s should still exist, because snapshot CR will be deleted 24 hours later if the status is a success", backupName2), func() {
						Expect(SnapshotCRsCountShouldBe(context.Background(), bslDeletionTestNs,
							backupName1, 1)).To(Succeed())
						Expect(SnapshotCRsCountShouldBe(context.Background(), bslDeletionTestNs,
							backupName2, 1)).To(Succeed())
					})
				}

				backupVolumeInfo, err := GetVolumeInfo(
					veleroCfg.ObjectStoreProvider,
					veleroCfg.CloudCredentialsFile,
					veleroCfg.BSLBucket,
					veleroCfg.BSLPrefix,
					veleroCfg.BSLConfig,
					backupName1,
					BackupObjectsPrefix+"/"+backupName1,
				)
				Expect(err).NotTo(HaveOccurred(), "Failed to get volume info for backup")

				var snapshotCheckPoint SnapshotCheckPoint
				snapshotCheckPoint.NamespaceBackedUp = bslDeletionTestNs
				By(fmt.Sprintf("Snapshot should not be deleted in cloud object store after deleting bsl %s", backupLocation1), func() {
					snapshotCheckPoint, err = BuildSnapshotCheckPointFromVolumeInfo(veleroCfg, backupVolumeInfo, 1, bslDeletionTestNs, backupName1, []string{podName1})
					Expect(err).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")
					Expect(CheckSnapshotsInProvider(
						veleroCfg,
						backupName1,
						snapshotCheckPoint,
						false,
					)).To(Succeed())
				})
				By(fmt.Sprintf("Snapshot should not be deleted in cloud object store after deleting bsl %s", backupLocation2), func() {
					snapshotCheckPoint, err = BuildSnapshotCheckPointFromVolumeInfo(
						veleroCfg,
						backupVolumeInfo,
						1,
						bslDeletionTestNs,
						backupName2,
						[]string{podName2},
					)
					Expect(err).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")

					Expect(CheckSnapshotsInProvider(
						veleroCfg,
						backupName2,
						snapshotCheckPoint,
						true,
					)).To(Succeed())
				})
			} else {
				By(fmt.Sprintf("BackupRepositories for BSL %s should be deleted in Velero namespace", backupLocation1), func() {
					Expect(BackupRepositoriesCountShouldBe(context.Background(),
						veleroCfg.VeleroNamespace, bslDeletionTestNs+"-"+backupLocation1, 0)).To(Succeed())
				})
				By(fmt.Sprintf("BackupRepositories for BSL %s should still exist in Velero namespace", backupLocation2), func() {
					Expect(BackupRepositoriesCountShouldBe(context.Background(),
						veleroCfg.VeleroNamespace, bslDeletionTestNs+"-"+backupLocation2, 1)).To(Succeed())
				})
			}
			fmt.Printf("|| EXPECTED || - Backup deletion test completed successfully\n")
		})
	})
}
