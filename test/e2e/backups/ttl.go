/*
 *
 * Copyright the Velero contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package backups

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/velero-io/velero/test"
	. "github.com/velero-io/velero/test/util/k8s"
	. "github.com/velero-io/velero/test/util/kibishii"
	. "github.com/velero-io/velero/test/util/providers"
	. "github.com/velero-io/velero/test/util/velero"
)

type TTL struct {
	testNS      string
	backupName  string
	restoreName string
	ttl         time.Duration
}

func (b *TTL) Init() {
	rand.Seed(time.Now().UnixNano())
	UUIDgen, _ = uuid.NewRandom()
	b.testNS = "backup-ttl-test-" + UUIDgen.String()
	b.backupName = "backup-ttl-test-" + UUIDgen.String()
	b.restoreName = "restore-ttl-test-" + UUIDgen.String()
	b.ttl = 10 * time.Minute
}

func TTLTest() {
	var veleroCfg VeleroConfig
	useVolumeSnapshots := true
	test := new(TTL)
	veleroCfg = VeleroCfg
	client := *veleroCfg.ClientToInstallVelero

	BeforeEach(func() {
		flag.Parse()
		veleroCfg = VeleroCfg
		if InstallVelero {
			// Make sure GCFrequency is shorter than backup TTL
			veleroCfg.GCFrequency = "4m0s"
			veleroCfg.UseVolumeSnapshots = useVolumeSnapshots
			Expect(VeleroInstall(context.Background(), &veleroCfg, false)).To(Succeed())
		}
	})

	AfterEach(func() {
		veleroCfg.GCFrequency = ""

		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
			ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
			defer ctxCancel()
			if InstallVelero {
				Expect(VeleroUninstall(ctx, veleroCfg)).To(Succeed())
			}
			Expect(DeleteNamespace(ctx, client, test.testNS, false)).To(Succeed(), fmt.Sprintf("Failed to delete the namespace %s", test.testNS))
		}
	})

	It("Backups in object storage should be synced to a new Velero successfully", func() {
		test.Init()
		ctx, ctxCancel := context.WithTimeout(context.Background(), 1*time.Hour)
		defer ctxCancel()
		By(fmt.Sprintf("Prepare workload as target to backup by creating namespace %s namespace", test.testNS), func() {
			Expect(CreateNamespace(ctx, client, test.testNS)).To(Succeed(),
				fmt.Sprintf("Failed to create %s namespace", test.testNS))
		})

		By("Deploy sample workload of Kibishii", func() {
			Expect(KibishiiPrepareBeforeBackup(
				ctx,
				client,
				veleroCfg.CloudProvider,
				test.testNS,
				veleroCfg.RegistryCredentialFile,
				veleroCfg.Features,
				veleroCfg.KibishiiDirectory,
				DefaultKibishiiData,
				veleroCfg.ImageRegistryProxy,
				veleroCfg.WorkerOS,
			)).To(Succeed())
		})

		var BackupCfg BackupConfig
		BackupCfg.BackupName = test.backupName
		BackupCfg.Namespace = test.testNS
		BackupCfg.BackupLocation = ""
		BackupCfg.UseVolumeSnapshots = useVolumeSnapshots
		BackupCfg.Selector = ""
		BackupCfg.TTL = test.ttl

		By(fmt.Sprintf("Backup the workload in %s namespace", test.testNS), func() {
			Expect(VeleroBackupNamespace(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, BackupCfg)).To(Succeed(), func() string {
				RunDebug(context.Background(), veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, test.backupName, "")
				return "Fail to backup workload"
			})
		})

		var snapshotCheckPoint SnapshotCheckPoint
		if useVolumeSnapshots {
			if veleroCfg.HasVspherePlugin {
				By("Waiting for vSphere uploads to complete", func() {
					Expect(WaitForVSphereUploadCompletion(ctx, time.Hour,
						test.testNS, 2)).To(Succeed())
				})
			}

			backupVolumeInfo, err := GetVolumeInfo(
				veleroCfg.ObjectStoreProvider,
				veleroCfg.CloudCredentialsFile,
				veleroCfg.BSLBucket,
				veleroCfg.BSLPrefix,
				veleroCfg.BSLConfig,
				test.backupName,
				BackupObjectsPrefix+"/"+test.backupName,
			)
			Expect(err).NotTo(HaveOccurred(), "Failed to get volume info for backup")

			snapshotCheckPoint, err = BuildSnapshotCheckPointFromVolumeInfo(
				veleroCfg,
				backupVolumeInfo,
				DefaultKibishiiWorkerCounts,
				test.testNS,
				test.backupName,
				KibishiiPVCNameList,
			)
			Expect(err).NotTo(HaveOccurred(), "Fail to get snapshot checkpoint")

			Expect(
				CheckSnapshotsInProvider(
					veleroCfg,
					test.backupName,
					snapshotCheckPoint,
					false,
				),
			).NotTo(HaveOccurred(), "Fail to verify the created snapshots")
		}

		By(fmt.Sprintf("Simulating a disaster by removing namespace %s\n", BackupCfg.BackupName), func() {
			Expect(DeleteNamespace(ctx, client, BackupCfg.BackupName, true)).To(Succeed(),
				fmt.Sprintf("Failed to delete namespace %s", BackupCfg.BackupName))
		})

		if veleroCfg.CloudProvider == AWS && useVolumeSnapshots {
			fmt.Println("Waiting 7 minutes to make sure the snapshots are ready...")
			time.Sleep(7 * time.Minute)
		}

		By(fmt.Sprintf("Restore %s", test.testNS), func() {
			Expect(VeleroRestore(ctx, veleroCfg.VeleroCLI,
				veleroCfg.VeleroNamespace, test.restoreName, test.backupName, "")).To(Succeed(), func() string {
				RunDebug(ctx, veleroCfg.VeleroCLI,
					veleroCfg.VeleroNamespace, "", test.restoreName)
				return "Fail to restore workload"
			})
		})

		By("Associated Restores should be created", func() {
			Expect(ObjectsShouldBeInBucket(veleroCfg.ObjectStoreProvider,
				veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket,
				veleroCfg.BSLPrefix, veleroCfg.BSLConfig, test.restoreName,
				RestoreObjectsPrefix)).NotTo(HaveOccurred(), "Fail to get restore object")
		})

		By("Check TTL was set correctly", func() {
			ttl, err := GetBackupTTL(ctx, veleroCfg.VeleroNamespace, test.backupName)
			Expect(err).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")
			t, _ := time.ParseDuration(strings.ReplaceAll(ttl, "'", ""))
			fmt.Println(t.Round(time.Minute).String())
			Expect(t).To(Equal(test.ttl))
		})

		By(fmt.Sprintf("Waiting %s minutes for removing backup related resources by GC", test.ttl.String()), func() {
			time.Sleep(test.ttl)
		})

		By("Check if backups are deleted by GC", func() {
			Expect(WaitBackupDeleted(ctx, test.backupName, time.Minute*10, &veleroCfg)).To(Succeed(), fmt.Sprintf("Backup %s was not deleted by GC", test.backupName))
		})

		By("Backup file from cloud object storage should be deleted", func() {
			Expect(ObjectsShouldNotBeInBucket(veleroCfg.ObjectStoreProvider,
				veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket,
				veleroCfg.BSLPrefix, veleroCfg.BSLConfig, test.backupName,
				BackupObjectsPrefix, 5)).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")
		})

		By("PersistentVolume snapshots should be deleted", func() {
			if useVolumeSnapshots {
				snapshotCheckPoint.ExpectCount = 0
				Expect(CheckSnapshotsInProvider(
					veleroCfg,
					test.backupName,
					snapshotCheckPoint,
					false,
				)).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")
			}
		})

		By("Associated Restores should be deleted", func() {
			Expect(ObjectsShouldNotBeInBucket(veleroCfg.ObjectStoreProvider,
				veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket,
				veleroCfg.BSLPrefix, veleroCfg.BSLConfig, test.restoreName,
				RestoreObjectsPrefix, 5)).NotTo(HaveOccurred(), "Fail to get restore object")
		})
	})
}
