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
package backups

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/kibishii"
	. "github.com/vmware-tanzu/velero/test/util/providers"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

func BackupDeletionWithSnapshots() {
	backup_deletion_test(true)
}

func BackupDeletionWithFSBackup() {
	backup_deletion_test(false)
}
func backup_deletion_test(useVolumeSnapshots bool) {
	veleroCfg := VeleroCfg
	veleroCfg.UseVolumeSnapshots = useVolumeSnapshots
	veleroCfg.UseNodeAgent = !useVolumeSnapshots

	BeforeEach(func() {
		if useVolumeSnapshots && veleroCfg.CloudProvider == Kind {
			Skip(fmt.Sprintf("Volume snapshots not supported on %s", Kind))
		}
		var err error
		flag.Parse()
		if InstallVelero {
			Expect(PrepareVelero(context.Background(), "backup deletion", veleroCfg)).To(Succeed())
		}
		UUIDgen, err = uuid.NewRandom()
		Expect(err).To(Succeed())
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
		}
	})

	When("kibishii is the sample workload", func() {
		It("Deleted backups are deleted from object storage and backups deleted from object storage can be deleted locally", func() {
			Expect(runBackupDeletionTests(*veleroCfg.ClientToInstallVelero, veleroCfg, "", useVolumeSnapshots, veleroCfg.KibishiiDirectory)).To(Succeed(),
				"Failed to run backup deletion test")
		})
	})
}

// runUpgradeTests runs upgrade test on the provider by kibishii.
func runBackupDeletionTests(client TestClient, veleroCfg VeleroConfig, backupLocation string,
	useVolumeSnapshots bool, kibishiiDirectory string) error {
	var err error
	var snapshotCheckPoint SnapshotCheckPoint
	backupName := "backup-" + UUIDgen.String()

	workloadNamespaceList := []string{"backup-deletion-1-" + UUIDgen.String(), "backup-deletion-2-" + UUIDgen.String()}
	nsCount := len(workloadNamespaceList)
	workloadNamespaces := strings.Join(workloadNamespaceList[:], ",")

	if useVolumeSnapshots && veleroCfg.CloudProvider == "kind" {
		Skip("Volume snapshots not supported on kind")
	}
	oneHourTimeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*60)
	defer ctxCancel()
	veleroCLI := veleroCfg.VeleroCLI
	providerName := veleroCfg.CloudProvider
	veleroNamespace := veleroCfg.VeleroNamespace
	registryCredentialFile := veleroCfg.RegistryCredentialFile
	veleroFeatures := veleroCfg.Features
	for _, ns := range workloadNamespaceList {
		if err := CreateNamespace(oneHourTimeout, client, ns); err != nil {
			return errors.Wrapf(err, "Failed to create namespace %s to install Kibishii workload", ns)
		}

		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			defer func() {
				if err := DeleteNamespace(context.Background(), client, ns, true); err != nil {
					fmt.Println(errors.Wrapf(err, "failed to delete the namespace %q", ns))
				}
			}()
		}

		if err := KibishiiPrepareBeforeBackup(
			oneHourTimeout,
			client,
			providerName,
			ns,
			registryCredentialFile,
			veleroFeatures,
			kibishiiDirectory,
			DefaultKibishiiData,
			veleroCfg.ImageRegistryProxy,
			veleroCfg.WorkerOS,
		); err != nil {
			return errors.Wrapf(err, "Failed to install and prepare data for kibishii %s", ns)
		}
		err := ObjectsShouldNotBeInBucket(veleroCfg.ObjectStoreProvider, veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket, veleroCfg.BSLPrefix, veleroCfg.BSLConfig, backupName, BackupObjectsPrefix, 1)
		if err != nil {
			return err
		}
	}

	var BackupCfg BackupConfig
	BackupCfg.BackupName = backupName
	BackupCfg.Namespace = workloadNamespaces
	BackupCfg.BackupLocation = backupLocation
	BackupCfg.UseVolumeSnapshots = useVolumeSnapshots
	BackupCfg.DefaultVolumesToFsBackup = !useVolumeSnapshots
	BackupCfg.Selector = ""

	By(fmt.Sprintf("Back up workload with name %s", BackupCfg.BackupName), func() {
		Expect(VeleroBackupNamespace(oneHourTimeout, veleroCLI,
			veleroNamespace, BackupCfg)).To(Succeed(), func() string {
			RunDebug(context.Background(), veleroCLI, veleroNamespace, BackupCfg.BackupName, "")
			return "Fail to backup workload"
		})
	})
	for _, ns := range workloadNamespaceList {
		if useVolumeSnapshots &&
			veleroCfg.HasVspherePlugin {
			// Wait for uploads started by the Velero Plugin for vSphere to complete
			// TODO - remove after upload progress monitoring is implemented
			fmt.Println("Waiting for vSphere uploads to complete")
			if err := WaitForVSphereUploadCompletion(oneHourTimeout, time.Hour, ns, DefaultKibishiiWorkerCounts); err != nil {
				return errors.Wrapf(err, "Error waiting for uploads to complete")
			}
		}
	}
	err = ObjectsShouldBeInBucket(veleroCfg.ObjectStoreProvider, veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket, veleroCfg.BSLPrefix, veleroCfg.BSLConfig, backupName, BackupObjectsPrefix)
	if err != nil {
		return err
	}

	backupVolumeInfo, err := GetVolumeInfo(
		veleroCfg.ObjectStoreProvider,
		veleroCfg.CloudCredentialsFile,
		veleroCfg.BSLBucket,
		veleroCfg.BSLPrefix,
		veleroCfg.BSLConfig,
		backupName,
		BackupObjectsPrefix+"/"+backupName,
	)
	if err != nil {
		return errors.Wrapf(err, "Failed to get volume info for backup %s", backupName)
	}
	if useVolumeSnapshots {
		// Check for snapshots existence
		if veleroCfg.CloudProvider == Vsphere {
			// For vSphere, checking snapshot should base on namespace and backup name
			for _, ns := range workloadNamespaceList {
				snapshotCheckPoint, err := BuildSnapshotCheckPointFromVolumeInfo(veleroCfg, backupVolumeInfo, DefaultKibishiiWorkerCounts, ns, backupName, KibishiiPVCNameList)
				Expect(err).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")
				err = CheckSnapshotsInProvider(
					veleroCfg,
					backupName,
					snapshotCheckPoint,
					false,
				)
				if err != nil {
					return errors.Wrap(err, "exceed waiting for snapshot created in cloud")
				}
			}
		} else {
			// For public cloud, When using backup name to index VolumeSnapshotContents, make sure count of VolumeSnapshotContents should including PVs in all namespace
			// so VolumeSnapshotContents count should be equal to "namespace count" * "Kibishii worker count per namespace".
			snapshotCheckPoint, err := BuildSnapshotCheckPointFromVolumeInfo(veleroCfg, backupVolumeInfo, DefaultKibishiiWorkerCounts*nsCount, "", backupName, KibishiiPVCNameList)
			Expect(err).NotTo(HaveOccurred(), "Fail to get Azure CSI snapshot checkpoint")

			// Get all snapshots base on backup name, regardless of namespaces
			err = CheckSnapshotsInProvider(
				veleroCfg,
				backupName,
				snapshotCheckPoint,
				false,
			)
			if err != nil {
				return errors.Wrap(err, "exceed waiting for snapshot created in cloud")
			}
		}
	} else {
		// Check for BackupRepository and DeleteRequest
		var brList, pvbList []string
		brList, err = KubectlGetBackupRepository(oneHourTimeout, "kopia", veleroCfg.VeleroNamespace)
		if err != nil {
			return err
		}
		pvbList, err = KubectlGetPodVolumeBackup(oneHourTimeout, BackupCfg.BackupName, veleroCfg.VeleroNamespace)

		fmt.Println(brList)
		fmt.Println(pvbList)
		if err != nil {
			return err
		}
	}

	err = DeleteBackup(context.Background(), backupName, &veleroCfg)
	if err != nil {
		return err
	}

	// Verify snapshots are deleted after backup deletion.
	if useVolumeSnapshots {
		snapshotCheckPoint.ExpectCount = 0
		err = CheckSnapshotsInProvider(
			veleroCfg,
			backupName,
			snapshotCheckPoint,
			false,
		)
		if err != nil {
			return errors.Wrap(err, "fail to verify snapshots are deleted in provider.")
		}
	}

	// Verify backup metadata files are deleted in OSS after backup deletion.
	err = ObjectsShouldNotBeInBucket(
		veleroCfg.ObjectStoreProvider,
		veleroCfg.CloudCredentialsFile,
		veleroCfg.BSLBucket,
		veleroCfg.BSLPrefix,
		veleroCfg.BSLConfig,
		backupName,
		BackupObjectsPrefix,
		5,
	)
	if err != nil {
		return err
	}

	// Hit issue: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html#:~:text=SnapshotCreationPerVolumeRateExceeded
	// Sleep for more than 15 seconds to avoid this issue.
	time.Sleep(1 * time.Minute)

	backupName = "backup-1-" + UUIDgen.String()
	BackupCfg.BackupName = backupName

	By(fmt.Sprintf("Back up workload with name %s", BackupCfg.BackupName), func() {
		Expect(VeleroBackupNamespace(oneHourTimeout, veleroCLI,
			veleroNamespace, BackupCfg)).To(Succeed(), func() string {
			RunDebug(context.Background(), veleroCLI, veleroNamespace, BackupCfg.BackupName, "")
			return "Fail to backup workload"
		})
	})

	if err := DeleteObjectsInBucket(
		veleroCfg.ObjectStoreProvider,
		veleroCfg.CloudCredentialsFile,
		veleroCfg.BSLBucket,
		veleroCfg.BSLPrefix,
		veleroCfg.BSLConfig,
		backupName,
		BackupObjectsPrefix,
	); err != nil {
		return err
	}

	if err := ObjectsShouldNotBeInBucket(
		veleroCfg.ObjectStoreProvider,
		veleroCfg.CloudCredentialsFile,
		veleroCfg.BSLBucket,
		veleroCfg.BSLPrefix,
		veleroCfg.BSLConfig,
		backupName,
		BackupObjectsPrefix,
		1,
	); err != nil {
		return err
	}

	err = DeleteBackup(context.Background(), backupName, &veleroCfg)
	if err != nil {
		return errors.Wrapf(err, "|| UNEXPECTED || - Failed to delete backup %q", backupName)
	} else {
		fmt.Printf("|| EXPECTED || - Success to delete backup %s locally\n", backupName)
	}
	fmt.Printf("|| EXPECTED || - Backup deletion test completed successfully\n")
	return nil
}
