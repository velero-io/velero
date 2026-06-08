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
package backup

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/kibishii"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

type BackupRestoreTestConfig struct {
	useVolumeSnapshots  bool
	kibishiiPatchSubDir string
	isRetainPVTest      bool
}

func BackupRestoreWithSnapshots() {
	config := BackupRestoreTestConfig{true, "", false}
	BackupRestoreTest(config)
}

func BackupRestoreWithFSBackup() {
	config := BackupRestoreTestConfig{false, "", false}
	BackupRestoreTest(config)
}

func BackupRestoreRetainedPVWithSnapshots() {
	config := BackupRestoreTestConfig{true, "overlays/sc-reclaim-policy/", true}
	BackupRestoreTest(config)
}

func BackupRestoreRetainedPVWithFSBackup() {
	config := BackupRestoreTestConfig{false, "overlays/sc-reclaim-policy/", true}
	BackupRestoreTest(config)
}

func BackupRestoreTest(backupRestoreTestConfig BackupRestoreTestConfig) {
	var (
		backupName, restoreName, kibishiiNamespace string
		err                                        error
		provideSnapshotVolumesParmInBackup         bool
		veleroCfg                                  VeleroConfig
	)
	provideSnapshotVolumesParmInBackup = false
	useVolumeSnapshots := backupRestoreTestConfig.useVolumeSnapshots

	BeforeEach(func() {
		veleroCfg = VeleroCfg

		veleroCfg.KibishiiDirectory = veleroCfg.KibishiiDirectory + backupRestoreTestConfig.kibishiiPatchSubDir
		veleroCfg.UseVolumeSnapshots = useVolumeSnapshots
		veleroCfg.UseNodeAgent = !useVolumeSnapshots
		if veleroCfg.CloudProvider == Kind {
			Skip("Volume snapshots plugin and File System Backups are not supported on kind")
			// on kind cluster snapshots are not supported since there is no velero snapshot plugin for kind volumes.
			// and PodVolumeBackups are not supported because PVB creation gets skipped for hostpath volumes, which are the only
			// volumes created on kind clusters using the default storage class and provisioner (provisioner: rancher.io/local-path)
			// This test suite checks for volume snapshots and PVBs generated from FileSystemBackups, so skip it on kind clusters
		}

		// [SKIP]: Static provisioning for vSphere CSI driver works differently from other drivers.
		//         For vSphere CSI, after you create a PV specifying an existing volume handle, CSI
		//         syncer will need to register it with CNS. For other CSI drivers, static provisioning
		//         usually does not go through storage system at all.  That's probably why it took longer
		if backupRestoreTestConfig.isRetainPVTest && veleroCfg.CloudProvider == Vsphere {
			Skip("Skip due to vSphere CSI driver long time issue of Static provisioning")
		}
		var err error
		flag.Parse()
		UUIDgen, err = uuid.NewRandom()
		kibishiiNamespace = "k-" + UUIDgen.String()
		Expect(err).To(Succeed())
		DeleteStorageClass(context.Background(), *veleroCfg.ClientToInstallVelero, KibishiiStorageClassName)
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
				if backupRestoreTestConfig.isRetainPVTest {
					CleanAllRetainedPV(context.Background(), *veleroCfg.ClientToInstallVelero)
				}
				DeleteStorageClass(context.Background(), *veleroCfg.ClientToInstallVelero, KibishiiStorageClassName)
			})
			if InstallVelero {
				ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*10)
				defer ctxCancel()
				err = VeleroUninstall(ctx, veleroCfg)
				Expect(err).To(Succeed())
			}
		}
	})

	When("kibishii is the sample workload", func() {
		It("should be successfully backed up and restored to the default BackupStorageLocation", func() {
			if InstallVelero {
				if useVolumeSnapshots {
					//Install node agent also
					veleroCfg.UseNodeAgent = useVolumeSnapshots
					// DefaultVolumesToFsBackup should be mutually exclusive with useVolumeSnapshots in installation CLI,
					// otherwise DefaultVolumesToFsBackup need to be set to false in backup CLI when taking volume snapshot
					// Make sure DefaultVolumesToFsBackup was set to false in backup CLI
					veleroCfg.DefaultVolumesToFsBackup = useVolumeSnapshots
				} else {
					veleroCfg.DefaultVolumesToFsBackup = !useVolumeSnapshots
				}
				Expect(VeleroInstall(context.Background(), &veleroCfg, false)).To(Succeed())
			}
			backupName = "backup-" + UUIDgen.String()
			restoreName = "restore-" + UUIDgen.String()
			// Even though we are using Velero's CloudProvider plugin for object storage, the Kubernetes cluster is running on
			// KinD. So use the kind installation for Kibishii.

			// if set ProvideSnapshotsVolumeParam to false here, make sure set it true in other tests of this case
			veleroCfg.ProvideSnapshotsVolumeParam = provideSnapshotVolumesParmInBackup

			// Set DefaultVolumesToFsBackup to false since DefaultVolumesToFsBackup was set to true during installation
			Expect(RunKibishiiTests(
				veleroCfg,
				backupName,
				restoreName,
				"",
				kibishiiNamespace,
				useVolumeSnapshots,
				false,
			)).To(Succeed(),
				"Failed to successfully backup and restore Kibishii namespace")
		})

		It("should successfully back up and restore to an additional BackupStorageLocation with unique credentials", func() {
			if backupRestoreTestConfig.isRetainPVTest {
				Skip("It's tested by 1st test case")
			}
			if veleroCfg.AdditionalBSLProvider == "" {
				Skip("no additional BSL provider given, not running multiple BackupStorageLocation with unique credentials tests")
			}

			if veleroCfg.AdditionalBSLBucket == "" {
				Skip("no additional BSL bucket given, not running multiple BackupStorageLocation with unique credentials tests")
			}

			if veleroCfg.AdditionalBSLCredentials == "" {
				Skip("no additional BSL credentials given, not running multiple BackupStorageLocation with unique credentials tests")
			}
			if InstallVelero {
				if useVolumeSnapshots {
					veleroCfg.DefaultVolumesToFsBackup = !useVolumeSnapshots
				} else { //FS volume backup
					// Install VolumeSnapshots also
					veleroCfg.UseVolumeSnapshots = !useVolumeSnapshots
					// DefaultVolumesToFsBackup is false in installation CLI here,
					// so must set DefaultVolumesToFsBackup to be true in backup CLI come after
					veleroCfg.DefaultVolumesToFsBackup = useVolumeSnapshots
				}

				Expect(VeleroInstall(context.Background(), &veleroCfg, false)).To(Succeed())
			}
			plugins, err := GetPlugins(context.TODO(), veleroCfg, false)
			Expect(err).To(Succeed())
			Expect(AddPlugins(plugins, veleroCfg)).To(Succeed())

			// Create Secret for additional BSL
			secretName := fmt.Sprintf("bsl-credentials-%s", UUIDgen)
			secretKey := fmt.Sprintf("creds-%s", veleroCfg.AdditionalBSLProvider)
			files := map[string]string{
				secretKey: veleroCfg.AdditionalBSLCredentials,
			}

			Expect(CreateSecretFromFiles(context.TODO(), *veleroCfg.ClientToInstallVelero, veleroCfg.VeleroNamespace, secretName, files)).To(Succeed())

			// Create additional BSL using credential
			Expect(VeleroCreateBackupLocation(context.TODO(),
				veleroCfg.VeleroCLI,
				veleroCfg.VeleroNamespace,
				common.AdditionalBSLName,
				veleroCfg.AdditionalBSLProvider,
				veleroCfg.AdditionalBSLBucket,
				veleroCfg.AdditionalBSLPrefix,
				veleroCfg.AdditionalBSLConfig,
				secretName,
				secretKey,
			)).To(Succeed())

			// We limit the length of backup name here to avoid the issue of vsphere plugin
			// https://github.com/vmware-tanzu/velero-plugin-for-vsphere/issues/370
			// We can remove the logic once the issue is fixed
			backupName = "backup-" + common.AdditionalBSLName
			restoreName = "restore-" + common.AdditionalBSLName
			veleroCfg.ProvideSnapshotsVolumeParam = !provideSnapshotVolumesParmInBackup
			workloadNS := kibishiiNamespace + common.AdditionalBSLName
			Expect(
				RunKibishiiTests(
					veleroCfg,
					backupName,
					restoreName,
					common.AdditionalBSLName,
					workloadNS,
					useVolumeSnapshots,
					!useVolumeSnapshots,
				),
			).To(Succeed(),
				"Failed to successfully backup and restore Kibishii namespace with additional BSL %s", common.AdditionalBSLName)
		})
	})
}
