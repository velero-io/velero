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

package kibishii

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"k8s.io/apimachinery/pkg/util/wait"

	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/providers"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

const (
	jumpPadPod = "jump-pad"
)

type KibishiiData struct {
	Levels        int
	DirsPerLevel  int
	FilesPerLevel int
	FileLength    int
	BlockSize     int
	PassNum       int
	ExpectedNodes int
}

var DefaultKibishiiWorkerCounts = 2
var DefaultKibishiiData = &KibishiiData{2, 10, 10, 1024, 1024, 0, DefaultKibishiiWorkerCounts}

var KibishiiPVCNameList = []string{"kibishii-data-kibishii-deployment-0", "kibishii-data-kibishii-deployment-1"}
var KibishiiStorageClassName = "kibishii-storage-class"

// RunKibishiiTests runs kibishii tests on the provider.
func RunKibishiiTests(veleroCfg VeleroConfig, backupName, restoreName, backupLocation, kibishiiNamespace string,
	useVolumeSnapshots, defaultVolumesToFsBackup bool) error {
	pvCount := len(KibishiiPVCNameList)
	client := *veleroCfg.ClientToInstallVelero
	oneHourTimeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*60)
	defer ctxCancel()
	veleroCLI := veleroCfg.VeleroCLI
	providerName := veleroCfg.CloudProvider
	veleroNamespace := veleroCfg.VeleroNamespace
	registryCredentialFile := veleroCfg.RegistryCredentialFile
	veleroFeatures := veleroCfg.Features
	kibishiiDirectory := veleroCfg.KibishiiDirectory
	if _, err := GetNamespace(context.Background(), client, kibishiiNamespace); err == nil {
		fmt.Printf("Workload namespace %s exists, delete it first.\n", kibishiiNamespace)
		if err = DeleteNamespace(context.Background(), client, kibishiiNamespace, true); err != nil {
			fmt.Println(errors.Wrapf(err, "failed to delete the namespace %q", kibishiiNamespace))
		}
	}
	if err := CreateNamespace(oneHourTimeout, client, kibishiiNamespace); err != nil {
		return errors.Wrapf(err, "Failed to create namespace %s to install Kibishii workload", kibishiiNamespace)
	}
	defer func() {
		if !veleroCfg.Debug {
			if err := DeleteNamespace(context.Background(), client, kibishiiNamespace, true); err != nil {
				fmt.Println(errors.Wrapf(err, "failed to delete the namespace %q", kibishiiNamespace))
			}
		}
	}()
	fmt.Printf("KibishiiPrepareBeforeBackup %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err := KibishiiPrepareBeforeBackup(oneHourTimeout, client, providerName,
		kibishiiNamespace, registryCredentialFile, veleroFeatures,
		kibishiiDirectory, useVolumeSnapshots, DefaultKibishiiData); err != nil {
		return errors.Wrapf(err, "Failed to install and prepare data for kibishii %s", kibishiiNamespace)
	}
	fmt.Printf("KibishiiPrepareBeforeBackup done %s\n", time.Now().Format("2006-01-02 15:04:05"))

	var BackupCfg BackupConfig
	BackupCfg.BackupName = backupName
	BackupCfg.Namespace = kibishiiNamespace
	BackupCfg.BackupLocation = backupLocation
	BackupCfg.UseVolumeSnapshots = useVolumeSnapshots
	BackupCfg.DefaultVolumesToFsBackup = defaultVolumesToFsBackup
	BackupCfg.Selector = ""
	BackupCfg.ProvideSnapshotsVolumeParam = veleroCfg.ProvideSnapshotsVolumeParam

	fmt.Printf("VeleroBackupNamespace %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err := VeleroBackupNamespace(oneHourTimeout, veleroCLI, veleroNamespace, BackupCfg); err != nil {
		RunDebug(context.Background(), veleroCLI, veleroNamespace, backupName, "")
		return errors.Wrapf(err, "Failed to backup kibishii namespace %s", kibishiiNamespace)
	}

	fmt.Printf("VeleroBackupNamespace done %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if useVolumeSnapshots {
		if providerName == "vsphere" {
			// Wait for uploads started by the Velero Plugin for vSphere to complete
			// TODO - remove after upload progress monitoring is implemented
			fmt.Println("Waiting for vSphere uploads to complete")
			if err := WaitForVSphereUploadCompletion(oneHourTimeout, time.Hour, kibishiiNamespace, 2); err != nil {
				return errors.Wrapf(err, "Error waiting for uploads to complete")
			}
		}
		snapshotCheckPoint, err := GetSnapshotCheckPoint(client, veleroCfg, 2, kibishiiNamespace, backupName, KibishiiPVCNameList)

		if err != nil {
			return errors.Wrap(err, "Fail to get snapshot checkpoint")
		}
		err = SnapshotsShouldBeCreatedInCloud(veleroCfg.CloudProvider,
			veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket, veleroCfg.BSLConfig,
			backupName, snapshotCheckPoint)
		if err != nil {
			return errors.Wrap(err, "exceed waiting for snapshot created in cloud")
		}
	} else {
		pvbs, err := GetPVB(oneHourTimeout, veleroCfg.VeleroNamespace, kibishiiNamespace)
		if err != nil {
			return errors.Wrapf(err, "failed to get PVB for namespace %s", kibishiiNamespace)
		}
		if len(pvbs) != pvCount {
			return errors.New(fmt.Sprintf("PVB count %d should be %d in namespace %s", len(pvbs), pvCount, kibishiiNamespace))
		}
		if providerName == "vsphere" {
			// Wait for uploads started by the Velero Plugin for vSphere to complete
			// TODO - remove after upload progress monitoring is implemented

			// TODO[High] - uncomment code block below when vSphere plugin PR #500 is included in release version.
			//   https://github.com/vmware-tanzu/velero-plugin-for-vsphere/pull/500/

			// fmt.Println("Make sure no vSphere snapshot uploads created")
			// if err := WaitForVSphereUploadCompletion(oneHourTimeout, time.Hour, kibishiiNamespace, 0); err != nil {
			// 	return errors.Wrapf(err, "Error get vSphere snapshot uploads")
			// }
		} else {
			// wait for a period to confirm no snapshots exist for the backup
			time.Sleep(5 * time.Minute)
			if strings.EqualFold(veleroFeatures, "EnableCSI") {
				_, err = GetSnapshotCheckPoint(*veleroCfg.ClientToInstallVelero, veleroCfg, 0,
					kibishiiNamespace, backupName, KibishiiPVCNameList)
				if err != nil {
					return errors.Wrap(err, "failed to get snapshot checkPoint")
				}
			} else {
				err = SnapshotsShouldNotExistInCloud(veleroCfg.CloudProvider,
					veleroCfg.CloudCredentialsFile, veleroCfg.BSLBucket, veleroCfg.BSLConfig,
					backupName, SnapshotCheckPoint{})
				if err != nil {
					return errors.Wrap(err, "exceed waiting for snapshot created in cloud")
				}
			}
		}
	}

	fmt.Printf("Simulating a disaster by removing namespace %s %s\n", kibishiiNamespace, time.Now().Format("2006-01-02 15:04:05"))
	if err := DeleteNamespace(oneHourTimeout, client, kibishiiNamespace, true); err != nil {
		return errors.Wrapf(err, "failed to delete namespace %s", kibishiiNamespace)
	}

	// the snapshots of AWS may be still in pending status when do the restore, wait for a while
	// to avoid this https://github.com/vmware-tanzu/velero/issues/1799
	// TODO remove this after https://github.com/vmware-tanzu/velero/issues/3533 is fixed
	if useVolumeSnapshots {
		fmt.Println("Waiting 5 minutes to make sure the snapshots are ready...")
		time.Sleep(5 * time.Minute)
	}

	fmt.Printf("VeleroRestore %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err := VeleroRestore(oneHourTimeout, veleroCLI, veleroNamespace, restoreName, backupName, ""); err != nil {
		RunDebug(context.Background(), veleroCLI, veleroNamespace, "", restoreName)
		return errors.Wrapf(err, "Restore %s failed from backup %s", restoreName, backupName)
	}
	if !useVolumeSnapshots && providerName != "vsphere" {
		pvrs, err := GetPVR(oneHourTimeout, veleroCfg.VeleroNamespace, kibishiiNamespace)
		if err != nil {
			return errors.Wrapf(err, "failed to get PVR for namespace %s", kibishiiNamespace)
		} else if len(pvrs) != pvCount {
			return errors.New(fmt.Sprintf("PVR count %d is not as expected %d", len(pvrs), pvCount))
		}
	}
	fmt.Printf("KibishiiVerifyAfterRestore %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err := KibishiiVerifyAfterRestore(client, kibishiiNamespace, oneHourTimeout, DefaultKibishiiData); err != nil {
		return errors.Wrapf(err, "Error verifying kibishii after restore")
	}
	fmt.Printf("kibishii test completed successfully %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

func installKibishii(ctx context.Context, namespace string, cloudPlatform, veleroFeatures,
	kibishiiDirectory string, useVolumeSnapshots bool, workerReplicas int) error {
	if strings.EqualFold(cloudPlatform, "azure") &&
		strings.EqualFold(veleroFeatures, "EnableCSI") {
		cloudPlatform = "azure-csi"
	}
	if strings.EqualFold(cloudPlatform, "aws") &&
		strings.EqualFold(veleroFeatures, "EnableCSI") {
		cloudPlatform = "aws-csi"
	}
	// We use kustomize to generate YAML for Kibishii from the checked-in yaml directories
	kibishiiInstallCmd := exec.CommandContext(ctx, "kubectl", "apply", "-n", namespace, "-k",
		kibishiiDirectory+cloudPlatform, "--timeout=90s")
	_, stderr, err := veleroexec.RunCommand(kibishiiInstallCmd)
	fmt.Printf("Install Kibishii cmd: %s\n", kibishiiInstallCmd)
	if err != nil {
		return errors.Wrapf(err, "failed to install kibishii, stderr=%s", stderr)
	}

	labelNamespaceCmd := exec.CommandContext(ctx, "kubectl", "label", "namespace", namespace, "pod-security.kubernetes.io/enforce=baseline", "pod-security.kubernetes.io/enforce-version=latest", "--overwrite=true")
	_, stderr, err = veleroexec.RunCommand(labelNamespaceCmd)
	fmt.Printf("Label namespace with PSA policy: %s\n", labelNamespaceCmd)
	if err != nil {
		return errors.Wrapf(err, "failed to label namespace with PSA policy, stderr=%s", stderr)
	}
	if workerReplicas != DefaultKibishiiWorkerCounts {
		err = ScaleStatefulSet(ctx, namespace, "kibishii-deployment", workerReplicas)
		if err != nil {
			return errors.Wrapf(err, "failed to scale statefulset, stderr=%s", err.Error())
		}
	}

	kibishiiSetWaitCmd := exec.CommandContext(ctx, "kubectl", "rollout", "status", "statefulset.apps/kibishii-deployment",
		"-n", namespace, "-w", "--timeout=30m")
	_, stderr, err = veleroexec.RunCommand(kibishiiSetWaitCmd)
	if err != nil {
		return errors.Wrapf(err, "failed to rollout, stderr=%s", stderr)
	}

	fmt.Printf("Waiting for kibishii jump-pad pod to be ready\n")
	jumpPadWaitCmd := exec.CommandContext(ctx, "kubectl", "wait", "--for=condition=ready", "-n", namespace, "pod/jump-pad")
	_, stderr, err = veleroexec.RunCommand(jumpPadWaitCmd)
	if err != nil {
		return errors.Wrapf(err, "Failed to wait for ready status of pod %s/%s, stderr=%s", namespace, jumpPadPod, stderr)
	}

	return err
}

func generateData(ctx context.Context, namespace string, kibishiiData *KibishiiData) error {
	timeout := 30 * time.Minute
	interval := 1 * time.Second
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		timeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*20)
		defer ctxCancel()
		kibishiiGenerateCmd := exec.CommandContext(timeout, "kubectl", "exec", "-n", namespace, "jump-pad", "--",
			"/usr/local/bin/generate.sh", strconv.Itoa(kibishiiData.Levels), strconv.Itoa(kibishiiData.DirsPerLevel),
			strconv.Itoa(kibishiiData.FilesPerLevel), strconv.Itoa(kibishiiData.FileLength),
			strconv.Itoa(kibishiiData.BlockSize), strconv.Itoa(kibishiiData.PassNum), strconv.Itoa(kibishiiData.ExpectedNodes))
		fmt.Printf("kibishiiGenerateCmd cmd =%v\n", kibishiiGenerateCmd)

		stdout, stderr, err := veleroexec.RunCommand(kibishiiGenerateCmd)
		if err != nil || strings.Contains(stderr, "Timeout occurred") || strings.Contains(stderr, "dialing backend") {
			fmt.Printf("Kibishi generate stdout Timeout occurred: %s stderr: %s err: %s", stdout, stderr, err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return errors.Wrapf(err, "Failed to wait generate data in namespace %s", namespace)
	}
	return nil
}

func verifyData(ctx context.Context, namespace string, kibishiiData *KibishiiData) error {
	timeout := 10 * time.Minute
	interval := 5 * time.Second
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		timeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*20)
		defer ctxCancel()
		kibishiiVerifyCmd := exec.CommandContext(timeout, "kubectl", "exec", "-n", namespace, "jump-pad", "--",
			"/usr/local/bin/verify.sh", strconv.Itoa(kibishiiData.Levels), strconv.Itoa(kibishiiData.DirsPerLevel),
			strconv.Itoa(kibishiiData.FilesPerLevel), strconv.Itoa(kibishiiData.FileLength),
			strconv.Itoa(kibishiiData.BlockSize), strconv.Itoa(kibishiiData.PassNum),
			strconv.Itoa(kibishiiData.ExpectedNodes))
		fmt.Printf("kibishiiVerifyCmd cmd =%v\n", kibishiiVerifyCmd)

		stdout, stderr, err := veleroexec.RunCommand(kibishiiVerifyCmd)
		if strings.Contains(stderr, "Timeout occurred") {
			return false, nil
		}
		if err != nil {
			fmt.Printf("Kibishi verify stdout Timeout occurred: %s stderr: %s err: %s\n", stdout, stderr, err)
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return errors.Wrapf(err, "Failed to verify kibishii data in namespace %s", namespace)
	}
	fmt.Printf("Success to verify kibishii data in namespace %s\n", namespace)
	return nil
}

func waitForKibishiiPods(ctx context.Context, client TestClient, kibishiiNamespace string) error {
	return WaitForPods(ctx, client, kibishiiNamespace, []string{"jump-pad", "etcd0", "etcd1", "etcd2", "kibishii-deployment-0", "kibishii-deployment-1"})
}

func KibishiiPrepareBeforeBackup(oneHourTimeout context.Context, client TestClient,
	providerName, kibishiiNamespace, registryCredentialFile, veleroFeatures,
	kibishiiDirectory string, useVolumeSnapshots bool, kibishiiData *KibishiiData) error {
	fmt.Printf("installKibishii %s\n", time.Now().Format("2006-01-02 15:04:05"))
	serviceAccountName := "default"

	// wait until the service account is created before patch the image pull secret
	if err := WaitUntilServiceAccountCreated(oneHourTimeout, client, kibishiiNamespace, serviceAccountName, 10*time.Minute); err != nil {
		return errors.Wrapf(err, "failed to wait the service account %q created under the namespace %q", serviceAccountName, kibishiiNamespace)
	}

	// add the image pull secret to avoid the image pull limit issue of Docker Hub
	if err := PatchServiceAccountWithImagePullSecret(oneHourTimeout, client, kibishiiNamespace, serviceAccountName, registryCredentialFile); err != nil {
		return errors.Wrapf(err, "failed to patch the service account %q under the namespace %q", serviceAccountName, kibishiiNamespace)
	}

	if err := installKibishii(oneHourTimeout, kibishiiNamespace, providerName, veleroFeatures,
		kibishiiDirectory, useVolumeSnapshots, kibishiiData.ExpectedNodes); err != nil {
		return errors.Wrap(err, "Failed to install Kibishii workload")
	}
	// wait for kibishii pod startup
	// TODO - Fix kibishii so we can check that it is ready to go
	fmt.Printf("Waiting for kibishii pods to be ready %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err := waitForKibishiiPods(oneHourTimeout, client, kibishiiNamespace); err != nil {
		return errors.Wrapf(err, "Failed to wait for ready status of kibishii pods in %s", kibishiiNamespace)
	}
	if kibishiiData == nil {
		kibishiiData = DefaultKibishiiData
	}
	fmt.Printf("generateData %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err := generateData(oneHourTimeout, kibishiiNamespace, kibishiiData); err != nil {
		return errors.Wrap(err, "Failed to generate data")
	}
	fmt.Printf("generateData done %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

func KibishiiVerifyAfterRestore(client TestClient, kibishiiNamespace string, oneHourTimeout context.Context,
	kibishiiData *KibishiiData) error {
	if kibishiiData == nil {
		kibishiiData = DefaultKibishiiData
	}
	// wait for kibishii pod startup
	// TODO - Fix kibishii so we can check that it is ready to go
	fmt.Printf("Waiting for kibishii pods to be ready\n")
	if err := waitForKibishiiPods(oneHourTimeout, client, kibishiiNamespace); err != nil {
		return errors.Wrapf(err, "Failed to wait for ready status of kibishii pods in %s", kibishiiNamespace)
	}

	// TODO - check that namespace exists
	fmt.Printf("running kibishii verify\n")
	if err := verifyData(oneHourTimeout, kibishiiNamespace, kibishiiData); err != nil {
		return errors.Wrap(err, "Failed to verify data generated by kibishii")
	}
	return nil
}
