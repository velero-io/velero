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

package inplacerestore

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	datamoverutil "github.com/velero-io/velero/pkg/util/datamover"
	veleroexec "github.com/velero-io/velero/pkg/util/exec"
	velerotest "github.com/velero-io/velero/test"
	. "github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/common"
	. "github.com/velero-io/velero/test/util/k8s"
)

const (
	workloadName = "workload"
	miB          = int64(1024 * 1024)
)

var CSIInplaceRestoreTest = func() {
	for _, mover := range []struct{ name, label string }{
		{"velero-block", "BlockDataMover"},
		{"velero-fs", "FilesystemDataMover"},
	} {
		for _, policy := range []string{"full", "incremental"} {
			Context(fmt.Sprintf("CSI snapshot with %s data movement, in-place %s restore", mover.name, policy),
				Label("CSI", "Snapshot", "DataMover", mover.label, policy),
				TestFunc(&InplaceRestore{dataMover: mover.name, policy: policy}),
			)
		}
	}
}

type InplaceRestore struct {
	TestCase
	dataMover    string
	policy       string
	checksums    string
	volumeHandle string
}

func (i *InplaceRestore) Init() error {
	if err := i.TestCase.Init(); err != nil {
		return err
	}
	i.CaseBaseName = fmt.Sprintf("inplace-%s-%s-%s", i.dataMover, i.policy, i.UUIDgen)
	i.BackupName = "backup-" + i.CaseBaseName
	i.RestoreName = "restore-" + i.CaseBaseName
	i.NamespacesTotal = 1
	i.NSIncluded = &[]string{i.CaseBaseName}
	i.VeleroCfg.UseNodeAgent = true
	i.TestMsg = &TestMSG{
		Desc:      fmt.Sprintf("CSI snapshot with %s data movement, in-place %s restore", i.dataMover, i.policy),
		Text:      "Restore volume data while preserving the existing CSI volume",
		FailedMSG: "In-place restore did not preserve the volume, restore its data, or report the expected statistics",
	}
	i.BackupArgs = []string{
		"backup", "create", i.BackupName, "--namespace", i.VeleroCfg.VeleroNamespace,
		"--include-namespaces", i.CaseBaseName, "--snapshot-volumes=true",
		"--default-volumes-to-fs-backup=false", "--snapshot-move-data=true",
		"--data-mover", i.dataMover, "--wait",
	}
	i.RestoreArgs = []string{
		"restore", "create", i.RestoreName, "--namespace", i.VeleroCfg.VeleroNamespace,
		"--from-backup", i.BackupName, "--existing-volume-data-policy", i.policy, "--wait",
	}
	if datamoverutil.IsVeleroFSDataMover(i.dataMover) {
		i.RestoreArgs = append(i.RestoreArgs, fmt.Sprintf("--delete-extra-files=%t", i.policy == "incremental"))
	}
	return nil
}

func (i *InplaceRestore) Start() error {
	if i.VeleroCfg.WorkerOS == common.WorkerOSWindows {
		Skip("These cases use a Linux filesystem workload")
	}
	if !velerotest.FeatureEnabled(i.VeleroCfg.Features, velerotest.FeatureCSI) || !i.VeleroCfg.UseVolumeSnapshots {
		Skip("These cases require CSI and volume snapshots enabled")
	}
	return i.TestCase.Start()
}

func (i *InplaceRestore) CreateResources() error {
	By("Create a deployment mounting a 256Mi filesystem PVC")
	if err := CreateNamespaceWithLabel(i.Ctx, i.Client, i.CaseBaseName, map[string]string{}); err != nil {
		return err
	}
	pvc := NewPVC(i.CaseBaseName, workloadName).
		WithStorageClass(velerotest.StorageClassName).
		WithResourceStorage(resource.MustParse("256Mi"))
	if err := CreatePvc(i.Client, pvc); err != nil {
		return err
	}
	deployment := NewDeployment(workloadName, i.CaseBaseName, 1,
		map[string]string{"app": workloadName}, i.VeleroCfg.ImageRegistryProxy, i.VeleroCfg.WorkerOS).
		WithVolume(CreateVolumes(workloadName, []string{"volume"})).Result()
	if _, err := CreateDeployment(i.Client.ClientGo, i.CaseBaseName, deployment); err != nil {
		return err
	}
	if err := WaitForReadyDeployment(i.Client.ClientGo, i.CaseBaseName, workloadName); err != nil {
		return err
	}

	By("Generate random data and record its checksum before backup")
	script := "dd if=/dev/urandom of=/volume/data01 bs=1M count=128"
	if datamoverutil.IsVeleroFSDataMover(i.dataMover) && i.policy == "incremental" {
		script += " && dd if=/dev/urandom of=/volume/data02 bs=1M count=64"
	}
	if _, err := i.exec(script + " && sync"); err != nil {
		return err
	}
	var err error
	i.checksums, err = i.exec("sha256sum /volume/data*")
	return err
}

// Destroy deliberately keeps the namespace, PVC and PV for an in-place restore.
func (i *InplaceRestore) Destroy() error {
	return i.prepareRestore(false)
}

func (i *InplaceRestore) prepareRestore(deleteDeployment bool) error {
	By("Modify the data after backup and add a file absent from the backup")
	if i.dataMover == "velero-block" {
		if _, err := i.exec("dd if=/dev/urandom of=/volume/data01 bs=1M count=1 seek=32 conv=notrunc"); err != nil {
			return err
		}
	} else if i.policy == "incremental" {
		if _, err := i.exec("rm /volume/data02"); err != nil {
			return err
		}
	}
	if _, err := i.exec("echo a > /volume/a && sync"); err != nil {
		return err
	}

	if deleteDeployment {
		By("Delete the deployment and wait until all consuming pods are deleted")
		propagation := metav1.DeletePropagationForeground
		if err := i.Client.ClientGo.AppsV1().Deployments(i.CaseBaseName).Delete(i.Ctx, workloadName,
			metav1.DeleteOptions{PropagationPolicy: &propagation}); err != nil {
			return err
		}
	} else {
		By("Scale down the deployment and wait until all consuming pods are deleted")
		if err := i.scale(0); err != nil {
			return err
		}
	}
	if err := wait.PollUntilContextTimeout(i.Ctx, 2*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		pods, err := i.Client.ClientGo.CoreV1().Pods(i.CaseBaseName).List(ctx, metav1.ListOptions{})
		if err != nil || len(pods.Items) != 0 {
			return false, err
		}
		if deleteDeployment {
			_, err := i.Client.ClientGo.AppsV1().Deployments(i.CaseBaseName).Get(ctx, workloadName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return true, nil
	}); err != nil {
		return errors.Wrap(err, "wait for consuming pods to be deleted")
	}

	By("Record the original CSI volume handle")
	pv, err := i.boundPV()
	if err != nil {
		return err
	}
	i.volumeHandle = pv.Spec.CSI.VolumeHandle
	return nil
}

func (i *InplaceRestore) Verify() error {
	if err := i.verifyVolumeData(true); err != nil {
		return err
	}
	return i.verifyDescription()
}

func (i *InplaceRestore) verifyVolumeData(scaleUp bool) error {
	By("Verify the PVC binds to a PV with the original CSI volume handle")
	pv, err := i.boundPV()
	if err != nil {
		return err
	}
	Expect(pv.Spec.CSI.VolumeHandle).To(Equal(i.volumeHandle))

	if scaleUp {
		By("Scale up the workload")
		if err := i.scale(1); err != nil {
			return err
		}
	}
	By("Wait for the workload and verify restored file contents")
	if err := WaitForReadyDeployment(i.Client.ClientGo, i.CaseBaseName, workloadName); err != nil {
		return err
	}
	checksums, err := i.exec("sha256sum /volume/data*")
	if err != nil {
		return err
	}
	Expect(strings.TrimSpace(checksums)).To(Equal(strings.TrimSpace(i.checksums)))
	script := "test ! -e /volume/a"
	if datamoverutil.IsVeleroFSDataMover(i.dataMover) && i.policy == "full" {
		script = "test -f /volume/a && test \"$(cat /volume/a)\" = a"
	}
	if _, err := i.exec(script); err != nil {
		return errors.Wrap(err, "verify handling of the file added after backup")
	}
	return nil
}

func (i *InplaceRestore) exec(script string) (string, error) {
	stdout, _, err := KubectlExec(i.Ctx, "--namespace", i.CaseBaseName,
		"exec", "deployment/"+workloadName, "--", "sh", "-c", script)
	return stdout, err
}

func (i *InplaceRestore) scale(replicas int) error {
	_, _, err := KubectlExec(i.Ctx, "--namespace", i.CaseBaseName,
		"scale", "deployment/"+workloadName, fmt.Sprintf("--replicas=%d", replicas))
	return err
}

func (i *InplaceRestore) boundPV() (*corev1api.PersistentVolume, error) {
	pvc, err := GetPVC(i.Ctx, i.Client, i.CaseBaseName, workloadName)
	if err != nil {
		return nil, err
	}
	if pvc.Status.Phase != corev1api.ClaimBound || pvc.Spec.VolumeName == "" {
		return nil, errors.New("workload PVC is not bound")
	}
	pv, err := i.Client.ClientGo.CoreV1().PersistentVolumes().Get(i.Ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if pv.Spec.CSI == nil || pv.Spec.CSI.VolumeHandle == "" {
		return nil, errors.New("workload PV has no CSI volume handle")
	}
	return pv, nil
}

func (i *InplaceRestore) verifyDescription() error {
	By("Verify restore description reports the data mover, restore type and byte counts")
	cmd := exec.CommandContext(i.Ctx, i.VeleroCfg.VeleroCLI,
		"restore", "describe", i.RestoreName, "--namespace", i.VeleroCfg.VeleroNamespace,
		"--details", "--output", "json")
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrapf(err, "describe restore: %s", stderr)
	}
	fmt.Fprintln(GinkgoWriter, stdout)
	var description struct {
		CSISnapshotRestores map[string]struct {
			DataMovement struct {
				DataMover       string `json:"dataMover"`
				RestoreType     string `json:"restoreType"`
				Size            int64  `json:"size"`
				IncrementalSize *int64 `json:"incrementalSize"`
			} `json:"dataMovement"`
		} `json:"csiSnapshotRestores"`
	}
	if err := json.Unmarshal([]byte(stdout), &description); err != nil {
		return errors.Wrap(err, "decode restore description")
	}
	Expect(description.CSISnapshotRestores).To(HaveLen(1))
	entry, found := description.CSISnapshotRestores[i.CaseBaseName+"/"+workloadName]
	Expect(found).To(BeTrue(), "CSI snapshot restore description is missing the workload PVC")
	movement := entry.DataMovement
	Expect(movement.DataMover).To(Equal(i.dataMover))
	// Case is presentation dependent; a fallback suffix must still fail the check.
	Expect(strings.ToLower(movement.RestoreType)).To(Equal(i.policy))
	Expect(movement.IncrementalSize).NotTo(BeNil(), "incremental byte count must be reported")

	if i.dataMover == "velero-block" {
		Expect(movement.Size).To(Equal(256 * miB))
		if i.policy == "full" {
			Expect(*movement.IncrementalSize).To(Equal(movement.Size))
		} else {
			// The exact delta depends on CSI CBT granularity and filesystem metadata.
			Expect(*movement.IncrementalSize).To(BeNumerically(">", 0))
			Expect(*movement.IncrementalSize).To(BeNumerically("<", movement.Size))
		}
	} else {
		expected := 128 * miB
		if i.policy == "incremental" {
			// data01 is unchanged; only the deleted 64MiB data02 should transfer.
			expected = 64 * miB
		}
		Expect(movement.Size).To(Equal(expected))
		Expect(*movement.IncrementalSize).To(Equal(expected))
	}
	return nil
}
