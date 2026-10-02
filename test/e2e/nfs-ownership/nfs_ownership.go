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

// Package nfsownership reproduces https://github.com/velero-io/velero/issues/10040:
// fs-backup (kopia) restore silently loses file ownership on NFS exports that
// squash root. The node-agent data path runs as root, the export squashes it to
// the anonymous uid, so kopia's post-create os.Chown to the original UID fails
// with EPERM — which is silently swallowed because pkg/uploader/kopia/snapshot.go
// hardcodes IgnorePermissionErrors: true. The restore reports Completed while
// every restored file is owned by the anonymous uid instead of the original one.
//
// This test asserts that ownership IS preserved, so it fails on current main by
// design; it goes green once the swallowed permission errors are surfaced or
// ownership restore is made to work/fail loudly.
package nfsownership

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

const (
	// The UID the workload writes files as. Must differ from the NFS anonymous
	// uid (65534) that root gets squashed to, or the bug would be masked.
	workloadUID = 1001

	ganeshaManifest = "../testdata/nfs-ownership/nfs-ganesha.yaml"
	ganeshaNS       = "nfs-ownership-ganesha"
	storageClass    = "nfs-rootsquash-e2e"
	podName         = "writer"
	pvcName         = "data"
)

// Files created by the workload before backup; ownership of each is verified
// after restore.
var dataFiles = []string{"/data/apps/a.txt", "/data/caslibs/b.txt"}

type NFSOwnership struct {
	TestCase
}

var NFSOwnershipTest func() = TestFunc(&NFSOwnership{})

func (n *NFSOwnership) Init() error {
	n.TestCase.Init()
	n.CaseBaseName = "nfs-ownership-" + n.UUIDgen
	n.BackupName = "backup-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName
	n.VeleroCfg.UseVolumeSnapshots = false
	n.VeleroCfg.UseNodeAgent = true
	n.NSIncluded = &[]string{n.CaseBaseName}

	n.TestMsg = &TestMSG{
		Desc:      "Restore of fs-backup preserves file ownership on root-squashing NFS",
		FailedMSG: "Restored files lost their original ownership (see https://github.com/velero-io/velero/issues/10040)",
		Text:      fmt.Sprintf("Files owned by uid %d should keep that ownership after fs-backup restore from a root-squashing NFS volume", workloadUID),
	}

	n.BackupArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "backup", n.BackupName,
		"--include-namespaces", n.CaseBaseName,
		"--snapshot-volumes=false", "--default-volumes-to-fs-backup", "--wait",
	}
	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore", n.RestoreName,
		"--from-backup", n.BackupName, "--wait",
	}
	return nil
}

func (n *NFSOwnership) CreateResources() error {
	workloadNS := n.CaseBaseName

	By("Deploy in-cluster NFS-Ganesha server with a root-squashing StorageClass", func() {
		Expect(KubectlApplyByFile(n.Ctx, ganeshaManifest)).To(Succeed())
		Expect(waitDeploymentAvailable(n.Ctx, ganeshaNS, "nfs-provisioner")).To(Succeed())
	})

	By(fmt.Sprintf("Create workload namespace %s with a uid-%d writer pod on the NFS PVC", workloadNS, workloadUID), func() {
		Expect(CreateNamespace(n.Ctx, n.Client, workloadNS)).To(Succeed())
		Expect(n.applyWorkload(workloadNS)).To(Succeed())
		Expect(WaitForPods(n.Ctx, n.Client, workloadNS, []string{podName})).To(Succeed())
	})

	By(fmt.Sprintf("Verify pre-backup ownership of %v is uid %d", dataFiles, workloadUID), func() {
		for _, f := range dataFiles {
			uid, err := fileUID(n.Ctx, workloadNS, podName, f)
			Expect(err).To(Succeed())
			Expect(uid).To(Equal(strconv.Itoa(workloadUID)),
				"pre-backup file %s should be owned by the workload uid; test setup is broken otherwise", f)
		}
	})
	return nil
}

func (n *NFSOwnership) Verify() error {
	workloadNS := n.CaseBaseName

	By("Wait for the restored workload pod to be ready", func() {
		Expect(WaitForPods(n.Ctx, n.Client, workloadNS, []string{podName})).To(Succeed())
	})

	By(fmt.Sprintf("Verify restored files kept ownership uid %d", workloadUID), func() {
		for _, f := range dataFiles {
			uid, err := fileUID(n.Ctx, workloadNS, podName, f)
			Expect(err).To(Succeed())
			Expect(uid).To(Equal(strconv.Itoa(workloadUID)),
				"restored file %s is owned by uid %s instead of the original uid %d: "+
					"the kopia restore's chown failed on the root-squashing NFS export and the "+
					"EPERM was silently swallowed (IgnorePermissionErrors is hardcoded true in "+
					"pkg/uploader/kopia/snapshot.go) while the restore reported success — "+
					"https://github.com/velero-io/velero/issues/10040", f, uid, workloadUID)
		}
	})
	return nil
}

func (n *NFSOwnership) Clean() error {
	cleanErr := n.TestCase.Clean()
	var ganeshaErr error
	By("Remove the NFS-Ganesha server and StorageClass", func() {
		ganeshaErr = KubectlDeleteByFile(n.Ctx, ganeshaManifest)
	})
	if cleanErr != nil || ganeshaErr != nil {
		return errors.Join(cleanErr, ganeshaErr)
	}
	return nil
}

// applyWorkload creates the PVC and the uid-1001 writer pod. The framework's
// CreatePod helper is unusable here: it hardcodes RunAsUser/FSGroup 65534,
// which is exactly the anonymous uid root gets squashed to and would mask the
// bug.
func (n *NFSOwnership) applyWorkload(ns string) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  accessModes:
  - ReadWriteMany
  storageClassName: %[3]s
  resources:
    requests:
      storage: 100Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: %[4]s
  namespace: %[2]s
spec:
  securityContext:
    runAsUser: %[5]d
    runAsGroup: %[5]d
    fsGroup: %[5]d
  containers:
  - name: app
    image: busybox:1.36
    command:
    - sh
    - -c
    - |
      mkdir -p /data/apps /data/caslibs
      echo hello-apps > /data/apps/a.txt
      echo hello-caslibs > /data/caslibs/b.txt
      ls -lnR /data
      sleep 3600
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: %[1]s
`, pvcName, ns, storageClass, podName, workloadUID)

	file, err := os.CreateTemp("", "nfs-ownership-workload-*.yaml")
	if err != nil {
		return errors.Wrap(err, "failed to create temp workload manifest")
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(manifest); err != nil {
		file.Close()
		return errors.Wrap(err, "failed to write workload manifest")
	}
	file.Close()
	return KubectlApplyByFile(n.Ctx, filepath.Clean(file.Name()))
}

// fileUID returns the numeric owner uid of path inside the pod.
func fileUID(ctx context.Context, namespace, pod, path string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl",
		"exec", "-n", namespace, "-c", "app", pod, "--", "stat", "-c", "%u", path)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return "", errors.Wrapf(err, "failed to stat %s in %s/%s: %s", path, namespace, pod, stderr)
	}
	return strings.TrimSpace(stdout), nil
}

// waitDeploymentAvailable blocks until the named deployment reports Available.
func waitDeploymentAvailable(ctx context.Context, namespace, name string) error {
	cmd := exec.CommandContext(ctx, "kubectl",
		"wait", "--for=condition=Available", "-n", namespace,
		"deployment/"+name, "--timeout=180s")
	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrapf(err, "deployment %s/%s not available: %s", namespace, name, stderr)
	}
	return nil
}
