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
	"fmt"
	"path"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/velero-io/velero/test/e2e/test"
	. "github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/common"
	. "github.com/velero-io/velero/test/util/k8s"
)

// RestoreExecHooks tests that a pod with multiple restore exec hooks does not hang
// at the Finalizing phase during restore (Issue #9359 / PR #9366).
type RestoreExecHooks struct {
	TestCase
	podName string
}

var RestoreExecHooksTest func() = test.TestFunc(&RestoreExecHooks{})

func (r *RestoreExecHooks) Init() error {
	Expect(r.TestCase.Init()).To(Succeed())
	r.CaseBaseName = "restore-exec-hooks-" + r.UUIDgen
	r.BackupName = "backup-" + r.CaseBaseName
	r.RestoreName = "restore-" + r.CaseBaseName
	r.podName = "pod-multiple-hooks"
	r.NamespacesTotal = 1
	r.NSIncluded = &[]string{}

	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)
		*r.NSIncluded = append(*r.NSIncluded, createNSName)
	}

	r.TestMsg = &test.TestMSG{
		Desc:      "Restore pod with multiple restore exec hooks",
		Text:      "Should successfully backup and restore without hanging at Finalizing phase",
		FailedMSG: "Failed to successfully backup and restore pod with multiple hooks",
	}

	r.BackupArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "backup", r.BackupName,
		"--include-namespaces", strings.Join(*r.NSIncluded, ","),
		"--default-volumes-to-fs-backup", "--wait",
	}

	r.RestoreArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "restore", r.RestoreName,
		"--from-backup", r.BackupName, "--wait",
	}

	return nil
}

func (r *RestoreExecHooks) CreateResources() error {
	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)

		By(fmt.Sprintf("Creating namespace %s", createNSName), func() {
			Expect(CreateNamespace(r.Ctx, r.Client, createNSName)).
				To(Succeed(), fmt.Sprintf("Failed to create namespace %s", createNSName))
		})

		// Prepare images and commands adaptively for the target OS
		imageAddress := LinuxTestImage
		initCommand := `["/bin/sh", "-c", "echo init-hook-done"]`
		execCommand1 := `["/bin/sh", "-c", "echo hook1"]`
		execCommand2 := `["/bin/sh", "-c", "echo hook2"]`

		if r.VeleroCfg.WorkerOS == common.WorkerOSLinux && r.VeleroCfg.ImageRegistryProxy != "" {
			imageAddress = path.Join(r.VeleroCfg.ImageRegistryProxy, LinuxTestImage)
		} else if r.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			imageAddress = WindowTestImage
			initCommand = `["cmd", "/c", "echo init-hook-done"]`
			execCommand1 = `["cmd", "/c", "echo hook1"]`
			execCommand2 = `["cmd", "/c", "echo hook2"]`
		}

		// Inject mixing InitContainer hook and multiple Exec post-restore hooks.
		// This guarantees that the loop index 'i' mismatched 'hook.hookIndex' (Issue #9359),
		// ensuring the bug is properly reproduced and the fix is verified.
		ann := map[string]string{
			// Inject InitContainer Restore Hook
			"init.hook.restore.velero.io/container-image": imageAddress,
			"init.hook.restore.velero.io/container-name":  "test-init-hook",
			"init.hook.restore.velero.io/command":         initCommand,

			// Inject multiple Exec Restore Hooks
			"post.hook.restore.velero.io/test1.command":   execCommand1,
			"post.hook.restore.velero.io/test1.container": r.podName,
			"post.hook.restore.velero.io/test2.command":   execCommand2,
			"post.hook.restore.velero.io/test2.container": r.podName,
		}

		By(fmt.Sprintf("Creating pod %s with multiple restore hooks in namespace %s", r.podName, createNSName), func() {
			_, err := CreatePod(
				r.Client,
				createNSName,
				r.podName,
				"",         // No storage class needed
				"",         // No PVC needed
				[]string{}, // No volumes
				nil,
				ann,
				r.VeleroCfg.ImageRegistryProxy,
				r.VeleroCfg.WorkerOS,
			)
			Expect(err).To(Succeed(), fmt.Sprintf("Failed to create pod with hooks in namespace %s", createNSName))
		})

		By(fmt.Sprintf("Waiting for pod %s to be ready", r.podName), func() {
			err := WaitForPods(r.Ctx, r.Client, createNSName, []string{r.podName})
			Expect(err).To(Succeed(), fmt.Sprintf("Failed to wait for pod %s in namespace %s", r.podName, createNSName))
		})
	}
	return nil
}

func (r *RestoreExecHooks) Verify() error {
	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)

		By(fmt.Sprintf("Verifying pod %s in namespace %s after restore", r.podName, createNSName), func() {
			err := WaitForPods(r.Ctx, r.Client, createNSName, []string{r.podName})
			Expect(err).To(Succeed(), fmt.Sprintf("Failed to verify pod %s in namespace %s after restore", r.podName, createNSName))
		})
	}
	return nil
}
