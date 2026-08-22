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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

type RestoreHooksPolicy struct {
	TestCase
	nsContinue string
	nsFail     string
	podName    string
}

var RestoreHooksPolicyTest func() = test.TestFunc(&RestoreHooksPolicy{})

func (r *RestoreHooksPolicy) Init() error {
	Expect(r.TestCase.Init()).To(Succeed())
	r.CaseBaseName = "restore-hooks-policy-" + r.UUIDgen
	r.nsContinue = r.CaseBaseName + "-continue"
	r.nsFail = r.CaseBaseName + "-fail"
	r.podName = "hook-pod"
	r.BackupName = "backup-" + r.CaseBaseName
	r.RestoreName = "restore-" + r.CaseBaseName
	r.NamespacesTotal = 2
	r.NSIncluded = &[]string{r.nsContinue, r.nsFail}

	r.BackupArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "backup", r.BackupName,
		"--include-namespaces", fmt.Sprintf("%s,%s", r.nsContinue, r.nsFail),
		"--snapshot-volumes=false", "--wait",
	}

	r.TestMsg = &test.TestMSG{
		Desc:      "Restore hook error policy E2E test",
		Text:      "OnError: Continue should result in Completed, OnError: Fail should result in PartiallyFailed",
		FailedMSG: "Failed to validate restore hook error policies",
	}

	return nil
}

func (r *RestoreHooksPolicy) CreateResources() error {
	// 1. Create nsContinue namespace and a pod with failing hook (OnError: Continue)
	By(fmt.Sprintf("Creating namespace %s", r.nsContinue), func() {
		Expect(CreateNamespace(r.Ctx, r.Client, r.nsContinue)).To(Succeed())
	})

	annContinue := map[string]string{
		"post.hook.restore.velero.io/command":   `["/bin/sh", "-c", "exit 1"]`,
		"post.hook.restore.velero.io/container": r.podName,
		"post.hook.restore.velero.io/on-error":  "Continue",
	}

	By(fmt.Sprintf("Creating pod %s in namespace %s", r.podName, r.nsContinue), func() {
		_, err := CreatePod(
			r.Client,
			r.nsContinue,
			r.podName,
			"",
			"",
			[]string{},
			nil,
			annContinue,
			r.VeleroCfg.ImageRegistryProxy,
			r.VeleroCfg.WorkerOS,
		)
		Expect(err).To(Succeed())
	})

	// 2. Create nsFail namespace and a pod with failing hook (OnError: Fail)
	By(fmt.Sprintf("Creating namespace %s", r.nsFail), func() {
		Expect(CreateNamespace(r.Ctx, r.Client, r.nsFail)).To(Succeed())
	})

	annFail := map[string]string{
		"post.hook.restore.velero.io/command":   `["/bin/sh", "-c", "exit 1"]`,
		"post.hook.restore.velero.io/container": r.podName,
		"post.hook.restore.velero.io/on-error":  "Fail",
	}

	By(fmt.Sprintf("Creating pod %s in namespace %s", r.podName, r.nsFail), func() {
		_, err := CreatePod(
			r.Client,
			r.nsFail,
			r.podName,
			"",
			"",
			[]string{},
			nil,
			annFail,
			r.VeleroCfg.ImageRegistryProxy,
			r.VeleroCfg.WorkerOS,
		)
		Expect(err).To(Succeed())
	})

	// Wait for pods to be ready in both namespaces
	By("Waiting for pods to start running", func() {
		Expect(WaitForPods(r.Ctx, r.Client, r.nsContinue, []string{r.podName})).To(Succeed())
		Expect(WaitForPods(r.Ctx, r.Client, r.nsFail, []string{r.podName})).To(Succeed())
	})

	return nil
}

func (r *RestoreHooksPolicy) Destroy() error {
	By("Deleting target namespaces before restore", func() {
		Expect(CleanupNamespacesWithPoll(r.Ctx, r.Client, r.nsContinue)).To(Succeed())
		Expect(CleanupNamespacesWithPoll(r.Ctx, r.Client, r.nsFail)).To(Succeed())
	})
	return nil
}

func (r *RestoreHooksPolicy) Restore() error {
	// We override the standard restore behavior to perform two separate restores to verify each policy.

	// 1. Run restore for Continue namespace (expect Completed)
	restoreContinueName := r.RestoreName + "-continue"
	restoreContinueArgs := []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "restore", restoreContinueName,
		"--from-backup", r.BackupName, "--include-namespaces", r.nsContinue, "--wait",
	}
	By(fmt.Sprintf("Start to restore %s (OnError: Continue) and expect PartiallyFailed status", restoreContinueName), func() {
		Expect(VeleroRestoreExec(r.Ctx, r.VeleroCfg.VeleroCLI,
			r.VeleroCfg.VeleroNamespace, restoreContinueName,
			restoreContinueArgs, velerov1api.RestorePhasePartiallyFailed)).To(Succeed(), func() string {
			RunDebug(context.Background(), r.VeleroCfg.VeleroCLI, r.VeleroCfg.VeleroNamespace, "", restoreContinueName)
			return "Failed to restore Continue namespace with PartiallyFailed status"
		})
	})

	// 2. Run restore for Fail namespace (expect PartiallyFailed)
	restoreFailName := r.RestoreName + "-fail"
	restoreFailArgs := []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "restore", restoreFailName,
		"--from-backup", r.BackupName, "--include-namespaces", r.nsFail, "--wait",
	}
	By(fmt.Sprintf("Start to restore %s (OnError: Fail) and expect PartiallyFailed status", restoreFailName), func() {
		Expect(VeleroRestoreExec(r.Ctx, r.VeleroCfg.VeleroCLI,
			r.VeleroCfg.VeleroNamespace, restoreFailName,
			restoreFailArgs, velerov1api.RestorePhasePartiallyFailed)).To(Succeed(), func() string {
			RunDebug(context.Background(), r.VeleroCfg.VeleroCLI, r.VeleroCfg.VeleroNamespace, "", restoreFailName)
			return "Failed to restore Fail namespace with PartiallyFailed status"
		})
	})

	return nil
}

func (r *RestoreHooksPolicy) Verify() error {
	// Verify pods are running in both namespaces post-restore
	By("Verifying pods are restored and running", func() {
		Expect(WaitForPods(r.Ctx, r.Client, r.nsContinue, []string{r.podName})).To(Succeed())
		Expect(WaitForPods(r.Ctx, r.Client, r.nsFail, []string{r.podName})).To(Succeed())
	})
	return nil
}

func (r *RestoreHooksPolicy) Clean() error {
	return r.TestCase.Clean()
}
