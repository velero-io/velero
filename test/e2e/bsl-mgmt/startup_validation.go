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
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

func BackupRepoStartupValidationTest() {
	var veleroCfg VeleroConfig
	veleroCfg = VeleroCfg

	BeforeEach(func() {
		if InstallVelero {
			Expect(PrepareVelero(context.Background(), "BackupRepo Startup Validation", veleroCfg)).To(Succeed())
		}
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() || !veleroCfg.FailFast {
			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
		}
	})

	When("BSL prefix changes while Velero is not running", func() {
		It("should invalidate stale BackupRepositories on startup and recover", func() {
			ctx, ctxCancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer ctxCancel()

			ns := "startup-validation"
			By("Create test namespace", func() {
				Expect(CreateNamespace(ctx, *veleroCfg.ClientToInstallVelero, ns)).To(Succeed())
			})
			defer func() {
				_ = DeleteNamespace(context.Background(), *veleroCfg.ClientToInstallVelero, ns, true)
			}()

			podName := "startup-val-pod"
			By("Create a pod with PVC so FSBackup creates a BackupRepository", func() {
				_, err := CreatePod(
					*veleroCfg.ClientToInstallVelero,
					ns, podName, "", "",
					[]string{"startup-val-vol"},
					nil, nil,
					veleroCfg.ImageRegistryProxy,
					"",
				)
				Expect(err).To(Succeed())
			})

			By("Wait for pod to be running", func() {
				Expect(WaitForPods(ctx, *veleroCfg.ClientToInstallVelero, ns, []string{podName})).To(Succeed())
			})

			backupCfg := BackupConfig{
				BackupName:               "startup-val-backup",
				Namespace:                ns,
				BackupLocation:           "default",
				DefaultVolumesToFsBackup: true,
				UseVolumeSnapshots:       false,
			}

			By("Create a kopia backup to establish BackupRepository", func() {
				Expect(VeleroBackupNamespace(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, backupCfg)).To(Succeed(), func() string {
					RunDebug(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, backupCfg.BackupName, "")
					return "Fail to backup workload"
				})
			})

			By("Verify BackupRepository exists and is Ready", func() {
				repos, err := KubectlGetBackupRepository(ctx, "kopia", veleroCfg.VeleroNamespace)
				Expect(err).To(Succeed())
				Expect(repos).NotTo(BeEmpty(), "Expected at least one backup repository")
			})

			By("Scale down Velero deployment to 0", func() {
				cmd := exec.CommandContext(ctx, "kubectl", "scale", "deployment/velero",
					"-n", veleroCfg.VeleroNamespace, "--replicas=0")
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("scale down output: %s\n", string(output))
				}
				Expect(err).To(Succeed())
			})

			By("Wait for Velero pods to terminate", func() {
				Eventually(func() bool {
					cmd := exec.CommandContext(ctx, "kubectl", "get", "pods",
						"-n", veleroCfg.VeleroNamespace, "-l", "deploy=velero",
						"--no-headers")
					output, _ := cmd.Output()
					lines := strings.TrimSpace(string(output))
					if lines == "" {
						return true
					}
					fmt.Printf("Still waiting for velero pods to terminate: %s\n", lines)
					return false
				}, 5*time.Minute, 10*time.Second).Should(BeTrue(), "Velero pod should terminate")
			})

			originalPrefix := veleroCfg.BSLPrefix
			newPrefix := originalPrefix + "-changed"

			// Restore BSL prefix on exit so other tests aren't affected
			defer func() {
				patchJSON := fmt.Sprintf(`{"spec":{"objectStorage":{"prefix":"%s"}}}`, originalPrefix)
				cmd := exec.CommandContext(context.Background(), "kubectl", "patch",
					"backupstoragelocation/default",
					"-n", veleroCfg.VeleroNamespace,
					"--type=merge",
					"-p", patchJSON)
				if output, err := cmd.CombinedOutput(); err != nil {
					fmt.Printf("warning: failed to restore BSL prefix: %s\n", string(output))
				}
			}()

			By(fmt.Sprintf("Patch BSL prefix from %q to %q while Velero is down", originalPrefix, newPrefix), func() {
				patchJSON := fmt.Sprintf(`{"spec":{"objectStorage":{"prefix":"%s"}}}`, newPrefix)
				cmd := exec.CommandContext(ctx, "kubectl", "patch",
					"backupstoragelocation/default",
					"-n", veleroCfg.VeleroNamespace,
					"--type=merge",
					"-p", patchJSON)
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("patch BSL output: %s\n", string(output))
				}
				Expect(err).To(Succeed())
			})

			By("Scale Velero deployment back to 1", func() {
				cmd := exec.CommandContext(ctx, "kubectl", "scale", "deployment/velero",
					"-n", veleroCfg.VeleroNamespace, "--replicas=1")
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("scale up output: %s\n", string(output))
				}
				Expect(err).To(Succeed())
			})

			By("Wait for Velero pod to be ready", func() {
				Eventually(func() bool {
					cmd := exec.CommandContext(ctx, "kubectl", "get", "deployment/velero",
						"-n", veleroCfg.VeleroNamespace,
						"-o", "jsonpath={.status.readyReplicas}")
					output, err := cmd.Output()
					if err != nil {
						return false
					}
					return strings.TrimSpace(string(output)) == "1"
				}, 3*time.Minute, 5*time.Second).Should(BeTrue(), "Velero deployment should have 1 ready replica")
			})

			// Startup validation invalidates the repo, then checkNotReadyRepo re-establishes it
			// with the new BSL config. The repo may go NotReady -> Ready very quickly, so instead
			// of trying to catch the transient NotReady state, verify the end result: repo is Ready
			// and its BSL prefix annotation matches the NEW prefix (proving invalidation + re-establishment).
			By("Verify BackupRepository was invalidated and re-established with new BSL prefix", func() {
				Eventually(func() string {
					cmd := exec.CommandContext(ctx, "kubectl", "get", "backuprepositories",
						"-n", veleroCfg.VeleroNamespace,
						"-o", fmt.Sprintf("jsonpath={.items[?(@.spec.repositoryType=='%s')].metadata.annotations.velero\\.io/bsl-prefix}", velerov1api.BackupRepositoryTypeKopia))
					output, err := cmd.Output()
					if err != nil {
						return ""
					}
					return strings.TrimSpace(string(output))
				}, 5*time.Minute, 10*time.Second).Should(Equal(newPrefix),
					fmt.Sprintf("BackupRepository BSL prefix annotation should be updated to %q", newPrefix))
			})

			By("Verify BackupRepository is Ready with new config", func() {
				cmd := exec.CommandContext(ctx, "kubectl", "get", "backuprepositories",
					"-n", veleroCfg.VeleroNamespace,
					"-o", fmt.Sprintf("jsonpath={.items[?(@.spec.repositoryType=='%s')].status.phase}", velerov1api.BackupRepositoryTypeKopia))
				output, err := cmd.Output()
				Expect(err).To(Succeed())
				Expect(string(output)).To(ContainSubstring(string(velerov1api.BackupRepositoryPhaseReady)))
			})
		})
	})
}
