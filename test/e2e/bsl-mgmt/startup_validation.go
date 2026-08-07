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
	. "github.com/vmware-tanzu/velero/test/util/providers"
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

			originalHash := ""
			By("Verify BackupRepository exists and is Ready with the BSL config hash recorded", func() {
				repos, err := KubectlGetBackupRepository(ctx, "kopia", veleroCfg.VeleroNamespace)
				Expect(err).To(Succeed())
				Expect(repos).NotTo(BeEmpty(), "Expected at least one backup repository")

				Eventually(func() string {
					originalHash = kopiaRepoConfigHash(ctx, veleroCfg.VeleroNamespace, ns)
					return originalHash
				}, 2*time.Minute, 5*time.Second).ShouldNot(BeEmpty(),
					"BackupRepository should have the BSL config hash recorded")
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

			// Ensure Velero is scaled back up even if an assertion below fails
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cleanupCancel()
				cmd := exec.CommandContext(cleanupCtx, "kubectl", "scale", "deployment/velero",
					"-n", veleroCfg.VeleroNamespace, "--replicas=1")
				if output, err := cmd.CombinedOutput(); err != nil {
					fmt.Printf("warning: failed to scale velero back up: %s\n", string(output))
				}
			}()

			By("Wait for Velero pods to terminate", func() {
				Eventually(func() bool {
					cmd := exec.CommandContext(ctx, "kubectl", "get", "pods",
						"-n", veleroCfg.VeleroNamespace, "-l", "deploy=velero",
						"--no-headers")
					// only stdout: with zero pods kubectl exits 0 but prints
					// "No resources found ..." to stderr
					output, err := cmd.Output()
					if err != nil {
						fmt.Printf("failed to query velero pods: %v\n", err)
						return false
					}
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

			// Restore BSL prefix on exit so other tests aren't affected; purge objects
			// created under the temporary prefix first so the restored (possibly empty)
			// prefix passes the BSL store layout validation
			defer func() {
				restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer restoreCancel()
				cleanupObjectsUnderPrefix(veleroCfg, newPrefix)
				patchJSON := fmt.Sprintf(`{"spec":{"objectStorage":{"prefix":"%s"}}}`, originalPrefix)
				cmd := exec.CommandContext(restoreCtx, "kubectl", "patch",
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

			// The controller detects the prefix mismatch on reconciliation and invalidates the repo.
			// Verify the repo was marked NotReady with the BSL change message.
			By("Verify BackupRepository was invalidated on startup", func() {
				Eventually(func() string {
					cmd := exec.CommandContext(ctx, "kubectl", "get", "backuprepositories",
						"-n", veleroCfg.VeleroNamespace,
						"-l", kopiaRepoSelector(ns),
						"-o", "jsonpath={range .items[*]}{.status.phase}|{.status.message}{end}")
					output, err := cmd.Output()
					if err != nil {
						return ""
					}
					result := strings.TrimSpace(string(output))
					fmt.Printf("BackupRepo state: %s\n", result)
					// Accept either: still NotReady with our message, OR already recovered to Ready
					// (the controller re-establishes the repository right after invalidating it)
					if strings.Contains(result, "BSL config has changed") ||
						strings.Contains(result, string(velerov1api.BackupRepositoryPhaseReady)) {
						return result
					}
					return ""
				}, 5*time.Minute, 10*time.Second).ShouldNot(BeEmpty(),
					"BackupRepository should be invalidated or already recovered")
			})

			By("Verify BackupRepository recovers to Ready with an updated BSL config hash", func() {
				Eventually(func() bool {
					hash := kopiaRepoConfigHash(ctx, veleroCfg.VeleroNamespace, ns)
					phase := kopiaRepoPhase(ctx, veleroCfg.VeleroNamespace, ns)
					return hash != "" && hash != originalHash && phase == string(velerov1api.BackupRepositoryPhaseReady)
				}, 5*time.Minute, 10*time.Second).Should(BeTrue(),
					"BackupRepository should be Ready with a hash different from the original after the BSL prefix change")
			})

			By("Run another backup at the changed prefix", func() {
				backupCfg.BackupName = "startup-val-backup-2"
				Expect(VeleroBackupNamespace(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, backupCfg)).To(Succeed(), func() string {
					RunDebug(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, backupCfg.BackupName, "")
					return "Fail to backup workload after the BSL prefix change"
				})
			})

			By("Delete the backup created at the changed prefix while the BSL still points there", func() {
				Expect(DeleteBackup(ctx, backupCfg.BackupName, &veleroCfg)).To(Succeed())
			})

			By("Clean up repository data under the changed prefix", func() {
				cleanupObjectsUnderPrefix(veleroCfg, newPrefix)
			})

			By("Restore original BSL prefix", func() {
				patchJSON := fmt.Sprintf(`{"spec":{"objectStorage":{"prefix":"%s"}}}`, originalPrefix)
				cmd := exec.CommandContext(ctx, "kubectl", "patch",
					"backupstoragelocation/default",
					"-n", veleroCfg.VeleroNamespace,
					"--type=merge",
					"-p", patchJSON)
				output, err := cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("restore BSL output: %s\n", string(output))
				}
				Expect(err).To(Succeed())
			})

			By("Verify BackupRepository recovers to Ready", func() {
				Eventually(func() bool {
					return kopiaRepoPhase(ctx, veleroCfg.VeleroNamespace, ns) == string(velerov1api.BackupRepositoryPhaseReady)
				}, 5*time.Minute, 10*time.Second).Should(BeTrue(), "BackupRepository should recover to Ready")
			})

			By("Verify BSL config hash returns to the original after the prefix is restored", func() {
				Eventually(func() string {
					return kopiaRepoConfigHash(ctx, veleroCfg.VeleroNamespace, ns)
				}, 5*time.Minute, 10*time.Second).Should(Equal(originalHash),
					"BackupRepository hash should match the original once the BSL prefix is restored")
			})
		})
	})
}

// kopiaRepoSelector returns a label selector matching the kopia BackupRepository for
// the given volume namespace.
func kopiaRepoSelector(volumeNamespace string) string {
	return fmt.Sprintf("%s=%s,%s=%s",
		velerov1api.VolumeNamespaceLabel, volumeNamespace,
		velerov1api.RepositoryTypeLabel, velerov1api.BackupRepositoryTypeKopia)
}

// cleanupObjectsUnderPrefix removes the velero store layout directories created under a
// temporary BSL prefix. Without this, restoring the original (possibly empty) prefix
// leaves unknown top-level directories in the bucket that fail the BSL's store layout
// validation and turn it Unavailable.
func cleanupObjectsUnderPrefix(veleroCfg VeleroConfig, prefix string) {
	for _, dir := range []string{"backups", "restores", "kopia", "restic", "metadata", "plugins"} {
		if err := DeleteObjectsInBucket(veleroCfg.ObjectStoreProvider, veleroCfg.CloudCredentialsFile,
			veleroCfg.BSLBucket, prefix, veleroCfg.BSLConfig, dir, ""); err != nil {
			fmt.Printf("cleanup of %s/%s from object store: %v\n", prefix, dir, err)
		}
	}
}

// kopiaRepoConfigHash returns the BSL config hash annotation of the kopia BackupRepository
// for the given volume namespace, or an empty string if it is not (yet) set.
func kopiaRepoConfigHash(ctx context.Context, namespace, volumeNamespace string) string {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "backuprepositories",
		"-n", namespace,
		"-l", kopiaRepoSelector(volumeNamespace),
		"-o", `jsonpath={.items[*].metadata.annotations.velero\.io/bsl-config-hash}`)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("failed to get repo config hash: %v\n", err)
		return ""
	}
	return strings.TrimSpace(string(output))
}

// kopiaRepoPhase returns the phase of the kopia BackupRepository for the given volume
// namespace, or an empty string if it cannot be determined.
func kopiaRepoPhase(ctx context.Context, namespace, volumeNamespace string) string {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "backuprepositories",
		"-n", namespace,
		"-l", kopiaRepoSelector(volumeNamespace),
		"-o", "jsonpath={.items[*].status.phase}")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("failed to get repo phase: %v\n", err)
		return ""
	}
	return strings.TrimSpace(string(output))
}
