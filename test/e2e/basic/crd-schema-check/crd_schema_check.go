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
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	. "github.com/vmware-tanzu/velero/test"
)

var veleroCfg VeleroConfig

const (
	crdSchemaCheckCRDName   = "serverstatusrequests.velero.io"
	crdSchemaCheckFieldPath = "/spec/versions/0/schema/openAPIV3Schema/properties/status/properties/serverVersion"
	crdSchemaCheckFlag      = "--crd-schema-check="

	// backuprepositories.velero.io is used here (rather than backups.velero.io) because it isn't
	// touched by concurrently-run E2E tests: mutating and restoring the schema of a CRD that other
	// tests actively create/read (like Backup) risks racing with their real backup/restore calls.
	crdSchemaCheckSpecCRDName   = "backuprepositories.velero.io"
	crdSchemaCheckSpecFieldPath = "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/backupStorageLocation"

	crdSchemaCheckLogMismatch = "CRD schema mismatch detected"
	crdSchemaCheckLogRunning  = "Validating CRD schemas match server expectations"
	crdSchemaCheckLogSuccess  = "All CRD schemas match server expectations"
)

// crdSchemaMutation records a single field removed from a CRD's schema by removeCRDSchemaProperty,
// so it can be restored independently of any other mutation made in the same test.
type crdSchemaMutation struct {
	crdName       string
	fieldPath     string
	originalValue json.RawMessage
}

// CRDSchemaCheckTest exercises the --crd-schema-check server flag (warn/strict/skip) by
// temporarily removing a known field from an installed CRD's schema and verifying the
// resulting velero server behavior and log output for each mode.
func CRDSchemaCheckTest() {
	var (
		ctx          context.Context
		cancel       context.CancelFunc
		ns           string
		originalArgs []string
		mutations    []crdSchemaMutation
		argsMutated  bool
	)

	removeAndTrack := func(crdName, path string) {
		orig, err := removeCRDSchemaProperty(ctx, crdName, path)
		// Track whenever we have an original value to restore, even if the patch call itself
		// errored — the underlying kubectl patch may have landed despite a client-observed
		// error, and skipping the tracking here would leave AfterEach unaware it needs to
		// restore a CRD schema that's actually been mutated.
		if orig != nil {
			mutations = append(mutations, crdSchemaMutation{crdName: crdName, fieldPath: path, originalValue: orig})
		}
		Expect(err).ShouldNot(HaveOccurred())
	}

	BeforeEach(func() {
		veleroCfg = VeleroCfg
		ctx, cancel = context.WithTimeout(context.Background(), 15*time.Minute)
		ns = veleroCfg.VeleroNamespace
		mutations = nil
		argsMutated = false

		var err error
		originalArgs, err = getVeleroContainerArgs(ctx, ns)
		Expect(err).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		cancel()
		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
			return
		}

		// Each restore step is attempted independently (rather than aborting on the first
		// failure via Expect(...).To(Succeed())) so that a failure restoring a CRD schema
		// doesn't leave the shared velero Deployment stuck with a test-only --crd-schema-check
		// arg for the rest of the suite run, and vice versa.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cleanupCancel()

		var cleanupErrs []error
		crdMutated := len(mutations) > 0
		if crdMutated {
			By("Restoring original CRD schema(s)", func() {
				for _, m := range mutations {
					if err := restoreCRDSchemaProperty(cleanupCtx, m.crdName, m.fieldPath, m.originalValue); err != nil {
						cleanupErrs = append(cleanupErrs, err)
					}
				}
			})
		}
		if argsMutated {
			By("Restoring original velero deployment args", func() {
				if err := setVeleroContainerArgs(cleanupCtx, ns, originalArgs); err != nil {
					cleanupErrs = append(cleanupErrs, err)
				} else if err := waitForVeleroRollout(cleanupCtx, ns, 3*time.Minute); err != nil {
					cleanupErrs = append(cleanupErrs, err)
				}
			})
		} else if crdMutated {
			// Args were left alone, so the running pod never re-validated against the restored
			// schema. Restart so the next test starts from a clean, settled pod.
			By("Restarting velero deployment to pick up restored CRD schema(s)", func() {
				if err := restartVeleroDeployment(cleanupCtx, ns); err != nil {
					cleanupErrs = append(cleanupErrs, err)
				} else if err := waitForVeleroRollout(cleanupCtx, ns, 3*time.Minute); err != nil {
					cleanupErrs = append(cleanupErrs, err)
				}
			})
		}
		Expect(cleanupErrs).To(BeEmpty())
	})

	It("should log a warning and keep running when the CRD schema mismatches in warn mode", func() {
		By("Removing status.serverVersion from the CRD schema", func() {
			removeAndTrack(crdSchemaCheckCRDName, crdSchemaCheckFieldPath)
		})

		By(fmt.Sprintf("Setting velero deployment args to include %swarn", crdSchemaCheckFlag), func() {
			err := setVeleroContainerArgs(ctx, ns, append(originalArgs, crdSchemaCheckFlag+"warn"))
			argsMutated = true
			Expect(err).To(Succeed())
		})

		By("Waiting for the velero deployment to roll out successfully despite the schema mismatch", func() {
			Expect(waitForVeleroRollout(ctx, ns, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs contain the CRD schema mismatch warning", func() {
			podName, err := getVeleroPodName(ctx, ns)
			Expect(err).ShouldNot(HaveOccurred())
			logs, err := getPodLogs(ctx, ns, podName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring(crdSchemaCheckLogMismatch))
		})
	})

	It("should fail to start when the CRD schema mismatches in strict mode", func() {
		oldPods, err := listVeleroPodNames(ctx, ns)
		Expect(err).ShouldNot(HaveOccurred())

		By("Removing status.serverVersion from the CRD schema", func() {
			removeAndTrack(crdSchemaCheckCRDName, crdSchemaCheckFieldPath)
		})

		By(fmt.Sprintf("Setting velero deployment args to include %sstrict", crdSchemaCheckFlag), func() {
			err := setVeleroContainerArgs(ctx, ns, append(originalArgs, crdSchemaCheckFlag+"strict"))
			argsMutated = true
			Expect(err).To(Succeed())
		})

		var newPod string
		By("Waiting for a new velero pod to be created for the updated deployment", func() {
			newPod, err = waitForNewVeleroPod(ctx, ns, oldPods, 2*time.Minute)
			Expect(err).ShouldNot(HaveOccurred())
		})

		By("Waiting for the new velero pod to fail to start due to the schema mismatch", func() {
			Expect(waitForVeleroContainerFailure(ctx, ns, newPod, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs contain the CRD schema mismatch error", func() {
			logs, err := getPodLogs(ctx, ns, newPod)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring(crdSchemaCheckLogMismatch))
		})
	})

	It("should skip CRD schema validation entirely in skip mode", func() {
		By("Removing status.serverVersion from the CRD schema", func() {
			removeAndTrack(crdSchemaCheckCRDName, crdSchemaCheckFieldPath)
		})

		By(fmt.Sprintf("Setting velero deployment args to include %sskip", crdSchemaCheckFlag), func() {
			err := setVeleroContainerArgs(ctx, ns, append(originalArgs, crdSchemaCheckFlag+"skip"))
			argsMutated = true
			Expect(err).To(Succeed())
		})

		By("Waiting for the velero deployment to roll out successfully", func() {
			Expect(waitForVeleroRollout(ctx, ns, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs do not contain CRD schema validation messages", func() {
			podName, err := getVeleroPodName(ctx, ns)
			Expect(err).ShouldNot(HaveOccurred())
			logs, err := getPodLogs(ctx, ns, podName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).NotTo(ContainSubstring(crdSchemaCheckLogRunning))
		})
	})

	It("should fail to start when an invalid --crd-schema-check value is provided", func() {
		oldPods, err := listVeleroPodNames(ctx, ns)
		Expect(err).ShouldNot(HaveOccurred())

		By(fmt.Sprintf("Setting velero deployment args to include %sfoo", crdSchemaCheckFlag), func() {
			err := setVeleroContainerArgs(ctx, ns, append(originalArgs, crdSchemaCheckFlag+"foo"))
			argsMutated = true
			Expect(err).To(Succeed())
		})

		var newPod string
		By("Waiting for a new velero pod to be created for the updated deployment", func() {
			newPod, err = waitForNewVeleroPod(ctx, ns, oldPods, 2*time.Minute)
			Expect(err).ShouldNot(HaveOccurred())
		})

		By("Waiting for the new velero pod to fail to start due to the invalid flag value", func() {
			Expect(waitForVeleroContainerFailure(ctx, ns, newPod, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs contain the invalid value error", func() {
			logs, err := getPodLogs(ctx, ns, newPod)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring("invalid value"))
		})
	})

	It("should log a warning and keep running when the CRD schema mismatches in default mode", func() {
		By("Removing status.serverVersion from the CRD schema", func() {
			removeAndTrack(crdSchemaCheckCRDName, crdSchemaCheckFieldPath)
		})

		By("Restarting the velero deployment without changing its args", func() {
			Expect(restartVeleroDeployment(ctx, ns)).To(Succeed())
			Expect(waitForVeleroRollout(ctx, ns, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs contain the CRD schema mismatch warning", func() {
			podName, err := getVeleroPodName(ctx, ns)
			Expect(err).ShouldNot(HaveOccurred())
			logs, err := getPodLogs(ctx, ns, podName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring(crdSchemaCheckLogMismatch))
		})
	})

	It("should log success when CRD schemas are unmodified", func() {
		By("Restarting the velero deployment to capture a fresh validation run", func() {
			Expect(restartVeleroDeployment(ctx, ns)).To(Succeed())
			Expect(waitForVeleroRollout(ctx, ns, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs report success and no mismatch", func() {
			podName, err := getVeleroPodName(ctx, ns)
			Expect(err).ShouldNot(HaveOccurred())
			logs, err := getPodLogs(ctx, ns, podName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring(crdSchemaCheckLogSuccess))
			Expect(logs).NotTo(ContainSubstring(crdSchemaCheckLogMismatch))
		})
	})

	It("should log a warning and keep running when a spec field mismatches in warn mode", func() {
		By("Removing spec.backupStorageLocation from the backuprepositories CRD schema", func() {
			removeAndTrack(crdSchemaCheckSpecCRDName, crdSchemaCheckSpecFieldPath)
		})

		By(fmt.Sprintf("Setting velero deployment args to include %swarn", crdSchemaCheckFlag), func() {
			err := setVeleroContainerArgs(ctx, ns, append(originalArgs, crdSchemaCheckFlag+"warn"))
			argsMutated = true
			Expect(err).To(Succeed())
		})

		By("Waiting for the velero deployment to roll out successfully despite the schema mismatch", func() {
			Expect(waitForVeleroRollout(ctx, ns, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs contain the spec field CRD schema mismatch warning", func() {
			podName, err := getVeleroPodName(ctx, ns)
			Expect(err).ShouldNot(HaveOccurred())
			logs, err := getPodLogs(ctx, ns, podName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring(crdSchemaCheckLogMismatch))
			Expect(logs).To(ContainSubstring("backuprepositories.velero.io: spec.backupStorageLocation"))
		})
	})

	It("should fail to start when multiple CRDs have multiple missing fields in strict mode", func() {
		oldPods, err := listVeleroPodNames(ctx, ns)
		Expect(err).ShouldNot(HaveOccurred())

		By("Removing status.serverVersion from the serverstatusrequests CRD schema", func() {
			removeAndTrack(crdSchemaCheckCRDName, crdSchemaCheckFieldPath)
		})

		By("Removing spec.backupStorageLocation from the backuprepositories CRD schema", func() {
			removeAndTrack(crdSchemaCheckSpecCRDName, crdSchemaCheckSpecFieldPath)
		})

		By(fmt.Sprintf("Setting velero deployment args to include %sstrict", crdSchemaCheckFlag), func() {
			err := setVeleroContainerArgs(ctx, ns, append(originalArgs, crdSchemaCheckFlag+"strict"))
			argsMutated = true
			Expect(err).To(Succeed())
		})

		var newPod string
		By("Waiting for a new velero pod to be created for the updated deployment", func() {
			newPod, err = waitForNewVeleroPod(ctx, ns, oldPods, 2*time.Minute)
			Expect(err).ShouldNot(HaveOccurred())
		})

		By("Waiting for the new velero pod to fail to start due to the schema mismatches", func() {
			Expect(waitForVeleroContainerFailure(ctx, ns, newPod, 3*time.Minute)).To(Succeed())
		})

		By("Verifying the velero pod logs contain both CRD schema mismatches", func() {
			logs, err := getPodLogs(ctx, ns, newPod)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(logs).To(ContainSubstring("serverstatusrequests.velero.io: status.serverVersion"))
			Expect(logs).To(ContainSubstring("backuprepositories.velero.io: spec.backupStorageLocation"))
		})
	})
}

// getVeleroContainerArgs returns the current args of the "velero" container in the velero Deployment.
func getVeleroContainerArgs(ctx context.Context, ns string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "deployment", "velero", "-n", ns,
		"-o", `jsonpath={.spec.template.spec.containers[?(@.name=="velero")].args}`)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return nil, errors.Wrap(err, stderr)
	}
	var args []string
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return args, nil
	}
	if err := json.Unmarshal([]byte(stdout), &args); err != nil {
		return nil, errors.Wrapf(err, "parsing velero container args from %q", stdout)
	}
	return args, nil
}

// setVeleroContainerArgs replaces the args of the "velero" container in the velero Deployment.
func setVeleroContainerArgs(ctx context.Context, ns string, args []string) error {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return errors.Wrap(err, "marshaling velero container args")
	}
	patch := fmt.Sprintf(`{"spec":{"template":{"spec":{"containers":[{"name":"velero","args":%s}]}}}}`, argsJSON)
	cmd := exec.CommandContext(ctx, "kubectl", "patch", "deployment", "velero", "-n", ns,
		"--type=strategic", "-p", patch)
	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrap(err, stderr)
	}
	return nil
}

// getCRDSchemaProperty returns the raw JSON value at path within the CRD's spec.
func getCRDSchemaProperty(ctx context.Context, crdName, path string) (json.RawMessage, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "crd", crdName, "-o", "json")
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return nil, errors.Wrap(err, stderr)
	}
	return jsonPointerGet([]byte(stdout), path)
}

// jsonPointerGet resolves an RFC 6901 JSON Pointer against doc and returns the value found there.
func jsonPointerGet(doc []byte, pointer string) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return nil, errors.Wrap(err, "parsing document")
	}

	pointer = strings.TrimPrefix(pointer, "/")
	for _, tok := range strings.Split(pointer, "/") {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		switch node := v.(type) {
		case map[string]any:
			val, ok := node[tok]
			if !ok {
				return nil, errors.Errorf("path %q not found: missing key %q", pointer, tok)
			}
			v = val
		case []any:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, errors.Errorf("path %q not found: invalid index %q", pointer, tok)
			}
			v = node[idx]
		default:
			return nil, errors.Errorf("path %q not found: unexpected node type at %q", pointer, tok)
		}
	}
	return json.Marshal(v)
}

// removeCRDSchemaProperty removes the field at path from the CRD's (single-version) OpenAPI schema,
// returning the field's original value so it can be restored later via restoreCRDSchemaProperty. The
// original value is returned even when the patch call itself errors (e.g. a client-side timeout on a
// request that actually landed), so the caller can still track and restore it.
func removeCRDSchemaProperty(ctx context.Context, crdName, path string) (json.RawMessage, error) {
	orig, err := getCRDSchemaProperty(ctx, crdName, path)
	if err != nil {
		return nil, err
	}

	patch := fmt.Sprintf(`[{"op":"remove","path":"%s"}]`, path)
	cmd := exec.CommandContext(ctx, "kubectl", "patch", "crd", crdName, "--type=json", "-p", patch)
	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return orig, errors.Wrap(err, stderr)
	}
	return orig, nil
}

// restoreCRDSchemaProperty adds back the field at path to the CRD's (single-version) OpenAPI schema,
// using the original value captured by removeCRDSchemaProperty.
func restoreCRDSchemaProperty(ctx context.Context, crdName, path string, value json.RawMessage) error {
	patch := fmt.Sprintf(`[{"op":"add","path":"%s","value":%s}]`, path, value)
	cmd := exec.CommandContext(ctx, "kubectl", "patch", "crd", crdName, "--type=json", "-p", patch)
	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrap(err, stderr)
	}
	return nil
}

// restartVeleroDeployment triggers a rollout restart of the velero Deployment, forcing a fresh
// pod even when its container args are unchanged (e.g. to re-run CRD schema validation after the
// CRD schema itself was mutated/restored rather than the deployment's args).
func restartVeleroDeployment(ctx context.Context, ns string) error {
	cmd := exec.CommandContext(ctx, "kubectl", "rollout", "restart", "deployment/velero", "-n", ns)
	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrap(err, stderr)
	}
	return nil
}

// waitForVeleroRollout waits for the velero Deployment rollout to complete successfully, and for
// the resulting pod to reach its main run loop. The velero Deployment defines no readiness probe,
// so Kubernetes reports the pod Ready as soon as its container starts — well before
// --crd-schema-check validation and controller-runtime cache sync finish. Without the extra wait,
// a test elsewhere in the suite that immediately performs a real operation (e.g. creating a
// backup) can race ahead of a just-restarted server that isn't actually ready yet.
func waitForVeleroRollout(ctx context.Context, ns string, timeout time.Duration) error {
	cmd := exec.CommandContext(ctx, "kubectl", "rollout", "status", "deployment/velero",
		"-n", ns, fmt.Sprintf("--timeout=%s", timeout))
	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrap(err, stderr)
	}
	return waitForVeleroServerStarting(ctx, ns, timeout)
}

// waitForVeleroServerStarting polls the current velero pod's logs until the server has logged
// "Server starting..." (emitted just before the controller-runtime manager starts, after
// --crd-schema-check validation completes), or timeout elapses.
func waitForVeleroServerStarting(ctx context.Context, ns string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if podName, err := getVeleroPodName(ctx, ns); err == nil {
			if logs, err := getPodLogs(ctx, ns, podName); err == nil && strings.Contains(logs, "Server starting...") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return errors.Errorf("timed out waiting for velero server to start in namespace %s", ns)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// listVeleroPodNames returns the names of pods matching the velero Deployment's pod label selector.
func listVeleroPodNames(ctx context.Context, ns string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", ns, "-l", "deploy=velero",
		"-o", "jsonpath={.items[*].metadata.name}")
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return nil, errors.Wrap(err, stderr)
	}
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil, nil
	}
	return strings.Fields(stdout), nil
}

// getVeleroPodName returns the single Running velero pod name, for use once the deployment has
// settled on exactly one ready pod (e.g. after a successful rollout). It retries briefly because
// a terminating old-ReplicaSet pod can still report phase=Running for a few seconds after
// `kubectl rollout status` considers the rollout complete.
func getVeleroPodName(ctx context.Context, ns string) (string, error) {
	var lastErr error
	deadline := time.Now().Add(30 * time.Second)
	for {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-n", ns, "-l", "deploy=velero",
			"--field-selector=status.phase=Running",
			"-o", "jsonpath={.items[*].metadata.name}")
		stdout, stderr, err := veleroexec.RunCommand(cmd)
		if err != nil {
			lastErr = errors.Wrap(err, stderr)
		} else {
			pods := strings.Fields(strings.TrimSpace(stdout))
			if len(pods) == 1 {
				return pods[0], nil
			}
			lastErr = errors.Errorf("expected exactly one Running velero pod, found %d: %v", len(pods), pods)
		}

		if time.Now().After(deadline) {
			return "", lastErr
		}
		time.Sleep(2 * time.Second)
	}
}

// waitForNewVeleroPod polls until a velero pod appears whose name was not in oldPods, returning
// its name. This is needed because a Deployment update surges a new pod alongside the old one
// rather than replacing it in place when the new pod never becomes ready (as in strict mode).
func waitForNewVeleroPod(ctx context.Context, ns string, oldPods []string, timeout time.Duration) (string, error) {
	oldSet := make(map[string]bool, len(oldPods))
	for _, p := range oldPods {
		oldSet[p] = true
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pods, err := listVeleroPodNames(ctx, ns)
		if err == nil {
			for _, p := range pods {
				if !oldSet[p] {
					return p, nil
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	return "", errors.New("timed out waiting for a new velero pod to be created")
}

type containerStatusInfo struct {
	RestartCount int32 `json:"restartCount"`
	State        struct {
		Waiting *struct {
			Reason string `json:"reason"`
		} `json:"waiting"`
		Terminated *struct {
			ExitCode int32 `json:"exitCode"`
		} `json:"terminated"`
	} `json:"state"`
}

// veleroContainerFailed reports whether the named pod's "velero" container has failed to start:
// either it has already restarted, is waiting in a crash-loop backoff state, or its most recent
// run terminated with a non-zero exit code.
func veleroContainerFailed(ctx context.Context, ns, podName string) (bool, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "pod", podName, "-n", ns,
		"-o", `jsonpath={.status.containerStatuses[?(@.name=="velero")]}`)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return false, errors.Wrap(err, stderr)
	}
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return false, nil
	}

	var status containerStatusInfo
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		return false, errors.Wrapf(err, "parsing container status from %q", stdout)
	}

	if status.RestartCount > 0 {
		return true, nil
	}
	if status.State.Waiting != nil &&
		(status.State.Waiting.Reason == "CrashLoopBackOff" || status.State.Waiting.Reason == "Error") {
		return true, nil
	}
	if status.State.Terminated != nil && status.State.Terminated.ExitCode != 0 {
		return true, nil
	}
	return false, nil
}

// waitForVeleroContainerFailure polls until veleroContainerFailed reports true for podName.
func waitForVeleroContainerFailure(ctx context.Context, ns, podName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		failed, err := veleroContainerFailed(ctx, ns, podName)
		if err == nil && failed {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	return errors.Errorf("timed out waiting for velero pod %s to fail to start", podName)
}

// getPodLogs returns the current logs of the "velero" container in podName.
func getPodLogs(ctx context.Context, ns, podName string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "logs", podName, "-n", ns, "-c", "velero")
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return "", errors.Wrap(err, stderr)
	}
	return stdout, nil
}
