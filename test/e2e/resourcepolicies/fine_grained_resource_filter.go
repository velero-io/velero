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

package resourcepolicies

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	. "github.com/velero-io/velero/test/e2e/test"
	. "github.com/velero-io/velero/test/util/k8s"
	. "github.com/velero-io/velero/test/util/velero"
)

// backupDescribeDetailsOutput captures the structured output of `velero backup describe --details -o json`
type backupDescribeDetailsOutput struct {
	Status struct {
		ResourceList map[string][]string `json:"resourceList"`
	} `json:"status"`
}

// FineGrainedResourceFilter tests the end-to-end integration of fine-grained backup and restore
// filtering via ResourcePolicy within a single backup and restore workflow:
//
// 1. Backup-side filtering:
//   - includedNamespacesByLabel selects targeted namespaces; untargeted namespaces are excluded.
//   - Global resource filters (includedNamespaceScopedResources, excludedNamespaceScopedResources,
//     and includedClusterScopedResources) set global ceilings; global excluded kinds (Secret)
//     cannot be re-included by namespace policies.
//   - namespacedFilterPolicies enforces kind, label, name, and excludedNames filters per namespace.
//   - clusterScopedFilterPolicy enforces kind, label, name, and excludedNames filters for cluster-scoped resources.
//   - Backup verification is performed directly by inspecting the backed-up resources in the backup
//     manifest via `velero backup describe --details -o json`.
//
// 2. Restore-side filtering:
//   - RestoreSpec.ResourcePolicy specifies restore filter policies (namespacedFilterPolicies &
//     clusterScopedFilterPolicy).
//   - Restore verification verifies that items confirmed present in the backup archive are selectively
//     restored or excluded according to the restore filter policies.
type FineGrainedResourceFilter struct {
	TestCase
	backupCMName      string
	restoreCMName     string
	labelKey          string
	labelValue        string
	clusterLabelKey   string
	clusterLabelValue string
	targetedNS        string
	untargetedNS      string

	// ClusterRoles for backup and restore filter verification
	crBothIncluded          string
	crBackupDebug           string
	crBackupMismatchedLabel string
	crBackupUnmatchedName   string
	crRestoreDebug          string
	crRestoreMismatchedEnv  string
	clusterRoles            []string
}

var FineGrainedResourceFilterTest func() = TestFunc(&FineGrainedResourceFilter{})

func (f *FineGrainedResourceFilter) Init() error {
	Expect(f.TestCase.Init()).To(Succeed())

	f.CaseBaseName = "fg-filter-" + f.UUIDgen
	f.BackupName = "backup-" + f.CaseBaseName
	f.RestoreName = "restore-" + f.CaseBaseName
	f.backupCMName = "cm-backup-" + f.CaseBaseName
	f.restoreCMName = "cm-restore-" + f.CaseBaseName

	f.labelKey = "velero-e2e-selector"
	f.labelValue = "target-" + f.UUIDgen

	f.clusterLabelKey = "app"
	f.clusterLabelValue = "cluster-workload-" + f.UUIDgen

	f.targetedNS = f.CaseBaseName + "-targeted"
	f.untargetedNS = f.CaseBaseName + "-untargeted"

	f.crBothIncluded = fmt.Sprintf("cr-%s-both-included", f.UUIDgen)
	f.crBackupDebug = fmt.Sprintf("cr-%s-backup-debug", f.UUIDgen)
	f.crBackupMismatchedLabel = fmt.Sprintf("cr-%s-backup-mismatched-label", f.UUIDgen)
	f.crBackupUnmatchedName = fmt.Sprintf("other-%s-role", f.UUIDgen)
	f.crRestoreDebug = fmt.Sprintf("cr-%s-restore-debug", f.UUIDgen)
	f.crRestoreMismatchedEnv = fmt.Sprintf("cr-%s-restore-mismatched-env", f.UUIDgen)

	f.clusterRoles = []string{
		f.crBothIncluded,
		f.crBackupDebug,
		f.crBackupMismatchedLabel,
		f.crBackupUnmatchedName,
		f.crRestoreDebug,
		f.crRestoreMismatchedEnv,
	}

	f.TestMsg = &TestMSG{
		Desc:      "Integration test for fine-grained resource and restore filters via ResourcePolicy",
		Text:      "should correctly filter backup items and restore items using ResourcePolicy in a single backup and restore cycle",
		FailedMSG: "Failed to perform backup and restore with fine-grained resource filters",
	}

	// Restore command uses the restore ResourcePolicy ConfigMap
	f.RestoreArgs = []string{
		"create", "--namespace", f.VeleroCfg.VeleroNamespace, "restore", f.RestoreName,
		"--from-backup", f.BackupName,
		"--resource-policies-configmap", f.restoreCMName,
		"--wait",
	}

	return nil
}

func (f *FineGrainedResourceFilter) CreateResources() error {
	// 1. Create Backup ResourcePolicy ConfigMap
	backupPolicyYAML := fmt.Sprintf(`version: v1
includeExcludePolicy:
  includedNamespacesByLabel:
    - "%s=%s"
  includedNamespaceScopedResources:
    - "configmaps"
  excludedNamespaceScopedResources:
    - "secrets"
  includedClusterScopedResources:
    - "clusterroles"
clusterScopedFilterPolicy:
  resourceFilters:
    - kinds: ["ClusterRole"]
      labelSelector:
        matchLabels:
          %s: "%s"
      names: ["cr-%s-*"]
      excludedNames: ["*-backup-debug"]
namespacedFilterPolicies:
  - namespaces:
      - "%s"
    resourceFilters:
      - kinds: ["ConfigMap", "Secret"]
        labelSelector:
          matchLabels:
            app: test-workload
        names: ["app-*"]
        excludedNames: ["*-backup-debug"]
`, f.labelKey, f.labelValue, f.clusterLabelKey, f.clusterLabelValue, f.UUIDgen, f.targetedNS)

	By(fmt.Sprintf("Create backup ResourcePolicy ConfigMap %s in namespace %s\n", f.backupCMName, f.VeleroCfg.VeleroNamespace), func() {
		Expect(CreateConfigMapFromYAMLData(f.Client.ClientGo, backupPolicyYAML, f.backupCMName, f.VeleroCfg.VeleroNamespace)).To(Succeed())
	})
	By(fmt.Sprintf("Waiting for ConfigMap %s in namespace %s ready\n", f.backupCMName, f.VeleroCfg.VeleroNamespace), func() {
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.VeleroCfg.VeleroNamespace, f.backupCMName)).To(Succeed())
	})

	// 2. Create Restore ResourcePolicy ConfigMap
	// Filters applied at restore time:
	// - Requires env=production on ConfigMaps and ClusterRoles
	// - Excludes *-restore-debug
	restorePolicyYAML := fmt.Sprintf(`version: v1
clusterScopedFilterPolicy:
  resourceFilters:
    - kinds: ["ClusterRole"]
      labelSelector:
        matchLabels:
          env: "production"
      names: ["cr-%s-*"]
      excludedNames: ["*-restore-debug"]
namespacedFilterPolicies:
  - namespaces:
      - "%s"
    resourceFilters:
      - kinds: ["ConfigMap"]
        labelSelector:
          matchLabels:
            env: "production"
        names: ["app-*"]
        excludedNames: ["*-restore-debug"]
`, f.UUIDgen, f.targetedNS)

	By(fmt.Sprintf("Create restore ResourcePolicy ConfigMap %s in namespace %s\n", f.restoreCMName, f.VeleroCfg.VeleroNamespace), func() {
		Expect(CreateConfigMapFromYAMLData(f.Client.ClientGo, restorePolicyYAML, f.restoreCMName, f.VeleroCfg.VeleroNamespace)).To(Succeed())
	})
	By(fmt.Sprintf("Waiting for ConfigMap %s in namespace %s ready\n", f.restoreCMName, f.VeleroCfg.VeleroNamespace), func() {
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.VeleroCfg.VeleroNamespace, f.restoreCMName)).To(Succeed())
	})

	// 3. Create targeted namespace with label
	By(fmt.Sprintf("Create targeted namespace %s with label %s=%s\n", f.targetedNS, f.labelKey, f.labelValue), func() {
		Expect(CreateNamespaceWithLabel(f.Ctx, f.Client, f.targetedNS, map[string]string{f.labelKey: f.labelValue})).To(Succeed())
	})

	// Inside targeted namespace:
	// a. Both included: matches backup and restore criteria
	By("Create ConfigMap app-cfg-both-included in targeted namespace", func() {
		_, err := CreateConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-both-included",
			map[string]string{"app": "test-workload", "env": "production"}, map[string]string{"data": "retained"})
		Expect(err).To(Succeed())
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.targetedNS, "app-cfg-both-included")).To(Succeed())
	})

	// b. Excluded by backup name filter (*-backup-debug)
	By("Create ConfigMap app-cfg-backup-debug in targeted namespace", func() {
		_, err := CreateConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-backup-debug",
			map[string]string{"app": "test-workload", "env": "production"}, map[string]string{"data": "debug"})
		Expect(err).To(Succeed())
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.targetedNS, "app-cfg-backup-debug")).To(Succeed())
	})

	// c. Excluded by backup labelSelector (app=other)
	By("Create ConfigMap other-cfg in targeted namespace", func() {
		_, err := CreateConfigMap(f.Client.ClientGo, f.targetedNS, "other-cfg",
			map[string]string{"app": "other", "env": "production"}, map[string]string{"data": "other"})
		Expect(err).To(Succeed())
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.targetedNS, "other-cfg")).To(Succeed())
	})

	// d. Excluded by backup global resource filter (excludedNamespaceScopedResources: ["secrets"])
	By("Create Secret app-secret in targeted namespace", func() {
		_, err := CreateSecret(f.Client.ClientGo, f.targetedNS, "app-secret", map[string]string{"app": "test-workload"})
		Expect(err).To(Succeed())
		Expect(WaitForSecretsComplete(f.Client.ClientGo, f.targetedNS, "app-secret")).To(Succeed())
	})

	// e. Backed up, but to be excluded by restore name filter (*-restore-debug)
	By("Create ConfigMap app-cfg-restore-debug in targeted namespace", func() {
		_, err := CreateConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-restore-debug",
			map[string]string{"app": "test-workload", "env": "production"}, map[string]string{"data": "debug"})
		Expect(err).To(Succeed())
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.targetedNS, "app-cfg-restore-debug")).To(Succeed())
	})

	// f. Backed up, but to be excluded by restore labelSelector (env=staging != production)
	By("Create ConfigMap app-cfg-restore-mismatched-env in targeted namespace", func() {
		_, err := CreateConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-restore-mismatched-env",
			map[string]string{"app": "test-workload", "env": "staging"}, map[string]string{"data": "staging"})
		Expect(err).To(Succeed())
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.targetedNS, "app-cfg-restore-mismatched-env")).To(Succeed())
	})

	// 4. Create untargeted namespace without label
	By(fmt.Sprintf("Create untargeted namespace %s\n", f.untargetedNS), func() {
		Expect(CreateNamespaceWithLabel(f.Ctx, f.Client, f.untargetedNS, map[string]string{})).To(Succeed())
	})
	By("Create ConfigMap in untargeted namespace", func() {
		_, err := CreateConfigMap(f.Client.ClientGo, f.untargetedNS, "app-cfg-both-included",
			map[string]string{"app": "test-workload", "env": "production"}, map[string]string{"data": "should-not-backup"})
		Expect(err).To(Succeed())
		Expect(WaitForConfigMapComplete(f.Client.ClientGo, f.untargetedNS, "app-cfg-both-included")).To(Succeed())
	})

	// 5. Create ClusterRoles:
	// a. Both included in backup and restore
	By(fmt.Sprintf("Create ClusterRole %s", f.crBothIncluded), func() {
		Expect(f.createTestClusterRole(f.crBothIncluded, map[string]string{f.clusterLabelKey: f.clusterLabelValue, "env": "production"})).To(Succeed())
	})

	// b. Excluded by backup excludedNames (*-backup-debug)
	By(fmt.Sprintf("Create ClusterRole %s (excluded by backup name filter)", f.crBackupDebug), func() {
		Expect(f.createTestClusterRole(f.crBackupDebug, map[string]string{f.clusterLabelKey: f.clusterLabelValue, "env": "production"})).To(Succeed())
	})

	// c. Excluded by backup labelSelector (app=other)
	By(fmt.Sprintf("Create ClusterRole %s (excluded by backup labelSelector)", f.crBackupMismatchedLabel), func() {
		Expect(f.createTestClusterRole(f.crBackupMismatchedLabel, map[string]string{f.clusterLabelKey: "other", "env": "production"})).To(Succeed())
	})

	// d. Excluded by backup names pattern (other-*)
	By(fmt.Sprintf("Create ClusterRole %s (excluded by backup names pattern)", f.crBackupUnmatchedName), func() {
		Expect(f.createTestClusterRole(f.crBackupUnmatchedName, map[string]string{f.clusterLabelKey: f.clusterLabelValue, "env": "production"})).To(Succeed())
	})

	// e. Backed up, but to be excluded by restore excludedNames (*-restore-debug)
	By(fmt.Sprintf("Create ClusterRole %s (backed up, excluded by restore excludedNames)", f.crRestoreDebug), func() {
		Expect(f.createTestClusterRole(f.crRestoreDebug, map[string]string{f.clusterLabelKey: f.clusterLabelValue, "env": "production"})).To(Succeed())
	})

	// f. Backed up, but to be excluded by restore labelSelector (env=staging != production)
	By(fmt.Sprintf("Create ClusterRole %s (backed up, excluded by restore labelSelector)", f.crRestoreMismatchedEnv), func() {
		Expect(f.createTestClusterRole(f.crRestoreMismatchedEnv, map[string]string{f.clusterLabelKey: f.clusterLabelValue, "env": "staging"})).To(Succeed())
	})

	return nil
}

func (f *FineGrainedResourceFilter) createTestClusterRole(name string, labels map[string]string) error {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	_, err := f.Client.ClientGo.RbacV1().ClusterRoles().Create(f.Ctx, role, metav1.CreateOptions{})
	return err
}

func (f *FineGrainedResourceFilter) Backup() error {
	backup := builder.ForBackup(f.VeleroCfg.VeleroNamespace, f.BackupName).
		ResourcePolicies(f.backupCMName).
		Result()

	By(fmt.Sprintf("Create backup %s directly via the API with no IncludedNamespaces set\n", f.BackupName), func() {
		Expect(f.Client.Kubebuilder.Create(f.Ctx, backup)).To(Succeed(),
			fmt.Sprintf("Failed to create backup %s", f.BackupName))
	})

	By(fmt.Sprintf("Waiting for backup %s to complete\n", f.BackupName), func() {
		Expect(wait.PollUntilContextTimeout(f.Ctx, PollInterval, PollTimeout, true, func(ctx context.Context) (bool, error) {
			got := &velerov1api.Backup{}
			if err := f.Client.Kubebuilder.Get(ctx, types.NamespacedName{Namespace: f.VeleroCfg.VeleroNamespace, Name: f.BackupName}, got); err != nil {
				return false, err
			}
			switch got.Status.Phase {
			case velerov1api.BackupPhaseCompleted:
				return true, nil
			case velerov1api.BackupPhaseFailed, velerov1api.BackupPhasePartiallyFailed,
				velerov1api.BackupPhaseFailedValidation:
				return false, errors.Newf("backup %s ended in phase %s", f.BackupName, got.Status.Phase)
			default:
				return false, nil
			}
		})).To(Succeed(), fmt.Sprintf("Backup %s did not complete successfully", f.BackupName))
	})

	// Verify the backup filters by inspecting the backed-up resourceList via `velero backup describe --details -o json`
	By(fmt.Sprintf("Verify backup filters via 'velero backup describe %s --details -o json'\n", f.BackupName), func() {
		cmd := exec.CommandContext(f.Ctx, f.VeleroCfg.VeleroCLI,
			"--namespace", f.VeleroCfg.VeleroNamespace,
			"backup", "describe", f.BackupName,
			"--details",
			"-o", "json",
		)
		outputBytes, err := cmd.Output()
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to describe backup %s: %v", f.BackupName, err))

		var descOutput backupDescribeDetailsOutput
		Expect(json.Unmarshal(outputBytes, &descOutput)).To(Succeed(), "Failed to unmarshal backup describe output")
		resourceList := descOutput.Status.ResourceList
		Expect(resourceList).NotTo(BeEmpty(), "Resource list in backup describe output should not be empty")

		hasResource := func(expectedItem string) bool {
			for _, items := range resourceList {
				for _, item := range items {
					if item == expectedItem {
						return true
					}
				}
			}
			return false
		}

		// A. Verified INCLUDED in backup:
		Expect(hasResource(fmt.Sprintf("%s/app-cfg-both-included", f.targetedNS))).To(BeTrue(),
			"app-cfg-both-included must be present in backup resourceList")
		Expect(hasResource(fmt.Sprintf("%s/app-cfg-restore-debug", f.targetedNS))).To(BeTrue(),
			"app-cfg-restore-debug must be present in backup resourceList")
		Expect(hasResource(fmt.Sprintf("%s/app-cfg-restore-mismatched-env", f.targetedNS))).To(BeTrue(),
			"app-cfg-restore-mismatched-env must be present in backup resourceList")
		Expect(hasResource(f.crBothIncluded)).To(BeTrue(),
			fmt.Sprintf("ClusterRole %s must be present in backup resourceList", f.crBothIncluded))
		Expect(hasResource(f.crRestoreDebug)).To(BeTrue(),
			fmt.Sprintf("ClusterRole %s must be present in backup resourceList", f.crRestoreDebug))
		Expect(hasResource(f.crRestoreMismatchedEnv)).To(BeTrue(),
			fmt.Sprintf("ClusterRole %s must be present in backup resourceList", f.crRestoreMismatchedEnv))

		// B. Verified EXCLUDED from backup:
		// 1. Excluded by backup name glob (*-backup-debug)
		Expect(hasResource(fmt.Sprintf("%s/app-cfg-backup-debug", f.targetedNS))).To(BeFalse(),
			"app-cfg-backup-debug must be excluded from backup resourceList by excludedNames")
		// 2. Excluded by backup labelSelector (app=other)
		Expect(hasResource(fmt.Sprintf("%s/other-cfg", f.targetedNS))).To(BeFalse(),
			"other-cfg must be excluded from backup resourceList by labelSelector")
		// 3. Excluded by global excludedNamespaceScopedResources: ["secrets"]
		Expect(hasResource(fmt.Sprintf("%s/app-secret", f.targetedNS))).To(BeFalse(),
			"app-secret must be excluded from backup resourceList by global resource filter")
		// 4. Excluded by includedNamespacesByLabel (untargeted namespace)
		Expect(hasResource(fmt.Sprintf("%s/app-cfg-both-included", f.untargetedNS))).To(BeFalse(),
			"untargeted namespace items must be excluded from backup resourceList")
		// 5. ClusterRole excluded by backup excludedNames (*-backup-debug)
		Expect(hasResource(f.crBackupDebug)).To(BeFalse(),
			"ClusterRole crBackupDebug must be excluded from backup resourceList by clusterScopedFilterPolicy excludedNames")
		// 6. ClusterRole excluded by backup labelSelector (app=other)
		Expect(hasResource(f.crBackupMismatchedLabel)).To(BeFalse(),
			"ClusterRole crBackupMismatchedLabel must be excluded from backup resourceList by clusterScopedFilterPolicy labelSelector")
		// 7. ClusterRole excluded by backup names pattern (other-*)
		Expect(hasResource(f.crBackupUnmatchedName)).To(BeFalse(),
			"ClusterRole crBackupUnmatchedName must be excluded from backup resourceList by clusterScopedFilterPolicy names pattern")
	})

	return nil
}

func (f *FineGrainedResourceFilter) Destroy() error {
	By("Deleting test cluster roles before restore", func() {
		for _, cr := range f.clusterRoles {
			_ = f.Client.ClientGo.RbacV1().ClusterRoles().Delete(f.Ctx, cr, metav1.DeleteOptions{})
		}
	})
	return f.TestCase.Destroy()
}

func (f *FineGrainedResourceFilter) Restore() error {
	veleroCfg := f.GetTestCase().VeleroCfg

	By(fmt.Sprintf("Start restore %s with resource policies configmap %s...", f.RestoreName, f.restoreCMName), func() {
		Expect(VeleroCmdExec(f.Ctx, veleroCfg.VeleroCLI, f.RestoreArgs)).To(Succeed(), "Failed to create restore")
	})

	By(fmt.Sprintf("Waiting for restore %s to complete\n", f.RestoreName), func() {
		Expect(wait.PollUntilContextTimeout(f.Ctx, PollInterval, PollTimeout, true, func(ctx context.Context) (bool, error) {
			got := &velerov1api.Restore{}
			if err := f.Client.Kubebuilder.Get(ctx, types.NamespacedName{Namespace: f.VeleroCfg.VeleroNamespace, Name: f.RestoreName}, got); err != nil {
				return false, err
			}
			switch got.Status.Phase {
			case velerov1api.RestorePhaseCompleted:
				return true, nil
			case velerov1api.RestorePhaseFailed, velerov1api.RestorePhasePartiallyFailed,
				velerov1api.RestorePhaseFailedValidation:
				return false, errors.Newf("restore %s ended in phase %s", f.RestoreName, got.Status.Phase)
			default:
				return false, nil
			}
		})).To(Succeed(), fmt.Sprintf("Restore %s did not complete successfully", f.RestoreName))
	})

	return nil
}

func (f *FineGrainedResourceFilter) Verify() error {
	// 1. Verify targeted namespace was restored
	By(fmt.Sprintf("Verify targeted namespace %s was restored", f.targetedNS), func() {
		_, err := GetNamespace(f.Ctx, f.Client, f.targetedNS)
		Expect(err).To(Succeed(), fmt.Sprintf("Targeted namespace %s should exist after restore", f.targetedNS))
	})

	// 2. Verify untargeted namespace was never restored
	By(fmt.Sprintf("Verify untargeted namespace %s was NOT restored", f.untargetedNS), func() {
		_, err := GetNamespace(f.Ctx, f.Client, f.untargetedNS)
		Expect(err).To(HaveOccurred(), fmt.Sprintf("Untargeted namespace %s should not exist after restore", f.untargetedNS))
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "Error should be NotFound")
	})

	// 3. Verify matching ConfigMap was restored
	By("Verify matching ConfigMap app-cfg-both-included was restored", func() {
		cm, err := GetConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-both-included")
		Expect(err).To(Succeed(), "app-cfg-both-included should exist in restored namespace")
		Expect(cm.Data["data"]).To(Equal("retained"))
	})

	// 4. Verify ConfigMap excluded by restore excludedNames (*-restore-debug) was NOT restored
	// (even though it was proven present in the backup archive!)
	By("Verify ConfigMap app-cfg-restore-debug was NOT restored (excluded by restore excludedNames)", func() {
		_, err := GetConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-restore-debug")
		Expect(err).To(HaveOccurred(), "app-cfg-restore-debug should not exist after restore")
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "app-cfg-restore-debug error should be NotFound")
	})

	// 5. Verify ConfigMap excluded by restore labelSelector (env=staging != production) was NOT restored
	// (even though it was proven present in the backup archive!)
	By("Verify ConfigMap app-cfg-restore-mismatched-env was NOT restored (excluded by restore labelSelector)", func() {
		_, err := GetConfigMap(f.Client.ClientGo, f.targetedNS, "app-cfg-restore-mismatched-env")
		Expect(err).To(HaveOccurred(), "app-cfg-restore-mismatched-env should not exist after restore")
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "app-cfg-restore-mismatched-env error should be NotFound")
	})

	// 6. Verify clusterScopedFilterPolicy at restore time:
	// a. Matching ClusterRole was restored
	By(fmt.Sprintf("Verify matching ClusterRole %s was restored", f.crBothIncluded), func() {
		cr, err := GetClusterRole(f.Ctx, f.Client, f.crBothIncluded)
		Expect(err).To(Succeed(), fmt.Sprintf("ClusterRole %s should be restored", f.crBothIncluded))
		Expect(cr.Name).To(Equal(f.crBothIncluded))
	})

	// b. ClusterRole excluded by restore excludedNames (*-restore-debug) was NOT restored
	By(fmt.Sprintf("Verify ClusterRole %s was NOT restored (excluded by restore clusterScopedFilterPolicy excludedNames)", f.crRestoreDebug), func() {
		_, err := GetClusterRole(f.Ctx, f.Client, f.crRestoreDebug)
		Expect(err).To(HaveOccurred(), fmt.Sprintf("ClusterRole %s should not exist after restore", f.crRestoreDebug))
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "ClusterRole error should be NotFound")
	})

	// c. ClusterRole excluded by restore labelSelector (env=staging != production) was NOT restored
	By(fmt.Sprintf("Verify ClusterRole %s was NOT restored (excluded by restore clusterScopedFilterPolicy labelSelector)", f.crRestoreMismatchedEnv), func() {
		_, err := GetClusterRole(f.Ctx, f.Client, f.crRestoreMismatchedEnv)
		Expect(err).To(HaveOccurred(), fmt.Sprintf("ClusterRole %s should not exist after restore", f.crRestoreMismatchedEnv))
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "ClusterRole error should be NotFound")
	})

	return nil
}

func (f *FineGrainedResourceFilter) Clean() error {
	if CurrentSpecReport().Failed() && f.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		return nil
	}

	for _, cr := range f.clusterRoles {
		_ = f.Client.ClientGo.RbacV1().ClusterRoles().Delete(f.Ctx, cr, metav1.DeleteOptions{})
	}

	if err := DeleteConfigMap(f.Client.ClientGo, f.VeleroCfg.VeleroNamespace, f.backupCMName); err != nil {
		fmt.Println("Failed to delete backup resource policy configmap: ", err)
	}

	if err := DeleteConfigMap(f.Client.ClientGo, f.VeleroCfg.VeleroNamespace, f.restoreCMName); err != nil {
		fmt.Println("Failed to delete restore resource policy configmap: ", err)
	}

	return f.GetTestCase().Clean()
}
