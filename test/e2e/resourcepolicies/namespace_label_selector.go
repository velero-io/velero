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
	"fmt"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

// NamespaceLabelSelector covers design step 8 of
// https://github.com/velero-io/velero/pull/9772: a backup with no explicit
// includedNamespaces (the same shape a Schedule with no includedNamespaces produces),
// relying entirely on a ResourcePolicy ConfigMap's includedNamespacesByLabel to select which
// namespaces to back up. Only namespaces matching the label selector should end up in the
// backup; everything else - including namespaces that already existed in the cluster before
// this test ran - must not.
//
// The Backup is created directly via the controller-runtime client rather than through
// `velero backup create`: that CLI command's --include-namespaces flag defaults to ["*"]
// when omitted (see pkg/cmd/cli/backup/create.go), which is an *explicit* wildcard - by
// design, mergeNamespacesByLabel leaves an explicit "*" untouched rather than narrowing it
// (see pkg/controller/backup_controller.go). Only a BackupSpec.IncludedNamespaces that was
// never set at all is treated as "defaulted" and gets replaced by the label-resolved set,
// so this test has to leave the field genuinely empty - something the CLI's own default
// makes impossible to express.
type NamespaceLabelSelector struct {
	TestCase
	cmName      string
	labelKey    string
	labelValue  string
	labeledNS   []string
	unlabeledNS []string
}

var NamespaceLabelSelectorTest func() = TestFunc(&NamespaceLabelSelector{})

func (n *NamespaceLabelSelector) Init() error {
	Expect(n.TestCase.Init()).To(Succeed())

	n.CaseBaseName = "ns-label-selector-" + n.UUIDgen
	n.BackupName = "backup-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName
	n.cmName = "cm-" + n.CaseBaseName
	n.labelKey = "velero-e2e-ns-label-selector"
	n.labelValue = n.UUIDgen

	n.labeledNS = []string{
		n.CaseBaseName + "-included-0",
		n.CaseBaseName + "-included-1",
	}
	n.unlabeledNS = []string{
		n.CaseBaseName + "-excluded-0",
		n.CaseBaseName + "-excluded-1",
	}

	n.TestMsg = &TestMSG{
		Desc: "Backup with a ResourcePolicy includedNamespacesByLabel selector and no IncludedNamespaces set",
		Text: "should back up only the namespaces matching the label selector, replacing the " +
			"default \"all namespaces\" behavior rather than unioning with it",
		FailedMSG: "Failed to select namespaces by label via ResourcePolicy",
	}

	// The Backup itself is created directly via the controller-runtime client (see
	// Backup() below) rather than through BackupArgs/`velero backup create`, so
	// BackupSpec.IncludedNamespaces can be left genuinely unset.
	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore", n.RestoreName,
		"--from-backup", n.BackupName, "--wait",
	}

	return nil
}

func (n *NamespaceLabelSelector) Backup() error {
	backup := builder.ForBackup(n.VeleroCfg.VeleroNamespace, n.BackupName).
		ResourcePolicies(n.cmName).
		Result()

	By(fmt.Sprintf("Create backup %s directly via the API, with no IncludedNamespaces set\n", n.BackupName), func() {
		Expect(n.Client.Kubebuilder.Create(n.Ctx, backup)).To(Succeed(),
			fmt.Sprintf("Failed to create backup %s", n.BackupName))
	})

	By(fmt.Sprintf("Waiting for backup %s to complete\n", n.BackupName), func() {
		Expect(wait.Poll(PollInterval, PollTimeout, func() (bool, error) {
			got := &velerov1api.Backup{}
			if err := n.Client.Kubebuilder.Get(n.Ctx, types.NamespacedName{Namespace: n.VeleroCfg.VeleroNamespace, Name: n.BackupName}, got); err != nil {
				return false, err
			}
			switch got.Status.Phase {
			case velerov1api.BackupPhaseCompleted:
				return true, nil
			case velerov1api.BackupPhaseFailed, velerov1api.BackupPhasePartiallyFailed,
				velerov1api.BackupPhaseFailedValidation:
				return false, errors.Newf("backup %s ended in phase %s", n.BackupName, got.Status.Phase)
			default:
				return false, nil
			}
		})).To(Succeed(), fmt.Sprintf("Backup %s did not complete successfully", n.BackupName))
	})

	return nil
}

func (n *NamespaceLabelSelector) CreateResources() error {
	yamlConfig := fmt.Sprintf(`version: v1
includeExcludePolicy:
  includedNamespacesByLabel:
    - "%s=%s"
`, n.labelKey, n.labelValue)

	By(fmt.Sprintf("Create ResourcePolicy configmap %s in namespace %s\n", n.cmName, n.VeleroCfg.VeleroNamespace), func() {
		Expect(CreateConfigMapFromYAMLData(n.Client.ClientGo, yamlConfig, n.cmName, n.VeleroCfg.VeleroNamespace)).To(Succeed(),
			fmt.Sprintf("Failed to create configmap %s in namespace %s\n", n.cmName, n.VeleroCfg.VeleroNamespace))
	})
	By(fmt.Sprintf("Waiting for configmap %s in namespace %s ready\n", n.cmName, n.VeleroCfg.VeleroNamespace), func() {
		Expect(WaitForConfigMapComplete(n.Client.ClientGo, n.VeleroCfg.VeleroNamespace, n.cmName)).To(Succeed(),
			fmt.Sprintf("Failed to wait configmap %s in namespace %s ready\n", n.cmName, n.VeleroCfg.VeleroNamespace))
	})

	for _, ns := range n.labeledNS {
		By(fmt.Sprintf("Create labeled namespace %s\n", ns), func() {
			Expect(CreateNamespaceWithLabel(n.Ctx, n.Client, ns, map[string]string{n.labelKey: n.labelValue})).To(Succeed(),
				fmt.Sprintf("Failed to create namespace %s", ns))
		})
		if err := n.createVerificationConfigMap(ns); err != nil {
			return err
		}
	}

	for _, ns := range n.unlabeledNS {
		By(fmt.Sprintf("Create unlabeled namespace %s\n", ns), func() {
			Expect(CreateNamespaceWithLabel(n.Ctx, n.Client, ns, map[string]string{})).To(Succeed(),
				fmt.Sprintf("Failed to create namespace %s", ns))
		})
		if err := n.createVerificationConfigMap(ns); err != nil {
			return err
		}
	}

	return nil
}

func (n *NamespaceLabelSelector) createVerificationConfigMap(ns string) error {
	cmName := "marker-" + ns
	By(fmt.Sprintf("Creating marker configmap %s in namespace %s\n", cmName, ns), func() {
		_, err := CreateConfigMap(n.Client.ClientGo, ns, cmName, map[string]string{"marker": "true"}, nil)
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to create marker configmap in namespace %s", ns))
	})
	return WaitForConfigMapComplete(n.Client.ClientGo, ns, cmName)
}

func (n *NamespaceLabelSelector) Verify() error {
	for _, ns := range n.labeledNS {
		By(fmt.Sprintf("Verify labeled namespace %s was backed up and restored", ns), func() {
			_, err := GetNamespace(n.Ctx, n.Client, ns)
			Expect(err).To(Succeed(), fmt.Sprintf("Labeled namespace %s should exist after restore", ns))

			_, err = GetConfigMap(n.Client.ClientGo, ns, "marker-"+ns)
			Expect(err).To(Succeed(), fmt.Sprintf("Marker configmap in labeled namespace %s should exist after restore", ns))
		})
	}

	for _, ns := range n.unlabeledNS {
		By(fmt.Sprintf("Verify unlabeled namespace %s was NOT backed up", ns), func() {
			_, err := GetNamespace(n.Ctx, n.Client, ns)
			Expect(err).To(HaveOccurred(), fmt.Sprintf("Unlabeled namespace %s should not exist after restore - it was never in the backup", ns))
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "Error should be NotFound")
		})
	}

	return nil
}

func (n *NamespaceLabelSelector) Clean() error {
	if CurrentSpecReport().Failed() && n.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		return nil
	}

	if err := DeleteConfigMap(n.Client.ClientGo, n.VeleroCfg.VeleroNamespace, n.cmName); err != nil {
		return errors.Wrap(err, "failed to delete resource policy configmap")
	}

	// Unlabeled namespaces are never touched by backup/restore, so the base Clean's
	// CaseBaseName-prefix sweep is what removes them (and the labeled ones) here.
	return n.GetTestCase().Clean()
}
