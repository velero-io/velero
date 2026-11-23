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

package filtering

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	. "github.com/velero-io/velero/test/e2e/test"
	. "github.com/velero-io/velero/test/util/k8s"
)

// WildcardNamespaces tests the inclusion and exclusion of namespaces using wildcards
// introduced in PR #9255 (Issue #1874). It verifies filtering at both Backup and Restore stages.
type WildcardNamespaces struct {
	TestCase            // Inherit from basic TestCase instead of FilteringCase to customize a single flow
	restoredNS          []string
	excludedByBackupNS  []string
	excludedByRestoreNS []string
}

// Register as a single E2E test
var WildcardNamespacesTest func() = TestFunc(&WildcardNamespaces{})

func (w *WildcardNamespaces) Init() error {
	Expect(w.TestCase.Init()).To(Succeed())

	w.CaseBaseName = "wildcard-ns-" + w.UUIDgen
	w.BackupName = "backup-" + w.CaseBaseName
	w.RestoreName = "restore-" + w.CaseBaseName

	// 1. Define namespaces for different filtering lifecycle scenarios
	nsIncBoth := w.CaseBaseName + "-inc-both" // Included in both backup and restore
	nsExact := w.CaseBaseName + "-exact"      // Included exactly without wildcards
	nsIncExc := w.CaseBaseName + "-inc-exc"   // Included in backup, but excluded during restore
	nsBakExc := w.CaseBaseName + "-test-bak"  // Excluded during backup

	// Group namespaces for validation
	w.restoredNS = []string{nsIncBoth, nsExact}
	w.excludedByRestoreNS = []string{nsIncExc}
	w.excludedByBackupNS = []string{nsBakExc}

	w.TestMsg = &TestMSG{
		Desc:      "Backup and restore with wildcard namespaces",
		Text:      "Should correctly filter namespaces using wildcards during both backup and restore stages",
		FailedMSG: "Failed to properly filter namespaces using wildcards",
	}

	// 2. Setup Backup Args
	backupIncWildcard1 := fmt.Sprintf("%s-inc-*", w.CaseBaseName)   // Matches nsIncBoth, nsIncExc
	backupIncWildcard2 := fmt.Sprintf("%s-test-*", w.CaseBaseName)  // Matches nsBakExc
	backupExcWildcard := fmt.Sprintf("%s-test-bak", w.CaseBaseName) // Excludes nsBakExc
	nonExistentWildcard := "non-existent-ns-*"                      // Tests zero-match boundary condition

	w.BackupArgs = []string{
		"create", "--namespace", w.VeleroCfg.VeleroNamespace, "backup", w.BackupName,
		// Use broad wildcards for inclusion to bypass Velero CLI's literal string collision validation
		"--include-namespaces", fmt.Sprintf("%s,%s,%s,%s", backupIncWildcard1, backupIncWildcard2, nsExact, nonExistentWildcard),
		"--exclude-namespaces", backupExcWildcard,
		"--default-volumes-to-fs-backup", "--wait",
	}

	// 3. Setup Restore Args
	restoreExcWildcard := fmt.Sprintf("%s-*-exc", w.CaseBaseName) // Excludes nsIncExc

	w.RestoreArgs = []string{
		"create", "--namespace", w.VeleroCfg.VeleroNamespace, "restore", w.RestoreName,
		"--from-backup", w.BackupName,
		"--include-namespaces", fmt.Sprintf("%s,%s,%s", backupIncWildcard1, nsExact, nonExistentWildcard),
		"--exclude-namespaces", restoreExcWildcard,
		"--wait",
	}

	return nil
}

func (w *WildcardNamespaces) CreateResources() error {
	allNamespaces := append(w.restoredNS, w.excludedByRestoreNS...)
	allNamespaces = append(allNamespaces, w.excludedByBackupNS...)

	for _, ns := range allNamespaces {
		By(fmt.Sprintf("Creating namespace %s", ns), func() {
			Expect(CreateNamespace(w.Ctx, w.Client, ns)).To(Succeed(), fmt.Sprintf("Failed to create namespace %s", ns))
		})

		// Create a ConfigMap in each namespace to verify resource restoration
		cmName := "configmap-" + ns
		By(fmt.Sprintf("Creating ConfigMap %s in namespace %s", cmName, ns), func() {
			_, err := CreateConfigMap(w.Client.ClientGo, ns, cmName, map[string]string{"wildcard-test": "true"}, nil)
			Expect(err).To(Succeed(), fmt.Sprintf("Failed to create configmap in namespace %s", ns))
		})
	}
	return nil
}

func (w *WildcardNamespaces) Verify() error {
	// 1. Verify namespaces that should be successfully restored
	for _, ns := range w.restoredNS {
		By(fmt.Sprintf("Checking included namespace %s exists", ns), func() {
			_, err := GetNamespace(w.Ctx, w.Client, ns)
			Expect(err).To(Succeed(), fmt.Sprintf("Included namespace %s should exist after restore", ns))

			_, err = GetConfigMap(w.Client.ClientGo, ns, "configmap-"+ns)
			Expect(err).To(Succeed(), fmt.Sprintf("ConfigMap in included namespace %s should exist", ns))
		})
	}

	// 2. Verify namespaces excluded during Backup
	for _, ns := range w.excludedByBackupNS {
		By(fmt.Sprintf("Checking namespace %s excluded by backup does NOT exist", ns), func() {
			_, err := GetNamespace(w.Ctx, w.Client, ns)
			Expect(err).To(HaveOccurred(), fmt.Sprintf("Namespace %s excluded by backup should NOT exist after restore", ns))
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "Error should be NotFound")
		})
	}

	// 3. Verify namespaces excluded during Restore
	for _, ns := range w.excludedByRestoreNS {
		By(fmt.Sprintf("Checking namespace %s excluded by restore does NOT exist", ns), func() {
			_, err := GetNamespace(w.Ctx, w.Client, ns)
			Expect(err).To(HaveOccurred(), fmt.Sprintf("Namespace %s excluded by restore should NOT exist after restore", ns))
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "Error should be NotFound")
		})
	}
	return nil
}
