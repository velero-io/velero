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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

type BslReadOnly struct {
	TestCase
}

var BslReadOnlyTest func() = TestFunc(&BslReadOnly{})

func (b *BslReadOnly) Init() error {
	b.TestCase.Init()
	b.CaseBaseName = "bsl-readonly-" + b.UUIDgen
	b.BackupName = "backup-" + b.CaseBaseName
	b.RestoreName = "restore-" + b.CaseBaseName
	b.NamespacesTotal = 1
	b.NSIncluded = &[]string{b.CaseBaseName}
	b.BackupArgs = []string{
		"create", "--namespace", b.VeleroCfg.VeleroNamespace, "backup", b.BackupName,
		"--include-namespaces", b.CaseBaseName,
		"--snapshot-volumes=false", "--wait",
	}
	b.RestoreArgs = []string{
		"create", "--namespace", b.VeleroCfg.VeleroNamespace, "restore", b.RestoreName,
		"--from-backup", b.BackupName, "--wait",
	}
	b.TestMsg = &TestMSG{
		Desc:      "BackupStorageLocation Read-Only Mode E2E Test",
		FailedMSG: "Failed to validate BSL Read-Only Mode behavior",
		Text:      "BSL Read-Only mode should restrict backups but allow restores",
	}
	return nil
}

func (b *BslReadOnly) CreateResources() error {
	By(fmt.Sprintf("Create namespace %s", b.CaseBaseName), func() {
		Expect(CreateNamespace(b.Ctx, b.Client, b.CaseBaseName)).To(Succeed())
	})
	By("Create a test ConfigMap in the namespace", func() {
		_, err := CreateConfigMap(b.Client.ClientGo, b.CaseBaseName, "test-cm", nil, map[string]string{"foo": "bar"})
		Expect(err).To(Succeed())
	})
	return nil
}

func (b *BslReadOnly) Destroy() error {
	// 1. Delete the namespace to verify we can restore it later.
	By(fmt.Sprintf("Delete namespace %s before restore", b.CaseBaseName), func() {
		Expect(CleanupNamespacesWithPoll(b.Ctx, b.Client, b.CaseBaseName)).To(Succeed())
	})

	// 2. Set default BSL to ReadOnly.
	By("Update BSL 'default' to ReadOnly access mode", func() {
		bsl := &velerov1api.BackupStorageLocation{}
		err := b.Client.Kubebuilder.Get(b.Ctx, kbclient.ObjectKey{
			Namespace: b.VeleroCfg.VeleroNamespace,
			Name:      "default",
		}, bsl)
		Expect(err).To(Succeed())

		bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadOnly
		err = b.Client.Kubebuilder.Update(b.Ctx, bsl)
		Expect(err).To(Succeed())
	})

	// 3. Try to create backup-2, which must fail validation.
	By("Try creating a new backup under ReadOnly BSL, expecting validation failure", func() {
		backup2Name := "backup-fail-" + b.CaseBaseName
		args := []string{
			"create", "--namespace", b.VeleroCfg.VeleroNamespace, "backup", backup2Name,
			"--include-namespaces", b.CaseBaseName,
			"--snapshot-volumes=false", "--wait",
		}
		// Expect VeleroBackupExec to return error because the backup phase will be FailedValidation
		err := VeleroBackupExec(b.Ctx, b.VeleroCfg.VeleroCLI, b.VeleroCfg.VeleroNamespace, backup2Name, args)
		Expect(err).To(MatchError(ContainSubstring(string(velerov1api.BackupPhaseFailedValidation))))
	})

	return nil
}

func (b *BslReadOnly) Verify() error {
	// 1. Verify resources are successfully restored.
	By("Verify ConfigMap was restored successfully", func() {
		_, err := GetConfigMap(b.Client.ClientGo, b.CaseBaseName, "test-cm")
		Expect(err).To(Succeed())
	})

	// 2. Reset BSL back to ReadWrite.
	By("Reset default BSL back to ReadWrite", func() {
		bsl := &velerov1api.BackupStorageLocation{}
		err := b.Client.Kubebuilder.Get(b.Ctx, kbclient.ObjectKey{
			Namespace: b.VeleroCfg.VeleroNamespace,
			Name:      "default",
		}, bsl)
		Expect(err).To(Succeed())

		bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadWrite
		err = b.Client.Kubebuilder.Update(b.Ctx, bsl)
		Expect(err).To(Succeed())
	})
	return nil
}

func (b *BslReadOnly) Clean() error {
	// Safety reset BSL back to ReadWrite in case verify was skipped or failed.
	if b.Ctx != nil {
		bsl := &velerov1api.BackupStorageLocation{}
		if err := b.Client.Kubebuilder.Get(b.Ctx, kbclient.ObjectKey{
			Namespace: b.VeleroCfg.VeleroNamespace,
			Name:      "default",
		}, bsl); err == nil {
			if bsl.Spec.AccessMode != velerov1api.BackupStorageLocationAccessModeReadWrite {
				bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadWrite
				if err := b.Client.Kubebuilder.Update(b.Ctx, bsl); err != nil {
					fmt.Println("Failed to reset default BSL access mode to ReadWrite:", err)
				}
			}
		}
	}
	return b.TestCase.Clean()
}
