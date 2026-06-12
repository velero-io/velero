/*
Copyright 2021 the Velero contributors.

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

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

/*
Resources with the label velero.io/exclude-from-backup=true are not included
in backup, even if it contains a matching selector label.
*/

type ExcludeFromBackup struct {
	FilteringCase
}

var ExcludeFromBackupTest func() = TestFunc(&ExcludeFromBackup{testInBackup})

func (e *ExcludeFromBackup) Init() error {
	e.FilteringCase.Init()
	e.CaseBaseName = "exclude-from-backup-" + e.UUIDgen
	e.BackupName = "backup-" + e.CaseBaseName
	e.RestoreName = "restore-" + e.CaseBaseName

	e.TestMsg = &TestMSG{
		Desc:      "Backup with the label velero.io/exclude-from-backup=true are not included test",
		Text:      "Should not backup resources with the label velero.io/exclude-from-backup=true",
		FailedMSG: "Failed to backup resources with the label velero.io/exclude-from-backup=true",
	}
	for nsNum := 0; nsNum < e.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", e.CaseBaseName, nsNum)
		*e.NSIncluded = append(*e.NSIncluded, createNSName)
	}
	e.labels = map[string]string{
		velerov1api.ExcludeFromBackupLabel: "true",
	}
	e.labelSelector = velerov1api.ExcludeFromBackupLabel

	e.BackupArgs = []string{
		"create", "--namespace", e.VeleroCfg.VeleroNamespace, "backup", e.BackupName,
		"--include-namespaces", e.CaseBaseName,
		"--default-volumes-to-fs-backup", "--wait",
	}

	e.RestoreArgs = []string{
		"create", "--namespace", e.VeleroCfg.VeleroNamespace, "restore", e.RestoreName,
		"--from-backup", e.BackupName, "--wait",
	}
	return nil
}

func (e *ExcludeFromBackup) CreateResources() error {
	namespace := e.CaseBaseName
	// These 2 labels for resources to be included
	label1 := map[string]string{
		"meaningless-label-resource-to-include": "true",
	}
	label2 := map[string]string{
		velerov1api.ExcludeFromBackupLabel: "false",
	}
	fmt.Printf("Creating resources in namespace ...%s\n", namespace)

	nsLabels := make(map[string]string)
	if e.VeleroCfg.WorkerOS == common.WorkerOSWindows {
		nsLabels = map[string]string{
			"pod-security.kubernetes.io/enforce":         "privileged",
			"pod-security.kubernetes.io/enforce-version": "latest",
		}
	}

	if err := CreateNamespaceWithLabel(e.Ctx, e.Client, namespace, nsLabels); err != nil {
		return errors.Wrapf(err, "Failed to create namespace %s", namespace)
	}
	//Create deployment: to be included
	fmt.Printf("Creating deployment in namespaces ...%s\n", namespace)
	deployment := NewDeployment(
		e.CaseBaseName,
		namespace,
		e.replica,
		label2,
		e.VeleroCfg.ImageRegistryProxy,
		e.VeleroCfg.WorkerOS,
	).Result()
	deployment, err := CreateDeployment(e.Client.ClientGo, namespace, deployment)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to delete the namespace %q", namespace))
	}
	err = WaitForReadyDeployment(e.Client.ClientGo, namespace, deployment.Name)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to ensure job completion in namespace: %q", namespace))
	}
	//Create Secret
	secretName := e.CaseBaseName
	fmt.Printf("Creating secret %s in namespaces ...%s\n", secretName, namespace)
	_, err = CreateSecret(e.Client.ClientGo, namespace, secretName, e.labels)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create secret in the namespace %q", namespace))
	}
	err = WaitForSecretsComplete(e.Client.ClientGo, namespace, secretName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to ensure secret completion in namespace: %q", namespace))
	}
	By(fmt.Sprintf("Checking secret %s should exists in namespaces ...%s\n", secretName, namespace), func() {
		_, err = GetSecret(e.Client.ClientGo, namespace, e.CaseBaseName)
		Expect(err).ShouldNot(HaveOccurred(), fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
	})
	//Create Configmap: to be included
	configmaptName := e.CaseBaseName
	fmt.Printf("Creating configmap %s in namespaces ...%s\n", configmaptName, namespace)
	_, err = CreateConfigMap(e.Client.ClientGo, namespace, configmaptName, label1, nil)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create configmap in the namespace %q", namespace))
	}
	err = WaitForConfigMapComplete(e.Client.ClientGo, namespace, configmaptName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to ensure secret completion in namespace: %q", namespace))
	}
	return nil
}

func (e *ExcludeFromBackup) Verify() error {
	namespace := e.CaseBaseName
	By(fmt.Sprintf("Checking resources in namespaces ...%s\n", namespace), func() {
		//Check namespace
		checkNS, err := GetNamespace(e.Ctx, e.Client, namespace)
		Expect(err).ShouldNot(HaveOccurred(), fmt.Sprintf("Could not retrieve test namespace %s", namespace))
		Expect(checkNS.Name).To(Equal(namespace), fmt.Sprintf("Retrieved namespace for %s has name %s instead", namespace, checkNS.Name))

		//Check deployment: should be included
		_, err = GetDeployment(e.Client.ClientGo, namespace, e.CaseBaseName)
		Expect(err).ShouldNot(HaveOccurred(), fmt.Sprintf("failed to list deployment in namespace: %q", namespace))

		//Check secrets: secrets should not be included
		_, err = GetSecret(e.Client.ClientGo, namespace, e.CaseBaseName)
		Expect(err).Should(HaveOccurred(), fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
		Expect(apierrors.IsNotFound(err)).To(BeTrue())

		//Check configmap: should be included
		_, err = GetConfigMap(e.Client.ClientGo, namespace, e.CaseBaseName)
		Expect(err).ShouldNot(HaveOccurred(), fmt.Sprintf("failed to list configmap in namespace: %q", namespace))
	})
	return nil
}
