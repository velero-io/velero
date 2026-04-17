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
	"strings"

	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

/*
exclude-resources
Exclude secrets from the backup.

velero backup create <backup-name> --exclude-resources secrets
Exclude secrets and rolebindings.

velero backup create <backup-name> --exclude-resources secrets
*/

type ExcludeResources struct {
	FilteringCase
}

var BackupWithExcludeResources func() = TestFunc(&ExcludeResources{testInBackup})
var RestoreWithExcludeResources func() = TestFunc(&ExcludeResources{testInRestore})

func (e *ExcludeResources) Init() error {
	e.FilteringCase.Init()
	e.CaseBaseName = "exclude-resources-" + e.UUIDgen
	for nsNum := 0; nsNum < e.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", e.CaseBaseName, nsNum)
		*e.NSIncluded = append(*e.NSIncluded, createNSName)
	}
	if e.IsTestInBackup { // testing case backup with exclude-resources option
		e.TestMsg = &TestMSG{
			Desc:      "Backup resources with resources included test",
			Text:      "Should not backup resources which is excluded others should be backup",
			FailedMSG: "Failed to backup with resource exclude",
		}
		e.BackupName = "backup-" + e.CaseBaseName
		e.RestoreName = "restore-" + UUIDgen.String()
		e.BackupArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "backup", e.BackupName,
			"--include-namespaces", strings.Join(*e.NSIncluded, ","),
			"--exclude-resources", "secrets",
			"--default-volumes-to-fs-backup", "--wait",
		}

		e.RestoreArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "restore", e.RestoreName,
			"--from-backup", e.BackupName, "--wait",
		}
	} else { // testing case restore with exclude-resources option
		e.BackupName = "backup-" + e.UUIDgen
		e.RestoreName = "restore-" + e.CaseBaseName
		e.TestMsg = &TestMSG{
			Desc:      "Restore resources with resources included test",
			Text:      "Should not restore resources which is excluded others should be backup",
			FailedMSG: "Failed to restore with resource exclude",
		}
		e.BackupArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "backup", e.BackupName,
			"--include-namespaces", strings.Join(*e.NSIncluded, ","),
			"--default-volumes-to-fs-backup", "--wait",
		}
		e.RestoreArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "restore", e.RestoreName,
			"--exclude-resources", "secrets",
			"--from-backup", e.BackupName, "--wait",
		}
	}
	return nil
}

func (e *ExcludeResources) Verify() error {
	for nsNum := 0; nsNum < e.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", e.CaseBaseName, nsNum)
		fmt.Printf("Checking resources in namespaces ...%s\n", namespace)
		//Check deployment
		_, err := GetDeployment(e.Client.ClientGo, namespace, e.CaseBaseName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
		}
		//Check secrets
		secretsList, err := e.Client.ClientGo.CoreV1().Secrets(namespace).List(e.Ctx, metav1.ListOptions{LabelSelector: e.labelSelector})
		if err != nil {
			if apierrors.IsNotFound(err) { //resource should be excluded
				return nil
			}
			return errors.Wrap(err, fmt.Sprintf("failed to list secrets in namespace: %q", namespace))
		} else if len(secretsList.Items) != 0 {
			return errors.Errorf("Should no secrets found  %s in namespace: %q", secretsList.Items[0].Name, namespace)
		}

		//Check configmap
		configmapList, err := e.Client.ClientGo.CoreV1().ConfigMaps(namespace).List(e.Ctx, metav1.ListOptions{LabelSelector: e.labelSelector})
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list configmap in namespace: %q", namespace))
		} else if len(configmapList.Items) == 0 {
			return errors.Errorf("Should have configmap found in namespace: %q", namespace)
		}
	}
	return nil
}
