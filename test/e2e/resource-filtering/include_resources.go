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
Backup all deployments in the cluster.
	velero backup create <backup-name> --include-resources deployments, configmaps

Restore all deployments and configmaps in the cluster.
	velero restore create <backup-name> --include-resources deployments,configmaps
*/

type IncludeResources struct {
	FilteringCase
}

var BackupWithIncludeResources func() = TestFunc(&IncludeResources{testInBackup})
var RestoreWithIncludeResources func() = TestFunc(&IncludeResources{testInRestore})

func (i *IncludeResources) Init() error {
	i.FilteringCase.Init()
	i.CaseBaseName = "include-resources-" + i.UUIDgen
	for nsNum := 0; nsNum < i.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", i.CaseBaseName, nsNum)
		*i.NSIncluded = append(*i.NSIncluded, createNSName)
	}
	if i.IsTestInBackup { // testing case backup with include-resources option
		i.TestMsg = &TestMSG{
			Desc:      "Backup resources with resources included test",
			Text:      "Should backup resources which is included others should not be backup",
			FailedMSG: "Failed to backup with resource include",
		}
		i.BackupName = "backup-" + i.CaseBaseName
		i.RestoreName = "restore-" + i.UUIDgen
		i.BackupArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "backup", i.BackupName,
			"--include-resources", "deployments,configmaps",
			"--default-volumes-to-fs-backup", "--wait",
		}

		i.RestoreArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "restore", i.RestoreName,
			"--from-backup", i.BackupName, "--wait",
		}
	} else { // testing case restore with include-resources option
		i.TestMsg = &TestMSG{
			Desc:      "Restore resources with resources included test",
			Text:      "Should restore resources which is included others should not be backup",
			FailedMSG: "Failed to restore with resource include",
		}
		i.BackupName = "backup-" + i.UUIDgen
		i.RestoreName = "restore-" + i.CaseBaseName
		i.BackupArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "backup", i.BackupName,
			"--include-namespaces", strings.Join(*i.NSIncluded, ","),
			"--default-volumes-to-fs-backup", "--wait",
		}
		i.RestoreArgs = []string{
			"create", "--namespace", VeleroCfg.VeleroNamespace, "restore", i.RestoreName,
			"--include-resources", "deployments,configmaps",
			"--from-backup", i.BackupName, "--wait",
		}
	}
	return nil
}

func (i *IncludeResources) Verify() error {
	for nsNum := 0; nsNum < i.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", i.CaseBaseName, nsNum)
		fmt.Printf("Checking resources in namespaces ...%s\n", namespace)
		//Check deployment
		_, err := GetDeployment(i.Client.ClientGo, namespace, i.CaseBaseName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
		}
		//Check secrets
		secretsList, err := i.Client.ClientGo.CoreV1().Secrets(namespace).List(i.Ctx, metav1.ListOptions{LabelSelector: i.labelSelector})
		if err != nil {
			if apierrors.IsNotFound(err) { //resource should be excluded
				return nil
			}
			return errors.Wrap(err, fmt.Sprintf("failed to list secrets in namespace: %q", namespace))
		} else if len(secretsList.Items) != 0 {
			return errors.Errorf("Should no secrets found  %s in namespace: %q", secretsList.Items[0].Name, namespace)
		}

		//Check configmap
		configmapList, err := i.Client.ClientGo.CoreV1().ConfigMaps(namespace).List(i.Ctx, metav1.ListOptions{LabelSelector: i.labelSelector})
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list configmap in namespace: %q", namespace))
		} else if len(configmapList.Items) == 0 {
			return errors.Errorf("Should have configmap found in namespace: %q", namespace)
		}
	}
	return nil
}
