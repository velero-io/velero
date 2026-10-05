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
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

type NSAnnotationCase struct {
	TestCase
}

func (n *NSAnnotationCase) Init() error {
	n.TestCase.Init()
	n.CaseBaseName = "namespace-annotations-" + n.UUIDgen
	n.BackupName = "backup-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName

	n.NamespacesTotal = 1
	n.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < n.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", n.CaseBaseName, nsNum)
		*n.NSIncluded = append(*n.NSIncluded, createNSName)
	}
	n.TestMsg = &TestMSG{
		Desc:      "Backup/restore namespace annotation test",
		Text:      "Should be successfully backed up and restored including annotations",
		FailedMSG: "Failed to successfully backup and restore multiple namespaces",
	}
	n.BackupArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "backup", n.BackupName,
		"--include-namespaces", strings.Join(*n.NSIncluded, ","),
		"--default-volumes-to-fs-backup", "--wait",
	}

	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore", n.RestoreName,
		"--from-backup", n.BackupName, "--wait",
	}
	return nil
}

func (n *NSAnnotationCase) CreateResources() error {
	for nsNum := 0; nsNum < n.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", n.CaseBaseName, nsNum)
		createAnnotationName := fmt.Sprintf("annotation-%s-%00000d", n.CaseBaseName, nsNum)
		if err := CreateNamespaceWithAnnotation(n.Ctx, n.Client, createNSName, map[string]string{"testAnnotation": createAnnotationName}); err != nil {
			return errors.Wrapf(err, "Failed to create namespace %s", createNSName)
		}
	}
	return nil
}

func (n *NSAnnotationCase) Verify() error {
	for nsNum := 0; nsNum < n.NamespacesTotal; nsNum++ {
		checkNSName := fmt.Sprintf("%s-%00000d", n.CaseBaseName, nsNum)
		checkAnnoName := fmt.Sprintf("annotation-%s-%00000d", n.CaseBaseName, nsNum)
		checkNS, err := GetNamespace(n.Ctx, n.Client, checkNSName)

		if err != nil {
			return errors.Wrapf(err, "Could not retrieve test namespace %s", checkNSName)
		}
		if checkNS.Name != checkNSName {
			return errors.Errorf("Retrieved namespace for %s has name %s instead", checkNSName, checkNS.Name)
		}

		c := checkNS.ObjectMeta.Annotations["testAnnotation"]

		if c != checkAnnoName {
			return errors.Errorf("Retrieved annotation for %s has name %s instead", checkAnnoName, c)
		}
	}
	return nil
}
