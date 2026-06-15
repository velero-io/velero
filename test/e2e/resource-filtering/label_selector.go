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

	"github.com/cockroachdb/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

/*
Include resources matching the label selector.
	velero backup create <backup-name> --selector <key>=<value>
*/

type LabelSelector struct {
	FilteringCase
}

var BackupWithLabelSelector func() = TestFunc(&LabelSelector{testInBackup})

func (l *LabelSelector) Init() error {
	l.FilteringCase.Init()
	l.CaseBaseName = "backup-label-selector-" + l.UUIDgen
	l.BackupName = "backup-" + l.CaseBaseName
	l.RestoreName = "restore-" + l.CaseBaseName

	for nsNum := 0; nsNum < l.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", l.CaseBaseName, nsNum)
		*l.NSIncluded = append(*l.NSIncluded, createNSName)
	}
	l.TestMsg = &TestMSG{
		Desc:      "Backup with the label selector test",
		Text:      "Should backup resources with selected label resource",
		FailedMSG: "Failed to backup resources with selected label",
	}
	l.labels = map[string]string{
		"resourcefiltering": "true",
	}
	l.labelSelector = "resourcefiltering"
	l.BackupArgs = []string{
		"create", "--namespace", l.VeleroCfg.VeleroNamespace, "backup", l.BackupName,
		"--selector", "resourcefiltering=true",
		"--include-namespaces", strings.Join(*l.NSIncluded, ","),
		"--default-volumes-to-fs-backup", "--wait",
	}

	l.RestoreArgs = []string{
		"create", "--namespace", l.VeleroCfg.VeleroNamespace, "restore", l.RestoreName,
		"--from-backup", l.BackupName, "--wait",
	}
	return nil
}

func (l *LabelSelector) CreateResources() error {
	for nsNum := 0; nsNum < l.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", l.CaseBaseName, nsNum)
		fmt.Printf("Creating resources in namespace ...%s\n", namespace)
		labels := l.labels
		if nsNum%2 == 0 {
			labels = map[string]string{
				"resourcefiltering": "false",
			}
		}

		if l.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			labels["pod-security.kubernetes.io/enforce"] = "privileged"
			labels["pod-security.kubernetes.io/enforce-version"] = "latest"
		}

		if err := CreateNamespaceWithLabel(l.Ctx, l.Client, namespace, labels); err != nil {
			return errors.Wrapf(err, "Failed to create namespace %s", namespace)
		}
		//Create deployment
		fmt.Printf("Creating deployment in namespaces ...%s\n", namespace)

		deployment := NewDeployment(
			l.CaseBaseName,
			namespace,
			l.replica,
			labels,
			l.VeleroCfg.ImageRegistryProxy,
			l.VeleroCfg.WorkerOS,
		).Result()
		deployment, err := CreateDeployment(l.Client.ClientGo, namespace, deployment)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to delete the namespace %q", namespace))
		}
		err = WaitForReadyDeployment(l.Client.ClientGo, namespace, deployment.Name)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to ensure job completion in namespace: %q", namespace))
		}
		//Create Secret
		secretName := l.CaseBaseName
		fmt.Printf("Creating secret %s in namespaces ...%s\n", secretName, namespace)
		_, err = CreateSecret(l.Client.ClientGo, namespace, secretName, l.labels)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create secret in the namespace %q", namespace))
		}
		err = WaitForSecretsComplete(l.Client.ClientGo, namespace, secretName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to ensure secret completion in namespace: %q", namespace))
		}
	}
	return nil
}

func (l *LabelSelector) Verify() error {
	for nsNum := 0; nsNum < l.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", l.CaseBaseName, nsNum)
		fmt.Printf("Checking resources in namespaces ...%s\n", namespace)
		//Check deployment
		_, err := GetDeployment(l.Client.ClientGo, namespace, l.CaseBaseName)
		if nsNum%2 == 1 { //include
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
			}
		} else { //exclude
			if err == nil {
				return fmt.Errorf("failed to exclude deployment in namespaces %q", namespace)
			} else {
				if apierrors.IsNotFound(err) { //resource should be excluded
					return nil
				}
				return errors.Wrap(err, fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
			}
		}

		//Check secrets
		secretsList, err := l.Client.ClientGo.CoreV1().Secrets(namespace).List(l.Ctx, metav1.ListOptions{
			LabelSelector: l.labelSelector,
		})

		if nsNum%2 == 0 { //include
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to list secrets in namespace: %q", namespace))
			} else if len(secretsList.Items) == 0 {
				return errors.Errorf("no secrets found in namespace: %q", namespace)
			}
		} else { //exclude
			if err == nil {
				return fmt.Errorf("failed to exclude secrets in namespaces %q", namespace)
			} else {
				if apierrors.IsNotFound(err) { //resource should be excluded
					return nil
				}
				return errors.Wrap(err, fmt.Sprintf("failed to list secrets in namespace: %q", namespace))
			}
		}
	}
	return nil
}
