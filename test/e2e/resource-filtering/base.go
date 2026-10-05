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
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

type FilteringCase struct {
	TestCase
	IsTestInBackup bool
	replica        int32
	labels         map[string]string
	labelSelector  string
}

var testInBackup = FilteringCase{IsTestInBackup: true}
var testInRestore = FilteringCase{IsTestInBackup: false}

func (f *FilteringCase) Init() error {
	f.TestCase.Init()

	f.replica = int32(2)
	f.labels = map[string]string{"resourcefiltering": "true"}
	f.labelSelector = "resourcefiltering"
	f.NamespacesTotal = 3
	f.BackupArgs = []string{
		"create", "--namespace", f.VeleroCfg.VeleroNamespace, "backup", f.BackupName,
		"--default-volumes-to-fs-backup", "--wait",
	}

	f.RestoreArgs = []string{
		"create", "--namespace", f.VeleroCfg.VeleroNamespace, "restore", f.RestoreName,
		"--from-backup", f.BackupName, "--wait",
	}

	f.NSIncluded = &[]string{}
	return nil
}

func (f *FilteringCase) CreateResources() error {
	for nsNum := 0; nsNum < f.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", f.CaseBaseName, nsNum)
		fmt.Printf("Creating resources in namespace ...%s\n", namespace)
		nsLabels := make(map[string]string)
		if f.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			nsLabels = map[string]string{
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "latest",
			}
		}
		if err := CreateNamespaceWithLabel(f.Ctx, f.Client, namespace, nsLabels); err != nil {
			return errors.Wrapf(err, "Failed to create namespace %s", namespace)
		}
		//Create deployment
		fmt.Printf("Creating deployment in namespaces ...%s\n", namespace)
		deployment := NewDeployment(
			f.CaseBaseName,
			namespace,
			f.replica,
			f.labels,
			f.VeleroCfg.ImageRegistryProxy,
			f.VeleroCfg.WorkerOS,
		).Result()
		deployment, err := CreateDeployment(f.Client.ClientGo, namespace, deployment)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to delete the namespace %q", namespace))
		}
		err = WaitForReadyDeployment(f.Client.ClientGo, namespace, deployment.Name)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to ensure job completion in namespace: %q", namespace))
		}
		//Create Secret
		secretName := f.CaseBaseName
		fmt.Printf("Creating secret %s in namespaces ...%s\n", secretName, namespace)
		_, err = CreateSecret(f.Client.ClientGo, namespace, secretName, f.labels)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create secret in the namespace %q", namespace))
		}
		err = WaitForSecretsComplete(f.Client.ClientGo, namespace, secretName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to ensure secret completion in namespace: %q", namespace))
		}
		//Create Configmap
		configmaptName := f.CaseBaseName
		fmt.Printf("Creating configmap %s in namespaces ...%s\n", configmaptName, namespace)
		_, err = CreateConfigMap(f.Client.ClientGo, namespace, configmaptName, f.labels, nil)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create configmap in the namespace %q", namespace))
		}
		err = WaitForConfigMapComplete(f.Client.ClientGo, namespace, configmaptName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to ensure secret completion in namespace: %q", namespace))
		}
	}
	return nil
}

func (f *FilteringCase) Verify() error {
	for nsNum := 0; nsNum < f.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", f.CaseBaseName, nsNum)
		fmt.Printf("Checking resources in namespaces ...%s\n", namespace)
		//Check namespace
		checkNS, err := GetNamespace(f.Ctx, f.Client, namespace)
		if err != nil {
			return errors.Wrapf(err, "Could not retrieve test namespace %s", namespace)
		}
		if checkNS.Name != namespace {
			return errors.Errorf("Retrieved namespace for %s has name %s instead", namespace, checkNS.Name)
		}
		//Check deployment
		_, err = GetDeployment(f.Client.ClientGo, namespace, f.CaseBaseName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list deployment in namespace: %q", namespace))
		}

		//Check secrets
		secretsList, err := f.Client.ClientGo.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: f.labelSelector})
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list secrets in namespace: %q", namespace))
		} else if len(secretsList.Items) == 0 {
			return errors.Wrap(err, fmt.Sprintf("no secrets found in namespace: %q", namespace))
		}

		//Check configmap
		configmapList, err := f.Client.ClientGo.CoreV1().ConfigMaps(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: f.labelSelector})
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to list configmap in namespace: %q", namespace))
		} else if len(configmapList.Items) == 0 {
			return errors.Wrap(err, fmt.Sprintf("no configmap found in namespace: %q", namespace))
		}
	}
	return nil
}
