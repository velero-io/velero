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

package resourcemodifiers

import (
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

var yamlData = `
version: v1
resourceModifierRules:
- conditions:
    groupResource: deployments.apps
    resourceNameRegex: "resource-modifiers-.*"
  patches:
  - operation: add
    path: "/spec/template/spec/containers/1"
    value: "{\"name\": \"nginx\", \"image\": \"nginx:1.14.2\", \"ports\": [{\"containerPort\": 80}]}"
  - operation: replace
    path: "/spec/replicas"
    value: "2"
`

type ResourceModifiersCase struct {
	TestCase
	cmName, yamlConfig string
}

var ResourceModifiersTest func() = TestFunc(&ResourceModifiersCase{})

func (r *ResourceModifiersCase) Init() error {
	// generate random number as UUIDgen and set one default timeout duration
	r.TestCase.Init()

	// generate variable names based on CaseBaseName + UUIDgen
	r.CaseBaseName = "resource-modifiers-" + r.UUIDgen
	r.BackupName = "backup-" + r.CaseBaseName
	r.RestoreName = "restore-" + r.CaseBaseName
	r.cmName = "cm-" + r.CaseBaseName

	// generate namespaces by NamespacesTotal
	r.NamespacesTotal = 1
	r.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)
		*r.NSIncluded = append(*r.NSIncluded, createNSName)
	}

	// assign values to the inner variable for specific case
	r.yamlConfig = yamlData
	r.VeleroCfg.UseVolumeSnapshots = false
	r.VeleroCfg.UseNodeAgent = false

	r.BackupArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "backup", r.BackupName,
		"--include-namespaces", strings.Join(*r.NSIncluded, ","),
		"--snapshot-volumes=false", "--wait",
	}

	r.RestoreArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "restore", r.RestoreName,
		"--resource-modifier-configmap", r.cmName,
		"--from-backup", r.BackupName, "--wait",
	}

	// Message output by ginkgo
	r.TestMsg = &TestMSG{
		Desc:      "Validate resource modifiers",
		FailedMSG: "Failed to apply and / or validate resource modifiers in restored resources.",
		Text:      "Should be able to apply and validate resource modifiers in restored resources.",
	}
	return nil
}

func (r *ResourceModifiersCase) CreateResources() error {
	By(fmt.Sprintf("Create configmap %s in namespaces %s for workload\n", r.cmName, r.VeleroCfg.VeleroNamespace), func() {
		Expect(CreateConfigMapFromYAMLData(r.Client.ClientGo, r.yamlConfig, r.cmName, r.VeleroCfg.VeleroNamespace)).To(Succeed(), fmt.Sprintf("Failed to create configmap %s in namespaces %s for workload\n", r.cmName, r.VeleroCfg.VeleroNamespace))
	})

	By(fmt.Sprintf("Waiting for configmap %s in namespaces %s ready\n", r.cmName, r.VeleroCfg.VeleroNamespace), func() {
		Expect(WaitForConfigMapComplete(r.Client.ClientGo, r.VeleroCfg.VeleroNamespace, r.cmName)).To(Succeed(), fmt.Sprintf("Failed to wait configmap %s in namespaces %s ready\n", r.cmName, r.VeleroCfg.VeleroNamespace))
	})

	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		namespace := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)
		nsLabels := make(map[string]string)
		if r.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			nsLabels = map[string]string{
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "latest",
			}
		}

		By(fmt.Sprintf("Create namespaces %s for workload\n", namespace), func() {
			Expect(CreateNamespaceWithLabel(r.Ctx, r.Client, namespace, nsLabels)).To(Succeed(), fmt.Sprintf("Failed to create namespace %s", namespace))
		})

		By(fmt.Sprintf("Creating deployment in namespaces ...%s\n", namespace), func() {
			Expect(r.createDeployment(namespace)).To(Succeed(), fmt.Sprintf("Failed to create deployment namespace %s", namespace))
		})
	}
	return nil
}

func (r *ResourceModifiersCase) Verify() error {
	for _, ns := range *r.NSIncluded {
		By("Verify deployment has updated values", func() {
			deploy, err := GetDeployment(r.Client.ClientGo, ns, r.CaseBaseName)
			Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("Failed to get deployment %s in namespace %s", r.CaseBaseName, ns))

			Expect(*deploy.Spec.Replicas).To(Equal(int32(2)), fmt.Sprintf("Failed to verify deployment %s's replicas in namespace %s", r.CaseBaseName, ns))
			Expect(deploy.Spec.Template.Spec.Containers[1].Image).To(Equal("nginx:1.14.2"), fmt.Sprintf("Failed to verify deployment %s's image in namespace %s", r.CaseBaseName, ns))
		})
	}
	return nil
}

func (r *ResourceModifiersCase) Clean() error {
	// If created some resources which is not in current test namespace, we NEED to override the base Clean function
	if CurrentSpecReport().Failed() && r.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		if err := DeleteConfigMap(r.Client.ClientGo, r.VeleroCfg.VeleroNamespace, r.cmName); err != nil {
			return err
		}

		return r.GetTestCase().Clean() // only clean up resources in test namespace
	}

	return nil
}

func (r *ResourceModifiersCase) createDeployment(namespace string) error {
	deployment := NewDeployment(
		r.CaseBaseName,
		namespace,
		1,
		map[string]string{"app": "test"},
		r.VeleroCfg.ImageRegistryProxy,
		r.VeleroCfg.WorkerOS,
	).Result()
	deployment, err := CreateDeployment(r.Client.ClientGo, namespace, deployment)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create deloyment %s the namespace %q", deployment.Name, namespace))
	}
	err = WaitForReadyDeployment(r.Client.ClientGo, namespace, deployment.Name)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to wait for deployment %s to be ready in namespace: %q", deployment.Name, namespace))
	}
	return nil
}
