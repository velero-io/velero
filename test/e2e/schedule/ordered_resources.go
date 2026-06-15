package schedule

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

//the ordered resources test related to https://github.com/vmware-tanzu/velero/issues/4561
import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"
	waitutil "k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	framework "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	k8sutil "github.com/vmware-tanzu/velero/test/util/k8s"
	veleroutil "github.com/vmware-tanzu/velero/test/util/velero"
)

var ScheduleOrderedResources func() = framework.TestFunc(&OrderedResources{})

type OrderedResources struct {
	Namespace     string
	ScheduleName  string
	OrderResource map[string]string
	ScheduleArgs  []string
	framework.TestCase
}

func (o *OrderedResources) Init() error {
	Expect(o.TestCase.Init()).To(Succeed())

	o.CaseBaseName = "ordered-resources-" + o.UUIDgen
	o.ScheduleName = "schedule-" + o.CaseBaseName
	o.Namespace = o.CaseBaseName + "-" + o.UUIDgen

	o.OrderResource = map[string]string{
		"deployments": fmt.Sprintf("deploy-%s", o.CaseBaseName),
		"secrets":     fmt.Sprintf("secret-%s", o.CaseBaseName),
		"configmaps":  fmt.Sprintf("configmap-%s", o.CaseBaseName),
	}

	orderResourceArray := make([]string, 0)
	for k, v := range o.OrderResource {
		orderResourceArray = append(
			orderResourceArray,
			fmt.Sprintf("%s=%s", k, v),
		)
	}
	orderResourceStr := strings.Join(orderResourceArray, ";")

	o.TestMsg = &framework.TestMSG{
		Desc:      "Create a schedule to backup resources in a specific order should be successful",
		FailedMSG: "Failed to verify schedule backup resources in a specific order",
		Text:      "Create a schedule to backup resources in a specific order should be successful",
	}

	o.ScheduleArgs = []string{
		"--schedule",
		"@every 1m",
		"--include-namespaces",
		o.Namespace,
		"--default-volumes-to-fs-backup",
		"--ordered-resources",
		orderResourceStr,
	}

	return nil
}

func (o *OrderedResources) CreateResources() error {
	label := map[string]string{
		"orderedresources": "true",
	}
	fmt.Printf("Creating resources in %s namespace ...\n", o.Namespace)

	nsLabels := make(map[string]string)
	if o.VeleroCfg.WorkerOS == common.WorkerOSWindows {
		nsLabels = map[string]string{
			"pod-security.kubernetes.io/enforce":         "privileged",
			"pod-security.kubernetes.io/enforce-version": "latest",
		}
	}
	if err := k8sutil.CreateNamespaceWithLabel(o.Ctx, o.Client, o.Namespace, nsLabels); err != nil {
		return errors.Wrapf(err, "failed to create namespace %s", o.Namespace)
	}

	//Create deployment
	deploymentName := fmt.Sprintf("deploy-%s", o.CaseBaseName)
	fmt.Printf("Creating deployment %s in %s namespaces ...\n", deploymentName, o.Namespace)
	deployment := k8sutil.NewDeployment(
		deploymentName,
		o.Namespace,
		1,
		label,
		o.VeleroCfg.ImageRegistryProxy,
		o.VeleroCfg.WorkerOS,
	).Result()
	_, err := k8sutil.CreateDeployment(o.Client.ClientGo, o.Namespace, deployment)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create namespace %q with err %v", o.Namespace, err))
	}
	err = k8sutil.WaitForReadyDeployment(o.Client.ClientGo, o.Namespace, deployment.Name)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to ensure job completion in namespace: %q", o.Namespace))
	}

	//Create Secret
	secretName := fmt.Sprintf("secret-%s", o.CaseBaseName)
	fmt.Printf("Creating secret %s in %s namespaces ...\n", secretName, o.Namespace)
	_, err = k8sutil.CreateSecret(o.Client.ClientGo, o.Namespace, secretName, label)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create secret in the namespace %q", o.Namespace))
	}

	//Create ConfigMap
	cmName := fmt.Sprintf("configmap-%s", o.CaseBaseName)
	fmt.Printf("Creating ConfigMap %s in %s namespaces ...\n", cmName, o.Namespace)
	if _, err := k8sutil.CreateConfigMap(
		o.Client.ClientGo,
		o.Namespace,
		cmName,
		label,
		nil,
	); err != nil {
		return errors.Wrap(
			err,
			fmt.Sprintf("failed to create ConfigMap in the namespace %q", o.Namespace),
		)
	}

	return nil
}

func (o *OrderedResources) Backup() error {
	By(fmt.Sprintf("Create schedule the workload in %s namespace", o.Namespace), func() {
		err := veleroutil.VeleroScheduleCreate(
			o.Ctx,
			o.VeleroCfg.VeleroCLI,
			o.VeleroCfg.VeleroNamespace,
			o.ScheduleName,
			o.ScheduleArgs,
		)
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to create schedule %s  with err %v", o.ScheduleName, err))
	})

	By(fmt.Sprintf("Checking resource order in %s schedule CR", o.ScheduleName), func() {
		err := veleroutil.CheckScheduleWithResourceOrder(
			o.Ctx,
			o.VeleroCfg.VeleroCLI,
			o.VeleroCfg.VeleroNamespace,
			o.ScheduleName,
			o.OrderResource,
		)
		Expect(err).To(
			Succeed(),
			fmt.Sprintf("Failed to check schedule %s with err %v", o.ScheduleName, err),
		)
	})

	By("Checking resource order in backup cr", func() {
		err := waitutil.PollUntilContextTimeout(
			o.Ctx,
			30*time.Second,
			time.Minute*5,
			true,
			func(ctx context.Context) (bool, error) {
				backupList := new(velerov1api.BackupList)

				if err := o.Client.Kubebuilder.List(
					o.Ctx,
					backupList,
					&kbclient.ListOptions{
						Namespace: o.VeleroCfg.VeleroNamespace,
						LabelSelector: labels.SelectorFromSet(map[string]string{
							velerov1api.ScheduleNameLabel: o.ScheduleName,
						}),
					},
				); err != nil {
					return false, fmt.Errorf("failed to list backup in %s namespace for schedule %s: %s",
						o.VeleroCfg.VeleroNamespace, o.ScheduleName, err.Error())
				}

				for _, backup := range backupList.Items {
					if err := veleroutil.CheckBackupWithResourceOrder(
						o.Ctx,
						o.VeleroCfg.VeleroCLI,
						o.VeleroCfg.VeleroNamespace,
						backup.Name,
						o.OrderResource,
					); err == nil {
						// After schedule successfully triggers a backup,
						// the workload namespace is deleted.
						// It's possible the following backup may fail.
						// As a result, as long as there is one backup in Completed state,
						// the case assumes test pass.
						return true, nil
					}
				}
				fmt.Printf("still finding backup created by schedule %s ...\n", o.ScheduleName)
				return false, nil
			})
		Expect(err).To(
			Succeed(),
			fmt.Sprintf("Failed to check schedule %s created backup with err %v",
				o.ScheduleName, err),
		)
	})
	return nil
}

func (o *OrderedResources) Clean() error {
	if CurrentSpecReport().Failed() && o.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		Expect(veleroutil.VeleroScheduleDelete(
			o.Ctx,
			o.VeleroCfg.VeleroCLI,
			o.VeleroCfg.VeleroNamespace,
			o.ScheduleName,
		)).To(Succeed())

		Expect(o.TestCase.Clean()).To(Succeed())
	}

	return nil
}
