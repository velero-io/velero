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

package resourcepolicies

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

const FileName = "test-data.txt"

var yamlData = `version: v1
volumePolicies:
- conditions:
    capacity: "2Gi,3Gi"
  action:
    type: skip
- conditions:
    storageClass:
    - e2e-storage-class
  action:
    type: skip
`

type ResourcePoliciesCase struct {
	TestCase
	cmName, yamlConfig string
}

var ResourcePoliciesTest func() = TestFunc(&ResourcePoliciesCase{})

func (r *ResourcePoliciesCase) Init() error {
	// generate random number as UUIDgen and set one default timeout duration
	r.TestCase.Init()

	// generate variable names based on CaseBaseName + UUIDgen
	r.CaseBaseName = "resource-policies-" + r.UUIDgen
	r.BackupName = "backup-" + r.CaseBaseName
	r.RestoreName = "restore-" + r.CaseBaseName
	r.cmName = "cm-" + r.CaseBaseName

	// generate namespaces by NamespacesTotal
	r.NamespacesTotal = 3
	r.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)
		*r.NSIncluded = append(*r.NSIncluded, createNSName)
	}

	// assign values to the inner variable for specific case
	r.yamlConfig = yamlData
	r.VeleroCfg.UseVolumeSnapshots = false
	r.VeleroCfg.UseNodeAgent = true

	// NEED explicitly specify the value of the variables for snapshot-volumes or default-volumes-to-fs-backup
	r.BackupArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "backup", r.BackupName,
		"--resource-policies-configmap", r.cmName,
		"--include-namespaces", strings.Join(*r.NSIncluded, ","),
		"--default-volumes-to-fs-backup",
		"--snapshot-volumes=false", "--wait",
	}

	r.RestoreArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "restore", r.RestoreName,
		"--from-backup", r.BackupName, "--wait",
	}

	// Message output by ginkgo
	r.TestMsg = &TestMSG{
		Desc:      "Skip backup of volume by resource policies",
		FailedMSG: "Failed to skip backup of volume by resource policies",
		Text:      fmt.Sprintf("Should backup PVs in namespace %s respect to resource policies rules", *r.NSIncluded),
	}
	return nil
}

func (r *ResourcePoliciesCase) CreateResources() error {
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

		volName := fmt.Sprintf("vol-%s-%00000d", r.CaseBaseName, nsNum)
		volList := PrepareVolumeList([]string{volName})

		// Create PVC
		By(fmt.Sprintf("Creating pvc in namespaces ...%s\n", namespace), func() {
			Expect(r.createPVC(nsNum, namespace, volList)).To(Succeed(), fmt.Sprintf("Failed to create pvc in namespace %s", namespace))
		})

		// Create deployment
		By(fmt.Sprintf("Creating deployment in namespaces ...%s\n", namespace), func() {
			Expect(r.createDeploymentWithVolume(namespace, volList)).To(Succeed(), fmt.Sprintf("Failed to create deployment namespace %s", namespace))
		})

		//Write data into pods
		By(fmt.Sprintf("Writing data into pod in namespaces ...%s\n", namespace), func() {
			Expect(r.writeDataIntoPods(namespace, volName)).To(Succeed(), fmt.Sprintf("Failed to write data into pod in namespace %s", namespace))
		})
	}

	return nil
}

func (r *ResourcePoliciesCase) Verify() error {
	for i, ns := range *r.NSIncluded {
		By(fmt.Sprintf("Verify pod data in namespace %s", ns), func() {
			By(fmt.Sprintf("Waiting for deployment %s in namespace %s ready", r.CaseBaseName, ns), func() {
				Expect(WaitForReadyDeployment(r.Client.ClientGo, ns, r.CaseBaseName)).To(Succeed(), fmt.Sprintf("Failed to waiting for deployment %s in namespace %s ready", r.CaseBaseName, ns))
			})
			podList, err := ListPods(r.Ctx, r.Client, ns)
			Expect(err).To(Succeed(), fmt.Sprintf("failed to list pods in namespace: %q with error %v", ns, err))

			volName := fmt.Sprintf("vol-%s-%00000d", r.CaseBaseName, i)
			for _, pod := range podList.Items {
				for _, vol := range pod.Spec.Volumes {
					if vol.Name != volName {
						continue
					}
					content, _, err := ReadFileFromPodVolume(
						ns,
						pod.Name,
						"container-busybox",
						vol.Name,
						FileName,
						r.VeleroCfg.WorkerOS,
					)
					if i%2 == 0 {
						Expect(err).To(HaveOccurred(), "Expected file not found") // File should not exist
					} else {
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Fail to read file %s from volume %s of pod %s in namespace %s",
							FileName, vol.Name, pod.Name, ns))

						content = strings.TrimRightFunc(content, unicode.IsSpace)
						originContent := fmt.Sprintf("ns-%s pod-%s volume-%s", ns, pod.Name, vol.Name)

						Expect(content).To(Equal(originContent),
							fmt.Sprintf("Content not match.\n origin: %s\n result: %s\n", originContent, content),
						)
					}
				}
			}
		})
	}
	return nil
}

func (r *ResourcePoliciesCase) Clean() error {
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

func (r *ResourcePoliciesCase) createPVC(index int, namespace string, volList []*corev1api.Volume) error {
	var err error
	for i := range volList {
		pvcName := fmt.Sprintf("pvc-%d", i)
		By(fmt.Sprintf("Creating PVC %s in namespaces ...%s\n", pvcName, namespace))
		if index%3 == 0 {
			pvcBuilder := NewPVC(namespace, pvcName).WithStorageClass(StorageClassName) // Testing sc should not backup
			err = CreatePvc(r.Client, pvcBuilder)
		} else if index%3 == 1 {
			pvcBuilder := NewPVC(namespace, pvcName).WithStorageClass(StorageClassName2) // Testing sc should backup
			err = CreatePvc(r.Client, pvcBuilder)
		} else if index%3 == 2 {
			pvcBuilder := NewPVC(namespace, pvcName).WithStorageClass(StorageClassName2).WithResourceStorage(resource.MustParse("2Gi")) // Testing capacity should not backup
			err = CreatePvc(r.Client, pvcBuilder)
		}
		if err != nil {
			return errors.Wrapf(err, "failed to create pvc %s in namespace %s", pvcName, namespace)
		}
	}
	return nil
}

func (r *ResourcePoliciesCase) createDeploymentWithVolume(namespace string, volList []*corev1api.Volume) error {
	deployment := NewDeployment(
		r.CaseBaseName,
		namespace,
		1,
		map[string]string{"resource-policies": "resource-policies"},
		r.VeleroCfg.ImageRegistryProxy,
		r.VeleroCfg.WorkerOS,
	).WithVolume(volList).Result()
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

func (r *ResourcePoliciesCase) writeDataIntoPods(namespace, volName string) error {
	podList, err := ListPods(r.Ctx, r.Client, namespace)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to list pods in namespace: %q with error %v", namespace, err))
	}
	for _, pod := range podList.Items {
		for _, vol := range pod.Spec.Volumes {
			if vol.Name != volName {
				continue
			}
			err := CreateFileToPod(
				namespace,
				pod.Name,
				"container-busybox",
				vol.Name,
				FileName,
				fmt.Sprintf("ns-%s pod-%s volume-%s", namespace, pod.Name, vol.Name),
				r.VeleroCfg.WorkerOS,
			)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed to create file into pod %s in namespace: %q", pod.Name, namespace))
			}
		}
	}
	return nil
}
