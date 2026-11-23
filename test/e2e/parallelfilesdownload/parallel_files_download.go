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

package parallelfilesdownload

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/velero-io/velero/test"
	. "github.com/velero-io/velero/test/e2e/test"
	"github.com/velero-io/velero/test/util/common"
	. "github.com/velero-io/velero/test/util/k8s"
)

type ParallelFilesDownload struct {
	TestCase
	parallel  string
	namespace string
	pod       string
	pvc       string
	volume    string
	fileName  string
	fileNum   int
	fileSize  int64
	hash      []string
}

var ParallelFilesDownloadTest func() = TestFunc(&ParallelFilesDownload{})

func (p *ParallelFilesDownload) Init() error {
	// generate random number as UUIDgen and set one default timeout duration
	p.TestCase.Init()

	// generate variable names based on CaseBaseName + UUIDgen
	p.CaseBaseName = "parallel-files-download" + p.UUIDgen
	p.BackupName = p.CaseBaseName + "-backup"
	p.RestoreName = p.CaseBaseName + "-restore"
	p.pod = p.CaseBaseName + "-pod"
	p.pvc = p.CaseBaseName + "-pvc"
	p.fileName = p.CaseBaseName + "-file"
	p.parallel = "3"
	p.fileNum = 10
	p.fileSize = 1 * 1024 * 1024 // 1MB
	p.volume = p.CaseBaseName + "-vol"

	// generate namespace
	p.VeleroCfg.UseVolumeSnapshots = false
	p.VeleroCfg.UseNodeAgent = true
	p.namespace = p.CaseBaseName + "-ns"

	p.BackupArgs = []string{
		"create", "--namespace", p.VeleroCfg.VeleroNamespace,
		"backup", p.BackupName,
		"--include-namespaces", p.namespace,
		"--default-volumes-to-fs-backup",
		"--snapshot-volumes=false",
		"--wait",
	}

	p.RestoreArgs = []string{
		"create", "--namespace", p.VeleroCfg.VeleroNamespace,
		"restore", p.RestoreName,
		"--parallel-files-download", p.parallel,
		"--from-backup", p.BackupName, "--wait",
	}

	// Message output by ginkgo
	p.TestMsg = &TestMSG{
		Desc:      "Test parallel files download",
		FailedMSG: "Failed to test parallel files download",
		Text:      "Test parallel files download with parallel download " + p.parallel + " files",
	}
	return nil
}

func (p *ParallelFilesDownload) CreateResources() error {
	By(fmt.Sprintf("Create namespace %s", p.namespace), func() {
		labels := make(map[string]string)
		if p.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			labels = map[string]string{
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "latest",
			}
		}
		Expect(CreateNamespaceWithLabel(p.Ctx, p.Client, p.namespace, labels)).To(Succeed(),
			fmt.Sprintf("Failed to create namespace %s", p.namespace))
	})

	By(fmt.Sprintf("Create pod %s in namespace %s", p.pod, p.namespace), func() {
		_, err := CreatePod(
			p.Client,
			p.namespace,
			p.pod,
			StorageClassName,
			p.pvc,
			[]string{p.volume},
			nil,
			nil,
			p.VeleroCfg.ImageRegistryProxy,
			p.VeleroCfg.WorkerOS,
		)
		Expect(err).To(Succeed())
		err = WaitForPods(p.Ctx, p.Client, p.namespace, []string{p.pod})
		Expect(err).To(Succeed())
	})

	podList, err := ListPods(p.Ctx, p.Client, p.namespace)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to list pods in namespace: %q with error %v", p.namespace, err))

	for _, pod := range podList.Items {
		for i := 0; i < p.fileNum; i++ {
			fileName := fmt.Sprintf("%s-%d", p.fileName, i)
			// Write random data to file in pod
			Expect(WriteRandomDataToFileInPod(p.Ctx, p.namespace, pod.Name, pod.Name, p.volume,
				fileName, p.fileSize)).To(Succeed())
			// Calculate hash of the file
			hash, err := CalFileHashInPod(p.Ctx, p.namespace, pod.Name, pod.Name, fmt.Sprintf("%s/%s", p.volume, fileName))
			Expect(err).To(Succeed())
			p.hash = append(p.hash, hash)
		}
	}

	return nil
}

func (p *ParallelFilesDownload) Verify() error {
	podList, err := ListPods(p.Ctx, p.Client, p.namespace)
	Expect(err).To(Succeed(), fmt.Sprintf("failed to list pods in namespace: %q with error %v", p.namespace, err))

	for _, pod := range podList.Items {
		err = WaitForPods(p.Ctx, p.Client, p.namespace, []string{pod.Name})
		Expect(err).To(Succeed())

		for i := 0; i < p.fileNum; i++ {
			fileName := fmt.Sprintf("%s-%d", p.fileName, i)
			// Calculate hash of the file
			hash, err := CalFileHashInPod(p.Ctx, p.namespace, pod.Name, pod.Name, fmt.Sprintf("%s/%s", p.volume, fileName))
			Expect(err).To(Succeed())
			Expect(hash).To(Equal(p.hash[i]))
		}
	}

	return nil
}
