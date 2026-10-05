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

package repomaintenance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/gomega"
	batchv1api "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	velerokubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	k8sutil "github.com/vmware-tanzu/velero/test/util/k8s"
	veleroutil "github.com/vmware-tanzu/velero/test/util/velero"
)

type RepoMaintenanceTestCase struct {
	TestCase
	repoMaintenanceConfigMapName string
	repoMaintenanceConfigKey     string
	jobConfigs                   velerotypes.JobConfigs
}

var keepJobNum = 1

var GlobalRepoMaintenanceTest func() = TestFunc(&RepoMaintenanceTestCase{
	repoMaintenanceConfigKey:     "global",
	repoMaintenanceConfigMapName: "global",
	jobConfigs: velerotypes.JobConfigs{
		KeepLatestMaintenanceJobs: &keepJobNum,
		PodResources: &velerokubeutil.PodResources{
			CPURequest:              "100m",
			MemoryRequest:           "100Mi",
			EphemeralStorageRequest: "5Gi",
			CPULimit:                "200m",
			MemoryLimit:             "200Mi",
			EphemeralStorageLimit:   "10Gi",
		},
		PriorityClassName: test.PriorityClassNameForRepoMaintenance,
	},
})

var SpecificRepoMaintenanceTest func() = TestFunc(&RepoMaintenanceTestCase{
	repoMaintenanceConfigKey:     "",
	repoMaintenanceConfigMapName: "specific",
	jobConfigs: velerotypes.JobConfigs{
		KeepLatestMaintenanceJobs: &keepJobNum,
		PodResources: &velerokubeutil.PodResources{
			CPURequest:              "100m",
			MemoryRequest:           "100Mi",
			EphemeralStorageRequest: "5Gi",
			CPULimit:                "200m",
			MemoryLimit:             "200Mi",
			EphemeralStorageLimit:   "10Gi",
		},
		PriorityClassName: test.PriorityClassNameForRepoMaintenance,
	},
})

func (r *RepoMaintenanceTestCase) Init() error {
	// generate random number as UUIDgen and set one default timeout duration
	r.TestCase.Init()

	// generate variable names based on CaseBaseName + UUIDgen
	r.CaseBaseName = "repo-maintenance-" + r.UUIDgen
	r.BackupName = "backup-" + r.CaseBaseName
	r.RestoreName = "restore-" + r.CaseBaseName

	// generate namespaces by NamespacesTotal
	r.NamespacesTotal = 1
	r.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < r.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", r.CaseBaseName, nsNum)
		*r.NSIncluded = append(*r.NSIncluded, createNSName)
	}

	// If repoMaintenanceConfigKey is not set, it means testing the specific repo case.
	// Need to assemble the BackupRepository name. The format is "volumeNamespace-bslName-uploaderName"
	if r.repoMaintenanceConfigKey == "" {
		r.repoMaintenanceConfigKey = (*r.NSIncluded)[0] + "-" + "default" + "-" + test.UploaderTypeKopia
	}

	// assign values to the inner variable for specific case
	r.VeleroCfg.UseNodeAgent = true
	r.VeleroCfg.UseNodeAgentWindows = true

	r.BackupArgs = []string{
		"create", "--namespace", r.VeleroCfg.VeleroNamespace, "backup", r.BackupName,
		"--include-namespaces", strings.Join(*r.NSIncluded, ","),
		"--snapshot-volumes=true", "--snapshot-move-data", "--wait",
	}

	// Message output by ginkgo
	r.TestMsg = &TestMSG{
		Desc:      "Validate Repository Maintenance Job configuration",
		FailedMSG: "Failed to apply and / or validate configuration in repository maintenance jobs.",
		Text:      "Should be able to apply and validate configuration in repository maintenance jobs.",
	}
	return nil
}

func (r *RepoMaintenanceTestCase) InstallVelero() error {
	// Because this test needs to use customized repository maintenance ConfigMap,
	// need to uninstall and reinstall Velero.

	fmt.Println("Start to uninstall Velero")
	if err := veleroutil.VeleroUninstall(r.Ctx, r.VeleroCfg); err != nil {
		fmt.Printf("Fail to uninstall Velero: %s\n", err.Error())
		return err
	}

	result, err := json.Marshal(r.jobConfigs)
	if err != nil {
		return err
	}

	repoMaintenanceConfig := builder.ForConfigMap(r.VeleroCfg.VeleroNamespace, r.repoMaintenanceConfigMapName).
		Data(r.repoMaintenanceConfigKey, string(result)).Result()

	r.VeleroCfg.RepoMaintenanceJobConfigMap = r.repoMaintenanceConfigMapName

	return veleroutil.PrepareVelero(
		r.Ctx,
		r.CaseBaseName,
		r.VeleroCfg,
		repoMaintenanceConfig,
	)
}

func (r *RepoMaintenanceTestCase) CreateResources() error {
	for _, ns := range *r.NSIncluded {
		if err := k8sutil.CreateNamespace(r.Ctx, r.Client, ns); err != nil {
			fmt.Printf("Fail to create ns %s: %s\n", ns, err.Error())
			return err
		}

		pvc, err := k8sutil.CreatePVC(r.Client, ns, "volume-1", test.StorageClassName, nil)
		if err != nil {
			fmt.Printf("Fail to create PVC %s: %s\n", "volume-1", err.Error())
			return err
		}

		vols := k8sutil.CreateVolumes(pvc.Name, []string{"volume-1"})

		deployment := k8sutil.NewDeployment(
			r.CaseBaseName,
			(*r.NSIncluded)[0],
			1,
			map[string]string{"app": "test"},
			r.VeleroCfg.ImageRegistryProxy,
			r.VeleroCfg.WorkerOS,
		).WithVolume(vols).Result()

		deployment, err = k8sutil.CreateDeployment(r.Client.ClientGo, ns, deployment)
		if err != nil {
			fmt.Printf("Fail to create deployment %s: %s \n", deployment.Name, err.Error())
			return errors.Wrap(err, fmt.Sprintf("failed to create deployment: %s", err.Error()))
		}

		if err := k8sutil.WaitForReadyDeployment(r.Client.ClientGo, deployment.Namespace, deployment.Name); err != nil {
			fmt.Printf("Fail to create deployment %s: %s\n", r.CaseBaseName, err.Error())
			return err
		}
	}

	return nil
}

func (r *RepoMaintenanceTestCase) Verify() error {
	// Reduce the MaintenanceFrequency to 1 minute.
	backupRepositoryList := new(velerov1api.BackupRepositoryList)
	if err := r.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(
		r.Ctx,
		backupRepositoryList,
		&client.ListOptions{
			Namespace:     r.VeleroCfg.Namespace,
			LabelSelector: labels.SelectorFromSet(map[string]string{velerov1api.VolumeNamespaceLabel: (*r.NSIncluded)[0]}),
		},
	); err != nil {
		return err
	}

	if len(backupRepositoryList.Items) <= 0 {
		return fmt.Errorf("fail list BackupRepository. no item is returned")
	}

	backupRepository := backupRepositoryList.Items[0]

	updated := backupRepository.DeepCopy()
	updated.Spec.MaintenanceFrequency = metav1.Duration{Duration: time.Minute}
	if err := r.VeleroCfg.ClientToInstallVelero.Kubebuilder.Patch(r.Ctx, updated, client.MergeFrom(&backupRepository)); err != nil {
		fmt.Printf("failed to patch BackupRepository %q: %s", backupRepository.GetName(), err.Error())
		return err
	}

	// The minimal time unit of Repository Maintenance is 5 minutes.
	// Wait for more than one cycles to make sure the result is valid.
	time.Sleep(6 * time.Minute)

	jobList := new(batchv1api.JobList)
	if err := r.VeleroCfg.ClientToInstallVelero.Kubebuilder.List(r.Ctx, jobList, &client.ListOptions{
		Namespace:     r.VeleroCfg.Namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{"velero.io/repo-name": backupRepository.Name}),
	}); err != nil {
		return nil
	}

	resources, err := kube.ParseResourceRequirements(
		r.jobConfigs.PodResources.CPURequest,
		r.jobConfigs.PodResources.MemoryRequest,
		r.jobConfigs.PodResources.EphemeralStorageRequest,
		r.jobConfigs.PodResources.CPULimit,
		r.jobConfigs.PodResources.MemoryLimit,
		r.jobConfigs.PodResources.EphemeralStorageLimit,
	)
	if err != nil {
		return errors.Wrap(err, "failed to parse resource requirements for maintenance job")
	}

	Expect(jobList.Items[0].Spec.Template.Spec.Containers[0].Resources).To(Equal(resources))

	Expect(jobList.Items).To(HaveLen(*r.jobConfigs.KeepLatestMaintenanceJobs))

	Expect(jobList.Items[0].Spec.Template.Spec.PriorityClassName).To(Equal(r.jobConfigs.PriorityClassName))

	return nil
}
