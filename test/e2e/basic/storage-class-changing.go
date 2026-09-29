package basic

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

type StorageClasssChanging struct {
	TestCase
	labels          map[string]string
	data            map[string]string
	cmName          string
	namespace       string
	srcStorageClass string
	desStorageClass string
	pvcName         string
	volume          string
	podName         string
	mappedNS        string
	deploymentName  string
}

const SCCBaseName string = "scc-"

var StorageClasssChangingTest func() = TestFunc(&StorageClasssChanging{})

func (s *StorageClasssChanging) Init() error {
	s.TestCase.Init()
	s.CaseBaseName = SCCBaseName + s.UUIDgen
	s.namespace = s.CaseBaseName
	s.BackupName = "backup-" + s.CaseBaseName
	s.RestoreName = "restore-" + s.CaseBaseName
	s.mappedNS = s.namespace + "-mapped"
	s.TestMsg = &TestMSG{
		Desc:      "Changing PV/PVC Storage Classes",
		FailedMSG: "Failed to changing PV/PVC Storage Classes",
		Text: "Change the storage class of persistent volumes and persistent" +
			" volume claims during restores",
	}
	if StorageClassName2 == "" {
		Skip("this case needs a second StorageClass; set --storage-class-2 to run it")
	}
	s.srcStorageClass = StorageClassName
	s.desStorageClass = StorageClassName2
	s.labels = map[string]string{"velero.io/change-storage-class": "RestoreItemAction",
		"velero.io/plugin-config": ""}
	s.data = map[string]string{s.srcStorageClass: s.desStorageClass}
	s.cmName = "change-storage-class-config"
	s.volume = "volume-1"
	s.pvcName = fmt.Sprintf("pvc-%s", s.volume)
	s.podName = "pod-1"
	s.BackupArgs = []string{
		"create", "--namespace", s.VeleroCfg.VeleroNamespace, "backup", s.BackupName,
		"--include-namespaces", s.namespace,
		"--snapshot-volumes=false", "--wait",
	}
	s.RestoreArgs = []string{
		"create", "--namespace", s.VeleroCfg.VeleroNamespace, "restore", s.RestoreName,
		"--from-backup", s.BackupName, "--namespace-mappings", fmt.Sprintf("%s:%s", s.namespace, s.mappedNS), "--wait",
	}
	return nil
}

func (s *StorageClasssChanging) CreateResources() error {
	label := map[string]string{
		"app": "test",
	}

	By(fmt.Sprintf("Create namespace %s", s.namespace), func() {
		nsLabels := make(map[string]string)
		if s.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			nsLabels = map[string]string{
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "latest",
			}
		}
		Expect(CreateNamespaceWithLabel(s.Ctx, s.Client, s.namespace, nsLabels)).To(Succeed(),
			fmt.Sprintf("Failed to create namespace %s", s.namespace))
	})

	By(fmt.Sprintf("Create a deployment in namespace %s", s.VeleroCfg.VeleroNamespace), func() {
		pvc, err := CreatePVC(s.Client, s.namespace, s.pvcName, s.srcStorageClass, nil)
		Expect(err).To(Succeed())
		vols := CreateVolumes(pvc.Name, []string{s.volume})

		deployment := NewDeployment(
			s.CaseBaseName,
			s.namespace,
			1,
			label,
			s.VeleroCfg.ImageRegistryProxy,
			s.VeleroCfg.WorkerOS,
		).WithVolume(vols).Result()
		deployment, err = CreateDeployment(s.Client.ClientGo, s.namespace, deployment)
		Expect(err).To(Succeed())
		s.deploymentName = deployment.Name
		err = WaitForReadyDeployment(s.Client.ClientGo, s.namespace, s.deploymentName)
		Expect(err).To(Succeed())
	})

	By(fmt.Sprintf("Create ConfigMap %s in namespace %s", s.cmName, s.VeleroCfg.VeleroNamespace), func() {
		_, err := CreateConfigMap(s.Client.ClientGo, s.VeleroCfg.VeleroNamespace, s.cmName, s.labels, s.data)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to create configmap in the namespace %q", s.VeleroCfg.VeleroNamespace))
	})
	return nil
}

func (s *StorageClasssChanging) Destroy() error {
	By(fmt.Sprintf("Expect storage class of PV %s to be %s ", s.volume, s.srcStorageClass), func() {
		pvName, err := GetPVByPVCName(s.Client, s.namespace, s.pvcName)
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to get PV name by PVC name %s", s.pvcName))
		pv, err := GetPersistentVolume(s.Ctx, s.Client, s.namespace, pvName)
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to get PV by name %s", pvName))
		Expect(pv.Spec.StorageClassName).To(Equal(s.srcStorageClass),
			fmt.Sprintf("PV storage %s is not as expected %s", pv.Spec.StorageClassName, s.srcStorageClass))
	})

	return nil
}

func (s *StorageClasssChanging) Restore() error {
	By(fmt.Sprintf("Start to restore %s .....", s.RestoreName), func() {
		Expect(VeleroRestoreExec(s.Ctx, s.VeleroCfg.VeleroCLI,
			s.VeleroCfg.VeleroNamespace, s.RestoreName,
			s.RestoreArgs, velerov1api.RestorePhaseCompleted)).To(
			Succeed(),
			func() string {
				RunDebug(context.Background(), s.VeleroCfg.VeleroCLI,
					s.VeleroCfg.VeleroNamespace, "", s.RestoreName)
				return "Fail to restore workload"
			})
	})
	return nil
}
func (s *StorageClasssChanging) Verify() error {
	By(fmt.Sprintf("Expect storage class of PV %s to be %s ", s.volume, s.desStorageClass), func() {
		Expect(WaitForReadyDeployment(s.Client.ClientGo, s.mappedNS, s.deploymentName)).To(Succeed())
		pvName, err := GetPVByPVCName(s.Client, s.mappedNS, s.pvcName)
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to get PV name by pod name %s", s.podName))
		pv, err := GetPersistentVolume(s.Ctx, s.Client, s.mappedNS, pvName)
		Expect(err).To(Succeed(), fmt.Sprintf("Failed to get PV by pod name %s", s.podName))
		Expect(pv.Spec.StorageClassName).To(Equal(s.desStorageClass),
			fmt.Sprintf("PV storage %s is not as expected %s", pv.Spec.StorageClassName, s.desStorageClass))
	})
	return nil
}

func (s *StorageClasssChanging) Clean() error {
	if CurrentSpecReport().Failed() && s.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		By(fmt.Sprintf("Start to destroy namespace %s......", s.CaseBaseName), func() {
			Expect(CleanupNamespacesWithPoll(s.Ctx, s.Client, s.CaseBaseName)).To(Succeed(),
				fmt.Sprintf("Failed to delete namespace %s", s.CaseBaseName))
		})
		DeleteConfigMap(s.Client.ClientGo, s.VeleroCfg.VeleroNamespace, s.cmName)
		s.TestCase.Clean()
	}

	return nil
}
