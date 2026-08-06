package basic

import (
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/kibishii"
)

type NamespaceMapping struct {
	TestCase
	MappedNamespaceList []string
	kibishiiData        *KibishiiData
}

const NamespaceBaseName string = "ns-mp-"

var OneNamespaceMappingResticTest func() = TestFunc(&NamespaceMapping{TestCase: TestCase{NamespacesTotal: 1, UseVolumeSnapshots: false}})
var MultiNamespacesMappingResticTest func() = TestFunc(&NamespaceMapping{TestCase: TestCase{NamespacesTotal: 2, UseVolumeSnapshots: false}})
var OneNamespaceMappingSnapshotTest func() = TestFunc(&NamespaceMapping{TestCase: TestCase{NamespacesTotal: 1, UseVolumeSnapshots: true}})
var MultiNamespacesMappingSnapshotTest func() = TestFunc(&NamespaceMapping{TestCase: TestCase{NamespacesTotal: 2, UseVolumeSnapshots: true}})

func (n *NamespaceMapping) Init() error {
	n.TestCase.Init()
	n.CaseBaseName = "ns-mp-" + n.UUIDgen
	n.BackupName = "backup-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName
	n.VeleroCfg.UseVolumeSnapshots = n.UseVolumeSnapshots
	n.VeleroCfg.UseNodeAgent = !n.UseVolumeSnapshots
	n.kibishiiData = &KibishiiData{Levels: 2, DirsPerLevel: 10, FilesPerLevel: 10, FileLength: 1024, BlockSize: 1024, PassNum: 0, ExpectedNodes: 2}
	if n.VeleroCfg.CloudProvider == "kind" {
		n.kibishiiData = &KibishiiData{Levels: 0, DirsPerLevel: 0, FilesPerLevel: 0, FileLength: 0, BlockSize: 0, PassNum: 0, ExpectedNodes: 2}
	}
	backupType := "restic"
	if n.UseVolumeSnapshots {
		backupType = "snapshot"
	}
	var mappedNS string
	var mappedNSList []string
	n.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < n.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", n.CaseBaseName, nsNum)
		*n.NSIncluded = append(*n.NSIncluded, createNSName)
		mappedNS = mappedNS + createNSName + ":" + createNSName + "-mapped"
		mappedNSList = append(mappedNSList, createNSName+"-mapped")
		mappedNS = mappedNS + ","
	}
	mappedNS = strings.TrimRightFunc(mappedNS, func(r rune) bool {
		return r == ','
	})

	n.TestMsg = &TestMSG{
		Desc:      fmt.Sprintf("Restore namespace %s with namespace mapping by %s test", *n.NSIncluded, backupType),
		FailedMSG: "Failed to restore with namespace mapping",
		Text:      fmt.Sprintf("should restore namespace %s with namespace mapping by %s", *n.NSIncluded, backupType),
	}
	n.MappedNamespaceList = mappedNSList
	fmt.Println(mappedNSList)
	n.BackupArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "backup", n.BackupName,
		"--include-namespaces", strings.Join(*n.NSIncluded, ","), "--wait",
	}
	if n.VeleroCfg.CloudProvider == "kind" {
		// don't test volume snapshotter or file system backup on kind
		n.BackupArgs = append(n.BackupArgs, "--snapshot-volumes=false")
		n.UseVolumeSnapshots = false
	} else if n.UseVolumeSnapshots {
		n.BackupArgs = append(n.BackupArgs, "--snapshot-volumes")
	} else {
		n.BackupArgs = append(n.BackupArgs, "--snapshot-volumes=false")
		n.BackupArgs = append(n.BackupArgs, "--default-volumes-to-fs-backup")
	}
	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore", n.RestoreName,
		"--from-backup", n.BackupName, "--namespace-mappings", mappedNS,
		"--wait",
	}
	return nil
}

func (n *NamespaceMapping) CreateResources() error {
	for index, ns := range *n.NSIncluded {
		if n.VeleroCfg.CloudProvider != "kind" {
			n.kibishiiData.Levels = len(*n.NSIncluded) + index
		}
		By(fmt.Sprintf("Creating namespaces ...%s\n", ns), func() {
			Expect(CreateNamespace(n.Ctx, n.Client, ns)).To(Succeed(), fmt.Sprintf("Failed to create namespace %s", ns))
		})
		By("Deploy sample workload of Kibishii", func() {
			Expect(KibishiiPrepareBeforeBackup(
				n.Ctx,
				n.Client,
				n.VeleroCfg.CloudProvider,
				ns,
				n.VeleroCfg.RegistryCredentialFile,
				n.VeleroCfg.Features,
				n.VeleroCfg.KibishiiDirectory,
				n.kibishiiData,
				n.VeleroCfg.ImageRegistryProxy,
			)).To(Succeed())
		})
	}
	return nil
}

func (n *NamespaceMapping) Verify() error {
	for index, ns := range n.MappedNamespaceList {
		if n.VeleroCfg.CloudProvider != "kind" {
			n.kibishiiData.Levels = len(*n.NSIncluded) + index
		}
		By(fmt.Sprintf("Verify workload %s after restore ", ns), func() {
			Expect(KibishiiVerifyAfterRestore(n.Client, ns,
				n.Ctx, n.kibishiiData, "")).To(Succeed(), "Fail to verify workload after restore")
		})
	}
	for _, ns := range *n.NSIncluded {
		By(fmt.Sprintf("Verify namespace %s for backup is no longer exist after restore with namespace mapping", ns), func() {
			Expect(NamespaceShouldNotExist(n.Ctx, n.Client, ns)).To(Succeed())
		})
	}
	return nil
}

func (n *NamespaceMapping) Clean() error {
	if CurrentSpecReport().Failed() && n.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		if err := DeleteStorageClass(context.Background(), n.Client, KibishiiStorageClassName); err != nil {
			return err
		}
		for _, ns := range n.MappedNamespaceList {
			if err := DeleteNamespace(context.Background(), n.Client, ns, false); err != nil {
				return err
			}
		}

		return n.GetTestCase().Clean()
	}

	return nil
}
