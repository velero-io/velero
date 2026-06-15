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

package test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

/*
The VeleroBackupRestoreTest interface is just could be suit for the cases that follow the test flow of
create resources, backup, delete test resource, restore and verify.
And the cases have similar execute function and similar data. it's both fine for you to use it or not which
depends on your test patterns.
*/
type VeleroBackupRestoreTest interface {
	Init() error
	InstallVelero() error
	CreateResources() error
	Backup() error
	Destroy() error
	Restore() error
	Verify() error
	Clean() error
	Start() error
	GetTestMsg() *TestMSG
	GetTestCase() *TestCase
}

type TestMSG struct {
	Desc      string
	Text      string
	FailedMSG string
}

type TestCase struct {
	BackupName         string
	RestoreName        string
	CaseBaseName       string
	BackupArgs         []string
	RestoreArgs        []string
	NamespacesTotal    int
	TestMsg            *TestMSG
	Client             TestClient
	NSIncluded         *[]string
	UseVolumeSnapshots bool
	VeleroCfg          VeleroConfig
	RestorePhaseExpect velerov1api.RestorePhase
	Ctx                context.Context
	CtxCancel          context.CancelFunc
	UUIDgen            string
}

func TestFunc(test VeleroBackupRestoreTest) func() {
	return func() {
		TestIt(test)
	}
}

func TestFuncWithMultiIt(tests []VeleroBackupRestoreTest) func() {
	return func() {
		for k := range tests {
			TestIt(tests[k])
		}
	}
}

func TestIt(test VeleroBackupRestoreTest) error {
	It("Run E2E test case", func() {
		Expect(test.Init()).To(Succeed())

		Expect(RunTestCase(test)).To(Succeed(), test.GetTestMsg().FailedMSG)
	})
	return nil
}
func (t *TestCase) Init() error {
	t.UUIDgen = t.GenerateUUID()
	t.VeleroCfg = VeleroCfg
	t.Client = *t.VeleroCfg.ClientToInstallVelero
	return nil
}

func (t *TestCase) GenerateUUID() string {
	return fmt.Sprintf("%08d", rand.IntN(100000000))
}

func (t *TestCase) InstallVelero() error {
	return PrepareVelero(context.Background(), t.GetTestCase().CaseBaseName, t.GetTestCase().VeleroCfg)
}

func (t *TestCase) CreateResources() error {
	return nil
}

func (t *TestCase) Backup() error {
	veleroCfg := t.GetTestCase().VeleroCfg

	By("Start to backup ......", func() {
		Expect(VeleroBackupExec(t.Ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, t.BackupName, t.BackupArgs)).To(Succeed(), func() string {
			RunDebug(context.Background(), veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, t.BackupName, "")
			return "Failed to backup resources"
		})
	})

	return nil
}

func (t *TestCase) Destroy() error {
	By(fmt.Sprintf("Start to destroy namespace %s......", t.CaseBaseName), func() {
		Expect(CleanupNamespacesWithPoll(t.Ctx, t.Client, t.CaseBaseName)).To(Succeed(), "Could cleanup retrieve namespaces")
	})
	return nil
}

func (t *TestCase) Restore() error {
	if len(t.RestoreArgs) == 0 {
		return nil
	}

	veleroCfg := t.GetTestCase().VeleroCfg

	// the snapshots of AWS may be still in pending status when do the restore, wait for a while
	// to avoid this https://github.com/vmware-tanzu/velero/issues/1799
	// TODO remove this after https://github.com/vmware-tanzu/velero/issues/3533 is fixed
	By("Waiting 5 minutes to make sure the snapshots are ready...", func() {
		if t.UseVolumeSnapshots && veleroCfg.CloudProvider != Vsphere {
			time.Sleep(5 * time.Minute)
		}
	})

	By("Start to restore ......", func() {
		if t.RestorePhaseExpect == "" {
			t.RestorePhaseExpect = velerov1api.RestorePhaseCompleted
		}
		Expect(VeleroRestoreExec(t.Ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, t.RestoreName, t.RestoreArgs, t.RestorePhaseExpect)).To(Succeed(), func() string {
			RunDebug(context.Background(), veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, "", t.RestoreName)
			return "Fail to restore workload"
		})
	})
	return nil
}

func (t *TestCase) Verify() error {
	return nil
}

func (t *TestCase) Start() error {
	t.Ctx, t.CtxCancel = context.WithTimeout(context.Background(), 1*time.Hour)
	veleroCfg := t.GetTestCase().VeleroCfg

	if (veleroCfg.CloudProvider == Azure || veleroCfg.CloudProvider == AWS) &&
		strings.Contains(t.GetTestCase().CaseBaseName, "nodeport") {
		Skip("Skip due to issue https://github.com/kubernetes/kubernetes/issues/114384 on AKS")
	}

	return nil
}

func (t *TestCase) Clean() error {
	veleroCfg := t.GetTestCase().VeleroCfg
	if CurrentSpecReport().Failed() && veleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		By(fmt.Sprintf("Clean namespace with prefix %s after test", t.CaseBaseName), func() {
			if err := CleanupNamespaces(t.Ctx, t.Client, t.CaseBaseName); err != nil {
				fmt.Println("Fail to cleanup namespaces: ", err)
			}
		})
		By("Clean backups after test", func() {
			veleroCfg.ClientToInstallVelero = &t.Client
			if err := DeleteAllBackups(t.Ctx, &veleroCfg); err != nil {
				fmt.Println("Fail to clean backups after test: ", err)
			}
		})
	}

	return nil
}

func (t *TestCase) GetTestMsg() *TestMSG {
	return t.TestMsg
}

func (t *TestCase) GetTestCase() *TestCase {
	return t
}

func RunTestCase(test VeleroBackupRestoreTest) error {
	if test == nil {
		return errors.New("No case should be tested")
	}
	fmt.Println("Running case: ", test.GetTestMsg().Text)
	test.Start()
	defer test.GetTestCase().CtxCancel()

	fmt.Printf("Running test case %s %s\n", test.GetTestMsg().Desc, time.Now().Format("2006-01-02 15:04:05"))

	if InstallVelero {
		fmt.Printf("Install Velero for test case %s: %s", test.GetTestCase().CaseBaseName, time.Now().Format("2006-01-02 15:04:05"))
		Expect(test.InstallVelero()).To(Succeed())
	}

	defer test.Clean()

	fmt.Printf("CreateResources %s\n", time.Now().Format("2006-01-02 15:04:05"))
	err := test.CreateResources()
	if err != nil {
		return err
	}
	fmt.Printf("Backup %s\n", time.Now().Format("2006-01-02 15:04:05"))
	err = test.Backup()
	if err != nil {
		return err
	}
	fmt.Printf("Destroy %s\n", time.Now().Format("2006-01-02 15:04:05"))
	err = test.Destroy()
	if err != nil {
		return err
	}
	fmt.Printf("Restore %s\n", time.Now().Format("2006-01-02 15:04:05"))
	err = test.Restore()
	if err != nil {
		return err
	}
	fmt.Printf("Verify %s\n", time.Now().Format("2006-01-02 15:04:05"))
	err = test.Verify()
	if err != nil {
		return err
	}
	fmt.Printf("Finish run test %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}
