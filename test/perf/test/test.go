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
	"math/rand"
	"time"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	. "github.com/vmware-tanzu/velero/test"
	"github.com/vmware-tanzu/velero/test/perf/metrics"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	"github.com/vmware-tanzu/velero/test/util/report"
	"github.com/vmware-tanzu/velero/test/util/velero"
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
	CreateResources() error
	Backup() error
	Destroy() error
	Restore() error
	Verify() error
	Clean() error
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
	NSExcluded         *[]string
	UseVolumeSnapshots bool
	RestorePhaseExpect velerov1api.RestorePhase
	Ctx                context.Context
	CtxCancel          context.CancelFunc
	UUIDgen            string
	timer              *metrics.TimeMetrics
}

func TestFunc(test VeleroBackupRestoreTest) func() {
	return func() {
		Expect(test.Init()).To(Succeed(), "Failed to instantiate test cases")
		By(fmt.Sprintf("Run test %s ...... \n", test.GetTestCase().CaseBaseName))
		BeforeEach(func() {
			// Using the global velero config which covered the installation for most common cases
			if InstallVelero {
				Expect(PrepareVelero(context.Background(), test.GetTestCase().CaseBaseName, VeleroCfg)).To(Succeed())
			}
		})
		It(test.GetTestMsg().Text, func() {
			Expect(RunTestCase(test)).To(Succeed(), test.GetTestMsg().FailedMSG)
		})
	}
}

func (t *TestCase) Init() error {
	t.Ctx, t.CtxCancel = context.WithTimeout(context.Background(), 6*time.Hour)
	t.NSExcluded = &[]string{"kube-system", "velero", "default", "kube-public", "kube-node-lease"}
	t.UUIDgen = t.GenerateUUID()
	t.Client = *VeleroCfg.DefaultClient
	t.timer = &metrics.TimeMetrics{
		Name: "Total time cost",
		TimeInfo: map[string]metrics.TimeSpan{"Total time cost": {
			Start: time.Now(),
		}},
	}
	return nil
}

func (t *TestCase) GenerateUUID() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%08d", rand.Intn(100000000))
}

func (t *TestCase) CreateResources() error {
	return nil
}

func (t *TestCase) Backup() error {
	if len(t.BackupArgs) == 0 {
		return nil
	}

	if err := VeleroBackupExec(t.Ctx, VeleroCfg.VeleroCLI, VeleroCfg.VeleroNamespace, t.BackupName, t.BackupArgs); err != nil {
		RunDebug(context.Background(), VeleroCfg.VeleroCLI, VeleroCfg.VeleroNamespace, t.BackupName, "")
		return errors.Wrap(err, "Failed to backup resources")
	}
	return nil
}

func (t *TestCase) Destroy() error {
	if VeleroCfg.DeleteClusterResource {
		By(fmt.Sprintf("Start to destroy namespace %s......", t.CaseBaseName), func() {
			Expect(CleanupNamespacesFiterdByExcludes(t.GetTestCase().Ctx, t.Client, *t.NSExcluded)).To(Succeed(), "Could cleanup retrieve namespaces")
			Expect(ClearClaimRefForFailedPVs(t.Ctx, t.Client)).To(Succeed(), "Failed to make PV status become to available")
		})
	}
	return nil
}

func (t *TestCase) Restore() error {
	if len(t.RestoreArgs) == 0 {
		return nil
	}

	By("Start to restore ......", func() {
		if t.RestorePhaseExpect == "" {
			t.RestorePhaseExpect = velerov1api.RestorePhaseCompleted
		}
		Expect(VeleroRestoreExec(t.Ctx, VeleroCfg.VeleroCLI, VeleroCfg.VeleroNamespace, t.RestoreName, t.RestoreArgs, t.RestorePhaseExpect)).To(Succeed(), func() string {
			RunDebug(context.Background(), VeleroCfg.VeleroCLI, VeleroCfg.VeleroNamespace, "", t.RestoreName)
			return "Fail to restore workload"
		})
	})
	return nil
}

func (t *TestCase) Verify() error {
	return nil
}

func (t *TestCase) Clean() error {
	if (!CurrentSpecReport().Failed() || !VeleroCfg.FailFast) || VeleroCfg.DeleteClusterResource {
		By("Clean backups and restore after test", func() {
			if len(t.BackupArgs) != 0 {
				if err := VeleroBackupDelete(t.Ctx, VeleroCfg.VeleroCLI, VeleroCfg.VeleroNamespace, t.BackupName); err != nil {
					fmt.Printf("Failed to delete backup %s with err %v\n", t.BackupName, err)
				}
			}

			if len(t.RestoreArgs) != 0 {
				if err := VeleroRestoreDelete(t.Ctx, VeleroCfg.VeleroCLI, VeleroCfg.VeleroNamespace, t.RestoreName); err != nil {
					fmt.Printf("Failed to delete restore %s with err %v\n", t.RestoreName, err)
				}
			}
		})
		Expect(ClearClaimRefForFailedPVs(t.Ctx, t.Client)).To(Succeed(), "Failed to make PV status become to available")
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
	collectors := new(metrics.MetricsCollector)
	test.GetTestCase().MonitorMetircs(test.GetTestCase().Ctx, collectors)

	timer := test.GetTestCase().timer
	collectors.RegisterOneTimeMetric(timer)

	go collectors.UpdateMetrics()
	By(fmt.Sprintf("Running test case %s %s\n", test.GetTestMsg().Desc, time.Now().Format("2006-01-02 15:04:05")))
	if test == nil {
		return errors.New("No case should be tested")
	}

	defer func() {
		collectors.UpdateOneTimeMetrics()
		metrics := collectors.GetMetrics()
		report.AddTestSuitData(metrics, test.GetTestMsg().Desc)
		test.Clean()
		fmt.Printf("OutPut metrics %v for case %s", metrics, test.GetTestCase().CaseBaseName)
	}()

	fmt.Printf("CreateResources %s\n", time.Now().Format("2006-01-02 15:04:05"))
	timer.Start("Create Resources Time Cost")
	err := test.CreateResources()
	if err != nil {
		return err
	}
	timer.End("Create Resources Time Cost")

	timer.Start("Backup Time Cost")
	fmt.Printf("Backup %s\n", time.Now().Format("2006-01-02 15:04:05"))
	err = test.Backup()
	if err != nil {
		return err
	}
	timer.End("Backup Time Cost")

	fmt.Printf("Destroy %s\n", time.Now().Format("2006-01-02 15:04:05"))
	timer.Start("Destroy Resources Time Cost")
	err = test.Destroy()
	if err != nil {
		return err
	}
	timer.End("Destroy Resources Time Cost")

	fmt.Printf("Restore %s\n", time.Now().Format("2006-01-02 15:04:05"))
	timer.Start("Restore Time Cost")
	err = test.Restore()
	if err != nil {
		return err
	}
	timer.End("Restore Time Cost")

	fmt.Printf("Verify %s\n", time.Now().Format("2006-01-02 15:04:05"))
	timer.Start("Verify Resource Time Cost")
	err = test.Verify()
	if err != nil {
		return err
	}
	timer.End("Verify Resource Time Cost")
	fmt.Printf("Finish run test %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

func (t *TestCase) MonitorMetircs(ctx context.Context, collectors *metrics.MetricsCollector) {
	if VeleroCfg.NFSServerPath == "" {
		fmt.Println("couldn't monitor nfs server disk usage for nfs server path is not configured")
	} else {
		nfsMetrics := &metrics.NFSMetrics{NFSServerPath: VeleroCfg.NFSServerPath, Metrics: make(map[string]string), Ctx: ctx}
		collectors.RegisterOneTimeMetric(nfsMetrics)
	}

	minioMetrics := &metrics.MinioMetrics{
		CloudCredentialsFile: VeleroCfg.CloudCredentialsFile,
		BslPrefix:            VeleroCfg.BSLPrefix,
		BslConfig:            VeleroCfg.BSLConfig,
		Metrics:              make(map[string]string),
		BslBucket:            VeleroCfg.BSLBucket}
	collectors.RegisterOneTimeMetric(minioMetrics)

	timeMetrics := &metrics.TimeMetrics{
		Name:     t.CaseBaseName,
		TimeInfo: make(map[string]metrics.TimeSpan),
	}
	collectors.RegisterOneTimeMetric(timeMetrics)

	veleroPodList, err := velero.ListVeleroPods(ctx, VeleroCfg.VeleroNamespace)
	if err != nil {
		fmt.Printf("couldn't monitor velero pod metrics for failed to get velero pod with err %v\n", err)
	} else {
		for _, pod := range veleroPodList {
			podMetrics := &metrics.PodMetrics{
				Ctx:       ctx,
				Client:    VeleroCfg.DefaultClient.MetricsClient,
				Metrics:   make(map[string]int64),
				PodName:   pod,
				Namespace: VeleroCfg.VeleroNamespace,
			}
			collectors.RegisterMetric(podMetrics)
		}
	}
}
