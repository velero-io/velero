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

package perf_test

import (
	"context"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/vmware-tanzu/velero/pkg/cmd/cli/install"
	. "github.com/vmware-tanzu/velero/test"
	"github.com/vmware-tanzu/velero/test/perf/backup"
	"github.com/vmware-tanzu/velero/test/perf/basic"
	"github.com/vmware-tanzu/velero/test/perf/restore"
	"github.com/vmware-tanzu/velero/test/perf/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	"github.com/vmware-tanzu/velero/test/util/report"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

func init() {
	VeleroCfg.Options = install.Options{}
	flag.StringVar(&VeleroCfg.CloudProvider, "cloud-provider", "", "cloud that Velero will be installed into.  Required.")
	flag.StringVar(&VeleroCfg.ObjectStoreProvider, "object-store-provider", "", "provider of object store plugin. Required if cloud-provider is kind, otherwise ignored.")
	flag.StringVar(&VeleroCfg.BSLBucket, "bucket", "", "name of the object storage bucket where backups from e2e tests should be stored. Required.")
	flag.StringVar(&VeleroCfg.CloudCredentialsFile, "credentials-file", "", "file containing credentials for backup and volume provider. Required.")
	flag.StringVar(&VeleroCfg.VeleroCLI, "velerocli", "velero", "path to the velero application to use.")
	flag.StringVar(&VeleroCfg.VeleroImage, "velero-image", "velero/velero:main", "image for the velero server to be tested.")
	flag.StringVar(&VeleroCfg.Plugins, "plugins", "", "provider plugins to be tested.")
	flag.StringVar(&VeleroCfg.AddBSLPlugins, "additional-bsl-plugins", "", "additional plugins to be tested.")
	flag.StringVar(&VeleroCfg.VeleroVersion, "velero-version", "main", "image version for the velero server to be tested with.")
	flag.StringVar(&VeleroCfg.RestoreHelperImage, "restore-helper-image", "", "image for the velero restore helper to be tested.")
	flag.StringVar(&VeleroCfg.BSLConfig, "bsl-config", "", "configuration to use for the backup storage location. Format is key1=value1,key2=value2")
	flag.StringVar(&VeleroCfg.BSLPrefix, "prefix", "", "prefix under which all Velero data should be stored within the bucket. Optional.")
	flag.StringVar(&VeleroCfg.VSLConfig, "vsl-config", "", "configuration to use for the volume snapshot location. Format is key1=value1,key2=value2")
	flag.StringVar(&VeleroCfg.VeleroNamespace, "velero-namespace", "velero", "namespace to install Velero into")
	flag.BoolVar(&InstallVelero, "install-velero", true, "install/uninstall velero during the test.  Optional.")
	flag.BoolVar(&VeleroCfg.UseNodeAgent, "use-node-agent", true, "whether deploy node agent daemonset velero during the test.  Optional.")
	flag.StringVar(&VeleroCfg.RegistryCredentialFile, "registry-credential-file", "", "file containing credential for the image registry, follows the same format rules as the ~/.docker/config.json file. Optional.")
	flag.StringVar(&VeleroCfg.NodeAgentPodCPULimit, "node-agent-pod-cpu-limit", "4", "CPU limit for node agent pod. Optional.")
	flag.StringVar(&VeleroCfg.NodeAgentPodMemLimit, "node-agent-pod-mem-limit", "4Gi", "Memory limit for node agent pod. Optional.")
	flag.StringVar(&VeleroCfg.NodeAgentPodCPURequest, "node-agent-pod-cpu-request", "2", "CPU request for node agent pod. Optional.")
	flag.StringVar(&VeleroCfg.NodeAgentPodMemRequest, "node-agent-pod-mem-request", "2Gi", "Memory request for node agent pod. Optional.")
	flag.StringVar(&VeleroCfg.VeleroPodCPULimit, "velero-pod-cpu-limit", "4", "CPU limit for velero pod. Optional.")
	flag.StringVar(&VeleroCfg.VeleroPodMemLimit, "velero-pod-mem-limit", "4Gi", "Memory limit for velero pod. Optional.")
	flag.StringVar(&VeleroCfg.VeleroPodCPURequest, "velero-pod-cpu-request", "2", "CPU request for velero pod. Optional.")
	flag.StringVar(&VeleroCfg.VeleroPodMemRequest, "velero-pod-mem-request", "2Gi", "Memory request for velero pod. Optional.")
	flag.DurationVar(&VeleroCfg.PodVolumeOperationTimeout, "pod-volume-operation-timeout", 360*time.Minute, "Timeout for pod volume operations. Optional.")
	//vmware-tanzu-experiments
	flag.StringVar(&VeleroCfg.Features, "features", "", "Comma-separated list of features to enable for this Velero process.")
	flag.StringVar(&VeleroCfg.DefaultClusterContext, "default-cluster-context", "", "Default cluster context for migration test.")
	flag.StringVar(&VeleroCfg.UploaderType, "uploader-type", "kopia", "Identify persistent volume backup uploader.")
	flag.BoolVar(&VeleroCfg.VeleroServerDebugMode, "velero-server-debug-mode", false, "Identify persistent volume backup uploader.")
	flag.StringVar(&VeleroCfg.NFSServerPath, "nfs-server-path", "", "the path of nfs server")
	flag.StringVar(&VeleroCfg.TestCaseDescribe, "test-case-describe", "velero performance test", "the description for the current test")
	flag.StringVar(&VeleroCfg.BackupForRestore, "backup-for-restore", "", "the name of backup for restore")
	flag.BoolVar(&VeleroCfg.DeleteClusterResource, "delete-cluster-resource", false, "delete cluster resource after test")
	flag.BoolVar(&VeleroCfg.DebugVeleroPodRestart, "debug-velero-pod-restart", false, "Switch for debugging velero pod restart.")
	flag.BoolVar(&VeleroCfg.FailFast, "fail-fast", true, "a switch for failing fast on meeting error.")
}

func initConfig() error {
	cli, err := NewTestClient("")
	if err != nil {
		return errors.WithStack(err)
	}
	VeleroCfg.DefaultClient = &cli

	ReportData = &E2EReport{
		TestDescription: VeleroCfg.TestCaseDescribe,
		OtherFields:     make(map[string]any),
	}

	return nil
}

var _ = Describe("Velero test on both backup and restore resources",
	Label("PerformanceTest", "BackupAndRestore"), test.TestFunc(&basic.BasicTest{}))

var _ = Describe("Velero test on only backup resources",
	Label("PerformanceTest", "Backup"), test.TestFunc(&backup.BackupTest{}))

var _ = Describe("Velero test on only restore resources",
	Label("PerformanceTest", "Restore"), test.TestFunc(&restore.RestoreTest{}))

var testSuitePassed bool

func TestE2e(t *testing.T) {
	flag.Parse()
	By("Install test resources before testing TestE2e")
	// Skip running E2E tests when running only "short" tests because:
	// 1. E2E tests are long running tests involving installation of Velero and performing backup and restore operations.
	// 2. E2E tests require a Kubernetes cluster to install and run velero which further requires more configuration. See above referenced command line flags.

	if err := initConfig(); err != nil {
		fmt.Println(err)
		t.FailNow()
	}

	RegisterFailHandler(Fail)
	testSuitePassed = RunSpecs(t, "E2e Suite")
}

var _ = BeforeSuite(func() {
	if InstallVelero {
		By("Install test resources before testing BeforeSuite")
		Expect(PrepareVelero(context.Background(), "install resource before testing", VeleroCfg)).To(Succeed())
	}
})

var _ = AfterSuite(func() {
	Expect(report.GenerateYamlReport()).To(Succeed())
	// If the Velero is installed during test, and the FailFast is not enabled,
	// uninstall Velero. If not, either Velero is not installed, or kept it for debug.
	if InstallVelero {
		if !testSuitePassed && VeleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			By("release test resources after testing")
			ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
			defer ctxCancel()
			Expect(VeleroUninstall(ctx, VeleroCfg)).To(Succeed())
		}
	}
})
