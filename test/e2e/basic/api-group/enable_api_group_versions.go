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

package basic

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/pkg/builder"
	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
	. "github.com/vmware-tanzu/velero/test/util/velero"
)

var veleroCfg VeleroConfig

type apiGropuVersionsTest struct {
	name       string
	srcCrdYaml string
	srcCRs     map[string]string
	tgtCrdYaml string
	tgtVer     string
	cm         *corev1api.ConfigMap
	want       map[string]map[string]string
}

func APIGroupVersionsTest() {
	var (
		group       string
		err         error
		ctx         = context.Background()
		testCaseNum int
	)

	BeforeEach(func() {
		veleroCfg = VeleroCfg
		group = "music.example.io"
		UUIDgen, err = uuid.NewRandom()
		Expect(err).NotTo(HaveOccurred())
		flag.Parse()
		// TODO: install Velero once for the test suite once feature flag is
		// removed and velero installation becomes the same as other e2e tests.
		if InstallVelero {
			veleroCfg.Features = "EnableAPIGroupVersions"
			veleroCfg.UseVolumeSnapshots = false
			err = VeleroInstall(context.Background(), &veleroCfg, false)
			Expect(err).NotTo(HaveOccurred())
		}
		testCaseNum = 4
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() && veleroCfg.FailFast {
			fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
		} else {
			for i := 0; i < testCaseNum; i++ {
				curResource := fmt.Sprintf("rockband%ds", i)
				curGroup := fmt.Sprintf("%s.%d", group, i)
				By(fmt.Sprintf("Clean up resource: kubectl delete crd %s.%s\n", curResource, curGroup))
				cmd := exec.CommandContext(ctx, "kubectl", "delete", "crd", curResource+"."+curGroup)
				_, stderr, err := veleroexec.RunCommand(cmd)
				if strings.Contains(stderr, "NotFound") {
					fmt.Printf("Ignore error: %v\n", stderr)
					err = nil
				}
				Expect(err).NotTo(HaveOccurred())
			}

			By("Clean backups after test", func() {
				DeleteAllBackups(context.Background(), &veleroCfg)
			})
			if InstallVelero {
				By("Uninstall Velero in api group version case", func() {
					Expect(VeleroUninstall(ctx, veleroCfg)).NotTo(HaveOccurred())
				})
			}
		}
	})

	Context("When EnableAPIGroupVersions flag is set", func() {
		It("Should back up API group version and restore by version priority", func() {
			ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*60)
			defer ctxCancel()
			Expect(runEnableAPIGroupVersionsTests(
				ctx,
				*veleroCfg.ClientToInstallVelero,
				group,
			)).To(Succeed(), "Failed to successfully backup and restore multiple API Groups")
		})
	})
}

func runEnableAPIGroupVersionsTests(ctx context.Context, client TestClient, group string) error {
	tests := []apiGropuVersionsTest{
		{
			name:       "Target and source cluster preferred versions match; Preferred version v1 is restored (Priority 1, Case A).",
			srcCrdYaml: "../testdata/enable_api_group_versions/case-a-source.yaml",
			srcCRs: map[string]string{
				"v1":       "../testdata/enable_api_group_versions/music_v1_rockband.yaml",
				"v1alpha1": "../testdata/enable_api_group_versions/music_v1alpha1_rockband.yaml",
			},
			tgtCrdYaml: "../testdata/enable_api_group_versions/case-a-target.yaml",
			tgtVer:     "v1",
			cm:         nil,
			want: map[string]map[string]string{
				"annotations": {
					"rockband0s.music.example.io.0/originalVersion": "v1",
				},
				"specs": {
					"genre": "60s rock",
				},
			},
		},
		{
			name:       "Latest common non-preferred supported version v2beta2 is restored (Priority 3, Case D).",
			srcCrdYaml: "../testdata/enable_api_group_versions/case-b-source-manually-added-mutations.yaml",
			srcCRs: map[string]string{
				"v2beta2": "../testdata/enable_api_group_versions/music_v2beta2_rockband.yaml",
				"v2beta1": "../testdata/enable_api_group_versions/music_v2beta1_rockband.yaml",
				"v1":      "../testdata/enable_api_group_versions/music_v1_rockband.yaml",
			},
			tgtCrdYaml: "../testdata/enable_api_group_versions/case-d-target-manually-added-mutations.yaml",
			tgtVer:     "v2beta2",
			cm:         nil,
			want: map[string]map[string]string{
				"annotations": {
					"rockband1s.music.example.io.1/originalVersion": "v2beta2",
				},
				"specs": {
					"genre": "60s rock",
				},
			},
		},
		{
			name:       "No common supported versions means no rockbands custom resource is restored.",
			srcCrdYaml: "../testdata/enable_api_group_versions/case-a-source.yaml",
			srcCRs: map[string]string{
				"v1":       "../testdata/enable_api_group_versions/music_v1_rockband.yaml",
				"v1alpha1": "../testdata/enable_api_group_versions/music_v1alpha1_rockband.yaml",
			},
			tgtCrdYaml: "../testdata/enable_api_group_versions/case-b-target-manually-added-mutations.yaml",
			tgtVer:     "",
			cm:         nil,
			want:       nil,
		},
		{
			name:       "User config map overrides Priority 3, Case D and restores v2beta1",
			srcCrdYaml: "../testdata/enable_api_group_versions/case-b-source-manually-added-mutations.yaml",
			srcCRs: map[string]string{
				"v2beta2": "../testdata/enable_api_group_versions/music_v2beta2_rockband.yaml",
				"v2beta1": "../testdata/enable_api_group_versions/music_v2beta1_rockband.yaml",
				"v1":      "../testdata/enable_api_group_versions/music_v1_rockband.yaml",
			},
			tgtCrdYaml: "../testdata/enable_api_group_versions/case-d-target-manually-added-mutations.yaml",
			tgtVer:     "v2beta1",
			cm: builder.ForConfigMap(veleroCfg.VeleroNamespace, "enableapigroupversions").Data(
				"restoreResourcesVersionPriority",
				`rockband3s.music.example.io.3=v2beta1,v2beta2,v2`,
			).Result(),
			want: map[string]map[string]string{
				"annotations": {
					"rockband3s.music.example.io.3/originalVersion": "v2beta1",
				},
				"specs": {
					"genre": "60s rock",
				},
			},
		},
		{
			name:       "Restore successful when CRD doesn't (yet) exist in target",
			srcCrdYaml: "../testdata/enable_api_group_versions/case-a-source.yaml",
			srcCRs: map[string]string{
				"v1": "../testdata/enable_api_group_versions/music_v1_rockband.yaml",
			},
			tgtCrdYaml: "",
			tgtVer:     "v1",
			cm:         nil,
			want: map[string]map[string]string{
				"annotations": {
					"rockband4s.music.example.io.4/originalVersion": "v1",
				},
				"specs": {
					"genre": "60s rock",
				},
			},
		},
	}

	nsListwanted, nsListUnwanted, err := installTestResources(ctx, client, group, tests)
	Expect(err).NotTo(HaveOccurred())

	for i, tc := range tests {
		for version := range tc.srcCRs {
			ns := fmt.Sprintf("rockband%ds-src-%s-%d", i, version, i)
			defer func(namespace string) {
				if err = DeleteNamespace(ctx, client, namespace, true); err != nil {
					fmt.Println(errors.Wrapf(err, "failed to delete the namespace %q", ns))
				}
			}(ns)
		}
		if tc.cm != nil {
			defer func(name string) {
				if err = client.ClientGo.CoreV1().ConfigMaps(veleroCfg.VeleroNamespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
					fmt.Println(errors.Wrapf(err, "failed to delete configmap %q", name))
				}
			}(tc.cm.Name)
		}

		defer func(crdName string) {
			if err = DeleteCRDByName(ctx, crdName); err != nil {
				fmt.Println(errors.Wrapf(err, "failed to delete crd %q", crdName))
			}
		}(fmt.Sprintf("rockband%ds.music.example.io.%d", i, i))
	}

	time.Sleep(6 * time.Minute)

	BackupCfgWanted := BackupConfig{
		BackupName:         "backup-rockbands-" + UUIDgen.String() + "-wanted",
		Namespace:          nsListwanted,
		UseVolumeSnapshots: false,
	}

	Expect(VeleroBackupNamespace(ctx, veleroCfg.VeleroCLI,
		veleroCfg.VeleroNamespace, BackupCfgWanted)).To(Succeed(), func() string {
		RunDebug(context.Background(), veleroCfg.VeleroCLI,
			veleroCfg.VeleroNamespace, BackupCfgWanted.BackupName, "")
		return "Fail to backup workload"
	})

	BackupCfgUnwanted := BackupConfig{
		BackupName:         "backup-rockbands-" + UUIDgen.String() + "-unwanted",
		Namespace:          nsListUnwanted,
		UseVolumeSnapshots: false,
	}

	Expect(VeleroBackupNamespace(ctx, veleroCfg.VeleroCLI,
		veleroCfg.VeleroNamespace, BackupCfgUnwanted)).To(Succeed(), func() string {
		RunDebug(context.Background(), veleroCfg.VeleroCLI,
			veleroCfg.VeleroNamespace, BackupCfgUnwanted.BackupName, "")
		return "Fail to backup workload"
	})

	Expect(reinstallTestResources(ctx, group, client, tests)).NotTo(HaveOccurred())

	time.Sleep(6 * time.Minute)

	restoreName := "restore-rockbands-" + UUIDgen.String() + "-wanted"
	if err := VeleroRestore(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, restoreName, BackupCfgWanted.BackupName, ""); err != nil {
		RunDebug(context.Background(), veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, "", restoreName)
		return errors.Wrapf(err, "restore %s namespaces on target cluster", nsListwanted)
	}

	restoreName = "restore-rockbands-" + UUIDgen.String() + "-unwanted"
	err = VeleroRestore(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, restoreName, BackupCfgUnwanted.BackupName, "")
	if !strings.Contains(err.Error(), "Unexpected restore phase got PartiallyFailed, expecting Completed") {
		return errors.New("expected error but not none")
	}

	for i, tc := range tests {
		defer func() {
			_ = deleteTestCRD(ctx, i, group, tc.srcCrdYaml)
			if tc.tgtCrdYaml != "" {
				_ = deleteTestCRD(ctx, i, group, tc.tgtCrdYaml)
			}
			if tc.cm != nil {
				client.ClientGo.CoreV1().ConfigMaps(veleroCfg.VeleroNamespace).Delete(ctx, tc.cm.Name, metav1.DeleteOptions{})
			}
		}()

		if tc.want != nil {
			curResource := fmt.Sprintf("rockband%ds", i)
			annoSpec, err := resourceInfo(ctx, group, tc.tgtVer, curResource, i)
			if err != nil {
				return errors.Wrapf(
					err,
					"get annotation and spec from %s.%s/%s object",
					curResource,
					group,
					tc.tgtVer,
				)
			}

			// Assertion
			if !containsAll(annoSpec["annotations"], tc.want["annotations"]) {
				msg := fmt.Sprintf(
					"actual annotations: %v, expected annotations: %v",
					annoSpec["annotations"],
					tc.want["annotations"],
				)
				return errors.New(msg)
			}

			// Assertion
			if !containsAll(annoSpec["specs"], tc.want["specs"]) {
				msg := fmt.Sprintf(
					"actual specs: %v, expected specs: %v",
					annoSpec["specs"],
					tc.want["specs"],
				)
				return errors.New(msg)
			}
		}
	}

	return nil
}

func deleteTestCRD(ctx context.Context, index int, group, path string) error {
	fileName, err := rerenderTestYaml(index, group, path)
	defer func() {
		if fileName != "" {
			os.Remove(fileName)
		}
	}()
	if err != nil {
		return err
	}
	return DeleteCRD(ctx, fileName)
}

func installTestCR(ctx context.Context, index int, group, path, ns string) error {
	fileName, err := rerenderTestYaml(index, group, path)
	defer func() {
		if fileName != "" {
			os.Remove(fileName)
		}
	}()
	if err != nil {
		return err
	}
	return InstallCR(ctx, fileName, ns)
}

func installTestCRD(ctx context.Context, index int, group, path string) error {
	fileName, err := rerenderTestYaml(index, group, path)
	defer func() {
		if fileName != "" {
			os.Remove(fileName)
		}
	}()
	if err != nil {
		return err
	}
	return InstallCRD(ctx, fileName)
}

func rerenderTestYaml(index int, group, path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get %s when install test yaml", path)
	}

	// replace resource name to new value
	re := regexp.MustCompile(`\b(RockBand|RockBandList|rockband|rockbands)\b`)
	newContent := re.ReplaceAllStringFunc(string(content), func(s string) string {
		if s == "RockBand" {
			return fmt.Sprintf("RockBand%d", index)
		} else if s == "RockBandList" {
			return fmt.Sprintf("RockBand%dList", index)
		} else if s == "rockbands" {
			return fmt.Sprintf("rockband%ds", index)
		} else {
			return fmt.Sprintf("rockband%d", index)
		}
	})

	// replace group name to new value
	newContent = strings.ReplaceAll(newContent, group, fmt.Sprintf("%s.%d", group, index))

	By(fmt.Sprintf("\n%s\n", newContent))
	tmpFile, err := os.CreateTemp("", "test-yaml")
	if err != nil {
		return "", errors.Wrapf(err, "failed to create temp file  when install storage class")
	}

	if _, err := tmpFile.WriteString(newContent); err != nil {
		return "", errors.Wrapf(err, "failed to write content into temp file %s when install storage class", tmpFile.Name())
	}

	return tmpFile.Name(), nil
}

func resourceInfo(ctx context.Context, g, v, r string, index int) (map[string]map[string]string, error) {
	rvg := fmt.Sprintf("%s.%s.%s.%d", r, v, g, index)
	ns := fmt.Sprintf("rockband%ds-src-%s-%d", index, v, index)
	cmd := exec.CommandContext(ctx, "kubectl", "get", rvg, "-n", ns, "-o", "json")
	stdout, errMsg, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return nil, errors.Wrap(err, errMsg)
	}

	var info map[string]any
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, errors.Wrap(err, "unmarshal resource info JSON")
	}
	items := info["items"].([]any)

	if len(items) < 1 {
		return nil, errors.New("resource info is empty")
	}

	item := items[0].(map[string]any)
	metadata := item["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	specs := item["spec"].(map[string]any)

	annoSpec := make(map[string]map[string]string)

	for k, v := range annotations {
		if annoSpec["annotations"] == nil {
			annoSpec["annotations"] = map[string]string{
				k: v.(string),
			}
		} else {
			annoSpec["annotations"][k] = v.(string)
		}
	}

	for k, v := range specs {
		if val, ok := v.(string); ok {
			if annoSpec["specs"] == nil {
				annoSpec["specs"] = map[string]string{
					k: val,
				}
			} else {
				annoSpec["specs"][k] = val
			}
		}
	}

	return annoSpec, nil
}

// containsAll returns true if all the map values in the needles argument
// are found in the haystack argument values.
func containsAll(haystack, needles map[string]string) bool {
	for nkey, nval := range needles {
		hval, ok := haystack[nkey]
		if !ok {
			return false
		}

		if hval != nval {
			return false
		}
	}
	return true
}

func installTestResources(ctx context.Context, client TestClient, group string, tests []apiGropuVersionsTest) (string, string, error) {
	var wanted, unwanted []string
	for i, tc := range tests {
		fmt.Printf("\n====== Test Case %d: %s ======\n", i, tc.name)

		err := installTestCRD(ctx, i, group, tc.srcCrdYaml)
		if err != nil {
			return "", "", errors.Wrap(err, "install music-system CRD on source cluster")
		}

		for version, cr := range tc.srcCRs {
			ns := fmt.Sprintf("rockband%ds-src-%s-%d", i, version, i)
			if err := CreateNamespace(ctx, client, ns); err != nil {
				return "", "", errors.Wrapf(err, "create %s namespace", ns)
			}

			if err := installTestCR(ctx, i, group, cr, ns); err != nil {
				return "", "", errors.Wrapf(err, "install %s custom resource on source cluster in namespace %s", cr, ns)
			}

			if tc.want == nil {
				unwanted = append(unwanted, ns)
			} else {
				wanted = append(wanted, ns)
			}
		}
	}
	return strings.Join(wanted, ","), strings.Join(unwanted, ","), nil
}

func reinstallTestResources(ctx context.Context, group string, client TestClient, tests []apiGropuVersionsTest) error {
	for i, tc := range tests {
		By(fmt.Sprintf("Deleting CRD %s", tc.srcCrdYaml))
		if err := deleteTestCRD(ctx, i, group, tc.srcCrdYaml); err != nil {
			return errors.Wrapf(err, "delete music-system CRD from source cluster")
		}

		for version := range tc.srcCRs {
			ns := fmt.Sprintf("rockband%ds-src-%s-%d", i, version, i)
			By(fmt.Sprintf("Deleting namespace %s", ns))
			if err := DeleteNamespace(ctx, client, ns, true); err != nil {
				fmt.Println(errors.Wrapf(err, "failed to delete the namespace %q", ns))
			}
		}
		// Install music-system CRD for target cluster.
		if tc.tgtCrdYaml != "" {
			By(fmt.Sprintf("Installing CRD %s", tc.tgtCrdYaml))
			if err := installTestCRD(ctx, i, group, tc.tgtCrdYaml); err != nil {
				return errors.Wrapf(err, "install music-system CRD on target cluster")
			}
		}

		// Apply config map if there is one.
		if tc.cm != nil {
			By(fmt.Sprintf("Creating configmap %s", tc.cm.Name))
			_, err := client.ClientGo.CoreV1().ConfigMaps(veleroCfg.VeleroNamespace).Create(ctx, tc.cm, metav1.CreateOptions{})
			if err != nil {
				return errors.Wrap(err, "create config map with user version priorities")
			}
		}
	}
	return nil
}
