package basic

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/cockroachdb/errors"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

type PVBackupFiltering struct {
	TestCase
	annotation  string
	podsList    [][]string
	volumesList [][]string
	id          string
}

const POD_COUNT, VOLUME_COUNT_PER_POD = 2, 3
const OPT_IN_ANN, OPT_OUT_ANN = "backup.velero.io/backup-volumes", "backup.velero.io/backup-volumes-excludes"
const FILE_NAME = "test-data.txt"

var OptInPVBackupTest func() = TestFunc(&PVBackupFiltering{annotation: OPT_IN_ANN, id: "opt-in"})
var OptOutPVBackupTest func() = TestFunc(&PVBackupFiltering{annotation: OPT_OUT_ANN, id: "opt-out"})

func (p *PVBackupFiltering) Init() error {
	p.TestCase.Init()
	p.CaseBaseName = "pv-filter-" + p.UUIDgen
	p.BackupName = "backup-" + p.CaseBaseName + p.id
	p.RestoreName = "restore-" + p.CaseBaseName + p.id
	p.VeleroCfg.UseVolumeSnapshots = false
	p.VeleroCfg.UseNodeAgent = true
	p.NSIncluded = &[]string{fmt.Sprintf("%s-%s-%d", p.CaseBaseName, p.id, 1), fmt.Sprintf("%s-%s-%d", p.CaseBaseName, p.id, 2)}

	p.TestMsg = &TestMSG{
		Desc:      "Backup PVs filtering by opt-in/opt-out annotation",
		FailedMSG: "Failed to PVs filtering by opt-in/opt-out annotation",
		Text:      fmt.Sprintf("Should backup PVs in namespace %s according to annotation %s", *p.NSIncluded, p.annotation),
	}

	p.BackupArgs = []string{
		"create", "--namespace", p.VeleroCfg.VeleroNamespace, "backup", p.BackupName,
		"--include-namespaces", strings.Join(*p.NSIncluded, ","),
		"--snapshot-volumes=false", "--wait",
	}
	// "--default-volumes-to-fs-backup" is an overall switch, if it's set, then opt-in
	//   annotation will be ignored, so it's only set for opt-out test
	if p.annotation == OPT_OUT_ANN {
		p.BackupArgs = append(p.BackupArgs, "--default-volumes-to-fs-backup")
	}
	p.RestoreArgs = []string{
		"create", "--namespace", p.VeleroCfg.VeleroNamespace, "restore", p.RestoreName,
		"--from-backup", p.BackupName, "--wait",
	}
	return nil
}

func (p *PVBackupFiltering) CreateResources() error {
	for _, ns := range *p.NSIncluded {
		By(fmt.Sprintf("Create namespaces %s for workload\n", ns), func() {
			labels := make(map[string]string)
			if p.VeleroCfg.WorkerOS == common.WorkerOSWindows {
				labels = map[string]string{
					"pod-security.kubernetes.io/enforce":         "privileged",
					"pod-security.kubernetes.io/enforce-version": "latest",
				}
			}
			Expect(CreateNamespaceWithLabel(p.Ctx, p.Client, ns, labels)).To(Succeed(), fmt.Sprintf("Failed to create namespace %s", ns))
		})
		var pods []string
		By(fmt.Sprintf("Deploy a few pods with several PVs in namespace %s", ns), func() {
			var volumesToAnnotation string
			//Make sure PVC name is unique from other tests to avoid PVC creation error
			for i := 0; i <= POD_COUNT-1; i++ {
				var volumeToAnnotationList []string
				var volumes []string
				for j := 0; j <= VOLUME_COUNT_PER_POD-1; j++ {
					volume := fmt.Sprintf("volume-%s-%d-%d", p.id, i, j)
					volumes = append(volumes, volume)
					//Volumes cherry-pick policy for opt-in/out annotation to apply
					if j%2 == 0 {
						volumeToAnnotationList = append(volumeToAnnotationList, volume)
					}
				}
				p.volumesList = append(p.volumesList, volumes)
				volumesToAnnotation = strings.Join(volumeToAnnotationList, ",")
				podName := fmt.Sprintf("pod-%d", i)
				pods = append(pods, podName)
				By(fmt.Sprintf("Create pod %s in namespace %s", podName, ns), func() {
					pod, err := CreatePod(
						p.Client,
						ns,
						podName,
						StorageClassName,
						"",
						volumes,
						nil,
						nil,
						p.VeleroCfg.ImageRegistryProxy,
						p.VeleroCfg.WorkerOS,
					)
					Expect(err).To(Succeed())
					ann := map[string]string{
						p.annotation: volumesToAnnotation,
					}
					By(fmt.Sprintf("Add annotation to pod %s of namespace %s", pod.Name, ns), func() {
						_, err := AddAnnotationToPod(p.Ctx, p.Client, ns, pod.Name, ann)
						Expect(err).To(Succeed())
					})
				})
			}
		})
		p.podsList = append(p.podsList, pods)
	}
	By(fmt.Sprintf("Waiting for all pods to start %s\n", p.podsList), func() {
		for index, ns := range *p.NSIncluded {
			By(fmt.Sprintf("Waiting for all pods to start %d in namespace %s", index, ns), func() {
				Expect(WaitForPods(p.Ctx, p.Client, ns, p.podsList[index])).To(Succeed())
			})
		}
	})
	By(fmt.Sprintf("Populate all pods %s with file %s", p.podsList, FILE_NAME), func() {
		for index, ns := range *p.NSIncluded {
			By(fmt.Sprintf("Creating file in all pods to start %d in namespace %s", index, ns), func() {
				Expect(WaitForPods(p.Ctx, p.Client, ns, p.podsList[index])).To(Succeed())
				for i, pod := range p.podsList[index] {
					for j := range p.volumesList[i] {
						Expect(CreateFileToPod(
							ns,
							pod,
							pod,
							p.volumesList[i][j],
							FILE_NAME,
							CreateFileContent(ns, pod, p.volumesList[i][j]),
							p.VeleroCfg.WorkerOS,
						)).To(Succeed())
					}
				}
			})
		}
	})
	return nil
}

func (p *PVBackupFiltering) Verify() error {
	By(fmt.Sprintf("Waiting for all pods to start %s", p.podsList), func() {
		for index, ns := range *p.NSIncluded {
			By(fmt.Sprintf("Waiting for all pods to start %d in namespace %s", index, ns), func() {
				WaitForPods(p.Ctx, p.Client, ns, p.podsList[index])
			})
		}
	})

	for k, ns := range *p.NSIncluded {
		By("Verify PV backed up according to annotation", func() {
			for i := 0; i <= POD_COUNT-1; i++ {
				for j := 0; j <= VOLUME_COUNT_PER_POD-1; j++ {
					// Same with volumes cherry pick policy to verify backup result
					if j%2 == 0 {
						if p.annotation == OPT_IN_ANN {
							By(fmt.Sprintf("File should exists in PV %s of pod %s under namespace %s\n", p.volumesList[i][j], p.podsList[k][i], ns), func() {
								Expect(fileExist(
									p.Ctx,
									ns,
									p.podsList[k][i],
									p.volumesList[i][j],
									p.VeleroCfg.WorkerOS,
								)).To(Succeed(), "File not exist as expect")
							})
						} else {
							By(fmt.Sprintf("File should not exist in PV %s of pod %s under namespace %s\n", p.volumesList[i][j], p.podsList[k][i], ns), func() {
								Expect(fileNotExist(
									p.Ctx,
									ns,
									p.podsList[k][i],
									p.volumesList[i][j],
									p.VeleroCfg.WorkerOS,
								)).To(Succeed(), "File exists, not as expect")
							})
						}
					} else {
						if p.annotation == OPT_OUT_ANN {
							By(fmt.Sprintf("File should exists in PV %s of pod %s under namespace %s\n", p.volumesList[i][j], p.podsList[k][i], ns), func() {
								Expect(fileExist(
									p.Ctx,
									ns,
									p.podsList[k][i],
									p.volumesList[i][j],
									p.VeleroCfg.WorkerOS,
								)).To(Succeed(), "File not exist as expect")
							})
						} else {
							By(fmt.Sprintf("File should not exist in PV %s of pod %s under namespace %s\n", p.volumesList[i][j], p.podsList[k][i], ns), func() {
								Expect(fileNotExist(
									p.Ctx,
									ns,
									p.podsList[k][i],
									p.volumesList[i][j],
									p.VeleroCfg.WorkerOS,
								)).To(Succeed(), "File exists, not as expect")
							})
						}
					}
				}
			}
		})
	}

	return nil
}

func fileExist(
	ctx context.Context,
	namespace string,
	podName string,
	volume string,
	workerOS string,
) error {
	c, _, err := ReadFileFromPodVolume(namespace, podName, podName, volume, FILE_NAME, workerOS)
	if err != nil {
		fmt.Printf("Fail to read file %s from volume %s of pod %s in %s: %s",
			FILE_NAME, volume, podName, namespace, err.Error(),
		)
		return errors.Wrap(err, fmt.Sprintf("Fail to read file %s from volume %s of pod %s in %s ",
			FILE_NAME, volume, podName, namespace))
	}
	c = strings.TrimRightFunc(c, unicode.IsSpace)
	origin_content := strings.TrimRightFunc(CreateFileContent(namespace, podName, volume), unicode.IsSpace)
	if c == origin_content {
		return nil
	} else {
		fmt.Printf("Content not match: \n origin: %s\n result: %s\n", origin_content, c)
		return errors.New(fmt.Sprintf("UNEXPECTED: File %s does not exist in volume %s of pod %s in namespace %s.",
			FILE_NAME, volume, podName, namespace))
	}
}
func fileNotExist(
	ctx context.Context,
	namespace string,
	podName string,
	volume string,
	workerOS string,
) error {
	_, _, err := ReadFileFromPodVolume(namespace, podName, podName, volume, FILE_NAME, workerOS)
	if err != nil {
		return nil
	} else {
		return errors.New(fmt.Sprintf("UNEXPECTED: File %s exist in volume %s of pod %s in namespace %s.",
			FILE_NAME, volume, podName, namespace))
	}
}
