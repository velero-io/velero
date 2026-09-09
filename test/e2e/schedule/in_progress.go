package schedule

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/test"
	framework "github.com/vmware-tanzu/velero/test/e2e/test"
	"github.com/vmware-tanzu/velero/test/util/common"
	k8sutil "github.com/vmware-tanzu/velero/test/util/k8s"
	veleroutil "github.com/vmware-tanzu/velero/test/util/velero"
)

var ScheduleInProgressTest func() = framework.TestFunc(&InProgressCase{})

type InProgressCase struct {
	framework.TestCase
	namespace        string
	ScheduleName     string
	ScheduleArgs     []string
	volume           string
	podName          string
	pvcName          string
	podAnn           map[string]string
	podSleepDuration time.Duration
}

func (s *InProgressCase) Init() error {
	Expect(s.TestCase.Init()).To(Succeed())

	s.CaseBaseName = "schedule-backup-creation-test" + s.UUIDgen
	s.ScheduleName = "schedule-" + s.CaseBaseName
	s.namespace = s.CaseBaseName
	podSleepDurationStr := "60s"
	s.podSleepDuration, _ = time.ParseDuration(podSleepDurationStr)

	s.TestMsg = &framework.TestMSG{
		Desc:      "Schedule controller wouldn't create a new backup when it still has pending or InProgress backup",
		FailedMSG: "Failed to verify schedule back creation behavior",
		Text:      "Schedule controller wouldn't create a new backup when it still has pending or InProgress backup",
	}

	s.podAnn = map[string]string{
		"pre.hook.backup.velero.io/container": s.podName,
		"pre.hook.backup.velero.io/command":   "[\"sleep\", \"" + podSleepDurationStr + "\"]",
		"pre.hook.backup.velero.io/timeout":   "120s",
	}
	s.volume = "volume-1"
	s.podName = "pod-1"
	s.pvcName = "pvc-1"
	s.ScheduleArgs = []string{
		"--include-namespaces", s.namespace,
		"--schedule=@every 1m",
	}
	return nil
}

func (s *InProgressCase) CreateResources() error {
	By(fmt.Sprintf("Create namespace %s", s.namespace), func() {
		labels := make(map[string]string)
		if s.VeleroCfg.WorkerOS == common.WorkerOSWindows {
			labels = map[string]string{
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "latest",
			}
		}
		Expect(
			k8sutil.CreateNamespaceWithLabel(
				s.Ctx,
				s.Client,
				s.namespace,
				labels,
			),
		).To(Succeed(),
			fmt.Sprintf("Failed to create namespace %s", s.namespace))
	})

	By(fmt.Sprintf("Create pod %s in namespace %s", s.podName, s.namespace), func() {
		_, err := k8sutil.CreatePod(
			s.Client,
			s.namespace,
			s.podName,
			test.StorageClassName,
			s.pvcName,
			[]string{s.volume},
			nil,
			s.podAnn,
			s.VeleroCfg.ImageRegistryProxy,
			s.VeleroCfg.WorkerOS,
		)
		Expect(err).To(Succeed())

		err = k8sutil.WaitForPods(
			s.Ctx,
			s.Client,
			s.namespace,
			[]string{s.podName},
		)
		Expect(err).To(Succeed())
	})
	return nil
}

func (s *InProgressCase) Backup() error {
	By(fmt.Sprintf("Creating schedule %s\n", s.ScheduleName), func() {
		Expect(
			veleroutil.VeleroScheduleCreate(
				s.Ctx,
				s.VeleroCfg.VeleroCLI,
				s.VeleroCfg.VeleroNamespace,
				s.ScheduleName,
				s.ScheduleArgs,
			),
		).To(
			Succeed(),
			func() string {
				veleroutil.RunDebug(
					context.Background(),
					s.VeleroCfg.VeleroCLI,
					s.VeleroCfg.VeleroNamespace,
					"",
					"",
				)

				return "Fail to create schedule"
			})
	})

	By("Get backup every half minute.", func() {
		err := wait.PollUntilContextTimeout(
			s.Ctx,
			30*time.Second,
			5*time.Minute,
			true,
			func(ctx context.Context) (bool, error) {
				backupList := new(velerov1api.BackupList)

				if err := s.Client.Kubebuilder.List(
					s.Ctx,
					backupList,
					&kbclient.ListOptions{
						Namespace: s.VeleroCfg.VeleroNamespace,
						LabelSelector: labels.SelectorFromSet(map[string]string{
							velerov1api.ScheduleNameLabel: s.ScheduleName,
						}),
					},
				); err != nil {
					return false, fmt.Errorf("failed to list backup in %s namespace for schedule %s: %s",
						s.VeleroCfg.VeleroNamespace, s.ScheduleName, err.Error())
				}

				if len(backupList.Items) == 0 {
					fmt.Println("No backup is found yet. Continue query on the next turn.")
					return false, nil
				}

				inProgressBackupCount := 0
				for _, backup := range backupList.Items {
					if backup.Status.Phase == velerov1api.BackupPhaseInProgress {
						inProgressBackupCount++
					}
				}

				// There should be at most one in-progress backup per schedule.
				Expect(inProgressBackupCount).To(BeNumerically("<=", 1))

				// Already ensured at most one in-progress backup when schedule triggered 2 backups.
				// Succeed.
				if len(backupList.Items) >= 2 {
					return true, nil
				}

				fmt.Println("Wait until the schedule triggers two backups.")
				return false, nil
			},
		)

		Expect(err).To(Succeed())
	})
	return nil
}

func (s *InProgressCase) Clean() error {
	if CurrentSpecReport().Failed() && s.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		Expect(
			veleroutil.VeleroScheduleDelete(
				s.Ctx,
				s.VeleroCfg.VeleroCLI,
				s.VeleroCfg.VeleroNamespace,
				s.ScheduleName,
			),
		).To(Succeed())
		Expect(s.TestCase.Clean()).To(Succeed())
	}

	return nil
}
