package schedule

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	framework "github.com/vmware-tanzu/velero/test/e2e/test"
	k8sutil "github.com/vmware-tanzu/velero/test/util/k8s"
	veleroutil "github.com/vmware-tanzu/velero/test/util/velero"
)

type PeriodicalCase struct {
	framework.TestCase
	ScheduleName string
	ScheduleArgs []string
	Period       int // The minimum unit is minute.
}

var SchedulePeriodicalTest func() = framework.TestFunc(&PeriodicalCase{})

func (n *PeriodicalCase) Init() error {
	Expect(n.TestCase.Init()).To(Succeed())

	n.CaseBaseName = "schedule-backup-" + n.UUIDgen
	n.NSIncluded = &[]string{n.CaseBaseName}
	n.ScheduleName = "schedule-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName
	n.TestMsg = &framework.TestMSG{
		Desc:      "Set up a scheduled backup defined by a Cron expression",
		FailedMSG: "Failed to schedule a backup",
		Text:      "Should backup periodically according to the schedule",
	}
	n.ScheduleArgs = []string{
		"--include-namespaces", strings.Join(*n.NSIncluded, ","),
		"--schedule=@every 1m",
	}

	return nil
}

func (n *PeriodicalCase) CreateResources() error {
	for _, ns := range *n.NSIncluded {
		By(fmt.Sprintf("Creating namespaces %s ......\n", ns), func() {
			Expect(
				k8sutil.CreateNamespace(
					n.Ctx,
					n.Client,
					ns,
				),
			).To(
				Succeed(),
				fmt.Sprintf("Failed to create namespace %s", ns),
			)
		})

		cmName := n.CaseBaseName
		fmt.Printf("Creating ConfigMap %s in namespaces ...%s\n", cmName, ns)
		_, err := k8sutil.CreateConfigMap(
			n.Client.ClientGo,
			ns,
			cmName,
			nil,
			nil,
		)
		Expect(err).To(Succeed(), fmt.Sprintf("failed to create ConfigMap in the namespace %q", ns))
	}
	return nil
}

func (n *PeriodicalCase) Backup() error {
	By(fmt.Sprintf("Creating schedule %s ......\n", n.ScheduleName), func() {
		Expect(
			veleroutil.VeleroScheduleCreate(
				n.Ctx,
				n.VeleroCfg.VeleroCLI,
				n.VeleroCfg.VeleroNamespace,
				n.ScheduleName,
				n.ScheduleArgs,
			),
		).To(Succeed())
	})

	By(fmt.Sprintf("No immediate backup is created by schedule %s\n", n.ScheduleName), func() {
		backups, err := veleroutil.GetBackupsForSchedule(
			n.Ctx,
			n.Client.Kubebuilder,
			n.ScheduleName,
			n.VeleroCfg.Namespace,
		)
		Expect(err).To(Succeed())
		Expect(backups).To(BeEmpty())
	})

	By("Wait until schedule triggers backup.", func() {
		err := wait.PollUntilContextTimeout(
			n.Ctx,
			30*time.Second,
			5*time.Minute,
			true,
			func(ctx context.Context) (bool, error) {
				backups, err := veleroutil.GetBackupsForSchedule(
					n.Ctx,
					n.Client.Kubebuilder,
					n.ScheduleName,
					n.VeleroCfg.Namespace,
				)
				if err != nil {
					fmt.Println("Fail to get backups for schedule.")
					return false, err
				}

				// The triggered backup completed.
				if len(backups) == 1 &&
					backups[0].Status.Phase == velerov1api.BackupPhaseCompleted {
					n.BackupName = backups[0].Name
					return true, nil
				}

				return false, nil
			},
		)

		Expect(err).To(Succeed())
	})

	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore", n.RestoreName,
		"--from-backup", n.BackupName,
		"--wait",
	}

	By(fmt.Sprintf("Pause schedule %s ......\n", n.ScheduleName), func() {
		Expect(
			veleroutil.VeleroSchedulePause(
				n.Ctx,
				n.VeleroCfg.VeleroCLI,
				n.VeleroCfg.VeleroNamespace,
				n.ScheduleName,
			),
		).To(Succeed())
	})

	By(("Sleep 2 minutes"), func() {
		time.Sleep(2 * time.Minute)
	})

	backups, err := veleroutil.GetBackupsForSchedule(
		n.Ctx,
		n.Client.Kubebuilder,
		n.ScheduleName,
		n.VeleroCfg.Namespace,
	)
	Expect(err).To(Succeed(), fmt.Sprintf("Fail to get backups from schedule %s", n.ScheduleName))

	backupCountPostPause := len(backups)
	fmt.Printf("After pause, backups count is %d\n", backupCountPostPause)

	By(fmt.Sprintf("Verify no new backups from %s ......\n", n.ScheduleName), func() {
		Expect(backupCountPostPause).To(Equal(1))
	})

	By(fmt.Sprintf("Unpause schedule %s ......\n", n.ScheduleName), func() {
		Expect(
			veleroutil.VeleroScheduleUnpause(
				n.Ctx,
				n.VeleroCfg.VeleroCLI,
				n.VeleroCfg.VeleroNamespace,
				n.ScheduleName,
			),
		).To(Succeed())
	})

	return nil
}

func (n *PeriodicalCase) Verify() error {
	By("Namespaces were restored", func() {
		for _, ns := range *n.NSIncluded {
			_, err := k8sutil.GetConfigMap(n.Client.ClientGo, ns, n.CaseBaseName)
			Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("failed to list CM in namespace: %s\n", ns))
		}
	})
	return nil
}

func (n *PeriodicalCase) Clean() error {
	if CurrentSpecReport().Failed() && n.VeleroCfg.FailFast {
		fmt.Println("Test case failed and fail fast is enabled. Skip resource clean up.")
	} else {
		Expect(
			veleroutil.VeleroScheduleDelete(
				n.Ctx,
				n.VeleroCfg.VeleroCLI,
				n.VeleroCfg.VeleroNamespace,
				n.ScheduleName,
			),
		).To(Succeed())

		Expect(n.TestCase.Clean()).To(Succeed())
	}

	return nil
}
