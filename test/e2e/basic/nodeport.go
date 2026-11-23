package basic

import (
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	. "github.com/velero-io/velero/test/e2e/test"
	. "github.com/velero-io/velero/test/util/k8s"
	. "github.com/velero-io/velero/test/util/velero"
)

type NodePort struct {
	TestCase
	labels               map[string]string
	serviceName          string
	namespaceToCollision []string
	nodePort             int32
}

const NodeportBaseName string = "nodeport-"

var NodePortTest func() = TestFunc(&NodePort{})

func (n *NodePort) Init() error {
	n.TestCase.Init()
	n.CaseBaseName = NodeportBaseName + n.UUIDgen
	n.BackupName = "backup-" + n.CaseBaseName
	n.RestoreName = "restore-" + n.CaseBaseName
	n.serviceName = "nginx-service-" + n.CaseBaseName
	n.NamespacesTotal = 1
	n.TestMsg = &TestMSG{
		Desc:      "Nodeport preservation",
		FailedMSG: "Failed to restore with nodeport preservation",
		Text:      "Nodeport can be preserved or omit during restore",
	}

	n.labels = map[string]string{"app": "nginx"}
	n.NSIncluded = &[]string{}
	for nsNum := 0; nsNum < n.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", n.CaseBaseName, nsNum)
		n.namespaceToCollision = append(n.namespaceToCollision, createNSName+"-tmp")
		*n.NSIncluded = append(*n.NSIncluded, createNSName)
	}

	n.BackupArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "backup", n.BackupName,
		"--include-namespaces", strings.Join(*n.NSIncluded, ","), "--wait",
	}
	n.RestoreArgs = []string{
		"create", "--namespace", n.VeleroCfg.VeleroNamespace, "restore",
		"--from-backup", n.BackupName,
		"--wait",
	}
	return nil
}

func (n *NodePort) CreateResources() error {
	for _, ns := range *n.NSIncluded {
		By(fmt.Sprintf("Creating service %s in namespaces %s ......\n", n.serviceName, ns), func() {
			Expect(CreateNamespace(n.Ctx, n.Client, ns)).To(Succeed(), fmt.Sprintf("Failed to create namespace %s", ns))
			Expect(createServiceWithNodeport(n.Ctx, n.Client, ns, n.serviceName, n.labels, 0)).To(Succeed(), fmt.Sprintf("Failed to create service %s", n.serviceName))
			service, err := GetService(n.Ctx, n.Client, ns, n.serviceName)
			Expect(err).To(Succeed())
			Expect(service.Spec.Ports).To(HaveLen(1))
			n.nodePort = service.Spec.Ports[0].NodePort
			_, err = GetAllService(n.Ctx)
			Expect(err).To(Succeed(), "fail to get service")
		})
	}
	return nil
}

func (n *NodePort) Destroy() error {
	for i, ns := range *n.NSIncluded {
		By(fmt.Sprintf("Start to destroy namespace %s......", n.CaseBaseName), func() {
			Expect(CleanupNamespacesWithPoll(n.Ctx, n.Client, NodeportBaseName)).To(Succeed(),
				fmt.Sprintf("Failed to delete namespace %s", n.CaseBaseName))
			Expect(WaitForServiceDelete(n.Client, ns, n.serviceName, false)).To(Succeed(), "fail to delete service")
			_, err := GetAllService(n.Ctx)
			Expect(err).To(Succeed(), "fail to get service")
		})

		By(fmt.Sprintf("Creating a new service which has the same nodeport as backed up service has in a new namespaces for nodeport collision ...%s\n", n.namespaceToCollision[i]), func() {
			Expect(CreateNamespace(n.Ctx, n.Client, n.namespaceToCollision[i])).To(Succeed(), fmt.Sprintf("Failed to create namespace %s", n.namespaceToCollision[i]))
			Expect(createServiceWithNodeport(n.Ctx, n.Client, n.namespaceToCollision[i], n.serviceName, n.labels, n.nodePort)).To(Succeed(), fmt.Sprintf("Failed to create service %s", n.serviceName))
			_, err := GetAllService(n.Ctx)
			Expect(err).To(Succeed(), "fail to get service")
		})
	}

	return nil
}

func (n *NodePort) Restore() error {
	index := 4
	restoreName1 := n.RestoreName + "-1"
	restoreName2 := restoreName1 + "-1"

	args := n.RestoreArgs
	args = append(args[:index], append([]string{n.RestoreName}, args[index:]...)...)
	args = append(args, "--preserve-nodeports=true")
	By(fmt.Sprintf("Start to restore %s with nodeports preservation when port %d is already occupied by other service", n.RestoreName, n.nodePort), func() {
		Expect(VeleroRestoreExec(n.Ctx, n.VeleroCfg.VeleroCLI,
			n.VeleroCfg.VeleroNamespace, n.RestoreName,
			args, velerov1api.RestorePhasePartiallyFailed)).To(
			Succeed(),
			func() string {
				RunDebug(context.Background(), n.VeleroCfg.VeleroCLI,
					n.VeleroCfg.VeleroNamespace, "", n.RestoreName)
				return "Fail to restore workload"
			})
	})

	args = n.RestoreArgs
	args = append(args[:index], append([]string{restoreName1}, args[index:]...)...)
	args = append(args, "--preserve-nodeports=false")
	By(fmt.Sprintf("Start to restore %s without nodeports preservation ......", restoreName1), func() {
		Expect(VeleroRestoreExec(n.Ctx, n.VeleroCfg.VeleroCLI, n.VeleroCfg.VeleroNamespace,
			restoreName1, args, velerov1api.RestorePhaseCompleted)).To(Succeed(), func() string {
			RunDebug(context.Background(), n.VeleroCfg.VeleroCLI, n.VeleroCfg.VeleroNamespace, "", restoreName1)
			return "Fail to restore workload"
		})
	})

	for i, ns := range *n.NSIncluded {
		By(fmt.Sprintf("Delete service %s by deleting namespace %s", n.serviceName, ns), func() {
			service, err := GetService(n.Ctx, n.Client, ns, n.serviceName)
			Expect(err).To(Succeed())
			Expect(service.Spec.Ports).To(HaveLen(1))
			fmt.Println(service.Spec.Ports)
			Expect(DeleteNamespace(n.Ctx, n.Client, ns, true)).To(Succeed())
		})

		By(fmt.Sprintf("Start to delete service %s in namespace %s ......", n.serviceName, n.namespaceToCollision[i]), func() {
			Expect(WaitForServiceDelete(n.Client, n.namespaceToCollision[i], n.serviceName, true)).To(Succeed(), "fail to delete service")
			_, err := GetAllService(n.Ctx)
			Expect(err).To(Succeed(), "fail to get service")
		})
		args = n.RestoreArgs
		args = append(args[:index], append([]string{restoreName2}, args[index:]...)...)
		args = append(args, "--preserve-nodeports=true")
		By(fmt.Sprintf("Start to restore %s with nodeports preservation ......", restoreName2), func() {
			Expect(VeleroRestoreExec(n.Ctx, n.VeleroCfg.VeleroCLI, n.VeleroCfg.VeleroNamespace,
				restoreName2, args, velerov1api.RestorePhaseCompleted)).To(Succeed(), func() string {
				RunDebug(context.Background(), n.VeleroCfg.VeleroCLI, n.VeleroCfg.VeleroNamespace, "", restoreName2)
				return "Fail to restore workload"
			})
		})

		By(fmt.Sprintf("Verify service %s was restore successfully with the origin nodeport.", ns), func() {
			service, err := GetService(n.Ctx, n.Client, ns, n.serviceName)
			Expect(err).To(Succeed())
			Expect(service.Spec.Ports).To(HaveLen(1))
			Expect(service.Spec.Ports[0].NodePort).To(Equal(n.nodePort))
		})
	}

	return nil
}

func createServiceWithNodeport(ctx context.Context, client TestClient, namespace string,
	service string, labels map[string]string, nodePort int32) error {
	serviceSpec := &corev1api.ServiceSpec{
		Ports: []corev1api.ServicePort{
			{
				Port:       80,
				TargetPort: intstr.IntOrString{IntVal: 80},
				NodePort:   nodePort,
			},
		},
		Selector: nil,
		Type:     corev1api.ServiceTypeLoadBalancer,
	}
	return CreateService(ctx, client, namespace, service, labels, serviceSpec)
}
