package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	common "github.com/velero-io/velero/test/util/common"
)

func GetWorkerNodes(ctx context.Context, workerOS string) ([]string, error) {
	getCMD := exec.CommandContext(
		ctx,
		"kubectl", "get", "node", "-l",
		fmt.Sprintf("kubernetes.io/os=%s", workerOS),
		"-o", "json",
	)

	fmt.Printf("kubectl get node cmd =%v\n", getCMD)
	jsonBuf, err := common.CMDExecWithOutput(getCMD)
	if err != nil {
		return nil, err
	}

	nodes := &unstructured.UnstructuredList{}
	err = json.Unmarshal(*jsonBuf, &nodes)
	if err != nil {
		return nil, err
	}
	var nodeNameList []string
	for nodeIndex, node := range nodes.Items {
		fmt.Println(nodeIndex)
		fmt.Println(node.GetName())
		anns := node.GetAnnotations()
		lbls := node.GetLabels()
		fmt.Println(anns)
		fmt.Println(lbls)
		// For Kubeadm vanilla cluster control-plane node selection
		if _, ok := lbls["node-role.kubernetes.io/control-plane"]; ok {
			continue
		}
		// For public cloud provider cluster control-plane node selection
		if anns["cluster.x-k8s.io/owner-kind"] == "KubeadmControlPlane" {
			continue
		}
		nodeNameList = append(nodeNameList, node.GetName())
	}
	fmt.Println(nodeNameList)
	return nodeNameList, nil
}
