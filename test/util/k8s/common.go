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

package k8s

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"context"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/velero/pkg/builder"
	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	common "github.com/vmware-tanzu/velero/test/util/common"
)

// ensureClusterExists returns whether or not a Kubernetes cluster exists for tests to be run on.
func EnsureClusterExists(ctx context.Context) error {
	return exec.CommandContext(ctx, "kubectl", "cluster-info").Run()
}

func CreateSecretFromFiles(ctx context.Context, client TestClient, namespace string, name string, files map[string]string) error {
	data := make(map[string][]byte)

	for key, filePath := range files {
		contents, err := os.ReadFile(filePath)
		if err != nil {
			return errors.WithMessagef(err, "Failed to read secret file %q", filePath)
		}

		data[key] = contents
	}
	secret := builder.ForSecret(namespace, name).Data(data).Result()
	_, err := client.ClientGo.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

// WaitForPods waits until all of the pods have gone to PodRunning state
func WaitForPods(ctx context.Context, client TestClient, namespace string, pods []string) error {
	timeout := 5 * time.Minute
	interval := 5 * time.Second
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		for _, podName := range pods {
			checkPod, err := client.ClientGo.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
			if err != nil {
				//Should ignore "etcdserver: request timed out" kind of errors, try to get pod status again before timeout.
				fmt.Println(errors.Wrap(err, fmt.Sprintf("Failed to verify pod %s/%s is %s, try again...\n", namespace, podName, corev1api.PodRunning)))
				return false, nil
			}
			// If any pod is still waiting we don't need to check any more so return and wait for next poll interval
			if checkPod.Status.Phase != corev1api.PodRunning {
				fmt.Printf("Pod %s is in state %s waiting for it to be %s\n", podName, checkPod.Status.Phase, corev1api.PodRunning)
				return false, nil
			}
		}
		// All pods were in PodRunning state, we're successful
		return true, nil
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to wait for pods in namespace %s to start running", namespace)
	}
	return nil
}

func GetPvcByPVCName(ctx context.Context, namespace, pvcName string) ([]string, error) {
	// Example:
	//    NAME                                  STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS             AGE
	//    kibishii-data-kibishii-deployment-0   Bound    pvc-94b9fdf2-c30f-4a7b-87bf-06eadca0d5b6   1Gi        RWO            kibishii-storage-class   115s
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "pvc", "-n", namespace},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{pvcName},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)
	return common.GetListByCmdPipes(ctx, cmds)
}

func GetPvByPvc(ctx context.Context, namespace, pvc string) ([]string, error) {
	// Example:
	// 	  NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                              STORAGECLASS             REASON   AGE
	//    pvc-3f784366-58db-40b2-8fec-77307807e74b   1Gi        RWO            Delete           Bound    bsl-deletion/kibishii-data-kibishii-deployment-0   kibishii-storage-class            6h41m
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "pv"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{namespace + "/" + pvc},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func CRDShouldExist(ctx context.Context, name string) error {
	return CRDCountShouldBe(ctx, name, 1)
}

func CRDShouldNotExist(ctx context.Context, name string) error {
	return CRDCountShouldBe(ctx, name, 0)
}

func CRDCountShouldBe(ctx context.Context, name string, count int) error {
	crdList, err := GetCRD(ctx, name)
	if err != nil {
		return errors.Wrap(err, "Fail to get CRDs")
	}
	len := len(crdList)
	if len != count {
		return errors.New(fmt.Sprintf("CRD count is expected as %d instead of %d", count, len))
	}
	return nil
}

func GetCRD(ctx context.Context, name string) ([]string, error) {
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "crd"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{name},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func KubectlGetNS(ctx context.Context, name string) ([]string, error) {
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "ns"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{name},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func AddLabelToPv(ctx context.Context, pv, label string) error {
	return exec.CommandContext(ctx, "kubectl", "label", "pv", pv, label).Run()
}

func AddLabelToPvc(ctx context.Context, pvc, namespace, label string) error {
	args := []string{"label", "pvc", pvc, "-n", namespace, label}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}

func AddLabelToPod(ctx context.Context, podName, namespace, label string) error {
	args := []string{"label", "pod", podName, "-n", namespace, label}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}

func AddLabelToCRD(ctx context.Context, crd, label string) error {
	args := []string{"label", "crd", crd, label}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}

func KubectlApplyByFile(ctx context.Context, file string) error {
	args := []string{"apply", "-f", file, "--force=true"}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}

func KubectlDeleteByFile(ctx context.Context, file string) error {
	args := []string{"delete", "-f", file, "--force=true"}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}

func KubectlConfigUseContext(ctx context.Context, kubectlContext string) error {
	cmd := exec.CommandContext(ctx, "kubectl",
		"config", "use-context", kubectlContext)
	fmt.Printf("Kubectl config use-context cmd =%v\n", cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Print(stdout)
	fmt.Print(stderr)
	return err
}

func GetAPIVersions(client *TestClient, name string) ([]string, error) {
	var version []string
	APIGroup, err := client.ClientGo.Discovery().ServerGroups()
	if err != nil {
		return nil, errors.Wrap(err, "Fail to get server API groups")
	}
	for _, group := range APIGroup.Groups {
		if group.Name == name {
			for _, v := range group.Versions {
				fmt.Println(v.Version)
				version = append(version, v.Version)
			}
			return version, nil
		}
	}
	return nil, errors.New("Fail to get server API groups")
}

func GetPVByPVCName(client TestClient, namespace, pvcName string) (string, error) {
	pvcList, err := GetPvcByPVCName(context.Background(), namespace, pvcName)
	if err != nil {
		return "", err
	}
	if len(pvcList) != 1 {
		return "", errors.New(fmt.Sprintf("Only 1 PVC of pod %s should be found under namespace %s but got %v", pvcName, namespace, pvcList))
	}
	pvList, err := GetPvByPvc(context.Background(), namespace, pvcList[0])
	if err != nil {
		return "", err
	}
	if len(pvList) != 1 {
		return "", errors.New(fmt.Sprintf("Only 1 PV of PVC %s pod %s should be found under namespace %s", pvcList[0], pvcName, namespace))
	}
	pv_value, err := GetPersistentVolume(context.Background(), client, "", pvList[0])
	fmt.Println(pv_value.Annotations["pv.kubernetes.io/provisioned-by"])
	if err != nil {
		return "", err
	}
	return pv_value.Name, nil
}

func PrepareVolumeList(volumeNameList []string) (vols []*corev1api.Volume) {
	for i, volume := range volumeNameList {
		vols = append(vols, &corev1api.Volume{
			Name: volume,
			VolumeSource: corev1api.VolumeSource{
				PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
					ClaimName: fmt.Sprintf("pvc-%d", i),
					ReadOnly:  false,
				},
			},
		})
	}
	return
}

func CalFileHashInPod(ctx context.Context, namespace, podName, containerName, filePath string) (string, error) {
	arg := []string{"exec", "-n", namespace, "-c", containerName, podName,
		"--", "/bin/sh", "-c", fmt.Sprintf("sha256sum %s | awk '{ print $1 }'", filePath)}
	cmd := exec.CommandContext(ctx, "kubectl", arg...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// Trim any leading or trailing whitespace characters from the output
	hash := string(output)
	hash = strings.TrimSpace(hash)

	return hash, nil
}

func WriteRandomDataToFileInPod(ctx context.Context, namespace, podName, containerName, volume, filename string, fileSize int64) error {
	arg := []string{"exec", "-n", namespace, "-c", containerName, podName,
		"--", "/bin/sh", "-c", fmt.Sprintf("dd if=/dev/urandom of=/%s/%s bs=%d count=1", volume, filename, fileSize)}
	cmd := exec.CommandContext(ctx, "kubectl", arg...)
	fmt.Printf("Kubectl exec cmd =%v\n", cmd)
	return cmd.Run()
}

func CreateFileToPod(
	namespace string,
	podName string,
	containerName string,
	volume string,
	filename string,
	content string,
	workerOS string,
) error {
	filePath := fmt.Sprintf("/%s/%s", volume, filename)
	shell := "/bin/sh"
	shellParameter := "-c"

	if workerOS == common.WorkerOSWindows {
		filePath = fmt.Sprintf("C:\\%s\\%s", volume, filename)
		shell = "cmd"
		shellParameter = "/c"
	}

	arg := []string{"exec", "-n", namespace, "-c", containerName, podName,
		"--", shell, shellParameter, fmt.Sprintf("echo ns-%s pod-%s volume-%s  > %s", namespace, podName, volume, filePath)}

	cmd := exec.CommandContext(context.Background(), "kubectl", arg...)
	fmt.Printf("Kubectl exec cmd =%v\n", cmd)

	return cmd.Run()
}

func FileExistInPV(
	ctx context.Context,
	namespace string,
	podName string,
	containerName string,
	volume string,
	filename string,
	workerOS string,
) (bool, error) {
	stdout, stderr, err := ReadFileFromPodVolume(namespace, podName, containerName, volume, filename, workerOS)

	output := fmt.Sprintf("%s:%s:%s", stdout, stderr, err)

	if workerOS == common.WorkerOSWindows {
		if strings.Contains(output, "The system cannot find the file specified") {
			return false, nil
		}
	}

	if strings.Contains(output, fmt.Sprintf("/%s/%s: No such file or directory", volume, filename)) {
		return false, nil
	}

	if err == nil {
		return true, nil
	} else {
		return false, errors.Wrap(err, fmt.Sprintf("Fail to read file %s from volume %s of pod %s in %s",
			filename, volume, podName, namespace))
	}
}

func ReadFileFromPodVolume(
	namespace string,
	podName string,
	containerName string,
	volume string,
	filename string,
	workerOS string,
) (string, string, error) {
	arg := []string{"exec", "-n", namespace, "-c", containerName, podName,
		"--", "cat", fmt.Sprintf("/%s/%s", volume, filename)}

	if workerOS == common.WorkerOSWindows {
		arg = []string{"exec", "-n", namespace, "-c", containerName, podName,
			"--", "cmd", "/c", "type", fmt.Sprintf("C:\\%s\\%s", volume, filename)}
	}

	cmd := exec.CommandContext(context.Background(), "kubectl", arg...)
	fmt.Printf("kubectl exec cmd =%v\n", cmd)

	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Printf("stdout: %s\n", stdout)
	fmt.Printf("stderr: %s\n", stderr)
	fmt.Printf("err: %v\n", err)

	return stdout, stderr, err
}

func RunCommand(cmdName string, arg []string) string {
	cmd := exec.CommandContext(context.Background(), cmdName, arg...)
	fmt.Printf("Run cmd =%v\n", cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		fmt.Println(stderr)
		fmt.Println(err)
	}
	return stdout
}

func KubectlGetDsJson(veleroNamespace string) (string, error) {
	arg := []string{"get", "ds", "-n", veleroNamespace, "-ojson"}
	cmd := exec.CommandContext(context.Background(), "kubectl", arg...)
	fmt.Printf("Kubectl exec cmd =%v\n", cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Println(stdout)
	if err != nil {
		fmt.Println(stderr)
		fmt.Println(err)
		return "", err
	}
	return stdout, nil
}

func DeleteVeleroDs(ctx context.Context) error {
	args := []string{"delete", "ds", "-n", "velero", "--all", "--force", "--grace-period", "0"}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}

func WaitForCRDEstablished(crdName string) error {
	arg := []string{"wait", "--for", "condition=established", "--timeout=60s", "crd/" + crdName}
	cmd := exec.CommandContext(context.Background(), "kubectl", arg...)
	fmt.Printf("Kubectl exec cmd =%v\n", cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Println(stdout)
	if err != nil {
		fmt.Println(stderr)
		fmt.Println(err)
		return err
	}
	return nil
}

func GetAllService(ctx context.Context) (string, error) {
	args := []string{"get", "service", "-A"}
	cmd := exec.CommandContext(context.Background(), "kubectl", args...)
	fmt.Printf("Kubectl exec cmd =%v\n", cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Println(stdout)
	if err != nil {
		fmt.Println(stderr)
		fmt.Println(err)
		return "", err
	}
	return stdout, nil
}

func CreateVolumes(pvcName string, volumeNameList []string) (vols []*corev1api.Volume) {
	vols = []*corev1api.Volume{}
	for _, volume := range volumeNameList {
		vols = append(vols, &corev1api.Volume{
			Name: volume,
			VolumeSource: corev1api.VolumeSource{
				PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
					ClaimName: pvcName,
					ReadOnly:  false,
				},
			},
		})
	}
	return
}

func CollectClusterEvents(key string, pods []string) {
	prefix := "pod"
	date := RunCommand("date", []string{"-u"})
	logs := []string{}
	logs = append(logs, date)
	logs = append(logs, RunCommand("kubectl", []string{"get", "events", "-o", "custom-columns=FirstSeen:.firstTimestamp,Count:.count,From:.source.component,Type:.type,Reason:.reason,Message:.message", "--all-namespaces"}))
	logs = append(logs, RunCommand("kubectl", []string{"get", "events", "-o", "yaml", "--all-namespaces"}))
	for _, pod := range pods {
		logs = append(logs, RunCommand("kubectl", []string{"logs", "-n", "velero", pod, "--previous"}))
		prefix = fmt.Sprintf("%s-%s", prefix, pod)
	}
	logs = append(logs, RunCommand("date", []string{"-u"}))
	log := strings.Join(logs, "\n")

	fileName := fmt.Sprintf("%s-%s", prefix, key)
	fmt.Printf("Cluster event log file %s: %s", fileName, log)

	err := common.WriteToFile(log, fileName)
	if err != nil {
		fmt.Printf("Fail to log cluster event: %v", err)
	}
}
