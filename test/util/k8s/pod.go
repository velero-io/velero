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
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	common "github.com/vmware-tanzu/velero/test/util/common"
)

func CreatePod(
	client TestClient,
	ns, name, sc, pvcName string,
	volumeNameList []string,
	pvcAnn, ann map[string]string,
	imageRegistryProxy string,
	workerOS string,
) (*corev1api.Pod, error) {
	if pvcName != "" && len(volumeNameList) != 1 {
		return nil, errors.New("Volume name list should contain only 1 since PVC name is not empty")
	}

	// Default to Linux environment
	imageAddress := LinuxTestImage
	command := []string{"sleep", "infinity"}
	args := make([]string, 0)
	var affinity corev1api.Affinity
	var tolerations []corev1api.Toleration

	if workerOS == common.WorkerOSLinux && imageRegistryProxy != "" {
		imageAddress = path.Join(imageRegistryProxy, LinuxTestImage)
	}

	containerSecurityContext := &corev1api.SecurityContext{
		AllowPrivilegeEscalation: boolptr.False(),
		Capabilities: &corev1api.Capabilities{
			Drop: []corev1api.Capability{"ALL"},
		},
		RunAsNonRoot: boolptr.True(),
		RunAsUser:    func(i int64) *int64 { return &i }(65534),
		RunAsGroup:   func(i int64) *int64 { return &i }(65534),
		SeccompProfile: &corev1api.SeccompProfile{
			Type: corev1api.SeccompProfileTypeRuntimeDefault,
		},
	}

	podSecurityContext := &corev1api.PodSecurityContext{
		FSGroup:             func(i int64) *int64 { return &i }(65534),
		FSGroupChangePolicy: func(policy corev1api.PodFSGroupChangePolicy) *corev1api.PodFSGroupChangePolicy { return &policy }(corev1api.FSGroupChangeAlways),
	}

	// Settings for Windows
	if workerOS == common.WorkerOSWindows {
		imageAddress = WindowTestImage
		command = []string{"cmd"}
		args = []string{"/c", "ping -t localhost > NUL"}
		affinity = corev1api.Affinity{
			NodeAffinity: &corev1api.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
					NodeSelectorTerms: []corev1api.NodeSelectorTerm{
						{
							MatchExpressions: []corev1api.NodeSelectorRequirement{
								{
									Key:      "kubernetes.io/os",
									Values:   []string{common.WorkerOSWindows},
									Operator: corev1api.NodeSelectorOpIn,
								},
							},
						},
					},
				},
			},
		}

		tolerations = []corev1api.Toleration{
			{
				Effect: corev1api.TaintEffectNoSchedule,
				Key:    "os",
				Value:  common.WorkerOSWindows,
			},
			{
				Effect: corev1api.TaintEffectNoExecute,
				Key:    "os",
				Value:  common.WorkerOSWindows,
			},
		}

		whetherToRunAsRoot := false
		containerSecurityContext = &corev1api.SecurityContext{
			RunAsNonRoot: &whetherToRunAsRoot,
		}

		containerUserName := "ContainerAdministrator"
		podSecurityContext = &corev1api.PodSecurityContext{
			WindowsOptions: &corev1api.WindowsSecurityContextOptions{
				RunAsUserName: &containerUserName,
			},
		}
	}

	volumes := []corev1api.Volume{}
	for _, volume := range volumeNameList {
		var _pvcName string
		if pvcName == "" {
			_pvcName = fmt.Sprintf("pvc-%s", volume)
		} else {
			_pvcName = pvcName
		}
		pvc, err := CreatePVC(client, ns, _pvcName, sc, pvcAnn)
		if err != nil {
			return nil, err
		}

		volumes = append(volumes, corev1api.Volume{
			Name: volume,
			VolumeSource: corev1api.VolumeSource{
				PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
					ClaimName: pvc.Name,
					ReadOnly:  false,
				},
			},
		})
	}

	vmList := []corev1api.VolumeMount{}
	for _, v := range volumes {
		vmList = append(vmList, corev1api.VolumeMount{
			Name:      v.Name,
			MountPath: "/" + v.Name,
		})
	}

	p := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: ann,
		},
		Spec: corev1api.PodSpec{
			SecurityContext: podSecurityContext,
			Containers: []corev1api.Container{
				{
					Name:            name,
					Image:           imageAddress,
					Command:         command,
					Args:            args,
					VolumeMounts:    vmList,
					SecurityContext: containerSecurityContext,
				},
			},
			Volumes:     volumes,
			Affinity:    &affinity,
			Tolerations: tolerations,
		},
	}

	return client.ClientGo.CoreV1().Pods(ns).Create(context.TODO(), p, metav1.CreateOptions{})
}

func GetPod(ctx context.Context, client TestClient, namespace string, pod string) (*corev1api.Pod, error) {
	return client.ClientGo.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
}

func AddAnnotationToPod(ctx context.Context, client TestClient, namespace, podName string, ann map[string]string) (*corev1api.Pod, error) {
	newPod, err := GetPod(ctx, client, namespace, podName)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Fail to ge pod %s in namespace %s", podName, namespace))
	}
	newAnn := newPod.ObjectMeta.Annotations
	if newAnn == nil {
		newAnn = make(map[string]string)
	}
	for k, v := range ann {
		fmt.Println(k, v)
		newAnn[k] = v
	}
	newPod.Annotations = newAnn
	fmt.Println(newPod.Annotations)

	// Strategic merge patch to add/update label
	patch := map[string]any{
		"metadata": map[string]any{
			"annotations": newAnn,
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		fmt.Println("fail to marshal patch for pod: ", err.Error())
		return nil, err
	}

	return client.ClientGo.CoreV1().Pods(namespace).Patch(
		ctx,
		newPod.Name,
		types.StrategicMergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
}

func ListPods(ctx context.Context, client TestClient, namespace string) (*corev1api.PodList, error) {
	return client.ClientGo.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
}
