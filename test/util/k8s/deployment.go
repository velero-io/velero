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
	"path"
	"time"

	"context"

	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"

	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	common "github.com/vmware-tanzu/velero/test/util/common"
)

const (
	JobSelectorKey = "job"
	// Poll is how often to Poll pods, nodes and claims.
	PollInterval         = 2 * time.Second
	PollTimeout          = 15 * time.Minute
	DefaultContainerName = "container-busybox"
	LinuxTestImage       = "busybox:1.37.0"
	WindowTestImage      = "mcr.microsoft.com/windows/nanoserver:ltsc2022"
)

// DeploymentBuilder builds Deployment objects.
type DeploymentBuilder struct {
	*appsv1api.Deployment
}

func (d *DeploymentBuilder) Result() *appsv1api.Deployment {
	return d.Deployment
}

// newDeployment returns a RollingUpdate Deployment with a fake container image
func NewDeployment(
	name, ns string,
	replicas int32,
	labels map[string]string,
	imageRegistryProxy string,
	workerOS string,
) *DeploymentBuilder {
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
									Key:      corev1api.LabelOSStable,
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

	containers := []corev1api.Container{
		{
			Name:    DefaultContainerName,
			Image:   imageAddress,
			Command: command,
			Args:    args,
			// Make pod obeys the restricted pod security standards.
			SecurityContext: containerSecurityContext,
		},
	}

	return &DeploymentBuilder{
		&appsv1api.Deployment{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Deployment",
				APIVersion: "apps/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
				Labels:    labels,
			},
			Spec: appsv1api.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{MatchLabels: labels},
				Strategy: appsv1api.DeploymentStrategy{
					Type:          appsv1api.RollingUpdateDeploymentStrategyType,
					RollingUpdate: new(appsv1api.RollingUpdateDeployment),
				},
				Template: corev1api.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: labels,
					},
					Spec: corev1api.PodSpec{
						SecurityContext: podSecurityContext,
						Containers:      containers,
						Affinity:        &affinity,
						Tolerations:     tolerations,
					},
				},
			},
		},
	}
}

func (d *DeploymentBuilder) WithVolume(volumes []*corev1api.Volume) *DeploymentBuilder {
	vmList := []corev1api.VolumeMount{}
	for _, v := range volumes {
		vmList = append(vmList, corev1api.VolumeMount{
			Name:      v.Name,
			MountPath: "/" + v.Name,
		})
		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, *v)
	}

	// NOTE here just mount volumes to the first container
	d.Spec.Template.Spec.Containers[0].VolumeMounts = vmList
	return d
}

func CreateDeployment(c clientset.Interface, ns string, deployment *appsv1api.Deployment) (*appsv1api.Deployment, error) {
	return c.AppsV1().Deployments(ns).Create(context.TODO(), deployment, metav1.CreateOptions{})
}

func GetDeployment(c clientset.Interface, ns, name string) (*appsv1api.Deployment, error) {
	return c.AppsV1().Deployments(ns).Get(context.TODO(), name, metav1.GetOptions{})
}

// WaitForReadyDeployment waits for number of ready replicas to equal number of replicas.
func WaitForReadyDeployment(c clientset.Interface, ns, name string) error {
	if err := wait.PollImmediate(PollInterval, PollTimeout, func() (bool, error) {
		deployment, err := c.AppsV1().Deployments(ns).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to get deployment %q: %v", name, err)
		}
		return deployment.Status.ReadyReplicas == *deployment.Spec.Replicas, nil
	}); err != nil {
		return fmt.Errorf("failed to wait for .readyReplicas to equal .replicas: %v", err)
	}
	return nil
}
