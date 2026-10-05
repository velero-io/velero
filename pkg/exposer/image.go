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

package exposer

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vmware-tanzu/velero/pkg/nodeagent"
)

const (
	// excludeHostPathVolumes indicates that the volumes backed by a host path are not
	// inherited from the node-agent. The exposers accessing data through PVCs use it so
	// that the hosting pods don't get unnecessary access to the host file system.
	excludeHostPathVolumes = true

	// inheritHostPathVolumes indicates that the volumes backed by a host path are
	// inherited from the node-agent. fs-backup uses it because it resolves and accesses
	// the pod volume data through the kubelet pod directory on the host.
	inheritHostPathVolumes = false
)

type inheritedPodInfo struct {
	image            string
	serviceAccount   string
	env              []corev1api.EnvVar
	envFrom          []corev1api.EnvFromSource
	volumeMounts     []corev1api.VolumeMount
	volumes          []corev1api.Volume
	logLevelArgs     []string
	logFormatArgs    []string
	dnsPolicy        corev1api.DNSPolicy
	dnsConfig        *corev1api.PodDNSConfig
	imagePullSecrets []corev1api.LocalObjectReference
}

// getInheritedPodInfo collects the pod info to be inherited by the hosting pods from the
// node-agent pod template. When excludeHostPath is true, the volumes backed by a host path,
// together with their volume mounts, are dropped from the result. The volumes are detected
// by their source instead of their name, so the ones customized in the node-agent daemonset
// are covered as well.
func getInheritedPodInfo(ctx context.Context, client kubernetes.Interface, veleroNamespace string, osType string, excludeHostPath bool) (inheritedPodInfo, error) {
	podInfo := inheritedPodInfo{}

	podSpec, err := nodeagent.GetPodSpec(ctx, client, veleroNamespace, osType)
	if err != nil {
		return podInfo, errors.Wrap(err, "error to get node-agent pod template")
	}

	if len(podSpec.Containers) != 1 {
		return podInfo, errors.New("unexpected pod template from node-agent")
	}

	podInfo.image = podSpec.Containers[0].Image
	podInfo.serviceAccount = podSpec.ServiceAccountName

	podInfo.env = podSpec.Containers[0].Env
	podInfo.envFrom = podSpec.Containers[0].EnvFrom
	podInfo.volumeMounts, podInfo.volumes = filterVolumes(podSpec.Containers[0].VolumeMounts, podSpec.Volumes, excludeHostPath)

	podInfo.dnsPolicy = podSpec.DNSPolicy
	podInfo.dnsConfig = podSpec.DNSConfig

	args := podSpec.Containers[0].Args
	for i, arg := range args {
		if arg == "--log-format" {
			podInfo.logFormatArgs = append(podInfo.logFormatArgs, args[i:i+2]...)
		} else if strings.HasPrefix(arg, "--log-format") {
			podInfo.logFormatArgs = append(podInfo.logFormatArgs, arg)
		} else if arg == "--log-level" {
			podInfo.logLevelArgs = append(podInfo.logLevelArgs, args[i:i+2]...)
		} else if strings.HasPrefix(arg, "--log-level") {
			podInfo.logLevelArgs = append(podInfo.logLevelArgs, arg)
		}
	}

	podInfo.imagePullSecrets = podSpec.ImagePullSecrets

	return podInfo, nil
}

// filterVolumes removes the volumes backed by a host path, as well as the volume mounts
// referring to them, when excludeHostPath is true. The volumes are recognized by their
// source, so the host path volumes customized in the node-agent daemonset are removed as
// well. The other volumes, including the ones customized by users, are kept as is.
func filterVolumes(volumeMounts []corev1api.VolumeMount, volumes []corev1api.Volume, excludeHostPath bool) ([]corev1api.VolumeMount, []corev1api.Volume) {
	if !excludeHostPath {
		return volumeMounts, volumes
	}

	excluded := make(map[string]struct{})
	retainedVolumes := make([]corev1api.Volume, 0, len(volumes))
	for _, volume := range volumes {
		if volume.HostPath != nil {
			excluded[volume.Name] = struct{}{}
			continue
		}

		retainedVolumes = append(retainedVolumes, volume)
	}

	retainedMounts := make([]corev1api.VolumeMount, 0, len(volumeMounts))
	for _, volumeMount := range volumeMounts {
		if _, found := excluded[volumeMount.Name]; found {
			continue
		}

		retainedMounts = append(retainedMounts, volumeMount)
	}

	return retainedMounts, retainedVolumes
}
