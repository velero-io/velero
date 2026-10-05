/*
Copyright The Velero Contributors.

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
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vmware-tanzu/velero/pkg/datapath"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

var getVolumeDirectory = kube.GetVolumeDirectory
var getVolumeMode = kube.GetVolumeMode
var singlePathMatch = kube.SinglePathMatch

// GetPodVolumeHostPath returns a path that can be accessed from the host for a given volume of a pod
func GetPodVolumeHostPath(ctx context.Context, pod *corev1api.Pod, volumeName string,
	kubeClient kubernetes.Interface, fs filesystem.Interface, log logrus.FieldLogger) (datapath.AccessPoint, error) {
	logger := log.WithField("pod name", pod.Name).WithField("pod UID", pod.GetUID()).WithField("volume", volumeName)

	volDir, err := getVolumeDirectory(ctx, logger, pod, volumeName, kubeClient)
	if err != nil {
		return datapath.AccessPoint{}, errors.Wrapf(err, "error getting volume directory name for volume %s in pod %s", volumeName, pod.Name)
	}

	logger.WithField("volDir", volDir).Info("Got volume dir")

	volMode, err := getVolumeMode(ctx, logger, pod, volumeName, kubeClient)
	if err != nil {
		return datapath.AccessPoint{}, errors.Wrapf(err, "error getting volume mode for volume %s in pod %s", volumeName, pod.Name)
	}

	volSubDir := "volumes"
	if volMode == uploader.PersistentVolumeBlock {
		volSubDir = "volumeDevices"
	}

	pathGlob := fmt.Sprintf("%s/%s/%s/*/%s", nodeagent.HostPodVolumeMountPath(), string(pod.GetUID()), volSubDir, volDir)
	logger.WithField("pathGlob", pathGlob).Debug("Looking for path matching glob")

	path, err := singlePathMatch(pathGlob, fs, logger)
	if err != nil {
		return datapath.AccessPoint{}, errors.Wrapf(err, "error identifying unique volume path on host for volume %s in pod %s", volumeName, pod.Name)
	}

	logger.WithField("path", path).Info("Found path matching glob")

	return datapath.AccessPoint{
		ByPath:  path,
		VolMode: volMode,
	}, nil
}

var getHostPodPath = nodeagent.GetHostPodPath

func ExtractPodVolumeHostPath(ctx context.Context, path string, kubeClient kubernetes.Interface, veleroNamespace string, osType string) (string, error) {
	podPath, err := getHostPodPath(ctx, kubeClient, veleroNamespace, osType)
	if err != nil {
		return "", errors.Wrap(err, "error getting host pod path from node-agent")
	}

	if osType == kube.NodeOSWindows {
		podPath = strings.Replace(podPath, "/", "\\", -1)
	}

	if osType == kube.NodeOSWindows {
		return strings.Replace(path, nodeagent.HostPodVolumeMountPathWin(), podPath, 1), nil
	} else {
		return strings.Replace(path, nodeagent.HostPodVolumeMountPath(), podPath, 1), nil
	}
}
