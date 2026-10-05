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
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestGetPodVolumeHostPath(t *testing.T) {
	tests := []struct {
		name              string
		getVolumeDirFunc  func(context.Context, logrus.FieldLogger, *corev1api.Pod, string, kubernetes.Interface) (string, error)
		getVolumeModeFunc func(context.Context, logrus.FieldLogger, *corev1api.Pod, string, kubernetes.Interface) (uploader.PersistentVolumeMode, error)
		pathMatchFunc     func(string, filesystem.Interface, logrus.FieldLogger) (string, error)
		pod               *corev1api.Pod
		pvc               string
		err               string
	}{
		{
			name: "get volume dir fail",
			getVolumeDirFunc: func(context.Context, logrus.FieldLogger, *corev1api.Pod, string, kubernetes.Interface) (string, error) {
				return "", errors.New("fake-error-1")
			},
			pod: builder.ForPod(velerov1api.DefaultNamespace, "fake-pod-1").Result(),
			pvc: "fake-pvc-1",
			err: "error getting volume directory name for volume fake-pvc-1 in pod fake-pod-1: fake-error-1",
		},
		{
			name: "single path match fail",
			getVolumeDirFunc: func(context.Context, logrus.FieldLogger, *corev1api.Pod, string, kubernetes.Interface) (string, error) {
				return "", nil
			},
			getVolumeModeFunc: func(context.Context, logrus.FieldLogger, *corev1api.Pod, string, kubernetes.Interface) (uploader.PersistentVolumeMode, error) {
				return uploader.PersistentVolumeFilesystem, nil
			},
			pathMatchFunc: func(string, filesystem.Interface, logrus.FieldLogger) (string, error) {
				return "", errors.New("fake-error-2")
			},
			pod: builder.ForPod(velerov1api.DefaultNamespace, "fake-pod-2").Result(),
			pvc: "fake-pvc-1",
			err: "error identifying unique volume path on host for volume fake-pvc-1 in pod fake-pod-2: fake-error-2",
		},
		{
			name: "get block volume dir success",
			getVolumeDirFunc: func(context.Context, logrus.FieldLogger, *corev1api.Pod, string, kubernetes.Interface) (
				string, error) {
				return "fake-pvc-1", nil
			},
			pathMatchFunc: func(string, filesystem.Interface, logrus.FieldLogger) (string, error) {
				return "/host_pods/fake-pod-1-id/volumeDevices/kubernetes.io~csi/fake-pvc-1-id", nil
			},
			pod: builder.ForPod(velerov1api.DefaultNamespace, "fake-pod-1").Result(),
			pvc: "fake-pvc-1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.getVolumeDirFunc != nil {
				getVolumeDirectory = test.getVolumeDirFunc
			}

			if test.getVolumeModeFunc != nil {
				getVolumeMode = test.getVolumeModeFunc
			}

			if test.pathMatchFunc != nil {
				singlePathMatch = test.pathMatchFunc
			}

			_, err := GetPodVolumeHostPath(t.Context(), test.pod, test.pvc, nil, nil, velerotest.NewLogger())
			if test.err != "" || err != nil {
				assert.EqualError(t, err, test.err)
			}
		})
	}
}

func TestExtractPodVolumeHostPath(t *testing.T) {
	tests := []struct {
		name               string
		getHostPodPathFunc func(context.Context, kubernetes.Interface, string, string) (string, error)
		path               string
		osType             string
		expectedErr        string
		expected           string
	}{
		{
			name: "get host pod path error",
			getHostPodPathFunc: func(context.Context, kubernetes.Interface, string, string) (string, error) {
				return "", errors.New("fake-error-1")
			},

			expectedErr: "error getting host pod path from node-agent: fake-error-1",
		},
		{
			name: "Windows os",
			getHostPodPathFunc: func(context.Context, kubernetes.Interface, string, string) (string, error) {
				return "/var/lib/kubelet/pods", nil
			},
			path:     fmt.Sprintf("\\%s\\pod-id-xxx\\volumes\\kubernetes.io~csi\\pvc-id-xxx\\mount", nodeagent.HostPodVolumeMountPoint),
			osType:   kube.NodeOSWindows,
			expected: "\\var\\lib\\kubelet\\pods\\pod-id-xxx\\volumes\\kubernetes.io~csi\\pvc-id-xxx\\mount",
		},
		{
			name: "linux OS",
			getHostPodPathFunc: func(context.Context, kubernetes.Interface, string, string) (string, error) {
				return "/var/lib/kubelet/pods", nil
			},
			path:     fmt.Sprintf("/%s/pod-id-xxx/volumes/kubernetes.io~csi/pvc-id-xxx/mount", nodeagent.HostPodVolumeMountPoint),
			osType:   kube.NodeOSLinux,
			expected: "/var/lib/kubelet/pods/pod-id-xxx/volumes/kubernetes.io~csi/pvc-id-xxx/mount",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.getHostPodPathFunc != nil {
				getHostPodPath = test.getHostPodPathFunc
			}

			path, err := ExtractPodVolumeHostPath(t.Context(), test.path, nil, "", test.osType)

			if test.expectedErr != "" {
				assert.EqualError(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expected, path)
			}
		})
	}
}
