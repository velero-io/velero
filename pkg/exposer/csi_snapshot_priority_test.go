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
	"testing"
	"time"

	snapshotFake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestCreateBackupPodWithPriorityClass(t *testing.T) {
	testCases := []struct {
		name                   string
		nodeAgentConfigMapData string
		expectedPriorityClass  string
		description            string
	}{
		{
			name: "with priority class in config map",
			nodeAgentConfigMapData: `{
				"priorityClassName": "high-priority"
			}`,
			expectedPriorityClass: "high-priority",
			description:           "Should set priority class from node-agent-configmap",
		},
		{
			name: "without priority class in config map",
			nodeAgentConfigMapData: `{
				"loadAffinity": []
			}`,
			expectedPriorityClass: "",
			description:           "Should have empty priority class when not specified",
		},
		{
			name:                   "empty config map",
			nodeAgentConfigMapData: `{}`,
			expectedPriorityClass:  "",
			description:            "Should handle empty config map gracefully",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			// Create fake Kubernetes client
			kubeClient := fake.NewSimpleClientset()

			// Create node-agent daemonset (required for getInheritedPodInfo)
			daemonSet := &appsv1api.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-agent",
					Namespace: velerov1api.DefaultNamespace,
				},
				Spec: appsv1api.DaemonSetSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									Name:  "node-agent",
									Image: "velero/velero:latest",
								},
							},
						},
					},
				},
			}
			_, err := kubeClient.AppsV1().DaemonSets(velerov1api.DefaultNamespace).Create(ctx, daemonSet, metav1.CreateOptions{})
			require.NoError(t, err)

			// Create node-agent config map
			configMap := &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-agent-config",
					Namespace: velerov1api.DefaultNamespace,
				},
				Data: map[string]string{
					"config": tc.nodeAgentConfigMapData,
				},
			}
			_, err = kubeClient.CoreV1().ConfigMaps(velerov1api.DefaultNamespace).Create(ctx, configMap, metav1.CreateOptions{})
			require.NoError(t, err)

			// Create owner object for the backup pod
			ownerObject := corev1api.ObjectReference{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "DataUpload",
				Name:       "test-dataupload",
				Namespace:  velerov1api.DefaultNamespace,
				UID:        "test-uid",
			}

			// Create a backup PVC
			backupPVC := &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup-pvc",
					Namespace: velerov1api.DefaultNamespace,
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{
						corev1api.ReadWriteOnce,
					},
				},
			}

			// Create fake snapshot client
			fakeSnapshotClient := snapshotFake.NewSimpleClientset()

			// Create CSI snapshot exposer
			exposer := &csiSnapshotExposer{
				kubeClient:        kubeClient,
				csiSnapshotClient: fakeSnapshotClient.SnapshotV1(),
				log:               velerotest.NewLogger(),
			}

			// Call createBackupPod
			pod, err := exposer.createBackupPod(
				ctx,
				ownerObject,
				backupPVC,
				time.Minute*5,
				nil, // labels
				nil, // annotations
				nil, // tolerations
				nil, // affinity
				corev1api.ResourceRequirements{},
				false, // backupPVCReadOnly
				false, // spcNoRelabeling
				kube.NodeOSLinux,
				tc.expectedPriorityClass,
				nil,
				nil,
				nil,
				nil,
			)

			require.NoError(t, err, tc.description)
			assert.NotNil(t, pod)
			assert.Equal(t, tc.expectedPriorityClass, pod.Spec.PriorityClassName, tc.description)
		})
	}
}

func TestCreateBackupPodWithMissingConfigMap(t *testing.T) {
	ctx := t.Context()

	// Create fake Kubernetes client without config map
	kubeClient := fake.NewSimpleClientset()

	// Create node-agent daemonset (required for getInheritedPodInfo)
	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-agent",
			Namespace: velerov1api.DefaultNamespace,
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Name:  "node-agent",
							Image: "velero/velero:latest",
						},
					},
				},
			},
		},
	}
	_, err := kubeClient.AppsV1().DaemonSets(velerov1api.DefaultNamespace).Create(ctx, daemonSet, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create owner object for the backup pod
	ownerObject := corev1api.ObjectReference{
		APIVersion: velerov1api.SchemeGroupVersion.String(),
		Kind:       "DataUpload",
		Name:       "test-dataupload",
		Namespace:  velerov1api.DefaultNamespace,
		UID:        "test-uid",
	}

	// Create a backup PVC
	backupPVC := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backup-pvc",
			Namespace: velerov1api.DefaultNamespace,
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			AccessModes: []corev1api.PersistentVolumeAccessMode{
				corev1api.ReadWriteOnce,
			},
		},
	}

	// Create fake snapshot client
	fakeSnapshotClient := snapshotFake.NewSimpleClientset()

	// Create CSI snapshot exposer
	exposer := &csiSnapshotExposer{
		kubeClient:        kubeClient,
		csiSnapshotClient: fakeSnapshotClient.SnapshotV1(),
		log:               velerotest.NewLogger(),
	}

	// Call createBackupPod
	pod, err := exposer.createBackupPod(
		ctx,
		ownerObject,
		backupPVC,
		time.Minute*5,
		nil, // labels
		nil, // annotations
		nil, // tolerations
		nil, // affinity
		corev1api.ResourceRequirements{},
		false, // backupPVCReadOnly
		false, // spcNoRelabeling
		kube.NodeOSLinux,
		"", // empty priority class since config map is missing
		nil,
		nil,
		nil,
		nil,
	)

	// Should succeed even when config map is missing
	require.NoError(t, err, "Should succeed even when config map is missing")
	assert.NotNil(t, pod)
	assert.Empty(t, pod.Spec.PriorityClassName, "Should have empty priority class when config map is missing")
}
