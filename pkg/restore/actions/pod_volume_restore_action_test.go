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

package actions

import (
	"sort"
	"testing"

	"github.com/vmware-tanzu/velero/pkg/util/boolptr"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/buildinfo"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/kube"

	"k8s.io/client-go/kubernetes/scheme"

	"github.com/vmware-tanzu/velero/pkg/restorehelper"
)

func TestGetImage(t *testing.T) {
	configMapWithData := func(key, val string) *corev1api.ConfigMap {
		return &corev1api.ConfigMap{
			Data: map[string]string{
				key: val,
			},
		}
	}

	defaultImage := "velero/velero:v1.0"

	tests := []struct {
		name             string
		configMap        *corev1api.ConfigMap
		buildInfoVersion string
		want             string
	}{
		{
			name:      "nil config map returns default image",
			configMap: nil,
			want:      defaultImage,
		},
		{
			name:      "config map without 'image' key returns default image",
			configMap: configMapWithData("non-matching-key", "val"),
			want:      defaultImage,
		},
		{
			name:      "config map without '/' in image name returns default image",
			configMap: configMapWithData("image", "my-image"),
			want:      defaultImage,
		},
		{
			name:             "config map with untagged image returns image with buildinfo.Version as tag",
			configMap:        configMapWithData("image", "myregistry.io/my-image"),
			buildInfoVersion: "buildinfo-version",
			want:             "myregistry.io/my-image:buildinfo-version",
		},
		{
			name:             "config map with untagged image and custom registry port with ':' returns image with buildinfo.Version as tag",
			configMap:        configMapWithData("image", "myregistry.io:34567/my-image"),
			buildInfoVersion: "buildinfo-version",
			want:             "myregistry.io:34567/my-image:buildinfo-version",
		},
		{
			name:      "config map with tagged image returns tagged image",
			configMap: configMapWithData("image", "myregistry.io/my-image:my-tag"),
			want:      "myregistry.io/my-image:my-tag",
		},
		{
			name:      "config map with tagged image and custom registry port with ':' returns tagged image",
			configMap: configMapWithData("image", "myregistry.io:34567/my-image:my-tag"),
			want:      "myregistry.io:34567/my-image:my-tag",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.buildInfoVersion != "" {
				originalVersion := buildinfo.Version
				buildinfo.Version = test.buildInfoVersion
				defer func() {
					buildinfo.Version = originalVersion
				}()
			}
			assert.Equal(t, test.want, getImage(velerotest.NewLogger(), test.configMap, defaultImage))
		})
	}
}

// TestPodVolumeRestoreActionExecute tests the pod volume restore item action plugin's Execute method.
func TestPodVolumeRestoreActionExecute(t *testing.T) {
	resourceReqs, _ := kube.ParseCPUAndMemoryResources(
		defaultCPURequestLimit,
		defaultMemRequestLimit,
		defaultCPURequestLimit,
		defaultMemRequestLimit,
	)
	id := int64(1000)
	securityContext := corev1api.SecurityContext{
		AllowPrivilegeEscalation: boolptr.False(),
		Capabilities: &corev1api.Capabilities{
			Drop: []corev1api.Capability{"ALL"},
		},
		SeccompProfile: &corev1api.SeccompProfile{
			Type: corev1api.SeccompProfileTypeRuntimeDefault,
		},
		RunAsUser:    &id,
		RunAsNonRoot: boolptr.True(),
	}
	customID := int64(44444)
	customSecurityContext := corev1api.SecurityContext{
		AllowPrivilegeEscalation: boolptr.False(),
		Capabilities: &corev1api.Capabilities{
			Drop: []corev1api.Capability{"ALL"},
		},
		SeccompProfile: &corev1api.SeccompProfile{
			Type: corev1api.SeccompProfileTypeRuntimeDefault,
		},
		RunAsUser:    &customID,
		RunAsNonRoot: boolptr.True(),
	}

	var (
		restoreName = "my-restore"
		backupName  = "test-backup"
		veleroNs    = "velero"
	)

	defaultRestoreHelperImage := "velero/velero:v1.0"

	tests := []struct {
		name             string
		pod              *corev1api.Pod
		podFromBackup    *corev1api.Pod
		podVolumeBackups []runtime.Object
		want             *corev1api.Pod
	}{
		{
			name: "Restoring pod with no other initContainers adds the restore initContainer when volumes need file system restores",
			pod: builder.ForPod("ns-1", "my-pod").
				ObjectMeta(builder.WithAnnotations("snapshot.velero.io/myvol", "")).
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				Result(),
			podVolumeBackups: []runtime.Object{
				builder.ForPodVolumeBackup(veleroNs, "pvb-1").
					PodName("my-pod").
					PodNamespace("ns-1").
					Volume("myvol").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
			},
			want: builder.ForPod("ns-1", "my-pod").
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/myvol", "")).
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				InitContainers(
					newRestoreInitContainerBuilder(defaultRestoreHelperImage, "").
						Resources(&resourceReqs).
						SecurityContext(&securityContext).
						VolumeMounts(builder.ForVolumeMount("myvol", "/restores/myvol").Result()).
						Command([]string{"/velero-restore-helper"}).Result()).Result(),
		},
		{
			name: "Restoring pod with other initContainers adds the restore initContainer as the first one when volumes need file system restores",
			pod: builder.ForPod("ns-1", "my-pod").
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/myvol", "")).
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				InitContainers(builder.ForContainer("first-container", "").Result()).
				Result(),
			podVolumeBackups: []runtime.Object{
				builder.ForPodVolumeBackup(veleroNs, "pvb-1").
					PodName("my-pod").
					PodNamespace("ns-1").
					Volume("myvol").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
			},
			want: builder.ForPod("ns-1", "my-pod").
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/myvol", "")).
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				InitContainers(
					newRestoreInitContainerBuilder(defaultRestoreHelperImage, "").
						Resources(&resourceReqs).
						SecurityContext(&securityContext).
						VolumeMounts(builder.ForVolumeMount("myvol", "/restores/myvol").Result()).
						Command([]string{"/velero-restore-helper"}).Result(),
					builder.ForContainer("first-container", "").Result()).
				Result(),
		},
		{
			name: "Restoring pod with other initContainers adds the restore initContainer as the first one using PVB to identify the volumes and not annotations",
			pod: builder.ForPod("ns-1", "my-pod").
				Volumes(
					builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/not-used", "")).
				InitContainers(builder.ForContainer("first-container", "").Result()).
				Result(),
			podVolumeBackups: []runtime.Object{
				builder.ForPodVolumeBackup(veleroNs, "pvb-1").
					PodName("my-pod").
					PodNamespace("ns-1").
					Volume("vol-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
				builder.ForPodVolumeBackup(veleroNs, "pvb-2").
					PodName("my-pod").
					PodNamespace("ns-1").
					Volume("vol-2").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
			},
			want: builder.ForPod("ns-1", "my-pod").
				Volumes(
					builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/not-used", "")).
				InitContainers(
					newRestoreInitContainerBuilder(defaultRestoreHelperImage, "").
						Resources(&resourceReqs).
						SecurityContext(&securityContext).
						VolumeMounts(builder.ForVolumeMount("vol-1", "/restores/vol-1").Result(), builder.ForVolumeMount("vol-2", "/restores/vol-2").Result()).
						Command([]string{"/velero-restore-helper"}).Result(),
					builder.ForContainer("first-container", "").Result()).
				Result(),
		},
		{
			name: "Restoring pod in another namespace adds the restore initContainer and uses the namespace of the backup pod for matching PVBs",
			pod: builder.ForPod("new-ns", "my-pod").
				Volumes(
					builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("original-ns", "my-pod").
				Volumes(
					builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups: []runtime.Object{
				builder.ForPodVolumeBackup(veleroNs, "pvb-1").
					PodName("my-pod").
					PodNamespace("original-ns").
					Volume("vol-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
				builder.ForPodVolumeBackup(veleroNs, "pvb-2").
					PodName("my-pod").
					PodNamespace("original-ns").
					Volume("vol-2").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
			},
			want: builder.ForPod("new-ns", "my-pod").
				Volumes(
					builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				InitContainers(
					newRestoreInitContainerBuilder(defaultRestoreHelperImage, "").
						Resources(&resourceReqs).
						SecurityContext(&securityContext).
						VolumeMounts(builder.ForVolumeMount("vol-1", "/restores/vol-1").Result(), builder.ForVolumeMount("vol-2", "/restores/vol-2").Result()).
						Command([]string{"/velero-restore-helper"}).Result()).
				Result(),
		},
		{
			name: "Restoring pod with custom container SecurityContext uses this SecurityContext for the restore initContainer when volumes need file system restores",
			pod: builder.ForPod("ns-1", "my-pod").
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/myvol", "")).
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				Containers(
					builder.ForContainer("app-container", "app-image").
						SecurityContext(&customSecurityContext).Result()).
				Result(),
			podVolumeBackups: []runtime.Object{
				builder.ForPodVolumeBackup(veleroNs, "pvb-1").
					PodName("my-pod").
					PodNamespace("ns-1").
					Volume("myvol").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
			},
			want: builder.ForPod("ns-1", "my-pod").
				ObjectMeta(
					builder.WithAnnotations("snapshot.velero.io/myvol", "")).
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				Containers(
					builder.ForContainer("app-container", "app-image").
						SecurityContext(&customSecurityContext).Result()).
				InitContainers(
					newRestoreInitContainerBuilder(defaultRestoreHelperImage, "").
						Resources(&resourceReqs).
						SecurityContext(&customSecurityContext).
						VolumeMounts(builder.ForVolumeMount("myvol", "/restores/myvol").Result()).
						Command([]string{"/velero-restore-helper"}).Result()).Result(),
		},
		{
			name: "pod volume backups in a different namespace are ignored when looking for matches due to namespace scoping",
			pod: builder.ForPod("ns-1", "my-pod").
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				Result(),
			podVolumeBackups: []runtime.Object{
				builder.ForPodVolumeBackup("other-ns", "pvb-1").
					PodName("my-pod").
					PodNamespace("ns-1").
					Volume("myvol").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, backupName)).
					SnapshotID("foo").
					Result(),
			},
			want: builder.ForPod("ns-1", "my-pod").
				Volumes(
					builder.ForVolume("myvol").PersistentVolumeClaimSource("pvc-1").Result(),
				).
				Result(),
		},
	}

	veleroDeployment := &appsv1api.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsv1api.SchemeGroupVersion.String(),
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "velero",
			Labels: map[string]string{
				"component": "velero",
			},
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Name:  "velero",
							Image: "velero/velero:v1.0",
						},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()

			objects := []runtime.Object{veleroDeployment}
			objects = append(objects, tc.podVolumeBackups...)
			crClient := velerotest.NewFakeControllerRuntimeClient(t, objects...)

			unstructuredPod, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pod)
			require.NoError(t, err)

			// Default to using the same pod for both Item and ItemFromBackup if podFromBackup not provided
			var unstructuredPodFromBackup map[string]any
			if tc.podFromBackup != nil {
				unstructuredPodFromBackup, err = runtime.DefaultUnstructuredConverter.ToUnstructured(tc.podFromBackup)
				require.NoError(t, err)
			} else {
				unstructuredPodFromBackup = unstructuredPod
			}

			input := &velero.RestoreItemActionExecuteInput{
				Item: &unstructured.Unstructured{
					Object: unstructuredPod,
				},
				ItemFromBackup: &unstructured.Unstructured{
					Object: unstructuredPodFromBackup,
				},
				Restore: builder.ForRestore(veleroNs, restoreName).
					Backup(backupName).
					Phase(velerov1api.RestorePhaseInProgress).
					Result(),
			}

			a, err := NewPodVolumeRestoreAction(
				logrus.StandardLogger(),
				clientset.CoreV1().ConfigMaps(veleroNs),
				crClient,
				"velero",
			)
			require.NoError(t, err)

			// method under test
			res, err := a.Execute(input)
			require.NoError(t, err)

			updatedPod := new(corev1api.Pod)
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), updatedPod))

			for _, container := range tc.want.Spec.InitContainers {
				sort.Slice(container.VolumeMounts, func(i, j int) bool {
					return container.VolumeMounts[i].Name < container.VolumeMounts[j].Name
				})
			}
			for _, container := range updatedPod.Spec.InitContainers {
				sort.Slice(container.VolumeMounts, func(i, j int) bool {
					return container.VolumeMounts[i].Name < container.VolumeMounts[j].Name
				})
			}

			assert.Equal(t, tc.want, updatedPod)
		})
	}
}

func TestGetCommand(t *testing.T) {
	configMapWithData := func(key, val string) *corev1api.ConfigMap {
		return &corev1api.ConfigMap{
			Data: map[string]string{
				key: val,
			},
		}
	}
	testCases := []struct {
		name      string
		configMap *corev1api.ConfigMap
		expected  []string
	}{
		{
			name:      "should get default command when config key is missing",
			configMap: configMapWithData("non-matching-key", "val"),
			expected:  []string{defaultCommand},
		},
		{
			name:      "should get default command when config key is empty",
			configMap: configMapWithData("command", ""),
			expected:  []string{defaultCommand},
		},
		{
			name:      "should get default command when config is nil",
			configMap: nil,
			expected:  []string{defaultCommand},
		},
		{
			name:      "should get command from config",
			configMap: configMapWithData("command", "foobarbz"),
			expected:  []string{"foobarbz"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := getCommand(velerotest.NewLogger(), tc.configMap)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

// This tests that restore-wait is added when file system restore volume exists, nothing added otherwise,
// and removed if it exists but is not needed.
// issue: 8870
func TestPodVolumeRestoreActionExecuteWithFileSystemShouldAddWaitInitContainer(t *testing.T) {
	tests := []struct {
		name                   string
		pod                    *corev1api.Pod
		podFromBackup          *corev1api.Pod
		podVolumeBackups       []*velerov1api.PodVolumeBackup
		restore                *velerov1api.Restore
		expectedInitContainers int
		expectedError          error
	}{
		{
			name: "no pod volume backups results in no init container",
			pod: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups:       nil,
			restore:                builder.ForRestore("velero", "restore-1").Backup("test-backup").Result(),
			expectedInitContainers: 0,
			expectedError:          nil,
		},
		{
			name: "pod volume backups that don't match pod's volumes results in no init container",
			pod: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, "test-backup")).
					PodName("different-pod").
					PodNamespace("ns").
					Volume("volume-1").
					SnapshotID("snapshot-1").
					Result(),
			},
			restore:                builder.ForRestore("velero", "restore-1").Backup("test-backup").Result(),
			expectedInitContainers: 0,
			expectedError:          nil,
		},
		{
			name: "matching pod volume backup results in init container being added",
			pod: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, "test-backup")).
					PodName("pod").
					PodNamespace("ns").
					Volume("volume-1").
					SnapshotID("snapshot-1").
					Result(),
			},
			restore:                builder.ForRestore("velero", "restore-1").Backup("test-backup").Result(),
			expectedInitContainers: 1,
			expectedError:          nil,
		},
		{
			name: "matching pod volume backup with matching pod name and namespace results in init container being added",
			pod: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, "test-backup")).
					PodName("pod").
					PodNamespace("ns").
					Volume("volume-1").
					SnapshotID("snapshot-1").
					Result(),
			},
			restore:                builder.ForRestore("velero", "restore-1").Backup("test-backup").Result(),
			expectedInitContainers: 1,
			expectedError:          nil,
		},
		{
			name: "existing init container is removed when no file system restore is needed",
			pod: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				InitContainers(
					builder.ForContainer(restorehelper.WaitInitContainer, "velero/velero:latest").
						Command([]string{"/velero-restore-helper"}).
						Args("restore-1").
						Result(),
					builder.ForContainer("another-init", "another-image").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				// This PVB doesn't match the pod's name, so needsFileSystemRestore will be false
				builder.ForPodVolumeBackup("velero", "pvb-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, "test-backup")).
					PodName("different-pod").
					PodNamespace("ns").
					Volume("volume-1").
					SnapshotID("snapshot-1").
					Result(),
			},
			restore:                builder.ForRestore("velero", "restore-1").Backup("test-backup").Result(),
			expectedInitContainers: 1, // Only the "another-init" container should remain
			expectedError:          nil,
		},
		{
			name: "existing legacy init container is removed when no file system restore is needed",
			pod: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				InitContainers(
					builder.ForContainer(restorehelper.WaitInitContainerLegacy, "velero/velero:latest").
						Command([]string{"/velero-restore-helper"}).
						Args("restore-1").
						Result(),
					builder.ForContainer("another-init", "another-image").Result(),
				).
				Result(),
			podFromBackup: builder.ForPod("ns", "pod").
				ObjectMeta(builder.WithUID("pod-uid")).
				Volumes(
					builder.ForVolume("volume-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("volume-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				Result(),
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				// This PVB doesn't match the pod's name, so needsFileSystemRestore will be false
				builder.ForPodVolumeBackup("velero", "pvb-1").
					ObjectMeta(builder.WithLabels(velerov1api.BackupNameLabel, "test-backup")).
					PodName("different-pod").
					PodNamespace("ns").
					Volume("volume-1").
					SnapshotID("snapshot-1").
					Result(),
			},
			restore:                builder.ForRestore("velero", "restore-1").Backup("test-backup").Result(),
			expectedInitContainers: 1, // Only the "another-init" container should remain
			expectedError:          nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			var (
				client   = crfake.NewClientBuilder().Build()
				crClient = client
			)

			// Register the PodVolumeBackup type with the scheme
			require.NoError(t, velerov1api.AddToScheme(scheme.Scheme))

			// Create the PodVolumeBackups in the fake client
			for _, pvb := range tc.podVolumeBackups {
				require.NoError(t, crClient.Create(t.Context(), pvb))
			}

			// Create a fake clientset
			clientset := fake.NewSimpleClientset()

			// Create the action
			action := &PodVolumeRestoreAction{
				logger:      logrus.StandardLogger(),
				client:      clientset.CoreV1().ConfigMaps("velero"),
				crClient:    crClient,
				veleroImage: "velero/velero:latest",
			}

			// Convert the pod to unstructured
			podMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pod)
			require.NoError(t, err)
			podFromBackupMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.podFromBackup)
			require.NoError(t, err)

			// Create the input
			input := &velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: podMap},
				ItemFromBackup: &unstructured.Unstructured{Object: podFromBackupMap},
				Restore:        tc.restore,
			}

			// Execute the action
			output, err := action.Execute(input)

			// Verify the results
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError, err)
			} else {
				require.NoError(t, err)

				// Convert the output back to a pod
				outputPod := new(corev1api.Pod)
				err = runtime.DefaultUnstructuredConverter.FromUnstructured(output.UpdatedItem.UnstructuredContent(), outputPod)
				require.NoError(t, err)

				// Check if the init container was added or removed as expected
				assert.Len(t, outputPod.Spec.InitContainers, tc.expectedInitContainers, "Unexpected number of init containers")
			}
		})
	}
}
