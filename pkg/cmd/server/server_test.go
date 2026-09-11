/*
Copyright 2017 the Velero contributors.

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

package server

import (
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/cmd/server/config"
	"github.com/vmware-tanzu/velero/pkg/constant"
	discovery_mocks "github.com/vmware-tanzu/velero/pkg/discovery/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/uploader"
)

func TestVeleroResourcesExist(t *testing.T) {
	var (
		fakeDiscoveryHelper = &velerotest.FakeDiscoveryHelper{}
		server              = &server{
			logger:          velerotest.NewLogger(),
			discoveryHelper: fakeDiscoveryHelper,
		}
	)

	// Velero API group doesn't exist in discovery: should error
	fakeDiscoveryHelper.ResourceList = []*metav1.APIResourceList{
		{
			GroupVersion: "foo/v1",
			APIResources: []metav1.APIResource{
				{
					Name: "Backups",
					Kind: "Backup",
				},
			},
		},
	}
	require.Error(t, server.veleroResourcesExist())

	// Velero v1 API group doesn't contain any custom resources: should error
	veleroAPIResourceListVelerov1 := &metav1.APIResourceList{
		GroupVersion: velerov1api.SchemeGroupVersion.String(),
	}

	fakeDiscoveryHelper.ResourceList = append(fakeDiscoveryHelper.ResourceList, veleroAPIResourceListVelerov1)
	require.Error(t, server.veleroResourcesExist())

	// Velero v2alpha1 API group doesn't contain any custom resources: should error
	veleroAPIResourceListVeleroV2alpha1 := &metav1.APIResourceList{
		GroupVersion: velerov2alpha1api.SchemeGroupVersion.String(),
	}

	fakeDiscoveryHelper.ResourceList = append(fakeDiscoveryHelper.ResourceList, veleroAPIResourceListVeleroV2alpha1)
	require.Error(t, server.veleroResourcesExist())

	// Velero v1 API group contains all custom resources, but v2alpha1 doesn't contain any custom resources: should error
	for kind := range velerov1api.CustomResources() {
		veleroAPIResourceListVelerov1.APIResources = append(veleroAPIResourceListVelerov1.APIResources, metav1.APIResource{
			Kind: kind,
		})
	}
	require.Error(t, server.veleroResourcesExist())

	// Velero v1 and v2alpha1 API group contain all custom resources: should not error
	for kind := range velerov2alpha1api.CustomResources() {
		veleroAPIResourceListVeleroV2alpha1.APIResources = append(veleroAPIResourceListVeleroV2alpha1.APIResources, metav1.APIResource{
			Kind: kind,
		})
	}
	require.NoError(t, server.veleroResourcesExist())

	// Velero API group contains some but not all custom resources: should error
	veleroAPIResourceListVelerov1.APIResources = veleroAPIResourceListVelerov1.APIResources[:3]
	assert.Error(t, server.veleroResourcesExist())
}

func TestRemoveControllers(t *testing.T) {
	logger := velerotest.NewLogger()

	tests := []struct {
		name                string
		disabledControllers []string
		errorExpected       bool
	}{
		{
			name: "Remove one disable controller",
			disabledControllers: []string{
				constant.ControllerBackup,
			},
			errorExpected: false,
		},
		{
			name: "Remove all disable controllers",
			disabledControllers: []string{
				constant.ControllerBackupOperations,
				constant.ControllerBackup,
				constant.ControllerBackupDeletion,
				constant.ControllerBackupSync,
				constant.ControllerDownloadRequest,
				constant.ControllerGarbageCollection,
				constant.ControllerBackupRepo,
				constant.ControllerRestore,
				constant.ControllerSchedule,
				constant.ControllerServerStatusRequest,
			},
			errorExpected: false,
		},
		{
			name: "Remove with a non-disable controller included",
			disabledControllers: []string{
				constant.ControllerBackup,
				constant.ControllerBackupStorageLocation,
			},
			errorExpected: true,
		},
		{
			name: "Remove with a misspelled/non-existing controller name",
			disabledControllers: []string{
				"go",
			},
			errorExpected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabledRuntimeControllers := map[string]struct{}{
				constant.ControllerBackupSync:          {},
				constant.ControllerBackup:              {},
				constant.ControllerGarbageCollection:   {},
				constant.ControllerRestore:             {},
				constant.ControllerServerStatusRequest: {},
				constant.ControllerSchedule:            {},
				constant.ControllerBackupDeletion:      {},
				constant.ControllerBackupRepo:          {},
				constant.ControllerDownloadRequest:     {},
				constant.ControllerBackupOperations:    {},
			}

			totalNumOriginalControllers := len(enabledRuntimeControllers)

			if tt.errorExpected {
				assert.Error(t, removeControllers(tt.disabledControllers, enabledRuntimeControllers, logger))
			} else {
				require.NoError(t, removeControllers(tt.disabledControllers, enabledRuntimeControllers, logger))

				totalNumEnabledControllers := len(enabledRuntimeControllers)
				assert.Equal(t, totalNumEnabledControllers, totalNumOriginalControllers-len(tt.disabledControllers))

				for _, disabled := range tt.disabledControllers {
					_, ok := enabledRuntimeControllers[disabled]
					assert.False(t, ok)
				}
			}
		})
	}
}

func TestNewCommand(t *testing.T) {
	assert.NotNil(t, NewCommand(nil))
}

func Test_newServer(t *testing.T) {
	factory := &mocks.Factory{}
	logger := logrus.New()

	// invalid uploader type
	_, err := newServer(factory, &config.Config{
		UploaderType: "invalid",
	}, logger)
	require.Error(t, err)

	// invalid clientQPS
	_, err = newServer(factory, &config.Config{
		UploaderType: uploader.KopiaType,
		ClientQPS:    -1,
	}, logger)
	require.Error(t, err)

	// invalid clientQPS Kopia uploader
	_, err = newServer(factory, &config.Config{
		UploaderType: uploader.KopiaType,
		ClientQPS:    -1,
	}, logger)
	require.Error(t, err)

	// invalid clientBurst
	factory.On("SetClientQPS", mock.Anything).Return()
	_, err = newServer(factory, &config.Config{
		UploaderType: uploader.KopiaType,
		ClientQPS:    1,
		ClientBurst:  -1,
	}, logger)
	require.Error(t, err)

	// invalid clientBclientPageSizeurst
	factory.On("SetClientQPS", mock.Anything).Return().
		On("SetClientBurst", mock.Anything).Return()
	_, err = newServer(factory, &config.Config{
		UploaderType:   uploader.KopiaType,
		ClientQPS:      1,
		ClientBurst:    1,
		ClientPageSize: -1,
	}, logger)
	require.Error(t, err)

	// got error when creating client
	factory.On("SetClientQPS", mock.Anything).Return().
		On("SetClientBurst", mock.Anything).Return().
		On("KubeClient").Return(nil, nil).
		On("Client").Return(nil, nil).
		On("DynamicClient").Return(nil, errors.New("error"))
	_, err = newServer(factory, &config.Config{
		UploaderType:   uploader.KopiaType,
		ClientQPS:      1,
		ClientBurst:    1,
		ClientPageSize: 100,
	}, logger)
	require.Error(t, err)

	invalidCM := builder.ForConfigMap("velero", "invalid").Data("invalid", "{\"a\": \"b}").Result()
	crClient := velerotest.NewFakeControllerRuntimeClient(t, invalidCM)

	factory.On("KubeClient").Return(crClient, nil).
		On("Client").Return(nil, nil).
		On("DynamicClient").Return(nil, errors.New("error"))
	_, err = newServer(factory, &config.Config{
		UploaderType:     uploader.KopiaType,
		BackupRepoConfig: "invalid",
	}, logger)
	require.Error(t, err)

	factory.On("KubeClient").Return(crClient, nil).
		On("Client").Return(nil, nil).
		On("DynamicClient").Return(nil, errors.New("error"))
	_, err = newServer(factory, &config.Config{
		UploaderType:             uploader.KopiaType,
		RepoMaintenanceJobConfig: "invalid",
	}, logger)
	require.Error(t, err)
}

func Test_namespaceExists(t *testing.T) {
	client := kubefake.NewSimpleClientset(&corev1api.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "velero",
		},
	})
	server := &server{
		kubeClient: client,
		logger:     logrus.New(),
	}

	// namespace doesn't exist
	require.Error(t, server.namespaceExists("not-exist"))

	// namespace exists
	assert.NoError(t, server.namespaceExists("velero"))
}

func TestResolveGracefulShutdownTimeout(t *testing.T) {
	logger := velerotest.NewLogger()
	namespace := "velero"

	tests := []struct {
		name     string
		cfg      *config.Config
		podName  string
		pod      *corev1api.Pod
		expected time.Duration
	}{
		{
			name:     "explicit flag wins",
			cfg:      &config.Config{GracefulShutdownTimeout: 45 * time.Minute, GracefulShutdownSafetyBuffer: 10 * time.Second},
			expected: 45 * time.Minute,
		},
		{
			name:    "derives from pod spec",
			cfg:     &config.Config{GracefulShutdownSafetyBuffer: 10 * time.Second},
			podName: "velero-abc123",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "velero-abc123", Namespace: namespace},
				Spec:       corev1api.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(3600))},
			},
			expected: 3600*time.Second - 10*time.Second,
		},
		{
			name:     "POD_NAME unset falls back to default",
			cfg:      &config.Config{GracefulShutdownSafetyBuffer: 10 * time.Second},
			expected: defaultGracefulShutdownTimeout,
		},
		{
			name:    "terminationGracePeriodSeconds unset falls back to default",
			cfg:     &config.Config{GracefulShutdownSafetyBuffer: 10 * time.Second},
			podName: "velero-abc123",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "velero-abc123", Namespace: namespace},
			},
			expected: defaultGracefulShutdownTimeout,
		},
		{
			name:    "underflowed derived value falls back to terminationGracePeriodSeconds itself, preserving an operator-raised grace period",
			cfg:     &config.Config{GracefulShutdownSafetyBuffer: 90 * time.Second},
			podName: "velero-abc123",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "velero-abc123", Namespace: namespace},
				// The 90s safety buffer underflows this 60s grace period. Falling back to
				// the 30s default here would discard the 60s the operator explicitly
				// configured to give backups/restores more time to finish.
				Spec: corev1api.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(60))},
			},
			expected: 60 * time.Second,
		},
		{
			name:    "terminationGracePeriodSeconds at the kubernetes default still has the buffer subtracted",
			cfg:     &config.Config{GracefulShutdownSafetyBuffer: 2 * time.Second},
			podName: "velero-abc123",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "velero-abc123", Namespace: namespace},
				Spec:       corev1api.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(30))},
			},
			// The formula is uniform: no special-casing for terminationGracePeriodSeconds
			// matching Kubernetes' own default, so the resolved timeout stays strictly
			// below it.
			expected: 28 * time.Second,
		},
		{
			name:    "terminationGracePeriodSeconds below the kubernetes default derives normally",
			cfg:     &config.Config{GracefulShutdownSafetyBuffer: 10 * time.Second},
			podName: "velero-abc123",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "velero-abc123", Namespace: namespace},
				Spec:       corev1api.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(20))},
			},
			expected: 10 * time.Second,
		},
		{
			name:    "terminationGracePeriodSeconds shorter than the safety buffer falls back to itself, not the default",
			cfg:     &config.Config{GracefulShutdownSafetyBuffer: 10 * time.Second},
			podName: "velero-abc123",
			pod: &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "velero-abc123", Namespace: namespace},
				// The 10s safety buffer underflows this 5s grace period; falling back to
				// the 30s default here would exceed the pod's own grace period.
				Spec: corev1api.PodSpec{TerminationGracePeriodSeconds: ptr.To(int64(5))},
			},
			expected: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("POD_NAME", tt.podName)

			objs := []runtime.Object{}
			if tt.pod != nil {
				objs = append(objs, tt.pod)
			}
			kubeClient := kubefake.NewSimpleClientset(objs...)

			actual := resolveGracefulShutdownTimeout(t.Context(), kubeClient, namespace, tt.cfg, logger)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func Test_veleroResourcesExist(t *testing.T) {
	helper := &discovery_mocks.Helper{}
	server := &server{
		discoveryHelper: helper,
		logger:          logrus.New(),
	}

	// velero resources don't exist
	helper.On("Resources").Return(nil)
	require.Error(t, server.veleroResourcesExist())

	// velero resources exist
	helper.On("Resources").Unset()
	helper.On("Resources").Return([]*metav1.APIResourceList{
		{
			GroupVersion: velerov1api.SchemeGroupVersion.String(),
			APIResources: []metav1.APIResource{
				{Kind: "Backup"},
				{Kind: "Restore"},
				{Kind: "Schedule"},
				{Kind: "DownloadRequest"},
				{Kind: "DeleteBackupRequest"},
				{Kind: "PodVolumeBackup"},
				{Kind: "PodVolumeRestore"},
				{Kind: "BackupRepository"},
				{Kind: "BackupStorageLocation"},
				{Kind: "VolumeSnapshotLocation"},
				{Kind: "ServerStatusRequest"},
			},
		},
		{
			GroupVersion: velerov2alpha1api.SchemeGroupVersion.String(),
			APIResources: []metav1.APIResource{
				{Kind: "DataUpload"},
				{Kind: "DataDownload"},
			},
		},
	})
	assert.NoError(t, server.veleroResourcesExist())
}

func Test_markInProgressBackupsFailed(t *testing.T) {
	scheme := runtime.NewScheme()
	velerov1api.AddToScheme(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithLists(&velerov1api.BackupList{
			Items: []velerov1api.Backup{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "backup01",
					},
					Status: velerov1api.BackupStatus{
						Phase: velerov1api.BackupPhaseInProgress,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "backup02",
					},
					Status: velerov1api.BackupStatus{
						Phase: velerov1api.BackupPhaseCompleted,
					},
				},
			},
		}).
		Build()
	markInProgressBackupsFailed(t.Context(), c, "velero", logrus.New())

	backup01 := &velerov1api.Backup{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: "velero", Name: "backup01"}, backup01))
	assert.Equal(t, velerov1api.BackupPhaseFailed, backup01.Status.Phase)

	backup02 := &velerov1api.Backup{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: "velero", Name: "backup02"}, backup02))
	assert.Equal(t, velerov1api.BackupPhaseCompleted, backup02.Status.Phase)
}

func Test_markInProgressRestoresFailed(t *testing.T) {
	scheme := runtime.NewScheme()
	velerov1api.AddToScheme(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithLists(&velerov1api.RestoreList{
			Items: []velerov1api.Restore{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "restore01",
					},
					Status: velerov1api.RestoreStatus{
						Phase: velerov1api.RestorePhaseInProgress,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "restore02",
					},
					Status: velerov1api.RestoreStatus{
						Phase: velerov1api.RestorePhaseCompleted,
					},
				},
			},
		}).
		Build()
	markInProgressRestoresFailed(t.Context(), c, "velero", logrus.New())

	restore01 := &velerov1api.Restore{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: "velero", Name: "restore01"}, restore01))
	assert.Equal(t, velerov1api.RestorePhaseFailed, restore01.Status.Phase)

	restore02 := &velerov1api.Restore{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: "velero", Name: "restore02"}, restore02))
	assert.Equal(t, velerov1api.RestorePhaseCompleted, restore02.Status.Phase)
}

func Test_setDefaultBackupLocation(t *testing.T) {
	scheme := runtime.NewScheme()
	velerov1api.AddToScheme(scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithLists(&velerov1api.BackupStorageLocationList{
			Items: []velerov1api.BackupStorageLocation{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "default",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "non-default",
					},
				},
			},
		}).
		Build()
	setDefaultBackupLocation(t.Context(), c, "velero", "default", logrus.New())

	defaultLocation := &velerov1api.BackupStorageLocation{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: "velero", Name: "default"}, defaultLocation))
	assert.True(t, defaultLocation.Spec.Default)

	nonDefaultLocation := &velerov1api.BackupStorageLocation{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: "velero", Name: "non-default"}, nonDefaultLocation))
	assert.False(t, nonDefaultLocation.Spec.Default)

	// no default location specified
	c = fake.NewClientBuilder().WithScheme(scheme).Build()
	err := setDefaultBackupLocation(t.Context(), c, "velero", "", logrus.New())
	require.NoError(t, err)

	// no default location created
	err = setDefaultBackupLocation(t.Context(), c, "velero", "default", logrus.New())
	assert.NoError(t, err)
}
