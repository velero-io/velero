/*
Copyright 2019 the Velero contributors.

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
package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/exposer"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	testutil "github.com/vmware-tanzu/velero/pkg/test"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func Test_validatePodVolumesHostPath(t *testing.T) {
	tests := []struct {
		name      string
		pods      []*corev1api.Pod
		dirs      []string
		createDir bool
		wantErr   bool
	}{
		{
			name: "no error when pod volumes are present",
			pods: []*corev1api.Pod{
				builder.ForPod("foo", "bar").ObjectMeta(builder.WithUID("foo")).Result(),
				builder.ForPod("zoo", "raz").ObjectMeta(builder.WithUID("zoo")).Result(),
			},
			dirs:      []string{"foo", "zoo"},
			createDir: true,
			wantErr:   false,
		},
		{
			name: "no error when pod volumes are present and there are mirror pods",
			pods: []*corev1api.Pod{
				builder.ForPod("foo", "bar").ObjectMeta(builder.WithUID("foo")).Result(),
				builder.ForPod("zoo", "raz").ObjectMeta(builder.WithUID("zoo"), builder.WithAnnotations(corev1api.MirrorPodAnnotationKey, "baz")).Result(),
			},
			dirs:      []string{"foo", "baz"},
			createDir: true,
			wantErr:   false,
		},
		{
			name: "error when all pod volumes missing",
			pods: []*corev1api.Pod{
				builder.ForPod("foo", "bar").ObjectMeta(builder.WithUID("foo")).Result(),
				builder.ForPod("zoo", "raz").ObjectMeta(builder.WithUID("zoo")).Result(),
			},
			dirs:      []string{"unexpected-dir"},
			createDir: true,
			wantErr:   true,
		},
		{
			name: "error when some pod volumes missing",
			pods: []*corev1api.Pod{
				builder.ForPod("foo", "bar").ObjectMeta(builder.WithUID("foo")).Result(),
				builder.ForPod("zoo", "raz").ObjectMeta(builder.WithUID("zoo")).Result(),
			},
			dirs:      []string{"foo"},
			createDir: true,
			wantErr:   true,
		},
		{
			name: "no error when pod volumes are not present",
			pods: []*corev1api.Pod{
				builder.ForPod("foo", "bar").ObjectMeta(builder.WithUID("foo")).Result(),
			},
			dirs:      []string{"foo"},
			createDir: false,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := testutil.NewFakeFileSystem()

			for _, dir := range tt.dirs {
				if tt.createDir {
					err := fs.MkdirAll(filepath.Join(nodeagent.HostPodVolumeMountPath(), dir), os.ModePerm)
					if err != nil {
						t.Error(err)
					}
				}
			}

			kubeClient := fake.NewSimpleClientset()
			for _, pod := range tt.pods {
				_, err := kubeClient.CoreV1().Pods(pod.GetNamespace()).Create(t.Context(), pod, metav1.CreateOptions{})
				if err != nil {
					t.Error(err)
				}
			}

			s := &nodeAgentServer{
				logger:     testutil.NewLogger(),
				fileSystem: fs,
			}

			err := s.validatePodVolumesHostPath(kubeClient)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_getDataPathConfigs(t *testing.T) {
	configs := &velerotypes.NodeAgentConfigs{
		LoadConcurrency: &velerotypes.LoadConcurrency{
			GlobalConfig: -1,
		},
	}

	tests := []struct {
		name          string
		getFunc       func(context.Context, string, kubernetes.Interface, string) (*velerotypes.NodeAgentConfigs, error)
		configMapName string
		expectConfigs *velerotypes.NodeAgentConfigs
		expectedErr   string
	}{
		{
			name: "no config specified",
		},
		{
			name:          "failed to get configs",
			configMapName: "node-agent-config",
			getFunc: func(context.Context, string, kubernetes.Interface, string) (*velerotypes.NodeAgentConfigs, error) {
				return nil, errors.New("fake-get-error")
			},
			expectedErr: "error getting node agent configs from configMap node-agent-config: fake-get-error",
		},
		{
			name:          "configs cm not found",
			configMapName: "node-agent-config",
			getFunc: func(context.Context, string, kubernetes.Interface, string) (*velerotypes.NodeAgentConfigs, error) {
				return nil, errors.New("fake-not-found-error")
			},
			expectedErr: "error getting node agent configs from configMap node-agent-config: fake-not-found-error",
		},

		{
			name:          "succeed",
			configMapName: "node-agent-config",
			getFunc: func(context.Context, string, kubernetes.Interface, string) (*velerotypes.NodeAgentConfigs, error) {
				return configs, nil
			},
			expectConfigs: configs,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := &nodeAgentServer{
				config: nodeAgentServerConfig{
					nodeAgentConfig: test.configMapName,
				},
				logger: testutil.NewLogger(),
			}

			getConfigsFunc = test.getFunc

			err := s.getDataPathConfigs()
			if test.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, test.expectConfigs, s.dataPathConfigs)
			} else {
				require.EqualError(t, err, test.expectedErr)
			}
		})
	}
}

func Test_getDataPathConcurrentNum(t *testing.T) {
	defaultNum := 100001
	globalNum := 6
	nodeName := "node-agent-node"
	node1 := builder.ForNode("node-agent-node").Result()
	node2 := builder.ForNode("node-agent-node").Labels(map[string]string{
		"host-name": "node-1",
		"xxxx":      "yyyyy",
	}).Result()

	invalidLabelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"inva/lid": "inva/lid",
		},
	}
	validLabelSelector1 := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"host-name": "node-1",
		},
	}
	validLabelSelector2 := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"xxxx": "yyyyy",
		},
	}

	tests := []struct {
		name          string
		configs       velerotypes.NodeAgentConfigs
		setKubeClient bool
		kubeClientObj []runtime.Object
		expectNum     int
		expectLog     string
	}{
		{
			name:      "configs cm's data path concurrency is nil",
			expectLog: fmt.Sprintf("Concurrency configs are not found, use the default number %v", defaultNum),
			expectNum: defaultNum,
		},
		{
			name: "global number is invalid",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: -1,
				},
			},
			expectLog: fmt.Sprintf("Global number %v is invalid, use the default value %v", -1, defaultNum),
			expectNum: defaultNum,
		},
		{
			name: "global number is valid",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
				},
			},
			expectNum: globalNum,
		},
		{
			name: "node is not found",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							Number: 100,
						},
					},
				},
			},
			setKubeClient: true,
			expectLog:     fmt.Sprintf("Failed to get node info for %s, use the global number %v", nodeName, globalNum),
			expectNum:     globalNum,
		},
		{
			name: "failed to get selector",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							NodeSelector: invalidLabelSelector,
							Number:       100,
						},
					},
				},
			},
			setKubeClient: true,
			kubeClientObj: []runtime.Object{node1},
			expectLog:     fmt.Sprintf("Failed to parse rule with label selector %s, skip it", invalidLabelSelector.String()),
			expectNum:     globalNum,
		},
		{
			name: "rule number is invalid",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							NodeSelector: validLabelSelector1,
							Number:       -1,
						},
					},
				},
			},
			setKubeClient: true,
			kubeClientObj: []runtime.Object{node1},
			expectLog:     fmt.Sprintf("Rule with label selector %s is with an invalid number %v, skip it", validLabelSelector1.String(), -1),
			expectNum:     globalNum,
		},
		{
			name: "label doesn't match",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							NodeSelector: validLabelSelector1,
							Number:       -1,
						},
					},
				},
			},
			setKubeClient: true,
			kubeClientObj: []runtime.Object{node1},
			expectLog:     fmt.Sprintf("Per node number for node %s is not found, use the global number %v", nodeName, globalNum),
			expectNum:     globalNum,
		},
		{
			name: "match one rule",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							NodeSelector: validLabelSelector1,
							Number:       66,
						},
					},
				},
			},
			setKubeClient: true,
			kubeClientObj: []runtime.Object{node2},
			expectLog:     fmt.Sprintf("Use the per node number %v over global number %v for node %s", 66, globalNum, nodeName),
			expectNum:     66,
		},
		{
			name: "match multiple rules",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							NodeSelector: validLabelSelector1,
							Number:       66,
						},
						{
							NodeSelector: validLabelSelector2,
							Number:       36,
						},
					},
				},
			},
			setKubeClient: true,
			kubeClientObj: []runtime.Object{node2},
			expectLog:     fmt.Sprintf("Use the per node number %v over global number %v for node %s", 36, globalNum, nodeName),
			expectNum:     36,
		},
		{
			name: "match multiple rules 2",
			configs: velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					GlobalConfig: globalNum,
					PerNodeConfig: []velerotypes.RuledConfigs{
						{
							NodeSelector: validLabelSelector1,
							Number:       36,
						},
						{
							NodeSelector: validLabelSelector2,
							Number:       66,
						},
					},
				},
			},
			setKubeClient: true,
			kubeClientObj: []runtime.Object{node2},
			expectLog:     fmt.Sprintf("Use the per node number %v over global number %v for node %s", 36, globalNum, nodeName),
			expectNum:     36,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			logBuffer := ""

			s := &nodeAgentServer{
				nodeName:        nodeName,
				dataPathConfigs: &test.configs,
				logger:          testutil.NewSingleLogger(&logBuffer),
			}

			if test.setKubeClient {
				s.kubeClient = fakeKubeClient
			}

			num := s.getDataPathConcurrentNum(defaultNum)
			assert.Equal(t, test.expectNum, num)
			if test.expectLog == "" {
				assert.Empty(t, logBuffer)
			} else {
				assert.Contains(t, logBuffer, test.expectLog)
			}
		})
	}
}

func TestGetBackupRepoConfigs(t *testing.T) {
	cmNoData := builder.ForConfigMap(velerov1api.DefaultNamespace, "backup-repo-config").Result()
	cmWithData := builder.ForConfigMap(velerov1api.DefaultNamespace, "backup-repo-config").Data("cacheLimit", "100").Result()

	tests := []struct {
		name          string
		configMapName string
		kubeClientObj []runtime.Object
		expectConfigs map[string]string
		expectedErr   string
	}{
		{
			name: "no config specified",
		},
		{
			name:          "failed to get configs",
			configMapName: "backup-repo-config",
			expectedErr:   "error getting backup repo configs from configMap backup-repo-config: configmaps \"backup-repo-config\" not found",
		},
		{
			name:          "configs data not found",
			kubeClientObj: []runtime.Object{cmNoData},
			configMapName: "backup-repo-config",
			expectedErr:   "no data is in the backup repo configMap backup-repo-config",
		},
		{
			name:          "succeed",
			configMapName: "backup-repo-config",
			kubeClientObj: []runtime.Object{cmWithData},
			expectConfigs: map[string]string{"cacheLimit": "100"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			s := &nodeAgentServer{
				namespace:  velerov1api.DefaultNamespace,
				kubeClient: fakeKubeClient,
				config: nodeAgentServerConfig{
					backupRepoConfig: test.configMapName,
				},
				logger: testutil.NewLogger(),
			}

			err := s.getBackupRepoConfigs()
			if test.expectedErr == "" {
				require.NoError(t, err)
				require.Equal(t, test.expectConfigs, s.backupRepoConfigs)
			} else {
				require.EqualError(t, err, test.expectedErr)
			}
		})
	}
}

func TestValidateCachePVCConfig(t *testing.T) {
	scWithRetainPolicy := builder.ForStorageClass("fake-storage-class").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result()
	scWithDeletePolicy := builder.ForStorageClass("fake-storage-class").ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).Result()
	scWithNoPolicy := builder.ForStorageClass("fake-storage-class").Result()

	tests := []struct {
		name          string
		config        velerotypes.CachePVC
		kubeClientObj []runtime.Object
		expectedErr   string
	}{
		{
			name:        "no storage class",
			expectedErr: "storage class is absent",
		},
		{
			name:        "failed to get storage class",
			config:      velerotypes.CachePVC{StorageClass: "fake-storage-class"},
			expectedErr: "error getting storage class fake-storage-class: storageclasses.storage.k8s.io \"fake-storage-class\" not found",
		},
		{
			name:          "storage class reclaim policy is not expected",
			config:        velerotypes.CachePVC{StorageClass: "fake-storage-class"},
			kubeClientObj: []runtime.Object{scWithRetainPolicy},
			expectedErr:   "unexpected storage class reclaim policy Retain",
		},
		{
			name:          "storage class reclaim policy is delete",
			config:        velerotypes.CachePVC{StorageClass: "fake-storage-class"},
			kubeClientObj: []runtime.Object{scWithDeletePolicy},
		},
		{
			name:          "storage class with no reclaim policy",
			config:        velerotypes.CachePVC{StorageClass: "fake-storage-class"},
			kubeClientObj: []runtime.Object{scWithNoPolicy},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			s := &nodeAgentServer{
				kubeClient: fakeKubeClient,
			}

			err := s.validateCachePVCConfig(test.config)

			if test.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.expectedErr)
			}
		})
	}
}

func Test_initVgdpCounter(t *testing.T) {
	origStartVgdpCounterFunc := startVgdpCounterFunc
	defer func() {
		startVgdpCounterFunc = origStartVgdpCounterFunc
	}()

	mockCounter := &exposer.VgdpCounter{}

	tests := []struct {
		name                 string
		dataPathConfigs      *velerotypes.NodeAgentConfigs
		mockFunc             func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error)
		expectQueueLength    int
		expectVgdpCounterSet bool
		expectLog            string
	}{
		{
			name:            "default configs, startVgdpCounter succeeds",
			dataPathConfigs: nil,
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return mockCounter, nil
			},
			expectQueueLength:    defaultPrepareQueueLength,
			expectVgdpCounterSet: true,
			expectLog:            fmt.Sprintf("VGDP loads are constrained with %d", defaultPrepareQueueLength),
		},
		{
			name: "custom queue length, startVgdpCounter succeeds",
			dataPathConfigs: &velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					PrepareQueueLength: 10,
				},
			},
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return mockCounter, nil
			},
			expectQueueLength:    10,
			expectVgdpCounterSet: true,
			expectLog:            "VGDP loads are constrained with 10",
		},
		{
			name: "LoadConcurrency is nil, uses default queue length",
			dataPathConfigs: &velerotypes.NodeAgentConfigs{
				LoadConcurrency: nil,
			},
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return mockCounter, nil
			},
			expectQueueLength:    defaultPrepareQueueLength,
			expectVgdpCounterSet: true,
			expectLog:            fmt.Sprintf("VGDP loads are constrained with %d", defaultPrepareQueueLength),
		},
		{
			name: "PrepareQueueLength is 0, uses default queue length",
			dataPathConfigs: &velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					PrepareQueueLength: 0,
				},
			},
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return mockCounter, nil
			},
			expectQueueLength:    defaultPrepareQueueLength,
			expectVgdpCounterSet: true,
			expectLog:            fmt.Sprintf("VGDP loads are constrained with %d", defaultPrepareQueueLength),
		},
		{
			name: "PrepareQueueLength is negative, uses default queue length",
			dataPathConfigs: &velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					PrepareQueueLength: -1,
				},
			},
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return mockCounter, nil
			},
			expectQueueLength:    defaultPrepareQueueLength,
			expectVgdpCounterSet: true,
			expectLog:            fmt.Sprintf("VGDP loads are constrained with %d", defaultPrepareQueueLength),
		},
		{
			name:            "startVgdpCounter fails with default queue length",
			dataPathConfigs: nil,
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return nil, errors.New("fake-start-error")
			},
			expectQueueLength:    defaultPrepareQueueLength,
			expectVgdpCounterSet: false,
			expectLog:            fmt.Sprintf("Failed to start VGDP counter with length %d, VDGP loads are not constrained", defaultPrepareQueueLength),
		},
		{
			name: "startVgdpCounter fails with custom queue length",
			dataPathConfigs: &velerotypes.NodeAgentConfigs{
				LoadConcurrency: &velerotypes.LoadConcurrency{
					PrepareQueueLength: 8,
				},
			},
			mockFunc: func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				return nil, errors.New("fake-start-error")
			},
			expectQueueLength:    8,
			expectVgdpCounterSet: false,
			expectLog:            "Failed to start VGDP counter with length 8, VDGP loads are not constrained",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var recordedQueueLength int
			startVgdpCounterFunc = func(ctx context.Context, mgr manager.Manager, queueLength int) (*exposer.VgdpCounter, error) {
				recordedQueueLength = queueLength
				return test.mockFunc(ctx, mgr, queueLength)
			}

			logBuffer := ""
			s := &nodeAgentServer{
				ctx:             t.Context(),
				dataPathConfigs: test.dataPathConfigs,
				logger:          testutil.NewSingleLogger(&logBuffer),
			}

			s.initVgdpCounter()

			assert.Equal(t, test.expectQueueLength, recordedQueueLength)
			if test.expectVgdpCounterSet {
				assert.Equal(t, mockCounter, s.vgdpCounter)
			} else {
				assert.Nil(t, s.vgdpCounter)
			}

			if test.expectLog != "" {
				assert.Contains(t, logBuffer, test.expectLog)
			}
		})
	}
}
