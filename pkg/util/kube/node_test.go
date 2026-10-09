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

package kube

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/pkg/builder"

	kubeClientFake "k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	clientFake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestIsLinuxNode(t *testing.T) {
	nodeNoOSLabel := builder.ForNode("fake-node").Result()
	nodeWindows := builder.ForNode("fake-node").Labels(map[string]string{corev1api.LabelOSStable: "windows"}).Result()
	nodeLinux := builder.ForNode("fake-node").Labels(map[string]string{corev1api.LabelOSStable: "linux"}).Result()

	scheme := runtime.NewScheme()
	corev1api.AddToScheme(scheme)

	tests := []struct {
		name          string
		kubeClientObj []runtime.Object
		err           string
	}{
		{
			name: "error getting node",
			err:  "error getting node fake-node: nodes \"fake-node\" not found",
		},
		{
			name: "no os label",
			kubeClientObj: []runtime.Object{
				nodeNoOSLabel,
			},
			err: "no os type label for node fake-node",
		},
		{
			name: "os label does not match",
			kubeClientObj: []runtime.Object{
				nodeWindows,
			},
			err: "os type windows for node fake-node is not linux",
		},
		{
			name: "succeed",
			kubeClientObj: []runtime.Object{
				nodeLinux,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClientBuilder := clientFake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(scheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			err := IsLinuxNode(t.Context(), "fake-node", fakeClient)
			if err != nil {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWithLinuxNode(t *testing.T) {
	nodeWindows := builder.ForNode("fake-node-1").Labels(map[string]string{corev1api.LabelOSStable: "windows"}).Result()
	nodeLinux := builder.ForNode("fake-node-2").Labels(map[string]string{corev1api.LabelOSStable: "linux"}).Result()

	scheme := runtime.NewScheme()
	corev1api.AddToScheme(scheme)

	tests := []struct {
		name          string
		kubeClientObj []runtime.Object
		result        bool
	}{
		{
			name: "error listing node",
		},
		{
			name: "with node of other type",
			kubeClientObj: []runtime.Object{
				nodeWindows,
			},
		},
		{
			name: "with node of the same type",
			kubeClientObj: []runtime.Object{
				nodeWindows,
				nodeLinux,
			},
			result: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClientBuilder := clientFake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(scheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			result := withOSNode(t.Context(), fakeClient, "linux", velerotest.NewLogger())
			assert.Equal(t, test.result, result)
		})
	}
}

func TestGetNodeOSType(t *testing.T) {
	nodeNoOSLabel := builder.ForNode("fake-node").Result()
	nodeWindows := builder.ForNode("fake-node").Labels(map[string]string{corev1api.LabelOSStable: "windows"}).Result()
	nodeLinux := builder.ForNode("fake-node").Labels(map[string]string{corev1api.LabelOSStable: "linux"}).Result()
	scheme := runtime.NewScheme()
	corev1api.AddToScheme(scheme)
	tests := []struct {
		name           string
		kubeClientObj  []runtime.Object
		err            string
		expectedOSType string
	}{
		{
			name: "error getting node",
			err:  "error getting node fake-node: nodes \"fake-node\" not found",
		},
		{
			name: "no os label",
			kubeClientObj: []runtime.Object{
				nodeNoOSLabel,
			},
		},
		{
			name: "windows node",
			kubeClientObj: []runtime.Object{
				nodeWindows,
			},
			expectedOSType: "windows",
		},
		{
			name: "linux node",
			kubeClientObj: []runtime.Object{
				nodeLinux,
			},
			expectedOSType: "linux",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := kubeClientFake.NewSimpleClientset(test.kubeClientObj...)
			osType, err := GetNodeOS(t.Context(), "fake-node", fakeKubeClient.CoreV1())
			if err != nil {
				assert.EqualError(t, err, test.err)
			} else {
				assert.Equal(t, test.expectedOSType, osType)
			}
		})
	}
}

func TestHasNodeWithOS(t *testing.T) {
	nodeNoOSLabel := builder.ForNode("fake-node-1").Result()
	nodeWindows := builder.ForNode("fake-node-2").Labels(map[string]string{corev1api.LabelOSStable: "windows"}).Result()
	nodeLinux := builder.ForNode("fake-node-3").Labels(map[string]string{corev1api.LabelOSStable: "linux"}).Result()

	scheme := runtime.NewScheme()
	corev1api.AddToScheme(scheme)

	tests := []struct {
		name          string
		kubeClientObj []runtime.Object
		kubeReactors  []reactor
		os            string
		err           string
	}{
		{
			name: "os is empty",
			err:  "invalid node OS",
		},
		{
			name: "error to list node",
			kubeReactors: []reactor{
				{
					verb:     "list",
					resource: "nodes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-list-error")
					},
				},
			},
			os:  "linux",
			err: "error listing nodes with OS linux: fake-list-error",
		},
		{
			name: "no expected node - no node",
			os:   "linux",
			err:  "node with OS linux doesn't exist",
		},
		{
			name: "no expected node - no node with label",
			kubeClientObj: []runtime.Object{
				nodeNoOSLabel,
				nodeWindows,
			},
			os:  "linux",
			err: "node with OS linux doesn't exist",
		},
		{
			name: "succeed",
			kubeClientObj: []runtime.Object{
				nodeNoOSLabel,
				nodeWindows,
				nodeLinux,
			},
			os: "windows",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := kubeClientFake.NewSimpleClientset(test.kubeClientObj...)

			for _, reactor := range test.kubeReactors {
				fakeKubeClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			err := HasNodeWithOS(t.Context(), test.os, fakeKubeClient.CoreV1())
			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type fakeCoreV1 struct {
	corev1client.CoreV1Interface
	nodeClient corev1client.NodeInterface
}

func (f *fakeCoreV1) Nodes() corev1client.NodeInterface {
	return f.nodeClient
}

type fakeNodeClient struct {
	corev1client.NodeInterface
	getFunc func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1api.Node, error)
}

func (f *fakeNodeClient) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1api.Node, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, name, opts)
	}
	return f.NodeInterface.Get(ctx, name, opts)
}

func TestGetNodeOSWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var passedCtx context.Context
	nodeClient := &fakeNodeClient{
		getFunc: func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1api.Node, error) {
			passedCtx = ctx
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return builder.ForNode("fake-node").Labels(map[string]string{corev1api.LabelOSStable: "linux"}).Result(), nil
		},
	}
	fakeCore := &fakeCoreV1{nodeClient: nodeClient}

	_, err := GetNodeOS(ctx, "fake-node", fakeCore)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ctx, passedCtx)
}
