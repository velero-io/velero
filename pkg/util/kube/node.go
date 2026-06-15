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

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	NodeOSLinux   = "linux"
	NodeOSWindows = "windows"
	NodeOSLabel   = "kubernetes.io/os"
)

var realNodeOSMap = map[string]string{
	"linux":   NodeOSLinux,
	"windows": NodeOSWindows,
}

func IsLinuxNode(ctx context.Context, nodeName string, client client.Client) error {
	node := &corev1api.Node{}
	if err := client.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
		return errors.Wrapf(err, "error getting node %s", nodeName)
	}

	os, found := node.Labels[NodeOSLabel]
	if !found {
		return errors.Errorf("no os type label for node %s", nodeName)
	}

	if getRealOS(os) != NodeOSLinux {
		return errors.Errorf("os type %s for node %s is not linux", os, nodeName)
	}

	return nil
}

func WithLinuxNode(ctx context.Context, client client.Client, log logrus.FieldLogger) bool {
	return withOSNode(ctx, client, NodeOSLinux, log)
}

func WithWindowsNode(ctx context.Context, client client.Client, log logrus.FieldLogger) bool {
	return withOSNode(ctx, client, NodeOSWindows, log)
}

func withOSNode(ctx context.Context, client client.Client, osType string, log logrus.FieldLogger) bool {
	nodeList := new(corev1api.NodeList)
	if err := client.List(ctx, nodeList); err != nil {
		log.Warnf("Failed to list nodes, cannot decide existence of nodes of OS %s", osType)
		return false
	}

	allNodeLabeled := true
	for _, node := range nodeList.Items {
		os, found := node.Labels[NodeOSLabel]

		if getRealOS(os) == osType {
			return true
		}

		if !found {
			allNodeLabeled = false
		}
	}

	if !allNodeLabeled {
		log.Warnf("Not all nodes have os type label, cannot decide existence of nodes of OS %s", osType)
	}

	return false
}

func GetNodeOS(ctx context.Context, nodeName string, nodeClient corev1client.CoreV1Interface) (string, error) {
	node, err := nodeClient.Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", errors.Wrapf(err, "error getting node %s", nodeName)
	}

	if node.Labels == nil {
		return "", nil
	}

	return getRealOS(node.Labels[NodeOSLabel]), nil
}

func HasNodeWithOS(ctx context.Context, os string, nodeClient corev1client.CoreV1Interface) error {
	if os == "" {
		return errors.New("invalid node OS")
	}

	nodes, err := nodeClient.Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "error listing nodes with OS %s", os)
	}

	for _, node := range nodes.Items {
		osLabel, found := node.Labels[NodeOSLabel]
		if !found {
			continue
		}

		if getRealOS(osLabel) == os {
			return nil
		}
	}

	return errors.Errorf("node with OS %s doesn't exist", os)
}

func getRealOS(osLabel string) string {
	if os, found := realNodeOSMap[osLabel]; !found {
		return NodeOSLinux
	} else {
		return os
	}
}
