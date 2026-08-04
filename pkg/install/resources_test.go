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

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestResources(t *testing.T) {
	bsl := BackupStorageLocation(DefaultVeleroNamespace, "test", "test", "", make(map[string]string), []byte("test"))

	assert.Equal(t, "velero", bsl.ObjectMeta.Namespace)
	assert.Equal(t, "test", bsl.Spec.Provider)
	assert.Equal(t, "test", bsl.Spec.StorageType.ObjectStorage.Bucket)
	assert.Equal(t, make(map[string]string), bsl.Spec.Config)
	assert.Equal(t, []byte("test"), bsl.Spec.ObjectStorage.CACert)

	vsl := VolumeSnapshotLocation(DefaultVeleroNamespace, "test", make(map[string]string))

	assert.Equal(t, "velero", vsl.ObjectMeta.Namespace)
	assert.Equal(t, "test", vsl.Spec.Provider)
	assert.Equal(t, make(map[string]string), vsl.Spec.Config)

	ns := Namespace("velero")

	assert.Equal(t, "velero", ns.Name)
	// For k8s version v1.25 and later, need to add the following labels to make
	// velero installation namespace has privileged version to work with
	// PSA(Pod Security Admission) and PSS(Pod Security Standards).
	assert.Equal(t, "privileged", ns.Labels["pod-security.kubernetes.io/enforce"])
	assert.Equal(t, "latest", ns.Labels["pod-security.kubernetes.io/enforce-version"])
	assert.Equal(t, "privileged", ns.Labels["pod-security.kubernetes.io/audit"])
	assert.Equal(t, "latest", ns.Labels["pod-security.kubernetes.io/audit-version"])
	assert.Equal(t, "privileged", ns.Labels["pod-security.kubernetes.io/warn"])
	assert.Equal(t, "latest", ns.Labels["pod-security.kubernetes.io/warn-version"])

	crb := ClusterRoleBinding(DefaultVeleroNamespace)
	// The CRB is a cluster-scoped resource
	assert.Empty(t, crb.ObjectMeta.Namespace)
	assert.Equal(t, "velero", crb.ObjectMeta.Name)
	assert.Equal(t, "velero", crb.Subjects[0].Namespace)

	customNamespaceCRB := ClusterRoleBinding("foo")
	// The CRB is a cluster-scoped resource
	assert.Empty(t, customNamespaceCRB.ObjectMeta.Namespace)
	assert.Equal(t, "velero-foo", customNamespaceCRB.ObjectMeta.Name)
	assert.Equal(t, "foo", customNamespaceCRB.Subjects[0].Namespace)

	sa := ServiceAccount(DefaultVeleroNamespace, map[string]string{"abcd": "cbd"})
	assert.Equal(t, "velero", sa.ObjectMeta.Namespace)
	assert.Equal(t, "cbd", sa.ObjectMeta.Annotations["abcd"])
}

func TestAllCRDs(t *testing.T) {
	list := AllCRDs()
	assert.Len(t, list.Items, 13)
	assert.Equal(t, Labels(), list.Items[0].GetLabels())
}

func TestAllResources(t *testing.T) {
	option := &VeleroOptions{
		Namespace:           "velero",
		SecretData:          []byte{'a'},
		UseVolumeSnapshots:  true,
		UseNodeAgent:        true,
		UseNodeAgentWindows: true,
	}
	list := AllResources(option)

	objects := map[string][]unstructured.Unstructured{}
	for _, item := range list.Items {
		objects[item.GetKind()] = append(objects[item.GetKind()], item)
	}

	ns, exist := objects["Namespace"]
	require.True(t, exist)
	assert.Equal(t, "velero", ns[0].GetName())

	_, exist = objects["ClusterRoleBinding"]
	assert.True(t, exist)

	_, exist = objects["ServiceAccount"]
	assert.True(t, exist)

	_, exist = objects["Secret"]
	assert.True(t, exist)

	_, exist = objects["BackupStorageLocation"]
	assert.True(t, exist)

	_, exist = objects["VolumeSnapshotLocation"]
	assert.True(t, exist)

	_, exist = objects["Deployment"]
	assert.True(t, exist)

	ds, exist := objects["DaemonSet"]
	assert.True(t, exist)

	assert.Len(t, ds, 2)
}

func TestAllResourcesWithDefaultResourceModifierConfigMap(t *testing.T) {
	option := &VeleroOptions{
		Namespace:                        "velero",
		SecretData:                       []byte{'a'},
		DefaultResourceModifierConfigMap: "default-rm",
	}
	list := AllResources(option)

	for _, item := range list.Items {
		if item.GetKind() == "Deployment" && item.GetName() == "velero" {
			containers, _, _ := unstructured.NestedSlice(item.Object, "spec", "template", "spec", "containers")
			args, _, _ := unstructured.NestedStringSlice(containers[0].(map[string]any), "args")
			found := false
			for _, arg := range args {
				if arg == "--default-resource-modifier-configmap=default-rm" {
					found = true
					break
				}
			}
			assert.True(t, found, "expected --default-resource-modifier-configmap=default-rm in deployment args")
			return
		}
	}
	t.Fatal("velero deployment not found in AllResources output")
}

func TestAllResourcesWithPriorityClassName(t *testing.T) {
	testCases := []struct {
		name                       string
		serverPriorityClassName    string
		nodeAgentPriorityClassName string
		useNodeAgent               bool
	}{
		{
			name:                       "with same priority class for server and node agent",
			serverPriorityClassName:    "high-priority",
			nodeAgentPriorityClassName: "high-priority",
			useNodeAgent:               true,
		},
		{
			name:                       "with different priority classes for server and node agent",
			serverPriorityClassName:    "high-priority",
			nodeAgentPriorityClassName: "medium-priority",
			useNodeAgent:               true,
		},
		{
			name:                       "with only server priority class",
			serverPriorityClassName:    "high-priority",
			nodeAgentPriorityClassName: "",
			useNodeAgent:               true,
		},
		{
			name:                       "with only node agent priority class",
			serverPriorityClassName:    "",
			nodeAgentPriorityClassName: "medium-priority",
			useNodeAgent:               true,
		},
		{
			name:                       "with priority class name without node agent",
			serverPriorityClassName:    "high-priority",
			nodeAgentPriorityClassName: "medium-priority",
			useNodeAgent:               false,
		},
		{
			name:                       "without priority class name with node agent",
			serverPriorityClassName:    "",
			nodeAgentPriorityClassName: "",
			useNodeAgent:               true,
		},
		{
			name:                       "without priority class name without node agent",
			serverPriorityClassName:    "",
			nodeAgentPriorityClassName: "",
			useNodeAgent:               false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create VeleroOptions with the priority class names
			options := &VeleroOptions{
				Namespace:                  "velero",
				UseNodeAgent:               tc.useNodeAgent,
				ServerPriorityClassName:    tc.serverPriorityClassName,
				NodeAgentPriorityClassName: tc.nodeAgentPriorityClassName,
			}

			// Generate all resources
			resources := AllResources(options)

			// Find the deployment and verify priority class name
			deploymentFound := false
			daemonsetFound := false

			for i := range resources.Items {
				item := resources.Items[i]

				// Check deployment
				if item.GetKind() == "Deployment" && item.GetName() == "velero" {
					deploymentFound = true

					// Extract priority class name from the unstructured object
					priorityClassName, found, err := unstructured.NestedString(
						item.Object,
						"spec", "template", "spec", "priorityClassName",
					)

					require.NoError(t, err)
					if tc.serverPriorityClassName != "" {
						assert.True(t, found, "Server priorityClassName should be set")
						assert.Equal(t, tc.serverPriorityClassName, priorityClassName,
							"Server deployment should have the correct priority class")
					} else {
						// If no priority class name was provided, it might not be set at all
						if found {
							assert.Empty(t, priorityClassName)
						}
					}
				}

				// Check daemonset if node agent is enabled
				if tc.useNodeAgent && item.GetKind() == "DaemonSet" && item.GetName() == "node-agent" {
					daemonsetFound = true

					// Extract priority class name from the unstructured object
					priorityClassName, found, err := unstructured.NestedString(
						item.Object,
						"spec", "template", "spec", "priorityClassName",
					)

					require.NoError(t, err)
					if tc.nodeAgentPriorityClassName != "" {
						assert.True(t, found, "Node agent priorityClassName should be set")
						assert.Equal(t, tc.nodeAgentPriorityClassName, priorityClassName,
							"Node agent daemonset should have the correct priority class")
					} else {
						// If no priority class name was provided, it might not be set at all
						if found {
							assert.Empty(t, priorityClassName)
						}
					}
				}
			}

			// Verify we found the deployment
			assert.True(t, deploymentFound, "Deployment should be present in resources")

			// Verify we found the daemonset if node agent is enabled
			if tc.useNodeAgent {
				assert.True(t, daemonsetFound, "DaemonSet should be present when UseNodeAgent is true")
			}
		})
	}
}
