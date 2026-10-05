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

package archive

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/test"
)

func TestGetItemFilePath(t *testing.T) {
	res, err := GetItemFilePath("root", "resource", "", "item")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/cluster/item.json", res)

	res, err = GetItemFilePath("root", "resource", "namespace", "item")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/namespaces/namespace/item.json", res)

	res, err = GetItemFilePath("", "resource", "", "item")
	require.NoError(t, err)
	assert.Equal(t, "resources/resource/cluster/item.json", res)

	res, err = GetVersionedItemFilePath("root", "resource", "", "item", "")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/cluster/item.json", res)

	res, err = GetVersionedItemFilePath("root", "resource", "namespace", "item", "")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/namespaces/namespace/item.json", res)

	res, err = GetVersionedItemFilePath("root", "resource", "namespace", "item", "v1")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/v1/namespaces/namespace/item.json", res)

	res, err = GetVersionedItemFilePath("root", "resource", "", "item", "v1")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/v1/cluster/item.json", res)

	res, err = GetVersionedItemFilePath("", "resource", "", "item", "")
	require.NoError(t, err)
	assert.Equal(t, "resources/resource/cluster/item.json", res)
}

// TestGetItemFilePathRejectsPathTraversal verifies that a name or namespace containing
// ".." cannot address a file outside the extracted backup directory. These components can
// come from backup contents, for example the additional items a RestoreItemAction builds
// from annotations on a backed up object.
func TestGetItemFilePathRejectsPathTraversal(t *testing.T) {
	tests := []struct {
		name          string
		rootDir       string
		groupResource string
		namespace     string
		itemName      string
	}{
		{
			name:          "traversal in name escapes root",
			rootDir:       "/tmp/restore-dir",
			groupResource: "secrets",
			namespace:     "x",
			itemName:      "../../../../../../root/.docker/config",
		},
		{
			name:          "traversal in namespace escapes root",
			rootDir:       "/tmp/restore-dir",
			groupResource: "secrets",
			namespace:     "../../../../../../etc",
			itemName:      "passwd",
		},
		{
			name:          "traversal in group resource escapes root",
			rootDir:       "/tmp/restore-dir",
			groupResource: "../../../../../../etc",
			namespace:     "",
			itemName:      "passwd",
		},
		{
			name:          "traversal escapes archive-relative root",
			rootDir:       "",
			groupResource: "secrets",
			namespace:     "x",
			itemName:      "../../../../../../escape",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := GetItemFilePath(tc.rootDir, tc.groupResource, tc.namespace, tc.itemName)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "escapes the backup directory")
			assert.Empty(t, res)

			res, err = GetVersionedItemFilePath(tc.rootDir, tc.groupResource, tc.namespace, tc.itemName, "v1")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "escapes the backup directory")
			assert.Empty(t, res)
		})
	}
}

// TestGetItemFilePathAllowsInnerDotDot verifies the containment check does not reject a
// path whose ".." segments resolve back inside the root directory.
func TestGetItemFilePathAllowsInnerDotDot(t *testing.T) {
	res, err := GetItemFilePath("root", "resource", "namespaces/..", "item")
	require.NoError(t, err)
	assert.Equal(t, "root/resources/resource/namespaces/item.json", res)
}

func TestGetScopeDir(t *testing.T) {
	res := GetScopeDir("")
	assert.Equal(t, velerov1api.ClusterScopedDir, res)

	res = GetScopeDir("test-namespace")
	assert.Equal(t, velerov1api.NamespaceScopedDir, res)
}

func TestUnmarshal(t *testing.T) {
	fs := test.NewFakeFileSystem()
	filePath := "pod.json"
	fileContent := `{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "example-pod"
		},
		"spec": {
			"containers": [{
				"name": "example-container",
				"image": "example-image"
			}]
		}
	}`
	out, err := fs.Create(filePath)
	require.NoError(t, err)

	_, err = out.Write([]byte(fileContent))
	require.NoError(t, err)

	_, err = Unmarshal(fs, filePath)
	require.NoError(t, err)
}
