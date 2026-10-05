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
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

// GetItemFilePath returns an item's file path once extracted from a Velero backup archive.
func GetItemFilePath(rootDir, groupResource, namespace, name string) (string, error) {
	return GetVersionedItemFilePath(rootDir, groupResource, namespace, name, "")
}

// GetVersionedItemFilePath returns an item's file path once extracted from a Velero backup archive, with version included.
//
// The namespace and name components can originate from backup contents - for example the
// additional items a RestoreItemAction returns are built from annotations on a backed up
// object - so the joined path is verified to stay within rootDir. Without that check a
// component containing ".." escapes the extracted backup directory and addresses an
// arbitrary file on the Velero pod's filesystem.
func GetVersionedItemFilePath(rootDir, groupResource, namespace, name, versionPath string) (string, error) {
	path := filepath.Join(rootDir, velerov1api.ResourcesDir, groupResource, versionPath, GetScopeDir(namespace), namespace, name+".json")

	// rootDir is empty when building the path of an entry inside the backup tarball rather
	// than of an extracted file on disk; "." is the containment base for that relative form.
	base := rootDir
	if base == "" {
		base = "."
	}

	rel, err := filepath.Rel(base, path)
	if err != nil {
		return "", errors.Wrapf(err, "error resolving item path for %q/%q", namespace, name)
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.Errorf("invalid item path for %q/%q: escapes the backup directory", namespace, name)
	}

	return path, nil
}

// GetScopeDir returns NamespaceScopedDir if namespace is present, or ClusterScopedDir if empty
func GetScopeDir(namespace string) string {
	if namespace == "" {
		return velerov1api.ClusterScopedDir
	}
	return velerov1api.NamespaceScopedDir
}

// Unmarshal reads the specified file, unmarshals the JSON contained within it
// and returns an Unstructured object.
func Unmarshal(fs filesystem.Interface, filePath string) (*unstructured.Unstructured, error) {
	var obj unstructured.Unstructured

	bytes, err := fs.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bytes, &obj)
	if err != nil {
		return nil, err
	}

	return &obj, nil
}
