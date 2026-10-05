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

package archive

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

var ErrNotExist = errors.New("does not exist")

// Parser traverses an extracted archive on disk to validate
// it and provide a helpful representation of it to consumers.
type Parser struct {
	log logrus.FieldLogger
	fs  filesystem.Interface
}

// ResourceItems contains the collection of items of a given resource type
// within a backup, grouped by namespace (or empty string for cluster-scoped
// resources).
type ResourceItems struct {
	// GroupResource is API group and resource name,
	// formatted as "resource.group". For the "core"
	// API group, the ".group" suffix is omitted.
	GroupResource string

	// ItemsByNamespace is a map from namespace (or empty string
	// for cluster-scoped resources) to a list of individual item
	// names contained in the archive. Item names **do not** include
	// the file extension.
	ItemsByNamespace map[string][]string
}

// NewParser constructs a Parser.
func NewParser(log logrus.FieldLogger, fs filesystem.Interface) *Parser {
	return &Parser{
		log: log,
		fs:  fs,
	}
}

// Parse reads an extracted backup on the file system and returns
// a structured catalog of the resources and items contained within it.
func (p *Parser) Parse(dir string) (map[string]*ResourceItems, error) {
	// ensure top-level "resources" directory exists, and read subdirectories
	// of it, where each one is expected to correspond to a resource.
	resourcesDir := filepath.Join(dir, velerov1api.ResourcesDir)
	resourceDirs, err := p.checkAndReadDir(resourcesDir)
	if err != nil {
		return nil, err
	}

	// loop through each subdirectory (one per resource) and assemble
	// catalog of items within it.
	resources := map[string]*ResourceItems{}
	for _, resourceDir := range resourceDirs {
		if !resourceDir.IsDir() {
			p.log.Warnf("Ignoring unexpected file %q in directory %q", resourceDir.Name(), strings.TrimPrefix(resourcesDir, dir+"/"))
			continue
		}

		resourceItems := &ResourceItems{
			GroupResource:    resourceDir.Name(),
			ItemsByNamespace: map[string][]string{},
		}

		// check for existence of a "cluster" subdirectory containing cluster-scoped
		// instances of this resource, and read its contents if it exists.
		clusterScopedDir := filepath.Join(resourcesDir, resourceDir.Name(), velerov1api.ClusterScopedDir)
		exists, err := p.fs.DirExists(clusterScopedDir)
		if err != nil {
			return nil, errors.Wrapf(err, "error checking for existence of directory %q", strings.TrimPrefix(clusterScopedDir, dir+"/"))
		}
		if exists {
			items, err := p.getResourceItemsForScope(clusterScopedDir, dir)
			if err != nil {
				return nil, err
			}

			if len(items) > 0 {
				resourceItems.ItemsByNamespace[""] = items
			}
		}

		// check for existence of a "namespaces" subdirectory containing further subdirectories,
		// one per namespace, and read its contents if it exists.
		namespaceScopedDir := filepath.Join(resourcesDir, resourceDir.Name(), velerov1api.NamespaceScopedDir)
		exists, err = p.fs.DirExists(namespaceScopedDir)
		if err != nil {
			return nil, errors.Wrapf(err, "error checking for existence of directory %q", strings.TrimPrefix(namespaceScopedDir, dir+"/"))
		}
		if exists {
			namespaceDirs, err := p.fs.ReadDir(namespaceScopedDir)
			if err != nil {
				return nil, errors.Wrapf(err, "error reading contents of directory %q", strings.TrimPrefix(namespaceScopedDir, dir+"/"))
			}

			for _, namespaceDir := range namespaceDirs {
				if !namespaceDir.IsDir() {
					p.log.Warnf("Ignoring unexpected file %q in directory %q", namespaceDir.Name(), strings.TrimPrefix(namespaceScopedDir, dir+"/"))
					continue
				}

				items, err := p.getResourceItemsForScope(filepath.Join(namespaceScopedDir, namespaceDir.Name()), dir)
				if err != nil {
					return nil, err
				}

				if len(items) > 0 {
					resourceItems.ItemsByNamespace[namespaceDir.Name()] = items
				}
			}
		}

		resources[resourceDir.Name()] = resourceItems
	}

	return resources, nil
}

// getResourceItemsForScope returns the list of items with a namespace or
// cluster-scoped subdirectory for a specific resource.
func (p *Parser) getResourceItemsForScope(dir, archiveRootDir string) ([]string, error) {
	files, err := p.fs.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading contents of directory %q", strings.TrimPrefix(dir, archiveRootDir+"/"))
	}

	var items []string
	for _, file := range files {
		if file.IsDir() {
			p.log.Warnf("Ignoring unexpected subdirectory %q in directory %q", file.Name(), strings.TrimPrefix(dir, archiveRootDir+"/"))
			continue
		}

		items = append(items, strings.TrimSuffix(file.Name(), ".json"))
	}

	return items, nil
}

// checkAndReadDir is a wrapper around fs.DirExists and fs.ReadDir that does checks
// and returns errors if directory cannot be read.
func (p *Parser) checkAndReadDir(dir string) ([]os.FileInfo, error) {
	exists, err := p.fs.DirExists(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "error checking for existence of directory %q", filepath.ToSlash(dir))
	}
	if !exists {
		return nil, errors.Wrapf(ErrNotExist, "directory %q", filepath.ToSlash(dir))
	}

	contents, err := p.fs.ReadDir(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "reading contents of %q", filepath.ToSlash(dir))
	}

	return contents, nil
}

// ParseGroupVersions extracts the versions for each API Group from the backup
// directory names and stores them in a metav1 APIGroup object.
func (p *Parser) ParseGroupVersions(dir string) (map[string]metav1.APIGroup, error) {
	resourcesDir := filepath.Join(dir, velerov1api.ResourcesDir)

	// Get the subdirectories inside the "resources" directory. The subdirectories
	// will have resource.group names like "horizontalpodautoscalers.autoscaling".
	rgDirs, err := p.checkAndReadDir(resourcesDir)
	if err != nil {
		return nil, err
	}

	resourceAGs := make(map[string]metav1.APIGroup)

	// Loop through the resource.group directory names.
	for _, rgd := range rgDirs {
		group := metav1.APIGroup{
			Name: extractGroupName(rgd.Name()),
		}

		rgdPath := filepath.Join(resourcesDir, rgd.Name())

		// Inside each of the resource.group directories are directories whose
		// names are API Group versions like "v1" or "v1-preferredversion"
		gvDirs, err := p.checkAndReadDir(rgdPath)
		if err != nil {
			return nil, err
		}

		var supportedVersions []metav1.GroupVersionForDiscovery

		for _, gvd := range gvDirs {
			gvdName := gvd.Name()

			// Don't save the namespaces or clusters directories in list of
			// supported API Group Versions.
			if gvdName == "namespaces" || gvdName == "cluster" {
				continue
			}

			version := metav1.GroupVersionForDiscovery{
				GroupVersion: strings.TrimPrefix(group.Name+"/"+gvdName, "/"),
				Version:      gvdName,
			}

			if strings.Contains(gvdName, velerov1api.PreferredVersionDir) {
				gvdName = strings.TrimSuffix(gvdName, velerov1api.PreferredVersionDir)

				// Update version and group version to be without suffix.
				version.Version = gvdName
				version.GroupVersion = strings.TrimPrefix(group.Name+"/"+gvdName, "/")

				group.PreferredVersion = version
			}

			supportedVersions = append(supportedVersions, version)
		}

		group.Versions = supportedVersions

		resourceAGs[rgd.Name()] = group
	}

	return resourceAGs, nil
}

// extractGroupName will take a concatenated resource.group and extract the group,
// if there is one. Resources like "pods" which has no group and will return an
// empty string.
func extractGroupName(resourceGroupDir string) string {
	parts := strings.SplitN(resourceGroupDir, ".", 2)
	var group string

	if len(parts) == 2 {
		group = parts[1]
	}

	return group
}
