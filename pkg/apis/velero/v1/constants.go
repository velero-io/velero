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

package v1

const (
	// DefaultNamespace is the Kubernetes namespace that is used by default for
	// the Velero server and API objects.
	DefaultNamespace = "velero"

	// ResourcesDir is a top-level directory expected in backups which contains sub-directories
	// for each resource type in the backup.
	ResourcesDir = "resources"

	// MetadataDir is a top-level directory expected in backups which contains
	// files that store metadata about the backup, such as the backup version.
	MetadataDir = "metadata"

	// ClusterScopedDir is the name of the directory containing cluster-scoped
	// resources within a Velero backup.
	ClusterScopedDir = "cluster"

	// NamespaceScopedDir is the name of the directory containing namespace-scoped
	// resource within a Velero backup.
	NamespaceScopedDir = "namespaces"

	// CSIFeatureFlag is the feature flag string that defines whether or not CSI features are being used.
	CSIFeatureFlag = "EnableCSI"

	// PreferredVersionDir is the suffix name of the directory containing the preferred version of the API group
	// resource within a Velero backup.
	PreferredVersionDir = "-preferredversion"

	// APIGroupVersionsFeatureFlag is the feature flag string that defines whether or not to handle multiple API Group Versions
	APIGroupVersionsFeatureFlag = "EnableAPIGroupVersions"

	// BSLWorkerIdentityFeatureFlag is the feature flag string that defines whether or not a
	// BackupStorageLocation may run its object-store operations in a dedicated worker pod
	// under a distinct pod identity (see BackupStorageLocationSpec.Worker).
	BSLWorkerIdentityFeatureFlag = "EnableBSLWorkerIdentity"
)
