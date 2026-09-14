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

package volumehelper

import (
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/volumehelper"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	podvolumeutil "github.com/vmware-tanzu/velero/pkg/util/podvolume"
	vhutil "github.com/vmware-tanzu/velero/pkg/util/volumehelper"
)

// ShouldPerformSnapshotWithBackup is used for third-party plugins.
// It supports to check whether the PVC or PodVolume should be backed
// up on demand. On the other hand, the volumeHelperImpl assume there
// is a VolumeHelper instance initialized before calling the
// ShouldPerformXXX functions.
//
// Deprecated: Use ShouldPerformSnapshotWithVolumeHelper instead for better performance.
// ShouldPerformSnapshotWithVolumeHelper allows passing a pre-created VolumeHelper with
// an internal PVC-to-Pod cache, which avoids O(N*M) complexity when there are many PVCs and pods.
// See issue #9179 for details.
func ShouldPerformSnapshotWithBackup(
	unstructured runtime.Unstructured,
	groupResource schema.GroupResource,
	backup velerov1api.Backup,
	crClient crclient.Client,
	logger logrus.FieldLogger,
) (bool, error) {
	return ShouldPerformSnapshotWithVolumeHelper(
		unstructured,
		groupResource,
		backup,
		crClient,
		logger,
		nil, // no cached VolumeHelper, will create one
	)
}

// ShouldPerformSnapshotWithVolumeHelper is like ShouldPerformSnapshotWithBackup
// but accepts an optional VolumeHelper. If vh is non-nil, it will be used directly,
// avoiding the overhead of creating a new VolumeHelper on each call.
// This is useful for BIA plugins that process multiple PVCs during a single backup
// and want to reuse the same VolumeHelper (with its internal cache) across calls.
func ShouldPerformSnapshotWithVolumeHelper(
	unstructured runtime.Unstructured,
	groupResource schema.GroupResource,
	backup velerov1api.Backup,
	crClient crclient.Client,
	logger logrus.FieldLogger,
	vh vhutil.VolumeHelper,
) (bool, error) {
	// If a VolumeHelper is provided, use it directly
	if vh != nil {
		return vh.ShouldPerformSnapshot(unstructured, groupResource)
	}

	// Otherwise, create a new VolumeHelper (original behavior for third-party plugins)
	resourcePolicies, err := resourcepolicies.GetResourcePoliciesFromBackup(
		backup,
		crClient,
		logger,
	)
	if err != nil {
		return false, err
	}

	//nolint:staticcheck // Intentional use of deprecated function for backwards compatibility
	volumeHelperImpl := volumehelper.NewVolumeHelperImpl(
		resourcePolicies,
		backup.Spec.SnapshotVolumes,
		logger,
		crClient,
		boolptr.IsSetToTrue(backup.Spec.DefaultVolumesToFsBackup),
		true,
		nil,
	)

	return volumeHelperImpl.ShouldPerformSnapshot(unstructured, groupResource)
}

// NewVolumeHelperWithNamespaces creates a VolumeHelper with a PVC-to-Pod cache for improved performance.
// The cache is built internally from the provided namespaces list.
// This avoids O(N*M) complexity when there are many PVCs and pods.
// See issue #9179 for details.
// Returns an error if cache building fails - callers should not proceed with backup in this case.
func NewVolumeHelperWithNamespaces(
	volumePolicy *resourcepolicies.Policies,
	snapshotVolumes *bool,
	logger logrus.FieldLogger,
	client crclient.Client,
	defaultVolumesToFSBackup bool,
	backupExcludePVC bool,
	namespaces []string,
	pvcMustInclusionTracker vhutil.PVCMustInclusionTracker,
) (vhutil.VolumeHelper, error) {
	return volumehelper.NewVolumeHelperImplWithNamespaces(
		volumePolicy,
		snapshotVolumes,
		logger,
		client,
		defaultVolumesToFSBackup,
		backupExcludePVC,
		namespaces,
		pvcMustInclusionTracker,
	)
}

// NewVolumeHelperWithCache creates a VolumeHelper using an externally managed PVC-to-Pod cache.
// This is used by plugins that build the cache lazily per-namespace (following the pattern from PR #9226).
// The cache can be nil, in which case PVC-to-Pod lookups will fall back to direct API calls.
func NewVolumeHelperWithCache(
	backup velerov1api.Backup,
	client crclient.Client,
	logger logrus.FieldLogger,
	pvcPodCache *podvolumeutil.PVCPodCache,
	pvcMustInclusionTracker vhutil.PVCMustInclusionTracker,
) (vhutil.VolumeHelper, error) {
	return volumehelper.NewVolumeHelperImplWithCache(
		backup,
		client,
		logger,
		pvcPodCache,
		pvcMustInclusionTracker,
	)
}
