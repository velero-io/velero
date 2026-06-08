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

package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

// DescribeBackupInSF describes a backup in structured format.
func DescribeBackupInSF(
	ctx context.Context,
	kbClient kbclient.Client,
	backup *velerov1api.Backup,
	deleteRequests []velerov1api.DeleteBackupRequest,
	podVolumeBackups []velerov1api.PodVolumeBackup,
	details bool,
	insecureSkipTLSVerify bool,
	caCertFile string,
	outputFormat string,
) string {
	return DescribeInSF(func(d *StructuredDescriber) {
		d.DescribeMetadata(backup.ObjectMeta)

		d.Describe("phase", backup.Status.Phase)

		if backup.Spec.ResourcePolicy != nil {
			DescribeResourcePoliciesInSF(d, backup.Spec.ResourcePolicy)
			DescribeFineGrainedFilterPoliciesInSF(ctx, kbClient, d, backup)
		}

		status := backup.Status
		if len(status.ValidationErrors) > 0 {
			d.Describe("validationErrors", status.ValidationErrors)
		}

		DescribeBackupResultsInSF(ctx, kbClient, d, backup, insecureSkipTLSVerify, caCertFile)

		DescribeBackupSpecInSF(d, backup.Spec)

		DescribeBackupStatusInSF(ctx, kbClient, d, backup, details, insecureSkipTLSVerify, caCertFile, podVolumeBackups)

		if len(deleteRequests) > 0 {
			DescribeDeleteBackupRequestsInSF(d, deleteRequests)
		}
	}, outputFormat)
}

// DescribeBackupSpecInSF describes a backup spec in structured format.
func DescribeBackupSpecInSF(d *StructuredDescriber, spec velerov1api.BackupSpec) {
	backupSpecInfo := make(map[string]any)
	var s string

	// describe namespaces
	namespaceInfo := make(map[string]any)
	if len(spec.IncludedNamespaces) == 0 {
		s = "*"
	} else {
		s = strings.Join(spec.IncludedNamespaces, ", ")
	}
	namespaceInfo["included"] = s
	if len(spec.ExcludedNamespaces) == 0 {
		s = emptyDisplay
	} else {
		s = strings.Join(spec.ExcludedNamespaces, ", ")
	}
	namespaceInfo["excluded"] = s
	backupSpecInfo["namespaces"] = namespaceInfo

	// describe resources
	resourcesInfo := make(map[string]string)
	if len(spec.IncludedResources) == 0 {
		s = "*"
	} else {
		s = strings.Join(spec.IncludedResources, ", ")
	}
	resourcesInfo["included"] = s

	if len(spec.ExcludedResources) == 0 {
		s = emptyDisplay
	} else {
		s = strings.Join(spec.ExcludedResources, ", ")
	}
	resourcesInfo["excluded"] = s
	resourcesInfo["clusterScoped"] = BoolPointerString(spec.IncludeClusterResources, "excluded", "included", "auto")
	backupSpecInfo["resources"] = resourcesInfo

	// describe label selector
	s = emptyDisplay
	if spec.LabelSelector != nil {
		s = metav1.FormatLabelSelector(spec.LabelSelector)
	}
	backupSpecInfo["labelSelector"] = s

	// describe storage location
	backupSpecInfo["storageLocation"] = spec.StorageLocation

	// describe snapshot volumes
	backupSpecInfo["veleroNativeSnapshotPVs"] = BoolPointerString(spec.SnapshotVolumes, "false", "true", "auto")
	// describe snapshot move data
	backupSpecInfo["veleroSnapshotMoveData"] = BoolPointerString(spec.SnapshotMoveData, "false", "true", "auto")
	// describe data mover
	if len(spec.DataMover) == 0 {
		s = emptyDisplay
	} else {
		s = spec.DataMover
	}
	backupSpecInfo["dataMover"] = s

	// describe TTL
	backupSpecInfo["TTL"] = spec.TTL.Duration.String()

	// describe CSI snapshot timeout
	backupSpecInfo["CSISnapshotTimeout"] = spec.CSISnapshotTimeout.Duration.String()

	// describe hooks
	hooksInfo := make(map[string]any)
	hooksResources := make(map[string]any)
	for _, backupResourceHookSpec := range spec.Hooks.Resources {
		ResourceDetails := make(map[string]any)
		var s string
		namespaceInfo := make(map[string]string)
		if len(backupResourceHookSpec.IncludedNamespaces) == 0 {
			s = "*"
		} else {
			s = strings.Join(backupResourceHookSpec.IncludedNamespaces, ", ")
		}
		namespaceInfo["included"] = s
		if len(backupResourceHookSpec.ExcludedNamespaces) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(backupResourceHookSpec.ExcludedNamespaces, ", ")
		}
		namespaceInfo["excluded"] = s
		ResourceDetails["namespaces"] = namespaceInfo

		resourcesInfo := make(map[string]string)
		if len(backupResourceHookSpec.IncludedResources) == 0 {
			s = "*"
		} else {
			s = strings.Join(backupResourceHookSpec.IncludedResources, ", ")
		}
		resourcesInfo["included"] = s
		if len(backupResourceHookSpec.ExcludedResources) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(backupResourceHookSpec.ExcludedResources, ", ")
		}
		resourcesInfo["excluded"] = s
		ResourceDetails["resources"] = resourcesInfo

		s = emptyDisplay
		if backupResourceHookSpec.LabelSelector != nil {
			s = metav1.FormatLabelSelector(backupResourceHookSpec.LabelSelector)
		}
		ResourceDetails["labelSelector"] = s

		preHooks := make([]map[string]any, 0)
		for _, hook := range backupResourceHookSpec.PreHooks {
			if hook.Exec != nil {
				preExecHook := make(map[string]any)
				preExecHook["container"] = hook.Exec.Container
				preExecHook["command"] = strings.Join(hook.Exec.Command, " ")
				preExecHook["onError:"] = hook.Exec.OnError
				preExecHook["timeout"] = hook.Exec.Timeout.Duration.String()
				preHooks = append(preHooks, preExecHook)
			}
		}
		ResourceDetails["preExecHook"] = preHooks

		postHooks := make([]map[string]any, 0)
		for _, hook := range backupResourceHookSpec.PostHooks {
			if hook.Exec != nil {
				postExecHook := make(map[string]any)
				postExecHook["container"] = hook.Exec.Container
				postExecHook["command"] = strings.Join(hook.Exec.Command, " ")
				postExecHook["onError:"] = hook.Exec.OnError
				postExecHook["timeout"] = hook.Exec.Timeout.Duration.String()
				postHooks = append(postHooks, postExecHook)
			}
		}
		ResourceDetails["postExecHook"] = postHooks
		hooksResources[backupResourceHookSpec.Name] = ResourceDetails
	}
	if len(spec.Hooks.Resources) > 0 {
		hooksInfo["resources"] = hooksResources
		backupSpecInfo["hooks"] = hooksInfo
	}

	// desrcibe ordered resources
	if spec.OrderedResources != nil {
		backupSpecInfo["orderedResources"] = spec.OrderedResources
	}

	d.Describe("spec", backupSpecInfo)
}

// DescribeFineGrainedFilterPoliciesInSF adds the clusterScopedFilterPolicy
// and namespacedFilterPolicies sections to the structured describer output when present
// in the ResourcePolicy ConfigMap referenced by the backup.
func DescribeFineGrainedFilterPoliciesInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, backup *velerov1api.Backup) {
	if backup.Spec.ResourcePolicy == nil {
		return
	}

	discardLogger := logrus.New()
	discardLogger.Out = io.Discard

	resPolicies, err := resourcepolicies.GetResourcePoliciesFromBackup(*backup, kbClient, discardLogger)
	if err != nil || resPolicies == nil {
		return
	}

	clusterScopedFilterPolicy := resPolicies.GetClusterScopedFilterPolicy()
	if clusterScopedFilterPolicy != nil {
		var clusterScopedFilters []map[string]any
		for _, rf := range clusterScopedFilterPolicy.ResourceFilters {
			entry := map[string]any{
				"kinds": rf.Kinds,
			}
			if len(rf.LabelSelector) > 0 {
				entry["labelSelector"] = rf.LabelSelector
			}
			if len(rf.OrLabelSelectors) > 0 {
				entry["orLabelSelectors"] = rf.OrLabelSelectors
			}
			if len(rf.Names) > 0 {
				entry["names"] = rf.Names
			}
			if len(rf.ExcludedNames) > 0 {
				entry["excludedNames"] = rf.ExcludedNames
			}
			clusterScopedFilters = append(clusterScopedFilters, entry)
		}
		d.Describe("clusterScopedFilterPolicy", map[string]any{
			"resourceFilters": clusterScopedFilters,
		})
	}

	nfPolicies := resPolicies.GetNamespacedFilterPolicies()
	if len(nfPolicies) == 0 {
		return
	}

	var structuredPolicies []map[string]any
	for _, policy := range nfPolicies {
		for _, ns := range policy.Namespaces {
			var rfEntries []map[string]any
			for _, rf := range policy.ResourceFilters {
				entry := map[string]any{}
				if rf.IsCatchAll() {
					entry["kinds"] = []string{}
					entry["isCatchAll"] = true
				} else {
					entry["kinds"] = rf.Kinds
				}
				if len(rf.LabelSelector) > 0 {
					entry["labelSelector"] = rf.LabelSelector
				}
				if len(rf.OrLabelSelectors) > 0 {
					entry["orLabelSelectors"] = rf.OrLabelSelectors
				}
				if len(rf.Names) > 0 {
					entry["names"] = rf.Names
				}
				if len(rf.ExcludedNames) > 0 {
					entry["excludedNames"] = rf.ExcludedNames
				}
				rfEntries = append(rfEntries, entry)
			}
			structuredPolicies = append(structuredPolicies, map[string]any{
				"namespace":       ns,
				"resourceFilters": rfEntries,
			})
		}
	}
	d.Describe("namespacedFilterPolicies", structuredPolicies)
}

// DescribeBackupStatusInSF describes a backup status in structured format.
func DescribeBackupStatusInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, backup *velerov1api.Backup, details bool,
	insecureSkipTLSVerify bool, caCertPath string, podVolumeBackups []velerov1api.PodVolumeBackup) {
	status := backup.Status
	backupStatusInfo := make(map[string]any)

	// Status.Version has been deprecated, use Status.FormatVersion
	backupStatusInfo["backupFormatVersion"] = status.FormatVersion

	// "<n/a>" output should only be applicable for backups that failed validation
	if status.StartTimestamp == nil || status.StartTimestamp.Time.IsZero() {
		backupStatusInfo["started"] = "<n/a>"
	} else {
		backupStatusInfo["started"] = status.StartTimestamp.Time.String()
	}
	if status.CompletionTimestamp == nil || status.CompletionTimestamp.Time.IsZero() {
		backupStatusInfo["completed"] = "<n/a>"
	} else {
		backupStatusInfo["completed"] = status.CompletionTimestamp.Time.String()
	}

	// Expiration can't be 0, it is always set to a 30-day default. It can be nil
	// if the controller hasn't processed this Backup yet, in which case this will
	// just display `<nil>`, though this should be temporary.
	backupStatusInfo["expiration"] = status.Expiration.String()

	defer d.Describe("status", backupStatusInfo)

	if backup.Status.Progress != nil {
		if backup.Status.Phase == velerov1api.BackupPhaseInProgress {
			backupStatusInfo["estimatedTotalItemsToBeBackedUp"] = backup.Status.Progress.TotalItems
			backupStatusInfo["itemsBackedUpSoFar"] = backup.Status.Progress.ItemsBackedUp
		} else {
			backupStatusInfo["totalItemsToBeBackedUp"] = backup.Status.Progress.TotalItems
			backupStatusInfo["itemsBackedUp"] = backup.Status.Progress.ItemsBackedUp
		}
	}

	if details {
		describeBackupResourceListInSF(ctx, kbClient, backupStatusInfo, backup, insecureSkipTLSVerify, caCertPath)
	}

	describeBackupVolumesInSF(ctx, kbClient, backup, details, insecureSkipTLSVerify, caCertPath, podVolumeBackups, backupStatusInfo)

	if status.HookStatus != nil {
		backupStatusInfo["hooksAttempted"] = status.HookStatus.HooksAttempted
		backupStatusInfo["hooksFailed"] = status.HookStatus.HooksFailed
	}
}

func describeBackupResourceListInSF(ctx context.Context, kbClient kbclient.Client, backupStatusInfo map[string]any, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string) {
	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		backupStatusInfo["warningGettingBSLCACert"] = fmt.Sprintf("Warning: Error getting cacert from BSL: %v", err)
		bslCACert = ""
	}

	// In consideration of decoding structured output conveniently, the two separate fields were created here(in func describeBackupResourceList, there is only one field describing either error message or resource list)
	// the field of 'errorGettingResourceList' gives specific error message when it fails to get resources list
	// the field of 'resourceList' lists the rearranged resources
	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupResourceList, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		if err == downloadrequest.ErrNotFound {
			// the backup resource list could be missing if (other reasons may exist as well):
			//	- the backup was taken prior to v1.1; or
			//	- the backup hasn't completed yet; or
			//	- there was an error uploading the file; or
			//	- the file was manually deleted after upload
			backupStatusInfo["errorGettingResourceList"] = "<backup resource list not found>"
		} else {
			backupStatusInfo["errorGettingResourceList"] = fmt.Sprintf("<error getting backup resource list: %v>", err)
		}
		return
	}

	var resourceList map[string][]string
	if err := json.NewDecoder(buf).Decode(&resourceList); err != nil {
		backupStatusInfo["errorGettingResourceList"] = fmt.Sprintf("<error reading backup resource list: %v>\n", err)
		return
	}
	backupStatusInfo["resourceList"] = resourceList
}

func describeBackupVolumesInSF(ctx context.Context, kbClient kbclient.Client, backup *velerov1api.Backup, details bool,
	insecureSkipTLSVerify bool, caCertPath string, podVolumeBackupCRs []velerov1api.PodVolumeBackup, backupStatusInfo map[string]any) {
	backupVolumes := make(map[string]any)

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		backupVolumes["warningGettingBSLCACert"] = fmt.Sprintf("Warning: Error getting cacert from BSL: %v", err)
		bslCACert = ""
	}

	nativeSnapshots := []*volume.BackupVolumeInfo{}
	csiSnapshots := []*volume.BackupVolumeInfo{}
	legacyInfoSource := false

	buf := new(bytes.Buffer)
	err = downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupVolumeInfos, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert)
	if err == downloadrequest.ErrNotFound {
		nativeSnapshots, err = retrieveNativeSnapshotLegacy(ctx, kbClient, backup, insecureSkipTLSVerify, caCertPath, bslCACert)
		if err != nil {
			backupVolumes["errorConcludeNativeSnapshot"] = fmt.Sprintf("error concluding native snapshot info: %v", err)
			return
		}

		csiSnapshots, err = retrieveCSISnapshotLegacy(ctx, kbClient, backup, insecureSkipTLSVerify, caCertPath, bslCACert)
		if err != nil {
			backupVolumes["errorConcludeCSISnapshot"] = fmt.Sprintf("error concluding CSI snapshot info: %v", err)
			return
		}

		legacyInfoSource = true
	} else if err != nil {
		backupVolumes["errorGetBackupVolumeInfo"] = fmt.Sprintf("error getting backup volume info: %v", err)
		return
	} else {
		var volumeInfos []volume.BackupVolumeInfo
		if err := json.NewDecoder(buf).Decode(&volumeInfos); err != nil {
			backupVolumes["errorReadBackupVolumeInfo"] = fmt.Sprintf("error reading backup volume info: %v", err)
			return
		}

		for i := range volumeInfos {
			switch volumeInfos[i].BackupMethod {
			case volume.NativeSnapshot:
				nativeSnapshots = append(nativeSnapshots, &volumeInfos[i])
			case volume.CSISnapshot:
				csiSnapshots = append(csiSnapshots, &volumeInfos[i])
			}
		}
	}

	describeNativeSnapshotsInSF(details, nativeSnapshots, backupVolumes)

	describeCSISnapshotsInSF(details, csiSnapshots, backupVolumes, legacyInfoSource)

	describePodVolumeBackupsInSF(podVolumeBackupCRs, details, backupVolumes)

	backupStatusInfo["backupVolumes"] = backupVolumes
}

func describeNativeSnapshotsInSF(details bool, infos []*volume.BackupVolumeInfo, backupVolumes map[string]any) {
	if len(infos) == 0 {
		backupVolumes["nativeSnapshots"] = "<none included>"
		return
	}

	snapshotDetails := make(map[string]any)
	for _, info := range infos {
		describNativeSnapshotInSF(details, info, snapshotDetails)
	}
	backupVolumes["nativeSnapshots"] = snapshotDetails
}

func describNativeSnapshotInSF(details bool, info *volume.BackupVolumeInfo, snapshotDetails map[string]any) {
	if details {
		snapshotInfo := make(map[string]string)
		snapshotInfo["snapshotID"] = info.NativeSnapshotInfo.SnapshotHandle
		snapshotInfo["type"] = info.NativeSnapshotInfo.VolumeType
		snapshotInfo["availabilityZone"] = info.NativeSnapshotInfo.VolumeAZ
		snapshotInfo["IOPS"] = info.NativeSnapshotInfo.IOPS
		snapshotInfo["result"] = string(info.Result)

		snapshotDetails[info.PVName] = snapshotInfo
	} else {
		snapshotDetails[info.PVName] = "specify --details for more information"
	}
}

func describeCSISnapshotsInSF(details bool, infos []*volume.BackupVolumeInfo, backupVolumes map[string]any, legacyInfoSource bool) {
	if len(infos) == 0 {
		if legacyInfoSource {
			backupVolumes["csiSnapshots"] = "<none included or not detectable>"
		} else {
			backupVolumes["csiSnapshots"] = "<none included>"
		}
		return
	}

	snapshotDetails := make(map[string]any)
	for _, info := range infos {
		describeCSISnapshotInSF(details, info, snapshotDetails)
	}
	backupVolumes["csiSnapshots"] = snapshotDetails
}

func describeCSISnapshotInSF(details bool, info *volume.BackupVolumeInfo, snapshotDetails map[string]any) {
	snapshotDetail := make(map[string]any)

	describeLocalSnapshotInSF(details, info, snapshotDetail)
	describeDataMovementInSF(details, info, snapshotDetail)

	snapshotDetails[fmt.Sprintf("%s/%s", info.PVCNamespace, info.PVCName)] = snapshotDetail
}

// describeLocalSnapshotInSF describes CSI volume snapshot contents in structured format.
func describeLocalSnapshotInSF(details bool, info *volume.BackupVolumeInfo, snapshotDetail map[string]any) {
	if !info.PreserveLocalSnapshot {
		return
	}

	if details {
		localSnapshot := make(map[string]any)

		if !info.SnapshotDataMoved {
			localSnapshot["operationID"] = info.CSISnapshotInfo.OperationID
		}

		localSnapshot["snapshotContentName"] = info.CSISnapshotInfo.VSCName
		localSnapshot["storageSnapshotID"] = info.CSISnapshotInfo.SnapshotHandle
		localSnapshot["snapshotSize(bytes)"] = info.CSISnapshotInfo.Size
		localSnapshot["csiDriver"] = info.CSISnapshotInfo.Driver
		localSnapshot["result"] = string(info.Result)

		snapshotDetail["snapshot"] = localSnapshot
	} else {
		snapshotDetail["snapshot"] = "included, specify --details for more information"
	}
}

func describeDataMovementInSF(details bool, info *volume.BackupVolumeInfo, snapshotDetail map[string]any) {
	if !info.SnapshotDataMoved {
		return
	}

	if details {
		dataMovement := make(map[string]any)
		dataMovement["operationID"] = info.SnapshotDataMovementInfo.OperationID

		dataMover := "velero"
		if info.SnapshotDataMovementInfo.DataMover != "" {
			dataMover = info.SnapshotDataMovementInfo.DataMover
		}
		dataMovement["dataMover"] = dataMover

		dataMovement["uploaderType"] = info.SnapshotDataMovementInfo.UploaderType
		dataMovement["result"] = string(info.Result)
		if info.SnapshotDataMovementInfo.Size > 0 || info.SnapshotDataMovementInfo.IncrementalSize > 0 {
			dataMovement["size"] = info.SnapshotDataMovementInfo.Size
			dataMovement["incrementalSize"] = info.SnapshotDataMovementInfo.IncrementalSize
		}

		snapshotDetail["dataMovement"] = dataMovement
	} else {
		snapshotDetail["dataMovement"] = "included, specify --details for more information"
	}
}

// DescribeDeleteBackupRequestsInSF describes delete backup requests in structured format.
func DescribeDeleteBackupRequestsInSF(d *StructuredDescriber, requests []velerov1api.DeleteBackupRequest) {
	deletionAttempts := make(map[string]any)
	if count := failedDeletionCount(requests); count > 0 {
		deletionAttempts["failed"] = count
	}

	deletionRequests := make([]map[string]any, 0)
	for _, req := range requests {
		deletionReq := make(map[string]any)
		deletionReq["creationTimestamp"] = req.CreationTimestamp.String()
		deletionReq["phase"] = req.Status.Phase

		if len(req.Status.Errors) > 0 {
			deletionReq["errors"] = req.Status.Errors
		}
		deletionRequests = append(deletionRequests, deletionReq)
	}
	deletionAttempts["deleteBackupRequests"] = deletionRequests
	d.Describe("deletionAttempts", deletionAttempts)
}

// describePodVolumeBackupsInSF describes pod volume backups in structured format.
func describePodVolumeBackupsInSF(backups []velerov1api.PodVolumeBackup, details bool, backupVolumes map[string]any) {
	podVolumeBackupsInfo := make(map[string]any)
	// Get the type of pod volume uploader. Since the uploader only comes from a single source, we can
	// take the uploader type from the first element of the array.
	var uploaderType string
	if len(backups) > 0 {
		uploaderType = backups[0].Spec.UploaderType
	} else {
		backupVolumes["podVolumeBackups"] = "<none included>"
		return
	}
	// type display the type of pod volume backups
	podVolumeBackupsInfo["uploderType"] = uploaderType

	podVolumeBackupsDetails := make(map[string]any)
	// separate backups by phase (combining <none> and New into a single group)
	backupsByPhase := groupByPhase(backups)

	// go through phases in a specific order
	for _, phase := range []string{
		string(velerov1api.PodVolumeBackupPhaseCompleted),
		string(velerov1api.PodVolumeBackupPhaseFailed),
		string(velerov1api.PodVolumeBackupPhaseCanceled),
		"In Progress",
		string(velerov1api.PodVolumeBackupPhaseCanceling),
		string(velerov1api.PodVolumeBackupPhasePrepared),
		string(velerov1api.PodVolumeBackupPhaseAccepted),
		string(velerov1api.PodVolumeBackupPhaseNew),
	} {
		if len(backupsByPhase[phase]) == 0 {
			continue
		}
		// if we're not printing details, just report the phase and count
		if !details {
			podVolumeBackupsDetails[phase] = len(backupsByPhase[phase])
			continue
		}
		// group the backups in the current phase by pod (i.e. "ns/name")
		backupsByPod := new(volumesByPod)
		for _, backup := range backupsByPhase[phase] {
			backupsByPod.Add(backup.Spec.Pod.Namespace, backup.Spec.Pod.Name, backup.Spec.Volume, phase, backup.Status.Progress, backup.Status.IncrementalBytes)
		}

		backupsByPods := make([]map[string]string, 0)
		for _, backupGroup := range backupsByPod.volumesByPodSlice {
			// print volumes backed up for this pod
			backupsByPods = append(backupsByPods, map[string]string{backupGroup.label: strings.Join(backupGroup.volumes, ", ")})
		}
		podVolumeBackupsDetails[phase] = backupsByPods
	}
	// Pod Volume Backups Details display the detailed pod volume backups info
	podVolumeBackupsInfo["podVolumeBackupsDetails"] = podVolumeBackupsDetails
	backupVolumes["podVolumeBackups"] = podVolumeBackupsInfo
}

// DescribeBackupResultsInSF describes errors and warnings in structured format.
func DescribeBackupResultsInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string) {
	if backup.Status.Warnings == 0 && backup.Status.Errors == 0 {
		return
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		warnings := make(map[string]any)
		warnings["warningGettingBSLCACert"] = fmt.Sprintf("Warning: Error getting cacert from BSL: %v", err)
		d.Describe("warningsGettingBSLCACert", warnings)
		bslCACert = ""
	}

	var buf bytes.Buffer
	var resultMap map[string]results.Result

	errors, warnings := make(map[string]any), make(map[string]any)
	defer func() {
		d.Describe("errors", errors)
		d.Describe("warnings", warnings)
	}()

	// If 'ErrNotFound' occurs, it means the backup bundle in the bucket has already been there before the backup-result file is introduced.
	// We only display the count of errors and warnings in this case.
	err = downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupResults, &buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert)
	if err == downloadrequest.ErrNotFound {
		errors["count"] = backup.Status.Errors
		warnings["count"] = backup.Status.Warnings
		return
	} else if err != nil {
		errors["errorGettingErrors"] = fmt.Errorf("<error getting errors: %v>", err)
		warnings["errorGettingWarnings"] = fmt.Errorf("<error getting warnings: %v>", err)
		return
	}

	if err := json.NewDecoder(&buf).Decode(&resultMap); err != nil {
		errors["errorGettingErrors"] = fmt.Errorf("<error decoding errors: %v>", err)
		warnings["errorGettingWarnings"] = fmt.Errorf("<error decoding warnings: %v>", err)
		return
	}

	if backup.Status.Warnings > 0 {
		describeResultInSF(warnings, resultMap["warnings"])
	}
	if backup.Status.Errors > 0 {
		describeResultInSF(errors, resultMap["errors"])
	}
}

// DescribeResourcePoliciesInSF describes resource policies in structured format.
func DescribeResourcePoliciesInSF(d *StructuredDescriber, resPolicies *corev1api.TypedLocalObjectReference) {
	policiesInfo := make(map[string]any)
	policiesInfo["type"] = resPolicies.Kind
	policiesInfo["name"] = resPolicies.Name
	d.Describe("resourcePolicies", policiesInfo)
}

func describeResultInSF(m map[string]any, result results.Result) {
	m["velero"], m["cluster"], m["namespace"] = []string{}, []string{}, []string{}

	if len(result.Velero) > 0 {
		m["velero"] = result.Velero
	}
	if len(result.Cluster) > 0 {
		m["cluster"] = result.Cluster
	}
	if len(result.Namespaces) > 0 {
		m["namespace"] = result.Namespaces
	}
}
