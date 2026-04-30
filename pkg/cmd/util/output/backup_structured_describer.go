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
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"

	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/util/results"
	"github.com/vmware-tanzu/velero/pkg/volume"
)

// DescribeBackupInSF describes a backup in structured format.
func DescribeBackupInSF(
	ctx context.Context,
	kbClient kbclient.Client,
	backup *velerov1api.Backup,
	deleteRequests []velerov1api.DeleteBackupRequest,
	podVolumeBackups []velerov1api.PodVolumeBackup,
	volumeSnapshotContents []snapshotv1api.VolumeSnapshotContent,
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
		}

		status := backup.Status
		if len(status.ValidationErrors) > 0 {
			d.Describe("validationErrors", status.ValidationErrors)
		}

		DescribeBackupResultsInSF(ctx, kbClient, d, backup, insecureSkipTLSVerify, caCertFile)

		DescribeBackupSpecInSF(d, backup.Spec)

		DescribeBackupStatusInSF(ctx, kbClient, d, backup, details, insecureSkipTLSVerify, caCertFile)

		if len(deleteRequests) > 0 {
			DescribeDeleteBackupRequestsInSF(d, deleteRequests)
		}

		if features.IsEnabled(velerov1api.CSIFeatureFlag) {
			DescribeCSIVolumeSnapshotsInSF(d, details, volumeSnapshotContents)
		}

		if len(podVolumeBackups) > 0 {
			DescribePodVolumeBackupsInSF(d, podVolumeBackups, details)
		}
	}, outputFormat)
}

// DescribeBackupSpecInSF describes a backup spec in structured format.
func DescribeBackupSpecInSF(d *StructuredDescriber, spec velerov1api.BackupSpec) {
	backupSpecInfo := make(map[string]interface{})
	var s string

	// describe namespaces
	namespaceInfo := make(map[string]interface{})
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
	hooksInfo := make(map[string]interface{})
	hooksResources := make(map[string]interface{})
	for _, backupResourceHookSpec := range spec.Hooks.Resources {
		ResourceDetails := make(map[string]interface{})
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

		preHooks := make([]map[string]interface{}, 0)
		for _, hook := range backupResourceHookSpec.PreHooks {
			if hook.Exec != nil {
				preExecHook := make(map[string]interface{})
				preExecHook["container"] = hook.Exec.Container
				preExecHook["command"] = strings.Join(hook.Exec.Command, " ")
				preExecHook["onError:"] = hook.Exec.OnError
				preExecHook["timeout"] = hook.Exec.Timeout.Duration.String()
				preHooks = append(preHooks, preExecHook)
			}
		}
		ResourceDetails["preExecHook"] = preHooks

		postHooks := make([]map[string]interface{}, 0)
		for _, hook := range backupResourceHookSpec.PostHooks {
			if hook.Exec != nil {
				postExecHook := make(map[string]interface{})
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

// DescribeBackupStatusInSF describes a backup status in structured format.
func DescribeBackupStatusInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, backup *velerov1api.Backup, details bool, insecureSkipTLSVerify bool, caCertPath string) {
	status := backup.Status
	backupStatusInfo := make(map[string]interface{})

	// Status.Version has been deprecated, use Status.FormatVersion
	backupStatusInfo["backupFormatVersion"] = status.FormatVersion

	// "<n/a>" output should only be applicable for backups that failed validation
	if status.StartTimestamp == nil || status.StartTimestamp.Time.IsZero() {
		backupStatusInfo["started"] = "<n/a>"
	} else {
		backupStatusInfo["started"] = status.StartTimestamp.String()
	}
	if status.CompletionTimestamp == nil || status.CompletionTimestamp.Time.IsZero() {
		backupStatusInfo["completed"] = "<n/a>"
	} else {
		backupStatusInfo["completed"] = status.CompletionTimestamp.String()
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

	// In consideration of decoding structured output conveniently, the three separate fields were created here
	// the field of "veleroNativeSnapshots" displays the brief snapshots info
	// the field of "errorGettingSnapshots" displays the error message if it fails to get snapshot info
	// the field of "veleroNativeSnapshotsDetail" displays the detailed snapshots info
	if status.VolumeSnapshotsAttempted > 0 {
		if !details {
			backupStatusInfo["veleroNativeSnapshots"] = fmt.Sprintf("%d of %d snapshots completed successfully", status.VolumeSnapshotsCompleted, status.VolumeSnapshotsAttempted)
			return
		}

		buf := new(bytes.Buffer)
		if err := downloadrequest.Stream(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupVolumeSnapshots, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath); err != nil {
			backupStatusInfo["errorGettingSnapshots"] = fmt.Sprintf("<error getting snapshot info: %v>", err)
			return
		}

		var snapshots []*volume.Snapshot
		if err := json.NewDecoder(buf).Decode(&snapshots); err != nil {
			backupStatusInfo["errorGettingSnapshots"] = fmt.Sprintf("<error reading snapshot info: %v>", err)
			return
		}

		snapshotDetails := make(map[string]interface{})
		for _, snap := range snapshots {
			describeSnapshotInSF(snap.Spec.PersistentVolumeName, snap.Status.ProviderSnapshotID, snap.Spec.VolumeType, snap.Spec.VolumeAZ, snap.Spec.VolumeIOPS, snapshotDetails)
		}
		backupStatusInfo["veleroNativeSnapshotsDetail"] = snapshotDetails
		return
	}
}

func describeBackupResourceListInSF(ctx context.Context, kbClient kbclient.Client, backupStatusInfo map[string]interface{}, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string) {
	// In consideration of decoding structured output conveniently, the two separate fields were created here(in func describeBackupResourceList, there is only one field describing either error message or resource list)
	// the field of 'errorGettingResourceList' gives specific error message when it fails to get resources list
	// the field of 'resourceList' lists the rearranged resources
	buf := new(bytes.Buffer)
	if err := downloadrequest.Stream(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupResourceList, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath); err != nil {
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

func describeSnapshotInSF(pvName, snapshotID, volumeType, volumeAZ string, iops *int64, snapshotDetails map[string]interface{}) {
	snapshotInfo := make(map[string]string)
	iopsString := "<N/A>"
	if iops != nil {
		iopsString = fmt.Sprintf("%d", *iops)
	}

	snapshotInfo["snapshotID"] = snapshotID
	snapshotInfo["type"] = volumeType
	snapshotInfo["availabilityZone"] = volumeAZ
	snapshotInfo["IOPS"] = iopsString
	snapshotDetails[pvName] = snapshotInfo
}

// DescribeDeleteBackupRequestsInSF describes delete backup requests in structured format.
func DescribeDeleteBackupRequestsInSF(d *StructuredDescriber, requests []velerov1api.DeleteBackupRequest) {
	deletionAttempts := make(map[string]interface{})
	if count := failedDeletionCount(requests); count > 0 {
		deletionAttempts["failed"] = count
	}

	deletionRequests := make([]map[string]interface{}, 0)
	for _, req := range requests {
		deletionReq := make(map[string]interface{})
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

// DescribePodVolumeBackupsInSF describes pod volume backups in structured format.
func DescribePodVolumeBackupsInSF(d *StructuredDescriber, backups []velerov1api.PodVolumeBackup, details bool) {
	PodVolumeBackupsInfo := make(map[string]interface{})
	// Get the type of pod volume uploader. Since the uploader only comes from a single source, we can
	// take the uploader type from the first element of the array.
	var uploaderType string
	if len(backups) > 0 {
		uploaderType = backups[0].Spec.UploaderType
	} else {
		return
	}
	// type display the type of pod volume backups
	PodVolumeBackupsInfo["type"] = uploaderType

	podVolumeBackupsDetails := make(map[string]interface{})
	// separate backups by phase (combining <none> and New into a single group)
	backupsByPhase := groupByPhase(backups)

	// go through phases in a specific order
	for _, phase := range []string{
		string(velerov1api.PodVolumeBackupPhaseCompleted),
		string(velerov1api.PodVolumeBackupPhaseFailed),
		"In Progress",
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
			backupsByPod.Add(backup.Spec.Pod.Namespace, backup.Spec.Pod.Name, backup.Spec.Volume, phase, backup.Status.Progress)
		}

		backupsByPods := make([]map[string]string, 0)
		for _, backupGroup := range backupsByPod.volumesByPodSlice {
			// print volumes backed up for this pod
			backupsByPods = append(backupsByPods, map[string]string{backupGroup.label: strings.Join(backupGroup.volumes, ", ")})
		}
		podVolumeBackupsDetails[phase] = backupsByPods
	}
	// Pod Volume Backups Details display the detailed pod volume backups info
	PodVolumeBackupsInfo["podVolumeBackupsDetails"] = podVolumeBackupsDetails
	d.Describe("podVolumeBackups", PodVolumeBackupsInfo)
}

// DescribeCSIVolumeSnapshotsInSF describes CSI volume snapshots in structured format.
func DescribeCSIVolumeSnapshotsInSF(d *StructuredDescriber, details bool, volumeSnapshotContents []snapshotv1api.VolumeSnapshotContent) {
	CSIVolumeSnapshotsInfo := make(map[string]interface{})
	if !features.IsEnabled(velerov1api.CSIFeatureFlag) {
		return
	}

	if len(volumeSnapshotContents) == 0 {
		return
	}

	// In consideration of decoding structured output conveniently, the two separate fields were created here
	// the field of 'CSI Volume Snapshots Count' displays the count of CSI Volume Snapshots
	// the field of 'CSI Volume Snapshots Details' displays the content of CSI Volume Snapshots
	if !details {
		CSIVolumeSnapshotsInfo["CSIVolumeSnapshotsCount"] = len(volumeSnapshotContents)
	} else {
		vscDetails := make(map[string]interface{})
		for _, vsc := range volumeSnapshotContents {
			DescribeVSCInSF(details, vsc, vscDetails)
		}
		CSIVolumeSnapshotsInfo["CSIVolumeSnapshotsDetails"] = vscDetails
	}
	d.Describe("CSIVolumeSnapshots", CSIVolumeSnapshotsInfo)
}

// DescribeVSCInSF describes CSI volume snapshot contents in structured format.
func DescribeVSCInSF(details bool, vsc snapshotv1api.VolumeSnapshotContent, vscDetails map[string]interface{}) {
	content := make(map[string]interface{})
	if vsc.Status == nil {
		vscDetails[vsc.Name] = content
		return
	}

	if vsc.Status.SnapshotHandle != nil {
		content["storageSnapshotID"] = *vsc.Status.SnapshotHandle
	}

	if vsc.Status.RestoreSize != nil {
		content["snapshotSize(bytes)"] = *vsc.Status.RestoreSize
	}

	if vsc.Status.ReadyToUse != nil {
		content["readyToUse"] = *vsc.Status.ReadyToUse
	}
	vscDetails[vsc.Name] = content
}

// DescribeBackupResultsInSF describes errors and warnings in structured format.
func DescribeBackupResultsInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string) {
	if backup.Status.Warnings == 0 && backup.Status.Errors == 0 {
		return
	}

	var buf bytes.Buffer
	var resultMap map[string]results.Result

	errors, warnings := make(map[string]interface{}), make(map[string]interface{})
	defer func() {
		d.Describe("errors", errors)
		d.Describe("warnings", warnings)
	}()

	// If 'ErrNotFound' occurs, it means the backup bundle in the bucket has already been there before the backup-result file is introduced.
	// We only display the count of errors and warnings in this case.
	err := downloadrequest.Stream(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupResults, &buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath)
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
func DescribeResourcePoliciesInSF(d *StructuredDescriber, resPolicies *v1.TypedLocalObjectReference) {
	policiesInfo := make(map[string]interface{})
	policiesInfo["type"] = resPolicies.Kind
	policiesInfo["name"] = resPolicies.Name
	d.Describe("resourcePolicies", policiesInfo)
}

func describeResultInSF(m map[string]interface{}, result results.Result) {
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
