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
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/vmware-tanzu/velero/internal/volume"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fatih/color"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

func DescribeRestore(
	ctx context.Context,
	kbClient kbclient.Client,
	restore *velerov1api.Restore,
	podVolumeRestores []velerov1api.PodVolumeRestore,
	details bool,
	insecureSkipTLSVerify bool,
	caCertFile string,
) string {
	return Describe(func(d *Describer) {
		d.DescribeMetadata(restore.ObjectMeta)

		d.Println()
		phase := restore.Status.Phase
		if phase == "" {
			phase = velerov1api.RestorePhaseNew
		}
		phaseString := string(phase)

		// Append "Deleting" to phaseString if deletionTimestamp is marked.
		if !restore.DeletionTimestamp.IsZero() {
			phaseString += " (Deleting)"
		}

		switch phase {
		case velerov1api.RestorePhaseCompleted:
			phaseString = color.GreenString(phaseString)
		case velerov1api.RestorePhaseFailedValidation, velerov1api.RestorePhasePartiallyFailed, velerov1api.RestorePhaseFailed:
			phaseString = color.RedString(phaseString)
		}

		resultsNote := ""
		if phase == velerov1api.RestorePhaseFailed || phase == velerov1api.RestorePhasePartiallyFailed {
			resultsNote = fmt.Sprintf(" (run 'velero restore logs %s' for more information)", restore.Name)
		}

		d.Printf("Phase:\t%s%s\n", phaseString, resultsNote)
		if restore.Status.Progress != nil {
			if restore.Status.Phase == velerov1api.RestorePhaseInProgress {
				d.Printf("Estimated total items to be restored:\t%d\n", restore.Status.Progress.TotalItems)
				d.Printf("Items restored so far:\t%d\n", restore.Status.Progress.ItemsRestored)
			} else {
				d.Printf("Total items to be restored:\t%d\n", restore.Status.Progress.TotalItems)
				d.Printf("Items restored:\t%d\n", restore.Status.Progress.ItemsRestored)
			}
		}

		d.Println()
		// "<n/a>" output should only be applicable for restore that failed validation
		if restore.Status.StartTimestamp == nil || restore.Status.StartTimestamp.IsZero() {
			d.Printf("Started:\t%s\n", "<n/a>")
		} else {
			d.Printf("Started:\t%s\n", restore.Status.StartTimestamp)
		}

		if restore.Status.CompletionTimestamp == nil || restore.Status.CompletionTimestamp.IsZero() {
			d.Printf("Completed:\t%s\n", "<n/a>")
		} else {
			d.Printf("Completed:\t%s\n", restore.Status.CompletionTimestamp)
		}

		if len(restore.Status.ValidationErrors) > 0 {
			d.Println()
			d.Printf("Validation errors:")
			for _, ve := range restore.Status.ValidationErrors {
				d.Printf("\t%s\n", color.RedString(ve))
			}
		}

		describeRestoreResults(ctx, kbClient, d, restore, insecureSkipTLSVerify, caCertFile)

		d.Println()
		d.Printf("Backup:\t%s\n", restore.Spec.BackupName)

		d.Println()
		d.Printf("Namespaces:\n")
		var s string
		if len(restore.Spec.IncludedNamespaces) == 0 {
			s = "all namespaces found in the backup"
		} else if len(restore.Spec.IncludedNamespaces) == 1 && restore.Spec.IncludedNamespaces[0] == "*" {
			s = "all namespaces found in the backup"
		} else {
			s = strings.Join(restore.Spec.IncludedNamespaces, ", ")
		}
		d.Printf("\tIncluded:\t%s\n", s)
		if len(restore.Spec.ExcludedNamespaces) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(restore.Spec.ExcludedNamespaces, ", ")
		}
		d.Printf("\tExcluded:\t%s\n", s)

		d.Println()
		d.Printf("Resources:\n")
		if len(restore.Spec.IncludedResources) == 0 {
			s = "*"
		} else {
			s = strings.Join(restore.Spec.IncludedResources, ", ")
		}
		d.Printf("\tIncluded:\t%s\n", s)
		if len(restore.Spec.ExcludedResources) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(restore.Spec.ExcludedResources, ", ")
		}
		d.Printf("\tExcluded:\t%s\n", s)

		d.Printf("\tCluster-scoped:\t%s\n", BoolPointerString(restore.Spec.IncludeClusterResources, "excluded", "included", "auto"))

		d.Println()
		d.DescribeMap("Namespace mappings", restore.Spec.NamespaceMapping)

		d.Println()
		s = emptyDisplay
		if restore.Spec.LabelSelector != nil {
			s = metav1.FormatLabelSelector(restore.Spec.LabelSelector)
		}
		d.Printf("Label selector:\t%s\n", s)

		d.Println()
		if len(restore.Spec.OrLabelSelectors) == 0 {
			s = emptyDisplay
		} else {
			orLabelSelectors := []string{}
			for _, v := range restore.Spec.OrLabelSelectors {
				orLabelSelectors = append(orLabelSelectors, metav1.FormatLabelSelector(v))
			}
			s = strings.Join(orLabelSelectors, " or ")
		}
		d.Printf("Or label selector:\t%s\n", s)

		d.Println()
		d.Printf("Restore PVs:\t%s\n", BoolPointerString(restore.Spec.RestorePVs, "false", "true", "auto"))

		if len(podVolumeRestores) > 0 {
			d.Println()
			describePodVolumeRestores(d, podVolumeRestores, details)
		}

		// Get BSL cacert if available
		bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
		if err != nil {
			// Log the error but don't fail - we can still try to download without the BSL cacert
			d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
			bslCACert = ""
		}

		buf := new(bytes.Buffer)
		if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreVolumeInfo,
			buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertFile, bslCACert); err == nil {
			var restoreVolInfo []volume.RestoreVolumeInfo
			if err := json.NewDecoder(buf).Decode(&restoreVolInfo); err != nil {
				d.Printf("\t<error reading restore volume info: %v>\n", err)
			} else {
				describeCSISnapshotsRestores(d, restoreVolInfo, details)
			}
		} else if err != nil && !errors.Is(err, downloadrequest.ErrNotFound) {
			// For the restores by older versions of velero, it will see NotFound Error when downloading the volume info.
			// In that case, no errors will be printed.
			d.Printf("\t<error getting restore volume info: %v>\n", err)
		}

		d.Println()
		s = emptyDisplay
		if restore.Spec.ExistingResourcePolicy != "" {
			s = string(restore.Spec.ExistingResourcePolicy)
		}
		d.Printf("Existing Resource Policy: \t%s\n", s)
		d.Printf("ItemOperationTimeout:\t%s\n", restore.Spec.ItemOperationTimeout.Duration)

		d.Println()
		d.Printf("Preserve Service NodePorts:\t%s\n", BoolPointerString(restore.Spec.PreserveNodePorts, "false", "true", "auto"))

		if restore.Spec.ResourceModifier != nil {
			d.Println()
			DescribeResourceModifier(d, restore.Spec.ResourceModifier)
		}

		if restore.Spec.ResourcePolicy != nil {
			d.Println()
			DescribeResourcePolicies(d, restore.Spec.ResourcePolicy)
		}

		describeUploaderConfigForRestore(d, restore.Spec)

		d.Println()
		describeRestoreItemOperations(ctx, kbClient, d, restore, details, insecureSkipTLSVerify, caCertFile)

		if restore.Status.HookStatus != nil {
			d.Println()
			d.Printf("HooksAttempted: \t%d\n", restore.Status.HookStatus.HooksAttempted)
			d.Printf("HooksFailed: \t%d\n", restore.Status.HookStatus.HooksFailed)
		}

		if details {
			d.Println()
			describeRestoreResourceList(ctx, kbClient, d, restore, insecureSkipTLSVerify, caCertFile)
		}
	})
}

// describeUploaderConfigForRestore describes uploader config in human-readable format
func describeUploaderConfigForRestore(d *Describer, spec velerov1api.RestoreSpec) {
	if spec.UploaderConfig != nil {
		d.Println()
		d.Printf("Uploader config:\n")
		if boolptr.IsSetToTrue(spec.UploaderConfig.WriteSparseFiles) {
			d.Printf("\tWrite Sparse Files:\t%v\n", boolptr.IsSetToTrue(spec.UploaderConfig.WriteSparseFiles))
		}
		if spec.UploaderConfig.ParallelFilesDownload > 0 {
			d.Printf("\tParallel Restore:\t%d\n", spec.UploaderConfig.ParallelFilesDownload)
		}
	}
}

func describeRestoreItemOperations(ctx context.Context, kbClient kbclient.Client, d *Describer, restore *velerov1api.Restore, details bool, insecureSkipTLSVerify bool, caCertPath string) {
	status := restore.Status
	if status.RestoreItemOperationsAttempted > 0 {
		if !details {
			d.Printf("Restore Item Operations:\t%d of %d completed successfully, %d failed (specify --details for more information)\n", status.RestoreItemOperationsCompleted, status.RestoreItemOperationsAttempted, status.RestoreItemOperationsFailed)
			return
		}

		// Get BSL cacert if available
		bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
		if err != nil {
			// Log the error but don't fail - we can still try to download without the BSL cacert
			d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
			bslCACert = ""
		}

		buf := new(bytes.Buffer)
		if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreItemOperations, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
			d.Printf("Restore Item Operations:\t<error getting operation info: %v>\n", err)
			return
		}

		var operations []*itemoperation.RestoreOperation
		if err := json.NewDecoder(buf).Decode(&operations); err != nil {
			d.Printf("Restore Item Operations:\t<error reading operation info: %v>\n", err)
			return
		}

		d.Printf("Restore Item Operations:\n")
		for _, operation := range operations {
			describeRestoreItemOperation(d, operation)
		}
	}
}

func describeRestoreResults(ctx context.Context, kbClient kbclient.Client, d *Describer, restore *velerov1api.Restore, insecureSkipTLSVerify bool, caCertPath string) {
	if restore.Status.Warnings == 0 && restore.Status.Errors == 0 {
		return
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	var buf bytes.Buffer
	var resultMap map[string]results.Result

	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreResults, &buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		d.Printf("Warnings:\t<error getting warnings: %v>\n\nErrors:\t<error getting errors: %v>\n", err, err)
		return
	}

	if err := json.NewDecoder(&buf).Decode(&resultMap); err != nil {
		d.Printf("Warnings:\t<error decoding warnings: %v>\n\nErrors:\t<error decoding errors: %v>\n", err, err)
		return
	}

	if restore.Status.Warnings > 0 {
		d.Println()
		describeResult(d, "Warnings", resultMap["warnings"])
	}
	if restore.Status.Errors > 0 {
		d.Println()
		describeResult(d, "Errors", resultMap["errors"])
	}
}

func describeResult(d *Describer, name string, result results.Result) {
	d.Printf("%s:\n", name)
	d.DescribeSlice(1, "Velero", result.Velero)
	d.DescribeSlice(1, "Cluster", result.Cluster)
	if len(result.Namespaces) == 0 {
		d.Printf("\tNamespaces: <none>\n")
	} else {
		d.Printf("\tNamespaces:\n")
		for ns, warnings := range result.Namespaces {
			d.DescribeSlice(2, ns, warnings)
		}
	}
}

func describeRestoreItemOperation(d *Describer, operation *itemoperation.RestoreOperation) {
	d.Printf("\tOperation for %s %s/%s:\n", operation.Spec.ResourceIdentifier, operation.Spec.ResourceIdentifier.Namespace, operation.Spec.ResourceIdentifier.Name)
	d.Printf("\t\tRestore Item Action Plugin:\t%s\n", operation.Spec.RestoreItemAction)
	d.Printf("\t\tOperation ID:\t%s\n", operation.Spec.OperationID)
	d.Printf("\t\tPhase:\t%s\n", operation.Status.Phase)
	if operation.Status.Error != "" {
		d.Printf("\t\tOperation Error:\t%s\n", operation.Status.Error)
	}
	if operation.Status.NTotal > 0 || operation.Status.NCompleted > 0 {
		d.Printf("\t\tProgress:\t%v of %v complete (%s)\n",
			operation.Status.NCompleted,
			operation.Status.NTotal,
			operation.Status.OperationUnits)
	}
	if operation.Status.Description != "" {
		d.Printf("\t\tProgress description:\t%s\n", operation.Status.Description)
	}
	if operation.Status.Created != nil {
		d.Printf("\t\tCreated:\t%s\n", operation.Status.Created.String())
	}
	if operation.Status.Started != nil {
		d.Printf("\t\tStarted:\t%s\n", operation.Status.Started.String())
	}
	if operation.Status.Updated != nil {
		d.Printf("\t\tUpdated:\t%s\n", operation.Status.Updated.String())
	}
}

// describePodVolumeRestores describes pod volume restores in human-readable format.
func describePodVolumeRestores(d *Describer, restores []velerov1api.PodVolumeRestore, details bool) {
	// Get the type of pod volume uploader. Since the uploader only comes from a single source, we can
	// take the uploader type from the first element of the array.
	var uploaderType string
	if len(restores) > 0 {
		uploaderType = restores[0].Spec.UploaderType
	} else {
		return
	}

	if details {
		d.Printf("%s Restores:\n", uploaderType)
	} else {
		d.Printf("%s Restores (specify --details for more information):\n", uploaderType)
	}

	// separate restores by phase (combining <none> and New into a single group)
	restoresByPhase := groupRestoresByPhase(restores)

	// go through phases in a specific order
	for _, phase := range []string{
		string(velerov1api.PodVolumeRestorePhaseCompleted),
		string(velerov1api.PodVolumeRestorePhaseCanceled),
		string(velerov1api.PodVolumeRestorePhaseFailed),
		"In Progress",
		string(velerov1api.PodVolumeRestorePhasePrepared),
		string(velerov1api.PodVolumeRestorePhaseAccepted),
		string(velerov1api.PodVolumeRestorePhaseNew),
	} {
		if len(restoresByPhase[phase]) == 0 {
			continue
		}

		// if we're not printing details, just report the phase and count
		if !details {
			d.Printf("\t%s:\t%d\n", phase, len(restoresByPhase[phase]))
			continue
		}

		// group the restores in the current phase by pod (i.e. "ns/name")
		restoresByPod := new(volumesByPod)

		for _, restore := range restoresByPhase[phase] {
			restoresByPod.Add(restore.Spec.Pod.Namespace, restore.Spec.Pod.Name, restore.Spec.Volume, phase, restore.Status.Progress, 0)
		}

		d.Printf("\t%s:\n", phase)
		for _, restoreGroup := range restoresByPod.Sorted() {
			sort.Strings(restoreGroup.volumes)

			// print volumes restored up for this pod
			d.Printf("\t\t%s: %s\n", restoreGroup.label, strings.Join(restoreGroup.volumes, ", "))
		}
	}
}

// describeCSISnapshotsRestores describes PVC restored via CSISnapshots, incl. data-movement, in human-readable format.
func describeCSISnapshotsRestores(d *Describer, restoreVolInfo []volume.RestoreVolumeInfo, details bool) {
	d.Println()
	var nonDMInfoList, dmInfoList []volume.RestoreVolumeInfo
	for _, info := range restoreVolInfo {
		if info.RestoreMethod != volume.CSISnapshot {
			continue
		}
		if info.SnapshotDataMoved {
			dmInfoList = append(dmInfoList, info)
		} else {
			nonDMInfoList = append(nonDMInfoList, info)
		}
	}
	if len(nonDMInfoList) == 0 && len(dmInfoList) == 0 {
		d.Printf("CSI Snapshot Restores: <none included>\n")
		return
	}
	d.Printf("CSI Snapshot Restores:\n")
	for _, info := range nonDMInfoList {
		// All CSI snapshots are restored via PVC
		d.Printf("\t%s/%s:\n", info.PVCNamespace, info.PVCName)
		if details {
			d.Printf("\t\tSnapshot:\n")
			d.Printf("\t\t\tSnapshot Content Name: %s\n", info.CSISnapshotInfo.VSCName)
			d.Printf("\t\t\tStorage Snapshot ID: %s\n", info.CSISnapshotInfo.SnapshotHandle)
			d.Printf("\t\t\tCSI Driver: %s\n", info.CSISnapshotInfo.Driver)
		} else {
			d.Printf("\t\tSnapshot: specify --details for more information\n")
		}
	}
	for _, info := range dmInfoList {
		d.Printf("\t%s/%s:\n", info.PVCNamespace, info.PVCName)
		if details {
			d.Printf("\t\tData Movement:\n")
			d.Printf("\t\t\tOperation ID: %s\n", info.SnapshotDataMovementInfo.OperationID)
			d.Printf("\t\t\tData Mover: %s\n", info.SnapshotDataMovementInfo.DataMover)
			d.Printf("\t\t\tUploader Type: %s\n", info.SnapshotDataMovementInfo.UploaderType)
		} else {
			d.Printf("\t\tData Movement: specify --details for more information\n")
		}
	}
}

func groupRestoresByPhase(restores []velerov1api.PodVolumeRestore) map[string][]velerov1api.PodVolumeRestore {
	restoresByPhase := make(map[string][]velerov1api.PodVolumeRestore)

	phaseToGroup := map[velerov1api.PodVolumeRestorePhase]string{
		velerov1api.PodVolumeRestorePhaseCompleted:  string(velerov1api.PodVolumeRestorePhaseCompleted),
		velerov1api.PodVolumeRestorePhaseCanceled:   string(velerov1api.PodVolumeRestorePhaseCanceled),
		velerov1api.PodVolumeRestorePhaseFailed:     string(velerov1api.PodVolumeRestorePhaseFailed),
		velerov1api.PodVolumeRestorePhaseInProgress: "In Progress",
		velerov1api.PodVolumeRestorePhasePrepared:   string(velerov1api.PodVolumeRestorePhasePrepared),
		velerov1api.PodVolumeRestorePhaseAccepted:   string(velerov1api.PodVolumeRestorePhaseAccepted),
		velerov1api.PodVolumeRestorePhaseNew:        string(velerov1api.PodVolumeRestorePhaseNew),
		"":                                          string(velerov1api.PodVolumeRestorePhaseNew),
	}

	for _, restore := range restores {
		group := phaseToGroup[restore.Status.Phase]
		restoresByPhase[group] = append(restoresByPhase[group], restore)
	}

	return restoresByPhase
}

func describeRestoreResourceList(ctx context.Context, kbClient kbclient.Client, d *Describer, restore *velerov1api.Restore, insecureSkipTLSVerify bool, caCertPath string) {
	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreResourceList, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		if err == downloadrequest.ErrNotFound {
			d.Println("Resource List:\t<restore resource list not found>")
		} else {
			d.Printf("Resource List:\t<error getting restore resource list: %v>\n", err)
		}
		return
	}

	var resourceList map[string][]string
	if err := json.NewDecoder(buf).Decode(&resourceList); err != nil {
		d.Printf("Resource List:\t<error reading restore resource list: %v>\n", err)
		return
	}

	d.Println("Resource List:")

	// Sort GVKs in output
	gvks := make([]string, 0, len(resourceList))
	for gvk := range resourceList {
		gvks = append(gvks, gvk)
	}
	sort.Strings(gvks)

	for _, gvk := range gvks {
		d.Printf("\t%s:\n\t\t- %s\n", gvk, strings.Join(resourceList[gvk], "\n\t\t- "))
	}
}

// DescribeResourceModifier describes resource policies in human-readable format
func DescribeResourceModifier(d *Describer, resModifier *corev1api.TypedLocalObjectReference) {
	d.Printf("Resource modifier:\n")
	d.Printf("\tType:\t%s\n", resModifier.Kind)
	d.Printf("\tName:\t%s\n", resModifier.Name)
}
