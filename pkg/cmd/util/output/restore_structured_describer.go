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
	"strings"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

// DescribeRestoreInSF describes a restore in structured format.
func DescribeRestoreInSF(
	ctx context.Context,
	kbClient kbclient.Client,
	restore *velerov1api.Restore,
	podVolumeRestores []velerov1api.PodVolumeRestore,
	details bool,
	insecureSkipTLSVerify bool,
	caCertFile string,
	outputFormat string,
) string {
	return DescribeInSF(func(d *StructuredDescriber) {
		d.DescribeMetadata(restore.ObjectMeta)

		phase := restore.Status.Phase
		if phase == "" {
			phase = velerov1api.RestorePhaseNew
		}
		phaseString := string(phase)
		if !restore.DeletionTimestamp.IsZero() {
			phaseString += " (Deleting)"
		}
		d.Describe("phase", phaseString)

		describeRestoreProgressInSF(d, restore)
		describeRestoreTimestampsInSF(d, restore)

		if len(restore.Status.ValidationErrors) > 0 {
			d.Describe("validationErrors", restore.Status.ValidationErrors)
		}

		describeRestoreResultsInSF(ctx, kbClient, d, restore, insecureSkipTLSVerify, caCertFile)

		describeRestoreSpecInSF(d, restore.Spec)

		describePodVolumeRestoresInSF(d, podVolumeRestores, details)

		describeRestoreCSISnapshotsInSF(ctx, kbClient, d, restore, details, insecureSkipTLSVerify, caCertFile)

		describeRestoreItemOperationsInSF(ctx, kbClient, d, restore, details, insecureSkipTLSVerify, caCertFile)

		if restore.Status.HookStatus != nil {
			hookStatus := map[string]any{
				"hooksAttempted": restore.Status.HookStatus.HooksAttempted,
				"hooksFailed":    restore.Status.HookStatus.HooksFailed,
			}
			d.Describe("hookStatus", hookStatus)
		}

		if details {
			describeRestoreResourceListInSF(ctx, kbClient, d, restore, insecureSkipTLSVerify, caCertFile)
		}
	}, outputFormat)
}

func describeRestoreProgressInSF(d *StructuredDescriber, restore *velerov1api.Restore) {
	if restore.Status.Progress == nil {
		return
	}
	progress := map[string]any{}
	if restore.Status.Phase == velerov1api.RestorePhaseInProgress {
		progress["estimatedTotalItemsToBeRestored"] = restore.Status.Progress.TotalItems
		progress["itemsRestoredSoFar"] = restore.Status.Progress.ItemsRestored
	} else {
		progress["totalItemsToBeRestored"] = restore.Status.Progress.TotalItems
		progress["itemsRestored"] = restore.Status.Progress.ItemsRestored
	}
	d.Describe("progress", progress)
}

func describeRestoreTimestampsInSF(d *StructuredDescriber, restore *velerov1api.Restore) {
	timestamps := map[string]any{}
	if restore.Status.StartTimestamp == nil || restore.Status.StartTimestamp.IsZero() {
		timestamps["started"] = "<n/a>"
	} else {
		timestamps["started"] = restore.Status.StartTimestamp.String()
	}
	if restore.Status.CompletionTimestamp == nil || restore.Status.CompletionTimestamp.IsZero() {
		timestamps["completed"] = "<n/a>"
	} else {
		timestamps["completed"] = restore.Status.CompletionTimestamp.String()
	}
	d.Describe("timestamps", timestamps)
}

func describeRestoreSpecInSF(d *StructuredDescriber, spec velerov1api.RestoreSpec) {
	specInfo := map[string]any{}

	specInfo["backupName"] = spec.BackupName

	// namespaces
	namespaceInfo := map[string]any{}
	var s string
	if len(spec.IncludedNamespaces) == 0 || (len(spec.IncludedNamespaces) == 1 && spec.IncludedNamespaces[0] == "*") {
		s = "all namespaces found in the backup"
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
	specInfo["namespaces"] = namespaceInfo

	// resources
	resourcesInfo := map[string]string{}
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
	specInfo["resources"] = resourcesInfo

	// namespace mappings
	if len(spec.NamespaceMapping) > 0 {
		specInfo["namespaceMappings"] = spec.NamespaceMapping
	} else {
		specInfo["namespaceMappings"] = emptyDisplay
	}

	// label selector
	s = emptyDisplay
	if spec.LabelSelector != nil {
		s = metav1.FormatLabelSelector(spec.LabelSelector)
	}
	specInfo["labelSelector"] = s

	// or label selectors
	if len(spec.OrLabelSelectors) == 0 {
		specInfo["orLabelSelectors"] = emptyDisplay
	} else {
		orSelectors := make([]string, 0, len(spec.OrLabelSelectors))
		for _, v := range spec.OrLabelSelectors {
			orSelectors = append(orSelectors, metav1.FormatLabelSelector(v))
		}
		specInfo["orLabelSelectors"] = strings.Join(orSelectors, " or ")
	}

	specInfo["restorePVs"] = BoolPointerString(spec.RestorePVs, "false", "true", "auto")

	// existing resource policy
	if spec.ExistingResourcePolicy != "" {
		specInfo["existingResourcePolicy"] = string(spec.ExistingResourcePolicy)
	} else {
		specInfo["existingResourcePolicy"] = emptyDisplay
	}

	specInfo["itemOperationTimeout"] = spec.ItemOperationTimeout.Duration.String()
	specInfo["preserveNodePorts"] = BoolPointerString(spec.PreserveNodePorts, "false", "true", "auto")

	// resource modifier
	if spec.ResourceModifier != nil {
		specInfo["resourceModifier"] = describeResourceModifierInSF(spec.ResourceModifier)
	}

	// resource policy
	if spec.ResourcePolicy != nil {
		specInfo["resourcePolicy"] = map[string]any{
			"type": spec.ResourcePolicy.Kind,
			"name": spec.ResourcePolicy.Name,
		}
	}

	// uploader config
	if spec.UploaderConfig != nil {
		uploaderConfig := map[string]any{}
		if boolptr.IsSetToTrue(spec.UploaderConfig.WriteSparseFiles) {
			uploaderConfig["writeSparseFiles"] = true
		}
		if spec.UploaderConfig.ParallelFilesDownload > 0 {
			uploaderConfig["parallelFilesDownload"] = spec.UploaderConfig.ParallelFilesDownload
		}
		specInfo["uploaderConfig"] = uploaderConfig
	}

	d.Describe("spec", specInfo)
}

func describeResourceModifierInSF(resModifier *corev1api.TypedLocalObjectReference) map[string]any {
	return map[string]any{
		"type": resModifier.Kind,
		"name": resModifier.Name,
	}
}

func describePodVolumeRestoresInSF(d *StructuredDescriber, restores []velerov1api.PodVolumeRestore, details bool) {
	if len(restores) == 0 {
		d.Describe("podVolumeRestores", "<none included>")
		return
	}

	uploaderType := restores[0].Spec.UploaderType
	podVolumeInfo := map[string]any{
		"uploaderType": uploaderType,
	}

	restoresByPhase := groupRestoresByPhase(restores)

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
		if !details {
			podVolumeInfo[phase] = len(restoresByPhase[phase])
			continue
		}

		restoresByPod := new(volumesByPod)
		for _, restore := range restoresByPhase[phase] {
			restoresByPod.Add(restore.Spec.Pod.Namespace, restore.Spec.Pod.Name, restore.Spec.Volume, phase, restore.Status.Progress, 0)
		}

		podEntries := make([]map[string]string, 0)
		for _, restoreGroup := range restoresByPod.Sorted() {
			podEntries = append(podEntries, map[string]string{
				restoreGroup.label: strings.Join(restoreGroup.volumes, ", "),
			})
		}
		podVolumeInfo[phase] = podEntries
	}

	d.Describe("podVolumeRestores", podVolumeInfo)
}

func describeRestoreCSISnapshotsInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, restore *velerov1api.Restore, details bool, insecureSkipTLSVerify bool, caCertFile string) {
	bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
	if err != nil {
		bslCACert = ""
	}

	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreVolumeInfo,
		buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertFile, bslCACert); err != nil {
		if !errors.Is(err, downloadrequest.ErrNotFound) {
			d.Describe("csiSnapshotRestores", fmt.Sprintf("<error getting restore volume info: %v>", err))
		}
		return
	}

	var restoreVolInfo []volume.RestoreVolumeInfo
	if err := json.NewDecoder(buf).Decode(&restoreVolInfo); err != nil {
		d.Describe("csiSnapshotRestores", fmt.Sprintf("<error reading restore volume info: %v>", err))
		return
	}

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
		d.Describe("csiSnapshotRestores", "<none included>")
		return
	}

	csiRestores := map[string]any{}

	for _, info := range nonDMInfoList {
		key := fmt.Sprintf("%s/%s", info.PVCNamespace, info.PVCName)
		if details {
			csiRestores[key] = map[string]any{
				"snapshot": map[string]any{
					"snapshotContentName": info.CSISnapshotInfo.VSCName,
					"storageSnapshotID":   info.CSISnapshotInfo.SnapshotHandle,
					"csiDriver":           info.CSISnapshotInfo.Driver,
				},
			}
		} else {
			csiRestores[key] = map[string]any{
				"snapshot": "specify --details for more information",
			}
		}
	}

	for _, info := range dmInfoList {
		key := fmt.Sprintf("%s/%s", info.PVCNamespace, info.PVCName)
		if details {
			csiRestores[key] = map[string]any{
				"dataMovement": map[string]any{
					"operationID":  info.SnapshotDataMovementInfo.OperationID,
					"dataMover":    info.SnapshotDataMovementInfo.DataMover,
					"uploaderType": info.SnapshotDataMovementInfo.UploaderType,
				},
			}
		} else {
			csiRestores[key] = map[string]any{
				"dataMovement": "specify --details for more information",
			}
		}
	}

	d.Describe("csiSnapshotRestores", csiRestores)
}

func describeRestoreResultsInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, restore *velerov1api.Restore, insecureSkipTLSVerify bool, caCertPath string) {
	if restore.Status.Warnings == 0 && restore.Status.Errors == 0 {
		return
	}

	bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
	if err != nil {
		bslCACert = ""
	}

	var buf bytes.Buffer
	var resultMap map[string]results.Result

	warnings, errs := make(map[string]any), make(map[string]any)
	defer func() {
		if restore.Status.Warnings > 0 {
			d.Describe("warnings", warnings)
		}
		if restore.Status.Errors > 0 {
			d.Describe("errors", errs)
		}
	}()

	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreResults, &buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		if restore.Status.Warnings > 0 {
			warnings["errorGettingWarnings"] = fmt.Sprintf("<error getting warnings: %v>", err)
		}
		if restore.Status.Errors > 0 {
			errs["errorGettingErrors"] = fmt.Sprintf("<error getting errors: %v>", err)
		}
		return
	}

	if err := json.NewDecoder(&buf).Decode(&resultMap); err != nil {
		if restore.Status.Warnings > 0 {
			warnings["errorDecodingWarnings"] = fmt.Sprintf("<error decoding warnings: %v>", err)
		}
		if restore.Status.Errors > 0 {
			errs["errorDecodingErrors"] = fmt.Sprintf("<error decoding errors: %v>", err)
		}
		return
	}

	if restore.Status.Warnings > 0 {
		describeResultInSF(warnings, resultMap["warnings"])
	}
	if restore.Status.Errors > 0 {
		describeResultInSF(errs, resultMap["errors"])
	}
}

func describeRestoreItemOperationsInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, restore *velerov1api.Restore, details bool, insecureSkipTLSVerify bool, caCertPath string) {
	status := restore.Status
	if status.RestoreItemOperationsAttempted == 0 {
		return
	}

	opsInfo := map[string]any{
		"attempted": status.RestoreItemOperationsAttempted,
		"completed": status.RestoreItemOperationsCompleted,
		"failed":    status.RestoreItemOperationsFailed,
	}

	if !details {
		d.Describe("restoreItemOperations", opsInfo)
		return
	}

	bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
	if err != nil {
		bslCACert = ""
	}

	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreItemOperations, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		opsInfo["errorGettingOperations"] = fmt.Sprintf("<error getting operation info: %v>", err)
		d.Describe("restoreItemOperations", opsInfo)
		return
	}

	var operations []*itemoperation.RestoreOperation
	if err := json.NewDecoder(buf).Decode(&operations); err != nil {
		opsInfo["errorReadingOperations"] = fmt.Sprintf("<error reading operation info: %v>", err)
		d.Describe("restoreItemOperations", opsInfo)
		return
	}

	opsList := make([]map[string]any, 0, len(operations))
	for _, op := range operations {
		opEntry := map[string]any{
			"resource":                fmt.Sprintf("%s %s/%s", op.Spec.ResourceIdentifier, op.Spec.ResourceIdentifier.Namespace, op.Spec.ResourceIdentifier.Name),
			"restoreItemActionPlugin": op.Spec.RestoreItemAction,
			"operationID":             op.Spec.OperationID,
			"phase":                   op.Status.Phase,
		}
		if op.Status.Error != "" {
			opEntry["error"] = op.Status.Error
		}
		if op.Status.NTotal > 0 || op.Status.NCompleted > 0 {
			opEntry["progress"] = map[string]any{
				"completed": op.Status.NCompleted,
				"total":     op.Status.NTotal,
				"units":     op.Status.OperationUnits,
			}
		}
		if op.Status.Description != "" {
			opEntry["progressDescription"] = op.Status.Description
		}
		if op.Status.Created != nil {
			opEntry["created"] = op.Status.Created.String()
		}
		if op.Status.Started != nil {
			opEntry["started"] = op.Status.Started.String()
		}
		if op.Status.Updated != nil {
			opEntry["updated"] = op.Status.Updated.String()
		}
		opsList = append(opsList, opEntry)
	}
	opsInfo["operations"] = opsList
	d.Describe("restoreItemOperations", opsInfo)
}

func describeRestoreResourceListInSF(ctx context.Context, kbClient kbclient.Client, d *StructuredDescriber, restore *velerov1api.Restore, insecureSkipTLSVerify bool, caCertPath string) {
	bslCACert, err := cacert.GetCACertFromRestore(ctx, kbClient, restore.Namespace, restore)
	if err != nil {
		bslCACert = ""
	}

	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, restore.Namespace, restore.Name, velerov1api.DownloadTargetKindRestoreResourceList, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		if errors.Is(err, downloadrequest.ErrNotFound) {
			d.Describe("resourceList", "<restore resource list not found>")
		} else {
			d.Describe("resourceList", fmt.Sprintf("<error getting restore resource list: %v>", err))
		}
		return
	}

	var resourceList map[string][]string
	if err := json.NewDecoder(buf).Decode(&resourceList); err != nil {
		d.Describe("resourceList", fmt.Sprintf("<error reading restore resource list: %v>", err))
		return
	}

	d.Describe("resourceList", resourceList)
}
