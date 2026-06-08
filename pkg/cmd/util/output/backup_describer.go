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
	"sort"
	"strconv"
	"strings"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/fatih/color"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	veleroapishared "github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/downloadrequest"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/volume"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
	"github.com/vmware-tanzu/velero/pkg/util/results"
)

// DescribeBackup describes a backup in human-readable format.
func DescribeBackup(
	ctx context.Context,
	kbClient kbclient.Client,
	backup *velerov1api.Backup,
	deleteRequests []velerov1api.DeleteBackupRequest,
	podVolumeBackups []velerov1api.PodVolumeBackup,
	details bool,
	insecureSkipTLSVerify bool,
	caCertFile string,
) string {
	return Describe(func(d *Describer) {
		d.DescribeMetadata(backup.ObjectMeta)

		d.Println()
		phase := backup.Status.Phase
		if phase == "" {
			phase = velerov1api.BackupPhaseNew
		}
		phaseString := string(phase)
		switch phase {
		case velerov1api.BackupPhaseFailedValidation, velerov1api.BackupPhasePartiallyFailed, velerov1api.BackupPhaseFailed:
			phaseString = color.RedString(phaseString)
		case velerov1api.BackupPhaseCompleted:
			phaseString = color.GreenString(phaseString)
		case velerov1api.BackupPhaseDeleting:
		case velerov1api.BackupPhaseWaitingForPluginOperations, velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed:
		case velerov1api.BackupPhaseFinalizing, velerov1api.BackupPhaseFinalizingPartiallyFailed:
		case velerov1api.BackupPhaseInProgress:
		case velerov1api.BackupPhaseNew:
		case velerov1api.BackupPhaseQueued, velerov1api.BackupPhaseReadyToStart:
		}

		logsNote := ""
		if backup.Status.Phase == velerov1api.BackupPhaseFailed || backup.Status.Phase == velerov1api.BackupPhasePartiallyFailed {
			logsNote = fmt.Sprintf(" (run `velero backup logs %s` for more information)", backup.Name)
		}

		d.Printf("Phase:\t%s%s\n", phaseString, logsNote)
		if phase == velerov1api.BackupPhaseQueued {
			d.Printf("Queue position:\t%v\n", backup.Status.QueuePosition)
		}

		if backup.Spec.ResourcePolicy != nil {
			d.Println()
			DescribeResourcePolicies(d, backup.Spec.ResourcePolicy)

			// Display fine-grained filter policies if they exist
			DescribeFineGrainedFilterPolicies(ctx, kbClient, d, backup)
		}

		if backup.Spec.UploaderConfig != nil && backup.Spec.UploaderConfig.ParallelFilesUpload > 0 {
			d.Println()
			DescribeUploaderConfigForBackup(d, backup.Spec)
		}

		status := backup.Status
		if len(status.ValidationErrors) > 0 {
			d.Println()
			d.Printf("Validation errors:")
			for _, ve := range status.ValidationErrors {
				d.Printf("\t%s\n", color.RedString(ve))
			}
		}

		d.Println()
		DescribeBackupResults(ctx, kbClient, d, backup, insecureSkipTLSVerify, caCertFile)

		d.Println()
		DescribeBackupSpec(d, backup.Spec)

		d.Println()
		DescribeBackupStatus(ctx, kbClient, d, backup, details, insecureSkipTLSVerify, caCertFile, podVolumeBackups)

		if len(deleteRequests) > 0 {
			d.Println()
			DescribeDeleteBackupRequests(d, deleteRequests)
		}
	})
}

// DescribeResourcePolicies describes resource policies in human-readable format
func DescribeResourcePolicies(d *Describer, resPolicies *corev1api.TypedLocalObjectReference) {
	d.Printf("Resource policies:\n")
	d.Printf("\tType:\t%s\n", resPolicies.Kind)
	d.Printf("\tName:\t%s\n", resPolicies.Name)
}

// DescribeFineGrainedFilterPolicies describes cluster-scoped and namespace-scoped filter policies if present
func DescribeFineGrainedFilterPolicies(ctx context.Context, kbClient kbclient.Client, d *Describer, backup *velerov1api.Backup) {
	if backup.Spec.ResourcePolicy == nil {
		return
	}

	// Create a discard logger for the resource policies function since this is CLI output context
	discardLogger := logrus.New()
	discardLogger.Out = io.Discard

	resourcePolicies, err := resourcepolicies.GetResourcePoliciesFromBackup(*backup, kbClient, discardLogger)
	if err != nil {
		// Don't fail the describe if we can't read policies, just skip
		return
	}

	if resourcePolicies == nil {
		return
	}

	clusterScopedFilterPolicy := resourcePolicies.GetClusterScopedFilterPolicy()
	if clusterScopedFilterPolicy != nil {
		d.Printf("\nCluster Scoped Filter Policy:\n")
		d.Printf("  Resource Filters:\n")
		for _, rf := range clusterScopedFilterPolicy.ResourceFilters {
			kindsStr := strings.Join(rf.Kinds, ", ")
			d.Printf("    %s:\n", kindsStr)

			// Label selector
			if len(rf.LabelSelector) > 0 {
				selectorStr := formatLabelMap(rf.LabelSelector)
				d.Printf("      Label selector:     %s\n", selectorStr)
			} else if len(rf.OrLabelSelectors) > 0 {
				var orStrs []string
				for _, ols := range rf.OrLabelSelectors {
					orStrs = append(orStrs, formatLabelMap(ols))
				}
				d.Printf("      OR label selectors: [%s]\n", strings.Join(orStrs, ", "))
			} else {
				d.Printf("      Label selector:     <none>\n")
			}

			// Name patterns
			if len(rf.Names) > 0 {
				d.Printf("      Included names:     [%s]\n", strings.Join(rf.Names, ", "))
			} else {
				d.Printf("      Included names:     <none>\n")
			}

			if len(rf.ExcludedNames) > 0 {
				d.Printf("      Excluded names:     [%s]\n", strings.Join(rf.ExcludedNames, ", "))
			} else {
				d.Printf("      Excluded names:     <none>\n")
			}
		}
	}

	nfPolicies := resourcePolicies.GetNamespacedFilterPolicies()
	if len(nfPolicies) > 0 {
		d.Printf("\nNamespace-Scoped Filter Policies:\n")
		for _, policy := range nfPolicies {
			for _, ns := range policy.Namespaces {
				d.Printf("  %s:\n", ns)
				d.Printf("    Resource Filters:\n")
				for _, rf := range policy.ResourceFilters {
					var kindsStr string
					if rf.IsCatchAll() {
						kindsStr = "<catch-all> (all other kinds)"
					} else {
						kindsStr = strings.Join(rf.Kinds, ", ")
					}
					d.Printf("      %s:\n", kindsStr)

					// Label selector
					if len(rf.LabelSelector) > 0 {
						selectorStr := formatLabelMap(rf.LabelSelector)
						d.Printf("        Label selector:     %s\n", selectorStr)
					} else if len(rf.OrLabelSelectors) > 0 {
						var orStrs []string
						for _, ols := range rf.OrLabelSelectors {
							orStrs = append(orStrs, formatLabelMap(ols))
						}
						d.Printf("        OR label selectors: [%s]\n", strings.Join(orStrs, ", "))
					} else {
						d.Printf("        Label selector:     <none>\n")
					}

					// Name patterns
					if len(rf.Names) > 0 {
						d.Printf("        Included names:     [%s]\n", strings.Join(rf.Names, ", "))
					} else {
						d.Printf("        Included names:     <none>\n")
					}

					if len(rf.ExcludedNames) > 0 {
						d.Printf("        Excluded names:     [%s]\n", strings.Join(rf.ExcludedNames, ", "))
					} else {
						d.Printf("        Excluded names:     <none>\n")
					}
				}
			}
		}
	}
}

func formatLabelMap(labelMap map[string]string) string {
	var pairs []string
	for k, v := range labelMap {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, ",")
}

// DescribeUploaderConfigForBackup describes uploader config in human-readable format
func DescribeUploaderConfigForBackup(d *Describer, spec velerov1api.BackupSpec) {
	d.Printf("Uploader config:\n")
	d.Printf("\tParallel files upload:\t%d\n", spec.UploaderConfig.ParallelFilesUpload)
}

// DescribeBackupSpec describes a backup spec in human-readable format.
func DescribeBackupSpec(d *Describer, spec velerov1api.BackupSpec) {
	// TODO make a helper for this and use it in all the describers.
	d.Printf("Namespaces:\n")
	var s string
	if len(spec.IncludedNamespaces) == 0 {
		s = "*"
	} else {
		s = strings.Join(spec.IncludedNamespaces, ", ")
	}
	d.Printf("\tIncluded:\t%s\n", s)
	if len(spec.ExcludedNamespaces) == 0 {
		s = emptyDisplay
	} else {
		s = strings.Join(spec.ExcludedNamespaces, ", ")
	}
	d.Printf("\tExcluded:\t%s\n", s)

	d.Println()
	d.Printf("Resources:\n")
	if collections.UseOldResourceFilters(spec) {
		if len(spec.IncludedResources) == 0 {
			s = "*"
		} else {
			s = strings.Join(spec.IncludedResources, ", ")
		}
		d.Printf("\tIncluded:\t%s\n", s)
		if len(spec.ExcludedResources) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(spec.ExcludedResources, ", ")
		}
		d.Printf("\tExcluded:\t%s\n", s)
		d.Printf("\tCluster-scoped:\t%s\n", BoolPointerString(spec.IncludeClusterResources, "excluded", "included", "auto"))
	} else {
		if len(spec.IncludedClusterScopedResources) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(spec.IncludedClusterScopedResources, ", ")
		}
		d.Printf("\tIncluded cluster-scoped:\t%s\n", s)
		if len(spec.ExcludedClusterScopedResources) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(spec.ExcludedClusterScopedResources, ", ")
		}
		d.Printf("\tExcluded cluster-scoped:\t%s\n", s)

		if len(spec.IncludedNamespaceScopedResources) == 0 {
			s = "*"
		} else {
			s = strings.Join(spec.IncludedNamespaceScopedResources, ", ")
		}
		d.Printf("\tIncluded namespace-scoped:\t%s\n", s)
		if len(spec.ExcludedNamespaceScopedResources) == 0 {
			s = emptyDisplay
		} else {
			s = strings.Join(spec.ExcludedNamespaceScopedResources, ", ")
		}
		d.Printf("\tExcluded namespace-scoped:\t%s\n", s)
	}

	d.Println()
	s = emptyDisplay
	if spec.LabelSelector != nil {
		s = metav1.FormatLabelSelector(spec.LabelSelector)
	}
	d.Printf("Label selector:\t%s\n", s)

	d.Println()
	if len(spec.OrLabelSelectors) == 0 {
		s = emptyDisplay
	} else {
		orLabelSelectors := []string{}
		for _, v := range spec.OrLabelSelectors {
			orLabelSelectors = append(orLabelSelectors, metav1.FormatLabelSelector(v))
		}
		s = strings.Join(orLabelSelectors, " or ")
	}
	d.Printf("Or label selector:\t%s\n", s)

	d.Println()
	d.Printf("Storage Location:\t%s\n", spec.StorageLocation)

	d.Println()
	d.Printf("Velero-Native Snapshot PVs:\t%s\n", BoolPointerString(spec.SnapshotVolumes, "false", "true", "auto"))
	if spec.DefaultVolumesToFsBackup != nil {
		d.Printf("File System Backup (Default):\t%s\n", BoolPointerString(spec.DefaultVolumesToFsBackup, "false", "true", ""))
	}
	d.Printf("Snapshot Move Data:\t%s\n", BoolPointerString(spec.SnapshotMoveData, "false", "true", "auto"))
	if len(spec.DataMover) == 0 {
		s = defaultDataMover
	} else {
		s = spec.DataMover
	}
	d.Printf("Data Mover:\t%s\n", s)

	d.Println()
	d.Printf("TTL:\t%s\n", spec.TTL.Duration)

	d.Println()
	d.Printf("CSISnapshotTimeout:\t%s\n", spec.CSISnapshotTimeout.Duration)
	d.Printf("ItemOperationTimeout:\t%s\n", spec.ItemOperationTimeout.Duration)

	d.Println()
	if len(spec.Hooks.Resources) == 0 {
		d.Printf("Hooks:\t" + emptyDisplay + "\n")
	} else {
		d.Printf("Hooks:\n")
		d.Printf("\tResources:\n")
		for _, backupResourceHookSpec := range spec.Hooks.Resources {
			d.Printf("\t\t%s:\n", backupResourceHookSpec.Name)
			d.Printf("\t\t\tNamespaces:\n")
			var s string
			if len(backupResourceHookSpec.IncludedNamespaces) == 0 {
				s = "*"
			} else {
				s = strings.Join(backupResourceHookSpec.IncludedNamespaces, ", ")
			}
			d.Printf("\t\t\t\tIncluded:\t%s\n", s)
			if len(backupResourceHookSpec.ExcludedNamespaces) == 0 {
				s = emptyDisplay
			} else {
				s = strings.Join(backupResourceHookSpec.ExcludedNamespaces, ", ")
			}
			d.Printf("\t\t\t\tExcluded:\t%s\n", s)

			d.Println()
			d.Printf("\t\t\tResources:\n")
			if len(backupResourceHookSpec.IncludedResources) == 0 {
				s = "*"
			} else {
				s = strings.Join(backupResourceHookSpec.IncludedResources, ", ")
			}
			d.Printf("\t\t\t\tIncluded:\t%s\n", s)
			if len(backupResourceHookSpec.ExcludedResources) == 0 {
				s = emptyDisplay
			} else {
				s = strings.Join(backupResourceHookSpec.ExcludedResources, ", ")
			}
			d.Printf("\t\t\t\tExcluded:\t%s\n", s)

			d.Println()
			s = emptyDisplay
			if backupResourceHookSpec.LabelSelector != nil {
				s = metav1.FormatLabelSelector(backupResourceHookSpec.LabelSelector)
			}
			d.Printf("\t\t\tLabel selector:\t%s\n", s)

			for _, hook := range backupResourceHookSpec.PreHooks {
				if hook.Exec != nil {
					d.Println()
					d.Printf("\t\t\tPre Exec Hook:\n")
					d.Printf("\t\t\t\tContainer:\t%s\n", hook.Exec.Container)
					d.Printf("\t\t\t\tCommand:\t%s\n", strings.Join(hook.Exec.Command, " "))
					d.Printf("\t\t\t\tOn Error:\t%s\n", hook.Exec.OnError)
					d.Printf("\t\t\t\tTimeout:\t%s\n", hook.Exec.Timeout.Duration)
				}
			}

			for _, hook := range backupResourceHookSpec.PostHooks {
				if hook.Exec != nil {
					d.Println()
					d.Printf("\t\t\tPost Exec Hook:\n")
					d.Printf("\t\t\t\tContainer:\t%s\n", hook.Exec.Container)
					d.Printf("\t\t\t\tCommand:\t%s\n", strings.Join(hook.Exec.Command, " "))
					d.Printf("\t\t\t\tOn Error:\t%s\n", hook.Exec.OnError)
					d.Printf("\t\t\t\tTimeout:\t%s\n", hook.Exec.Timeout.Duration)
				}
			}
		}
	}

	if spec.OrderedResources != nil {
		d.Println()
		d.Printf("OrderedResources:\n")
		for key, value := range spec.OrderedResources {
			d.Printf("\t%s: %s\n", key, value)
		}
	}
}

// DescribeBackupStatus describes a backup status in human-readable format.
func DescribeBackupStatus(ctx context.Context,
	kbClient kbclient.Client,
	d *Describer,
	backup *velerov1api.Backup,
	details bool,
	insecureSkipTLSVerify bool,
	caCertPath string,
	podVolumeBackups []velerov1api.PodVolumeBackup) {
	status := backup.Status

	// Status.Version has been deprecated, use Status.FormatVersion
	d.Printf("Backup Format Version:\t%s\n", status.FormatVersion)

	d.Println()
	// "<n/a>" output should only be applicable for backups that failed validation
	if status.StartTimestamp == nil || status.StartTimestamp.Time.IsZero() {
		d.Printf("Started:\t%s\n", "<n/a>")
	} else {
		d.Printf("Started:\t%s\n", status.StartTimestamp.Time)
	}
	if status.CompletionTimestamp == nil || status.CompletionTimestamp.Time.IsZero() {
		d.Printf("Completed:\t%s\n", "<n/a>")
	} else {
		d.Printf("Completed:\t%s\n", status.CompletionTimestamp.Time)
	}

	d.Println()
	// Expiration can't be 0, it is always set to a 30-day default. It can be nil
	// if the controller hasn't processed this Backup yet, in which case this will
	// just display `<nil>`, though this should be temporary.
	d.Printf("Expiration:\t%s\n", status.Expiration)
	d.Println()

	if backup.Status.Progress != nil {
		if backup.Status.Phase == velerov1api.BackupPhaseInProgress {
			d.Printf("Estimated total items to be backed up:\t%d\n", backup.Status.Progress.TotalItems)
			d.Printf("Items backed up so far:\t%d\n", backup.Status.Progress.ItemsBackedUp)
		} else {
			d.Printf("Total items to be backed up:\t%d\n", backup.Status.Progress.TotalItems)
			d.Printf("Items backed up:\t%d\n", backup.Status.Progress.ItemsBackedUp)
		}

		d.Println()
	}

	describeBackupItemOperations(ctx, kbClient, d, backup, details, insecureSkipTLSVerify, caCertPath)

	if details {
		describeBackupResourceList(ctx, kbClient, d, backup, insecureSkipTLSVerify, caCertPath)
		d.Println()
	}

	describeBackupVolumes(ctx, kbClient, d, backup, details, insecureSkipTLSVerify, caCertPath, podVolumeBackups)

	if status.HookStatus != nil {
		d.Println()
		d.Printf("HooksAttempted:\t%d\n", status.HookStatus.HooksAttempted)
		d.Printf("HooksFailed:\t%d\n", status.HookStatus.HooksFailed)
	}
}

func describeBackupItemOperations(ctx context.Context, kbClient kbclient.Client, d *Describer, backup *velerov1api.Backup, details bool, insecureSkipTLSVerify bool, caCertPath string) {
	status := backup.Status
	if status.BackupItemOperationsAttempted > 0 {
		if !details {
			d.Printf("Backup Item Operations:\t%d of %d completed successfully, %d failed (specify --details for more information)\n", status.BackupItemOperationsCompleted, status.BackupItemOperationsAttempted, status.BackupItemOperationsFailed)
			return
		}

		// Get BSL cacert if available
		bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
		if err != nil {
			// Log the error but don't fail - we can still try to download without the BSL cacert
			d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
			bslCACert = ""
		}

		buf := new(bytes.Buffer)
		if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupItemOperations, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
			d.Printf("Backup Item Operations:\t<error getting operation info: %v>\n", err)
			return
		}

		var operations []*itemoperation.BackupOperation
		if err := json.NewDecoder(buf).Decode(&operations); err != nil {
			d.Printf("Backup Item Operations:\t<error reading operation info: %v>\n", err)
			return
		}

		d.Printf("Backup Item Operations:\n")
		for _, operation := range operations {
			describeBackupItemOperation(d, operation)
		}
	}
}

func describeBackupResourceList(ctx context.Context, kbClient kbclient.Client, d *Describer, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string) {
	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupResourceList, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		if err == downloadrequest.ErrNotFound {
			// the backup resource list could be missing if (other reasons may exist as well):
			//	- the backup was taken prior to v1.1; or
			//	- the backup hasn't completed yet; or
			//	- there was an error uploading the file; or
			//	- the file was manually deleted after upload
			d.Println("Resource List:\t<backup resource list not found>")
		} else {
			d.Printf("Resource List:\t<error getting backup resource list: %v>\n", err)
		}
		return
	}

	var resourceList map[string][]string
	if err := json.NewDecoder(buf).Decode(&resourceList); err != nil {
		d.Printf("Resource List:\t<error reading backup resource list: %v>\n", err)
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

func describeBackupVolumes(
	ctx context.Context,
	kbClient kbclient.Client,
	d *Describer,
	backup *velerov1api.Backup,
	details bool,
	insecureSkipTLSVerify bool,
	caCertPath string,
	podVolumeBackupCRs []velerov1api.PodVolumeBackup,
) {
	d.Println("Backup Volumes:")

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
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
			d.Printf("\t<error concluding native snapshot info: %v>\n", err)
			return
		}

		csiSnapshots, err = retrieveCSISnapshotLegacy(ctx, kbClient, backup, insecureSkipTLSVerify, caCertPath, bslCACert)
		if err != nil {
			d.Printf("\t<error concluding CSI snapshot info: %v>\n", err)
			return
		}

		legacyInfoSource = true
	} else if err != nil {
		d.Printf("\t<error getting backup volume info: %v>\n", err)
		return
	} else {
		var volumeInfos []volume.BackupVolumeInfo
		if err := json.NewDecoder(buf).Decode(&volumeInfos); err != nil {
			d.Printf("\t<error reading backup volume info: %v>\n", err)
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

	describeNativeSnapshots(d, details, nativeSnapshots)
	d.Println()

	describeCSISnapshots(d, details, csiSnapshots, legacyInfoSource)
	d.Println()

	describePodVolumeBackups(d, details, podVolumeBackupCRs)
}

func retrieveNativeSnapshotLegacy(ctx context.Context, kbClient kbclient.Client, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string, bslCACert string) ([]*volume.BackupVolumeInfo, error) {
	status := backup.Status
	nativeSnapshots := []*volume.BackupVolumeInfo{}

	if status.VolumeSnapshotsAttempted == 0 {
		return nativeSnapshots, nil
	}

	buf := new(bytes.Buffer)
	if err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupVolumeSnapshots, buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert); err != nil {
		return nativeSnapshots, errors.Wrapf(err, "error to download native snapshot info")
	}

	var snapshots []*volume.Snapshot
	if err := json.NewDecoder(buf).Decode(&snapshots); err != nil {
		return nativeSnapshots, errors.Wrapf(err, "error to decode native snapshot info")
	}

	for _, snap := range snapshots {
		volumeInfo := volume.BackupVolumeInfo{
			PVName: snap.Spec.PersistentVolumeName,
			NativeSnapshotInfo: &volume.NativeSnapshotInfo{
				SnapshotHandle: snap.Status.ProviderSnapshotID,
				VolumeType:     snap.Spec.VolumeType,
				VolumeAZ:       snap.Spec.VolumeAZ,
			},
		}

		if snap.Spec.VolumeIOPS != nil {
			volumeInfo.NativeSnapshotInfo.IOPS = strconv.FormatInt(*snap.Spec.VolumeIOPS, 10)
		}

		nativeSnapshots = append(nativeSnapshots, &volumeInfo)
	}

	return nativeSnapshots, nil
}

func retrieveCSISnapshotLegacy(ctx context.Context, kbClient kbclient.Client, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string, bslCACert string) ([]*volume.BackupVolumeInfo, error) {
	status := backup.Status
	csiSnapshots := []*volume.BackupVolumeInfo{}

	if status.CSIVolumeSnapshotsAttempted == 0 {
		return csiSnapshots, nil
	}

	vsBuf := new(bytes.Buffer)
	err := downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindCSIBackupVolumeSnapshots, vsBuf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert)
	if err != nil {
		return csiSnapshots, errors.Wrapf(err, "error to download vs list")
	}

	var vsList []snapshotv1api.VolumeSnapshot
	if err := json.NewDecoder(vsBuf).Decode(&vsList); err != nil {
		return csiSnapshots, errors.Wrapf(err, "error to decode vs list")
	}

	vscBuf := new(bytes.Buffer)
	err = downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindCSIBackupVolumeSnapshotContents, vscBuf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert)
	if err != nil {
		return csiSnapshots, errors.Wrapf(err, "error to download vsc list")
	}

	var vscList []snapshotv1api.VolumeSnapshotContent
	if err := json.NewDecoder(vscBuf).Decode(&vscList); err != nil {
		return csiSnapshots, errors.Wrapf(err, "error to decode vsc list")
	}

	for _, vsc := range vscList {
		volInfo := volume.BackupVolumeInfo{
			PreserveLocalSnapshot: true,
			CSISnapshotInfo: &volume.CSISnapshotInfo{
				VSCName: vsc.Name,
				Driver:  vsc.Spec.Driver,
			},
		}

		if vsc.Status != nil && vsc.Status.SnapshotHandle != nil {
			volInfo.CSISnapshotInfo.SnapshotHandle = *vsc.Status.SnapshotHandle
		}

		if vsc.Status != nil && vsc.Status.RestoreSize != nil {
			volInfo.CSISnapshotInfo.Size = *vsc.Status.RestoreSize
		}

		for _, vs := range vsList {
			if vs.Status.BoundVolumeSnapshotContentName == nil {
				continue
			}

			if vs.Spec.Source.PersistentVolumeClaimName == nil {
				continue
			}

			if *vs.Status.BoundVolumeSnapshotContentName == vsc.Name {
				volInfo.PVCName = *vs.Spec.Source.PersistentVolumeClaimName
				volInfo.PVCNamespace = vs.Namespace
			}
		}

		if volInfo.PVCName == "" {
			volInfo.PVCName = "<PVC name not found>"
		}

		csiSnapshots = append(csiSnapshots, &volInfo)
	}

	return csiSnapshots, nil
}

func describeNativeSnapshots(d *Describer, details bool, infos []*volume.BackupVolumeInfo) {
	if len(infos) == 0 {
		d.Printf("\tVelero-Native Snapshots: <none included>\n")
		return
	}

	d.Println("\tVelero-Native Snapshots:")
	for _, info := range infos {
		describNativeSnapshot(d, details, info)
	}
}

func describNativeSnapshot(d *Describer, details bool, info *volume.BackupVolumeInfo) {
	if details {
		d.Printf("\t\t%s:\n", info.PVName)
		d.Printf("\t\t\tSnapshot ID:\t%s\n", info.NativeSnapshotInfo.SnapshotHandle)
		d.Printf("\t\t\tType:\t%s\n", info.NativeSnapshotInfo.VolumeType)
		d.Printf("\t\t\tAvailability Zone:\t%s\n", info.NativeSnapshotInfo.VolumeAZ)
		d.Printf("\t\t\tIOPS:\t%s\n", info.NativeSnapshotInfo.IOPS)
		d.Printf("\t\t\tResult:\t%s\n", info.Result)
	} else {
		d.Printf("\t\t%s: specify --details for more information\n", info.PVName)
	}
}

func describeCSISnapshots(d *Describer, details bool, infos []*volume.BackupVolumeInfo, legacyInfoSource bool) {
	if len(infos) == 0 {
		if legacyInfoSource {
			d.Printf("\tCSI Snapshots: <none included or not detectable>\n")
		} else {
			d.Printf("\tCSI Snapshots: <none included>\n")
		}
		return
	}

	d.Println("\tCSI Snapshots:")
	for _, info := range infos {
		describeCSISnapshot(d, details, info)
	}
}

func describeCSISnapshot(d *Describer, details bool, info *volume.BackupVolumeInfo) {
	d.Printf("\t\t%s:\n", fmt.Sprintf("%s/%s", info.PVCNamespace, info.PVCName))

	describeLocalSnapshot(d, details, info)
	describeDataMovement(d, details, info)
}

func describeLocalSnapshot(d *Describer, details bool, info *volume.BackupVolumeInfo) {
	if !info.PreserveLocalSnapshot {
		return
	}

	if details {
		d.Printf("\t\t\tSnapshot:\n")
		if !info.SnapshotDataMoved && info.CSISnapshotInfo.OperationID != "" {
			d.Printf("\t\t\t\tOperation ID: %s\n", info.CSISnapshotInfo.OperationID)
		}

		d.Printf("\t\t\t\tSnapshot Content Name: %s\n", info.CSISnapshotInfo.VSCName)
		d.Printf("\t\t\t\tStorage Snapshot ID: %s\n", info.CSISnapshotInfo.SnapshotHandle)
		d.Printf("\t\t\t\tSnapshot Size (bytes): %d\n", info.CSISnapshotInfo.Size)
		d.Printf("\t\t\t\tCSI Driver: %s\n", info.CSISnapshotInfo.Driver)
		d.Printf("\t\t\t\tResult: %s\n", info.Result)
	} else {
		d.Printf("\t\t\tSnapshot: %s\n", "included, specify --details for more information")
	}
}

func describeDataMovement(d *Describer, details bool, info *volume.BackupVolumeInfo) {
	if !info.SnapshotDataMoved {
		return
	}

	if details {
		d.Printf("\t\t\tData Movement:\n")
		d.Printf("\t\t\t\tOperation ID: %s\n", info.SnapshotDataMovementInfo.OperationID)

		dataMover := "velero"
		if info.SnapshotDataMovementInfo.DataMover != "" {
			dataMover = info.SnapshotDataMovementInfo.DataMover
		}
		d.Printf("\t\t\t\tData Mover: %s\n", dataMover)
		d.Printf("\t\t\t\tUploader Type: %s\n", info.SnapshotDataMovementInfo.UploaderType)
		d.Printf("\t\t\t\tMoved data Size (bytes): %d\n", info.SnapshotDataMovementInfo.Size)
		if info.SnapshotDataMovementInfo.IncrementalSize > 0 {
			d.Printf("\t\t\t\tIncremental data Size (bytes): %d\n", info.SnapshotDataMovementInfo.IncrementalSize)
		}
		d.Printf("\t\t\t\tResult: %s\n", info.Result)
	} else {
		d.Printf("\t\t\tData Movement: %s\n", "included, specify --details for more information")
	}
}

func describeBackupItemOperation(d *Describer, operation *itemoperation.BackupOperation) {
	d.Printf("\tOperation for %s %s/%s:\n", operation.Spec.ResourceIdentifier, operation.Spec.ResourceIdentifier.Namespace, operation.Spec.ResourceIdentifier.Name)
	d.Printf("\t\tBackup Item Action Plugin:\t%s\n", operation.Spec.BackupItemAction)
	d.Printf("\t\tOperation ID:\t%s\n", operation.Spec.OperationID)
	if len(operation.Spec.PostOperationItems) > 0 {
		d.Printf("\t\tItems to Update:\n")
	}
	for _, item := range operation.Spec.PostOperationItems {
		d.Printf("\t\t\t%s %s/%s\n", item, item.Namespace, item.Name)
	}
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

// DescribeDeleteBackupRequests describes delete backup requests in human-readable format.
func DescribeDeleteBackupRequests(d *Describer, requests []velerov1api.DeleteBackupRequest) {
	d.Printf("Deletion Attempts")
	if count := failedDeletionCount(requests); count > 0 {
		d.Printf(" (%d failed)", count)
	}
	d.Println(":")

	started := false
	for _, req := range requests {
		if !started {
			started = true
		} else {
			d.Println()
		}

		d.Printf("\t%s: %s\n", req.CreationTimestamp.String(), req.Status.Phase)
		if len(req.Status.Errors) > 0 {
			d.Printf("\tErrors:\n")
			for _, err := range req.Status.Errors {
				d.Printf("\t\t%s\n", err)
			}
		}
	}
}

func failedDeletionCount(requests []velerov1api.DeleteBackupRequest) int {
	var count int
	for _, req := range requests {
		if req.Status.Phase == velerov1api.DeleteBackupRequestPhaseProcessed && len(req.Status.Errors) > 0 {
			count++
		}
	}
	return count
}

// describePodVolumeBackups describes pod volume backups in human-readable format.
func describePodVolumeBackups(d *Describer, details bool, podVolumeBackups []velerov1api.PodVolumeBackup) {
	// Get the type of pod volume uploader. Since the uploader only comes from a single source, we can
	// take the uploader type from the first element of the array.
	var uploaderType string
	if len(podVolumeBackups) > 0 {
		uploaderType = podVolumeBackups[0].Spec.UploaderType
	} else {
		d.Printf("\tPod Volume Backups: <none included>\n")
		return
	}

	if details {
		d.Printf("\tPod Volume Backups - %s:\n", uploaderType)
	} else {
		d.Printf("\tPod Volume Backups - %s (specify --details for more information):\n", uploaderType)
	}

	// separate backups by phase (combining <none> and New into a single group)
	backupsByPhase := groupByPhase(podVolumeBackups)

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
			d.Printf("\t\t%s:\t%d\n", phase, len(backupsByPhase[phase]))
			continue
		}

		// group the backups in the current phase by pod (i.e. "ns/name")
		backupsByPod := new(volumesByPod)

		for _, backup := range backupsByPhase[phase] {
			backupsByPod.Add(backup.Spec.Pod.Namespace, backup.Spec.Pod.Name, backup.Spec.Volume, phase, backup.Status.Progress, backup.Status.IncrementalBytes)
		}

		d.Printf("\t\t%s:\n", phase)
		for _, backupGroup := range backupsByPod.Sorted() {
			sort.Strings(backupGroup.volumes)

			// print volumes backed up for this pod
			d.Printf("\t\t\t%s: %s\n", backupGroup.label, strings.Join(backupGroup.volumes, ", "))
		}
	}
}

func groupByPhase(backups []velerov1api.PodVolumeBackup) map[string][]velerov1api.PodVolumeBackup {
	backupsByPhase := make(map[string][]velerov1api.PodVolumeBackup)

	phaseToGroup := map[velerov1api.PodVolumeBackupPhase]string{
		velerov1api.PodVolumeBackupPhaseCompleted:  string(velerov1api.PodVolumeBackupPhaseCompleted),
		velerov1api.PodVolumeBackupPhaseFailed:     string(velerov1api.PodVolumeBackupPhaseFailed),
		velerov1api.PodVolumeBackupPhaseCanceled:   string(velerov1api.PodVolumeBackupPhaseCanceled),
		velerov1api.PodVolumeBackupPhaseInProgress: "In Progress",
		velerov1api.PodVolumeBackupPhaseCanceling:  string(velerov1api.PodVolumeBackupPhaseCanceling),
		velerov1api.PodVolumeBackupPhasePrepared:   string(velerov1api.PodVolumeBackupPhasePrepared),
		velerov1api.PodVolumeBackupPhaseAccepted:   string(velerov1api.PodVolumeBackupPhaseAccepted),
		velerov1api.PodVolumeBackupPhaseNew:        string(velerov1api.PodVolumeBackupPhaseNew),
		"":                                         string(velerov1api.PodVolumeBackupPhaseNew),
	}

	for _, backup := range backups {
		group := phaseToGroup[backup.Status.Phase]
		backupsByPhase[group] = append(backupsByPhase[group], backup)
	}

	return backupsByPhase
}

type podVolumeGroup struct {
	label   string
	volumes []string
}

// volumesByPod stores podVolumeGroups, where the grouping
// label is "namespace/name".
type volumesByPod struct {
	volumesByPodMap   map[string]*podVolumeGroup
	volumesByPodSlice []*podVolumeGroup
}

// Add adds a pod volume with the specified pod namespace, name
// and volume to the appropriate group.
// Used for both backup and restore
func (v *volumesByPod) Add(namespace, name, volume, phase string, progress veleroapishared.DataMoveOperationProgress, incrementalBytes int64) {
	if v.volumesByPodMap == nil {
		v.volumesByPodMap = make(map[string]*podVolumeGroup)
	}

	key := fmt.Sprintf("%s/%s", namespace, name)

	// append backup progress percentage if backup is in progress
	if phase == "In Progress" && progress.TotalBytes != 0 {
		volume = fmt.Sprintf("%s (%.2f%%)", volume, float64(progress.BytesDone)/float64(progress.TotalBytes)*100)
	} else if phase == string(velerov1api.PodVolumeBackupPhaseCompleted) && incrementalBytes > 0 {
		volume = fmt.Sprintf("%s (size: %v, incremental size: %v)", volume, progress.TotalBytes, incrementalBytes)
	} else if (phase == string(velerov1api.PodVolumeBackupPhaseCompleted) ||
		phase == string(velerov1api.PodVolumeRestorePhaseCompleted)) &&
		progress.TotalBytes > 0 {
		volume = fmt.Sprintf("%s (size: %v)", volume, progress.TotalBytes)
	}

	if group, ok := v.volumesByPodMap[key]; !ok {
		group := &podVolumeGroup{
			label:   key,
			volumes: []string{volume},
		}

		v.volumesByPodMap[key] = group
		v.volumesByPodSlice = append(v.volumesByPodSlice, group)
	} else {
		group.volumes = append(group.volumes, volume)
	}
}

// Sorted returns a slice of all pod volume groups, ordered by
// label.
func (v *volumesByPod) Sorted() []*podVolumeGroup {
	sort.Slice(v.volumesByPodSlice, func(i, j int) bool {
		return v.volumesByPodSlice[i].label <= v.volumesByPodSlice[j].label
	})

	return v.volumesByPodSlice
}

// DescribeBackupResults describes errors and warnings in human-readable format.
func DescribeBackupResults(ctx context.Context, kbClient kbclient.Client, d *Describer, backup *velerov1api.Backup, insecureSkipTLSVerify bool, caCertPath string) {
	if backup.Status.Warnings == 0 && backup.Status.Errors == 0 {
		return
	}

	// Get BSL cacert if available
	bslCACert, err := cacert.GetCACertFromBackup(ctx, kbClient, backup.Namespace, backup)
	if err != nil {
		// Log the error but don't fail - we can still try to download without the BSL cacert
		d.Printf("WARNING: Error getting cacert from BSL: %v\n", err)
		bslCACert = ""
	}

	var buf bytes.Buffer
	var resultMap map[string]results.Result

	// If err 'ErrNotFound' occurs, it means the backup bundle in the bucket has already been there before the backup-result file is introduced.
	// We only display the count of errors and warnings in this case.
	err = downloadrequest.StreamWithBSLCACert(ctx, kbClient, backup.Namespace, backup.Name, velerov1api.DownloadTargetKindBackupResults, &buf, downloadRequestTimeout, insecureSkipTLSVerify, caCertPath, bslCACert)
	if err == downloadrequest.ErrNotFound {
		d.Printf("Errors:\t%d\n", backup.Status.Errors)
		d.Printf("Warnings:\t%d\n", backup.Status.Warnings)
		return
	} else if err != nil {
		d.Printf("Warnings:\t<error getting warnings: %v>\n\nErrors:\t<error getting errors: %v>\n", err, err)
		return
	}

	if err := json.NewDecoder(&buf).Decode(&resultMap); err != nil {
		d.Printf("Warnings:\t<error decoding warnings: %v>\n\nErrors:\t<error decoding errors: %v>\n", err, err)
		return
	}

	if backup.Status.Warnings > 0 {
		d.Println()
		describeResult(d, "Warnings", resultMap["warnings"])
	}
	if backup.Status.Errors > 0 {
		d.Println()
		describeResult(d, "Errors", resultMap["errors"])
	}
}
