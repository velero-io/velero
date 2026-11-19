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

package backup

import (
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/sirupsen/logrus"
	"github.com/velero-io/velero/internal/itemoutcome"
	"github.com/velero-io/velero/internal/volume"
	"github.com/velero-io/velero/pkg/itemoperation"
	"github.com/velero-io/velero/pkg/persistence"
	"github.com/velero-io/velero/pkg/util/encode"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
)

// recordArchiveFailure turns a tar-writer failure into a failed row. Observe
// has already minted the row at Succeeded, and the item is not in the archive,
// so returning without recording would leave a false success in the artifact.
func (ib *itemBackupper) recordArchiveFailure(obj runtime.Unstructured, groupResource schema.GroupResource, err error) {
	if metadata, mErr := meta.Accessor(obj); mErr == nil {
		ib.outcomeFor(metadata, groupResource).Fail(fmt.Sprintf("failed to write item to backup archive: %v", err))
	}
}

// outcomeFor returns the item-scoped recorder handle for obj. It is nil when
// collection is disabled, and every handle method is a no-op on nil.
func (ib *itemBackupper) outcomeFor(obj metav1.Object, groupResource schema.GroupResource) *itemoutcome.Item {
	if ib.backupRequest.ItemOutcomes == nil || obj == nil {
		return nil
	}
	return ib.backupRequest.ItemOutcomes.For(newResourceIdentifier(groupResource, obj.GetNamespace(), obj.GetName()))
}

// recordOwner derives the item's controller owner from its metadata.ownerReferences
// and records it as the only true parentage relationship. The derivation itself
// lives in itemoutcome so it is testable without a backupper.
func (ib *itemBackupper) recordOwner(metadata metav1.Object, item *itemoutcome.Item) {
	if item == nil {
		return
	}

	owner, ok := itemoutcome.OwnerFromOwnerReference(metadata, item.ID(), ib.discoveryHelper)
	if !ok {
		return
	}
	item.SetOwner(owner)
}

func (ib *itemBackupper) trackSkippedVolumeOutcome(obj runtime.Unstructured, groupResource schema.GroupResource, approach string, reason string, byVolume bool, log logrus.FieldLogger) {
	pvName, pvcName, pvcNamespace, err := getVolumeTrackingInfo(obj, groupResource)
	if err == nil && (len(pvName) > 0 || len(pvcName) > 0) {
		ib.backupRequest.SkippedVolumeTracker.Track(pvName, pvcName, pvcNamespace, approach, reason)

		// The tracker is what feeds the volumeinfo artifact, but it carries no
		// link back to the item that owned the volume, so a reader chasing a
		// failed VM cannot tell where the skip came from. Record the same skip
		// against the item itself so the item-outcomes artifact explains it in
		// place. Skipped is a weaker outcome than Failed, so this never masks a
		// real failure recorded for the same item.
		if metadata, mErr := meta.Accessor(obj); mErr == nil {
			method := itemOutcomeVolumeMethod(approach)
			message := fmt.Sprintf("%s volume skipped (%s): %s", method, volumeRef(pvName, pvcName), reason)
			if method == "" {
				message = fmt.Sprintf("volume skipped (%s): %s", volumeRef(pvName, pvcName), reason)
			}
			item := ib.outcomeFor(metadata, groupResource)
			if byVolume {
				item.SkipVolume(message)
				item.RecordVolumeAttempt(itemoutcome.VolumeAttempt{
					Method:        method,
					Skipped:       true,
					SkippedReason: reason,
				})
			} else {
				item.Skip(message)
			}
		}
	} else if err != nil {
		log.WithError(err).Info("unable to get volume tracking info, skip tracking.")
	}
}

// volumeRef renders whichever of the PV/PVC identifiers is populated, so a
// skip message names the volume a reader would recognise.
func volumeRef(pvName, pvcName string) string {
	switch {
	case pvcName != "" && pvName != "":
		return fmt.Sprintf("pvc=%s pv=%s", pvcName, pvName)
	case pvcName != "":
		return fmt.Sprintf("pvc=%s", pvcName)
	case pvName != "":
		return fmt.Sprintf("pv=%s", pvName)
	default:
		return "unknown volume"
	}
}

// itemOutcomeVolumeMethod maps a skip-tracker approach to the artifact method name.
func itemOutcomeVolumeMethod(approach string) string {
	switch approach {
	case podVolumeApproach:
		return itemoutcome.VolumeMethodPodVolumeBackup
	case csiSnapshotApproach:
		return itemoutcome.VolumeMethodCSISnapshot
	case volumeSnapshotApproach, vsphereSnapshotApproach:
		return itemoutcome.VolumeMethodNativeSnapshot
	case anyApproach, "":
		return ""
	default:
		return approach
	}
}

// parseSkipReasons splits the legacy "approach: reason;" string into pairs.
func parseSkipReasons(serialized string) []Reason {
	if serialized == "" {
		return nil
	}

	var reasons []Reason
	for _, entry := range strings.Split(serialized, ";") {
		entry = strings.TrimLeft(entry, " ")
		if entry == "" {
			continue
		}

		approach, reason, ok := strings.Cut(entry, ": ")
		if !ok {
			// No prefix: keep the text as a methodless reason rather than
			// dropping the only explanation for the skip.
			reasons = append(reasons, Reason{Reason: entry})
			continue
		}
		reasons = append(reasons, Reason{Approach: approach, Reason: reason})
	}
	return reasons
}

// updateItemOutcomes overlays settled async operation results onto the stored artifact.
func updateItemOutcomes(itemOutcomes *itemoutcome.ItemOutcomes, operations []*itemoperation.BackupOperation, log logrus.FieldLogger) {
	pending := itemoutcome.ApplyOperations(itemOutcomes, operationResults(operations))
	for _, operation := range pending {
		// A pending operation at finalize means no verdict was delivered.
		log.WithFields(logrus.Fields{
			"groupResource": operation.GroupResource,
			"namespace":     operation.Namespace,
			"name":          operation.Name,
			"phase":         operation.State,
		}).Warn("Item operation is not terminal at finalize; its outcome was not applied to the item outcomes artifact")
	}
}

// finalizeItemOutcomes merges settled operations and volume verdicts into the stored artifact.
func finalizeItemOutcomes(
	log logrus.FieldLogger,
	backupRequest *Request,
	volumeInfos []*volume.BackupVolumeInfo,
	operations []*itemoperation.BackupOperation,
	backupStore persistence.BackupStore,
) error {
	if backupRequest.ItemOutcomes == nil {
		return nil
	}

	itemOutcomes, err := backupStore.GetBackupItemOutcomes(backupRequest.Backup.Name)
	if err != nil {
		log.WithError(err).Errorf("fail to get the backup item outcomes for backup %s", backupRequest.Name)
		return err
	}

	// The finalize pass must not overlay an artifact it does not understand. A
	// newer schema may carry fields this server would silently drop, and an
	// artifact from another operation would get the wrong semantics.
	if !itemOutcomes.SupportedSchemaVersion() {
		return errors.Errorf("backup %s item outcomes use unsupported schema version %q", backupRequest.Name, itemOutcomes.SchemaVersion)
	}
	if itemOutcomes.Kind != "" && itemOutcomes.Kind != itemoutcome.KindBackup {
		return errors.Errorf("backup %s item outcomes record %q outcomes, not backup outcomes", backupRequest.Name, itemOutcomes.Kind)
	}

	// The finalize pass re-processes post-operation items. Merge those rows into
	// the stored artifact before applying operations and volumes; otherwise a
	// finalize-time warning or failure is recorded and then discarded.
	itemoutcome.Merge(itemOutcomes, backupRequest.ItemOutcomes.Result())

	updateItemOutcomes(itemOutcomes, operations, log)

	// The volume results are final at this point and both artifacts are in
	// memory, so fold the volume verdicts into the item rows here rather than
	// making every reader join two artifacts. This is what makes the artifact
	// self-describing.
	itemoutcome.ApplyVolumes(itemOutcomes, volumeOutcomes(volumeInfos))

	if err := putItemOutcomes(backupRequest.Name, itemOutcomes, backupStore); err != nil {
		log.WithError(err).Errorf("fail to put the item outcomes for backup %s", backupRequest.Name)
		return err
	}
	return nil
}

// FinalizeItemOutcomes completes the item outcomes artifact for a backup that
// has no async operations. Such a backup does not need its archive rewritten,
// but its artifact must still receive the final volume verdicts and be marked
// finalized; otherwise it would claim the finalize pass never ran.
func FinalizeItemOutcomes(
	log logrus.FieldLogger,
	backupRequest *Request,
	operations []*itemoperation.BackupOperation,
	backupStore persistence.BackupStore,
) error {
	if backupRequest.ItemOutcomes == nil {
		return nil
	}

	volumeInfos, err := backupStore.GetBackupVolumeInfos(backupRequest.Backup.Name)
	if err != nil {
		log.WithError(err).Errorf("fail to get the backup VolumeInfos for backup %s", backupRequest.Name)
		return err
	}

	return finalizeItemOutcomes(log, backupRequest, volumeInfos, operations, backupStore)
}

// operationResults projects backup operations onto the neutral shape the
// itemoutcome overlay takes, so the artifact package does not depend on the
// backup operation type and a restore artifact can reuse the same overlay.
func operationResults(operations []*itemoperation.BackupOperation) []itemoutcome.OperationResult {
	results := make([]itemoutcome.OperationResult, 0, len(operations))
	for _, operation := range operations {
		if operation == nil {
			continue
		}
		state := itemoutcome.OperationPending
		switch operation.Status.Phase {
		case itemoperation.OperationPhaseFailed:
			state = itemoutcome.OperationFailed
		case itemoperation.OperationPhaseCompleted:
			state = itemoutcome.OperationSucceeded
		}
		results = append(results, itemoutcome.OperationResult{
			GroupResource: operation.Spec.ResourceIdentifier.GroupResource.String(),
			Namespace:     operation.Spec.ResourceIdentifier.Namespace,
			Name:          operation.Spec.ResourceIdentifier.Name,
			State:         state,
			Error:         operation.Status.Error,
		})
	}
	return results
}

// volumeOutcomes projects the backup's volume info onto the shape the
// item-outcomes artifact records. The artifact keeps only the verdict it needs;
// volumeinfo remains the detailed per-volume record.
func volumeOutcomes(infos []*volume.BackupVolumeInfo) []itemoutcome.VolumeOutcome {
	out := make([]itemoutcome.VolumeOutcome, 0, len(infos))
	for _, info := range infos {
		if info == nil {
			continue
		}

		base := itemoutcome.VolumeOutcome{
			PVCNamespace: info.PVCNamespace,
			PVCName:      info.PVCName,
			PVName:       info.PVName,
			Result:       volumeOutcomeResult(info.Result),
			Skipped:      info.Skipped,
		}
		if info.Skipped {
			reasons := parseSkipReasons(info.SkippedReason)
			if len(reasons) == 0 {
				out = append(out, base)
				continue
			}
			// Volume info serializes every skip reason for one volume into a
			// single "approach: reason;" string. The artifact keeps one attempt
			// per reason so the fold can match the capture-time attempt and
			// dedupe the same skip when both artifacts record it.
			for _, reason := range reasons {
				attempt := base
				attempt.Method = itemOutcomeVolumeMethod(reason.Approach)
				attempt.SkippedReason = reason.Reason
				out = append(out, attempt)
			}
			continue
		}

		base.Method = itemOutcomeVolumeMethod(string(info.BackupMethod))
		out = append(out, base)
	}
	return out
}

func volumeOutcomeResult(result volume.VolumeResult) itemoutcome.VolumeResult {
	switch result {
	case volume.VolumeResultFailed:
		return itemoutcome.VolumeResultFailed
	case volume.VolumeResultSucceeded:
		return itemoutcome.VolumeResultSucceeded
	default:
		return ""
	}
}

func putItemOutcomes(
	backupName string,
	itemOutcomes *itemoutcome.ItemOutcomes,
	backupStore persistence.BackupStore,
) error {
	itemOutcomes.BackupName = backupName
	buf, errs := encode.ToJSONGzip(itemOutcomes, "backup item outcomes")
	if errs != nil {
		return kubeerrs.NewAggregate(errs)
	}

	return backupStore.PutBackupItemOutcomes(backupName, buf)
}
