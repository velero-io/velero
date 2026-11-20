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

package csi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotter "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/typed/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	"github.com/velero-io/velero/pkg/util/kube"
)

const (
	// VSCDeletionSecretNameAnnotation and VSCDeletionSecretNamespaceAnnotation are
	// set by the CSI snapshot controller on a VolumeSnapshotContent and name the
	// secret the CSI driver requires to delete the snapshot.
	VSCDeletionSecretNameAnnotation      = "snapshot.storage.kubernetes.io/deletion-secret-name"      // #nosec G101
	VSCDeletionSecretNamespaceAnnotation = "snapshot.storage.kubernetes.io/deletion-secret-namespace" // #nosec G101

	// VSCBoundProtectionFinalizer is the CSI snapshot finalizer that keeps a
	// VolumeSnapshotContent alive until the CSI snapshotter has handled its
	// deletion. A statically provisioned content without it can be dropped with
	// no DeleteSnapshot call at all, so the temporary content rebuilt to delete a
	// retained snapshot must carry it.
	VSCBoundProtectionFinalizer = "snapshot.storage.kubernetes.io/volumesnapshotcontent-bound-protection"

	// SnapshotDeleteErrorEventReason is the event reason the external-snapshotter
	// sidecar uses when the deletion of a VolumeSnapshotContent's snapshot fails.
	SnapshotDeleteErrorEventReason = "SnapshotDeleteError"
)

// The external-snapshotter sidecar emits SnapshotDeleteError events with three
// distinct messages: before the DeleteSnapshot call (credentials), for the call
// itself, and after a successful call (clearing the status). Only the call
// itself is a stale-snapshot signal; the others are environment problems or
// follow a successful delete and stay retryable.
const (
	snapshotDeleteCredentialFailureMessage = "Failed to get snapshot credentials" // #nosec G101
	snapshotDeleteCallFailureMessage       = "Failed to delete snapshot"
)

// RetainedSnapshotDeletionTimeout bounds the wait for the CSI snapshotter to
// delete a retained snapshot and remove the temporary VolumeSnapshotContent.
// On a live cluster a CSI snapshotter leader handover was observed to delay
// DeleteSnapshot by roughly two and a half minutes, which a short fixed bound
// would turn into a spurious failure.
var RetainedSnapshotDeletionTimeout = 5 * time.Minute

// retainedSnapshotPollInterval is the fixed interval, without backoff, at which
// the deletion of a temporary VolumeSnapshotContent is polled.
const retainedSnapshotPollInterval = 2 * time.Second

// SnapshotDeleteCallError reports that the CSI snapshotter's DeleteSnapshot
// call itself failed for a retained snapshot, as opposed to a credential
// failure before the call or a timeout. A stale record whose snapshot is
// already gone can fail the deletion on every retry, so the caller escalates
// after a bounded number of these instead of relying on driver compliance.
type SnapshotDeleteCallError struct {
	Message string
}

func (e *SnapshotDeleteCallError) Error() string {
	return "CSI snapshotter failed to delete the snapshot: " + e.Message
}

// GetRetainedSnapshotFromVSC builds the retained snapshot record of a backup
// VolumeSnapshotContent. It returns nil when the content has no snapshot
// handle. The exposer creates the backup content itself, synchronously, with
// the handle already in spec.source.snapshotHandle; status.snapshotHandle is
// read as a fallback only, because it may still be unset.
func GetRetainedSnapshotFromVSC(vsc *snapshotv1api.VolumeSnapshotContent) *velerov2alpha1api.RetainedCSIStorageSnapshot {
	if vsc == nil {
		return nil
	}

	handle := ""
	if vsc.Spec.Source.SnapshotHandle != nil {
		handle = *vsc.Spec.Source.SnapshotHandle
	}
	if handle == "" && vsc.Status != nil && vsc.Status.SnapshotHandle != nil {
		handle = *vsc.Status.SnapshotHandle
	}
	if handle == "" || vsc.Spec.Driver == "" {
		return nil
	}

	record := &velerov2alpha1api.RetainedCSIStorageSnapshot{
		CSISnapshotHandle:   handle,
		Driver:              vsc.Spec.Driver,
		ManagedByLabelValue: vsc.Labels[kube.VolumeSnapshotContentManagedByLabel],
	}
	if name := vsc.Annotations[VSCDeletionSecretNameAnnotation]; name != "" {
		record.DeletionSecretRef = &corev1api.SecretReference{
			Name:      name,
			Namespace: vsc.Annotations[VSCDeletionSecretNamespaceAnnotation],
		}
	}
	return record
}

// TempVSCName returns the name of the temporary VolumeSnapshotContent rebuilt
// to delete a retained snapshot. It is derived from the driver and the
// snapshot handle, so a retry of an interrupted deletion gets AlreadyExists
// and reuses the leftover instead of stacking a second content for the same
// snapshot.
func TempVSCName(driver, handle string) string {
	sum := sha256.Sum256([]byte(driver + "/" + handle))
	return "vsc-" + hex.EncodeToString(sum[:16])
}

// BuildTempVSCForRetainedSnapshot returns the statically provisioned
// VolumeSnapshotContent through which the CSI snapshotter deletes a retained
// snapshot:
//   - named vsc-<hash> of driver and handle, so a retry reuses the leftover;
//   - deletionPolicy Delete and the retained handle in spec.source.snapshotHandle;
//   - no volumeSnapshotClassName, so the deletion is independent of the class;
//   - the existing legacy action's synthetic volumeSnapshotRef, which the
//     schema requires, with an empty uid: that is what makes the snapshotter's
//     shouldDelete take the unbound pre-provisioned path and delete
//     immediately, where a fabricated uid routes the content into the bound
//     path and expects the referenced VolumeSnapshot to exist;
//   - the bound-protection finalizer, without which the content can be
//     dropped with no DeleteSnapshot call at all;
//   - the managed-by label of the record, so distributed snapshots, which
//     select contents by that label, process it too;
//   - the deletion secret annotations of the record, when the driver needs one.
func BuildTempVSCForRetainedSnapshot(record *velerov2alpha1api.RetainedCSIStorageSnapshot) *snapshotv1api.VolumeSnapshotContent {
	id := TempVSCName(record.Driver, record.CSISnapshotHandle)
	handle := record.CSISnapshotHandle

	vsc := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:       id,
			Finalizers: []string{VSCBoundProtectionFinalizer},
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
			Driver:         record.Driver,
			Source: snapshotv1api.VolumeSnapshotContentSource{
				SnapshotHandle: &handle,
			},
			// An empty uid is required: see the comment above.
			VolumeSnapshotRef: corev1api.ObjectReference{
				APIVersion: snapshotv1api.SchemeGroupVersion.String(),
				Kind:       "VolumeSnapshot",
				Namespace:  "ns-" + id,
				Name:       "name-" + id,
			},
		},
	}
	if record.ManagedByLabelValue != "" {
		vsc.Labels = map[string]string{kube.VolumeSnapshotContentManagedByLabel: record.ManagedByLabelValue}
	}
	if record.DeletionSecretRef != nil {
		vsc.Annotations = map[string]string{
			VSCDeletionSecretNameAnnotation:      record.DeletionSecretRef.Name,
			VSCDeletionSecretNamespaceAnnotation: record.DeletionSecretRef.Namespace,
		}
	}
	return vsc
}

// DeleteRetainedSnapshot has the CSI snapshotter delete the storage snapshot
// identified by record, through a temporary statically provisioned
// VolumeSnapshotContent.
//
// In external-snapshotter v8.6.0, syncContent issues DeleteSnapshot only when
// deletionPolicy is Delete and status.snapshotHandle is set, and its own
// status update runs ListSnapshots first, which fails on any driver that
// implements the capability for an already-gone snapshot. The controller
// therefore initializes the content's status itself: before deleting the temp
// content, it writes the retained handle from the record into
// status.snapshotHandle through the content's status subresource, confirms
// the write by the status response itself, and only then deletes the content,
// with no readyToUse wait.
//
// After the deletion, it polls every two seconds without backoff until the
// content disappears from the API, bounded by RetainedSnapshotDeletionTimeout.
// On a failed DeleteSnapshot the sidecar emits a SnapshotDeleteError event and
// does not write status.error, so the wait reports the event; a call failure
// is returned as a *SnapshotDeleteCallError so the caller can count attempts
// and escalate, while credential failures and timeouts stay retryable.
func DeleteRetainedSnapshot(
	ctx context.Context,
	crClient crclient.Client,
	record *velerov2alpha1api.RetainedCSIStorageSnapshot,
	log logrus.FieldLogger,
) error {
	if record == nil || record.CSISnapshotHandle == "" || record.Driver == "" {
		return errors.New("invalid retained snapshot record, handle and driver are required")
	}

	tempVSC := BuildTempVSCForRetainedSnapshot(record)

	current := tempVSC
	existing := &snapshotv1api.VolumeSnapshotContent{}
	err := crClient.Get(ctx, crclient.ObjectKey{Name: tempVSC.Name}, existing)
	switch {
	case err == nil:
		// A retry of an interrupted deletion reuses the leftover.
		current = existing
		log.Infof("Temp VolumeSnapshotContent %s for snapshot %s already exists, reusing it", tempVSC.Name, record.CSISnapshotHandle)
	case apierrors.IsNotFound(err):
		// The Create populates the resourceVersion the status write below
		// carries, as a real API server requires.
		if err := crClient.Create(ctx, tempVSC); err != nil && !apierrors.IsAlreadyExists(err) {
			return errors.Wrapf(err, "error creating temp VolumeSnapshotContent %s", tempVSC.Name)
		}
		current = tempVSC
		log.Infof("Created temp VolumeSnapshotContent %s with DeletionPolicy=Delete for snapshot %s", tempVSC.Name, record.CSISnapshotHandle)
	default:
		return errors.Wrapf(err, "error getting temp VolumeSnapshotContent %s", tempVSC.Name)
	}

	// Initialize the status the sidecar needs to issue DeleteSnapshot. The
	// write works whether or not the sidecar's own status check ever succeeds,
	// because the handle is known from the record, and the status response
	// itself is the confirmation of the write.
	statusVSC := current.DeepCopy()
	if statusVSC.Status == nil {
		statusVSC.Status = &snapshotv1api.VolumeSnapshotContentStatus{}
	}
	statusVSC.Status.SnapshotHandle = &record.CSISnapshotHandle
	if err := crClient.Status().Update(ctx, statusVSC); err != nil {
		return errors.Wrapf(err, "error writing the status of temp VolumeSnapshotContent %s", tempVSC.Name)
	}
	// The write is confirmed by reading the status back, not merely ordered:
	// deleting the content before the sidecar sees status.snapshotHandle would
	// remove it with no DeleteSnapshot call.
	confirmed := &snapshotv1api.VolumeSnapshotContent{}
	if err := crClient.Get(ctx, crclient.ObjectKey{Name: tempVSC.Name}, confirmed); err != nil {
		return errors.Wrapf(err, "error reading back the status of temp VolumeSnapshotContent %s", tempVSC.Name)
	}
	if confirmed.Status == nil || confirmed.Status.SnapshotHandle == nil || *confirmed.Status.SnapshotHandle != record.CSISnapshotHandle {
		return errors.Errorf("the status of temp VolumeSnapshotContent %s does not carry the snapshot handle", tempVSC.Name)
	}

	// The status response itself is the confirmation: deleting the content
	// before the sidecar sees status.snapshotHandle would remove it with no
	// DeleteSnapshot call.
	if err := crClient.Delete(ctx, tempVSC); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error deleting temp VolumeSnapshotContent %s", tempVSC.Name)
	}

	err = wait.PollUntilContextTimeout(ctx, retainedSnapshotPollInterval, RetainedSnapshotDeletionTimeout, true, func(ctx context.Context) (bool, error) {
		err := crClient.Get(ctx, crclient.ObjectKey{Name: tempVSC.Name}, &snapshotv1api.VolumeSnapshotContent{})
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
	if err == nil {
		log.Infof("Deleted temp VolumeSnapshotContent %s, the CSI driver deleted snapshot %s", tempVSC.Name, record.CSISnapshotHandle)
		return nil
	}
	if !wait.Interrupted(err) {
		return errors.Wrapf(err, "error waiting for temp VolumeSnapshotContent %s to be deleted", tempVSC.Name)
	}

	// The wait timed out: report the sidecar's failure if it recorded one.
	if message, kind := latestSnapshotDeleteErrorMessage(ctx, crClient, tempVSC.Name, log); message != "" {
		if kind == snapshotDeleteCallFailureMessage {
			return &SnapshotDeleteCallError{Message: message}
		}
		return errors.Errorf("CSI snapshotter failed on temp VolumeSnapshotContent %s: %s", tempVSC.Name, message)
	}
	return errors.Errorf("snapshot %s is not deleted within %v, temp VolumeSnapshotContent %s is still pending; check the events of the VolumeSnapshotContent and the CSI snapshotter logs",
		record.CSISnapshotHandle, RetainedSnapshotDeletionTimeout, tempVSC.Name)
}

// latestSnapshotDeleteErrorMessage returns the message of the latest
// SnapshotDeleteError event recorded for the named VolumeSnapshotContent, and
// whether the message belongs to the DeleteSnapshot call itself. Events of a
// cluster-scoped object are recorded in the default namespace, which the
// Velero manager's cache does not cover, so reads go through the API reader
// when one is given. A failure to list the events only removes detail from a
// pending deletion and is not an error.
func latestSnapshotDeleteErrorMessage(ctx context.Context, crClient crclient.Client, vscName string, log logrus.FieldLogger) (message, kind string) {
	events := &corev1api.EventList{}
	if err := crClient.List(ctx, events, crclient.InNamespace(metav1.NamespaceDefault)); err != nil {
		log.WithError(err).Warnf("Failed to list the events of VolumeSnapshotContent %s", vscName)
		return "", ""
	}

	var latest *corev1api.Event
	for i := range events.Items {
		event := &events.Items[i]
		if event.InvolvedObject.Kind != "VolumeSnapshotContent" || event.InvolvedObject.Name != vscName ||
			event.Reason != SnapshotDeleteErrorEventReason {
			continue
		}
		if latest == nil || event.LastTimestamp.After(latest.LastTimestamp.Time) {
			latest = event
		}
	}
	if latest == nil {
		return "", ""
	}

	// The matching is message-based and therefore snapshotter-version-sensitive;
	// an unknown message is treated as retryable rather than a call failure.
	if strings.Contains(latest.Message, snapshotDeleteCallFailureMessage) {
		return latest.Message, snapshotDeleteCallFailureMessage
	}
	return latest.Message, "other"
}

// PatchVSCDeletionPolicy patches the deletion policy of the named
// VolumeSnapshotContent through the typed snapshot client, with a
// resourceVersion precondition: the patch carries the captured
// resourceVersion, so a concurrent write to the content in between makes this
// operation fail instead of landing after it, where the sidecar would
// otherwise remove the finalizer under Retain with no DeleteSnapshot, and a
// vanished content would read as released. A resourceVersion of "" skips the
// precondition. A NotFound is tolerated, the caller decides what that means.
func PatchVSCDeletionPolicy(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vscName string,
	policy snapshotv1api.DeletionPolicy,
	resourceVersion string,
) error {
	patch := map[string]any{
		"spec": map[string]any{"deletionPolicy": string(policy)},
	}
	if resourceVersion != "" {
		patch["resourceVersion"] = resourceVersion
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return errors.Wrap(err, "error marshaling deletion policy patch")
	}
	if _, err := snapshotClient.VolumeSnapshotContents().Patch(ctx, vscName, types.MergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return errors.Wrapf(err, "error patching the deletion policy of VolumeSnapshotContent %s", vscName)
	}
	return nil
}

// DeleteVSCWithResourceVersion deletes the named VolumeSnapshotContent with a
// resourceVersion precondition, so a raced write makes the deletion fail and
// be retried instead of slipping between a confirm and a delete. A
// resourceVersion of "" skips the precondition. A NotFound is tolerated, the
// caller decides what that means.
func DeleteVSCWithResourceVersion(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vscName string,
	resourceVersion string,
) error {
	deleteOptions := metav1.DeleteOptions{}
	if resourceVersion != "" {
		deleteOptions.Preconditions = &metav1.Preconditions{ResourceVersion: &resourceVersion}
	}
	if err := snapshotClient.VolumeSnapshotContents().Delete(ctx, vscName, deleteOptions); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error deleting VolumeSnapshotContent %s", vscName)
	}
	return nil
}

// DeleteVSWithResourceVersion deletes the named VolumeSnapshot with a
// resourceVersion precondition. A resourceVersion of "" skips the
// precondition. A NotFound is tolerated, the caller decides what that means.
func DeleteVSWithResourceVersion(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vsNamespace string,
	vsName string,
	resourceVersion string,
) error {
	deleteOptions := metav1.DeleteOptions{}
	if resourceVersion != "" {
		deleteOptions.Preconditions = &metav1.Preconditions{ResourceVersion: &resourceVersion}
	}
	if err := snapshotClient.VolumeSnapshots(vsNamespace).Delete(ctx, vsName, deleteOptions); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error deleting VolumeSnapshot %s/%s", vsNamespace, vsName)
	}
	return nil
}

// SeedVSCStatusSnapshotHandle writes the given handle into the content's
// status.snapshotHandle through the status subresource, unless it is already
// set.
//
// The CSI snapshotter sidecar only issues DeleteSnapshot for a content being
// deleted when its DeletionPolicy is Delete and status.snapshotHandle is set;
// with a nil status it removes the bound-protection finalizer without the CSI
// call, so a patch-back that treated the content's disappearance as release
// would clear the record while the snapshot leaks in the storage. The same
// rule applies to the temp content of the retained-snapshot deletion, which is
// why DeleteRetainedSnapshot seeds its status itself. A conflict from the
// sidecar's own status write is tolerated: the fresh status is re-read, and
// any handle in it satisfies the requirement.
func SeedVSCStatusSnapshotHandle(
	ctx context.Context,
	snapshotClient snapshotter.SnapshotV1Interface,
	vsc *snapshotv1api.VolumeSnapshotContent,
	handle string,
) error {
	if handle == "" {
		return nil
	}
	if vsc.Status != nil && vsc.Status.SnapshotHandle != nil && *vsc.Status.SnapshotHandle != "" {
		return nil
	}

	updated := vsc.DeepCopy()
	if updated.Status == nil {
		updated.Status = &snapshotv1api.VolumeSnapshotContentStatus{}
	}
	updated.Status.SnapshotHandle = &handle
	if _, err := snapshotClient.VolumeSnapshotContents().UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
		if !apierrors.IsConflict(err) {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return errors.Wrapf(err, "error writing the status of VolumeSnapshotContent %s", vsc.Name)
		}
		// The sidecar wrote the status concurrently; any handle in the fresh
		// status satisfies the requirement.
		fresh, getErr := snapshotClient.VolumeSnapshotContents().Get(ctx, vsc.Name, metav1.GetOptions{})
		if getErr != nil {
			return errors.Wrap(getErr, "error re-reading the status of the VolumeSnapshotContent after a conflict")
		}
		if fresh.Status == nil || fresh.Status.SnapshotHandle == nil || *fresh.Status.SnapshotHandle == "" {
			return errors.Wrap(err, "error writing the status of VolumeSnapshotContent after a conflict")
		}
	}
	return nil
}
