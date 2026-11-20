# Block Data Mover: Base Snapshot Retention

## Abstract

This design adds Case 2 storage support to the Velero block data mover: storages, such as Ceph RBD, that need the base (parent) volume snapshot to still exist when changed blocks are computed.
Velero decides when to retain a snapshot, tracks every retained snapshot, and deletes each one when its backup is deleted.
Retention no longer depends on the `deletionPolicy` of the user's VolumeSnapshotClass.
It targets inclusion after 1.19.0, as agreed in the 2026-10-27 community meeting (#10743, #10744).

## Background

The CSI Changed Block Tracking (CBT) API lets a driver compute the delta between two volume snapshots.
The block data mover builds incremental backups from that metadata, see the [block data mover design][2], section "Volume Snapshot Retention".
Storages fall into two cases:

- **Case 1**: the driver computes changes from its own change-tracking state, so the base snapshot can be deleted as soon as the backup completes, e.g. vSphere.
- **Case 2**: the driver computes changes by diffing against the base snapshot its changeId refers to ([1], "ChangeId"). That snapshot must still exist in the storage when `GetMetadataDelta` is called, e.g. Ceph RBD.

On Case 2 storage, deleting the backup snapshot after each backup forces every later "incremental" back to a full read of the allocated blocks, and incremental restores degrade to full restores.

Through Velero 1.18, and in 1.19 until the rollback, a `Retain` VolumeSnapshotClass kept the backup snapshot through `deletionPolicy` inheritance (#10307), and nothing ever deleted those snapshots: every backup leaked one storage snapshot per volume, and the file system data mover leaked them too without ever using them (#10693, #10723).
Per the 2026-10-27 community meeting, we decided to leave Case 2 out of 1.19.0: Velero stops reading the VolumeSnapshotClass `deletionPolicy` for data movers (#10753), and Case 2 storage is a known issue.

The result is that 1.19.0 has no Case 2 support at all, and no way for a user to ask for it.
This design defines Case 2 support explicitly: Velero decides when to retain, and Velero owns the cleanup.

## Goals

- Let users opt into base snapshot retention for the block data mover through configuration Velero owns, independent of the VolumeSnapshotClass `deletionPolicy`.
- Own the retained snapshot's lifecycle: each retained snapshot is deleted when its backup is deleted, which is also how superseded snapshots are reclaimed.
- Track retained snapshots so the tracking survives Velero restarts and backup sync to another cluster.
- Retain no snapshot for failed, canceled or interrupted data movements.
- Change nothing for Case 1 storage and for users who do not opt in.

## Non Goals

- Auto-detection of Case 2 storage from `SnapshotMetadataService.spec.requireBaseSnapshotForDelta` ([kubernetes-csi/external-snapshot-metadata#258](https://github.com/kubernetes-csi/external-snapshot-metadata/issues/258), [ceph/ceph-csi#6680](https://github.com/ceph/ceph-csi/issues/6680)).
The field is merged upstream but not in an external-snapshot-metadata release Velero uses, and no driver sets it yet.
Auto-detection is tracked in #10722 for a later release.
- Honoring a `Retain` VolumeSnapshotClass for the file system data mover or any other data mover.
The file system data mover never retains snapshots; #10723 is closed by design.
- Keeping N local snapshots for fast restore (#7002 / #6240).
This design stays compatible with that work but does not implement it.
- Changes to the repository-side incremental chain: repo snapshots, parent selection and fallback to full backup keep working as specified in [1].
- Resuming interrupted DeleteBackupRequests (#10354).
Retrying a backup deletion by running `velero backup delete` again is the supported recovery, and this design makes that retry safe.

## High-Level Design

Retention is opt-in per volume through the existing volume policy: a `retainSnapshot` parameter next to the existing `dataMover` parameter of the `snapshot` action.
Retention applies to the block data mover only.

The backup VolumeSnapshotContent is created with `deletionPolicy: Delete`, as on current main.
When a DataUpload subject to retention completes, the node-agent records the snapshot handle, the CSI driver and the deletion secret in a new `DataUpload.status.retainedCSIStorageSnapshot` field, and only then switches the content to `Retain`, so the snapshot survives the exposer cleanup that follows.
The DataUpload is stored in the backup tarball, so the record survives Velero restarts and travels with backup sync to another cluster.

Data movements that do not complete never retain: their content keeps the `Delete` policy, and the patch-back reclaims the snapshot (section 3); the exposer cleanup handles the pod and PVC intermediates.

A retained snapshot lives as long as its backup: it is deleted by the backup-deletion controller, after the repository data and the DataUploads, and only if every earlier step succeeded.
When a backup is deleted, the record is first copied from the DataUpload into a ConfigMap, because the DataUploads are deleted before the snapshots (section 5).
Deleting a retained snapshot cannot be undone, which is why it runs last, before the tarball is deleted: any earlier failure leaves the snapshot and the record in place, and the backup deletion can be retried.

## Detailed Design

### 1. Configuration

Retention reuses the volume policy, the same surface that already selects the data mover per volume ([1], "Selectable Data Mover Type").
The `snapshot` action gains one parameter, `retainSnapshot`:

```yaml
version: v1
volumePolicies:
- conditions:
    csi:
      driver: rbd.csi.ceph.com
  action:
    type: snapshot
    parameters:
      dataMover: velero-block
      retainSnapshot: true
```

The policy is stored in a ConfigMap in the Velero namespace and attached to the backup through `--resource-policies-configmap` or `Backup.spec.resourcePolicy`, like any other volume policy.
The parent design [1] spells the parameter `RetainSnapshot`; this design names it `retainSnapshot`, matching the casing of the existing `dataMover` parameter.

`retainSnapshot` defaults to `false`, which is today's behavior: the snapshot is deleted when the backup completes.
It is only read for volumes backed up by the block data mover; the parameter is ignored, with a warning, for any other data mover.

The value is validated strictly: a YAML boolean or exactly `true`/`false`, anything else fails validation with the received and the allowed values.
For `action.type: snapshot` the parameter names are also validated against a closed list (`dataMover`, `snapshotClass`, `retainSnapshot`); a typo such as `retainSnapshots` otherwise reads as `false` and silently turns every incremental back into a full backup, which is a data-volume change no log line at backup time makes visible.
Unknown parameters stay accepted for `custom` actions, which pass arbitrary parameters to plugins; the closed list applies to the `snapshot` action only, and the change is called out in the changelog and in Compatibility.

The volume policy is a per-volume surface, while Case 2 is a per-storage capability.
That mismatch is accepted for this release because the policy conditions can already match on `storageClass` and the volume's CSI driver, which is how users would express the capability anyway; the cleaner per-driver surface arrives with auto-detection in #10722.

The policy is evaluated once, server-side, where the DataUpload is created; the node-agent never re-evaluates it, because the policy ConfigMap is not guaranteed to be readable from the node-agent and the global-policy annotation has its own semantics.
The decision travels on the DataUpload: `retainSnapshot: "true"` in `spec.dataMoverConfig`, the string map the DataUpload spec already defines, set by the backup action that creates the DataUpload.
The wire contract between the backup service and the node-agent is the DataUpload object, not the policy.
The key is consumed by the controllers, not by the data path: `DataMoverConfig` is documented for mover-specific configuration and is forwarded to the data path, which ignores unknown keys, so a controller-owned key in that map is safe and is called out as such; and the setter must not depend on the uploader-config branch that initializes the map today.

### 2. Retaining the snapshot

When a DataUpload whose `spec.dataMoverConfig` sets `retainSnapshot` completes, the node-agent reads the backup VolumeSnapshotContent to get the snapshot handle, the deletion secret and, when set, the `snapshot.storage.kubernetes.io/managed-by` label value.
No retry loop is needed: the exposer creates the backup content itself, synchronously, with the handle already in `spec.source.snapshotHandle` (`createBackupVSC` copies the source content's status handle at creation time); `status.snapshotHandle` is read as a fallback only, because it may still be unset.
The deletion secret is not a field: it lives in the content's `snapshot.storage.kubernetes.io/deletion-secret-name` and `-namespace` annotations.
The driver and the snapshot class are already on `DataUpload.spec.csiSnapshot` and need no re-reading.

The record, a `RetainedCSIStorageSnapshot` struct, is persisted in a new optional field, `DataUpload.status.retainedCSIStorageSnapshot`; the field is additive, so the DataUpload CRD changes are backward compatible.
It is a typed field rather than an entry in the existing `status.dataMoverResult` string map because the backup-deletion controller is a typed consumer, and the record must keep defined semantics after the mover result it came from is no longer relevant:

```go
type RetainedCSIStorageSnapshot struct {
    CSISnapshotHandle string                `json:"csiSnapshotHandle"`
    Driver            string                `json:"driver"`
    DeletionSecretRef *corev1api.SecretReference `json:"deletionSecretRef,omitempty"`
    ManagedByLabelValue string              `json:"managedByLabelValue,omitempty"`
}
```

The names were chosen to avoid the existing `RetainedSnapshot` field of `VolumeInfo`, which holds the VolumeSnapshot name on the data-mover paths (`BackupSnapshotDataMovementInfo` and `RestoreSnapshotDataMovementInfo`).
Both records would otherwise surface side by side in `velero backup describe`, same name, different meaning.

Only after the record is persisted does the node-agent patch the content's `deletionPolicy` to `Retain`.
The existing exposer cleanup then runs, and the `Retain` policy keeps the storage snapshot.
On the retention path the cleanup must also delete the backup VolumeSnapshotContent explicitly, after the VolumeSnapshot: #10753 removed the explicit content deletion because a VolumeSnapshot deletion cascades to its content only when the content's policy is `Delete`, so under `Retain` the content object would otherwise stay behind, one per volume per backup, while the storage snapshot survives as intended.
Deleting a `Retain` content is exactly what leaves the storage snapshot in place.

The cleanup on the retention path must also be able to fail.
`Exposer.CleanUp` returns nothing today, and `OnDataUploadCompleted` marks the DataUpload `Completed` unconditionally after calling it, so this design extends the cleanup interface to return an error (or adds an error-returning variant used by the retention path), and the completion callback holds the `Completed` mark until the cleanup has confirmed the intended end state.

The ordering is a hard rule, not an implementation detail.
Persisted means verified: after the status write, the node-agent gets the DataUpload back and asserts that `status.retainedCSIStorageSnapshot` carries the handle and the driver, before it patches the content.
The read-back is a direct, uncached read (an `APIReader`), because the node-agent's cached client can return the pre-write object — the DataUpload has no status subresource, so the persist is a plain object update — and a cached read would fail the verification spuriously, leaving retention silently off.
A cluster whose DataUpload CRD predates the field prunes it on write and the update still reports success (see Compatibility), so the read-back, not the API response, is the proof; if the field comes back empty, the DataUpload fails and the content keeps `Delete`.
If Velero restarts in between, the worst case is a snapshot that is deleted instead of retained: the next incremental falls back to a full backup, which is safe; the other order leaves a retained storage snapshot with no recoverable record, which is a leak.

Because the record lives on the DataUpload and DataUploads are serialized into the backup tarball, the record is durable and travels with backup sync to another cluster; no extra object needs to be synced.
The record has two forms, the DataUpload status field and the ConfigMap written during backup deletion (section 5).
Backups that never had a record are handled by the repository-tag recovery in section 7.

### 3. Unfinished data movements

Retention is applied only when a data movement finishes, so failed, canceled and interrupted data movements keep the default `Delete` policy and their snapshots are reclaimed by the existing exposer cleanup.
The switch window is narrow: the node-agent patches the content to `Retain` after the record is persisted but before the DataUpload is marked `Completed`, so a status update that fails, or a cancellation that races it, can leave a `Retain` content under an unfinished DataUpload.
On any such path, the node-agent patches the backup VolumeSnapshotContent, never the user's VolumeSnapshotClass, back to `Delete` before the cleanup.

A failed GET or PATCH must fail the cleanup and keep it retryable until the `Delete` policy is confirmed, including the prepare-timeout path.
Logging and moving on is not acceptable: the real risk is the window where the content is already switched to `Retain` and the DataUpload dies before the record is serialized into the backup tarball; moving on there strands a snapshot with no recoverable record.
A hard kill of the node-agent (OOM, force delete) inside the switch window leaves no in-process retry, so the patch-back is owned by the reconcile, not only by the failing code path.
The patch-back is ordered delete-first, clear-last: patch the content to `Delete` with a resourceVersion precondition, then delete the backup PVC, the backup VolumeSnapshot, and the backup VolumeSnapshotContent — all named after the DataUpload, so any reconciler can — wait for the content to disappear, and only then clear the record.
The VolumeSnapshot deletion is a prerequisite, not a nicety: the backup content is bound to the backup VolumeSnapshot (its `volumeSnapshotRef` carries the real UID), and the snapshotter deletes a bound content only after the snapshot deletion has begun — `shouldDelete` requires the being-deleted annotation that the VolumeSnapshot deletion sets — so deleting the content alone leaves it waiting, and the patch-back would reach its timeout even with a healthy driver.
The PVC deletion is a prerequisite too: the common snapshot controller refuses to delete a VolumeSnapshot that a pending claim is being provisioned from, reporting `SnapshotDeletePending`, and a failed exposer leaves exactly that state when it dies after creating the backup PVC; that PVC is owner-referenced by the DataUpload, so nothing but this path removes it before DataUpload deletion.
If the VolumeSnapshot still reports pending inside the bounded wait, the DataUpload fails with the record kept, and section 5 owns the snapshot.
The wait is bounded by the same deletion timeout as section 4 (five minutes by default): a driver that keeps failing `DeleteSnapshot` would otherwise leave the content with a deletionTimestamp and the bound-protection finalizer forever and block the reconcile indefinitely.
At the bound, the DataUpload fails, the record stays in place so section 5's read-any-record rule owns the snapshot, and an event is emitted.
A `NotFound` at any patch-back step clears nothing: the content can be absent because the retention-path cleanup already deleted it under a `Retain` policy — the storage snapshot then still exists — after a `Completed` update that failed to stick.
On `NotFound`, the record is kept, the DataUpload stays unfinished or fails, and section 5's deletion owns the snapshot by rebuilding the temp content from the record, which is safe whether the snapshot exists or not; clearing the record on absence alone would strand a retained snapshot with no cleanup record.
Confirming the policy is not release: a `Delete` content still has to be deleted for the sidecar to call `DeleteSnapshot`, and a crash between a record clear and that deletion would strand the snapshot with no record at all, the one leak this section exists to prevent.
Every patch-back path follows this order, in-process failures included, not only the restart path.
The invariant it buys, with its one exception: a surviving record means the snapshot was not released — except in the persist-before-retain window of section 2, where the record exists and the Retain patch never landed, so the snapshot may already be gone; the deletion tolerates that case as success (section 4), and section 5's read-any-record rule is the backstop for a crash between the steps.

Making the patch-back work is a code change, not an existing property: the `Prepared` and `InProgress` branches of the DataUpload reconcile, including the cancel path, return early when `status.node` names a different node, and the velero server never runs the exposer cleanup, so a DataUpload whose node is gone is acted on by nobody today.
The node gate must be dropped or bypassed for the patch-back — the backup VolumeSnapshotContent is named after the DataUpload, so the gate buys nothing there.
The concurrency model keeps that safe: the patch-back — policy patch, snapshot and content deletions and record clear — is idempotent and safe for any node-agent to run, last-writer-wins on each step; the exposer cleanup of the pod and PVC intermediates stays with the owning node or the cancel path exactly as today, and tolerates `NotFound` on intermediates another actor already removed.
The completion callback and the patch-back are fenced against each other by a lease on the DataUpload, not by a bare phase re-read: the callback conditionally marks the DataUpload as retaining, with a one-minute expiry — long enough for the two writes it guards — and re-checks that the mark is still its own immediately before it patches the content; if the re-check fails, for expiry or for client throttling, the callback does not patch `Retain`, fails the DataUpload, and keeps the record, leaving the content `Delete` and the snapshot to section 3's patch-back and section 5; every patch-back actor, the cancel path and any reconciler that picked up an ownerless DataUpload alike, conditionally marks the DataUpload as rolling back as its first write, which fails while an unexpired retaining mark exists and retries after it expires — the two intents serialize through one object.
The residual window, a `Retain` patch already in flight when rollback acquires the lease, is closed with server-side preconditions rather than read-then-act — on both sides of the fence: the callback's `Retain` patch is itself preconditioned on the content's resourceVersion, captured immediately after its mark re-check and used on the patch without a re-read, so a rollback that has patched or deleted the content in between makes the delayed write fail instead of landing after it, where the sidecar would otherwise remove the finalizer under `Retain` with no `DeleteSnapshot` and a vanished content would read as released; and the patch-back patches `Delete` with the content's resourceVersion as a precondition, and deletes the VolumeSnapshot and the content with `DeleteOptions` resourceVersion preconditions, so a raced `Retain` write makes the operation fail and be retried instead of slipping between a confirm and a delete.
Rollback never deletes the content or clears the record while the content reads `Retain`.
The snapshot controllers update these objects routinely — finalizers, the being-deleted annotation, status — so a precondition conflict is expected rather than exceptional: the retry is bounded per attempt and in total, and exhaustion routes into the existing timeout, where the DataUpload fails, the record is kept, and section 5 with its escalation owns the snapshot.
On the unfinished-DataUpload path, the backup VolumeSnapshot and VolumeSnapshotContent deletions belong to the patch-back, not to the exposer cleanup, so an unfinished DataUpload whose owner node is gone still has its snapshot released by whichever reconciler picks it up; on the success path, section 2's retention-path cleanup deletes the same objects, VolumeSnapshot first.
A DataUpload that failed before its record was persisted cannot leak: no record means the content was never switched to `Retain` (section 2), so the retry on that path is defensive only.
A DataUpload that failed after the record was persisted carries a stale record, which is harmless because a deletion that finds the snapshot already gone is a success (section 4).

### 4. Deleting a retained snapshot

Deleting a storage snapshot requires a CSI `DeleteSnapshot` call, and the CSI snapshotter sidecar only issues one for a VolumeSnapshotContent it can reconcile.
The design from [1] rebuilt a VolumeSnapshot and VolumeSnapshotContent pair for this.
Rebuilding only the content is enough: a statically provisioned VolumeSnapshotContent with no VolumeSnapshot still makes the sidecar call `DeleteSnapshot` when deleted; the rebuild skips the namespace and binding waits.
A temp-content rebuild already exists for legacy CSI backups (`volumesnapshotcontent_action.go`): it names the content `vsc-<uuid>`, points `spec.volumeSnapshotRef` at a synthetic reference (the schema requires the field), clears `spec.volumeSnapshotClassName` so the deletion is independent of the class, and separates create from delete by a short sleep.

This design keeps that shape and makes three structural changes, plus one data change: the `managed-by` label and the deletion secret come from the record rather than inherited from the tarball content's annotations.
The temporary content is:

- named `vsc-<hash>` of driver and snapshot handle instead of a fresh UUID, so a retry of an interrupted deletion gets `AlreadyExists` and reuses the leftover instead of stacking a second content for the same snapshot;
- statically provisioned, with `deletionPolicy: Delete`, the retained `snapshotHandle` in `spec.source.snapshotHandle`, and no `volumeSnapshotClassName`, as in the existing action;
- given the existing action's synthetic `volumeSnapshotRef`, which the schema requires, with an **empty `uid`**: an empty UID is what makes the snapshotter's `shouldDelete` take the unbound pre-provisioned path and delete immediately, where a fabricated UID routes the content into the bound path and the referenced VolumeSnapshot is expected to exist;
- created with the `snapshot.storage.kubernetes.io/volumesnapshotcontent-bound-protection` finalizer;
- labeled with the record's `snapshot.storage.kubernetes.io/managed-by` label value, when it has one, so distributed snapshotters, which select contents by that label, process it too;
- created with the deletion secret from the record, when the driver needs one, written back into the `snapshot.storage.kubernetes.io/deletion-secret-name` and `-namespace` annotations the sidecar reads credentials from.

The finalizer and the bounded wait are the second change, and they are required rather than cosmetic: live validation on kind (external-snapshotter v8.6.0) showed that a statically provisioned content without the finalizer can be dropped with no `DeleteSnapshot` call at all — every API-level check passes while the storage still holds the snapshot, which is exactly the regression the e2e case in #10694 asserts at the storage level.
The existing action's create-delete sleep has not been shown to be sufficient at that snapshotter version, so this design does not rely on it.
Within the retained path, the finalizer is the mechanism that keeps the object alive, and a status write is the mechanism that makes the sidecar act: in external-snapshotter v8.6.0, `syncContent` issues `DeleteSnapshot` only when `deletionPolicy` is `Delete` **and** `status.snapshotHandle` is set — otherwise it removes the finalizer and the content disappears with no CSI call and no error, a silent leak that reads as success to any API-level check.
The sidecar's own status update runs `ListSnapshots` first, which for an already-gone snapshot — the stale-record case section 5 relies on — fails on any driver that implements `LIST_SNAPSHOTS`; a driver without the capability assumes the handle is valid and skips the check, but the drivers this design targets do implement `ListSnapshots`, so the status cannot come from the sidecar on exactly the path that needs it.
The controller therefore initializes the content's status itself: before deleting the temp content, it writes the retained handle from the record into `status.snapshotHandle` through the content's status subresource, confirms the write by the status response itself — not merely orders the two — and only then deletes the content, with no `readyToUse` wait; the record's handle is known, so the write works whether or not the sidecar's status check ever succeeds.

These changes apply to the retained-snapshot path only.
The existing `volumesnapshotcontent_action` serves every legacy CSI backup deletion, so it keeps its current shape — a create-delete sleep with no finalizer — and if that sleep proves insufficient at newer snapshotter versions it is a separate bug to file and fix on its own, not a silent behavior change riding this design; the retained path gets its own helper or a guarded extension of the action, and the difference is called out in Compatibility.

Deleting the content makes the sidecar call `DeleteSnapshot` on the driver.
The controller polls every two seconds, without backoff, until the content disappears from the API, as `EnsureDeleteVSC` does, or until the sidecar reports failure: on a failed `DeleteSnapshot`, the external-snapshotter sidecar emits a `SnapshotDeleteError` event for the content and does not write `status.error` (the error status is a create-path mechanism), so the controller watches that event — Velero already consumes an `EventList` in `csi.DiagnoseVS`, the csi package's events reader, which is VolumeSnapshot-scoped — and keeps the timeout as the backstop.
The wait is bounded by a deletion timeout, default five minutes, not by a short fixed poll: on a live cluster, a CSI snapshotter leader handover was observed to delay `DeleteSnapshot` by roughly two and a half minutes, which a 30-second bound would have turned into a spurious failure.
The third change is where the deletion runs: in a dedicated retained-snapshot controller, not in the DeleteBackupRequest reconcile.
A DeleteBackupRequest in `InProgress` or `Processed` is not reconciled again, and the failure paths that give up mark it `Processed`, with the retry being a new request; the remaining error paths return the request `New` for a plain requeue, which restarts the reconcile rather than resuming it, so the request's reconcile cannot carry a requeue-based wait.
It cannot carry a blocking wait either: the backup-deletion controller runs with the controller-runtime default of one worker, so any wait inside it — even a short poll for a ConfigMap to empty — blocks the deletion of every unrelated backup behind it.
The DeleteBackupRequest therefore does not wait at all: its snapshot step writes the `velero.io/retained-snapshots-pending` annotation and activates the record ConfigMap family in one write — annotate first, then activate, never the reverse — and returns, leaving the request `InProgress`.
That annotation is a guard change the design requires: the request controller's skip-`InProgress` rule must consult it, and only a request carrying the annotation is let back in to evaluate completion — repair activation, re-read the family, and run the tail, meaning tarball removal and completion, only when nothing is active; a re-entry that finds pending work goes back to waiting without touching the tail.
An annotated request in `InProgress` is exempt from the 24-hour max-age deletion, so a slow snapshot controller cannot have its request deleted mid-deletion; the unstick for a genuinely wedged controller is the retry path, and the superseded annotated request is removed with the backup.
The step is level-triggered, not edge-triggered: on re-entry it first repairs activation — the annotation write and the shard activations cannot be one atomic write, and a crash in between must not strand shards — so every nonempty shard in the family that is not yet activated is activated before anything else; only then does it re-read the family, and when there is nothing active — no family, because a previous attempt already emptied and deleted it; empty shards; or every entry escalated or skipped — it clears its own annotation and runs the tail in the same reconcile, so a retry that starts after the family is gone cannot wedge waiting for a transition that already fired; the clear-then-tail branch covers pre-existing emptiness, while entries that finish after the read are covered by the wake.
The annotation wait covers only the non-empty case: when the family empties or every entry escalates between the step's read and its return, the retained-snapshot controller enqueues the request with an update that leaves the annotation in place — the annotation is what lets the request back in, so the waker never clears it; the request clears its own annotation only when it observes the completed family and runs the tail.
The ConfigMap carries a persisted activation state, written by the request's controller only after every prerequisite step — repository data and DataUploads — has succeeded; the retained-snapshot controller ignores an inactive ConfigMap, so a deletion whose repository step failed gathers records but never creates a temporary content.
The handoff is between two controllers over a live object, not a resume of an interrupted request, which stays out of scope (#10354); a retry of `velero backup delete` creates a new request that regathers from the ConfigMap, which is idempotent.
The retained-snapshot controller is keyed by the record ConfigMap, runs its own workers and requeues on its own objects, so a slow snapshot delays only its own entry.
If the driver reports that the snapshot is already gone, that is success, per the CSI spec — but that mapping is the driver's choice, not code: external-snapshotter v8.6 has no not-found tolerance of its own, and Ceph RBD is documented in this design's own Open Issue 2 to answer a deleted snapshot with an internal error rather than a not-found code.
A stale record whose snapshot is already gone can therefore fail the deletion on every retry, so the deletion escalates instead of relying on driver compliance: after a bounded number of `SnapshotDeleteError` failures for one record that come from the `DeleteSnapshot` call itself, the record is skipped with an event, and the backup deletion proceeds.
Not every `SnapshotDeleteError` escalates: the sidecar emits the same reason with three distinct messages — "Failed to get snapshot credentials", before the call; "Failed to delete snapshot", the call itself; and "Failed to clear content status", after a successful call — and only the second is a stale-snapshot signal.
The escalation counts only "Failed to delete snapshot"; credential failures are an environment problem that fails the backup deletion and stays retryable, so a restored secret lets the deletion succeed, as Security promises; a clear-status failure follows a successful delete and stays retryable; and an unknown message is treated as retryable, because the matching is message-based and therefore snapshotter-version-sensitive.
The attempt counter is persisted in the ConfigMap entry, because a retry of `velero backup delete` is a new DeleteBackupRequest and any in-memory count would reset on it — with a persisted count, a driver that fails slowly still reaches the bound across retries instead of looping forever.
An escalated handle, and a handle skipped for an unknown driver (see Security), is moved to a dedicated orphan-snapshot ConfigMap that is not labeled by backup and is therefore neither deleted by the last-entry rule nor garbage-collected when the Backup is gone; `velero backup describe` names it while the backup exists, the skip event names it, and the orphan record is the durable home for manual cleanup after the Backup object is gone.
Its entries are keyed by `<backup-uid>.<dataupload-name>` — the separator must satisfy the ConfigMap data key charset `[-._a-zA-Z0-9]+`, which a `/` does not — so they cannot collide across backups once the backup label is absent; the user docs point at the ConfigMap's name and namespace as the lookup after the Backup object is gone, and removing an entry after its snapshot is cleaned up by hand is the operator's action.
Escalating trades a possible leak against an undeletable backup, and that trade is deliberate.
Any other failure emits a `SnapshotDeleteError` event and fails the backup deletion, so it can be retried.

### 5. Deletion on backup deletion

The backup-deletion controller extends the existing order: record gathering first — the delete actions read the tarball, and if the tarball is gone the controller itself reads the local DataUploads, before they are deleted — then the repository data, then the DataUploads, then the retained snapshots, and only if every earlier step succeeded.
The backup tarball in the backup storage is deleted after that, only when all prior steps succeeded.

Because the DataUploads are deleted in an earlier step, the working record for the controller is a sharded ConfigMap family:

- The DataUpload delete action runs at the start of backup deletion, before the repository data is deleted, and reads the DataUpload from the backup tarball; any DataUpload carrying a `retainedCSIStorageSnapshot` record contributes an entry to the `retained-snapshots-<backup-UID>-<n>` family in the Velero namespace, keyed by the DataUpload name, whatever the DataUpload's final phase.
  Section 3 clears the record only after the backup content is gone, so a surviving record means the snapshot was never released; and even a stale record is harmless, because a deletion that finds the snapshot already gone is a success (section 4) — it costs one wasted temp-content round at worst, where refusing to read it would strand a real snapshot for good.
  The ConfigMap is written create-or-update: an existing map from an earlier, failed attempt of the same deletion is merged into, never rejected, because a plain create fails on `AlreadyExists` and turns every later retry of `velero backup delete` into a permanent failure until an operator removes the map by hand.
  ConfigMap data is limited to 1 MiB and a record is a few hundred bytes, so a backup with thousands of retained snapshots would exceed the bound and fail the gather itself; the records are therefore sharded into `retained-snapshots-<backup-UID>-<n>` objects, split before the limit and labeled by backup for discovery, and the orphan-snapshot ConfigMap is sharded the same way as entries accumulate across backups.
  The shard family is discovered by label; the gather and the activation step stamp the activation state on every shard they create or merge, and a shard without the key is activated by the next reconciliation of the owning request — it is never treated as complete or empty while unactivated; no shard is special, and "the ConfigMap empties" means every shard of the family is empty.
  A shard with no pending entries keeps its completed set — the evidence that suppresses replay — until the deletion finishes: the shard family is removed only after the request's tail completes, and an inactive shard is never treated as complete.
  The tail's own Backup deletion is not the GC trigger — the tail removes the family itself — and a GC that finds a family whose Backup is gone by other means removes it only when it has no pending entries; when pending entries exist, they are moved to the orphan-snapshot ConfigMap with an event, the same path as escalation and skip, and only then is the family removed, so no path deletes a pending record without leaving the orphan trace the Security section requires.
  Entries that escalate or are skipped move to the orphan-snapshot ConfigMap first (section 4), which is not backup-labeled and outlives the Backup.
- The record sources are merged, not just ordered: the local DataUploads are read even when the tarball exists, and where both carry a record for the same DataUpload, the local record wins — it entered through the API, where the tarball record is backup-storage data.
  Local presence is authoritative: when a local DataUpload exists for an entry and carries no record — section 3's patch-back cleared it — the tarball's record for that DataUpload is dropped, not resurrected; the tarball supplies entries only for DataUploads that no longer exist locally.
  Regathering respects what the family already did: an entry removed after its snapshot was confirmed deleted leaves the DataUpload name in the family's completed set, and a later regather from the unchanged tarball — the DataUploads may already be gone — does not recreate it; an entry that escalated carries its persisted attempt count in the orphan-snapshot ConfigMap, and a re-encounter merges that count instead of resetting it, so a retry of a partially completed deletion replays only the unfinished entries.
  The gather runs before the DataUpload-deletion step, and when the tarball is missing — which makes the controller skip the delete actions entirely — the controller itself writes the ConfigMap from the local DataUploads, mirroring the delete action's tarball path; without that fallback every retained snapshot of such a backup would leak silently.
  The controller fails the deletion when it finds retention evidence (a DataUpload with a record) but no usable record source.
- `deleteRetainedSnapshots` reads the ConfigMap, deletes the snapshots as in section 4, and removes the ConfigMap entry only after the snapshot is confirmed deleted.
- After a restart, the retry needs only the shard family (found by the backup label) and the leftover temporary VolumeSnapshotContent, so it finishes without the DataUploads; automatic resume stays out of scope (#10354), and #10700 covers repository data already deleted.
- Expired backups are covered by the GC controller, which creates a new delete request periodically.

The lifecycle by DataUpload outcome: a completed DataUpload with retention has its snapshot deleted when its backup is deleted; a completed DataUpload without retention has nothing to delete; a failed, canceled or timed-out DataUpload has released its snapshot through section 3 — unless the patch-back has not run yet, in which case the record remains and this section's deletion covers it.

### 6. Superseded snapshots

The block data mover always uses the most recent backup as the parent, so only the latest retained snapshot of a volume serves as the base snapshot for the next backup.
A retained snapshot stops being needed as a base snapshot as soon as a newer backup of the same volume completes: the newer backup's delta is already stored in the repository, and restores read from the repository, not from the storage snapshot.

In this design, a superseded snapshot, meaning a retained snapshot that is no longer the latest base snapshot of its volume, is deleted when its backup is deleted, not eagerly.
This keeps one rule — snapshot lifetime equals backup lifetime — and avoids a second deletion path racing with backups in flight; the cost is storage for the superseded snapshots until their backups are deleted, which is bounded by the backup retention users already chose.
The cost is concrete: one retained storage snapshot per backed-up volume per backup, so an hourly schedule with a 30-day retention keeps on the order of 720 snapshots of each volume.
On copy-on-write storage such as Ceph RBD, each snapshot costs only the blocks it pins, so the space is proportional to churn rather than to 720 full copies, but the snapshot count per volume is bounded by nothing except backup retention, and it should be weighed against per-image snapshot limits a driver may impose.

Deleting an older backup deletes only that backup's snapshot and never breaks newer backups, because each newer backup's delta is already in the repository and no repository incremental depends on the storage snapshot once its delta is uploaded.
The guarantee covers the backup chain, not an in-place restore in flight: a restore whose DataDownload has not yet called `GetMetadataDelta` against the backup being deleted fails on the driver's error for the missing base, with no fallback on that path today (Open Issue 2), so deleting a backup that is being restored in place is the user's responsibility in this release.
Deleting the latest backup deletes its snapshot too; the next backup then uses the new most recent backup as its parent, and falls back to a full backup only when no usable base snapshot remains, the existing safe fallback ([1], "Fallback to Full Backup").

### 7. Backups created before the rollback

Backups taken by Velero 1.18, or by a 1.19 build from before the rollback, on a `Retain` VolumeSnapshotClass kept their snapshots, but their DataUploads carry no record.
The handle is still recoverable: the block uploader saves the CSI snapshot handle as the `cbt-change-id` tag of the repository snapshot.

For those backups:

- Trigger and writer: the backup-deletion controller writes a record for every completed `velero-block` CSI DataUpload whose VolumeSnapshotClass still exists with `deletionPolicy: Retain`; the DataUpload delete action writes nothing for these DataUploads, which carry no record.
  The DataUpload list comes from the backup tarball, not from the cluster: on a cluster that received the backup by backup sync no DataUploads exist locally, and the tarball is the only source.
  The class is looked up in the cluster where the deletion runs; a backup whose class was never synced to that cluster falls under the manual-cleanup list below.
- The record is written to the sharded `retained-snapshots-<backup-UID>-<n>` ConfigMaps, keyed by the DataUpload name as in section 5, and the deletion secret is taken from the class parameters.
- The controller resolves the handle from the tag, through a new `GetSnapshotTags` call on the repository manager, because deleting the repository data destroys the tag; it then writes the entry, and only then deletes the repository data.
- If the tag cannot be read, the repository data is kept and the backup deletion fails, so a retry can read it; if the repository snapshot is already gone or has no tag, the record is dropped.

Snapshots that cannot be recovered this way need manual cleanup and are documented as such in the user docs: vSphere backups (the tag holds a changeId, not a handle), file system data mover backups, DataUploads that never completed, backups whose class was deleted or changed since, classes that name the deletion secret with a template, repository snapshots or tags already deleted, and backups whose tarball is gone — the tag recovery reads the tarball, and the controller's tarball download is scoped to the delete actions today, so this path reuses the section 5 gather or restructures the download.

### 8. Restore-side baseline

In-place incremental restore creates a restore baseline, a snapshot of the target volume, and under the pre-rollback behavior it leaked the same way (#10728).
The restore baseline cleanup lands separately (#10699): the fix routes the exposer cleanup through the existing `csi.CleanupVolumeSnapshot` helper, which already patches the bound content's `deletionPolicy` to `Delete`; the change is in the exposer's routing, not in the helper.
Backup-side retention and restore baseline cleanup are one lifecycle story and land together after 1.19.0, as separate PRs.

## Alternatives Considered

**Honor the VolumeSnapshotClass `deletionPolicy` (1.18 and early 1.19 behavior, #10307).**
Rejected: the class is not Velero-owned configuration, it applies to every data mover including the file system one, and nothing deletes the snapshots, so every backup leaks one per volume (#10693, #10723).
The community decided against it on 2026-10-27 and rolled it back in #10753.

**Auto-detect from `requireBaseSnapshotForDelta` now.**
Rejected for this release: the field is not in an external-snapshot-metadata release Velero uses and no driver sets it; tracked in #10722, and the volume policy parameter designed here is the explicit override that auto-detection will complement, not replace.

**A dedicated per-driver configuration surface next to the VolumeSnapshotClass.**
Retention is a per-storage-capability decision, which argues for a driver-keyed setting rather than a per-volume policy.
Rejected for now: volume policy already selects by CSI driver or StorageClass, comes with no new API, and matches the sketch in [1].
Revisited in Open Issues.

**Never delete; leave cleanup to the storage side.**
Rejected: storage-side retention policies are opaque to Velero, so a snapshot deleted under a backup's feet would silently degrade incrementals to fulls.

**Delete superseded snapshots eagerly.**
Deleting a snapshot as soon as a newer backup of the same volume completes would bound storage to one retained snapshot per volume, but it adds a second deletion path that races with backups in flight and with backup deletion; snapshot lifetime equals backup lifetime is simpler (section 6).
Eager cleanup can be revisited as a follow-up if the storage cost matters.

**A dedicated CR or ConfigMap as the durable record, instead of DataUpload status.**
Rejected: the DataUpload already travels in the backup tarball, so its status gives restart survival and backup sync for free, where a separate object would need its own lifecycle, deletion and sync story.
A ConfigMap is used for the working record during backup deletion, short-lived for the primary record; the orphan-snapshot ConfigMap holds only the exceptions that can no longer be deleted and is cleaned up by the operator, which is the smaller story than giving the primary record its own object.

## Security Considerations

The record stores references (a snapshot handle, a driver name and a secret reference), never secret data; it is the same information a VolumeSnapshotContent already holds in the cluster.
The deletion secret itself stays in the cluster where the backup was taken.
If the backup is synced to another cluster and deleted there, the secret must exist in that cluster too, or the backup deletion fails and can be retried once the secret is recreated; drivers that need no deletion secret (the common case, e.g. Ceph RBD) are unaffected.
The record travels in the backup tarball, so anyone who can read a backup can see its snapshot handles, driver and secret names, the same sensitivity level as the rest of the backup metadata.
The temporary VolumeSnapshotContent is created in the Velero namespace and deleted with the snapshot.
Deletion is also a write amplified by backup data: the handle and the driver come from the backup tarball or the repository tag, so anyone able to write the backup storage can make Velero issue `DeleteSnapshot` for an arbitrary handle of a driver the cluster runs, before the tarball is removed.
Records sourced from `DataUpload.status` are trusted — they entered through the API, not the tarball — and are preferred over tarball- or tag-derived values wherever both exist.
For a tarball- or tag-sourced record naming a driver the cluster does not run, the deletion neither issues the `DeleteSnapshot` call nor hard-fails: the record is skipped with an event and in `velero backup describe`, moved to the orphan-snapshot ConfigMap for manual cleanup (section 4), so the deletion completes and the Backup object can go away — a skip that left nothing behind would be indistinguishable from a silent leak, the one thing this section exists to prevent — because a secondary cluster that runs no such driver, or has no volumes or classes to cross-check against, is exactly the sync use case, and a hard failure would make synced backups undeletable.
Permissions stay within reading, writing and patching VolumeSnapshotContents, updating DataUpload status and writing ConfigMaps in the Velero namespace.
The node-agent and the backup-deletion controller already hold most of these, and the implementation verifies the exact delta instead of assuming it.

## Compatibility

- Case 1 storage and users who do not set `retainSnapshot` see exactly the post-#10753 1.19.0 behavior.
- The `DataUpload.status.retainedCSIStorageSnapshot` field is additive and optional; older Velero versions ignore it, and backups without it use the legacy tag-resolution path, subject to the conditions in section 7.
  The reverse direction needs care, and it is a hard prerequisite, not a silent degradation: while the cluster's DataUpload CRD predates the field, the API server prunes it on write, the read-back verification detects the missing record, and the DataUpload fails — so operators must upgrade the DataUpload CRD before enabling `retainSnapshot`.
  This applies to OADP, which ships the DataUpload CRD in its own bundle and may lag the Velero patch; the user docs state it.
- Downgrading to 1.19.0 from a release carrying this design is supported but lossy: the 1.19.0 binary knows nothing of retention, so deleting a backup there removes the DataUploads and the tarball while the storage snapshot stays, which is exactly the #10693 condition this design fixes.
  Before rolling back, delete the backups that have retained snapshots, or accept that their snapshots leak and need manual cleanup.
  An in-flight backup deletion interrupted by a rollback must be re-run after re-upgrading: the old binary's DeleteBackupRequest GC deletes `InProgress` requests after 24 hours (`deleteBackupRequestMaxAge`, backup_deletion_controller.go) and does not honor this design's annotations, so the request cannot be resumed, only restarted.
- The record is one snapshot per DataUpload.
A future design that keeps N local snapshots for fast restore (#7002 / #6240) extends it to a list; nothing here conflicts with that work.
- A `Retain` VolumeSnapshotClass no longer keeps data mover snapshots, matching 1.19.0; the user docs state this for both data movers.
- Validating the `snapshot` action's parameter names against a closed list is a behavior change for policies that carry typos or unexpected keys today; it is called out in the changelog, and `custom` actions are unaffected.
- The temp-content deletion changes (finalizer, bounded wait) apply to the retained-snapshot path only; legacy CSI backup deletion keeps its existing mechanism and latency.
- Backups from before the rollback are handled as in section 7; backups taken by 1.19.0 never retained and are unaffected; retention starts with the release carrying this design.
- The parent design [2] states that a Case 2 parent snapshot "can NOT be deleted as long as there are incremental backups based on it"; this design supersedes that sentence, because once a backup's delta is uploaded the repository chain no longer depends on the storage snapshot.

## Implementation

- The candidate implementation is #10691, reworked against this design; it covers the record (section 2), the unfinished-DataUpload release (section 3), the deletion mechanics (sections 4 and 5) and the pre-rollback recovery (section 7).
- Restore-side baseline cleanup lands as #10699 in the same window.
- e2e coverage is #10694: a kind CSI case that asserts on the storage, not just the API objects, because csi-driver-host-path keeps each snapshot as `/csi-data-dir/<handle>.snap`, which is what catches a missing bound-protection finalizer that API-level checks miss.
- The case either installs the snapshot metadata service into the kind CSI job, or runs host-path-only against the retention mechanics.
- Unit tests: lifecycle and idempotency against a fake CSI backend, one dedicated test per ordering and failure-propagation rule (persist-before-retain with the read-back verification, deletionPolicy-patch-failure propagation, create-or-update of the record ConfigMap across repeated deletions), and the legacy tag-resolution paths.
- Diagnostics: `velero backup describe` reports, per volume, whether retention applied and which policy entry matched, the retained handle, and a DataUpload `fallbackReason` when an incremental fell back to a full read (base not retained, base gone, driver error), because the existing first-backup wording, "fallen back to Full", does not say why.
  A volume that matched no policy, or matched one without `retainSnapshot`, logs the decision and its source at backup time.
- Live validation on Ceph RBD: delete non-latest and latest backups, force-kill Velero mid-deletion and rerun `velero backup delete`, and recover pre-rollback backups with no record.
- The "Volume Snapshot Retention" section of [1] is updated to point to this design.

## Open Issues

1. Is the volume policy the right home for `retainSnapshot`, given retention is a per-storage capability rather than a per-volume decision?
2. Should deleting a retained snapshot that a later backup still uses as its base snapshot be blocked, and how aggressively, or is backup deletion ordering the user's responsibility in this release?
   Evidence to weigh: the base is consumed when the DataDownload calls `GetMetadataDelta`, not when the restore is created, and Ceph RBD answers a deleted base with an internal error rather than a not-found code, so a restore that loses its base mid-flight surfaces an opaque driver error that error codes cannot distinguish from a real storage fault.
3. Fold the restore baseline cleanup (#10728) into the implementation PR, or land it immediately after in the same window?
4. Snapshot count grows with backup retention (one retained snapshot per volume per backup, on the order of 720 at hourly/30-day); is that acceptable for every Case 2 driver, or does the patch window need eager deletion of superseded snapshots after all?

Velero issue numbers (`#NNNN`) refer to https://github.com/velero-io/velero/issues/NNNN.

[1]: Implemented/block-data-mover/block-data-mover.md
[2]: Implemented/block-data-mover/block-data-mover.md#volume-snapshot-retention
