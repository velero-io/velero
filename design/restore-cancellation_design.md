# Restore cancellation

Status: proposed.
This is the Restore follow-on to the [unified Backup and Restore cancellation RFC](https://github.com/velero-io/velero/pull/10602); it adopts that RFC's request CR, phases and status shape and covers what the RFC leaves to the per-workflow designs.
Related issues: [restore cancellation #9190](https://github.com/velero-io/velero/issues/9190) and [backup cancellation #2098](https://github.com/velero-io/velero/issues/2098).
Proposed Restore contributor: Ruslan Shaydullin; the Backup follow-on belongs to the backup contributors.
Source references point at `1342339994850613eb7f967eaa20e1149f6ddb6e`.

## Abstract

Define how a Restore is cancelled under the unified cancellation model: where each Restore controller checks for the signal, what each phase still completes after acceptance, how PodVolumeRestores, DataDownloads and plugin operations are cancelled, what is persisted so an operator can tell restored items from never-attempted ones, and what restart and deletion do to a cancelled Restore.

## Background

The RFC settles the shared parts.
A user creates a `RestoreCancellationRequest`; the request controller sets the internal `spec.cancel` signal on the Restore; the controller that owns the current phase accepts by recording `Cancelling` and `status.cancellation.acceptedAt` together, stops normal work, attempts to cancel work underway, and records `Cancelled` when its handling ends.
`Cancelled` means Velero finished its handling, not that all external work stopped, and nothing is rolled back.
`status.cancellation` carries `acceptedAt`, `reason` and `conditions`; a bounded deadline is deferred.
This design therefore says, for each Restore phase, what the checkpoint is and what ends the handling, instead of relying on a timer.

A Restore today passes through three controllers.
The restore controller validates a `New` Restore, moves it to `InProgress` and runs the whole item restore synchronously inside its reconcile; when the run returns it writes the results, the restored resource list and the item operation list to object storage and moves the Restore to `WaitingForPluginOperations` or `Finalizing`, each with a `PartiallyFailed` variant.
The restore operations controller polls asynchronous `RestoreItemAction` v2 operations and already calls the plugin's `Cancel` when an operation exceeds `spec.itemOperationTimeout`, recording the operation as failed.
The restore finalizer controller patches dynamically provisioned PVs with the backed-up volume information, removes the stub VolumeGroupSnapshotClass, writes the volume information file and waits for the post-restore exec hooks, bounded by the resource timeout, before recording `Completed` or `PartiallyFailed`.
Inside the run, pod volume restores and exec hooks are started in goroutines: the engine waits for the PodVolumeRestores before it returns, while exec hooks keep running until the finalizer collects them through the hook tracker.
PodVolumeRestore and DataDownload have a `spec.cancel` field and `Canceling`/`Canceled` phases of their own, and on startup the server already marks `InProgress` Restores as `Failed` and sets `spec.cancel` on their DataDownloads and PodVolumeRestores.
Phase writes use a merge patch without an optimistic lock.

## Goals

- Reach `Cancelled` from every non-terminal Restore phase while keeping the Restore object, its logs and the results and resource list for everything that was processed.
- Stop admitting restore work at defined checkpoints and cancel PodVolumeRestores, DataDownloads and plugin operations through their existing paths, reporting what could not be confirmed.
- Keep a cancelled Restore safe to reason about: restored, skipped, failed and never-attempted items are distinguishable, destination storage is never removed by cancellation, and restart and deletion preserve the cancelled outcome.

## Non Goals

- Rolling back restored objects or volume data.
- A cancellation deadline; the RFC defers it and this design ends handling at explicit points instead.
- The request CR, the request controller, the `velero restore cancel` command and the shared status types, which the RFC defines.
- Backup cancellation.
- Interrupting an exec hook that is already running inside a pod, or an init container hook that has already been injected.
- Changing the `RestoreItemAction` or `VolumeSnapshotter` plugin interfaces.

## High-Level Design

The restore controller already watches Restores, so the `spec.cancel` signal arrives through its informer; the engine reads it from a per-Restore flag at its checkpoints and never issues an extra API read per item.
Whichever controller owns the current phase accepts the request with a conditional update and runs the cancellation handling for that phase: the engine stops admitting items and hands back what it processed, the operations controller cancels the known operations, the finalizer stops waiting for hooks.
Every path then runs the same wrap-up: request cancellation of owned PodVolumeRestores and DataDownloads, run the finalizer steps that protect already restored volumes, persist the results, the resource list and the operation list for the processed part, record the conditions, and commit `Cancelled`.
The Restore, its artifacts and its children stay in place; deletion remains a separate request.

## Detailed Design

### 1. Checkpoints and acceptance by phase

| Phase | Owner | Checkpoint | Handling after acceptance | Handling ends when |
|---|---|---|---|---|
| empty or `New` | restore controller | Before validation and before the backup is fetched | None; nothing has run | Immediately; `Cancelled` with no artifacts |
| `InProgress` | restore controller, inside the engine | Before each resource group, before each item, before the additional items an action returns, before a pod volume restore or an exec hook is started, and while waiting for pod volume restores | Stop admitting; request PodVolumeRestore and DataDownload cancellation; cancel the hook wait; run the volume-protecting finalizer steps; persist results, resource list and operations | Every started pod volume restore and operation has been asked to cancel or has already finished, and the artifacts are written or their failure recorded |
| `WaitingForPluginOperations`, also `PartiallyFailed` | operations controller | At the start of each poll | Call `Cancel` for every operation that is still `New` or `InProgress`, record it, then the same wrap-up | Every known operation has been cancelled, completed or failed, and the operation list is written |
| `Finalizing`, also `PartiallyFailed` | finalizer controller | Before the hook wait | Complete the volume-protecting steps that already started, stop waiting for hooks, record the hook tracker state | The finalizer steps have run once and the status is written |
| `Cancelling` after a restart | the controller that owns the recorded phase | On startup, before stale `InProgress` Restores are marked `Failed` | Continue the wrap-up from the persisted state | As above, with unknown items recorded as unconfirmed |

Acceptance happens where the signal is observed.
For an `InProgress` Restore the observing code runs inside the restore controller's own reconcile, so the engine records `Cancelling` through the controller's client at the checkpoint and continues with the wrap-up in the same goroutine; no separate coordinator is needed, matching the RFC's ownership rule.
A call that is already underway finishes first: a Kubernetes create or patch for one item, a `CreateVolumeFromSnapshot` call for a native snapshot or an action's `Execute` cannot be interrupted, and the checkpoint after it is where handling starts.
A `Cancelled` Restore does not pass through `WaitingForPluginOperations` or `Finalizing`; the wrap-up performs the parts of those stages that cancellation still needs.

### 2. Observing the signal and writing phases

The restore controller keeps a set of Restore UIDs for which it has seen `spec.cancel`, fed by the Restore informer it already has, and clears entries when a Restore reaches a terminal phase.
The engine checks that set at the checkpoints above; this costs nothing per item and does not depend on the API server being reachable at that moment.
As a fallback, the engine re-reads the Restore from the informer cache at resource group boundaries, so a missed event is caught within one group.

Every writer of a Restore phase moves from `kube.PatchResource`, which patches with `client.MergeFrom` and no optimistic lock, to a merge patch with `client.MergeFromWithOptimisticLock` or an update carrying the resourceVersion it read.
On a conflict the writer reads the Restore again; if cancellation has been accepted in the meantime it hands over to the wrap-up instead of writing its own phase, and if the Restore already reached a normal terminal phase the cancellation request is too late, as the RFC specifies.
This applies to the end-of-run update in the restore controller, the operations controller, the finalizer controller, the progress updater and the startup recovery code.
The shared implementation should provide this helper so that Backup and Restore use the same one.

### 3. Stopping work

| Work | Cancellation path |
|---|---|
| Items not yet processed, including additional items returned by actions | Not started; counted as never attempted |
| A create or patch of one item already sent to the API server | Finishes; its real outcome is recorded in the resource list |
| PodVolumeRestore | Set `spec.cancel` on every PodVolumeRestore labelled with this Restore's UID, as the startup recovery already does, cancel the engine's pod volume context and stop waiting for the group; the PodVolumeRestore controller moves them to `Canceling` and `Canceled` |
| DataDownload created by the CSI `PVCRestoreItemAction` | Call `Cancel(operationID)`, which sets `spec.cancel` on the DataDownload; its controller cancels the transfer and removes the restore pod and PVC it created |
| Other `RestoreItemAction` v2 operations with an operation ID | Call `Cancel(operationID)`; the plugin may treat it as a no-op |
| An operation whose ID was never persisted, for example after a crash during the run | Nothing to call; recorded as unconfirmed |
| Native `CreateVolumeFromSnapshot` | No context and no operation ID; the call returns on its own and handling continues after it |
| Exec hooks waiting for a pod to become ready | The hook context is cancelled, so they never start; recorded as not executed in `status.hookStatus` |
| An exec hook already running inside a pod | Left to finish or hit its own timeout; its outcome is recorded if it arrives before the status is written, otherwise it is unconfirmed |
| Init container hooks already injected into created pods | Run by the kubelet as part of the pod; nothing to cancel |
| `DataUploadResult` ConfigMaps and the stub VolumeGroupSnapshotClass | Removed, as the normal end of a run removes them |

Cancellation cleanup removes only what this Restore created for its own use.
It never deletes a restored PVC, a PV, or data on the destination, whether the volume was restored from a snapshot, a DataDownload or a pod volume restore.
For an in-place restore the DataDownload exposer retains the existing PV and its error path deletes the PV it retained; cancellation must not take that path for a PV the restore did not create, and in-place restore stays outside the supported modes until that is verified.

### 4. Volume-protecting finalizer steps

Three finalizer tasks still run during the wrap-up, because skipping them leaves restored volumes in a worse state than letting them finish.
Patching dynamically provisioned PVs with the backed-up reclaim policy and labels keeps a restored volume from being removed by the storage class default when its PVC is later deleted during manual reconciliation.
Writing the volume information file keeps `describe` able to show which volumes were restored and how.
Removing the stub VolumeGroupSnapshotClass is cleanup of a temporary object this Restore created.
They are idempotent and already bounded by the resource timeout.
The hook wait is the finalizer step that cancellation cuts.

### 5. What the operator sees

`status.phase` is `Cancelled`; `status.cancellation.reason` says whether the wrap-up settled everything or left unconfirmed work; `status.progress` stays at the point where admission stopped.
Conditions, with names to be aligned with the Backup design, cover admission (`AdmissionClosed`, with the number of never-attempted items in its message), pod volume restores (`PodVolumeRestoresSettled`), plugin operations (`PluginOperationsSettled`), hooks (`HooksSettled`), the finalizer steps (`VolumesFinalized`) and the artifacts (`DiagnosticsPersisted`), each `True`, `False` or `Unknown` with a reason and a bounded message.
Object storage receives the same files as a completed Restore, for the processed part: the results file with warnings and errors, `restore-<name>-resource-list.json.gz` with every processed item as `created`, `updated`, `skipped` or `failed`, the item operation list, the volume information and the log.
`velero restore describe --details` shows them unchanged, and the resource list is the reconciliation tool: an item marked `created` was created by this Restore and carries the `velero.io/restore-name` and `velero.io/backup-name` labels, an item marked `updated` existed before the Restore and must not be removed on the strength of the label, and an item absent from the list was never attempted.
A request accepted before the run started leaves no artifacts, which `describe` and `download` report as never created rather than as a failed upload; a failed upload after a run is a `False` `DiagnosticsPersisted` condition.
The `restore create --wait` loop, `restore logs`, the download request controller's artifact check and the restore outcome metrics gain the new phase; a `restore_cancelled_total` counter sits next to the existing success, partial failure and failure counters.

### 6. Restart

On startup the server marks `InProgress` Restores as `Failed` and cancels their DataDownloads and PodVolumeRestores.
With cancellation, a Restore with `spec.cancel` set or already `Cancelling` is excluded from that marking and handed to the wrap-up instead: accept if not yet accepted, cancel the children exactly as the recovery code does today, call `Cancel` for the operations in the persisted operation list if one was written, run the finalizer steps where the restored PVCs are known from the volume information, and record `Cancelled`.
Work the dead process did not persist is recorded as unconfirmed: hooks have no tracker after a restart, and operations that were never written cannot be cancelled.
A `Cancelling` Restore never resumes normal processing after a restart, even if `spec.cancel` was cleared.
The same applies to the operations and finalizer controllers, which must not continue their normal progression on a Restore that records acceptance.

### 7. Deletion

A cancelled Restore is retained until a user deletes it; deletion then runs the existing path, which removes the Restore's files from object storage and relies on owner references and labels for its children.
A deletion request that arrives before acceptance wins, as in the RFC: the request controller treats a Restore with a deletion timestamp as terminal and rejects the cancellation request.
A deletion request that arrives after acceptance waits for `Cancelled`, so the wrap-up does not write artifacts the deletion is removing.

### 8. Supported modes for the first implementation

Items of every kind, pod volume restores, DataDownloads through the CSI data mover and plugin operations with an ID are supported from the start.
Native snapshot restores are supported with their unconfirmed path only.
In-place restore waits for the exposer verification in section 3.
Hooks follow section 3; the `Finalizing` checkpoint is included because the RFC allows cancellation in any non-terminal phase, although it changes little beyond the hook wait.

### Acceptance matrix

| Case | Required result |
|---|---|
| Request before validation | No validation or backup fetch; `Cancelled` with no artifacts and no `Cancelling` work |
| Request during an item group | The current item finishes; no further item or additional item starts; the resource list holds the processed part |
| Request while pod volume restores run | Their `spec.cancel` is set and the engine stops waiting; their final phases are their own, and the condition reports what was unconfirmed |
| Request while a DataDownload runs | `Cancel(operationID)` is called once; the DataDownload cancels and cleans up its own pod and PVC; the destination PVC remains |
| Request during a native snapshot call | Handling starts when the call returns; the volume it created remains |
| Request while hooks wait for pod readiness | They never start and are recorded as not executed |
| Request while a hook runs | The hook is not interrupted; its result is recorded if it arrives in time, otherwise it is unconfirmed |
| Request in `WaitingForPluginOperations` | Every remaining operation gets one `Cancel` call and a recorded outcome; no finalization beyond the volume-protecting steps |
| Request in `Finalizing` | PV patches, volume information and stub cleanup complete; the hook wait stops |
| Normal completion commits first | The request is too late; the terminal phase and timestamps stay |
| Stale phase writer after acceptance | It conflicts, re-reads, and defers to the wrap-up; `Cancelling` is never overwritten |
| Restart before acceptance | The Restore is not marked `Failed`; the wrap-up runs from persisted state |
| Restart during `Cancelling` | The wrap-up continues; recorded conditions are kept, missing state is unconfirmed |
| Deletion before acceptance | Deletion proceeds; the cancellation request is rejected |
| Deletion after acceptance | Deletion waits for `Cancelled` |
| In-place restore | Not supported until the exposer path is verified; the destination PV is never deleted |
| `describe`, `logs`, `download`, `--wait`, metrics | Show `Cancelled` and the conditions; never-created and failed-upload artifacts are distinguished; the counter increments once |

## Alternatives Considered

**A separate cancellation controller for Restore.**
Rejected, as in the RFC: the controller that owns the phase already has the reconcile, the client and the children, and acceptance at a checkpoint inside the engine keeps the ordering simple.

**Interrupting a running exec hook by closing its exec session.**
Rejected: a hook stopped halfway has its own side effects, and a retry after a restart would run it again; letting it finish within its own timeout is the predictable option.

**Skipping all finalizer steps on cancellation.**
Rejected: the PV reclaim policy patch and the volume information are what make a half-restored set of volumes safe to clean up by hand, and they are cheap and bounded.

**A `Cancelled` phase for item operations.**
Deferred: the operations controller already records a cancelled operation as failed with an explanatory error when it times out, and the first implementation reuses that; a dedicated phase can follow if `describe` output needs it.

**A bounded deadline for the Restore wrap-up.**
Deferred with the RFC; the wrap-up ends at explicit points, and every wait inside it is already bounded by existing timeouts.

## Security Considerations

Cancellation acts only on PodVolumeRestores and DataDownloads that carry this Restore's UID label and on operations recorded for this Restore; the Restore name alone is never used to select children.
It never deletes restored PVCs, PVs or destination data, and it never removes a PV the restore did not create.
Status messages are bounded and contain no credentials; metrics carry no per-Restore labels.
Permission to create a `RestoreCancellationRequest` is governed by the RFC.

## Compatibility

The phases, the `status.cancellation` block and the request CR come from the shared implementation and ship together with their CRD changes.
On the Restore side, `restore create --wait`, `restore logs`, `restore describe`, the download request controller's artifact check, the outcome metrics and the startup recovery code are updated to know `Cancelled`; an older CLI prints the phase as a string but its `--wait` loop would not stop on it, so matching CLI and server versions are required for the command.
Existing Restores are not affected until a request is created for them.
The optimistic-lock phase writes change the retry behavior of normal Restores only on real conflicts, where today's merge patch would silently overwrite.

## Implementation

1. After the shared slice lands: acceptance at the `New` and `InProgress` checkpoints, persistence of the processed results, resource list and operation list, child cancellation through the existing paths, the volume-protecting finalizer steps and `Cancelled`.
2. Acceptance in the operations and finalizer controllers, the conditions, and the Restore consumers listed under Compatibility.
3. Startup recovery changes and the restart cases of the acceptance matrix.
4. In-place restore verification, documentation and end-to-end tests.

Ruslan Shaydullin proposes to implement the Restore slices; the shared slice is coordinated with the backup contributors.
Timelines follow the RFC.

## Open Issues

- Condition names and `reason` values shared with the Backup design.
- Whether a cancellation request during `Finalizing` should wait for running exec hooks up to the resource timeout or stop the wait at once.
- Whether item operations need a `Cancelled` phase.
- The in-place restore exposer path.
- Whether the request controller rejects targets with a deletion timestamp, or the restore finalizer waits for `Cancelled`; this design assumes the first.

## Source References

The references pin the current behavior this design changes.

- [Restore phases `New` to `InProgress`](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/controller/restore_controller.go#L229-L254) and [the end of the run](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/controller/restore_controller.go#L749-L780) with the results, resource list and operation list writes.
- [Operations controller timeout cancel](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/controller/restore_operations_controller.go#L326-L338).
- [Finalizer tasks](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/controller/restore_finalizer_controller.go#L312-L331) and [the bounded hook wait](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/controller/restore_finalizer_controller.go#L636-L650).
- [Engine progress updates](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/restore.go#L789-L803), [resource loops](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/restore.go#L830-L914), [temporary ConfigMap cleanup](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/restore.go#L931-L939), [hook dispatch](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/restore.go#L2171-L2178), [pod volume restore goroutines](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/restore.go#L2311-L2345) and [the hook executor context](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/restore.go#L2346-L2397).
- [Native snapshot restore call](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/pv_restorer.go#L80).
- [Startup recovery of `InProgress` Restores](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/cmd/server/server.go#L1021-L1045), [DataDownload cancellation](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/cmd/server/server.go#L1088-L1128) and [PodVolumeRestore cancellation](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/cmd/server/server.go#L1170).
- [Merge patch helper without an optimistic lock](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/util/kube/client.go#L28-L31).
- [CSI PVC action `Cancel`](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/restore/actions/csi/pvc_action.go#L399) and [the `RestoreItemAction` v2 `Progress` and `Cancel` contract](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/plugin/velero/restoreitemaction/v2/restore_item_action.go#L55-L61).
- Child `spec.cancel` fields and phases: [PodVolumeRestore](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/apis/velero/v1/pod_volume_restore_type.go#L63), [DataDownload](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/apis/velero/v2alpha1/data_download_types.go#L60) with its [`Canceling`/`Canceled` phases](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/apis/velero/v2alpha1/data_download_types.go#L100-L101), and [PodVolumeBackup phases](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/apis/velero/v1/pod_volume_backup_types.go#L81-L82).
- Consumers of the phase set: [`restore create --wait`](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/cmd/cli/restore/create.go#L465-L466), [download artifact check](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/controller/download_request_controller.go#L281-L289) and [restore outcome metrics](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/metrics/metrics.go#L56-L61).
- [In-place restore PV retention and the error path that deletes the retained PV](https://github.com/velero-io/velero/blob/1342339994850613eb7f967eaa20e1149f6ddb6e/pkg/exposer/generic_restore.go#L551-L577).
