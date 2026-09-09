# Explicit cancellation of Restores

Status: proposal for discussion, revised after [sseago's feedback](https://github.com/velero-io/velero/issues/9190#issuecomment-5602961803); no API or implementation has been approved.
Related issues: [restore cancellation #9190](https://github.com/velero-io/velero/issues/9190) and [backup cancellation #2098](https://github.com/velero-io/velero/issues/2098).
Proposed implementation contributor: Ruslan Shaydullin; a design reviewer has not yet committed.
The original restore request/direction belongs to Lyndon-Li and blackpiglet; sseago supplied the explicit-cancellation and shared-API direction.
Source audit: `cbd9059f8006211170e2ac9911221f1ea30d1082`; earlier diagnostic probes ran on `193cfdc58f9bddf43be6196a29512c8a2d7f175d`.
The intervening changes update gRPC and version-priority line-ending parsing; the audited cancellation and phase-writing paths are unchanged.
Codex assisted the investigation, fixtures and drafting; independent source audits accompany this proposal, with review evidence retained by the contributor.

## Abstract

Introduce explicit cancellation of a non-terminal Restore while retaining its object and available diagnostic metadata.
Use an API pattern compatible with future backup cancellation, stop further restore work, and report cancellation honestly without rolling back restored resources or data.

## Background

In #9190, sseago asks for cancellation as an operation distinct from deleting a Restore, with eventual APIs similar to backup cancellation.
In [#2098](https://github.com/velero-io/velero/issues/2098#issuecomment-2634886944), an explicit spec field or a cancellation-request CR was discussed; later discussion favors preserving the object and using a distinct terminal [Canceled phase](https://github.com/velero-io/velero/issues/2098#issuecomment-2640290422).
[Terminal backups remain unchanged when cancellation arrives too late](https://github.com/velero-io/velero/issues/2098#issuecomment-3211169866).
These provide design direction; the exact shared API is still to be agreed with the backup contributors.
Joeavaikath's later [backup design #9284](https://github.com/velero-io/velero/pull/9284) proposed `Backup.spec.cancel`; that design and [implementation #9320](https://github.com/velero-io/velero/pull/9320) closed without merge on February 26, 2026.
Their review discusses [keeping cancellation in the existing state machine](https://github.com/velero-io/velero/pull/9284#discussion_r2430934181), [waiting for synchronous actions to complete or time out](https://github.com/velero-io/velero/pull/9284#discussion_r2430951752), and alternatives for unconfirmed asynchronous cancellation.
The earlier request-CR discussion is therefore not an accepted shared API; this proposal must resolve the later spec-field and controller-ownership feedback with those contributors before implementation.
Backup data deletion in that discussion must not be applied to already restored destination data.

The current Restore controller runs the restore synchronously within Reconcile, while independent operations and finalizer controllers perform later work and metadata writes.
DataDownload and PodVolumeRestore already expose cancellation, and server startup already fails stale InProgress Restores and requests child cancellation.
Three earlier component probes demonstrated deferred delete reconciliation, lack of explicit child coordination in the parent's delete branch, and continued real-engine item creation after a fake-API deletion request.
Those tests describe existing Delete behavior; they do not test the API proposed here, real volume cancellation, Kubernetes GC, restart, or production data loss.

## Goals

- Provide an explicit, observable cancellation operation with a shared backup/restore API convention and an unambiguous completion race.
- Stop participating producers and coordinate owned operations and cleanup while preserving Restore identity, diagnostics and destination storage.
- Recover an accepted cancellation after process restart and prevent late normal writers from undoing its outcome.

## Non Goals

- Roll back already restored Kubernetes objects or bytes, resume a canceled Restore, or guarantee instantaneous physical termination across a partition.
- Implement backup cancellation in this change, replace child cancellation protocols, or redesign the plugin interface.
- Make deletion of every running Restore automatically request cancellation in this first implementation; concurrent deletion of an already accepted cancellation is covered below.

## High-Level Design

The preferred proposal is a namespaced `RestoreCancellationRequest` with an immutable target name and UID, accompanied by a `velero restore cancel NAME` command.
The server accepts a request by a conditional update on the target Restore that records durable cancellation identity/time, installs its existing cleanup finalizer if necessary, and changes its phase to proposed `Canceling`.
A coordinator independent of the busy Restore workqueue stops local producers, coordinates child/plugin outcomes and required temporary-resource cleanup, persists available diagnostics, and finally records proposed `Canceled`.
Standalone cancellation does not invoke DeleteRestore or remove the Restore object, diagnostic metadata, or its ordinary external-resources finalizer.

Request creation and cancellation acceptance are different events.
All normal phase writers and the cancellation coordinator use the same UID/resourceVersion-checked transition contract, so normal terminal completion and cancellation acceptance have one ordering point.
The in-memory execution registry makes cancellation responsive; the persisted Restore record makes it recoverable.
Normal restore concurrency remains bounded by the existing worker limits.

## Detailed Design

### API proposal and backup alignment

The following names and shapes are proposed for review, not existing API.
A future `BackupCancellationRequest` should use the same target-identity, request-outcome and terminal-race conventions; backup repository/snapshot cleanup remains its own design.
The backup issue is assigned to other contributors, so agreement on this shared pattern does not transfer that implementation to this contribution.

```yaml
apiVersion: velero.io/v1
kind: RestoreCancellationRequest
metadata:
  generateName: restore-cancel-
  namespace: velero
spec:
  target:
    name: restore-example
    uid: 5b857595-d70d-4f06-afb7-aa87c775c613
```

The example UID is illustrative; the CLI reads the real Restore UID immediately before creating the request.
The target is always in the request's namespace, both target fields are required and nonempty, and the entire spec is immutable through CRD validation.
Validate that the chosen immutability mechanism works at Velero's supported Kubernetes minimum before publishing the schema.
The controller verifies the live UID before every target transition; a same-name replacement is never retargeted.

| Object | Proposed state | Meaning |
|---|---|---|
| Request | New (including empty) | Submitted; the target has not necessarily accepted cancellation |
| Request | InProgress | Its UID-matched target accepted cancellation or this request joined an accepted cancellation |
| Request | Completed | Target reached Canceled under the contract below, or was already Canceled |
| Request | Failed | Definitive rejection: TargetNotFound, TargetUIDMismatch, AlreadyTerminal, AlreadyDeleting or UnsupportedPhase; TargetLost means the result became unverifiable after acceptance |
| Restore | Canceling | Cancellation was durably accepted; normal work must stop, required outcomes are still being reconciled |
| Restore | Canceled | Producer and supported-operation/cleanup barriers completed; partial results remain available |

Request status proposes `phase`, `reason`, `message`, `acceptedAt` and `completionTimestamp`.
The new request CR has a status subresource: client-supplied status on create is ignored, and only the controller writes its result.
Invalid or missing required spec fields are rejected by the API server; transient API errors are retried and do not become a definitive request Failed result.
If an accepted target disappears or is replaced before a terminal result is observed, a surviving request reports Failed/TargetLost with its acceptedAt retained; this means its outcome is unknown, not that external work stopped or the Restore became Failed.
Never retarget a replacement or infer success from absence.
A blocked accepted cancellation whose target still exists stays InProgress with a concrete reason; it must not become Completed merely because a timer expired.

Restore status proposes `cancellation` containing `requestUID`, `acceptedAt`, `completionTimestamp` and bounded `conditions` for ProducersStopped, OperationsSettled, TemporaryResourcesCleaned and DiagnosticsPersisted.
The stored request UID is the identity of the first accepted logical cancellation; subsequent requests observe that same operation.
Conditions carry normal True/False/Unknown, reason, message and transition time; they describe observations rather than unbounded lists of child objects.
The existing Restore completion timestamp is set only when Canceled is committed, not when cancellation is requested.

Current Restore has no status subresource.
This proposal preserves that existing endpoint and uses conditional whole-object updates for the relevant status/finalizer transitions; introducing a Restore status subresource would require a separate compatibility decision.
Write request acceptance only after the parent commit; a crash between these writes is repaired from the durable parent marker.
All controller code sharing these transitions must use fresh reads and concurrency preconditions as described below.

### CLI, authorization and request lifecycle

`velero restore cancel NAME` reads the target, creates a UID-bound request and prints that submission is pending; an API create acknowledgment is not reported as completed cancellation.
Proposed `--wait` observes the request and UID-matched Restore until Completed, definitive Failed, or the caller's wait timeout.
A CLI timeout leaves server cancellation running; it must print the request identity so the operator can inspect the outcome later.
Repeated CLI invocations may create separate request records, but they join one target cancellation.
The CLI can poll the UID-matched Restore with get when its request disappears; a watch-based fallback additionally requires watch on restores.
Request/get/describe output must show the actual request result and the target's phase without requiring users to infer success from deletion.

Creating a cancellation request grants cancellation capability for any Restore in that namespace.
It does not provide per-object authorization simply because the target has a UID.
The minimal caller role needs get on restores and create/get/watch on restorecancellationrequests; it does not need Restore update, patch or delete.
Controller roles add request list/watch/status permissions and the existing target/child permissions required by the lifecycle.
Do not grant request creation to default read-only roles; cluster administrators must explicitly choose the namespace-wide cancellation capability.
A supplied username/annotation is not a trustworthy caller identity and must not be used for an impersonated authorization check.

Deleting a request before acceptance may withdraw that unaccepted submission; the controller must re-read it with no deletionTimestamp before attempting acceptance.
Deletion can still race that read and acceptance on another object, so withdrawing a request is not a guaranteed cancellation-of-cancellation API.
After acceptance, deleting the request never resumes work: Restore.status.cancellation is authoritative, and the coordinator also watches Canceling Restores directly.
Request records need no finalizer to keep an accepted cancellation alive.
This initial proposal leaves completed request retention to the operator, instead of adding a new automatic TTL policy.

### Acceptance and the completion race

Treat empty phase, New, InProgress, WaitingForPluginOperations, WaitingForPluginOperationsPartiallyFailed, Finalizing and FinalizingPartiallyFailed as cancellable.
Completed, PartiallyFailed, Failed and FailedValidation are existing terminal outcomes and remain unchanged when an unaccepted cancellation is too late.
A target already Canceled completes a new UID-matched request with reason AlreadyCanceled; a target Canceling joins its existing cancellation.
An unknown phase is rejected explicitly rather than guessed to be cancellable.

Acceptance is a single optimistic update of the freshly read Restore: verify UID/resourceVersion, require a cancellable phase and no deletionTimestamp, retain/add ExternalResourcesFinalizer, and atomically write Canceling plus the cancellation record.
Normal completion and acceptance must use this same conditional update discipline.
If normal terminal completion commits first, request processing observes AlreadyTerminal and does not mutate the Restore.
If cancellation acceptance commits first, any old completion, validation-failure, finalization or startup-failure write must conflict and then preserve Canceling when it re-reads.

The current PatchResource helper uses a plain merge patch; its retry helper repeats the same snapshots.
It is therefore insufficient to add conditional writes only in the new coordinator.
Introduce a scoped Restore-transition helper or equivalent at every participating writer, with UID checks, resourceVersion preconditions and a fresh decision on each retry; do not blindly replay stale normal status.
This includes initial admission/validation, synchronous restore completion, plugin-operation phase updates, finalization and startup recovery.
Ordinary counters and diagnostic patches also need to avoid replaying a stale phase or cancellation record.

The ordering point governs the recorded outcome, not an impossible instantaneous barrier on all external side effects.
A resource request already in flight may finish after acceptance.
The completed ProducersStopped condition is the boundary after which participating local producers must not initiate further restore work.

### Stop producers and coordinate existing controllers

Register work under namespace/Restore UID before side effects, then make a fresh authoritative state check after registration.
This closes the case where the cancellation observer saw the request before the producer registered.
The observer cancels active contexts and prevents new registrations for an accepted cancellation; context cancellation alone is not acknowledgment that work exited.
Thread the context through engine iteration, PVR waits, informer synchronization, restore hooks, relevant Kubernetes calls and server/leader shutdown.
Keep the per-UID execution registry entry and hook cancellation/acknowledgment alive through operations and finalization; hooks can outlive the synchronous engine stage.
Wait for participating work to acknowledge completion and repeat dependent-operation discovery after this barrier to capture late creations from previously admitted calls.
Use a separate bounded reconciliation/persistence context for cancellation coordination, child patches and diagnostics; an already canceled work context cannot perform that cleanup.
Do not terminate a shared plugin process to stop one Restore, and do not assume a wrapper context interrupts plugin methods that accept no context.

The operations and restore-finalizer controllers must stop new restorative work and ordinary phase progression after cancellation wins.
Allow only the agreed cancellation cleanup and diagnostic-persistence paths, under coordinated writer ownership.
The DownloadRequest controller is also a writer: requesting RestoreItemOperations can flush the in-memory operation map to object storage.
Include that upload path in UID validation, persistence ownership and the deletion drain; reviewing its phase eligibility alone is insufficient.
Persist partial resource/volume information and known operation IDs even when the synchronous engine exits by cancellation; do not lose them through an early-return path.
Do not complete normal restore hooks or signal successful volume restoration merely to unblock destination pods.
The recovery implications for partially restored workloads must be documented.

### Children, plugins, storage and completion

Reuse DD/PVR spec.cancel and their actual worker/informer handshake, preserving namespace, owner UID and compatible historical child identity checks.
Completed or Failed children that won their own race remain valid terminal outcomes; do not rewrite all children to Canceled.
The local microservice watcher Cancel method alone is insufficient because that method currently only logs.

A child Canceled phase can precede best-effort temporary-resource cleanup.
Require both the agreed operation result and observed safe cleanup for owned temporary resources; a terminal CR alone is not that evidence.
Reconcile failed cleanup rather than forcibly removing child finalizers or releasing local watchers to manufacture completion.
For supported in-place modes, verify existing destination PV/PVC ownership and preservation before enabling cancellation: the current generic cleanup can act on a temporary PVC bound to an existing target PV.
Any missing preservation guard is an implementation prerequisite or an explicitly agreed unsupported-mode boundary, not a reproduced claim of data loss.

Preserve every known plugin operation ID and request best-effort cancellation using its existing contract.
A successful optional Cancel call is not proof of termination; unknown or unsupported results stay explicit.
The engine currently learns the operation ID after Execute returns and persists its operation list after the synchronous stage.
External work that starts before an ID is durably recorded cannot be guaranteed recoverable after a crash without another plugin/persistence contract.
Retry behavior must account for ambiguous results and process crashes; exactly-once Cancel invocation is not promised.
Native snapshot restores also call `VolumeSnapshotter.CreateVolumeFromSnapshot` synchronously, without a context or RIA operation ID.
Fence admission before that call and include the call's return in producer acknowledgment; context cancellation cannot interrupt it or prove the provider operation ended.
After an ambiguous call outcome or crash, retain the unresolved outcome until the supported provider contract supplies evidence, or explicitly exclude that mode from the initial guarantee.

The proposed conservative completion policy keeps Restore Canceling and requests InProgress while producer acknowledgment, relevant operation termination, storage preservation or required cleanup is unresolved.
A diagnostic deadline can expose a blocked condition and operator guidance, but does not automatically declare Canceled or force deletion.
The deadline source/default and manual recovery guidance must be agreed before implementation; existing child cancellation grace periods are not automatically a new parent deadline.
This can leave an unavailable-worker/plugin case pending indefinitely, so maintainers must explicitly accept the tradeoff or choose a visibly weaker bounded outcome.
Canceled means the agreed control-plane and supported-operation contract completed; it is not a guarantee of physical process termination on an unreachable node or of rollback.

Retain the Restore object, its normal cleanup finalizer, available logs, results, resource/volume summaries and operation metadata after standalone cancellation.
Serialize final diagnostic persistence so a late normal writer cannot erase the cancellation outcome.
For a Restore canceled before starting, there may be no object-store artifacts; represent that absence accurately instead of blocking on files that never existed.
Persist durable execution/artifact availability information so download and CLI consumers can distinguish never-started work from a failed upload.
A required operation-ID checkpoint failure blocks accounting for external work; an optional log upload failure must be reported without claiming logs exist.
For partially executed work, the exact mandatory diagnostic set and handling of optional upload failures must be agreed before implementation; required persistence failures remain visible and retryable.

### Delete interaction and restart

If Delete wins before acceptance, reject the explicit request as AlreadyDeleting without rewriting the deleting Restore's outcome.
Automatic cancellation for every pre-existing delete-first path is a separate scope decision.
If cancellation was accepted first, the existing Restore deletion branch must wait for committed Canceled, including the agreed terminal diagnostic-persistence outcome and acknowledgment that every diagnostic/operation-metadata writer has exited, before calling DeleteRestore or removing its finalizer.
The separate persistence context must be drained too; no cancellation or normal writer may upload metadata after deletion begins.
A separate Delete can therefore remove a canceled record later; cancellation alone never does so.
The finalizer installed atomically at acceptance also covers cancel-before-start followed immediately by Delete.
This cancellation-first/delete-second protection is required in the first change because otherwise ordinary deletion can erase metadata the accepted coordinator still needs.

Restore deletion can also originate from the backup-deletion controller, which deletes Restores referencing the Backup and waits for them to disappear.
Today that controller removes backup snapshots/data and object-store backup artifacts before requesting Restore deletion; it deletes the Backup API object only after the Restore wait succeeds without errors.
An unresolved Canceling Restore could exhaust that wait and leave a DeleteBackupRequest Processed with errors after destructive backup cleanup has already happened.
Processed deletion requests are not automatically retried by that controller.
Retaining the Backup API object alone therefore does not preserve the dependencies needed by cancellation.
For the cancellation-first case, the preferred requirement is to preserve required backup data, identity/location information and diagnostic dependencies until the agreed cancellation and persistence barriers complete, coordinating before the first destructive backup-deletion action.
Retain the dependencies needed to settle admitted operations or provide an agreed durable independent source; backup artifact deletion and Restore diagnostic-prefix deletion are separate operations.
This requires an agreed ordering mechanism between cancellation acceptance and backup deletion; a point-in-time list of dependent Restores is not a sufficient race fence.
If backup deletion has already begun or required backup information disappears independently, expose the unavailable dependency and unresolved outcome instead of inferring Canceled or taking a missing-backup finalization shortcut.
The admission outcome, retained metadata and operator handling of these orderings must be agreed before implementation; the necessary backup-deletion integration is a Restore cancellation prerequisite, not an implementation of backup cancellation.

After restart, scan accepted Canceling Restores independently of whether their original request CR still exists.
Reuse current DD/PVR startup handling, but do not let the existing stale-InProgress-to-Failed path overwrite an accepted cancellation.
Persist acceptedAt rather than restarting elapsed-time diagnostics from zero.
An empty local registry after restart or leader change is not proof that remote work stopped; reconstruct known children/operation metadata and retain unresolved evidence.
Old workers and callbacks must pass identity/state fences before updating outcomes.
Validate RestoreUID on name-keyed operation-cache entries; do not use a restore-name label alone to authorize cleanup of temporary resources after a name is reused.
The current hook tracker is also name-keyed and reports complete when no tracker exists.
Neither a missing tracker after restart nor a same-name entry supplies UID-specific acknowledgment that an old hook finished; recovery must preserve that uncertainty until the agreed hook outcome can be established.

### Compatibility and acceptance matrix

| Case | Required result |
|---|---|
| Cancel New before any work | No producer starts after its admission check; Canceled retains the record; absent logs are reported as absent |
| Request UID differs from live target | Definitive rejection; replacement Restore untouched |
| Normal completion versus acceptance | Conditional update winner determines terminal no-op or Canceling; stale loser cannot overwrite |
| Cancel every waiting/finalizing phase | Ordinary work/writes stop; only agreed cleanup/diagnostic paths continue |
| In-flight child creation | ProducersStopped waits for acknowledgment; repeat discovery includes the late child |
| Duplicate requests or deleted accepted request | One logical target cancellation continues; deletion of a request cannot resume restore |
| Child completes before cancel patch | Preserve its terminal result and still verify required cleanup |
| Plugin unsupported, unavailable or untracked | Explicit unresolved outcome; no invented termination acknowledgment |
| Native snapshot call admitted before cancellation | Wait for the supported call/outcome acknowledgment; an ambiguous provider result remains unresolved |
| Cancel then Delete / Delete then cancel | Respect both orderings; drain diagnostic writers too, with no late metadata recreation after deletion |
| Operation download races cancellation or Delete | Fence the DownloadRequest-triggered upload by UID and drain it before deleting metadata |
| Backup deletion while cancellation is unresolved | Apply the agreed ordering before destructive backup cleanup; expose defer/failure or unavailable dependencies without false Canceled or silent diagnostic loss |
| Restart around every acceptance/completion write | Durable cancellation survives; no stale Failed/Completed overwrite or renewed producer admission |
| Restart loses hook tracker or a name is reused | Missing/name-only hook state cannot acknowledge the prior Restore's producers |
| In-place full/incremental and destination volumes | Preserve pre-existing storage; partial restored bytes remain possible |
| CLI wait/logs/describe/download | Canceled is recognized; supported diagnostics remain accessible; before-start absence is distinguished |
| Phase metrics race normal completion and cancellation | Count committed outcomes once; a losing normal transition cannot report successful completion |
| Another Restore or reused name | No collateral cancellation, phase update or metadata cleanup |

## Alternatives Considered

### Restore.spec.cancel

This matches existing child flags and needs fewer resource types.
It also matches the closed backup design #9284 and remains a concrete shared-API candidate, not merely a hypothetical alternative.
It grants cancellation through broad Restore update/patch capability, has no separate request result for a too-late call, and requires explicit irreversible false-to-true semantics and UID/resourceVersion preconditions in the client.
It remains a valid alternative if backup maintainers prefer it; request CRs are preferred here for separate permissions/results and the existing backup discussion.
The coordination and writer-fencing requirements remain the same with either API.

### Delete as the cancellation API

This removes the record/results by design and conflicts with the requested explicit-cancellation semantics.
Delete may later compose with cancellation internally, but must not define the user-facing cancellation operation.

### A fully asynchronous Restore executor

This can free the main workqueue but requires broader concurrency, shutdown and recovery redesign.
The independent coordinator/registry is the narrower preferred proposal; neither approach avoids durable state and writer fencing.

## Security Considerations

Treat request creation as an explicit namespace-wide cancellation permission, not harmless read-only access.
Require target namespace/name/UID checks and immutable request spec; protect controller-owned request status through its status subresource.
Respect current Restore RBAC and do not claim that its existing main endpoint offers per-field status isolation.
Use bounded messages that omit plugin credentials and secrets, keep request/Restore UIDs out of metric labels, and validate ownership before temporary-resource cleanup.
Preserving destination backing storage is required even when a temporary object's name looks disposable.

## Compatibility

Add CRD/scheme/generated-client/deepcopy/RBAC/install changes, the two proposed Restore phase values and every affected phase consumer as one coherent rollout.
Current consumers needing explicit review include restore create --wait, logs/describe output, download-request eligibility, phase metrics, normal and cancellation finalizers, startup recovery, serialization and tests.
Current logs CLI excludes new phases; create --wait enumerates terminal states; download eligibility currently distinguishes New/FailedValidation but cannot by phase alone distinguish canceled-before-start artifacts.
Do not announce a supported API with only some server components respecting cancellation.

Use the upgraded schema and a fully upgraded Velero server for this feature; an old CLI has no cancel command and older phase consumers may misinterpret new states.
An older Restore CRD explicitly rejects Canceling/Canceled phase writes because its phase enum lacks those values; update the CRD before the server uses them.
Do not claim a rolling mixed-controller or downgrade combination is safe without validation.
The first implementation needs an agreed supported-version/rollout contract and version-consistent installation manifests.
No existing Restore is canceled merely by upgrading.

## Implementation

1. Agree the request-CR preference with the backup contributors and a reviewer, the terminal/unknown-operation contract, supported storage modes and rollout boundary.
2. Implement the API plus identity/conditional-transition foundation, including all normal writers and cancellation-first deletion protection, without exposing a partially functioning cancel command.
3. Integrate the observer/context/registry, child/plugin coordination, diagnostics and restart recovery; resolve confirmed storage-preservation prerequisites and coordinate adjacent worker PRs #10264/#10327.
4. Add the command and phase consumers, then verify the acceptance matrix against real API/manager tests and disposable data-mover/CSI installations before documenting the feature as supported.

Only a design document is being prepared now; no feature implementation or API schema has been committed.
The earlier 4–8 focused engineering-week estimate is provisional and must be revisited after the API, storage and unknown-plugin decisions, excluding review latency.
Prior diagnostic tests are preserved as baseline evidence; they have not been rerun or relabeled as explicit-cancel verification.

## Open Issues

- Do the backup contributors and reviewers prefer the proposed matching cancellation-request CRs or matching spec.cancel fields?
- Is strict pending-on-unknown acceptable, or what explicitly weaker timeout outcome and recovery procedure should be exposed?
- Which in-place/data-mover modes and third-party plugin outcomes can meet the initial completion contract?
- What diagnostic deadline, request retention, user-facing condition details and rollout/version guarantees should be finalized before implementation?
- How should cancellation acceptance and backup deletion order their work to retain required dependencies, and what defer/retry or Processed-with-errors outcome should operators see when cancellation is unresolved or backup cleanup has already begun?
- Who can review the shared API and the cross-controller implementation, and should automatic delete-first cancellation be a separately reviewed follow-up?

## Source References

The following references pin the current behavior being changed, rather than describe an implemented cancellation API.

- [Restore phases](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/apis/velero/v1/restore_types.go#L282-L335) and [CRD without a status subresource](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/config/crd/v1/bases/velero.io_restores.yaml#L629-L631).
- [Current merge-patch retry helper](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/util/kube/client.go#L28-L44) and [primary phase writes](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/restore_controller.go#L240-L295).
- [Operations controller](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/restore_operations_controller.go#L205-L350) and [finalizer phase writes](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/restore_finalizer_controller.go#L243-L255).
- [Hook context lifetime](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/restore/restore.go#L2319-L2363) and [startup failure recovery](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/cmd/server/server.go#L1020-L1042).
- [CLI terminal wait](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/cmd/cli/restore/create.go#L465-L466) and [download artifact eligibility](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/download_request_controller.go#L280-L287).
- [Download-triggered operation upload](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/download_request_controller.go#L221-L226) and [name-keyed operation flush](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/itemoperationmap/restore_operation_map.go#L99-L113).
- [Native snapshot restore call](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/restore/pv_restorer.go#L71-L100) and [absent-hook completion](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/internal/hook/hook_tracker.go#L231-L238).
- [Backup cleanup before Restore deletion and its final request outcome](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/backup_deletion_controller.go#L265-L445).
