# Shared Backup/Restore cancellation contract and Restore integration

Status: proposal revised after Joeavaikath's [shared API](https://github.com/velero-io/velero/pull/10509#issuecomment-5639307429) and [bounded cancellation](https://github.com/velero-io/velero/pull/10509#issuecomment-5639336763) feedback; no API or implementation has been approved.
Related issues: [restore cancellation #9190](https://github.com/velero-io/velero/issues/9190) and [backup cancellation #2098](https://github.com/velero-io/velero/issues/2098).
Proposed Restore implementation contributor: Ruslan Shaydullin; Backup lifecycle and implementation ownership remain coordinated with the backup contributors.
The original restore request/direction belongs to Lyndon-Li and blackpiglet; sseago requested a unified design, and Joeavaikath supplied the shared field and completion contract used here.
Source audit: `cbd9059f8006211170e2ac9911221f1ea30d1082`; earlier diagnostic probes ran on `193cfdc58f9bddf43be6196a29512c8a2d7f175d`.
Codex assisted the investigation, fixtures and drafting; independent source/design reviews accompany this proposal, with evidence retained by the contributor.

## Abstract

Use a one-way `spec.cancel: true` field and a shared, bounded best-effort cancellation contract for Backup and Restore, retaining the parent object and available diagnostics.
Specify Restore integration under that contract: stop admitting new work, attempt cancellation where a usable mechanism exists, and reach `Canceled` by the cancellation deadline without claiming rollback or proven termination of every external effect.

## Background

In #9190, sseago distinguishes cancellation from deletion and asks that Backup and Restore use a unified API and behavior.
Joeavaikath's earlier [backup design #9284](https://github.com/velero-io/velero/pull/9284) proposed `Backup.spec.cancel`; that design and implementation #9320 closed without merge on February 26, 2026.
His current review favors the field over a request CR because per-attempt audit records and cancellation-specific caller RBAC are not established product requirements.
His completion model groups work by its state when cancellation arrives: not yet admitted, started without an effective cancellation path, or started with a usable asynchronous cancellation path.
The common API, race ordering and terminal meaning below apply to both parent kinds; the Restore sections provide this contribution's lifecycle details for joint review with the Backup design.
Backup-specific repository/snapshot cleanup does not authorize deleting already restored destination objects or data.

The current Restore controller performs synchronous work within Reconcile, while operations and finalizer controllers perform later work and metadata writes.
DataDownload (DD) and PodVolumeRestore (PVR) already expose cancellation, and startup recovery already fails stale InProgress Restores and requests child cancellation.
Three historical component probes demonstrated deferred delete reconciliation, missing explicit child coordination in the parent's delete branch, and continued real-engine item creation after a fake-API deletion request.
They are baseline Delete observations, not tests of this proposed API, real volume cancellation, restart or production data loss.

## Goals

- Give Backup and Restore the same cancellation intent, terminal-completion race and bounded best-effort user experience.
- Stop admitting further work and attempt supported cancellation while preserving parent identity, available diagnostics and existing destination storage.
- Recover durable cancellation after restart and prevent late normal writers from changing its terminal outcome.

## Non Goals

- Roll back restored objects/bytes, resume a canceled operation, or prove physical termination of unreachable provider/plugin work.
- Implement Backup cancellation in this PR, add a cancellation-request CR, or redesign third-party plugin interfaces.
- Automatically convert every Delete into cancellation; deletion of a parent with an already accepted cancellation is covered separately.

## High-Level Design

Clients set `spec.cancel: true` on the existing Backup or Restore, using identity and concurrency checks.
The responsible controller records acceptance and a fixed deadline in `status.cancellation`, closes admission and enters `Canceling` without waiting for the synchronous workqueue to become free.
It fences new work, signals participating local contexts, requests supported child/plugin cancellation and observes results only within the remaining budget.
It commits `Canceled` once work has settled or the deadline expires, retaining explicit residual/unknown outcomes instead of extending `Canceling` indefinitely.
Cancellation does not call DeleteRestore, remove the parent, or undo work already performed.

A successful spec patch means requested, not accepted or completed.
All normal writers must observe the same cancellation intent and use UID/resourceVersion-checked transitions, so they cannot commit ordinary completion after cancellation has won the race.
Durable status governs recovery; local execution tracking makes cancellation responsive but is not proof that remote work stopped.
Parent cancellation completion and eligibility for subsequent destructive deletion are separate states.

## Detailed Design

### Shared API and status

The field and status names below are proposed for joint Backup/Restore review, not implemented APIs.
The intent is the same for either kind:

```yaml
spec:
  cancel: true
```

`cancel` is an optional Boolean, with omission equivalent to false.
The supported transition is false/absent to true; repeated true is idempotent, and clearing it does not provide a resume operation.
A schema-valid object created with true is canceled before execution or runtime backup lookup; schema validation still applies to the create itself.
Admission must reject a subsequent true-to-false/unset transition at the feature's supported Kubernetes versions.
Velero currently advertises a Kubernetes compatibility floor that predates CEL validation, so this is an explicit implementation gate: agree a compatible admission mechanism or a feature version boundary before exposing the API.
Do not silently ship a CEL-only guarantee to older API servers or introduce a webhook/version-floor change without review.
The controller also latches accepted cancellation in status and must never resume because a stale or misconfigured writer cleared the flag.

The parent UID identifies the operation being canceled; there is no second object, request UID, per-invocation result, request retention policy or request-deletion lifecycle.
Proposed `status.cancellation` fields are `acceptedAt`, `deadline`, `completionTimestamp`, `reason` and a bounded set of `conditions`.
`acceptedAt` and `deadline` are written together once; the original deadline is not reset by duplicate requests, config changes, reconciliation or restart.
The parent's existing completion timestamp is set when `Canceled` is committed, never when intent is merely submitted.
Suggested completion reasons are `WorkSettled` and `DeadlineExceeded`; neither implies rollback.
Conditions summarize `AdmissionClosed`, `LocalWorkStopped`, `OperationsSettled`, `TemporaryResourcesCleaned` and `DiagnosticsPersisted`, with True/False/Unknown, reason, bounded message and transition time.
Only admission closure and completion of the bounded orchestration define the parent terminal contract; operation, cleanup, local-exit and diagnostic conditions may remain False or Unknown at `Canceled`.
Retain known operation IDs and residual details in the normal operation metadata where available, rather than an unbounded list in status or metric labels.
A missing handle is recorded as unavailable; it is not invented from a name or treated as successful cancellation.

| Parent state | Meaning |
|---|---|
| Non-terminal, `spec.cancel: true`, no acceptance | Cancellation requested; no acceptance/deadline has yet been committed |
| `Canceling` | Accepted, admission closed, bounded cancellation work is in progress |
| `Canceled` | Velero completed its bounded best-effort cancellation orchestration; residual effects and incomplete cleanup remain explicitly observable |
| An earlier terminal phase | Cancellation arrived too late; the original outcome and completion timestamp remain unchanged |

Both current Backup and Restore CRDs lack a status subresource.
This design retains their existing endpoint and uses conditional parent updates; controller ownership of cancellation status is a convention, not per-field RBAC isolation.
Adding a status subresource would be a separate compatibility change.
A shared status/transition helper can encode the common contract, while each kind supplies its phase set and operation adapters.
Backup phases must be classified from its own API rather than copied blindly from Restore; Finalizing and FinalizingPartiallyFailed are not terminal outcomes.

### CLI and authorization

The proposed commands are `velero restore cancel NAME` and the corresponding `velero backup cancel NAME` under the shared contract.
This contribution implements only the Restore side after design agreement; publishing a shared field does not authorize a nonfunctional Backup command.
The CLI reads the target, records its UID and resourceVersion, and conditionally patches only `spec.cancel` with both identity and concurrency preconditions.
On conflict, read again, require the same UID, and decide again; never cancel a replacement object that reused the name.
A missing target, unknown phase or already deleting target is reported without claiming cancellation acceptance.
A target already in a normal terminal phase is a no-op: do not patch it or rewrite its outcome.
A Canceling/Canceled target is reported as the existing operation, with its original deadline and any residual conditions.

After a write, read back the same UID and flag; an API-server acknowledgment is insufficient if an older schema pruned the field.
Print requested until the controller has committed acceptance; report the phase, acceptance/deadline and completion reason when available.
Proposed `--wait` observes the same UID until Canceled, a too-late normal terminal outcome, deletion/replacement, or a caller-side timeout.
A CLI timeout does not clear intent or extend the server deadline; print the target identity and current state for later inspection.
`Canceled` ends the wait even if operation/cleanup conditions are unresolved, and the CLI displays those warnings without presenting cancellation as a successful Backup/Restore.
No per-invocation audit trail is created; Kubernetes audit logging remains available according to cluster configuration.

The minimal caller role needs get and patch on the relevant parent resource; polling uses get and an optional watch implementation additionally needs watch.
This is broad parent mutation authority, not a cancellation-only permission; controller roles retain the permissions needed for the target and child operations.
Do not add patch rights to read-only roles, use caller-supplied identity annotations as authorization, or claim namespace/name/UID checks create field-level access control.

### Intent, acceptance and normal completion

Restore cancellable phases are empty/New, InProgress, WaitingForPluginOperations, WaitingForPluginOperationsPartiallyFailed, Finalizing and FinalizingPartiallyFailed.
Completed, PartiallyFailed, Failed and FailedValidation are normal terminal outcomes; Canceling/Canceled are handled idempotently.
Backup uses the same cancellable phases plus Queued and ReadyToStart, with the same four normal terminal outcomes; Backup Deleting is a delete-first state even before checking deletionTimestamp.
Unknown phases are not guessed to be cancellable.

The linearization point against normal terminal completion is the conditional intent write on a cancellable, non-deleting object.
If normal completion commits first, the CLI conflict/no-op path leaves that terminal outcome alone.
An arbitrary direct patch of true to an already terminal object also cannot create an accepted cancellation or rewrite its phase/timestamps.
If true commits first while the object is cancellable and non-deleting, every fresh normal phase writer must route it to cancellation acceptance instead of committing ordinary success, failure or finalization.
A stale normal writer must conflict and make that fresh decision, preserving both the flag and any existing cancellation status.
Acceptance is the controller's subsequent conditional update: verify UID/resourceVersion, require a cancellable non-deleting target and write Canceling with acceptedAt/deadline.
For Restore, that update also retains/adds its ExternalResourcesFinalizer; Backup's deletion protection belongs to its kind-specific lifecycle and does not use the Restore finalizer.
The time between intent and this update is visibly requested, not a false claim that the deadline has already begun.
If Delete has already acquired a deletionTimestamp before acceptance, the cancel request is not accepted and this initial design leaves delete-first behavior unchanged.

The current merge-patch helper retries the same snapshots and cannot enforce this contract by itself.
All participating writers need a scoped transition helper or equivalent using fresh reads, UID validation and resourceVersion preconditions, including validation/admission, synchronous completion, operations, finalization and startup recovery.
Counters and diagnostic patches must not replay stale phase, spec or cancellation fields; metrics reflect committed transitions rather than a losing writer's intent.
Admission checks cover pending true as well as accepted cancellation, including a create with true before the existing validateAndComplete/backup-fetch path.
An external call already admitted before the fence can still finish afterward; acceptance is not an instantaneous physical stop barrier.

### Deadline and operation classes

Propose a shared server `--cancellation-timeout` with a finite positive default of **1 minute**, subject to maintainer review and validation for supported deployments.
This is a proposed parent policy, not an existing Velero default or a reuse of child cancellation grace periods.
Persist `deadline = acceptedAt + timeout` at acceptance and schedule reconciliation for that deadline independently of long-running operations.
Each attempt, wait and diagnostic/cleanup operation uses the remaining budget; a retry or newly discovered operation never gets a new full timeout.
If all admitted work has settled and available cleanup/diagnostic outcomes are recorded earlier, complete with WorkSettled; otherwise complete with DeadlineExceeded when the budget is exhausted.
A non-interruptible call, unavailable child, missing ID, failed cleanup or failed object-store diagnostic upload cannot hold the parent in Canceling beyond that budget.
This bounds controller waiting while the controller and Kubernetes API are available; it cannot guarantee a persisted phase update during a server/API outage.
After an outage, an expired accepted deadline is finalized on recovery without starting a new grace period, recording unfinished attempts/uncertainty.

The following table applies Joeavaikath's operation classes to both workflows.
It describes proposed behavior rather than claiming every current path already implements it.

| State at cancellation | Backup examples | Restore examples | Shared behavior |
|---|---|---|---|
| Not yet admitted | Queued items, native snapshot call not invoked, New/Prepared PVB or DU | Unprocessed items, volume restore not invoked, New/Prepared PVR or DD | Fence admission; do not start that work |
| Started without an effective cancellation path | Inline work, native snapshot calls, hooks, object-store work, observable but non-cancelable CSI snapshot creation | Inline item/Kubernetes writes, plugin execution without a durable operation ID, native volume-from-snapshot calls, hooks, object-store work | Use available local signals, record uncertainty, and complete the parent by the deadline without rollback or waiting for proof of stop |
| Started async work with usable cancellation support | PVB/DU and item operations with a persisted ID and plugin-supported Cancel | PVR/DD and item operations with a persisted ID and plugin-supported Cancel | Request existing child spec.cancel or plugin Cancel; observe only within the remaining budget, then complete the parent |

An asynchronous operation whose ID was never durably persisted belongs to the second class at cancellation time, including after a crash.
A successful optional plugin Cancel can be a no-op; it is not proof that external work ended.
Child terminal states that won their own race are preserved rather than rewritten to Canceled.
At the deadline, the parent may be Canceled while children remain Canceling/InProgress or external operations continue; diagnostics must make that distinction explicit.
Existing child controllers may finish their own cancellation and cleanup afterward without reopening the parent or rewriting its terminal reason/deadline.

### Restore producers, callbacks and bounded coordination

Use a responsive cancellation observer/coordinator independent of the busy synchronous Restore workqueue, with namespace/UID-scoped execution tracking and a shared transition contract.
Register work before side effects and make a fresh authoritative admission check after registration, so an observer that ran before registration cannot miss the work permanently.
Close future producer admission for the UID, cancel participating contexts, and check the durable intent/state before every subsequent Velero-controlled work item, hook or external call.
Context cancellation does not itself acknowledge producer exit, and a returning old call must not start its next step after admission closes.
An unavailable authoritative check must not permit new work.
Thread cancellation through engine iteration, PVR waits, informer synchronization, hooks and relevant Kubernetes calls where the API supports it.
Keep execution identity through operations/finalization, since hooks can outlive the synchronous engine stage.
Observe acknowledgments and repeat child discovery to include late creations from calls admitted before the fence, but stop waiting at the parent deadline.
A late child found after completion can receive best-effort cancellation through its existing path; it does not restart the parent or extend its deadline.

The coordinator must not synchronously wait on a plugin Progress/Cancel method or native provider call whose API does not accept its context.
Use bounded per-UID and global execution capacity, track outstanding calls, and do not spawn an unbounded new goroutine on every reconcile.
At deadline, leave unreturned calls visible as unresolved; keep their capacity accounted for until they return or the owning process exits.
Unavailable capacity or an exhausted budget is an explicit NotAttempted/Unconfirmed outcome, not an unbounded queue ahead of the terminal update.
Do not kill a shared plugin process to cancel one Restore or pretend a context wrapper terminated its call.
The cancellation timer/status path must remain runnable when all cancellation-call workers are occupied.

Only agreed cancellation coordination, bounded diagnostics and safe cleanup may run after acceptance; ordinary operations/finalizer phase progression and restorative work stop.
Late local/remote results may be recorded as residual diagnostics by the designated owner without reopening Canceled, counting normal success, or restarting hooks/volume restoration.
Fence these writes by UID and lifecycle, including DownloadRequest-triggered operation uploads and name-keyed operation caches.
An already-issued object-store write may finish after terminal cancellation; that unresolved writer matters to subsequent deletion, not to the parent deadline.
Do not signal successful volume restoration merely to unblock a partially restored workload.

### Children, storage and diagnostics

Reuse DD/PVR spec.cancel and their actual worker/informer protocol, with namespace, owner UID and compatible historical identity checks.
The local microservice watcher's Cancel method alone currently only logs, so it is not a substitute for the real child cancellation path.
A child Canceled phase can precede cleanup; record operation and cleanup outcomes separately and preserve valid Completed/Failed child outcomes.
Never force-remove child finalizers or delete destination storage to manufacture cancellation completion.
For in-place restore, validate/fix preservation guards in the actual cancellation cleanup before enabling that fan-out: a temporary PVC can reference an existing destination PV.
If a cleanup/cancellation path cannot preserve that storage, do not invoke the destructive path; record it as unavailable and agree the supported mode boundary before implementation.
Skipping unsafe cleanup or exposing a residual resource must not turn into an indefinite parent Canceling state.

Preserve known operation IDs and attempt supported plugin cancellation; ambiguous replies and crash recovery do not imply exactly-once invocation.
Native CreateVolumeFromSnapshot has neither a context parameter nor an RIA operation ID; an admitted call can remain unresolved after the parent deadline.
Missing IDs/handles or provider confirmation are residual evidence, not reasons to invent termination acknowledgment or wait forever.

Retain the parent, its ordinary cleanup finalizer, available logs/results, resource/volume summaries and known operation metadata after standalone cancellation.
Use a separate bounded persistence context, since an already canceled work context cannot perform cancellation status/diagnostic work.
Try to persist partial execution and artifact availability, with one owner preventing late normal writes from erasing the cancellation result.
Failed optional uploads, unavailable operation-ID checkpoints and missing never-created artifacts must be represented accurately in status; none delays parent completion past deadline.
The small parent status update is still required to record Canceled, and an unavailable Kubernetes API is reported as a persistence outage rather than a completed state that was never written.
Before-start cancellation may legitimately have no object-store artifacts; logs/describe/download must distinguish that from failed persistence after execution.
Completed cancellation never means that all diagnostics were successfully saved.

### Delete, backup dependencies and restart

Cancellation retains the parent; deletion is a separately requested destructive operation.
For Delete after accepted cancellation, the finalizer waits for the parent terminal phase and for UID-scoped metadata writers to drain or an effective storage-write fence to prevent late writes.
This includes the independent cancellation persistence context, normal writers and DownloadRequest-triggered uploads.
Canceled alone is not a writer-drain signal: a synchronous object-store call admitted earlier may still return after the deadline.
Do not call DeleteRestore/remove its finalizer while that can recreate the metadata being deleted.
If safe deletion remains unverifiable, retain the finalizer with an explicit deletion blocker and operator guidance; the cancellation result stays terminal Canceled.
Do not force-finalize deletion, prolong the cancellation deadline, or promise bounded destructive deletion as part of this feature.
The finalizer installed at acceptance also protects cancel-before-start followed by Delete; deleting the parent before cancellation acceptance is covered by the delete-first ordering above.

Backup deletion also deletes dependent Restores, but currently removes backup snapshots/data and backup-store artifacts before it requests those Restore deletions.
Retaining only the Backup API object does not preserve those dependencies, and a Processed DeleteBackupRequest with errors is not automatically retried.
For accepted cancellation, coordinate required source/diagnostic dependencies before the first destructive backup-deletion action during the bounded cancellation window, or persist an independent description of them.
A point-in-time dependent-Restore list is not a sufficient ordering fence; the shared design needs explicit ownership/concurrency checks between acceptance and backup deletion.
Cancellation completion releases any hold whose only purpose was waiting for external operation outcomes; unconfirmed remote termination must not imply indefinite retention of source backup data under this cancellation contract.
Separate deletion safety checks for in-flight metadata writers still apply to the relevant prefixes and objects, and may visibly defer deletion.
If backup cleanup has already started or a dependency vanishes, record DependencyUnavailable and the best available cancellation attempt, then still complete by the deadline.
Do not infer rollback, successful resource cleanup or available diagnostics from a missing Backup.
The exact backup-deletion ordering/ownership and operator retry behavior need joint review; this Restore integration is not an implementation of Backup cancellation.

On restart, observe both non-terminal spec.cancel intent and accepted Canceling objects independently of the old synchronous worker.
A requested but unaccepted intent is accepted when possible; an accepted one uses its persisted deadline and never receives a new budget.
Startup stale-InProgress failure handling must defer to cancellation intent/status rather than overwrite it with Failed.
Reconstruct known children and durable operation handles, using only the remaining budget; unavailable handles/old hooks are Unknown.
A missing local registry or name-keyed hook tracker is not evidence that prior work exited.
Late callbacks, reused names, metrics and metadata cleanup must all verify UID and terminal ownership; do not authorize cleanup using a name-only label.

### Acceptance matrix

| Case | Required result |
|---|---|
| Create/New with cancel true | No execution or runtime backup lookup; accept and retain Canceled with accurate artifact absence |
| False/absent to true; repeat true; reset attempt | Intent set once; duplicate does not reset deadline; reset rejected by supported admission enforcement and never resumes an accepted cancellation |
| Stale client or reused name | UID/resourceVersion conflict, re-read same UID only; replacement untouched |
| Normal terminal commit before intent | CLI no-op; late direct patch cannot change original phase/timestamps |
| Intent commits before ordinary completion/failure | Stale writer conflicts; fresh writer routes to acceptance and cannot overwrite cancellation |
| Cancel any waiting/finalizing phase | Ordinary phase progression and new restorative work stop; bounded coordination continues |
| Already-deleting/unknown phase | No false acceptance or guessed transition |
| In-flight child creation or late call return | Rediscover/attempt child cancellation; no next work item, parent reopening or fresh grace period |
| Async cancel acknowledged before deadline | Preserve actual child outcome; complete early only when work has settled |
| Unsupported/untracked/plugin call never returns | Residual/Unknown or NotAttempted detail; Canceled by deadline, no unbounded worker spawning |
| Native provider call, hook or admitted write continues | Deadline completion does not claim termination/rollback; late results cannot resume work |
| Failed cleanup or diagnostic upload | Canceled by deadline with False/Unknown conditions; never manufacture successful cleanup/artifacts |
| Cancel then Delete / Delete then acceptance | Separate ordering; terminal cancellation can coexist with a visible deletion blocker |
| Operation download races cancellation/Delete | UID-owned upload obeys lifecycle fence; Delete waits for writer safety, not just Canceled |
| Backup deletion or missing dependencies | Respect bounded-window ordering, expose unavailable dependencies and residual effects; do not extend cancellation deadline |
| Restart before acceptance, during grace, after expiry | Recover durable intent; reuse deadline; expired cancellation finalizes without a new wait |
| Lost hook tracker or missing operation ID after crash | Unknown outcome; deadline still completes parent |
| Controller/API outage over deadline | No false persisted completion; finalize accepted expired cancellation on recovery |
| In-place full/incremental restore | No destructive cancellation cleanup of pre-existing storage; partial restored bytes remain possible |
| CLI wait/logs/describe/download and metrics | Canceled ends wait and is distinct from normal success; residual details/absent artifacts visible; committed outcome counted once |
| Unrelated parent or reused name | No collateral cancellation, status update or metadata cleanup |

## Alternatives Considered

### Separate cancellation-request CRs

A request CR provides a first-class per-attempt record and separate create permission, following an existing Velero request pattern.
Those benefits do not eliminate the hard cancellation work, and neither is an established requirement here.
Prefer the smaller target field as requested in review, avoiding duplicate-request handling, cross-object acceptance recovery, retention and request-deletion semantics.
Revisit a separate request API only if those product requirements are explicitly adopted.

### Remain Canceling until every outcome is proven

This preserves a stronger terminal interpretation but can wait indefinitely on plugins, providers, lost IDs or unreachable workers.
The selected contract is bounded best effort: parent termination is separate from residual operation/cleanup evidence and later deletion safety.
A timeout is not relabeled as proof of stop.

### Delete as cancellation or a fully asynchronous executor

Delete removes the record and conflicts with retaining cancellation results; automatic delete-first cancellation remains a follow-up scope decision.
A fully asynchronous executor could free the main workqueue, but requires broader concurrency/shutdown changes and does not remove the need for a durable deadline and fenced normal writers.
A responsive observer with shared transition logic is the narrower Restore integration proposed here; Backup should use the same contract with its appropriate controller arrangement.

## Security Considerations

Setting cancel requires parent mutation authority and can disrupt workloads; it is not harmless read-only access or a separate cancellation-only RBAC verb.
Use UID/resourceVersion preconditions and enforce one-way admission semantics at supported feature versions; do not present main-endpoint status as protected by /status RBAC.
Bound cancellation-call capacity, retries, status messages and diagnostics, omit secrets/provider credentials, and keep UIDs out of metric labels.
Validate ownership before cleanup, preserve destination backing storage, and retain visible uncertainty rather than performing unsafe cleanup to satisfy a deadline.

## Compatibility

Ship the spec/status additions, Canceling/Canceled phases, generated types/clients/CRDs and all relevant phase consumers as a coherent, feature-supported server/schema combination.
Use the common contract for Backup and Restore, but do not expose a kind's cancellation command/field as supported before that kind's controllers and storage adapters honor it.
The admission mechanism, shared enablement sequence and any feature-specific Kubernetes floor require maintainer agreement; the repository's older Kubernetes compatibility declaration is not evidence CEL rules work there.
No new CR kind, request controller or request RBAC is needed.

Review restore create --wait, cancel wait, logs/describe, downloads, phase metrics, deletion/finalization, startup recovery, serialization and tests.
Current logs/wait code enumerates phases; older CRDs omit cancel and reject new phase enum values, so a patch acknowledgment alone is not sufficient feature detection.
Feature support requires matched schema/server and an explicit capability/version check plus UID/flag/status readback in the new CLI.
An old CLI lacks cancel; older clients/servers can misinterpret the field and phases, and mixed-server rollout or downgrade safety must be validated before promising support.
Upgrading must not set cancellation on existing objects.

## Implementation

1. Agree this shared spec/status/race/deadline contract with Joeavaikath, sseago and the backup contributors, including admission enforcement, default timeout and version/enablement boundaries.
2. Implement the common identity/transition/deadline foundation and phase consumers; audit every normal writer and pending-intent path before exposing a command.
3. Integrate Restore observation, bounded producer/child/plugin coordination, diagnostics and restart recovery; resolve storage-preservation and Delete/backup-dependency ordering, coordinating with worker PRs #10264/#10327.
4. Coordinate Backup-specific adapters/cleanup and feature exposure with its contributors under the same accepted contract; do not design its terminal semantics independently.
5. Verify the matrix with API/manager/fake-clock tests, blocked plugin/late-writer cases and disposable data-mover/CSI installations before documenting a supported feature.

This PR changes a design document only; no runtime feature, schema or cancel command is implemented.
Historical probes are preserved as baseline evidence and have not been rerun or relabeled as cancellation verification.
Implementation effort and supported storage modes remain to be estimated after the joint API, admission and lifecycle decisions.

## Open Issues

- Confirm the proposed 1-minute configurable cancellation budget and shared status/condition names; the bounded terminal meaning is the selected proposal, not an unresolved strict-pending alternative.
- Select compatible one-way field admission enforcement and a feature version/enablement contract without silently raising Velero's advertised Kubernetes minimum.
- Agree Backup-specific operation adapters, repository/snapshot cleanup and joint implementation ownership under this shared API.
- Finalize bounded-window dependency ordering with backup deletion, writer-drain/fencing mechanisms for subsequent Delete, and operator retry guidance for blocked deletion.
- Validate in-place/data-mover cleanup preservation and third-party capability reporting for the first supported modes.

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
- [Backup phase enumeration](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/apis/velero/v1/backup_types.go#L296-L364), [Backup CRD endpoint](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/config/crd/v1/bases/velero.io_backups.yaml#L711), and [expected/tested Kubernetes compatibility](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/README.md#L55-L69).
- [Optional RIA Cancel semantics](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/plugin/velero/restoreitemaction/v2/restore_item_action.go#L57-L61) and [Progress/Cancel gRPC calls](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/plugin/framework/restoreitemaction/v2/restore_item_action_client.go#L137-L179).
- [Current child cancellation delays](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/data_upload_controller.go#L64-L65), [watcher Cancel](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/datapath/micro_service_watcher.go#L419-L421), and [DD Canceled transition before cleanup](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/controller/data_download_controller.go#L575-L601).
- [In-place cleanup preservation surface](https://github.com/velero-io/velero/blob/cbd9059f8006211170e2ac9911221f1ea30d1082/pkg/exposer/generic_restore.go#L507-L508) and [Kubernetes transition-rule support/immutability guidance](https://kubernetes.io/blog/2022/09/29/enforce-immutability-using-cel/).
