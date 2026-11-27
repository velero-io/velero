# Unified Backup and Restore cancellation

Status: proposed.

## Abstract

Let users cancel a Backup or Restore while retaining its API object and available diagnostics for inspection.

## Background

Velero has no unified way to cancel an in-progress Backup or Restore while keeping the object for later inspection.
Deletion alone cannot serve this purpose: it removes the object and eventually its diagnostics.
The existing Backup deletion controller rejects Backups tracked as in progress rather than stopping their execution.
This proposal defines a single cancellation model shared by both Backup and Restore, building on the prior discussion in [#9284](https://github.com/velero-io/velero/pull/9284) and [#10509](https://github.com/velero-io/velero/pull/10509).

## Terminology

| Term | Meaning |
|---|---|
| **Cancellation request** | The user's intent. A request does not mean cancellation has been accepted. |
| **Cancellation acceptance** | The workflow owner commits to cancellation by recording `Cancelling` and the acceptance time, then begins wrapping up. Normal processing must not resume afterward. |
| **Cancellation handling** | Work performed after acceptance: stopping normal processing and attempting to cancel running work. |
| **Terminal phase** | A phase that marks a Backup or Restore as finished, including `Cancelled`. External work may still be running. |

## Goals

- Let users cancel a Backup or Restore in any non-terminal phase while retaining the object and its available diagnostics.
- Provide one consistent cancellation model, phase set, and status shape across both Backup and Restore.

## Non Goals

- Rolling back changes already made by a Backup or Restore before cancellation.
- Guaranteeing that all external work, such as snapshots, uploads, or provider operations, has stopped when a resource reaches `Cancelled`.
- Adding a status subresource or separate status protection for cancellation.

## High-Level Design

Cancellation introduces two new phases, `Cancelling` and `Cancelled`, shared by Backup and Restore.
A user requests cancellation by creating a durable `BackupCancellationRequest` or `RestoreCancellationRequest` CR that names the target.
A request controller binds the request to the target and sets the target's internal `spec.cancel` signal; it does not itself accept cancellation.
The controller that currently owns the Backup or Restore observes the signal and accepts it by recording `Cancelling` and the acceptance time together, then begins wrapping up work.
Acceptance is the workflow owner's responsibility; requesting cancellation alone does not accept it.

After acceptance, Velero starts no new normal work, attempts to cancel work already underway, and drives the single transition to `Cancelled`.
The workflow controller that accepted the request retains ownership of cancellation handling; child controllers continue to cancel their own resources, acting only on children that belong to the correct parent by namespace and UID.
Cancellation is best-effort: `Cancelled` means Velero has finished its cancellation handling, not that all external work has stopped.
A new `status.cancellation` block records the acceptance time, the reason handling ended, and conditions describing progress and any unfinished or unconfirmed work.
By default the cancelled object and its diagnostics are retained for inspection.

## Detailed Design

This design defines the cancellation model, phases, status shape, and shared controller rules common to both workflows.
Workflow-specific behavior is deferred to the in-depth Backup and Restore cancellation designs, as summarized under [Workflow-specific requirements](#7-workflow-specific-requirements).

### 1. Requesting cancellation

A user requests cancellation by creating a `BackupCancellationRequest` or `RestoreCancellationRequest` CR.
It names the target and may supply cancellation-specific configuration, while its status retains a history of the request and its outcome.

```yaml
apiVersion: velero.io/v1
kind: BackupCancellationRequest
metadata:
  generateName: cancel-nightly-
spec:
  backupName: nightly
```

The request controller resolves the target, records its UID on the request, and labels the request with the target name and UID.
It may reject an absent or already-terminal target and deduplicates concurrent requests for the same target UID so a single request drives the outcome.
It sets the target's internal `spec.cancel` signal but does **not** write `Cancelling` itself.
The controller that currently owns the Backup or Restore observes the signal and records `Cancelling` and the acceptance time together on the parent, then begins wrapping up local work.
The request controller then mirrors the parent outcome to request status.

Cancellation can be requested in any non-terminal phase, including before work starts.
If the Backup or Restore reaches a terminal phase before acceptance, the request has no effect and `--wait` reports that outcome.
Deleting a request cannot revoke an accepted cancellation, and repeating a request has no additional effect.
Retain processed requests for a bounded period, like `DeleteBackupRequest`, so users can inspect the result.

`spec.cancel` is an internal signal set by the request controller, not a user-facing API.
Once status records cancellation acceptance, controllers must not resume normal processing, even if `spec.cancel` is later cleared.
This does not require API validation rules that prevent clearing the field, keeping the feature available on all Kubernetes versions Velero supports.

The CLI would provide:

```text
velero backup cancel NAME
velero restore cancel NAME
```

Both commands create and follow a cancellation request, and accept `--wait` to report the terminal phase.
A successful API write only records cancellation intent; it does not confirm acceptance or that the Backup or Restore has reached `Cancelled`.

### 2. Status and completion

The two new phases are `Cancelling` and `Cancelled`:

```text
non-terminal phase -- request accepted --> Cancelling
Cancelling -- cancellation handling ends --> Cancelled
```

- After acceptance, Velero starts no new normal workflow work and attempts to cancel work already underway.
  It may start work required for cancellation handling.
- If normal completion wins first, its terminal phase stays unchanged.
  The request remains visible but is too late to change the outcome; `--wait` reports that normal outcome.
- Once the request is accepted, normal completion cannot replace `Cancelling` or `Cancelled` with another terminal phase.
  Child operations that already completed or failed keep their status.

`Cancelled` means Velero has finished its cancellation handling.
It does **not** guarantee that all external work has stopped or roll back changes already made.
Velero reports any known unfinished or unconfirmed work.

Add `status.cancellation` when the request is accepted, alongside the existing status metadata:

| Field | Meaning |
|---|---|
| `acceptedAt` | Time of cancellation acceptance. |
| `reason` | Why cancellation handling ended. |
| `conditions` | Progress of cancellation handling, known unfinished or unconfirmed work, and cancellation cleanup or diagnostic outcomes. |

Update conditions during cancellation handling.
Set the reason and the existing `status.completionTimestamp` when recording `Cancelled`.

### 3. Data and diagnostics

Early cancellation may leave no archive or diagnostics.
Downloads and CLI output should distinguish files never created from failed uploads.

#### 3.1 Backup

Retain the Backup object and available diagnostics by default.
An optional configuration setting on `BackupCancellationRequest` can request normal full deletion through `DeleteBackupRequest` after the Backup reaches `Cancelled`.
This also removes the retained diagnostics; it is a separate lifecycle from cancellation.
The exact configuration field is defined during implementation.
Without that option, cancelled Backups remain until explicit deletion or expiration through the existing `spec.ttl` lifecycle, including their retained diagnostics.
Restore source selection must reject Backups in `Cancelled` phase in every explicit and automatic selection path.

#### 3.2 Restore

Retain restored resources, destination volumes, and partial data.
Cancellation cleanup may remove only owned temporary resources, never destination storage, including during in-place restore.
Cancelled Restores require explicit deletion.

### 4. Controller responsibility

Acceptance precedes wrapping up, and the workflow controller that accepts a request owns cancellation handling through to `Cancelled`:

1. The workflow controller accepts the request in a non-terminal phase by recording `Cancelling` and `status.cancellation.acceptedAt` together, then begins wrapping up.
   `Cancelling` records acceptance, not proof that local work has already stopped.
2. The same controller coordinates children, cleanup, restarts, and the single transition to `Cancelled`.
   The request controller only signals intent; it never performs this handling.

Child controllers continue to handle cancellation of their own resources.
Controllers must act only on children belonging to the correct Backup or Restore, identified by namespace and UID.

### 5. Stopping work

Check for cancellation regularly without reading the API before every item.
Check before starting normal workflow work, between items or actions, while waiting, and before normal finalization.
A call already underway may finish, but the workflow must recheck cancellation before starting its next normal processing step.

| Work | Cancellation path |
|---|---|
| Normal workflow work not yet started | Do not start it. |
| PodVolumeBackup/PodVolumeRestore, DataUpload/DataDownload | Set the child `spec.cancel`; its controller handles cancellation. |
| v2 item action with a known operation ID | Call `Cancel(operationID, parent)` and observe progress. Plugin cancellation may be a no-op. |
| No effective cancellation path | Record available outcome information and report unconfirmed work. Examples include native/CSI snapshot creation, in-flight synchronous calls or writes, and operations whose IDs were lost. |

### 6. Restarts and status updates

- On restart, workflow controllers process cancellation requests that have not yet been accepted.
- Do not resume normal processing after the cancellation request is accepted.
- Use a conditional status update so normal completion and cancellation acceptance cannot overwrite each other.
  A retry using stale status must not undo an accepted cancellation request.

### 7. Workflow-specific requirements

This is a shared design; the in-depth Backup and Restore cancellation designs pick up the workflow-specific aspects.
Each identifies its cancellation checkpoints and the conditions for ending cancellation handling at each checkpoint, and defines child resource discovery, supported plugins and storage modes, and safe cancellation cleanup.
Two areas need explicit per-workflow policies:

- **Finalization:** define how cancellation is handled during finalization, including which finalization steps must still complete.
- **Hooks:** examine partial pre-hook execution, application pause/unfreeze behavior, interrupted exec calls, and duplicate side effects after retries or restarts before choosing a cancellation policy.
  Distinguish cleanup hooks from success-only hooks.
  Restore must not falsely signal successful volume restoration.

## Alternatives Considered

**Cancel by deleting the object.**
Rejected: deletion removes the object and eventually its diagnostics, and the existing Backup deletion controller rejects in-progress Backups rather than stopping their execution.
It cannot both stop work and preserve state for inspection.

**Create immediately-cancelled Backups from a Schedule.**
Rejected as the mechanism to stop a Schedule: users pause a Schedule with `spec.paused` instead, and `Schedule.spec.template.cancel` is invalid and must be rejected.

**A direct `spec.cancel` write as the user-facing request API.**
Rejected in favor of the request CR: a bare spec field keeps no request history, has nowhere to carry cancellation configuration such as delete-after-cancellation, and cannot mirror per-request outcomes.
The CR wraps this signal, so `spec.cancel` is retained internally as the mechanism the request controller sets.

**A bounded cancellation deadline or timeout.**
Considered: a server-wide timeout with a per-request override, recording a fixed deadline at acceptance and forcing `Cancelled` on expiry.
Deferred: cancellation is best-effort in this design, and enforcing a deadline despite blocked workflow, plugin, or provider calls needs its own investigation.
It can be added later without changing the phase model or status shape.

**A dedicated post-acceptance cancellation coordinator.**
Rejected for now: the workflow controller already owns the Backup or Restore and its children, so a separate coordinator under a different reconciliation key adds moving parts without a clear benefit at this scope.

## Security Considerations

Status and metrics must not expose secrets.
Keep status reports bounded in size and avoid metric labels with unbounded sets of values.
As with existing Backups and Restores, permission to patch the resource also allows changes to its status.
This proposal does not add a status subresource or separate status protection.

## Compatibility

Once status records cancellation acceptance, controllers must not resume normal processing, even if `spec.cancel` is later cleared.
This does not require API validation rules that prevent clearing the field, keeping the feature available on all Kubernetes versions Velero supports.
`Schedule.spec.template.cancel` is invalid and must be rejected.
Restore source selection must reject Backups in the `Cancelled` phase in every explicit and automatic selection path.
Cancelled Backups otherwise follow the existing `spec.ttl` lifecycle unless the delete-after-cancellation option is used.

## Implementation

The design is intended to be implemented incrementally.
Shared phases, the `status.cancellation` block, and the cancellation request CR come first, followed by per-workflow cancellation handling for Backup and Restore.
Each workflow will have its own follow-on design covering its cancellation checkpoints, child discovery, supported plugins and storage modes, and cleanup, as outlined under the workflow-specific requirements.
Timelines and contributors are to be determined.

## References

- [#9284: Backup Cancellation Design](https://github.com/velero-io/velero/pull/9284).
- [#9284: bounded wait discussion](https://github.com/velero-io/velero/pull/9284#discussion_r2363925189).
- [#9284: cancellation in the existing state machine](https://github.com/velero-io/velero/pull/9284#discussion_r2430934181).
- [#9284: backup payload and diagnostic retention discussion](https://github.com/velero-io/velero/pull/9284#discussion_r2384454776).
- [#10509: Shared bounded Backup/Restore cancellation proposal](https://github.com/velero-io/velero/pull/10509).
