# Backup Cancellation

## Abstract

Add a supported way to cancel an in-progress Velero backup. This involves two outcomes:
1. stopping further work where possible before moving to a terminal phase, and
2. keeping the Backup object and any artifacts for diagnosis.
Velero currently does not have any cooperative cancellation path for backups.

## Background

A backup moves through phases owned by different controllers: 
- the queue controller advances `New -> Queued -> ReadyToStart`; 
- the backup controller runs `InProgress` via one blocking `runBackup()` call, then hands off to
- plugin-operations, finalization, and a terminal phase.  

Cancellation is complex because a backup is not one unit of work; for instance, `runBackup()` does synchronous item collection/archiving, waits on asynchronous node-side children (pod-volume backups and CSI data uploads), and starts durable asynchronous plugin operations polled by a separate controller.  
While a reconciler is blocked inside `runBackup()`, no watch event can re-enter for that object, so the work itself must poll for a cancellation signal at cooperative points. That signal must also live on the persisted Backup object: if the process restarts mid-teardown, the restarted controller must see it and continue tearing down, not silently resume the backup.

## Goals

- A supported way to cancel an in-progress backup that stops further work where possible and retains the Backup and artifacts for diagnosis.
- Safety: cancellation never leaves the Backup inconsistent, and a stale engine, finalizer, or operations write cannot overwrite an accepted cancellation outcome.

## Non Goals

- Restore cancellation.
- Undoing applied work; a completed action or an in-flight plugin call cannot be reversed.
- A hard, real-time interruption guarantee; cancellation is cooperative and best-effort.
- Provider-enforced write fencing; this does not prove a plugin's external work truly stopped.
- Deleting stored artifacts; that stays with `velero backup delete` (cancellation can *trigger* it as a follow-up — see Cleanup).

## High-Level Design

- **User Intent is a CR.** Users create a `BackupCancellationRequest` rather than patching the Backup. It names a target Backup, binds to that Backup's UID (so a name reuse cannot satisfy it), and carries configuration.
- **The internal signal is `spec.cancel`.** The request controller translates an accepted request into `Backup.spec.cancel`, the internal signal phase owners observe. Users do not set it directly.
- **Acceptance is authoritative.** A backup is not canceled until a phase owner records acceptance (`Canceling`) on the Backup; once accepted, it cannot be resumed.
- **Teardown is observer-owned.** Since phases are owned by different controllers, whichever owns the current phase observes `spec.cancel`, tears down its in-flight work, records `Canceling` plus status, and drives the Backup to terminal `Canceled`. There is no central coordinator.

The `PartiallyFailed` variants (`WaitingForPluginOperationsPartiallyFailed`, `FinalizingPartiallyFailed`) behave like their siblings and are omitted below for readability.

```mermaid
stateDiagram-v2
    [*] --> New
    New --> Queued
    Queued --> ReadyToStart
    ReadyToStart --> InProgress
    InProgress --> WaitingForPluginOperations
    InProgress --> Finalizing
    WaitingForPluginOperations --> Finalizing
    Finalizing --> Completed
    Finalizing --> PartiallyFailed
    Completed --> [*]
    PartiallyFailed --> [*]

    New --> Canceling
    Queued --> Canceling
    ReadyToStart --> Canceling
    InProgress --> Canceling
    WaitingForPluginOperations --> Canceling
    Canceling --> Canceled
    Canceled --> [*]

    note right of Finalizing
        past the acceptance boundary:
        spec.cancel does not transition;
        request is Rejected (TooLate)
    end note

    classDef cancel fill:#fdd,stroke:#c00,color:#900
    class Canceling,Canceled cancel
```

*Figure: Backup phase transitions*

## Detailed Design

### API: BackupCancellationRequest CRD

A namespaced CR in `velero.io/v1`, shaped like `DeleteBackupRequest`/`DownloadRequest`.
Its spec names the target; its status carries the request phase, the bound UID, a rejection reason, and a message.

```go
// BackupCancellationRequestSpec is the specification for a request to cancel a backup.
type BackupCancellationRequestSpec struct {
	// BackupName is the name of the backup to cancel.
	BackupName string `json:"backupName"`

	// DeleteBackup, when true, requests deletion after cancellation completes successfully: the
	// request controller creates a DeleteBackupRequest once the backup reaches Canceled. Not
	// applied when the request is Rejected. See Cleanup.
	// +optional
	DeleteBackup bool `json:"deleteBackup,omitempty"`
}

// BackupCancellationRequestPhase represents the lifecycle phase of a BackupCancellationRequest.
// +kubebuilder:validation:Enum=New;Accepted;Completed;Rejected
type BackupCancellationRequestPhase string

const (
	// New: observed, but no phase owner has recorded acceptance on the target Backup yet.
	BackupCancellationRequestPhaseNew BackupCancellationRequestPhase = "New"

	// Accepted: a phase owner recorded Canceling on the target Backup; the outcome is authoritative.
	BackupCancellationRequestPhaseAccepted BackupCancellationRequestPhase = "Accepted"

	// Completed: the target Backup reached the terminal Canceled phase.
	BackupCancellationRequestPhaseCompleted BackupCancellationRequestPhase = "Completed"

	// Rejected: the request could not be honored; Status.Reason distinguishes why.
	BackupCancellationRequestPhaseRejected BackupCancellationRequestPhase = "Rejected"
)

// BackupCancellationRequestRejectedReason explains why a request was Rejected.
// +kubebuilder:validation:Enum=TooLate;AlreadyTerminal;NotFound
type BackupCancellationRequestRejectedReason string

const (
	// TooLate: the Backup was still running but past the acceptance boundary (Finalizing*).
	RejectedReasonTooLate BackupCancellationRequestRejectedReason = "TooLate"

	// AlreadyTerminal: the Backup had already reached a terminal phase (Completed, PartiallyFailed,
	// Failed, FailedValidation, or Canceled). Message records the exact phase.
	RejectedReasonAlreadyTerminal BackupCancellationRequestRejectedReason = "AlreadyTerminal"

	// NotFound: no Backup with the requested name existed when the request was bound.
	RejectedReasonNotFound BackupCancellationRequestRejectedReason = "NotFound"
)

// BackupCancellationRequestStatus is the current status of a BackupCancellationRequest.
type BackupCancellationRequestStatus struct {
	// Phase is the current state of the request.
	// +optional
	Phase BackupCancellationRequestPhase `json:"phase,omitempty"`

	// BackupUID binds the request: it is only acted on for the Backup with this UID, so a later
	// Backup reusing the same name cannot satisfy or be affected by it.
	// +optional
	BackupUID string `json:"backupUID,omitempty"`

	// Reason categorizes a Rejected request.
	// +optional
	Reason BackupCancellationRequestRejectedReason `json:"reason,omitempty"`

	// Message is a human-readable explanation of the current phase (e.g. the exact terminal phase
	// behind an AlreadyTerminal rejection).
	// +optional
	Message string `json:"message,omitempty"`
}
```

The object wrapper carries the standard markers and print columns, mirroring the existing request CRDs (proposed short name `bcr`):

```go
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=bcr
// +kubebuilder:printcolumn:name="BackupName",type="string",JSONPath=".spec.backupName"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.reason"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// BackupCancellationRequest is a request to cancel an in-progress backup.
type BackupCancellationRequest struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +optional
	Spec BackupCancellationRequestSpec `json:"spec,omitempty"`
	// +optional
	Status BackupCancellationRequestStatus `json:"status,omitempty"`
}
```

Binding: on first observation, resolve the named Backup and record its UID in `status.backupUID`; associate for listing/cleanup via the `velero.io/backup-name` label (matching `DeleteBackupRequest`).

### Parent Backup status and phases

Two phases are added to `BackupPhase`:

```go
// BackupPhaseCanceling means cancellation has been accepted for an in-progress backup and the
// owning controller is tearing down its work. The backup is not usable.
BackupPhaseCanceling BackupPhase = "Canceling"

// BackupPhaseCanceled means the backup was canceled. Terminal and non-resumable. Available
// artifacts are retained for diagnosis but the backup is not restorable.
BackupPhaseCanceled BackupPhase = "Canceled"
```

- `Canceling` is recorded by whichever controller owns the accepting phase; recording it is what makes cancellation authoritative. `Canceled` is terminal.
- Parent spellings `Canceling`/`Canceled` match the existing child spellings (DataUpload, PodVolumeBackup already use `Canceling`/`Canceled`).

A `cancellation` struct is added to `BackupStatus`, set only after acceptance.

```go
// Cancellation records the outcome of a cancellation. Set only once accepted (phase Canceling
// or Canceled).
// +optional
// +nullable
Cancellation *BackupCancellationStatus `json:"cancellation,omitempty"`
```

```go
// BackupCancellationStatus records the outcome of canceling a backup.
type BackupCancellationStatus struct {
	// AcceptedAt is when the owning controller accepted cancellation (recorded Canceling).
	// +optional
	// +nullable
	AcceptedAt *metav1.Time `json:"acceptedAt,omitempty"`

	// Reason is a short, human-readable summary of the outcome (e.g. noting unconfirmed teardown).
	// +optional
	Reason string `json:"reason,omitempty"`

	// AcceptedFromPhase records the phase the backup was in when cancellation was accepted.
	// +optional
	AcceptedFromPhase BackupPhase `json:"acceptedFromPhase,omitempty"`

}
```

### Cancellation across controllers

`spec.cancel` is the signal; each phase owner observes it and runs **observer-owned teardown** (no coordinator):  
record `Canceling` -> tear down in-flight work -> record `Canceled`.  
Teardown grows with lifecycle progress: ranging from nothing before work starts, up to child and operation teardown once work is in flight.

| Phase | Controller | Teardown |
|---|---|---|
| New / Queued | queue | none (bookkeeping only) |
| ReadyToStart | backup | release tracker reservation |
| InProgress | backup + engine | drain local item-blocks / cancel PVBs / sweep ops |
| WaitingForPluginOperations | operations | sweep ops |
| Finalizing+ | finalizer | none — request Rejected (past boundary) |

Rules that apply to every owner:

- **Guarded transitions.** Every phase write is a fresh read plus an optimistic-lock (resourceVersion) update, recomputing on conflict, so exactly one transition wins and a stale write cannot overwrite acceptance. The replay-prone helpers (`kube.PatchResource`, `PatchResourceWithRetriesOnErrors`) must **not** be used here. This is the safety mechanism.
- **Shared vs. local teardown.** Only plugin-operation cancellation (`bia.Cancel()` on recorded operation IDs) is shared: backup and operations controllers call one helper. PVB teardown is engine-only (PVBs exist and are tracked only inside the engine, and are terminal by later phases).
- **Acceptance boundary.** Accepted through `WaitingForPluginOperations`; `Finalizing`/terminal -> `Rejected` (`TooLate` for `Finalizing`*, `AlreadyTerminal` otherwise).

Rationale for observer-owned vs. central coordinator, and request-based vs. confirmation-based, is in Alternatives. Per-controller detail follows.

#### Queue controller (New, Queued)

*Owns `New -> Queued -> ReadyToStart`. Nothing is in flight: no pool, children, or operations; the tracker only reserves at `AddReadyToStart`.*

```mermaid
flowchart TD
    A([Reconcile New / Queued backup]) --> B{spec.cancel set?}
    B -- no --> C[Normal queue advance]
    B -- yes --> D["Guarded write: Canceling<br/>acceptedFromPhase = New or Queued"]
    D --> E{Was Queued?}
    E -- yes --> F[Compact remaining QueuePosition gap]
    E -- no --> G["Guarded write: Canceled<br/>+ completionTimestamp"]
    F --> G
    G --> H([done])

    classDef cancel fill:#fdd,stroke:#c00,color:#900
    class D,G cancel
```

- **Observe.** Add a watch-predicate case for `spec.cancel` on `New`/`Queued` so it is seen promptly, not at the ~1-minute requeue (`defaultQueuedBackupRecheckFrequency`).
- **Teardown.** Bookkeeping only: guarded `Canceling` (`acceptedFromPhase` New/Queued); if `Queued`, compact `QueuePosition` like the dequeue path; add no tracker entry (`AddReadyToStart` has not run).
- **Transition.** No work to settle -> guarded `Canceled` + `completionTimestamp` immediately. Uses the optimistic-locked update, not `kube.PatchResource`.

#### Backup controller (ReadyToStart, InProgress)

*Owns the `ReadyToStart` gate, `ReadyToStart -> InProgress`, and the blocking `runBackup()`. Once `InProgress`, no watch event re-enters for that key until the call returns. Owns the worker pool (deferred `StopWorkerPool()`) and the tracker entry.*

Cancellation is checked at **three boundaries** only (plus the engine's cooperative wind-down), not scattered through the controller.

```mermaid
flowchart TD
    Start([Reconcile: ReadyToStart backup]) --> B1{"Boundary 1 — pre-start gate<br/>spec.cancel set?"}
    B1 -- yes --> P1["Release tracker reservation; no worker pool,<br/>no InProgress; guarded write: Canceling<br/>acceptedFromPhase = ReadyToStart"]
    P1 --> P2[Guarded write: Canceled]
    P2 --> End1([done])

    B1 -- no --> Run["Start worker pool, patch InProgress,<br/>run runBackup / engine"]
    Run --> B2{"Boundary 2 — engine refresh<br/>spec.cancel observed?"}
    B2 -- yes --> Hybrid["Local item-block work: DRAIN<br/>(atomic flag stops new blocks)<br/>Remote pod-volume work: CANCEL<br/>(cancel podVolumeContext -> PVB sweep)"]
    B2 -- no --> Normal[Engine completes normally]
    Hybrid --> B3
    Normal --> B3{"Boundary 3 — phase-selection switch"}
    B3 -- cancel observed --> Sweep["Shared sweep: bia.Cancel on unfinished<br/>operation IDs; log each outcome"]
    Sweep --> CW["Guarded write: Canceling -> Canceled<br/>(persistence branches on phase)"]
    CW --> End2([done])
    B3 -- fatal errors --> F1[Failed]
    B3 -- "errors + ops in progress" --> F2["WaitingForPluginOperations*"]
    B3 -- otherwise --> F3["Finalizing*"]

    classDef cancel fill:#fdd,stroke:#c00,color:#900
    class P1,P2,Hybrid,Sweep,CW cancel
```

**1. Pre-start gate (event-driven).**
Before `prepareBackupRequest` builds the request or starts a pool, check `spec.cancel`.
Nothing is in flight: release the `AddReadyToStart` reservation, create no pool, do not patch `InProgress`, record guarded `Canceling` (`acceptedFromPhase: ReadyToStart`), and proceed straight to `Canceled`.

**2. Engine-owned refresh (in-flight).**
The engine (`pkg/backup/backup.go`) re-reads `spec.cancel` itself (rate-limited; it takes no context from the reconciler) and winds down with a **hybrid**, because local and remote work want opposite things:

- *Local (item-block producer + pool): drain.* An atomic flag at the producer loop top stops submitting new blocks; in-flight blocks finish; the deferred `StopWorkerPool()` tears the pool down. A flag, not a context, because drain-then-stop wants the in-flight waits and the worker-return send to *complete* — a context would interrupt them and deadlock the result consumer. An item whose action already started runs to its next boundary so its operation ID is recorded for the op sweep.
- *Remote (pod-volume backups): cancel.* These are the expensive node-agent copy, so stop them. `WaitAllPodVolumesProcessed` already selects on `podVolumeContext.Done()` and, when it fires, sets `Spec.Cancel = true` on non-terminal PVBs and waits for `Canceled` — today driven only by the PVB timeout. Cancellation reuses it unchanged by also canceling `podVolumeContext` on `spec.cancel`. A context *is* right here (interrupting is the goal), and no new PVB helper is needed.

**3. Phase-selection transition.**
After the engine returns, `runBackup()` picks the handoff phase in a `switch`. Cancellation must be a first-class case evaluated *ahead* of the error and operation cases — otherwise in-flight plugin operations route to `WaitingForPluginOperations`, which would *wait for* the canceled work.
The controller already holds the plugin manager and operation list (`getBackupItemOperationProgress`), so it runs the shared op sweep (`bia.Cancel()` per unfinished operation ID) in place, logs each action's outcome, and transitions toward `Canceled`.
Persistence must branch on the phase (so no usable terminal metadata is published), the write must be guarded (not `PatchResourceWithRetriesOnErrors`), and the deferred tracker handling must gain `Canceling`/`Canceled` cases so the entry is not leaked.

#### Operations controller (WaitingForPluginOperations)

*Already reconciles waiting backups periodically and already cancels in-flight operations on timeout via `bia.Cancel(operationID, backup)`.*

```mermaid
flowchart TD
    A([Reconcile WaitingForPluginOperations backup]) --> B{spec.cancel set?}
    B -- no --> C[Poll Progress; normal timeout handling]
    B -- yes --> D["Shared sweep: bia.Cancel on each<br/>unfinished operation ID"]
    D --> E["Keep observing Progress();<br/>successful Cancel is not proof -> count Unconfirmed"]
    E --> F{Operations still in progress?}
    F -- yes --> E
    F -- no --> G["Guarded write: Canceling<br/>acceptedFromPhase = WaitingForPluginOperations"]
    G --> H[Guarded write: Canceled]
    H --> I([done])

    classDef cancel fill:#fdd,stroke:#c00,color:#900
    class D,G,H cancel
```

Cancellation reuses that exact sweep, triggered by `spec.cancel` instead of the timeout — a new trigger, not new logic.
It `Cancel()`s each unfinished operation and keeps polling `Progress()` rather than trusting a successful `Cancel()` return (the interface permits unsupported cancellation to succeed); such cases are logged as unconfirmed.
Modes with no real cancel path (e.g. native snapshots) stop new calls and record the work unconfirmed.
When no operations remain in progress: guarded `Canceling` (`acceptedFromPhase: WaitingForPluginOperations`) -> `Canceled`.

#### Finalizer controller (Finalizing)

*Owns `Finalizing`: data is already captured and async operations are already complete; only results and the final artifact upload remain.*

**Does not accept cancellation** — abandoning a near-done backup yields a half-finalized artifact for no benefit.
No finalizer code is needed: boundary 3 already makes `Canceling` win ahead of the `Finalizing` case, so a backup only reaches `Finalizing` with `spec.cancel` set if the signal arrived *after* it entered `Finalizing`.
Then no `Canceling` write happens, the backup finalizes normally to its terminal phase, and the request controller sees the non-`Canceling` outcome -> `Rejected`/`TooLate`.

```mermaid
flowchart TD
    A([Reconcile Finalizing backup]) --> B{spec.cancel set?}
    B -- no --> C[Finalize normally]
    B -- yes --> D["Past the acceptance boundary:<br/>do NOT cancel"]
    D --> C
    C --> E[Terminal: Completed / PartiallyFailed]
    E --> F["BCR controller observes non-Canceling outcome<br/>-> request Rejected (TooLate)"]
    F --> G([done])
```

#### BackupCancellationRequest controller (new)

*Owns the request lifecycle. Never writes the parent's phase or `status.cancellation` — it raises the signal, then projects the parent's outcome back onto the request.*

```mermaid
flowchart TD
    A([New BackupCancellationRequest]) --> B{Backup with name exists?}
    B -- no --> R1["Rejected (NotFound)"]
    B -- yes --> Bind["Bind: record status.backupUID;<br/>set backup-name / backup-uid labels; dedupe"]
    Bind --> P{Target backup phase?}
    P -- "terminal (Completed/Failed/Canceled/...)" --> R2["Rejected (AlreadyTerminal);<br/>exact phase in Message"]
    P -- "Finalizing / FinalizingPartiallyFailed" --> R3["Rejected (TooLate)"]
    P -- "cancellable (before Finalizing)" --> T["Translate: set Backup.spec.cancel once (idempotent)"]
    T --> Proj[Watch + project parent phase onto request]
    Proj --> C1["parent Canceling -> Accepted"]
    Proj --> C2["parent Canceled -> Completed"]
    C2 --> Del{spec.deleteBackup set?}
    Del -- yes --> DBR[Create DeleteBackupRequest]
    Del -- no --> End([done])
    DBR --> End

    classDef reject fill:#eee,stroke:#999,color:#555
    classDef cancel fill:#fdd,stroke:#c00,color:#900
    class R1,R2,R3 reject
    class C1,C2 cancel
```

- **Bind.** On a `New` request, resolve the Backup, record its UID, and set the `velero.io/backup-name` and `velero.io/backup-uid` labels (like `DeleteBackupRequest`). No such Backup -> `Rejected`/`NotFound`.
- **Dedupe.** Collapse redundant requests for the same bound Backup (DeleteBackupRequest convention).
- **Translate.** If still cancellable (before `Finalizing`), set `spec.cancel` once, idempotently. Setting it is not acceptance — acceptance is a phase owner recording `Canceling`.
- **Reject past the boundary.** `Finalizing`* -> `TooLate`; terminal -> `AlreadyTerminal` (exact phase in `Message`).
- **Project.** Once `spec.cancel` is set, the request controller watches the parent Backup and maps its phase onto the request: `Canceling` → `Accepted`, `Canceled` → `Completed`. It reads from the parent's actual phase rather than assuming acceptance the moment it sets the signal — this handles the race where the backup slips past `Finalizing` before any phase owner checks `spec.cancel`. In that case the backup finalizes normally and the request ends up `Rejected`/`TooLate`.

### Cleanup

- **Artifacts retained, non-restorable.** Partial artifacts are kept for diagnosis, but `Canceled` marks them diagnostic-only. A canceled backup still uploads its log and metadata, but persistence branches on the phase (boundary 3) so it publishes no usable terminal or restorable metadata.
- Cancellation does not delete artifacts itself (Non Goals). Deletion is opt-in via `spec.deleteBackup`: when set, the request controller creates a `DeleteBackupRequest` once the backup reaches `Canceled` (request `Completed`), reusing the existing deletion machinery. It fires only on successful cancellation — a `Rejected` request triggers no deletion.
- Process-local resources (temp tarball, worker pool, plugin processes) need no special cleanup: the existing deferred teardown (`StopWorkerPool`, plugin-manager cleanup, temp-file removal) runs regardless of how `runBackup` returns.

### Hooks

No special handling. Hooks run inside `backupItemBlock`, which a worker runs to completion once it picks up the block; the drain boundary is *between* blocks, never inside one.
So a started block always runs its pre-hooks, items, and paired post-hooks together — cancellation cannot split a pre/post-hook pair or leave an application quiesced without its matching post-hook.

### CLI, metrics, and sync

- `velero backup cancel BACKUP_NAME` creates a `BackupCancellationRequest`; `--wait` blocks to a terminal request phase (`Completed`/`Rejected`), `--delete` sets `spec.deleteBackup` (`--timeout` if the tentative timeout lands).
- `velero backup describe` shows the `Canceling`/`Canceled` phase; `velero backup logs` includes the ledger.
- Backup sync treats `Canceled` as terminal and non-restorable: synced for visibility/audit, not offered as a restore source (see Compatibility).

## Alternatives Considered

**User-facing `spec.cancel` instead of a request CR.**
Rejected as the user surface: no place for per-request config or a timeout, no durable record of who/when, and no clean "too late".
The CR gives an auditable, UID-bound object with request/accepted/rejected outcomes; `spec.cancel` stays the internal signal.

**Central coordinator instead of observer-owned teardown.**
Rejected: phases are already owned by distinct controllers, so a coordinator would reach into in-flight work it does not own (the engine pool, the operations poll), duplicating logic and racing the owner.
Observer-owned keeps teardown next to the code that understands it and makes transitions naturally single-writer.

**Hard abort instead of drain-then-stop.**
Rejected: the worker result send is blocking and unguarded, so interrupting mid-flight risks deadlocking shutdown — and aborting local work buys little, since the cost is the remote copy.
Drain-then-stop uses an atomic flag; a context is used only for the PVB wait, where interrupting is what triggers the existing cancel sweep.

**Confirmation-based `Canceled` instead of fast/request-based.**
Rejected as default: holding `Canceling` until every child/operation is confirmed terminal depends on work Velero cannot always confirm (a no-op `Cancel`, native snapshots) and would need a bounding timeout.
Instead `Canceled` means *requested*: PVBs confirmed, plugin operations `Unconfirmed`.

## Security Considerations

- Cancellation privilege is the ability to create a `BackupCancellationRequest`, gated by normal RBAC (as `DeleteBackupRequest` gates deletion). `spec.cancel` is internal, not user-facing.
- Because phase owners honor `spec.cancel` from any source, Backup-write access effectively grants cancellation. This design accepts that rather than adding a validating webhook to forbid direct edits (a possible hardening — Open Issues).
- `spec.deleteBackup` escalates to deletion but does not bypass controls: it creates a `DeleteBackupRequest` through the normal deletion flow and its checks. Granting create access with this option effectively grants deletion of the target.

## Compatibility

- **`Canceled` is not a restore source.** The restore controller already allowlists only `Completed`/`PartiallyFailed` (`restore_controller.go`), so `Canceled` is already refused. The only change is an explicit `Canceled`-specific message, plus backup sync and CLI surfacing `Canceled` as terminal/non-restorable rather than an error or omission.
- **Child phase spellings.** Parent `Canceling`/`Canceled` use the same spelling as the existing child phases (DataUpload, PodVolumeBackup), so no adapter or rename is needed.

## Implementation

**Ordering principle (why it is safe to land in pieces):** `spec.cancel` defaults to false and no request exists until a user creates one, so every observer added before the request path is **inert** — it changes behavior only once something sets `spec.cancel`.
So teardown lands first (tested by setting `spec.cancel` directly), and the request path — which turns the feature *on* — lands last, after every phase has an observer, so no user can file a request that a phase silently ignores.

**Phase 1 — Foundations (inert plumbing)**
1. API types: `spec.cancel` on `BackupSpec`, the `Canceling`/`Canceled` phases, `BackupCancellationStatus`, and the `BackupCancellationRequest` CRD with generated clients and manifests.
2. Guarded phase-transition helper (fresh read + optimistic lock), replacing the replay-prone patch helpers for these transitions.

**Phase 2 — Teardown observers (inert until `spec.cancel` is set)**
3. Engine wind-down: the atomic drain flag plus routing `podVolumeContext` off `spec.cancel` (reusing the PVB sweep). The riskiest change, isolated.
4. Backup controller: the three boundaries plus the shared op-cancel helper (introduced here).
5. Operations controller: trigger the shared sweep from `spec.cancel`. Small; depends on #4's helper.
6. Queue controller: pre-start handling for `New`/`Queued`. Small and self-contained.

**Phase 3 — Activation (user-facing)**
7. BackupCancellationRequest controller: bind/UID, translate, dedupe, project, rejection reasons, and the `deleteBackup` follow-up. Lands only after Phase 2.
8. CLI, metrics, backup sync, and the restore-gate message.

## Open Issues

- **Timeout/deadline:** whether to implement it, and how to enforce it at the deadline. The fast transition reduces its need (no blocking on unconfirmable work), so it may stay an optional bound. `spec.timeoutSeconds` and `status.cancellation.deadline` are tentative pending this.
- **Direct `spec.cancel` edits:** add a validating webhook to force cancellation through the CR, or accept Backup-write as cancellation access.
- **`deleteBackup` failure:** behavior when the follow-up `DeleteBackupRequest` fails or is rejected (retry, surface on the request, or leave to the deletion-request lifecycle).
