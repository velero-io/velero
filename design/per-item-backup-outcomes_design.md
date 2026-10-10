# Per-item backup outcomes

## Abstract

After a backup runs there is no single, structured place to see how each item did.
The signal exists but is scattered across several backup-store files, none of which alone says which objects failed and why, so every consumer downloads those files and stitches them together, usually incorrectly.
This proposal adds one structured per-item outcome artifact, `<backup>-item-outcomes.json.gz`, assembled by Velero at finalize and fetched through the existing `DownloadRequest` mechanism.

## Background

Consumers (dashboards, GitOps health checks, support tooling) repeatedly ask the same question about a finished backup: which items passed, which failed, and why.
Velero answers only at the job level, with a phase and error counts on `Backup.status`.
The per-item truth is spread across `resource-list.json.gz` (inventory, no pass/fail), `results.gz` (free-text errors bucketed by namespace), `itemoperations.json.gz` (structured async-op status), and `volumeinfo.json.gz` (structured, PVC-only).
None is authoritative alone, `results.gz` is unstructured and its item identity is ambiguous, and it goes stale because async operations finish after it is written (see #9377, a confirmed bug where BackupItemAction timeouts never reach `results.gz` or the error count).
Velero already does structured, finalize-time, per-item reconciliation for volumes: `BackupVolumeInfo` (design/Implemented/pv_backup_info.md) is written at initial persist and then re-read and reconciled at finalize by `updateVolumeInfos` in pkg/backup/backup.go, merging completed async results into each per-PVC entry.
This proposal generalizes that pattern from volumes to every item kind.

## Goals

- Produce a stable, structured per-item outcome for one backup run: `{groupResource, namespace, name, outcome, messages}`.
- Assemble it at finalize, after async operations settle, so it reflects the final state and not a mid-run snapshot.

## Non Goals

- Adding more free text to `logs.gz` or `results.gz`, or changing their formats.
- Changing what Velero backs up or how any item is handled during the backup itself.
- Restore-side per-item outcomes (a natural follow-on, deliberately out of scope here).
- Inlining per-item rows into the `Backup` CR (rejected on etcd object-size grounds, see Alternatives).

## High-Level Design

Velero records a structured outcome for every item at the point in the backup where the item's identity is still canonical, defaulting each touched item to a success outcome and upgrading it when an error, warning, skip, or async operation applies.
The outcomes are written as a new gzipped-JSON artifact at initial persist (synchronous results), then re-read and reconciled at finalize once async operations have completed, exactly mirroring the `BackupVolumeInfo` lifecycle.
The artifact is delivered to clients through the existing `DownloadRequest` mechanism under a new download target kind, and is kept out of the `Backup` CR.
The feature is opt-in, via a per-backup spec field and a server-level default toggle.

## Detailed Design

### Why capture, not pure merge

The obvious approach, merging the existing artifacts at finalize, cannot produce structured per-item errors.
When an item error or warning is logged, the structured triple is present in the log entry (`entry.Data["resource"|"namespace"|"name"]`) but `LogHook.Fire` in pkg/util/logging/log_counter_hook.go concatenates it into one free-text string and buckets it by namespace only; the resource and name survive only inside the string.
`results.gz` therefore has no reliable per-item key, and reconstructing one means re-parsing the free text, which is the brittleness this proposal exists to remove.
So the design captures a structured outcome where the identity is still first-class, rather than reconstructing it after the fact.
The three existing renderings of resource identity, `schema.GroupResource` (in `velero.ResourceIdentifier`), `groupResource.String()` (in logs), and the GVK string `apps/v1/Deployment` (in `BackupResourceList`), never have to be reconciled, because the recorder keys on `velero.ResourceIdentifier` from the start.

### Types

A new package `internal/itemoutcome` defines the artifact schema.

```go
type Outcome string

const (
	OutcomeBackedUp Outcome = "BackedUp" // item processed with no error or warning
	OutcomeWarning  Outcome = "Warning"  // item processed but produced one or more warnings
	OutcomeFailed   Outcome = "Failed"   // item errored, synchronously or during an async operation
	OutcomeSkipped  Outcome = "Skipped"  // item excluded or skipped (e.g. skipped PVC)
)

// ItemOutcome is the outcome of a single backed-up item.
type ItemOutcome struct {
	GroupResource string   `json:"groupResource"`      // e.g. "deployments.apps"
	Namespace     string   `json:"namespace,omitempty"`
	Name          string   `json:"name"`
	Outcome       Outcome  `json:"outcome"`
	Messages      []string `json:"messages,omitempty"` // errors/warnings/skip reasons attributed to this item
}

// ItemOutcomes is the top-level artifact, a versioned list.
type ItemOutcomes struct {
	SchemaVersion string        `json:"schemaVersion"` // "v1"
	Items         []ItemOutcome `json:"items"`
}
```

The in-memory recorder lives on the backup `Request` (pkg/backup/request.go), keyed by `velero.ResourceIdentifier` so that repeated writes for one item collapse into a single row.

```go
// on *Request
itemOutcomes *itemoutcome.Recorder

// Recorder API (internal/itemoutcome)
func (r *Recorder) Observe(id velero.ResourceIdentifier)                     // default: BackedUp
func (r *Recorder) Warn(id velero.ResourceIdentifier, msg string)            // -> Warning (unless already Failed)
func (r *Recorder) Fail(id velero.ResourceIdentifier, msg string)            // -> Failed
func (r *Recorder) Skip(id velero.ResourceIdentifier, reason string)         // -> Skipped
func (r *Recorder) Result() *ItemOutcomes                                    // sorted, deterministic
```

Outcome precedence when a row is written more than once: `Failed` > `Skipped` > `Warning` > `BackedUp`.

### Capture during backup

`itemBackupper.backupItemInternal` (pkg/backup/item_backupper.go) already computes the canonical identity for the item it is processing.
It calls `Observe` when it begins an item and `Skip` with the reason when it skips one.
Item errors and warnings are captured by extending `LogHook.Fire` (pkg/util/logging/log_counter_hook.go): when `entry.Data` carries the `resource`, `namespace`, and `name` fields, it additionally calls `Fail`/`Warn` on the recorder with those structured values, before flattening to the existing `results.Result` string.
This keeps `results.gz` unchanged (compatibility) while capturing the same events structurally.

### Assembly and finalize reconciliation

Initial persist (`persistBackup`, pkg/controller/backup_controller.go): encode `request.itemOutcomes.Result()` with `encode.ToJSONGzip` and add it to `persistence.BackupInfo` for the existing `PutBackup` call.
At this point the synchronous outcomes are complete but async operations may still be in flight, exactly as with `BackupVolumeInfo`.

Finalize (`backupFinalizerReconciler.Reconcile`, pkg/controller/backup_finalizer_controller.go, and `FinalizeBackup`, pkg/backup/backup.go): re-read the artifact with the new `GetBackupItemOutcomes`, then overlay the async-operation results already loaded there.
`itemoperation.BackupOperation` carries a fully structured `Spec.ResourceIdentifier` and a `Status.Phase`/`Status.Error`, so each operation joins directly onto its item: a `Failed` phase sets the item to `Failed` with `Status.Error` appended; a `Completed` phase leaves a previously-successful item unchanged.
Rewrite the artifact with `PutBackupItemOutcomes`.
This is the same read-reconcile-rewrite shape as `updateVolumeInfos`, and it is what closes the #9377 timing hole for this artifact.

### Persistence and download plumbing

- pkg/persistence/object_store_layout.go: add `getBackupItemOutcomesKey` returning `<backup>-item-outcomes.json.gz` (reuses the `backups` subdir).
- pkg/persistence/object_store.go: add `BackupItemOutcomes io.Reader` to `BackupInfo`; add `PutBackupItemOutcomes(name string, r io.Reader) error` and `GetBackupItemOutcomes(name string) (*itemoutcome.ItemOutcomes, error)` to the `BackupStore` interface and `objectBackupStore`, mirroring the `BackupVolumeInfo` pair; `GetBackupItemOutcomes` returns an empty result when the object is absent, so old backups and opt-out backups stay readable.
- pkg/persistence/object_store.go `GetDownloadURL`: add a `case velerov1api.DownloadTargetKindBackupItemOutcomes`.
- pkg/apis/velero/v1/download_request_types.go: add the `DownloadTargetKindBackupItemOutcomes = "BackupItemOutcomes"` const and extend the `+kubebuilder:validation:Enum` marker.
- No change is needed in `download_request_controller.go` (backup-scoped kinds route through the generic `GetDownloadURL`) or in the CLI download streamer (it gunzips `.json.gz` automatically).

### Opt-in

Per-backup: add `CollectItemOutcomes *bool` to `BackupSpec` (pkg/apis/velero/v1/backup_types.go), following the `SnapshotMoveData *bool` pattern, plus a builder method and deepcopy.

Server default: add `DefaultCollectItemOutcomes bool` to the server `Config` (pkg/cmd/server/config/config.go) with a `--default-collect-item-outcomes` flag, threaded through `NewBackupFinalizerReconciler` and the backup reconciler so an unset per-backup field falls back to the server default.

Effective value: `Spec.CollectItemOutcomes` if set, else the server default.
When disabled, the recorder is a no-op and no artifact is written.

### CLI (nice-to-have)

`velero backup describe --details` (pkg/cmd/util/output/backup_describer.go) gains an "Item Outcomes" section that streams the artifact via `downloadrequest.Stream(..., DownloadTargetKindBackupItemOutcomes, ...)` and prints a compact summary (counts plus the failed/warning rows).

### Code generation

Adding the `BackupSpec` field and the download-target enum requires regenerating CRDs and deepcopy (`make update` / generate) and the API docs.

## Alternatives Considered

Pure merge of existing artifacts at finalize, with no new capture: rejected because `results.gz` has already discarded per-item identity (see "Why capture, not pure merge"), so this would reintroduce free-text parsing.

Inline the outcomes in `Backup.status`: rejected because a large backup has tens of thousands of items and the list would exceed the etcd per-object size limit; a store artifact behind `DownloadRequest` is how every comparable per-item dataset is already delivered.

A dedicated CRD for the view: rejected as unnecessary API surface; the data is a read-only report, not desired state a controller reconciles toward, and `DownloadRequest` already exists for exactly this.

Fixing #9377 by writing async errors back into `results.gz` at finalize: this helps that specific bug but keeps the unstructured, unkeyable format; the structured artifact is a superset that addresses the same root cause.

## Security Considerations

The artifact contains resource group/namespace/name and error text, the same information already present in `results.gz`, `resource-list.json.gz`, and `itemoperations.json.gz`, and is stored in the same backup bucket with the same access controls and served through the same signed-URL `DownloadRequest` path.
No new secrets or data classes are exposed.
Error messages should carry no more detail than the existing `results.gz` strings, since they originate from the same log events.

## Compatibility

The feature is opt-in and defaults off, so existing backups and clients are unaffected.
`results.gz`, `resource-list.json.gz`, and all other artifacts are left byte-for-byte unchanged; the recorder only adds a parallel structured sink.
`GetBackupItemOutcomes` returns an empty result when the artifact is absent, so backups taken before this feature (or with it disabled) download cleanly.
The artifact carries `schemaVersion` for forward evolution.

## Implementation

Incremental, in dependency order, each step independently mergeable:

1. `internal/itemoutcome`: the `ItemOutcome`/`ItemOutcomes` types and the `Recorder`, with unit tests.
2. Persistence: layout key, `BackupInfo` field, `BackupStore` Put/Get pair and impl.
3. Capture: recorder on `Request`, `Observe`/`Skip` in `item_backupper.go`, structured hook in `log_counter_hook.go`.
4. Assembly: encode at `persistBackup`; reconcile async ops and rewrite at finalize.
5. Download: `DownloadTargetKind` const + enum marker + `GetDownloadURL` case; codegen.
6. Opt-in: `BackupSpec.CollectItemOutcomes`, server config toggle and threading; codegen.
7. CLI describe section (nice-to-have).

## Open Issues

- Should the artifact record a per-item outcome for cluster-scoped and additional (RIA) items, or only top-level included items? Leaning toward every item Velero touches, keyed by `ResourceIdentifier`.
- Whether to also surface a small per-outcome count summary on `Backup.status` (bounded, no per-item rows) so the common case needs no download; proposed as a follow-on.
- Restore-side parity, deferred to a separate proposal.
