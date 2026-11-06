# Per-item outcomes: implementation design

**Status:** Draft.

**Tracking:** [#10503 Per-item outcomes for observability](https://github.com/velero-io/velero/issues/10503).

## Abstract

An implementation design for the per-item outcomes artifact: the model, the storage format, where rows are created in the backup and restore flows, where the artifact is uploaded, and how it is read.
It is written for a reviewer of the code; the problem statement is in #10503.

## Background

The feature is opt-in and produces one artifact per backup or restore.
Two producers write it, `pkg/backup` and `pkg/restore`, and both use the same model and the same renderer.
Rows are created while Velero decides an item's fate, because no existing artifact stores an ordinary item's verdict with a stable key.
Finalize applies the results that settle later: asynchronous item operations, and backup volume results.
Everything below names the package and function that owns each step.

## Goals

- Record a verdict, its messages, the item's identity, and its parent at the point Velero decides the item's fate, for backups and restores.
- Apply the asynchronous operation results and the backup volume results once, at finalize, and mark the artifact complete only after they are applied.
- Read the artifact through one renderer without reading any other artifact.

## Non Goals

- **Data-integrity verification.** Velero reports what CSI, node-agent, PodVolumeRestore, and DataDownload report.
- **Replacing existing artifacts.** Logs, results, resource lists, item operations, and volume info are unchanged.
- **Restore volume verdicts.** Restore volume info has no reliable failure signal, so no verdict is synthesized.
- **Compatibility with pre-release artifacts.** A `BackedUp` value was written by one development build; no released version produced it.
- **A UI or long-term analytics.**

## High-Level Design

A recorder accumulates rows during the operation and is flushed once to the object store.
The artifact is read back at finalize, the two write-time joins are applied, and it is written again with `finalized` set.
Readers download the artifact through a `DownloadRequest` and never consult volume info, item operations, or the log.

| Package | Responsibility | Key symbols |
|---|---|---|
| `internal/itemoutcome` | model, recorder, rollup, finalize transforms | `ItemOutcomes`, `ItemOutcome`, `Recorder`, `Item`, `ApplyOperations`, `ApplyVolumes`, `Rollup`, `ParentFromOwnerReference` |
| `pkg/backup` | capture and backup finalize | `itemBackupper.backupItem`, `kubernetesBackupper.FinalizeBackup` |
| `pkg/restore` | capture | `restoreItem`, `recordItemOutcome` |
| `pkg/controller` | wiring, first write, restore finalize, download allowlist | `persistBackup`, `runValidatedRestore`, `restoreFinalizerReconciler.Reconcile` |
| `pkg/persistence` | object keys, put/get, signed URLs | `getBackupItemOutcomesKey`, `PutBackupItemOutcomes`, `PutRestoreItemOutcomes` |
| `pkg/apis/velero/v1` | spec fields and download kinds | `CollectItemOutcomes`, `DownloadTargetKindBackupItemOutcomes`, `DownloadTargetKindRestoreItemOutcomes` |
| `pkg/cmd/cli/backup`, `pkg/cmd/cli/restore` | commands and flags | `NewItemOutcomesCommand` |
| `pkg/cmd/util/itemoutcomes` | shared renderer | `PrintRollup` |
| `pkg/cmd/util/output` | describe integration | `describeBackupItemOutcomes`, `describeRestoreItemOutcomes` |

### Lifecycle

```text
capture per item  →  first write  →  finalize  →  read
```

| Moment | What runs | Artifact state |
|---|---|---|
| Per item | the recorder records the verdict, messages, parent, and, for restores, source and action | in memory only |
| End of synchronous work | `persistBackup` (backup) or `runValidatedRestore` (restore) encodes the recorder's `Result()` | written with `finalized: false` |
| Finalize | `FinalizeBackup` (backup) or `restoreFinalizerReconciler.Reconcile` (restore) re-reads, applies operations and, for backups, volumes, and writes again | `finalized: true` |
| Read | `PrintRollup` or the describers | the finalized artifact |

The first write is what makes a run that dies before finalize inspectable: the artifact exists and says it is provisional.

## Detailed Design

### The model

The artifact is one JSON document.

```go
const SchemaVersion = "v1"

type ItemOutcomes struct {
	SchemaVersion string        `json:"schemaVersion"`
	Kind          Kind          `json:"kind,omitempty"`   // "backup" or "restore"
	Finalized     bool          `json:"finalized"`
	Items         []ItemOutcome `json:"items"`
}

type ItemOutcome struct {
	GroupResource string         `json:"groupResource"` // e.g. "deployments.apps"
	Namespace     string         `json:"namespace,omitempty"`
	Name          string         `json:"name"`
	Outcome       Outcome        `json:"outcome"`
	Action        string         `json:"action,omitempty"`        // restore only: "created" or "updated"
	Messages      []string       `json:"messages,omitempty"`
	Parent        *ItemRef       `json:"parent,omitempty"`
	ParentSource  *ParentSource  `json:"parentSource,omitempty"`
	Source        *ItemRef       `json:"source,omitempty"`        // restore only: the object in the backup
	Volume        *VolumeOutcome `json:"volume,omitempty"`        // backup only: the volume this row owns
}

type VolumeOutcome struct {
	PVCNamespace  string       `json:"pvcNamespace,omitempty"`
	PVCName       string       `json:"pvcName,omitempty"`
	PVName        string       `json:"pvName,omitempty"`
	Method        string       `json:"method,omitempty"`
	Result        VolumeResult `json:"result,omitempty"` // empty when skipped
	Skipped       bool         `json:"skipped,omitempty"`
	SkippedReason string       `json:"skippedReason,omitempty"`
}
```

`Outcome` is recorded at capture time.
Repeated writes for one item collapse into one row:

| Value | Rank | Meaning |
|---|---|---|
| `Named` | -1 | an ownership edge named the item; nothing processed it |
| `Succeeded` | 0 | processed with no warning or error |
| `Warning` | 1 | processed, but something was reported |
| `Skipped` | 2 | excluded or deliberately not processed |
| `Failed` | 3 | an error was recorded, synchronously or by an operation |

An upgrade only raises the rank, so the recorder never loses the worst verdict seen for an item.

`ParentSource` records where the edge came from.
The plugin's view outranks the object's own metadata, which keeps the tree independent of the order concurrent item blocks finish:

| Value | Rank | Source |
|---|---|---|
| `ownerReference` | 0 | `metadata.ownerReferences` (controller reference only) |
| `additionalItem` | 1 | a plugin's `AdditionalItems` |

Invariants enforced by the package:

- one row per `(groupResource, namespace, name)`; writes merge by rank;
- `Messages` is capped at `MaxMessagesPerItem = 5`;
- `Result()` sets `Kind`, caps messages, and sorts rows by group resource, namespace, and name;
- `Named` is not a verdict: it exists so an edge cannot claim a success nobody established;
- `SupportedSchemaVersion()` accepts `""` and `"v1"`, so an artifact written before the field existed reads as v1.

### Recorder

`Recorder` is the write side; `Item` is the per-item handle.

| Call | Effect |
|---|---|
| `NewRecorder()` | recorder for `KindBackup` |
| `NewRecorderFor(kind)` | recorder for either kind |
| `For(id) *Item` | handle for one `velero.ResourceIdentifier`; returns `nil` when the recorder is `nil` |
| `Observe()` | marks processing started; mints `Succeeded` or upgrades a `Named` row |
| `Fail(msg)` | upgrades to `Failed`, appends `msg` |
| `Warn(msg)` | upgrades to `Warning`, appends `msg` |
| `Skip(reason)` | upgrades to `Skipped`, appends `reason` |
| `SetAction(action)` | records `created` / `updated` for a successful restore |
| `SetSource(source)` | records the backup identity for a restore |
| `SetParent(parent)` | records an `additionalItem` edge |
| `SetOwnerParent(parent)` | records an `ownerReference` edge |
| `Rekey(id)` | moves the row to a new identity after a plugin rename |

Minting rules:

- `rowFor` mints `Succeeded`; every verdict is an upgrade from there.
- `edgeRowFor` mints `Named`; an edge alone never asserts a verdict.
- `Result()` is the only conversion from recorder state to `ItemOutcomes`.

The recorder is guarded by a mutex.
Item blocks are processed concurrently, and two blocks can write the same child or claim different parents for it; rank ordering makes the surviving value deterministic.

A `nil` recorder represents the feature being disabled for one operation.
Every `Item` method is a no-op on a `nil` handle, so capture sites need no existence checks beyond `For`.

### Enablement

| Surface | Symbol |
|---|---|
| `BackupSpec` | `CollectItemOutcomes *bool` (`json:"collectItemOutcomes,omitempty"`) |
| `RestoreSpec` | `CollectItemOutcomes *bool` (`json:"collectItemOutcomes,omitempty"`) |
| Server default | `--default-collect-item-outcomes` → `config.DefaultCollectItemOutcomes`, default `false` |
| `backup create` | `--collect-item-outcomes` |
| `restore create` | `--collect-item-outcomes` |
| `schedule create` | `--collect-item-outcomes`, copied into the backup spec |

`itemoutcome.CollectEnabled(spec, serverDefault)` resolves the per-operation value over the server default.
The backup controller stores the resolved value back into `request.Spec.CollectItemOutcomes` and creates a recorder only when it is true.
The restore controller and the restore finalizer resolve the same way.
When the value is false, no recorder exists and no artifact is written.

### Capture: backup

Capture happens in `itemBackupper.backupItem` (`pkg/backup/item_backupper.go`).

| Point | Call |
|---|---|
| item entry | `For(resourceIdentifier).Observe()` |
| owner reference | `recordOwnerParent` → `SetOwnerParent` |
| any item error | `failItem` → `Fail(aggregate)` |
| after plugin actions | `Rekey(resourceIdentifier)` when a plugin changed the name or namespace |
| skipped volume | `trackSkippedVolume` → `Skip("<approach> volume skipped (<pvc/pv>): <reason>")` |
| PV snapshot path | `outcomeFor(pv, persistentvolumes)` records warnings about the chosen snapshot method: no data-movement support, no CSI spec, or a resource-policy error |
| additional items | `SetParent(child, current)` before the child is backed up |
| missing additional item | `For(child).Warn("additional item was not found in the Kubernetes API; it was not backed up")` |
| no pod volume backupper | `Warn("no pod volume backupper; pod volumes were not backed up")` |

Hook failures are recorded in `pkg/backup/backup.go`, not in the item backupper:

- `handleItemBlockPreHooks` records `Fail("pre hook failed: <err>")` against the pod, because a failed pre-hook marks the pod as backed up before `backupItem` reaches `Observe`.
- `handleItemBlockPostHooks` records `Fail("post hook failed: <err>")` against the pod, which was already written before its post-hooks ran.

Owner-reference parentage is derived by `ParentFromOwnerReference`:

- it uses `metav1.GetControllerOf`, so only the controller reference counts;
- the owner's scope comes from discovery: a namespaced owner inherits the child's namespace, a cluster-scoped owner has none;
- a self-edge is refused.

### Capture: restore

Capture happens in `restoreItem` and is finished by `recordItemOutcome` (`pkg/restore/restore.go`).

`restoreItem` prepares three things before any plugin runs:

- `ownerObj`, a deep copy of the object as it came from the backup, taken only when outcomes are collected;
- `sourceID`, the object's identity in the backup;
- `outcome`, the handle for the target identity, on which it calls `Observe()` and `SetSource(sourceID)`.

A `defer` calls `recordItemOutcome` on every path after the item is claimed, once `itemStatus` is final.

`recordItemOutcome` performs, in order:

1. `Rekey` to `itemStatus.createdName` when the API server generated a name.
2. For a `PersistentVolume`, `SetOwnerParent` to the `claimRef` PVC, with the PVC's namespace mapped through `Spec.NamespaceMapping`.
3. `SetOwnerParent` from the controller reference of `ownerObj`, with `ownerObj`'s namespace set to the target namespace, so the pre-action parentage survives a plugin that rewrote the object's metadata.
4. `Fail` with the flattened errors and warnings when `errs` is non-empty, otherwise `Warn` with the flattened warnings when `warnings` is non-empty.
5. `SetAction("created")` or `SetAction("updated")` from `itemStatus.action`.
6. `Skip(skipReason)`, defaulting to `"not restored"`.

Messages are flattened from `results.Result` by `outcomeMessages`: Velero, then Cluster, then each namespace prefixed with its name, then sorted.

Additional items record their edge before the recursive call, with the namespace mapped:

```go
// abbreviated: both keys are built from groupResource, namespace, and name
ctx.itemOutcomes.For(additionalItemKey).SetParent(currentItemKey)
```

Setting the edge first keeps it attached when a plugin-generated name rekeys the child.

### Writes

#### Backup: first write

`persistBackup` (`pkg/controller/backup_controller.go`) encodes `backup.ItemOutcomes.Result()` with `encode.ToJSONGzip` and passes the buffer as `BackupItemOutcomes` on a `persistence.BackupInfo`.
`object_store.go` writes that reader at the layout key as part of the backup tarball.
`Finalized` is false at this point.

#### Backup: finalize

`kubernetesBackupper.FinalizeBackup` (`pkg/backup/backup.go`) runs after volume info has been updated and rewrites the artifact:

1. `GetBackupItemOutcomes(name)`;
2. `updateItemOutcomes` → `ApplyOperations(operationResults(asyncBIAOperations))`, logging any operation that is not terminal;
3. `ApplyVolumes(volumeOutcomes(volumeInfos))`;
4. `putItemOutcomes` → `PutBackupItemOutcomes(name, buf)`.

The finalizer only reaches this point once operations are terminal; the operations and finalizer controllers enforce that.

#### Restore: first write

`runValidatedRestore` (`pkg/controller/restore_controller.go`) takes `restoreReq.ItemOutcomes.Result()`, applies the operations that have already settled with `ApplyOperations`, and calls `putRestoreItemOutcomes`.
A restore with no pending operations is final after this write.
A restore that waits on operations is rewritten by the finalizer.

#### Restore: finalize

`restoreFinalizerReconciler.Reconcile` (`pkg/controller/restore_finalizer_controller.go`) re-reads with `GetRestoreItemOutcomes`, applies `ApplyOperations`, and calls `putRestoreItemOutcomes` again.
There is no volume fold on this path.

#### Operation overlay

`ApplyOperations(items, operations)` takes `[]OperationResult`, a neutral shape declared in `internal/itemoutcome` so the same function serves both operations:

```go
type OperationResult struct {
	GroupResource string
	Namespace     string
	Name          string
	State         OperationState // succeeded, failed, pending
	Error         string
}
```

| State | Effect |
|---|---|
| `succeeded` | no change; the item was processed synchronously and the operation finishing only confirms it |
| `failed` | row is upgraded to `Failed` and the error is appended; a missing row is minted at `Failed` |
| `pending` | returned to the caller, left out of the artifact |

The overlay is monotone and never touches `Parent`.
`Finalized` is set to `len(pending) == 0`.

Operation state is projected by the callers:

| Source | Mapping |
|---|---|
| `itemoperation.OperationPhaseCompleted` | `succeeded` |
| `itemoperation.OperationPhaseFailed` | `failed` |
| anything else | `pending` |

#### Volume fold

`ApplyVolumes(items, volumes)` attaches the backup volume verdicts to the rows that own them.

1. Drop entries with no result and no skip flag; nothing was concluded.
2. Collapse entries by `(pvcNamespace, pvcName, pvName)`; one volume can have a skipped twin and a captured entry.
3. When merging, rank `failed > succeeded > skipped` and fill missing identity or method fields from the loser.
4. Choose the row: the PVC row when the volume names one, otherwise the PV row.
5. Drop the verdict when neither row exists; the artifact is per-item and volume info still records it.
6. Set `row.Volume`; a failed result upgrades the row to `Failed` and appends a message such as `volume pvc=<ns>/<name> pv=<name> (<method>) failed`.

`ApplyVolumes` sets `Finalized = true`.

### The artifact at rest

| Property | Value |
|---|---|
| Encoding | gzip'd JSON |
| Backup key | `backups/<backup>/<backup>-item-outcomes.json.gz` |
| Restore key | `restores/<restore>/<restore>-item-outcomes.json.gz` |
| Schema version | `"v1"`; `""` is accepted as v1 |
| `Kind` | `backup` or `restore` |
| `Finalized` | false at first write, true only after the finalize transforms |

`GetBackupItemOutcomes` and `GetRestoreItemOutcomes` return an empty artifact with the correct `Kind` when the key is absent, so callers inside the controllers do not branch on a missing file.
A reader that must distinguish "not collected" from "empty" uses the `DownloadRequest` result, which returns `ErrNotFound` for a missing target.

Reads outside the controllers go through `DownloadRequest`:

| Target kind | Signed object |
|---|---|
| `BackupItemOutcomes` | `getBackupItemOutcomesKey(target.Name)` |
| `RestoreItemOutcomes` | `getRestoreItemOutcomesKey(target.Name)` |

`download_request_controller.go` treats `RestoreItemOutcomes` as a restore-scoped target and verifies the named restore exists before signing.
The `DownloadRequest` CRD's `spec.target.kind` enum must include both new values; without it the API server rejects the request before the controller sees it.

### Reading it

Both commands are registered on their parent command and share one renderer.

| Flag | Behavior |
|---|---|
| *(none)* | pretty-printed artifact JSON |
| `--raw` | compact JSON rather than the indented form |
| `--by-owner` | rollup: table by default, or `-o json` / `-o tree` |
| `-o, --output` | `table`, `tree`, or `json`; requires `--by-owner` |
| `--all` | with `--by-owner` table, add the per-outcome count columns and keep clean subtrees |
| `--timeout`, `--cacert`, `--insecure-skip-tls-verify` | download controls |

`PrintRollup` (`pkg/cmd/util/itemoutcomes/render.go`) is the shared reader.
It calls `itemoutcome.Rollup` and renders one of three shapes:

| Format | Rows | Ordering | Filtering |
|---|---|---|---|
| `table` | indented `GROUP/RESOURCE, NAMESPACE, NAME, OUTCOME, ITEMS` | worst-first roots, children sorted by resource then name | clean subtrees pruned unless `--all` |
| `tree` | indented `resource name (namespace)` | same | never filtered |
| `json` | `[]OwnerSummary` | same | never filtered |

`--all` appends `BACKEDUP`/`RESTORED`, `WARNING`, `FAILED`, `SKIPPED`, and `NAMED` counts, all computed per subtree.
The success column header comes from `OutcomeLabel(kind, Succeeded)`: `BackedUp` for backups, `Restored` for restores.

A row that raises its owner prints its verdict in brackets and one `- message` line per message:

```text
persistentvolumeclaims cirros-disk (vm-ns)  [Failed]
  - volume pvc=vm-ns/cirros-disk pv=pv-1 (CSISnapshot) failed
```

The commands print these warnings to stderr before the rollup:

| Condition | Warning |
|---|---|
| `Backup.status.Errors` / `Restore.status.Errors` > 0 | the count need not belong to a listed row; see the logs |
| `!artifact.Finalized` | the finalize transforms were not applied: backup volume and async-operation verdicts may be missing |
| unsupported `schemaVersion` | output may be incomplete |
| `kind` does not match the command | the artifact records the other operation |

`backup describe --details` and `restore describe --details` call `describeBackupItemOutcomes` / `describeRestoreItemOutcomes`.
They print a counts line, a line for unresolved `Named` rows, the unfinalized and schema warnings, and the failed or warned rows anchored at the root of their chain.
The backup structured describer publishes the same artifact under `itemOutcomes`, or `errorGettingItemOutcomes` when it is absent.

## Alternatives Considered

- **Capture from the log hook.** Rejected: identity and severity become properties of log formatting, and a failure without the expected fields is invisible.
- **Join the existing artifacts at read time.** Rejected: no artifact stores an ordinary item's verdict, and the join would be duplicated in every client.
- **Build the artifact only at finalize.** Rejected: a finalize-only pass cannot recover a synchronous item's verdict or messages.
- **Store the rollup instead of the rows.** Rejected: it freezes the rule and discards the data a tree or a different view needs.
- **One artifact per operation kind.** Rejected: it duplicates the schema, the recorder, and the renderer for a different `kind` and verb.

## Security Considerations

The artifact stores resource identities and messages Velero already writes to its logs.
It adds no secret material and lives beside the other per-operation artifacts under the same bucket, prefix, and access controls.
The download path reuses `DownloadRequest`, so the existing namespace and existence checks apply.

## Compatibility

- The feature is additive and opt-in; nothing changes for a backup or restore that does not collect outcomes.
- No existing artifact changes shape.
- An absent artifact is reported as "not collected", not as an empty success.
- An artifact with `finalized: false` is reported as provisional.
- An unrecognized `schemaVersion` produces a warning; the reader does not claim the output is complete.
- A `kind` mismatch is reported instead of rendered as the wrong operation.
- `BackedUp` was written by a development build only; there is no released vocabulary to migrate.

## Implementation

### Validation

| Area | Tests |
|---|---|
| recorder precedence, rekey, message cap | `internal/itemoutcome/itemoutcome_test.go` |
| parent resolution, dangling parents, cycles | `internal/itemoutcome/rollup_test.go`, `internal/itemoutcome/itemoutcome_test.go` |
| volume fold, dedupe, row ownership | `internal/itemoutcome/volumes_test.go` |
| operation overlay, pending, finalized | `internal/itemoutcome/operations_test.go` |
| backup capture and finalize | `pkg/backup/*_test.go` |
| restore capture | `pkg/restore/restore_test.go` |
| controller wiring and persistence | `pkg/controller/*_test.go`, `pkg/persistence/object_store_test.go` |
| CLI flags, output, warnings | `pkg/cmd/cli/{backup,restore}/item_outcomes_test.go` |
| renderer table, tree, JSON | `pkg/cmd/util/itemoutcomes/render_test.go` |
| describe integration | `pkg/cmd/util/output/backup_describer_itemoutcomes_test.go`, `backup_structured_describer_itemoutcomes_test.go` |

The failure matrix to keep covered: synchronous error, warning, benign skip, conflict skip, async failure, volume failure, hook failure, namespace-mapped restore, generated name, cluster-scoped item, dangling parent, cycle, absent artifact, unfinalized artifact, unknown schema, wrong kind.

### Phases

- **Phase 1:** model, recorder, backup capture, backup finalize, persistence, CLI, describe.
- **Phase 2:** restore capture, restore first write, restore finalize, restore CLI and describe.
- **Phase 3:** restore volume verdicts once each restore method has a defined terminal state.
- **Phase 4:** documentation and Helm support for the server default.

Backup and restore item-level phases are implemented on `itemoutcomes-self-describing`.
Phase 3 is not.

## Open Issues

- `ApplyVolumes` sets `Finalized = true` unconditionally after `ApplyOperations` has set it from pending operations. The caller order makes the volume fold authoritative; the flag should be computed in one place instead.
- The restore artifact key omits the `restore-` prefix that `results`, `logs`, `resource-list`, and `itemoperations` use. It matches the existing `volumeinfo` key pattern.
- Backup encodes with `encode.ToJSONGzip`; restore uses a hand-rolled gzip writer and `json.Encoder`. Both produce gzip'd JSON, but the two paths should be one.
- The `DownloadRequest` CRD enum must be regenerated and applied for the new target kinds; a cluster running an older CRD rejects the request before the controller can serve it.
- Restore volume verdicts need one trusted terminal state per method (PodVolumeRestore phase, DataDownload phase, or provisioning success) before they can be added.
