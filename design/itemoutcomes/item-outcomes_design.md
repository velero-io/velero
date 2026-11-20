# Item Outcomes Design

## Abstract

Velero’s backup status and logs are aggregate and unstructured, so operators cannot reliably answer what happened to a specific item and why.
This proposal adds an opt-in, backup-only per-item outcomes artifact that records each item’s outcome and supporting evidence, finalized after asynchronous operations and volume verdicts.
The artifact is a stable, machine-readable contract for triage and automation; CLI views are consumers.

## Background

Velero writes multiple artifacts to object storage over the life of a backup.
The main ones are:

| Artifact | What it contains | Why it does not answer per-item outcomes |
|---|---|---|
| `<backup>.tar.gz` | Backup contents: the restorable Kubernetes objects | Contains data, not processing verdicts |
| `<backup>-logs.gz` | Execution log | Unstructured; not a stable API |
| `<backup>-results.gz` | Aggregate error and warning records | No item identity or per-item outcome |
| `<backup>-itemoperations.json.gz` | Asynchronous BackupItemAction operations | Covers async operations only; not the item’s overall disposition |
| `<backup>-volumeinfo.json.gz` | Per-volume method, result, and skip information | Volume-centric; no item ownership or additional-item provenance; updated during finalization |
| `<backup>-resource-list.json.gz` | Inventory of backed-up resources | Inventory, not outcome |
| `<backup>-podvolumebackups.json.gz`, `<backup>-volumesnapshots.json.gz`, CSI snapshot artifacts | Method-specific volume records | Split by method; no unified per-item verdict |
| `velero-backup.json` | Backup spec/status snapshot | Backup-level only |

Each artifact was added for a different purpose.
None is a per-item execution record.

Joining these artifacts at read time is possible in principle, but they use different identities, freshness points, and semantics.
They also cannot recover information Velero never recorded during processing.

Issue #9377 tracks the asynchronous BIA attribution gap that motivates this work.
In practice, operators must manually correlate errors across these artifacts to determine which item failed, which volume was skipped, and whether a later volume path rescued it.

## Goals
1. Emit an opt-in, backup-only per-item outcomes artifact for each item Velero processes or names.
2. Record item identity, outcome, attributed messages, controller ownership, additional-item provenance, and volume method/result evidence; fold volumeinfo verdicts at finalize.
3. Provide a stable schema and a basic CLI read surface (`json`/`table`/`raw`) for triage and automation.

## Non Goals
- Restore item outcomes; this is future work
- Replacing or enhancing existing artifacts
- Affecting core backup workflow


## High-Level Design

The artifact is a versioned, machine-readable per-item record produced in two phases: capture during item processing, and finalization after the backup archive is built.
Collection is opt-in; when disabled, the recorder is nil, no artifact is produced, and the backup path pays no artifact cost.

```text
Main phases

1. Capture  (while Velero processes backup items)
   item processing
     -> mint or update one row per item
     -> record outcome, messages, owner, reportedBy, and volume-path attempts
     -> write the unfinalized artifact with the backup bundle
   unfinalized =   "finalized": false; async operations and volume verdicts may still be pending

2. Finalize (after the backup archive is built and async work settles)
   re-read the artifact
     -> merge post-op rows   (items re-processed after async BackupItemAction operations)
     -> apply async ops      (completed or failed BackupItemAction results)
     -> fold volumeinfo      (final volume method, result, and skip verdicts)
     -> write the finalized artifact ("finalized": true only after the archive commit)
```

### Capture

Velero processes items within an item block.
As each item is processed, the recorder mints a row uniquely identified by group/resource, namespace, and name, or adds fields to an existing row.
A Pod's pre- and post-hooks run around the item block; hook failures are recorded against the associated Pod row.
Hook attribution has a known control-flow gap; see Open Issues.
A BackupItemAction (BIA) may update the item's name or namespace.
Renames are handled with in-memory aliases during capture so the artifact does not contain duplicate old- and new-identity rows.
Cross-finalize alias persistence is a known gap; see Open Issues.
The recorder derives the controller ownerReference from the item; this is the only true parentage in the artifact.
Additional items named by the BIA are backed up and recorded as provenance in `reportedBy`.
`reportedBy` is not parentage and is never used to propagate failures or infer causality.
When an item is skipped or fails, the reason is recorded against its row.
Velero otherwise spreads per-item reasons across logs, aggregate results, item operations, and volumeinfo; the recorder gives them one stable per-item place.
Skips, warnings, and failures move the row's outcome to the most severe recorded state; an outcome never downgrades.
Item-level skips are distinct from volume-path skips.

A row from the artifact looks like:

```json
{
  "groupResource": "persistentvolumeclaims",
  "namespace": "ns",
  "name": "data-disk",
  "outcome": "Skipped",
  "messages": ["NativeSnapshot volume skipped: policy"],
  "owner": {"groupResource": "datavolumes.cdi.kubevirt.io", "namespace": "ns", "name": "data-disk"},
  "reportedBy": [
    {"groupResource": "virtualmachines.kubevirt.io", "namespace": "ns", "name": "vm-a"}
  ]
}
```

The two relationships are different:

```text
owner:       datavolume/ns/data-disk  ->  pvc/ns/data-disk     parentage
reportedBy:  vm/ns/vm-a               ->  pvc/ns/data-disk     provenance, not parentage
```

The capture pass stores an unfinalized artifact with the backup bundle in object storage.

### Finalize

The finalize pass re-reads the artifact, merges rows produced while re-processing post-operation items, and applies settled asynchronous item operation results.
Finalize normally runs only after all asynchronous operations are terminal; timed-out operations are marked `Failed` before the backup enters `Finalizing`.
If `ApplyOperations` still observes a pending operation, this indicates an unknown or inconsistent operation state, not a normal timeout.
This is an extreme corner case we do not expect.
The artifact is not published as finalized; the finalizer retries for a bounded grace period and, if the operation is still pending, writes `finalized=false` and surfaces the anomaly.
Pending operations must not block the backup indefinitely.
The backup operations controller advances operations only while the backup is in `WaitingForPluginOperations`/`WaitingForPluginOperationsPartiallyFailed`, so the finalizer must not rely on a bare requeue to make a pending operation settle.
Volume info is available after volume verdicts settle and is folded into the item rows.
Volume entries are keyed by PVC namespace/name and PV name; the join is best-effort because either the PVC or PV row may be absent.
The structured summary belongs to the PVC row, or to the PV row when no PVC row exists; the verdict is mirrored to both rows when both exist.
The volume entity carries method-level attempts, final result, and skip reasons.
The volume evidence folded into the PVC row looks like:

```json
"volume": {
  "pvcNamespace": "ns",
  "pvcName": "data-disk",
  "pvName": "pvc-123",
  "result": "succeeded",
  "attempts": [
    {"method": "NativeSnapshot", "skipped": true, "skippedReason": "policy"},
    {"method": "CSISnapshot", "result": "succeeded"}
  ]
}
```

A volume-path skip recorded during capture can be rescued if another volume path captured the disk; an item-level skip must not be rescued.
The artifact is written back with `finalized: true` only after the final archive is committed.
If the capture artifact is missing or unreadable, finalize leaves it absent or unchanged; it never synthesizes a clean artifact.
Artifact read/write failures are surfaced without reclassifying item outcomes or fabricating a finalized result.

The finalized marker is a commit boundary, not a progress flag:

```text
capture:   finalized=false
finalize:  finalized=false   # async operations still pending
commit:    finalized=true    # archive committed, verdicts settled

missing capture artifact:
           leave absent; never write { "items": [], "finalized": true }
```

### Read

The artifact is exposed through the existing download path.
JSON is the stable contract; CLI table and raw output are views over the same data.

```bash
velero backup item-outcomes <backup> -o json
```

v1 is backup-only; the versioned envelope leaves room for restore support additively.

## Detailed Design

### Data model

The artifact has a versioned envelope and one row per item.
A row is identified by `groupResource`, `namespace`, and `name`.
`owner` is the controller ownerReference; `reportedBy` is additional-item provenance.
`skippedByVolume` distinguishes a volume-path skip from an item-level skip.

```go
type ItemOutcomes struct {
	SchemaVersion string        `json:"schemaVersion"`
	Kind          Kind          `json:"kind,omitempty"`
	BackupName    string        `json:"backupName,omitempty"`
	Finalized     bool          `json:"finalized"`
	Items         []ItemOutcome `json:"items"`
}

type ItemOutcome struct {
	GroupResource   string          `json:"groupResource"`
	Namespace       string          `json:"namespace,omitempty"`
	Name            string          `json:"name"`
	Outcome         Outcome         `json:"outcome"`
	Messages        []string        `json:"messages,omitempty"`
	Owner           *ItemRef        `json:"owner,omitempty"`
	ReportedBy      []ItemRef       `json:"reportedBy,omitempty"`
	SkippedByVolume bool            `json:"skippedByVolume,omitempty"`
	Volume          *VolumeOutcome  `json:"volume,omitempty"`
	VolumeAttempts  []VolumeAttempt `json:"volumeAttempts,omitempty"`
}
```

`VolumeAttempts` is capture-time evidence.
`ApplyVolumes` folds it into `Volume.Attempts` and clears it from rows covered by a volume entity.

```go
type ItemRef struct {
	GroupResource string `json:"groupResource"`
	Namespace     string `json:"namespace,omitempty"`
	Name          string `json:"name"`
}

type VolumeOutcome struct {
	PVCNamespace    string          `json:"pvcNamespace,omitempty"`
	PVCName         string          `json:"pvcName,omitempty"`
	PVName          string          `json:"pvName,omitempty"`
	Method          string          `json:"method,omitempty"`
	Result          VolumeResult    `json:"result,omitempty"`
	Skipped         bool            `json:"skipped,omitempty"`
	SkippedReason   string          `json:"skippedReason,omitempty"`
	Attempts        []VolumeAttempt `json:"attempts,omitempty"`
	DroppedAttempts int             `json:"droppedAttempts,omitempty"`
}

type VolumeAttempt struct {
	Method        string       `json:"method,omitempty"`
	Result        VolumeResult `json:"result,omitempty"`
	Skipped       bool         `json:"skipped,omitempty"`
	SkippedReason string       `json:"skippedReason,omitempty"`
}
```

### Skip provenance: item skip vs volume-path skip

A `Skipped` outcome alone does not say why the item was skipped.
The artifact distinguishes two cases:

| Case | Meaning | `skippedByVolume` | Rescuable at finalize? |
|---|---|---|---|
| Item skip | Velero decided not to back up the item itself, e.g. a BIA returned no object or an item-level policy excluded it | `false` | No |
| Volume-path skip | The item was processed, but one volume method declined the volume, e.g. a PodVolumeBackup opt-out or a NativeSnapshot policy decision | `true` | Yes, if another volume method captures the disk |

A volume-path skip is provisional.
A PVC may be attempted by PodVolumeBackup, NativeSnapshot, and CSISnapshot; one method skipping does not decide the volume.
At finalize, volumeinfo provides the final verdict.
If another method captured the disk, the item row is rescued to `Succeeded`.
If every method skipped, the final volume result remains skipped.

An item-level skip is final.
Even if a volume associated with the item is captured by another path, the item itself was not part of the backup and must not be rescued.
This is why `skippedByVolume` is serialized: the finalize pass runs in a separate process and must know which skips are eligible.

A volume-path skip before finalize:

```json
{
  "outcome": "Skipped",
  "skippedByVolume": true,
  "messages": ["NativeSnapshot volume skipped: policy"],
  "volume": {
    "skipped": true,
    "attempts": [
      {"method": "NativeSnapshot", "skipped": true, "skippedReason": "policy"}
    ]
  }
}
```

The same row after a successful CSI capture:

```json
{
  "outcome": "Succeeded",
  "volume": {
    "result": "succeeded",
    "attempts": [
      {"method": "NativeSnapshot", "skipped": true, "skippedReason": "policy"},
      {"method": "CSISnapshot", "result": "succeeded"}
    ]
  }
}
```

Skipped attempts and their reasons remain as evidence after a rescue.
Readers must use the final `volume.result` and the row outcome, not the presence of a skipped attempt, to decide whether the volume was captured.
The item-skip rule wins even if a volume-path skip is also recorded; it must not depend on call order.

### Recorder lifecycle

Rows are minted at `Named` when an edge names an item, and at `Succeeded` when the item is observed.
Updates only raise the outcome according to precedence.
Item-level skips and volume-path skips are tracked separately so a volume skip can be rescued later.
`Rekey` moves or merges a row after a BIA rename and follows aliases within the capture process.

```text
             Observe                Warn
Named ───────────────► Succeeded ─────────► Warning
                           │
                           ├── Skip ──────► Skipped (item)
                           ├── SkipVolume ► Skipped (volume-only)
                           └── Fail ──────► Failed

Skipped (volume-only) ─── volume success ───► Succeeded
Skipped (item)        ─── volume success ───► still Skipped
```

Precedence is `Named < Succeeded < Warning < Skipped < Failed`.
The recorder is the only place that changes a row outcome; the finalize overlays (`ApplyOperations`, `ApplyVolumes`) follow the same monotone rule, with the volume rescue as the explicit exception.

### Capture integration

During item processing, the recorder is attached to the item identity.
The capture path records observation, owner, additional-item provenance, failures, archive-write failures, and volume-path attempts.
Hook failures target the associated Pod row once the hook handler returns an error; see Open Issues for the current `on-error` gap.

```go
outcome := req.ItemOutcomes.For(id)
outcome.Observe()
recordOwner(metadata, outcome)

for _, additional := range additionalItems {
	req.ItemOutcomes.SetReportedBy(additional, currentItem)
}

if err := writeToArchive(obj); err != nil {
	outcome.Fail(fmt.Sprintf("failed to write item to backup archive: %v", err))
}

outcome.Rekey(renamedID) // if a BIA changes name or namespace
```

Additional items named by a BIA are backed up and recorded as provenance in `reportedBy`.
`reportedBy` is not parentage and is never used to propagate failures or infer causality.
When a BIA renames an item, the row moves to the new identity so later writes do not mint a second row.

### Finalize and volume fold

Finalize re-reads the capture artifact, merges rows produced while re-processing post-operation items, applies settled async operation results, and folds the final volume verdicts.
The artifact is marked `finalized` only after the archive is committed.

```go
stored := store.GetBackupItemOutcomes(name)
Merge(stored, finalizeRecorder.Result())
pending := ApplyOperations(stored, operationResults)
ApplyVolumes(stored, volumeOutcomes)

if len(pending) > 0 {
	// bounded retry; do not publish finalized=true
	return ErrOperationsPending
}
stored.Finalized = true
store.PutBackupItemOutcomes(name, stored)
```

`ApplyOperations` handles three states: completed leaves the verdict unchanged, failed raises the row to `Failed` and appends the error, pending is returned to the caller.
A failed operation with no existing row mints one.
Timed-out operations are marked `Failed` before the backup enters finalization; a pending observation is an extreme corner case indicating an unknown or inconsistent operation state, not a normal timeout.
Pending operations are returned rather than silently dropped.
The finalizer uses that signal for a bounded retry.
If the operation is still pending after the grace period, it writes `finalized=false` and surfaces the incomplete artifact.
A bare requeue is not sufficient because the backup operations controller only advances operations in `WaitingForPluginOperations`/`WaitingForPluginOperationsPartiallyFailed`.
`ApplyVolumes` deduplicates PVC/PV identities, folds method-level attempts, mirrors the verdict to both rows when both exist, and applies the rescue rule only to volume-path skips.

If the capture artifact is missing or unreadable, the finalize pass leaves it absent or unchanged; it never synthesizes a clean artifact.
If the schema or kind is unsupported, the artifact is left unchanged and the reason is surfaced.

### Persistence and API

Collection is opt-in through the Backup spec, with an optional server default.
The same field is exposed on the Schedule backup template.
The artifact is stored with the backup bundle and exposed through the existing download path.

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: bk-1
spec:
  collectItemOutcomes: true
```

```text
Object key:     backups/<backup>/<backup>-item-outcomes.json.gz
Download kind:  BackupItemOutcomes
```

`BackupInfo` carries the artifact into `PutBackup`.
`GetBackupItemOutcomes` returns an explicit not-found signal when the object is absent; it does not fabricate an empty artifact.
The CRD, deepcopy, builder, and download-target enum changes are part of the same API surface.

### CLI

JSON is the contract.
Table and raw output are views over the same artifact.

```bash
velero backup item-outcomes bk-1 -o json
velero backup item-outcomes bk-1 -o table
velero backup item-outcomes bk-1 --raw
```

```text
GROUP/RESOURCE          NAMESPACE  NAME       OUTCOME  MESSAGES
persistentvolumeclaims  ns         data-disk  Skipped  1
```

The command warns when the artifact is unfinalized, uses an unsupported schema, records another operation kind, or when the Backup reports errors that may not belong to a listed item.

### Error handling and edge cases

```text
collection disabled        -> no recorder, no artifact
capture artifact missing   -> leave absent; never write finalized empty
artifact corrupt           -> leave unchanged; surface the error
unsupported schema/kind    -> leave unchanged; surface the warning
pending async operation    -> extreme corner case (unknown/inconsistent state)
                             bounded retry; if still pending after grace:
                             write finalized=false and surface
archive not committed      -> do not write finalized=true
BIA rename during capture  -> in-memory alias, one row
BIA rename across finalize -> open issue; async IDs may still use the old name
```

### Implementation sequence

The changes are layered so each stage can be reviewed and tested independently.
The stage table, dependencies, and primary tests are in Implementation.

```text
contract -> recorder -> persistence/API -> capture -> finalize -> CLI -> docs/tests
```

### Testing

```bash
go test ./internal/itemoutcome/...
go test ./pkg/backup/... ./pkg/persistence/...
go test ./pkg/controller/ -run 'TestBackupFinalizer'
go test ./pkg/cmd/cli/backup/ -run 'ItemOutcomes|CollectItemOutcomes'
go build ./...
```

Finalize tests must cover:

- pending operations at finalize -> no write with `finalized=true`
- retry after operations settle -> `finalized=true`
- grace period expires -> `finalized=false` and the incomplete artifact is surfaced
- no infinite requeue

## Alternatives Considered

- **Extend `<backup>-results.gz`.** Rejected: it is an aggregate error/warning map, not a per-item record. Adding per-item identity, ownership, reporting, and volume evidence would break its schema and force every consumer to change.
- **Extend `<backup>-itemoperations.json.gz`.** Rejected: it covers asynchronous BackupItemAction operations only. It does not represent ordinary item processing, ownership, or volume-path outcomes.
- **Extend `<backup>-volumeinfo.json.gz`.** Rejected: it is volume-centric. It cannot express item identity, controller ownership, additional-item provenance, or non-volume outcomes.
- **Join the existing artifacts at read time.** Rejected: they use different identities, freshness points, and semantics. The join is fragile, and it cannot recover information Velero never recorded during processing.
- **Derive item rows from logs.** Rejected: logs are unstructured, high-volume, and not a stable API.
- **Emit a CR or Kubernetes event per item.** Rejected: annotation/status size, retention, and API-server load do not scale to thousands of items. Object storage is the right scope.

## Security Considerations

The artifact is stored in the BackupStorageLocation alongside backup metadata and logs and inherits the same encryption, access controls, retention, and deletion behavior.
It is read through the existing DownloadRequest path, so it introduces no new RBAC or cluster privileges.
Messages and volume skip reasons may contain operational details such as bucket names, paths, or plugin error text.
They are capped in count and size, and the artifact is documented as sensitive in the same way as backup logs.
No secrets are intentionally collected.

## Compatibility

Collection is opt-in and default-off.
Backups that do not set `collectItemOutcomes` produce no artifact and behave exactly as before.
Existing backups and restores are unaffected.
The artifact is schema-versioned.
The CLI warns on a schema it does not understand, and the finalize pass refuses to rewrite an unsupported schema or kind.
A capture artifact produced by a newer server may remain unfinalized if an older server finalizes the backup; this is surfaced to the reader rather than silently rewritten.
The Backup and Schedule spec additions are backward-compatible.
Restore artifacts are additive future work and do not change in v1.

## Implementation

The implementation is a single PR. The stages below are logical commit groups within that PR; the final history may squash or reorder them before merge. The boundaries are deliberately separable if review load later requires splitting, but splitting is not part of the current plan.

| Stage | Deliverable | Depends on | Primary tests | Default behavior |
|---|---|---|---|---|
| 1. Contract | schema, outcomes, `ItemRef`, volume types | — | JSON shape, precedence | No change |
| 2. Recorder | recorder, merge, rekey, operations, volume fold | Contract | recorder/merge/volumes | No change |
| 3. Persistence/API | object key, `BackupInfo`, download target, spec flag/CRD | Contract | persistence/controller | No change; default off |
| 4. Capture | item processing, owner, reportedBy, hooks, archive failures | Recorder + API | backup/item-backupper | Opt-in only |
| 5. Finalize | merge post-op rows, async ops, volumeinfo, finalized order | Capture | finalize/finalizer | Opt-in only |
| 6. CLI | `item-outcomes`, JSON/table/raw, warnings | Persistence/API | CLI | Opt-in only |
| 7. Docs/verification | design doc, changelog, envtest/e2e, real cluster | All | CI | Opt-in only |

The feature remains default-off through every stage.
Each stage has unit tests; the finalize stage adds controller/finalizer tests, one envtest/e2e with a BIA that creates an async operation, and real-cluster checks for:

- a metadata-only backup
- a volume-path skip with a rescue
- a healthy volume success path
- a large namespace with many items and events

Rollout: docs and changelog alongside the final stage; server default remains optional; no restore changes.
Target release: TBD.
Contributors: Joseph Antony Vaikath.
Risks and follow-ups: hook attribution (#10816), alias persistence across the capture-to-finalize boundary, and full-volume verification on a healthy CSI cluster.
Pending-operation grace/retry behavior is part of stage 5; the controller implementation and tests must match the policy in Detailed Design.

## Open Issues

Two correctness gaps are tracked outside the core artifact design.
Both are intended to land in separate PRs; neither changes the artifact shape.

### Hook failure attribution

- Issue: #10816.
- Problem: `HandleHooks` treats an omitted `on-error` as Continue while the executor defaults it to Fail. A failed pre- or post-hook can therefore be recorded in `Backup.status.hookStatus` without returning an error to the item outcomes capture path.
- Impact: a Pod row can read `Succeeded` even though its hook failed.
- Follow-up PR: normalize the effective `on-error` mode for control flow and add pre/post hook attribution tests against the real `DefaultItemHookHandler`.
- Until fixed: readers must reconcile the artifact with `Backup.status.hookStatus`.

### Alias persistence across finalize

- Problem: in-memory aliases handle BIA renames during capture, but aliases are not persisted. Async operation identifiers and finalize-pass rows can still use the old identity.
- Impact: a rename followed by a failed async operation can mint a duplicate row under the old name or leave a dangling owner/reporter edge.
- Follow-up PR: persist aliases in the artifact envelope and resolve them in operation/volume overlays, or rewrite operation identifiers at rekey time. Add a rename plus failed async operation test.
- Until fixed: BIA-driven renames are only safe within the capture process.

## Future Work

The following are deliberately out of scope for this PR:

- **Restore item outcomes.** Reuse the versioned envelope and per-item row model for restore, with restore-specific outcomes and volume evidence. This is additive; the backup artifact v1 remains unchanged.
- **Dedicated CLI for interpreting the artifact.** Add a generic CLI surface for per-item profiles, owner/reportedBy/volume summaries, filters, and machine-readable output. Keep it generic and consumer-oriented; no KubeVirt-specific policy in upstream.
