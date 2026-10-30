# Per-item backup outcomes

## Abstract

A finished Velero backup reports its result at the job level only: `Backup.status` carries a phase and error counts, and no artifact says which objects failed and why.
This proposal adds one opt-in, versioned artifact, `<backup>-item-outcomes.json.gz`, holding a row per processed item with its identity, a verdict from a fixed five-value set, its messages, and a pointer to the item that owns it, plus a read side that rolls a child's trouble up to the object a human would name.

The recorder behind it follows one rule: every write records a lower bound on how badly an item went, and the row is the maximum of every lower bound recorded about it.
A `Failed` row is therefore certain and a `BackedUp` row is provisional, and the artifact does not depend on the order concurrent item blocks finish in.

## Background

A backup directory already holds ten side artifacts besides the tarball and metadata, keyed by convention in `pkg/persistence/object_store_layout.go`, and none of them answers "which object failed".

| Artifact | Shape | Per-item verdict? |
| --- | --- | --- |
| `<backup>-logs.gz` | free text | no |
| `velero-backup.json` | `Backup` API object | job-level only |
| `<backup>-results.gz` | `results.Result`, messages bucketed by namespace | no |
| `<backup>-resource-list.json.gz` | `map[string][]string`, kind → names | inventory only |
| `<backup>-itemoperations.json.gz` | `[]*itemoperation.BackupOperation` | yes, async only |
| `<backup>-volumeinfo.json.gz` | `[]volume.BackupVolumeInfo` | yes, PVC/PV only |
| `<backup>-podvolumebackups.json.gz` | `[]PodVolumeBackup` | pod-volume ops only |
| `<backup>-volumesnapshots.json.gz` | `[]VolumeSnapshot` | no |
| `<backup>-csi-volumesnapshots.json.gz` | CSI snapshot objects | no |
| `<backup>-csi-volumesnapshotcontents.json.gz` | CSI snapshot contents | no |
| `<backup>-csi-volumesnapshotclasses.json.gz` | CSI classes | no |

Each was designed for a narrower purpose, and none is badly designed for its own.

`results.gz` is the closest thing to a per-item error report, and its type cannot hold an item's identity: `results.Result` is `Velero []string`, `Cluster []string` and `Namespaces map[string][]string` (`pkg/util/results/result.go`).
Identity survives only inside the message string `LogHook.Fire` concatenates, and only when the caller attached both a `resource` and a `name` field.
It is also written once at initial persist and never rewritten when async operations finish, so an async failure never reaches it.
`resource-list.json.gz` has identity but no verdict, and its map is populated after `DeleteItem` is called for a plugin-skipped item (`pkg/backup/item_backupper.go`), so a skip is indistinguishable from an item that was never collected.
`volumeinfo.json.gz` is structured and does carry a verdict, but keyed on PVC name/namespace and PV name only, so it cannot name a pod, a Deployment or a VirtualMachine.
Among kind-agnostic sources there is exactly one structured per-item verdict, `<backup>-itemoperations.json.gz`, and it covers only asynchronous `BackupItemAction` operations.

A client cannot close that gap from what is already stored, for two reasons.
The canonical identity of an item (its group-resource resolved from discovery, its live namespace, and its name) and its resolved owner reference exist inside the item block and nowhere else: `recordOwnerParent` resolves an owner reference's GVK through the server's discovery helper and refuses kinds it cannot resolve, and no artifact records which kinds exist or which are namespaced.
And asynchronous operations settle after initial persist has written every artifact a client would join, so a client-side answer is stale by construction.
That second one is issue #9377: when a `BackupItemAction` times out, the phase correctly becomes `PartiallyFailed` and the operation carries the error, but `results.gz` and the error count are never updated.
The open pull request #9402 patches that per artifact by re-uploading results and volume info at finalize; this proposal writes a structured artifact at the same point, so the same fix serves the whole per-item view rather than one file of it.

This proposal is tracked by #10503, which states the same problem and the same three goals, and which this document is the design for.
The scope is deliberately narrower than "make Velero observable": other per-item reports in the family, such as repository initialization and maintenance results (#8779, #7923), are separate artifacts with their own lifecycles and are not addressed by this schema.

## Goals

- Record, for every item that reaches the point in Velero's item path where its identity is canonical, one row containing that identity, a verdict, and its messages, in a form a client can read without parsing prose.
  The rows the capture point cannot reach are listed under Non Goals rather than claimed here.
- Record an ownership relation between rows with its source and a stated precedence, so the resulting tree does not depend on which item block finished first.
- Roll a chain's outcome up to the object that owns it, consulting the backup's volume info so that a volume declined by one method but captured by another does not read as a failure.

More than three goals suggests the scope is too large; the three above are one feature because none of them answers "which object broke?" alone.

## Non Goals

- **It does not answer "what did we miss".** Rows exist only for items that reach `Observe`, which runs after the inclusion checks, so an excluded namespace, an excluded kind, a name-filter miss or an `exclude-from-backup` label produces no row.
  A backup that excluded the wrong namespace will produce a clean, complete-looking artifact.
- **It does not replace `results.gz`.** Both are written, both are consumed, and `results.gz` keeps exactly the shape it has.
- **It is not authoritative for async operations.** It copies a failed operation's error string at finalize but not the operation ID, the plugin name or the phase; `<backup>-itemoperations.json.gz` remains the source of record.
- **It does not cover restore.** Restore-side items are untouched and the new download target kind is backup-scoped only.
- **It does not collate job-level errors against items.** `Backup.status` counts errors that need not belong to any listed item; the read side warns when the count is non-zero rather than trying to attribute them.
- **It does not give hook failures a row.** A pre- or post-hook failure is logged with only the name attached and no resource, and the pod is marked backed-up before `Observe` runs, so `backupItemInternal` returns before a row is minted.
  A backup whose only failure was a hook can therefore produce an artifact that reads clean beside a `PartiallyFailed` phase, which is why the read side warns on a non-zero job-level error count instead of trusting the rows.
  Giving hooks a row changes the backup path and is a separate proposal.
- **The CLI does not print every message.** The artifact carries each row's messages, but the read side renders them only where they explain a verdict, and the default table format does not render them at all.
  That is a rendering choice rather than a limit of the artifact, and it is deliberately not widened here: a consumer that wants every reason reads the artifact directly.

## High-Level Design

Velero records a structured outcome for every item at the point in the backup where the item's identity is still canonical, defaulting each touched item when it begins processing and upgrading it when an error, warning, skip or async result applies.
The outcomes are written as a new gzipped-JSON artifact at initial persist, then re-read and reconciled at finalize once async operations have completed, mirroring the `BackupVolumeInfo` lifecycle.
A row's verdict is recorded at the point the item is processed, and the finalize overlay can only raise it for operations whose identifier is that item.
A CSI snapshot operation names the `VolumeSnapshot`, not the `PVC`, so a snapshot failure raises the `volumesnapshots` row and leaves the `PVC` row reading `BackedUp`.
The read side therefore joins the rows against the backup's volume info, which records the verdict for the volume itself, and the rollup consults it for two things: to tell a benign skip from a lost disk, which no timing fix would remove, and to raise a summary whose row understates its own disk.

The artifact is delivered through the existing `DownloadRequest` mechanism under a new download target kind, and two surfaces consume it: `velero backup item-outcomes` and `velero backup describe --details`.
Collection is opt-in, per backup and by server default.

## Detailed Design

### Why capture, not pure merge

The obvious approach, merging the existing artifacts at finalize, cannot produce structured per-item errors.
When an item error or warning is logged, the structured triple is present in the log entry (`entry.Data["resource"|"namespace"|"name"]`) but `LogHook.Fire` concatenates it into one free-text string and buckets it by namespace only; the resource and name survive only inside the string.
`results.gz` therefore has no reliable per-item key, and reconstructing one means re-parsing free text, which is the brittleness this proposal exists to remove.

A second part genuinely cannot be derived client-side, which is the ownership edge: `recordOwnerParent` resolves an owner reference's GVK to a `schema.GroupResource` and to namespaced-ness through the server's discovery helper, refuses unresolved kinds, and refuses self-edges.
No artifact in the store records which kinds exist or which are namespaced, and the inventory's keys are `groupVersion/Kind` strings, yet another identity encoding, so no client can reproduce that mapping from `resource-list.json.gz` alone.

The three existing renderings of resource identity, `schema.GroupResource`, `groupResource.String()`, and the GVK string `apps/v1/Deployment`, never have to be reconciled, because the recorder keys on `velero.ResourceIdentifier` from the start.

### Types

A new package `internal/itemoutcome` defines the artifact schema and the rollup rules.

```go
type Outcome string

const (
	OutcomeBackedUp Outcome = "BackedUp" // item processed with no error or warning
	OutcomeWarning  Outcome = "Warning"  // item processed but produced one or more warnings
	OutcomeFailed   Outcome = "Failed"   // item errored, synchronously or during an async operation
	OutcomeSkipped  Outcome = "Skipped"  // item excluded or skipped (e.g. a skipped PVC)
	OutcomeNamed    Outcome = "Named"    // named by another item's edge; nothing processed it
)

type ItemOutcome struct {
	GroupResource string        `json:"groupResource"`
	Namespace     string        `json:"namespace,omitempty"`
	Name          string        `json:"name"`
	Outcome       Outcome       `json:"outcome"`
	Messages      []string      `json:"messages,omitempty"`
	Parent        *ItemRef      `json:"parent,omitempty"`
	ParentSource  *ParentSource `json:"parentSource,omitempty"`
}

type ItemOutcomes struct {
	SchemaVersion string        `json:"schemaVersion"`
	Items         []ItemOutcome `json:"items"`
}
```

`OutcomeNamed` is the only outcome that is not a verdict, and it exists so that a row created by an ownership edge cannot claim a success nobody established: an edge is set before the child is fetched, so at that moment nothing has confirmed the child is in the backup.
`Observe` promotes such a row when the item actually begins processing, so a row still reading `Named` in a finished artifact is one a plugin named and nothing resolved.

`ParentSource` distinguishes an edge taken from the child's `metadata.ownerReferences` from one a plugin named through `AdditionalItems`, and the plugin's claim is the stronger of the two.

The recorder is keyed by `velero.ResourceIdentifier` so repeated writes for one item collapse into one row.
Collapsing is by precedence, not arrival order: `Failed` > `Skipped` > `Warning` > `BackedUp` > `Named`, and an upgrade only ever raises severity, so concurrent item blocks produce the same row regardless of which finishes first.
Parent edges are likewise resolved by source precedence rather than arrival order.

`Messages` is bounded at five entries per row, with a counted marker (`"... and N more"`) replacing the rest rather than the tail being dropped silently.

### The rollup

`OwnerSummary` carries the root of a chain, its outcome, a count of each row verdict beneath it, and the rows that made it worth reading.
Two fields that look alike are deliberately different:

- `Counts` is a raw tally of the rows' own verdicts, the root included.
  It is descriptive.
- `Outcome` is the most significant outcome among the rows that `IsFailure` judged real trouble.
  It is normative.

`IsFailure` treats `Failed` and `Warning` as trouble always, and `Skipped` as trouble only when the volume info says that volume failed.
Velero records `Skipped` when it declines one path to a volume in favor of another, so rolling that up would report a virtual machine as skipped while every one of its disks succeeded.
A row that reads `BackedUp` but whose volume failed is trouble too, and it raises the summary to `Failed` rather than leaving the summary clean while its failed list names the row: a caller that asks "is this chain in trouble?" by reading `Outcome` alone would otherwise report a clean backup.

The rollup package must stay a leaf: `pkg/util/logging` imports it for the log hook, and `internal/volume` reaches `pkg/util/logging`, so importing volume would close a cycle.
`VolumeRef` exists for that reason, and callers project their volume info into it.

### Capture during backup

`itemBackupper.backupItemInternal` already computes the canonical identity for the item it is processing.
It records that the item began processing when it does, records a failure with the real aggregated error rather than relying on the log hook to notice it, and records skips with their reason, for non-volume kinds as well as volume-bearing ones.
Item errors and warnings are also captured by extending `LogHook.Fire`: when `entry.Data` carries the `resource`, `namespace`, and `name` fields at error or warning level, it additionally records against the recorder with those structured values, before flattening to the existing `results.Result` string.
This keeps `results.gz` unchanged while capturing the same events structurally.

Ownership edges are recorded once per backed-up item from its `metadata.ownerReferences`, and a plugin's `AdditionalItems` names its children explicitly.

### Assembly and finalize reconciliation

Initial persist (`persistBackup`, `pkg/controller/backup_controller.go`) encodes the recorder's result with `encode.ToJSONGzip` and adds it to `persistence.BackupInfo` for the existing `PutBackup` call.
At this point the synchronous outcomes are complete but async operations may still be in flight, exactly as with `BackupVolumeInfo`.

Finalize (`backupFinalizerReconciler.Reconcile` and `FinalizeBackup`, `pkg/backup/backup.go`) re-reads the artifact, overlays the async-operation results already loaded there, and rewrites it.
`itemoperation.BackupOperation` carries a fully structured `Spec.ResourceIdentifier` and a phase, so each operation joins directly onto its item: a failed phase sets the item to `Failed` with its error appended, and a completed phase leaves a previously-successful item unchanged.
This is the same read-reconcile-rewrite shape as `updateVolumeInfos`.

That overlay walks every settled asynchronous operation, snapshot operations included, but it can only raise the row its operation names.
A CSI snapshot operation names the `VolumeSnapshot`, so a snapshot failure raises that row and is marked against its volume, while the `PVC` row written earlier is left alone: the volume's data belongs to the PVC, but the operation was never about it.
That is the specific gap that makes a `BackedUp` PVC row over a failed volume reachable, and the read-side raise above is designed to report rather than hide it.

### Persistence and download plumbing

- `pkg/persistence/object_store_layout.go`: `getBackupItemOutcomesKey` returns `<backup>-item-outcomes.json.gz`.
- `pkg/persistence/object_store.go`: `BackupItemOutcomes io.Reader` on `BackupInfo`; `PutBackupItemOutcomes` and `GetBackupItemOutcomes` on the store interface, mirroring the volume-info pair, with `GetBackupItemOutcomes` returning an empty result when the object is absent.
- `GetDownloadURL` gains a case for the new target kind.
- `pkg/apis/velero/v1/download_request_types.go`: the `DownloadTargetKindBackupItemOutcomes` const and its enum marker.

### Opt-in

Per backup: `CollectItemOutcomes *bool` on `BackupSpec`, following the `SnapshotMoveData *bool` pattern, plus a builder method and deepcopy.
Server default: `DefaultCollectItemOutcomes` on the server config with a `--default-collect-item-outcomes` flag, threaded through both the backup reconciler and the finalizer reconciler.
The effective value is the spec field if set, else the server default.
When disabled no recorder is created and no artifact is written at all, rather than an empty one.

The field is optional and tri-state, so an unset value falls through to the server default rather than reading as false:

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: my-backup
  namespace: velero
spec:
  includedNamespaces:
    - my-namespace
  collectItemOutcomes: true
```

`velero backup create` has no flag for this field at present, so setting it on a single backup means patching the Backup, or enabling it cluster-wide through the server default below.
A `--collect-item-outcomes` flag on `backup create` is listed under Open Issues as a follow-on.

The server default is set once at install time for the whole cluster, and a Backup that omits the field inherits it:

```
velero server --default-collect-item-outcomes
```

### Recorder placement

The recorder lives on the backup `Request`, not on the reconciler or a package-level variable, because `itemBackupper` already carries the `*Request` it is processing and the recorder's lifetime is one backup run.

```go
// pkg/backup/request.go
type Request struct {
	// ... existing fields ...
	ItemOutcomes *itemoutcome.Recorder
}
```

It is a pointer and may be nil, which is how the opt-out is expressed: every recorder method tolerates a nil receiver, so a disabled backup needs no branch at the call sites.

### Read side

`velero backup item-outcomes BACKUP` streams the artifact through the existing `DownloadRequest` path and prints it as stored.
A 404 on the download means the feature was off for that backup, and is reported as such rather than as an error.
`--by-owner` loads the backup's volume info, rolls the rows up, and prints a forest; `-o table|json|tree` chooses the format, and `--all` widens the table from only the chains that hold trouble to every chain.

`velero backup describe --details` gains an "Item Outcomes" section in both the text and structured renderers.
Volume info is downloaded once per invocation and shared by the volume section and the item-outcomes section, and a failure to read it degrades the item-outcomes section with a stated warning rather than failing the command or silently treating every skip as benign.

### Compatibility of the JSON surfaces

The structured describer distinguishes two volume-info failures under different keys, `errorReadBackupVolumeInfo` and `errorGetBackupVolumeInfo`, because it has always done so and a consumer may key on them.
That distinction is preserved by an explicit sentinel error rather than collapsed for convenience.

## Alternatives Considered

**Pure merge of existing artifacts at finalize, with no new capture.** Rejected because `results.gz` has already discarded per-item identity, so this would reintroduce free-text parsing, and because the ownership edge requires server-side discovery.

**Inline the outcomes in `Backup.status`.** Rejected because a large backup has tens of thousands of items and the list would exceed the etcd per-object size limit; a store artifact behind `DownloadRequest` is how every comparable per-item dataset is already delivered.

**A dedicated CRD for the view.** Rejected as unnecessary API surface: the data is a read-only report, not desired state a controller reconciles toward, and `DownloadRequest` already exists for exactly this.

**Fix the async timing bug by writing async errors back into `results.gz` at finalize.** This helps that specific bug but keeps the unstructured, unkeyable format; the structured artifact is a superset that addresses the same root cause.

**Record the volume verdict on the row at finalize instead of joining at read time.** The overlay already runs after `updateVolumeInfos`, so the mapping it would need is in scope and cheap to add.
It is declined on semantics rather than cost.
The read side consults volume info for two questions: whether a `Skipped` row's volume was nevertheless captured, and whether a `BackedUp` row's volume failed.
Only the second can be answered by writing a verdict onto the row, so the join would shrink rather than go away, and both a row verdict and a read-side join would then answer it.
Doing it properly means the read side stops joining entirely, which also fixes the first question, and that is a larger change than one artifact.
The read-side raise reports the truth in the meantime and does not fabricate a verdict onto the row itself.

## Security Considerations

The artifact contains resource group/namespace/name and error text, the same information already present in `results.gz`, `resource-list.json.gz` and `itemoperations.json.gz`, and is stored in the same backup bucket with the same access controls and served through the same signed-URL `DownloadRequest` path.
No new secrets or data classes are exposed, and error messages carry no more detail than the existing `results.gz` strings, since they originate from the same log events.
One difference is worth naming: the artifact is a structured, long-lived object rather than a log, so text that a consumer previously had to grep out of `logs.gz` becomes directly queryable.
That does not widen what is exposed, because the same strings, identities and verdicts are already in the bucket, but it does make per-item failure text easier to aggregate, and an operator who considers log retention a control should treat this artifact the same way.

## Compatibility

The feature is opt-in and defaults off, so existing backups and clients are unaffected.
`results.gz`, `resource-list.json.gz` and all other artifacts are left byte-for-byte unchanged; the recorder adds a parallel structured sink.
`GetBackupItemOutcomes` returns an empty result when the artifact is absent, and an absent artifact downloads as a not-found rather than an error, so backups taken before this feature or with it disabled stay readable by every consumer.
The artifact carries `schemaVersion` for forward evolution.
Adding the `BackupSpec` field and the download-target enum requires regenerating CRDs, deepcopy and the API docs.

## Implementation

Incremental, in dependency order, each step independently mergeable:

1. `internal/itemoutcome`: types, `Recorder`, and the rollup rules, with unit tests.
2. Persistence: layout key, `BackupInfo` field, store Put/Get pair and implementation.
3. Capture: recorder on `Request`, the direct records in `item_backupper.go`, and the structured hook in `log_counter_hook.go`.
4. Assembly: encode at `persistBackup`; reconcile async operations and rewrite at finalize.
5. Download: target-kind const, enum marker, `GetDownloadURL` case; codegen.
6. Opt-in: `BackupSpec.CollectItemOutcomes`, server config toggle and threading; codegen.
7. Read side: the `item-outcomes` command with the rollup, then the describe sections in both renderers.

Steps 1 through 6 are the capture half and are useful alone; step 7 is what makes them answerable.
If the change is split across pull requests, the natural fault line is between 6 and 7, not inside 7.

All seven steps are implemented on the branch this proposal accompanies, so the sequence above is a record of the order the work was done in rather than a plan for work still outstanding.
No timeline is given because the remaining work is review rather than implementation, and no other contributors have committed to it.

## Open Issues

- There is no client flag to enable collection for a single backup; today it requires the spec field or the server-wide default.
  A `--collect-item-outcomes` flag on `backup create` is a follow-on.
- Whether to also surface a small per-outcome count summary on `Backup.status`, bounded and with no per-item rows, so the common case needs no download.
  Proposed as a follow-on.
- Restore-side parity is deferred to a separate proposal, and it is not a matter of adding a caller.
  The precedence order is backup's and inverts under restore: restore records its skipped result exactly when nothing failed and nothing warned, so a skip is restore's cleanest outcome rather than a runner-up to a warning, and it is also recorded alongside a warning when there is a reason to give.
  A restore client therefore needs a different order and a different rule for which rows count as trouble, which is a second design exercise rather than a second caller.
- The artifact is reusable; the rollup is not.
  The row types, the recorder and the graph code carry no backup nouns, but `Rollup` and `Summarize` take the volume join as a required parameter and `IsFailure` takes the volume index, so the summary rule is backup-shaped even though the row storage is not.
  The seam that would generalize it is making `IsFailure` an injected predicate rather than a volume-index lookup.
  That is a small change and a reasonable thing for a reviewer to ask for, but re-cutting the package into a generic core plus a backup client is not, and should not land here with no second consumer to justify it.
- Two per-item backup artifacts now exist, this one and `<backup>-itemoperations.json.gz`, which is the precedent that makes a per-item artifact an accepted shape rather than a novel one.
  It is also the reason this proposal does not claim to be the first.
