# Per-item outcomes for backups and restores

**Status:** Draft

**Tracking:** [#10503 Per-item outcomes for observability](https://github.com/velero-io/velero/issues/10503) (`Needs Design`, `observability`, `1.20-candidate`).

**Related work:**

- [#9377 BackupItemAction timeouts are not reported in backup results](https://github.com/velero-io/velero/issues/9377) — the async-staleness bug this artifact fixes structurally.
- [#9402 Re-upload backup results and volume info after BIA operations](https://github.com/velero-io/velero/pull/9402) — a narrow patch for #9377.
  It keeps two existing artifacts fresh; it does not produce per-item rows.

## Abstract

Velero reports a finished backup or restore at the job level: a phase, aggregate error counts, a log stream, and a set of artifacts that each serve a narrower purpose.

```text
# Backup.status: phase and aggregate counts
$ velero backup get
NAME                   STATUS            ERRORS   WARNINGS   CREATED                         EXPIRES   STORAGE LOCATION   SELECTOR
app-mongo-persistent   PartiallyFailed   2        0          2026-10-29 16:28:27 -0400 EDT   26d       default            <none>

# <backup>-results.gz: messages, bucketed by scope
$ velero backup describe app-mongo-persistent
Phase:  PartiallyFailed (run `velero backup logs app-mongo-persistent` for more information)

Errors:
  Velero:    message: /Error executing hook error: /command terminated with exit code 1
  Namespaces:
    mongo-persistent:  resource: /pods name: /hookfail-pod message: /Error running pre hooks for pod ...

# <backup>-logs.gz: free text; identity only where the caller attached it
$ velero backup logs app-mongo-persistent | tail -1
time="2026-10-29T20:28:28Z" level=error msg="Error running pre hooks for pod"
  error="command terminated with exit code 1" name=hookfail-pod namespace=mongo-persistent resource=pods

# the rest of the artifact set, each for a different consumer
backups/app-mongo-persistent/
  app-mongo-persistent-logs.gz                  19K   event stream
  app-mongo-persistent-results.gz              185B   messages, bucketed by namespace
  app-mongo-persistent-resource-list.json.gz   581B   GVK → names
  app-mongo-persistent-itemoperations.json.gz  357B   async operation, plugin, phase
  app-mongo-persistent-volumeinfo.json.gz      429B   PVC/PV, method, skipped reason
```

On a `PartiallyFailed`, none of the above outputs answer the question: *which top-level object is broken, and which of its children caused it?*

We aim to add one opt-in, versioned artifact per operation.
It records, for every item Velero processed, a verdict, the messages behind it, the item's identity, and the item that owns it.
A read side rolls a child's trouble up to the object a human names, so a failed disk is reported against its virtual machine rather than against a generated pod.

## Background

Velero already writes many artifacts per operation: logs, results, resource lists, item operations, and volume info.
Each was designed for a different consumer, and none is badly designed for its own purpose.
None is a structured per-item verdict:

| Artifact | Granularity | Signal | Gap |
|---|---|---|---|
| `<backup>-logs.gz` | event | free text | identity survives only when the caller attached `resource` and `name` |
| `<backup>-results.gz` | namespace / cluster / velero | messages | `results.Result` has no field for an item's identity |
| `<backup>-resource-list.json.gz` | GVK → names | inventory | no verdict, messages, or ownership |
| `<backup>-itemoperations.json.gz` | async operation | identity, phase, error | asynchronous work only; can go stale against results (#9377) |
| `<backup>-volumeinfo.json.gz` | volume | PVC/PV, method, result, skipped reason | volumes only; not the item |
| `restore-<restore>-results.gz` | namespace / cluster / velero | messages | no item identity |
| `restore-<restore>-resource-list.json.gz` | item, stringly | `name(created/updated/skipped/failed)` | no messages, parent, or source→target mapping |
| `restore-<restore>-itemoperations.json.gz` | async operation | identity, phase, error | asynchronous work only |
| `restore-<restore>-volumeinfo.json.gz` | volume | method, PVR/DataDownload phase | no per-volume result; failures are often omitted |
| `Backup.status` / `Restore.status` | job | phase, counts, progress | no items |

The restore resource list is the closest thing to a per-item verdict: it encodes the action in a string, but it discards the structure, carries no messages, and has no ownership.

The artifacts also do not share a freshness point:

| Artifact | First write | Updated at finalize? |
|---|---|---|
| backup results | initial persist | **no** (#9377) |
| restore results | initial persist | **yes** |
| backup volume info | initial persist | **yes** |
| restore volume info | initial persist | **yes** (DataDownload phases) |
| backup resource list | initial persist | no |
| restore resource list | initial persist | no |
| item operations | persist + operations map | yes |

Asynchronous work settles after the first write, so a client-side join is stale by construction.
The result is that a partial failure has no structured answer, and the answer a human can assemble depends on the order they read the log.

The tracking issue states the problem: no artifact carries a per-item verdict, the rows cannot be keyed reliably, the artifacts do not share a freshness point, and every consumer reimplements the same brittle merge.
That is why this design captures a verdict rather than parsing one.

## Goals

- Record a structured per-item verdict with the item's identity and the messages behind it, for backups and restores.
- Record parentage with its source and precedence, and roll a chain's outcome up to its root so users can find the top-level objects with issues.
- Deliver one self-describing, finalized artifact through one opt-in model and one reader for both operations.

## Non Goals

- **It does not verify data integrity.**
  Velero reports what CSI, node-agent, PodVolumeRestore, and DataDownload report; it does not compute whether bytes arrived on its own authority.
- **It does not replace logs, results, or the resource lists.**
  All remain written and consumed as before.
- **It does not change what Velero backs up or restores.**
  Capture is observation only.
- **It does not report what was filtered out.**
  Excluded namespaces, kinds, and label-selector misses produce no row.
  A clean artifact can still describe a backup that excluded the wrong namespace.
- **It does not reconcile job-level counts.**
  `Backup.status` and `Restore.status` keep their existing meaning; the artifact is the per-item source of truth.
- **It does not provide a UI or long-term analytics.**
- **It does not synthesize restore volume verdicts in the first version** (see “Restore identity and volumes”).

## High-Level Design

Capture happens where Velero decides an item's fate.
The artifact is written with the synchronous verdicts, re-read at finalize to settle asynchronous work and backup volume results, and written again as complete.
Readers only consume the finalized artifact.

**Capture at decision, authoritative at finalize.**
The artifact is *authoritative* at finalize: that is when asynchronous work and backup volume results are settled, and when the artifact is marked complete.
But capture must begin when the item is processed.
Building the artifact only at finalize cannot recover a synchronous item's verdict or messages, because no existing artifact stores them with a reliable item key.
The backup volume lifecycle already uses the same write-then-reconcile shape.

### Lifecycle

```text
capture per item  →  write  →  finalize  →  read
```

| Moment | What happens | Artifact state |
|---|---|---|
| Per item | Velero records the verdict, the messages, the parent, and, for restores, the source and action. | In memory only. |
| End of synchronous work | The recorder writes every row it has. | Written with `finalized: false`. |
| Finalize | Async operation results are overlaid, and for backups the volume verdicts from `<backup>-volumeinfo.json.gz` are joined onto their owning rows. The artifact is written again. | `finalized: true`. |
| Read | The command and describe roll the rows up and render them. | The finalized artifact only. |

The middle write is not redundant: if the process dies before finalize, the artifact still exists and says it is provisional, which is different from an artifact that never existed.
A reader can then tell "collection was not enabled" apart from "collection ran but never finished".

A finished artifact is self-describing: it carries the verdict, the messages, and the parent for every item, so a reader does not join it with volume info, item operations, or the log to decide whether something is trouble.

The volume join happens once, inside Velero, at finalize.
It is a write-time join, not the read-time stitching this design rules out: a reader never downloads volume info to decide whether a disk survived.

## Detailed Design

### Artifact model

An artifact is an envelope with a schema version, a kind (`backup` or `restore`), a finalized flag, and rows.

A row contains:

- the item's identity (group resource, namespace, name);
- an outcome from a fixed set: `Succeeded`, `Warning`, `Failed`, `Skipped`, `Named`;
- an optional action detail for successful restores (`created` or `updated`);
- the messages that explain the verdict;
- an optional parent and the source of that edge;
- for restores, the object in the backup it came from;
- for backup rows that own a volume, that volume's verdict.

A backup row and a restore row look like this:

```json
{ "groupResource": "persistentvolumeclaims", "namespace": "vm-ns", "name": "disk1",
  "outcome": "Failed",
  "messages": ["volume pvc=vm-ns/disk1 pv=pv-1 (CSISnapshot) failed"],
  "parent": { "groupResource": "pods", "namespace": "vm-ns", "name": "virt-launcher-..." },
  "volume": { "pvcNamespace": "vm-ns", "pvcName": "disk1", "pvName": "pv-1",
              "method": "CSISnapshot", "result": "failed" } }
```

```json
{ "groupResource": "persistentvolumeclaims", "namespace": "target-ns", "name": "disk1",
  "outcome": "Succeeded", "action": "created",
  "source": { "groupResource": "persistentvolumeclaims", "namespace": "vm-ns", "name": "disk1" },
  "parent": { "groupResource": "pods", "namespace": "target-ns", "name": "virt-launcher-..." } }
```

`Named` is the only value that is not a verdict.
It exists so an ownership edge can name a child without claiming that anything processed it.
A row still reading `Named` in a finalized artifact is a child a plugin named and Velero did not restore.

**Decision: one success value.**
The JSON uses `Succeeded`; the operation is carried by `kind`, and the action (`created`/`updated`) is a separate field.
The CLI renders the operation-specific verb, “BackedUp” or “Restored”.
This keeps the precedence rule, `IsFailure`, the rollup, and any future comparison from branching on the operation.

### Capture

**Backup.**
The item backupper records the outcome explicitly: observed, failed, warned, or skipped, with a rekey when a plugin renames the item.
The record is produced where the decision is made, not inferred from a log line.

**Restore.**
Capture uses the per-item defer where Velero already computes created, updated, skipped, or failed.
Failures and warnings carry the accumulated messages; successes carry the action; skips carry a reason, including a plugin's deliberate `SkipRestore`.

**Hooks.**
A failed pre- or post-hook is recorded against the pod whose hook failed.
It is not inferable from the log: the pre-hook path marks the pod as backed up before item capture runs, and the outer error line carries only a name.
Recording it explicitly is a deliberate part of this design.

**Parentage.**
An item's parent comes from, in increasing precedence:

1. metadata the object carries — its owner references, and a PersistentVolume's claimRef;
2. a plugin's view — the additional items a backup or restore item action names while processing the parent.

For restores, owner references are resolved from the object as it existed in the backup, before a restore item action can rewrite or strip its metadata, and are mapped to the target namespace.
That is what preserves a chain such as VM → VMI → pod → PVC when the VMI and pod are skipped because they already exist.

A dangling parent is a root, not an error: a cluster-scoped owner can be outside a namespaced backup, and an owner can be excluded from a restore.
Cycles terminate at a bounded depth.

**Named rows (decision).**
Restore keeps `Named` rows for plugin-named children that Velero did not restore; they are honest, do not raise any owner, and explain why an additional item is absent.
If they prove noisy in practice, suppressing them is a follow-on.

### Finalize

Some verdicts only settle after the first write:

- asynchronous backup and restore operations;
- backup volume results, which are reconciled at finalize.

A neutral operation result (identity, state, error) is overlaid onto the rows.
A failed operation raises its item; a successful one changes nothing; an unsettled one keeps the artifact unfinalized and is reported to the caller.

For backups, `<backup>-volumeinfo.json.gz` is joined in: duplicate entries for one volume are resolved to one verdict, the verdict is attached to the one row that owns it (the PVC, otherwise the PV), and a failed volume raises that row.
A row therefore never reads “succeeded” for a disk that did not survive.

`finalized` becomes true only when no verdict is outstanding.
This distinguishes a complete artifact from one written by a backup or restore that failed before finalize.

**Divergence from status and results.**
The artifact can name a failure that `Backup.status.Errors` and `results.gz` do not, because those are written before async work settles (#9377).
The read side warns when the job-level count is non-zero but no row explains it, and when the artifact is unfinalized.
The artifact is the per-item source of truth; status and results remain job-level summaries.

### Rollup

Every row resolves to the root of its parenting chain.
Two views are derived from the same data:

- a summary per row covering everything below it, so a nested view can show a verdict at every level;
- a roots-only rollup, the list of top-level objects and the worst verdict in each subtree.

The rule is one function: `Failed` and `Warning` are trouble; `Skipped` is a count; a benign skip does not raise an owner.
Because the artifact is finalized before it is read, a failed disk is already a `Failed` row.

For example, a failed disk renders against the VM that owns it:

```
virtualmachines cirros (vm-ns)
  virtualmachineinstances cirros (vm-ns)
    pods virt-launcher-cirros-... (vm-ns)
      persistentvolumeclaims cirros-disk (vm-ns)  [Failed]
        - volume pvc=vm-ns/cirros-disk pv=pv-... (CSISnapshot) failed
```

The tree prints a row bare when it is fine, and appends the bracketed verdict plus one `- message` line for each message when the row raises its owner.
The VM is the object the user names, and the row that explains the failure stays visible beneath it.

### Read surfaces

- `velero backup item-outcomes` and `velero restore item-outcomes` render the rollup as a table, a tree, or JSON, and can print the stored artifact.
- `backup describe --details` and `restore describe --details` gain an Item Outcomes section; the structured describers publish the same rollup in JSON.
- The CLI's success verb comes from the artifact kind: “BackedUp” for backups, “Restored” for restores.
  Restore rows can show whether they were created or updated.

A backup and a restore read the same way.
On a KubeVirt backup, the tree is:

```text
$ velero backup item-outcomes itemoutcomes-final --by-owner -o tree
namespaces cirros-multipvc-test
customresourcedefinitions datavolumes.cdi.kubevirt.io
customresourcedefinitions virtualmachineinstances.kubevirt.io
customresourcedefinitions virtualmachines.kubevirt.io
...
virtualmachines cirros-multipvc-test (cirros-multipvc-test)
  controllerrevisions revision-start-vm-406ff2dc-5bdc-4277-bfb6-ed1319f12c8a-3 (cirros-multipvc-test)
  datavolumes cirros-multipvc-test-datadisk (cirros-multipvc-test)
  datavolumes cirros-multipvc-test-disk (cirros-multipvc-test)
  virtualmachineinstances cirros-multipvc-test (cirros-multipvc-test)
    pods virt-launcher-cirros-multipvc-test-cz5xs (cirros-multipvc-test)
      persistentvolumeclaims cirros-multipvc-test-datadisk (cirros-multipvc-test)
        persistentvolumes pvc-be446add-0648-4a6e-9401-c3be84100ef4
        volumesnapshots velero-cirros-multipvc-test-datadisk-bmdwp (cirros-multipvc-test)
          volumesnapshotcontents snapcontent-ec3bc02c-3b6f-463a-be45-4135c14f6dbf
      persistentvolumeclaims cirros-multipvc-test-disk (cirros-multipvc-test)
        persistentvolumes pvc-48b54a5c-2545-4f41-a566-5141eac382e8
        volumesnapshots velero-cirros-multipvc-test-disk-k5cmn (cirros-multipvc-test)
          volumesnapshotclasses oadp-example-snapclass
          volumesnapshotcontents snapcontent-d0110bba-4d03-4cd9-aac1-0d45773f31b9
```

A restore prints the same forest with the `Restored` verb, and `--all` adds a column per outcome:

```text
$ velero restore item-outcomes cirros-restore-items-4 --by-owner --all
GROUP/RESOURCE                                    NAMESPACE               NAME                                                              OUTCOME             ITEMS  RESTORED  WARNING  FAILED  SKIPPED  NAMED
configmaps                                        cirros-restore-items-4  kube-root-ca.crt                                                  Warning             1      0         1        0       0        0
...
virtualmachines.kubevirt.io                       cirros-restore-items-4  cirros-multipvc-test                                              Restored (created)  12     6         0        0       4        2
  virtualmachineinstances.kubevirt.io             cirros-restore-items-4  cirros-multipvc-test                                              Restored            8      2         0        0       4        2
    pods                                          cirros-restore-items-4  virt-launcher-cirros-multipvc-test-cz5xs                          Restored            7      2         0        0       3        2
      persistentvolumeclaims                      cirros-restore-items-4  cirros-multipvc-test-datadisk                                     Restored (created)  3      1         0        0       1        1
```

`--all` is a table flag: it adds the per-outcome columns and keeps rows whose subtree is clean.
The tree is always unfiltered, so `--all` makes no difference there.

> **TODO:** Re-capture these transcripts from a cluster running the current build.
> The backup artifact used here was written by an earlier build that recorded `BackedUp` instead of `Succeeded`; it renders correctly as a tree, but its `--all` counts are zeros.

### Configuration

Both operations are opt-in through their spec, with a server-wide default.
A per-operation value overrides the default.

The default is off because the artifact adds storage and in-memory rows proportional to the item count, and because the schema is new.
The server default exists so an operator can enable it once for a cluster, and a per-create flag exists so a single backup or restore can opt in without changing the server.

When collection is disabled, no artifact is written and no per-item copy of the object is retained.

### API and plumbing

The change is additive:

- `BackupSpec.CollectItemOutcomes` and `RestoreSpec.CollectItemOutcomes` as nullable booleans, with a server default (`--default-collect-item-outcomes`) and per-create flags.
- `DownloadTargetKindBackupItemOutcomes` and `DownloadTargetKindRestoreItemOutcomes`.
- Object keys `<backup>-item-outcomes.json.gz` and `restore-<restore>-item-outcomes.json.gz`, beside the other per-operation artifacts.
- CRD additions for the two spec fields and the download kinds; no existing field changes meaning.
- One new internal package for the artifact model, recorder, capture handle, rollup, and finalize transforms.

### Restore identity and volumes

Restore rows use the target identity: the mapped namespace and the name the object actually received (including a server-generated name).
The backup identity is kept in `source`, so a reader can answer both “where did this come from?” and “where is it now?”.

Restore volume info does not carry a result.
It predates the backup volume result, is generated from created and bound PVCs, and tracks native snapshots only after success.
Deriving a verdict from it today would be survivor-biased: failures are omitted rather than marked failed, and a synthesized “succeeded” would be confidently wrong.

This version therefore reports restore outcomes at the control-plane level only.
A later design must define one source of truth per restore method — PodVolumeRestore phase, DataDownload phase, or provisioning success — before a restore volume verdict is added.

## Alternatives Considered

- **Capture parentage only and join the existing artifacts.**
  Rejected: the join recovers volume failures, async failures, and restore actions, but no backup item's ordinary verdict or messages.
  The issue's own problem table says the key is unreliable, and reconstructing it means parsing prose.
- **Join outcomes with volume info in each client at read time.**
  Rejected: it duplicates the rule, makes the answer depend on a second download, and lets clients disagree.
- **Capture outcomes from the log hook.**
  Rejected: identity and severity become properties of logging hygiene, messages are log text, and a failure without the expected fields is invisible.
- **Store the rollup instead of the rows.**
  Rejected: it freezes the rule and discards the data a tree or a different view needs.
- **Extend `results.gz`.**
  Rejected: it changes a shared type used by every consumer and still has no ownership or structured per-item messages.
- **Extend the restored resource list.**
  Rejected: it is a stringly-typed inventory with no messages or parent, and it is consumed by the finalizer.
- **One combined backup-and-restore artifact.**
  Rejected: a restore may be repeated, may come from an older backup, and may restore a subset.
  The comparison belongs at read time.

## Security Considerations

Rows contain resource identities and the messages Velero already writes to its logs.
The artifact does not add secret material and lives in the same object-store location, under the same access controls, as the other per-backup and per-restore artifacts.

## Compatibility

- The feature is additive.
  No existing artifact changes shape, and no API is removed.
- The feature is opt-in and defaults off.
  A server that does not know the spec field ignores it.
- An absent artifact is reported as “not collected”, not as an empty success.
- An artifact that did not finalize is reported as provisional, so missing verdicts are not read as clean.
- A reader that does not understand the schema version warns and does not present a partial reading as complete.
- The `kind` field lets a reader refuse an artifact produced by the wrong operation.
- Older backups and restores remain readable; older clients ignore the new command and describe sections.
- Hook failures, previously visible only in the log, now get a row.
  That is additive but changes what a consumer sees.

## Implementation

### Validation

- Unit tests for recorder precedence, parent precedence, message caps, rollup, volume folding, the operation overlay, and restore capture.
- Controller and persistence tests for opt-in, absent artifacts, round-trips, and the download target.
- CLI and describe tests for table, tree, JSON, labels, and the warnings for unfinalized or unknown artifacts.
- A failure matrix: synchronous error, warning, benign skip, conflict skip, async failure, volume failure, hook failure, namespace-mapped restore, generated name, cluster-scoped item.
- An end-to-end KubeVirt backup and namespace-mapped restore that verifies the VM → VMI → pod → PVC rollup and a real failure attributed to its VM.
- A manifest-plus-existing-artifacts reconstruction experiment to quantify what a join can and cannot recover.
- Artifact size and recorder memory at 1k, 10k, and 100k items.

### Success criteria

- A user can identify the top-level objects with issues in one command, for both a backup and a restore.
- A failed disk is attributed to the VM that owns it, not to a generated pod.
- The artifact can be read without volume info, item operations, or the log.
- An absent, unfinalized, or unknown-schema artifact is reported as such rather than as clean.
- No existing artifact changes shape, and the feature is off by default.
- The artifact has a measured, bounded size per item, and messages are capped.

### Phases

- **Phase 1 (backup):** artifact, capture, finalize, describe, command, and server flag.
  This is the phase that directly closes #10503.
- **Phase 2 (restore):** the same envelope at the item level, with source identity and ownership derived from the pre-action object.
- **Phase 3:** restore volume verdicts once their source of truth is defined.
- **Phase 4:** read-time comparison of a backup and a restore.
- **Phase 5:** user documentation and Helm chart support for the server default.

### Status

The backup and restore item-level phases are implemented on the feature branch `itemoutcomes-self-describing`, which is the implementation of record for this document.

## Open Issues

- Should restore volume verdicts exist, and which explicit terminal states are trusted?
- Should the server default be one flag for both operations or one per operation?
- What are the retention and size expectations for very large backups, and at what measured size should the default flip?
- Should restore eventually seed its parentage from a backup-time manifest rather than from owner references?
