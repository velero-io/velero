# Kubernetes Name Length Enforcement

## Abstract

Velero creates Kubernetes objects whose names are derived by concatenating user-controlled strings (backup names, restore names, BSL names, namespace names, PVC names) without bounding their length.
This causes object creation to fail when those strings are long, breaking backups and restores silently or with confusing errors.
This design proposes a consistent enforcement strategy that covers all affected object types.

## Background

Kubernetes enforces a maximum name length of 253 characters for most object types (DNS subdomain names per RFC 1123), and 63 characters for label values.
Velero constructs object names and label values by concatenating user-supplied names without checking these limits.

Known failing paths (tracked in [issue #8815](https://github.com/vmware-tanzu/velero/issues/8815)):

- `BackupRepository` name is `VolumeNamespace + "-" + BackupStorageLocation + "-" + RepositoryType`.
  A BSL or namespace name approaching the 253-character maximum causes the concatenated name to exceed the limit.
- `DataUpload` uses `GenerateName: backup.Name + "-"`.
  If `backup.Name` is near the 253-character maximum, the resulting `GenerateName` value itself exceeds 253 characters and Kubernetes rejects the create outright (`metadata.generateName` is validated as a DNS1123 subdomain, independent of the random suffix appended later).
- `DataDownload` uses `GenerateName: restore.Name + "-"` with the same failure mode.

A broader audit of the codebase found thirty-six distinct locations across five categories with this class of bug.
An additional audit found five `GenerateName` sites that bypass the existing `CreateRetryGenerateName` wrapper, leaving them vulnerable to spurious `AlreadyExists` failures on name collision.

A design review by @blackpiglet identified a critical flaw in the original proposal: four of the Category D label values are used by `find*ByPod` helper functions to look up their owning object by exact name (`client.Get(..., Name: label)`).
Truncating those label values with a hash (the original Category D approach) would break these lookups for any name long enough to require truncation, because the truncated label no longer matches the object's real name.
Category D below is split into a safe subset (label values used only for selector-based filtering, where hashing both the write and the read side is sufficient) and a subset that requires an additional annotation-based fallback so the full name remains recoverable.

A subsequent review caught a second, independent flaw in the `GetValidGenerateName` design: the 248-character target was derived from the wrong constraint.
248 keeps the raw `GenerateName` *field* under the 253-character DNS1123 subdomain limit (avoiding the rejection above), but it ignores what Kubernetes' name generator actually does with that field once it is accepted.
Every REST storage strategy — for CustomResourceDefinitions and built-in types alike — uses `k8s.io/apiserver/pkg/storage/names.SimpleNameGenerator` by default, which keeps only the **first 58 characters** of the submitted prefix and appends its own 5 random characters, for a fixed 63-character total, regardless of the resource's own maximum name length.
This is true for every one of Velero's Category A objects (DataUpload, DataDownload, PodVolumeBackup, PodVolumeRestore, DeleteBackupRequest, ConfigMap, VolumeSnapshot) because none of them install a custom `NameGenerator`.
A 248-character prefix with a hash placed at characters 243–248 has that hash silently discarded by Kubernetes before the object is ever created — it never reaches the real object name. `GetValidGenerateName` is corrected below to place the hash inside the 58 characters Kubernetes actually retains.

A third review pass, re-verifying the design against the current codebase, found: an eleventh `GenerateName` site (`pkg/cmd/cli/serverstatus/server_status.go:42`) missing from the audit, though it needs no fix since its prefix is a fixed literal; a genuine new instance of Category E's write/read inconsistency, introduced by this design's own Category D.1 fix to `ScheduleNameLabel` (four selector call sites still read the raw name after D.1 hashes the write side — see Category E.2); and a round of stale file:line references inherited from an earlier draft of this document, now corrected against the current codebase throughout.

A fourth review pass identified a structural problem with hashing `ScheduleNameLabel` in place at all: a raw schedule name that happens to be exactly 63 characters and a hash of some other, longer schedule name are indistinguishable by shape — both are ordinary 63-character label values — so no amount of length-checking on the read side can fully tell them apart, and an earlier fix attempt that tried to resolve the ambiguity via a `Schedule` existence check could be tricked into confidently returning the wrong schedule's name. Category D.1/E.2 are revised to give `ScheduleNameLabel` a sibling label, `ScheduleNameHashLabel`, so raw names and hashes never share the same key and the ambiguity cannot arise in the first place.

A fifth review pass pointed out that making the seven `ScheduleNameLabel` readers safe (never a hash) was not the same as making them complete: for schedule names over 63 characters they were left with an honest but uninformative empty value, unlike every other case this design handles, which recovers the real name after truncation rather than merely avoiding showing the wrong one. Category E.2 adds a `ScheduleFullNameAnnotation`, following the exact pattern already established for Category D.2, so all seven sites can recover and display the real name regardless of length.

## Goals

- Prevent object creation failures caused by name or label value length exceeding Kubernetes limits.
- Produce deterministic, unique, stable names when truncation is necessary.
- Introduce a minimal, reusable set of helper functions so future code is easy to write correctly.
- Fix all thirty-six known name-length locations identified in the audit.
- Make all eleven `GenerateName` sites in the codebase use `CreateRetryGenerateName` — five of Category A's ten already do, plus the eleventh (`server_status.go:42`); Category F fixes the remaining five, aligning with the KEP 4420 intent for collision-safe generated names.
- Preserve correct `find*ByPod` lookup behavior for hosting pods whose owning object's label value was truncated, by recovering the full name from a pod annotation.

## Non Goals

- Enforcing length limits on user-supplied names at Velero CLI admission time (e.g., rejecting a `velero backup create` invocation with a name long enough to force truncation of one or more derived object names, per Category A).
  The CLI already propagates the underlying Kubernetes API error to the user, which is sufficient feedback.
  Duplicate client-side validation is not needed.
- Changing the CRD schema or adding new API fields.
- Migrating objects that were already created with names derived from the old code.
  As explained in the Compatibility section, this is unnecessary for two different reasons depending on category: for the admission-rejected cases, such objects could never have existed; for Category E's lookup inconsistency, the fix makes existing objects findable without any data change.

## High-Level Design

Two new helper functions are added to `pkg/label/label.go`, following the same pattern as the existing `GetValidName` function which already handles the 63-character label limit:

**`GetValidGenerateName(prefix string) string`**
Truncates a `GenerateName` prefix to at most 58 characters — the number of characters Kubernetes' default `names.SimpleNameGenerator` actually retains from a `GenerateName` value before appending its own 5-character random suffix, independent of the resource's own maximum name length.
When truncation is needed the last 6 characters of the (58-character) result are replaced with the first 6 characters of the SHA-256 of the original prefix, so the retained portion still differs between distinct long inputs even though most of the input is discarded either way.

**`GetValidObjectName(name string) string`**
Truncates a deterministic object name to at most 253 characters using the same hash-suffix strategy.
Unlike `GetValidGenerateName`, this path sets `metadata.name` directly — it is never passed through `SimpleNameGenerator` — so the full 253-character DNS1123 subdomain limit applies, and the hash suffix is what stands between two distinct long inputs and an `AlreadyExists` conflict (there is no Kubernetes-injected randomness backstopping it here, unlike the `GenerateName` case). Because `GetValidObjectName` is a brand-new function with no pre-existing callers, and because that collision risk is a real functional conflict rather than just a readability concern, it uses a longer, 16-character hash suffix (64 bits) than `GetValidGenerateName`'s 6. `GetValidName` — an existing function this design does not otherwise change the collision behavior of — keeps its current 6-character suffix; see "Truncate without a hash suffix" under Alternatives Considered for why widening it was considered and rejected.

All thirty-six affected call sites are updated to pass their computed name or prefix through the appropriate helper before use.

For the four Category D locations whose label value is used to look up the owning object by exact name (`find*ByPod` helpers), truncation alone is insufficient: the design additionally introduces a per-object annotation on the hosting pod that stores the full, untruncated name, and updates the lookup helpers to read the annotation first, falling back to the (possibly truncated) label for pods created before this change. See Category D (D.2) below for details.

## Detailed Design

### Refactor `pkg/label/label.go`

The existing `GetValidName` function uses the same SHA-256 hash-suffix strategy that the new functions require.
Rather than duplicating the logic, `GetValidName` is refactored to delegate to a private helper `getValidNameWithMaxLen`, and the two new public functions delegate to the same helper with their respective limits:

```go
// randomSuffixLength is the number of random characters Kubernetes appends to a
// GenerateName prefix when creating an object.
const randomSuffixLength = 5

// kubernetesGeneratedNameTotalLength is the fixed total length (retained prefix +
// random suffix) that Kubernetes' default names.SimpleNameGenerator
// (k8s.io/apiserver/pkg/storage/names) produces for a GenerateName-based create.
// Every REST storage strategy -- for CustomResourceDefinitions and built-in types
// alike -- uses this generator unless it installs a custom NameGenerator, which
// none of Velero's GenerateName sites do. The retained-prefix length (58) is NOT
// derived from the per-resource DNS1123Subdomain limit (253); characters
// submitted past that point -- including a hash suffix appended by Velero itself
// -- are silently discarded before the object is created.
const kubernetesGeneratedNameTotalLength = 63

// getValidNameWithMaxLen is the shared implementation for all name-length helpers.
// If name fits within maxLen it is returned unchanged.
// Otherwise the last hashLen characters are replaced with the first hashLen hex
// characters of SHA-256(name), reducing (not eliminating) the chance that two
// distinct long names collide after truncation. See "Truncate without a hash
// suffix" in Alternatives Considered for why GetValidObjectName uses a longer
// hashLen than GetValidName/GetValidGenerateName, and why GetValidName's is
// deliberately left unchanged from its existing, already-shipped behavior.
func getValidNameWithMaxLen(name string, maxLen, hashLen int) string {
    if len(name) <= maxLen {
        return name
    }
    sha := sha256.Sum256([]byte(name))
    strSha := hex.EncodeToString(sha[:])
    charsFromName := maxLen - hashLen
    if charsFromName < 0 {
        return strSha[:maxLen]
    }
    return name[:charsFromName] + strSha[:hashLen]
}

// shortHashSuffixLength (6 characters) is GetValidName's existing, already-shipped
// suffix length (unchanged by this design -- see rationale below) and
// GetValidGenerateName's suffix, where hash length has no correctness role (see
// GetValidGenerateName's doc comment).
const shortHashSuffixLength = 6

// objectNameHashSuffixLength is used by GetValidObjectName and
// GetValidNameLongHash -- both brand-new (this design either introduces them,
// or is the first time they're ever exercised for a long input) with no
// pre-existing callers or persisted state -- where a hash collision is a real
// functional conflict (AlreadyExists, or a selector matching the wrong
// object), not just a readability concern. 16 hex characters (64 bits) makes
// the birthday-bound collision probability negligible for any realistic
// number of long, similarly-prefixed values, at the cost of 10 more
// characters than GetValidGenerateName/GetValidName's 6, which is negligible
// against a 253-character (GetValidObjectName) or even a 63-character
// (GetValidNameLongHash) budget.
const objectNameHashSuffixLength = 16

// GetValidName converts a string to a valid Kubernetes label value (≤ 63 characters).
// This function already exists in the codebase (with this same 6-character
// suffix) and already has dozens of callers unrelated to this design (e.g.
// BackupUIDLabel, StorageLocationLabel, VolumeNamespaceLabel); it is
// refactored here to delegate to the shared helper, but its suffix length is
// deliberately left unchanged -- see "Truncate without a hash suffix" under
// Alternatives Considered for why lengthening it would be a compatibility
// break, not a strict improvement.
func GetValidName(label string) string {
    return getValidNameWithMaxLen(label, validation.DNS1035LabelMaxLength, shortHashSuffixLength)
}

// GetValidGenerateName truncates a GenerateName prefix to the number of
// characters Kubernetes' SimpleNameGenerator actually retains (58) before
// appending its own 5-character random suffix. This is independent of --
// and much stricter than -- the 253-character DNS1123Subdomain limit that
// merely keeps the raw GenerateName field itself from being rejected at
// admission.
func GetValidGenerateName(prefix string) string {
    return getValidNameWithMaxLen(prefix, kubernetesGeneratedNameTotalLength-randomSuffixLength, shortHashSuffixLength) // 58
}

// GetValidObjectName truncates a deterministic object name to the Kubernetes
// 253-character DNS subdomain limit. Unlike GetValidGenerateName, this name
// is never passed through SimpleNameGenerator, so the full DNS1123Subdomain
// limit applies.
func GetValidObjectName(name string) string {
    return getValidNameWithMaxLen(name, validation.DNS1123SubdomainMaxLength, objectNameHashSuffixLength)
}

// GetValidNameLongHash converts a string to a valid Kubernetes label value
// (<= 63 characters), like GetValidName, but with the longer 16-character
// hash suffix. Unlike GetValidName, this is not a pre-existing function --
// it is for labels this design is the first to ever hash, where there is no
// already-persisted 6-character-hash value to remain compatible with (see
// Category E.2 and "Truncate without a hash suffix" under Alternatives
// Considered). Do not use this for labels GetValidName already covers
// (BackupNameLabel, RestoreNameLabel, StorageLocationLabel, etc.) -- doing so
// would break their existing callers' already-persisted long-name labels the
// same way lengthening GetValidName itself would.
func GetValidNameLongHash(label string) string {
    return getValidNameWithMaxLen(label, validation.DNS1035LabelMaxLength, objectNameHashSuffixLength)
}
```

`validation.DNS1035LabelMaxLength` (63) and `validation.DNS1123SubdomainMaxLength` (253) are both from `k8s.io/apimachinery/pkg/util/validation`, which is already imported by the package.
`kubernetesGeneratedNameTotalLength` (63) and `randomSuffixLength` (5) together document the fixed total that `names.SimpleNameGenerator` produces; Velero does not add `k8s.io/apiserver` as a dependency to obtain these as real constants (see "Import `k8s.io/apiserver/pkg/storage/names`" under Alternatives Considered) — they are redeclared locally with a comment citing the upstream behavior they mirror.
`GetValidNameLongHash`'s only caller is Category D.1/E.2's `ScheduleNameLabel` handling, which additionally needs a new sibling label constant, `ScheduleNameHashLabel`, added to `pkg/apis/velero/v1/labels_annotations.go` alongside the existing `ScheduleNameLabel` — see Category D.1 for why a second label key, not just a hash, is what actually needs to be new here.

### Category A — `GenerateName` prefix exceeds what Kubernetes retains (10 locations)

All ten locations replace the raw string with `label.GetValidGenerateName(...)`:

| File | Object | Before | After |
| --- | --- | --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:588` | DataUpload | `backup.Name + "-"` | `label.GetValidGenerateName(backup.Name + "-")` |
| `pkg/restore/actions/csi/pvc_action.go:547` | DataDownload | `restore.Name + "-"` | `label.GetValidGenerateName(restore.Name + "-")` |
| `pkg/podvolume/backupper.go:545` | PodVolumeBackup | `backup.Name + "-"` | `label.GetValidGenerateName(backup.Name + "-")` |
| `pkg/podvolume/restorer.go:288` | PodVolumeRestore | `restore.Name + "-"` | `label.GetValidGenerateName(restore.Name + "-")` |
| `pkg/cmd/cli/backup/delete.go:149` | BackupDeleteRequest (CLI) | `b.Name + "-"` | `label.GetValidGenerateName(b.Name + "-")` |
| `pkg/backup/delete_helpers.go:32` | DeleteBackupRequest (GC controller) | `name + "-"` | `label.GetValidGenerateName(name + "-")` |
| `pkg/restore/actions/dataupload_retrieve_action.go:101` | ConfigMap | `dataUpload.Name + "-"` | `label.GetValidGenerateName(dataUpload.Name + "-")` |
| `pkg/backup/actions/csi/pvc_action.go:260` | VolumeSnapshot | `"velero-" + pvc.Name + "-"` | `label.GetValidGenerateName("velero-" + pvc.Name + "-")` |
| `pkg/restore/actions/csi/pvc_action.go:717` | VolumeSnapshot (restore-side rehydration) | `"velero-" + pvc.Name + "-"` | `label.GetValidGenerateName("velero-" + pvc.Name + "-")` |
| `pkg/backup/actions/csi/pvc_action.go:1008` | VolumeGroupSnapshot | `fmt.Sprintf("velero-%s-", vgsLabelValue)` | `label.GetValidGenerateName(fmt.Sprintf("velero-%s-", vgsLabelValue))` |

Kubernetes' name generator retains only the first 58 characters of whatever `GenerateName` value is submitted (see Background), so the effective budget for user-controlled content is `58 - <fixed literal characters>` for each pattern above — roughly 57 characters for the seven `<name> + "-"` sites, and roughly 50 characters for the three `"velero-" + <name> + "-"` sites.
This is a much smaller budget than the 248/253-character figures the field-level admission check allows, so truncation is the common case for these sites, not a rare edge case: any backup, restore, or PVC name longer than ~50-57 characters — not just pathologically long ones — will have its `GenerateName` prefix hashed.
That is expected and harmless: Kubernetes' own random 5-character suffix, appended after this helper runs, already guarantees the final object name is essentially always unique regardless of what the retained 58-character prefix looks like; correlation back to the owning backup/restore/PVC always goes through labels (`BackupNameLabel`, etc.), not through parsing the generated name's prefix.

The VolumeSnapshot and VolumeGroupSnapshot cases deserve attention: `"velero-"` (7 chars) + a name up to 253 chars + `"-"` (1 char) can be up to 261 characters — far more than the 58 characters Kubernetes retains — so these three sites (`pkg/backup/actions/csi/pvc_action.go:260` and `:1008`, and `pkg/restore/actions/csi/pvc_action.go:717`) are truncated on nearly every real-world PVC name and VGS group-label value, not only unusually long ones. Two of these (`:260` and `:717`) were independent audit misses; `pkg/backup/actions/csi/pvc_action.go:1008` (VolumeGroupSnapshot) was instead previously misclassified — listed under "Locations confirmed safe" using the (incorrect) 248-character figure — see the note in that section below.

`pkg/backup/delete_helpers.go:32`'s `NewDeleteBackupRequest` is a second, independent `DeleteBackupRequest` constructor used by the GC controller (`pkg/controller/gc_controller.go:204`), distinct from the CLI's `pkg/cmd/cli/backup/delete.go:149`. Both construct the same object with the same `GenerateName` pattern but were previously two separate audit misses; both need the fix. The GC controller call site already uses `veleroclient.CreateRetryGenerateName`, so no Category F change is needed there.

### Category B — Deterministic `Name:` > 253 characters (1 location)

`pkg/repository/backup_repo_op.go:98`:

```go
// Before
Name: fmt.Sprintf("%s-%s-%s", key.VolumeNamespace, key.BackupLocation, key.RepositoryType),

// After
Name: label.GetValidObjectName(
    fmt.Sprintf("%s-%s-%s", key.VolumeNamespace, key.BackupLocation, key.RepositoryType),
),
```

The `BackupRepository` is already looked up exclusively by label selector (not by name) as documented by the comment at `pkg/repository/ensurer.go:73`.
The name change for pathologically long combinations is therefore safe.

### Category C — Derived name with suffix > 253 characters (2 locations)

`pkg/exposer/cache_volume.go:82`, function `getCachePVCName`:

```go
// Before
func getCachePVCName(ownerObject corev1api.ObjectReference) string {
    return ownerObject.Name + cacheVolumeDirSuffix  // cacheVolumeDirSuffix = "-cache" (6 chars)
}

// After
func getCachePVCName(ownerObject corev1api.ObjectReference) string {
    return label.GetValidObjectName(ownerObject.Name + cacheVolumeDirSuffix)
}
```

`ownerObject` is a DataDownload. Its `Name` is produced by `GenerateName`, so — as established in Background and Category A — Kubernetes' own name generator already guarantees it is ≤ 63 characters, regardless of how long `restore.Name` was; appending `"-cache"` (6 characters) therefore produces at most 69 characters, well under the 253-character limit. This fix is kept for defense-in-depth (see Compatibility) rather than because it is reachable with today's Kubernetes name generator behavior.
Because `getCachePVCName` is called consistently for both creation and all subsequent lookups, applying the same truncation function everywhere preserves correctness regardless.

`pkg/datamover/dataupload_delete_action.go:118`:

```go
// Before
Name: fmt.Sprintf("%s-info", du.Name),

// After
Name: label.GetValidObjectName(fmt.Sprintf("%s-info", du.Name)),
```

This ConfigMap's name is `du.Name` (a DataUpload name, up to 253 characters) plus a `"-info"` suffix (5 characters), up to 258 characters.
The ConfigMap is looked up elsewhere by label selector (`DataUploadSnapshotInfoLabel`), not by name, so applying the same helper at the single construction site is sufficient for consistency.

### Category D — Label value without `GetValidName` (9 locations)

Label values are limited to 63 characters.
Nine locations set a label from a raw object name that could exceed this limit.
They split into two groups depending on how the label value is consumed downstream.

#### D.1 — Selector-only label values (5 locations)

These label values are only ever consumed via `MatchingLabels` selectors or informational comparison, never as the `Name` of a direct `client.Get`.
Hashing both the write side (here) and any read side (selector construction) keeps them consistent, exactly like the existing `GetValidName` usage elsewhere in the codebase.

| File | Label | Before | After |
| --- | --- | --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:1128` | `BackupNameLabel` | `latestVS.Labels[velerov1api.BackupNameLabel] = backup.Name` | `latestVS.Labels[velerov1api.BackupNameLabel] = label.GetValidName(backup.Name)` |
| `pkg/builder/backup_builder.go:107` | `ScheduleNameLabel` (or `ScheduleNameHashLabel`, see below) | `labels[velerov1api.ScheduleNameLabel] = schedule.Name` | see below |
| `pkg/backup/actions/csi/pvc_action.go:389` | `VolumeSnapshotLabel` | `vs.Name` | `label.GetValidName(vs.Name)` |
| `pkg/backup/actions/csi/pvc_action.go:390` | `BackupNameLabel` | `backup.Name` | `label.GetValidName(backup.Name)` |
| `pkg/datamover/dataupload_delete_action.go:120` | `BackupNameLabel` | `bak.Name` | `label.GetValidName(bak.Name)` |

The last row is worth calling out: `pkg/datamover/dataupload_delete_action.go:68` already compares an *existing* DataUpload's `BackupNameLabel` against `label.GetValidName(input.Backup.Name)`, i.e. it already assumes the label was written as a hash.
Line 120 is a different code path (constructing the snapshot-info ConfigMap for a new DataUpload) that was still writing the raw name — an inconsistency within the same file that this fix resolves.

**The `ScheduleNameLabel` row is not a simple hash-in-place fix, unlike the other four rows.** `ScheduleNameLabel` is read by several places that assume an exact match (Category E.2), so a bare hash would create the same ambiguity `GetValidObjectName`'s 16-character suffix was designed to make negligible for *distinct long names* — except here the ambiguity is between a hash and a *short, real* name, not between two hashes, and no hash length closes that gap (see "Truncate without a hash suffix" under Alternatives Considered for why). Instead, `ScheduleNameLabel` gets a second, sibling label, `ScheduleNameHashLabel`, and every write/read site chooses between them based on the *candidate name's own length* — never based on inspecting a label value's shape, which is what created the ambiguity in the first place:

```go
// Before
labels[velerov1api.ScheduleNameLabel] = schedule.Name

// After
scheduleLabels := make(map[string]string, len(labels)+1)
for k, v := range labels {
    scheduleLabels[k] = v
}
if len(schedule.Name) <= validation.DNS1035LabelMaxLength {
    scheduleLabels[velerov1api.ScheduleNameLabel] = schedule.Name
} else {
    scheduleLabels[velerov1api.ScheduleNameHashLabel] = label.GetValidNameLongHash(schedule.Name)
}
labels = scheduleLabels
```

`ScheduleNameLabel` now holds *only* schedule names that are already ≤ 63 characters, verbatim; `ScheduleNameHashLabel` holds *only* hashes of names that were too long to fit. The two label keys are disjoint by construction — a value read from `ScheduleNameLabel` is never a hash, full stop, with no length-based inference required and no coincidental-collision risk between the two categories (see Category E.2 for the read side and why this fully replaces the length-heuristic approach considered and rejected there).

**The `VolumeSnapshotLabel` row (`pvc_action.go:389`) has a sibling that must *not* be touched.** The same function also sets an *annotation* with the identical key, on a separate `annotations` map (`pkg/backup/actions/csi/pvc_action.go:394`): `annotations[velerov1api.VolumeSnapshotLabel] = vs.Name`. That annotation, not the label, is what the restore side reads as the exact VolumeSnapshot name — `pkg/restore/actions/csi/pvc_action.go:103` reads `pvcFromBackup.Annotations[velerov1api.VolumeSnapshotLabel]`, then uses that value at `:174` (`GenerateSha256FromRestoreUIDAndVsName`), `:198`, and `:332` to point the restored PVC's data source at the original VolumeSnapshot by name. Annotations carry no 63-character limit, so `:394` must stay a raw, untruncated name; hashing it "for consistency" with the label fix at `:389` would point restored PVCs at a VolumeSnapshot that no longer exists under that name. This is Category D.2's hazard in reverse: D.2 *adds* a full-name annotation because a label can no longer hold one; here, that annotation already exists for an unrelated historical reason and must simply be left alone.

#### D.2 — Labels used for exact-name lookup by `find*ByPod` helpers (4 locations, requires annotation fallback)

These four label values are read back with `client.Get(..., Name: <label value>)` inside a `find*ByPod` helper, to locate the CR that owns a given hosting pod:

| File | Label | Owning object | `find*ByPod` helper |
| --- | --- | --- | --- |
| `pkg/controller/pod_volume_backup_controller.go:839` | `PVBLabel: pvb.Name` | PodVolumeBackup | `findPVBByPod` (`pkg/controller/pod_volume_backup_controller.go:904`) |
| `pkg/controller/pod_volume_restore_controller.go:940` | `PVRLabel: pvr.Name` | PodVolumeRestore | `findPVRByRestorePod` (`pkg/controller/pod_volume_restore_controller.go:1020`) |
| `pkg/controller/data_upload_controller.go:982` | `DataUploadLabel: du.Name` | DataUpload | `findDataUploadByPod` (`pkg/controller/data_upload_controller.go:1067`) |
| `pkg/controller/data_download_controller.go:912` | `DataDownloadLabel: dd.Name` | DataDownload | `findDataDownloadByPod` (`pkg/controller/data_download_controller.go:998`) |

**This is the critical design flaw identified in review (credit: @blackpiglet).**
Simply hashing these four label values with `GetValidName` — as originally proposed — would break the corresponding `find*ByPod` lookup whenever the owning object's name is long enough to require truncation: the label would hold a hash, but `client.Get` needs the object's *real* name, and the hash and the real name are different strings.
For example, today:

```go
// pkg/controller/pod_volume_backup_controller.go
func findPVBByPod(client client.Client, pod corev1api.Pod) (*velerov1api.PodVolumeBackup, error) {
    if label, exist := pod.Labels[velerov1api.PVBLabel]; exist {
        pvb := &velerov1api.PodVolumeBackup{}
        err := client.Get(context.Background(), types.NamespacedName{
            Namespace: pod.Namespace,
            Name:      label, // must be the PVB's real name, not a hash
        }, pvb)
        ...
    }
}
```

**Fix: recover the full name from a pod annotation, with label fallback.**
Four new annotation constants are added to `pkg/apis/velero/v1/labels_annotations.go`, one per object type, storing the full untruncated name:

```go
PVBFullNameAnnotation          = "velero.io/pvb-full-name"
PVRFullNameAnnotation          = "velero.io/pvr-full-name"
DataUploadFullNameAnnotation   = "velero.io/data-upload-full-name"
DataDownloadFullNameAnnotation = "velero.io/data-download-full-name"
```

At each of the four write sites, the hosting pod gets both the (possibly truncated) label — for selector-based listing and human-readable `kubectl get -l` filtering — and the full-name annotation.

**Reserved-key precedence.** All four sites merge a user-configurable map (`r.podLabels`/`r.podAnnotations`, or third-party labels/annotations discovered from the node-agent's own config) on top of a map that is seeded with Velero's own reserved key. Today that is true only for `hostingPodLabels` (`PVBLabel`, etc.); if the new `PVBFullNameAnnotation`-style keys were added the same way — reserved key first, user config merged in after — a user (or a copy-pasted config) that happened to set an annotation using one of these reserved keys would silently overwrite the real owning-object name, and the corresponding `find*ByPod` lookup would then fetch the wrong object or return `NotFound`.
To avoid this, both the pre-existing label map and the new annotation map must apply Velero's reserved key(s) *last*, after any user-configured or third-party-discovered entries, so user configuration can never replace them:

```go
// pkg/controller/pod_volume_backup_controller.go
hostingPodLabels := map[string]string{}
if len(r.podLabels) > 0 {
    for k, v := range r.podLabels {
        hostingPodLabels[k] = v
    }
} else {
    for _, k := range util.ThirdPartyLabels {
        // ... discover third-party labels as today ...
    }
}
hostingPodLabels[velerov1api.PVBLabel] = label.GetValidName(pvb.Name) // reserved; applied last

hostingPodAnnotation := map[string]string{}
if len(r.podAnnotations) > 0 {
    for k, v := range r.podAnnotations {
        hostingPodAnnotation[k] = v
    }
} else {
    for _, k := range util.ThirdPartyAnnotations {
        // ... discover third-party annotations as today ...
    }
}
hostingPodAnnotation[velerov1api.PVBFullNameAnnotation] = pvb.Name // reserved; applied last
```

The other three write sites (`pkg/controller/pod_volume_restore_controller.go`, `pkg/controller/data_upload_controller.go`, `pkg/controller/data_download_controller.go`) follow the same ordering with their respective label/annotation constant.

Each `find*ByPod` helper is updated to prefer the annotation and fall back to the label, so pods created by an older Velero version (before this annotation existed) continue to resolve correctly. The annotation is only trusted when non-empty — an empty string (which a `pod.Annotations[key]` lookup cannot distinguish from "absent" using the two-value form alone) falls back to the label rather than being used as a lookup name, as defense in depth alongside the reserved-key-last ordering above. If the annotation-derived name is stale or otherwise wrong (e.g. hand-edited pod metadata, or a future scenario where annotation and label genuinely diverge), the `client.Get` using it fails with `NotFound` — in that case the helper retries once with the label-derived name instead of returning the error immediately, rather than trusting the annotation unconditionally once it's present. Whenever *either* the annotation or the label resolves to a real object, the helper confirms that object actually owns this pod before trusting it — see below:

```go
func findPVBByPod(client client.Client, pod corev1api.Pod) (*velerov1api.PodVolumeBackup, error) {
    tryGet := func(name string) (*velerov1api.PodVolumeBackup, error) {
        if name == "" {
            return nil, nil
        }
        pvb := &velerov1api.PodVolumeBackup{}
        err := client.Get(context.Background(), types.NamespacedName{
            Namespace: pod.Namespace,
            Name:      name,
        }, pvb)
        if err != nil {
            return nil, err
        }
        return pvb, nil
    }

    if annotated := pod.Annotations[velerov1api.PVBFullNameAnnotation]; annotated != "" && len(validation.IsDNS1123Subdomain(annotated)) == 0 {
        pvb, err := tryGet(annotated)
        switch {
        case err == nil:
            // The annotation resolved to a real PVB; confirm the hosting pod is
            // actually controlled by it before trusting it, in case the
            // annotation is stale or was somehow copied from an unrelated pod.
            if metav1.IsControlledBy(&pod, pvb) {
                return pvb, nil
            }
            // Resolved to a real but unrelated PVB -- fall through to the label,
            // same as a NotFound.
        case !apierrors.IsNotFound(err):
            return nil, errors.Wrapf(err, "error to find PVB by pod %s/%s", pod.Namespace, pod.Name)
        }
        // NotFound, or resolved to the wrong object: fall through to the label.
    }

    labeled := pod.Labels[velerov1api.PVBLabel]
    if labeled == "" {
        return nil, nil
    }
    pvb, err := tryGet(labeled)
    if err != nil {
        return nil, errors.Wrapf(err, "error to find PVB by pod %s/%s", pod.Namespace, pod.Name)
    }
    if pvb != nil && !metav1.IsControlledBy(&pod, pvb) {
        // Resolved, but not this pod's owner (e.g. label was a hash that
        // happens to equal a real, unrelated PVB's name) -- no match.
        return nil, nil
    }
    return pvb, nil
}
```

`metav1.IsControlledBy` (from `k8s.io/apimachinery/pkg/apis/meta/v1`) checks whether `pod.OwnerReferences` contains a controller reference to the given object (matching `APIVersion`/`Kind`/`UID`) — exactly the relationship the exposer already establishes. Each of the four hosting pods is created by the shared exposer machinery (`pkg/exposer/pod_volume.go`'s `createHostingPod` for PVB/PVR, `pkg/exposer/csi_snapshot.go`/`generic_restore.go` for DataUpload/DataDownload), and in every case the hosting pod's `OwnerReferences` is set from an `ownerObject` that *is* the PVB/PVR/DataUpload/DataDownload itself (`getPVBOwnerObject`, `getPVROwnerObject`, `getOwnerObject`, `getDataDownloadOwnerObject` — each just copies `Kind`/`Name`/`UID`/`APIVersion` off the CR). So this check works identically, with no special-casing, for all four `find*ByPod` helpers: `findPVRByRestorePod`, `findDataUploadByPod`, and `findDataDownloadByPod` all use the same `metav1.IsControlledBy(&pod, resolvedObj)` guard as `findPVBByPod` above.

**The annotation is validated as a DNS-1123 subdomain (`validation.IsDNS1123Subdomain`) before `tryGet` is ever called, not just checked for emptiness.** A Velero-written annotation is always a real object name and therefore already valid, but the whole point of this fallback path is defense against a stale or corrupted annotation (see the `IsControlledBy` check above) — and a syntactically invalid name is exactly the kind of corruption this should tolerate. Without the pre-validation, `client.Get` with a malformed name can fail with something other than `apierrors.IsNotFound` (e.g. a `Invalid`/`BadRequest` response for a name that fails the API server's own name-syntax check), which the original `switch` would have propagated as a hard error out of `findPVBByPod` instead of falling through to the label lookup below — turning a corrupted annotation into a spurious lookup failure rather than a graceful fallback. Checking the syntax up front sidesteps needing to enumerate every apiserver error shape a malformed name could produce.

(An earlier version of this design tried to validate ownership by comparing `pvb.Spec.Pod`/`pvr.Spec.Pod` — a different `corev1api.ObjectReference` field entirely, pointing to the *client* pod whose volume is being backed up/restored, not the *hosting* pod `find*ByPod` is called with — and asserted that DataUpload/DataDownload had no equivalent field to check at all. Both were wrong: the correct signal for "does this hosting pod belong to this CR" is the `OwnerReferences` relationship the exposer already sets, which exists uniformly for all four types and needs no CR-specific field.)

**Reachability today, like Category C.** All four owning objects (PodVolumeBackup, PodVolumeRestore, DataUpload, DataDownload) get their `Name` from `GenerateName` (Category A), which — per Background — Kubernetes' `SimpleNameGenerator` always bounds to 63 characters. `label.GetValidName` also truncates at 63 characters. So today, `label.GetValidName(pvb.Name)` (and the other three) is *never actually truncating anything*: the input is already ≤ 63 characters by construction, before this design ever runs. The annotation fallback this section adds is, like the Category C fix, defense-in-depth rather than a fix for a bug reachable with today's Kubernetes name-generation behavior — it only matters if a future Kubernetes version changes `GenerateName` retention, or if one of these four CRD types is ever created directly (bypassing `GenerateName`) with a hand-crafted name longer than 63 characters. The design keeps it anyway: it is cheap (a few extra map entries and an `if`), and it is exactly the fix @blackpiglet's review asked for — the point of the review was that the *original, unpatched* proposal would have broken `find*ByPod` the moment a long name was truncated; this section makes that true even in a hypothetical where it currently is not.

### Category E — Label selector inconsistency (14 locations)

The same write/read inconsistency shows up for two different labels: `RestoreNameLabel` (E.1) and `ScheduleNameLabel` (E.2, found in review — the latter is a direct consequence of this design's own Category D.1 fix to `pkg/builder/backup_builder.go:107`, not a pre-existing bug).

#### E.1 — RestoreNameLabel (2 query call sites, 1 write site)

`pkg/controller/restore_finalizer_controller.go` lines 503 and 535 query objects using `RestoreNameLabel: ctx.restore.Name` as a raw string (against `VolumeGroupSnapshotContentList` and `VolumeSnapshotContentList` respectively).
However, most `RestoreNameLabel` values are written via the shared `addRestoreLabels` helper (`pkg/restore/restore.go:2548`), which already applies `label.GetValidName(restoreName)`.
When `restore.Name` exceeds 63 characters, that stored value is a hash but the query above uses the raw name, producing zero results.

Fix both query call sites:

```go
// Before
client.MatchingLabels{velerov1api.RestoreNameLabel: ctx.restore.Name}

// After
client.MatchingLabels{velerov1api.RestoreNameLabel: label.GetValidName(ctx.restore.Name)}
```

**Additional missed write site**: `pkg/restore/actions/csi/volumesnapshot_action.go:145` creates a stub `VolumeGroupSnapshotContent` — the exact object type the first query above lists — but sets `RestoreNameLabel: restore.Name` directly, bypassing `addRestoreLabels`.
Fixing only the query side is not sufficient for VGSC objects: this write site must also change to `label.GetValidName(restore.Name)`, otherwise long restore names produce a VGSC labeled with the raw (over-length) name, which Kubernetes would reject at admission, or — worse — a value the fixed query would never match anyway.

```go
// Before
velerov1api.RestoreNameLabel: restore.Name,

// After
velerov1api.RestoreNameLabel: label.GetValidName(restore.Name),
```

#### E.2 — ScheduleNameLabel (11 call sites: 4 selectors, 7 display-recovery reads)

Category D.1 fixes `pkg/builder/backup_builder.go:107` to write the schedule name into one of two disjoint labels — `ScheduleNameLabel` for names that fit in 63 characters unchanged, `ScheduleNameHashLabel` for a hash of names that don't (see Category D.1 for the write side and why a bare hash-in-place fix isn't sufficient here). Four separate read sites still build a selector against only `ScheduleNameLabel` with the *raw* schedule name, unconditionally, and need the same two-label branching to keep working once D.1 ships, for any schedule name over 63 characters:

| File | Context | Before | After |
| --- | --- | --- | --- |
| `pkg/cmd/cli/restore/create.go:251` | `velero restore create --from-schedule <name>` | `labels.SelectorFromSet(map[string]string{api.ScheduleNameLabel: o.ScheduleName})` | `labels.SelectorFromSet(label.ScheduleNameSelectorSet(o.ScheduleName))` |
| `pkg/cmd/cli/restore/create.go:313` | `--allow-partially-failed` lookup for the same restore | `labels.SelectorFromSet(map[string]string{api.ScheduleNameLabel: o.ScheduleName})` | `labels.SelectorFromSet(label.ScheduleNameSelectorSet(o.ScheduleName))` |
| `pkg/controller/restore_controller.go:388` | Fill in `BackupName` from the most recent backup of `restore.Spec.ScheduleName` | `labels.SelectorFromSet(labels.Set(map[string]string{api.ScheduleNameLabel: restore.Spec.ScheduleName}))` | `labels.SelectorFromSet(labels.Set(label.ScheduleNameSelectorSet(restore.Spec.ScheduleName)))` |
| `pkg/controller/schedule_controller.go:234` | `checkIfBackupInNewOrProgress`, used to skip a new backup while one is already running | `labels.Set(map[string]string{velerov1.ScheduleNameLabel: schedule.Name}).AsSelector()` | `labels.Set(label.ScheduleNameSelectorSet(schedule.Name)).AsSelector()` |

where `label.ScheduleNameSelectorSet` is a small shared helper (in `pkg/label`, alongside `GetValidNameLongHash` and the package's other domain-specific selector helpers) mirroring Category D.1's write-side branching:

```go
// ScheduleNameSelectorSet returns the single-entry label map to match backups
// created from the given schedule name, choosing ScheduleNameLabel or
// ScheduleNameHashLabel by the same rule the write side (Category D.1) uses:
// the candidate name's own length, never the shape of a label value already
// on some other object.
func ScheduleNameSelectorSet(scheduleName string) map[string]string {
    if len(scheduleName) <= validation.DNS1035LabelMaxLength {
        return map[string]string{velerov1api.ScheduleNameLabel: scheduleName}
    }
    return map[string]string{velerov1api.ScheduleNameHashLabel: GetValidNameLongHash(scheduleName)}
}
```

Before this design, a schedule name over 63 characters was already impossible to use this way — `ScheduleNameLabel` would have been rejected as an invalid label value the first time a Backup was created from the schedule, so these four selectors were dead code for such schedules (nothing to find). After Category D.1 alone (without this E.2 fix), long schedule names succeed and are labeled via `ScheduleNameHashLabel`, but these four selectors would still query only `ScheduleNameLabel` with the raw (long) name and silently find nothing — turning a loud creation failure into a silent, harder-to-diagnose lookup failure. `label.ScheduleNameSelectorSet` keeps all four read sites in sync with the D.1 write side, the same fix shape as E.1 (which uses the ordinary `label.GetValidName` in place, since `RestoreNameLabel` does have pre-existing 6-character-hashed values to stay compatible with, and has no read site that depends on distinguishing a hash from a real name the way `ScheduleNameLabel` does — see "Truncate without a hash suffix" under Alternatives Considered).

**The two-label split alone makes every other reader of `ScheduleNameLabel` safe, but not complete.** `pkg/controller/restore_controller.go:432`'s `restore.Spec.ScheduleName = info.backup.GetLabels()[api.ScheduleNameLabel]` (persisted into the Restore's own `Spec` via the merge-patch at `pkg/controller/restore_controller.go:267`) and six backup-metrics read sites (`pkg/controller/backup_controller.go:260,328,900`, `backup_finalizer_controller.go:205`, `backup_operations_controller.go:228`, `backup_deletion_controller.go:241`) all read `ScheduleNameLabel` as-is. Because Category D.1 only ever writes a schedule's *raw* name into `ScheduleNameLabel` (a hash never appears there — it goes into the separate `ScheduleNameHashLabel` instead), none of these seven can be corrupted by a hash anymore: for a schedule ≤ 63 characters they get the real name; for one > 63 characters they get an empty string (label simply absent). That's a real fix on its own — an earlier, reverted iteration of this design tried to reach the same "never a hash" guarantee with a length check and then an unsound `Schedule`-existence check, both unnecessary once the label is split in two.

But "empty" is still a worse answer than "the real name" for a schedule that does happen to have a long name, and unlike Category D.2's `find*ByPod` annotations (added only for defense-in-depth against a precondition that can't currently occur), this gap is *always* reachable the moment a schedule name exceeds 63 characters — Category D.1 makes that succeed rather than fail, so it's no longer a rare or hypothetical case for these seven sites to handle well. The fix follows the exact same shape as Category D.2: a new annotation carries the full, untruncated name alongside the (possibly absent) label, and every reader prefers it.

```go
// pkg/apis/velero/v1/labels_annotations.go
ScheduleFullNameAnnotation = "velero.io/schedule-full-name"
```

`pkg/builder/backup_builder.go`'s `FromSchedule` (Category D.1's write site) sets this annotation unconditionally, alongside the existing label/hash-label write, applied last so a schedule's own templated annotations can't override it — the same reserved-key-last principle as Category D.2. It copies into a fresh map rather than mutating `annotations` in place, because that variable can alias `schedule.Spec.Template.Metadata.Annotations` or `schedule.Annotations` directly (`annotations = schedule.Annotations` is a reference assignment in Go, not a copy) — writing into it would mutate the `Schedule` object itself, which may be a shared, informer-cached object read elsewhere in the controller. (The pre-existing code immediately above this, for `ScheduleNameLabel`, had the identical aliasing shape — `labels = schedule.Labels` followed by `labels[velerov1api.ScheduleNameLabel] = schedule.Name` — an independent, pre-existing bug rather than something this design introduced, but the D.1 write site is already being rewritten for the `ScheduleNameHashLabel` split, so it's fixed the same way here: copy into a fresh `scheduleLabels` map before assigning either label, same as `scheduleAnnotations` below.)

```go
// Before
if annotations != nil {
    b.ObjectMeta(WithAnnotationsMap(annotations))
}

// After
scheduleAnnotations := make(map[string]string, len(annotations)+1)
for k, v := range annotations {
    scheduleAnnotations[k] = v
}
scheduleAnnotations[velerov1api.ScheduleFullNameAnnotation] = schedule.Name // reserved; applied last
b.ObjectMeta(WithAnnotationsMap(scheduleAnnotations))
```

All seven read sites switch from indexing `ScheduleNameLabel` directly to a small shared helper that prefers the annotation, but only after confirming it actually corresponds to whichever of the two labels is set — the same "resolved, but confirm it's really this object's" discipline as the `metav1.IsControlledBy` check in Category D.2, adapted to a value comparison instead of an owner reference (there's no comparable structural relationship to check here, but the label/hash-label is exactly the derived-from-the-same-name value the annotation should reproduce):

```go
// ScheduleDisplayName returns the best available schedule name for display
// and metrics purposes: the full, untruncated name from
// ScheduleFullNameAnnotation when present *and* verified, falling back to
// ScheduleNameLabel otherwise -- for Backups created by a Velero version
// prior to this annotation existing, or if the annotation is stale or
// otherwise doesn't match (e.g. hand-edited metadata), the same defense in
// depth as Category D.2's annotation fallback. ScheduleNameLabel itself is,
// since Category D.1, never a hash, only ever the real name or absent.
func ScheduleDisplayName(obj metav1.Object) string {
    if fullName := obj.GetAnnotations()[velerov1api.ScheduleFullNameAnnotation]; fullName != "" {
        switch {
        case len(fullName) <= validation.DNS1035LabelMaxLength:
            // ScheduleNameLabel should hold this exact name verbatim.
            if fullName == obj.GetLabels()[velerov1api.ScheduleNameLabel] {
                return fullName
            }
        default:
            // ScheduleNameHashLabel should hold this exact name's hash.
            if GetValidNameLongHash(fullName) == obj.GetLabels()[velerov1api.ScheduleNameHashLabel] {
                return fullName
            }
        }
        // Annotation present but doesn't match either label -- don't trust it.
    }
    return obj.GetLabels()[velerov1api.ScheduleNameLabel]
}
```

| File | Before | After |
| --- | --- | --- |
| `pkg/controller/restore_controller.go:432` | `restore.Spec.ScheduleName = info.backup.GetLabels()[api.ScheduleNameLabel]` | `restore.Spec.ScheduleName = label.ScheduleDisplayName(info.backup)` |
| `pkg/controller/backup_controller.go:260` | `schedule := backup.Labels[velerov1api.ScheduleNameLabel]` | `schedule := label.ScheduleDisplayName(backup)` |
| `pkg/controller/backup_controller.go:328` | `backupScheduleName := request.GetLabels()[velerov1api.ScheduleNameLabel]` | `backupScheduleName := label.ScheduleDisplayName(request)` |
| `pkg/controller/backup_controller.go:900` | `backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]` | `backupScheduleName := label.ScheduleDisplayName(backup)` |
| `pkg/controller/backup_finalizer_controller.go:205` | `backupScheduleName := backupRequest.GetLabels()[velerov1api.ScheduleNameLabel]` | `backupScheduleName := label.ScheduleDisplayName(backupRequest)` |
| `pkg/controller/backup_operations_controller.go:228` | `backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]` | `backupScheduleName := label.ScheduleDisplayName(backup)` |
| `pkg/controller/backup_deletion_controller.go:241` | `backupScheduleName := backup.GetLabels()[velerov1api.ScheduleNameLabel]` | `backupScheduleName := label.ScheduleDisplayName(backup)` |

With this, all seven sites show the real schedule name regardless of its length — `restore.Spec.ScheduleName` and every backup metric now carry the same information for a long-named schedule that they already did for a short one, closing the gap this design's earlier "leave it empty" answer only avoided making worse.

Why `pkg/controller/restore_controller.go:432` got extra scrutiny across several iterations of this design: unlike the six backup-metrics sites (which stay local, `backupScheduleName := ...`, never touching a persisted field), this one is patched back to the Restore object's own `Spec.ScheduleName` — a real, user-facing API field, not just a display value. Earlier iterations tried a length check, then a `Schedule`-existence check (reverted after review found it could confidently persist an *unrelated* schedule's name on a rare coincidental match), before landing on the two-label split plus this annotation — which is both safe (no ambiguous value to misinterpret) and complete (no information lost for long schedule names either).

### Category F — `GenerateName` without conflict retry (5 locations)

Velero's `veleroclient.CreateRetryGenerateName` wraps object creation with a retry loop on `AlreadyExists` errors, handling the rare but possible collision when Kubernetes generates the same random suffix for two objects with the same prefix.
This mirrors the intent of KEP 4420 (server-side `GenerateName` retry, beta since Kubernetes 1.31 and GA/stable since 1.32).

Five `GenerateName` sites bypass this wrapper and call `crClient.Create` directly:

| File | Object | Change |
| --- | --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:272` | VolumeSnapshot | `p.crClient.Create` → `veleroclient.CreateRetryGenerateName` |
| `pkg/backup/actions/csi/pvc_action.go:648` | DataUpload | `crClient.Create` → `veleroclient.CreateRetryGenerateName` |
| `pkg/restore/actions/csi/pvc_action.go:628` | DataDownload | `crClient.Create` → `veleroclient.CreateRetryGenerateName` |
| `pkg/restore/actions/csi/pvc_action.go:729` | VolumeSnapshot (restore-side rehydration) | `p.crClient.Create` → `veleroclient.CreateRetryGenerateName` |
| `pkg/backup/actions/csi/pvc_action.go:1024` | VolumeGroupSnapshot | `p.crClient.Create` → `veleroclient.CreateRetryGenerateName` |

For completeness, the six sites that already use `CreateRetryGenerateName` are:

| File | Object |
| --- | --- |
| `pkg/podvolume/backupper.go:380` | PodVolumeBackup |
| `pkg/podvolume/restorer.go:212` | PodVolumeRestore |
| `pkg/cmd/cli/backup/delete.go:151` | BackupDeleteRequest (CLI) |
| `pkg/backup/delete_helpers.go` caller, `pkg/controller/gc_controller.go:206` | DeleteBackupRequest (GC controller) |
| `pkg/restore/actions/dataupload_retrieve_action.go:114` | DataUploadResult ConfigMap |
| `pkg/cmd/cli/serverstatus/server_status.go:44` | ServerStatusRequest (CLI) |

After this fix all eleven `GenerateName` sites in the codebase will be consistent — the ten in Category A above, plus `pkg/cmd/cli/serverstatus/server_status.go:42`, which is not part of Category A because its prefix (`"velero-cli-"`, a fixed 11-character literal with no user input) can never exceed the 58-character retained-prefix budget and so never needs `GetValidGenerateName`; see "Locations confirmed safe" below.
Deployments running on Kubernetes 1.31+ (beta) or 1.32+ (GA/stable) additionally benefit from server-side retry (KEP 4420); the client-side wrapper remains harmless in that case because a server-retried success will never return `AlreadyExists` to the client.

### Locations confirmed safe (no change needed)

| Location | Reason |
| --- | --- |
| Exposer Pod/PVC/VS/VSC names (`ownerObject.Name`) | `ownerObject` is a DataUpload or DataDownload whose name Kubernetes guarantees to be ≤ 63 characters (see Background) |
| `pkg/repository/maintenance/maintenance.go` — `RepositoryNameLabel` values | Already uses `velerolabel.ReturnNameOrHash(repo.Name)` which enforces ≤ 63 characters |
| `pkg/repository/maintenance/maintenance.go:GenerateJobName` | Already caps at 63 characters with a millisecond-based fallback |
| `pkg/cmd/cli/serverstatus/server_status.go:42` — ServerStatusRequest `GenerateName` | Prefix is the fixed literal `"velero-cli-"` (11 characters); no user-controlled input is concatenated, so it can never approach the 58-character retained-prefix budget. Already uses `CreateRetryGenerateName` (`:44`) |

`pkg/backup/actions/csi/pvc_action.go:1008` (VolumeGroupSnapshot `GenerateName`) was previously listed here as safe, reasoning that `vgsLabelValue` (a Kubernetes label value, ≤ 63 characters) keeps `"velero-" + 63 + "-"` = 71 characters under the (incorrect) 248-character figure.
71 is in fact well over the 58 characters Kubernetes' name generator actually retains (see Background and Category A), so this location is not safe from silent truncation and has moved into Category A/F above.

## Compatibility

### No impact for names within current limits

This section is split by helper, since `GetValidGenerateName` and `GetValidObjectName`/`GetValidName` now have very different effective budgets:

- `GetValidObjectName` (Category B, C), `GetValidName` (Category D.1, D.2, E.1), and `GetValidNameLongHash` (Category D.1/E.2's `ScheduleNameLabel` only): for BackupRepository key concatenations ≤ 253 characters, cache PVC / ConfigMap derived names ≤ 253 characters, and label values ≤ 63 characters, these helpers return the input unchanged. Behavior for all existing deployments operating within these limits is identical before and after this change.
- `GetValidGenerateName` (Category A): the effective unchanged-behavior threshold is **much smaller** than a naive reading of the 253-character DNS limit would suggest, because Kubernetes' own name generator only retains the first 58 characters of whatever is submitted (see Background). For the seven `<name> + "-"` sites, names ≤ ~57 characters are unaffected; for the three `"velero-" + <name> + "-"` sites, names ≤ ~50 characters are unaffected. This "unaffected" range only covers names that fit within the 58-character retained prefix; it is not the same range as "creation previously succeeded." Two distinct ranges of previously-affected names behave differently after this fix:
  - Names from ~51/58 characters up to the field-rejection boundary below (the raw `GenerateName` field is still valid): creation already succeeded today, with Kubernetes silently hard-cutting the submitted value at character 58 (no hash, no determinism). After this fix, creation still succeeds, but the retained 58 characters are Velero's deterministic hash-suffixed truncation instead of an arbitrary byte cut. This is the common case, not the rare one.
  - Names long enough that the raw `GenerateName` field itself exceeds 253 characters — i.e. the name exceeds 252 characters for the `<name> + "-"` pattern (1 fixed literal character), or 245 characters for the `"velero-" + <name> + "-"` pattern (8 fixed literal characters) — creation was previously **rejected outright** at admission (a real failure, matching Background's motivating bug). After this fix, the field is truncated by `GetValidGenerateName` before it ever reaches Kubernetes, so creation now succeeds.

### Objects that previously failed to create

For the cases where an object name, `GenerateName` field value, or raw label value itself exceeded its DNS1123 length limit (Category A/B/C's motivating bugs, and Category D.1's label-value case), Velero received a Kubernetes API error at object creation time and the backup or restore operation failed. No such object was ever persisted in etcd because Kubernetes itself enforces those limits at admission, so there are no existing objects to migrate for those cases.
Category E is different: it is a lookup bug against objects that *were* successfully created (the VGSC/VSC's stored `RestoreNameLabel` value, or the label's write side generally, was already within limits, or the query never even reached the point of hitting the length limit) — the problem is that the query and the stored value disagree, not that creation failed. No migration is needed there either, but for a different reason: once both the write and read sides consistently use `label.GetValidName`, existing objects created by the write-side fix become findable by the query-side fix without any data change.

### BackupRepository name change for long BSL or namespace names

When `VolumeNamespace + "-" + BackupLocation + "-" + RepositoryType` exceeds 253 characters, `GetValidObjectName` produces a truncated-with-hash name different from the raw concatenation.
Because `BackupRepository` objects are looked up by label selector (not by name), this name change does not affect the lookup logic.
The comment at `pkg/repository/ensurer.go:73` explicitly documents this: _"Don't use name to filter/search BackupRepository, since it may be changed in future, use label instead."_
Any pre-existing BackupRepository with a concatenated name that would have exceeded 253 characters could never have been successfully created, so no existing object is affected.

### Cache PVC name for very long DataDownload names

`DataDownload.Name` is generated via `GenerateName`, so — independent of any Category A fix — Kubernetes' own name generator guarantees it is always ≤ 63 characters (see Background).
`getCachePVCName` returns `GetValidObjectName(ownerObject.Name + "-cache")`; `ownerObject.Name + "-cache"` is therefore at most 69 characters, well under `GetValidObjectName`'s 253-character limit, so in practice this Category C fix is defensive rather than reachable today.
It is still worth keeping: it makes `getCachePVCName` correct in its own right rather than relying on a fact about a different code path (Category A / Kubernetes' generator) that could change if a future Kubernetes version or a differently-configured API server used a different `NameGenerator`.
Because all code paths that reference the cache PVC call the same `getCachePVCName` function, the name stays consistent between creation and lookup regardless of whether truncation is ever actually exercised.

### Label values for Category D.1 (selector-only)

The five Category D.1 fixes change label value assignment from a raw name to a hashing helper for four of the five (`label.GetValidName(name)`), and to the two-label `ScheduleNameLabel`/`ScheduleNameHashLabel` split for the fifth (see Category D.1's own note on why `ScheduleNameLabel` differs).
For names ≤ 63 characters, all five are unchanged from today: `GetValidName` returns the input as-is, and `ScheduleNameLabel` gets the raw name exactly as it does today.
For names > 63 characters the previous code produced a label value (or, for `ScheduleNameLabel`, would have) that Kubernetes would reject, causing the update to fail.
After this fix, long names are stored as a hash — in `ScheduleNameHashLabel` rather than `ScheduleNameLabel` for the fifth case, so `ScheduleNameLabel` itself never holds anything but a name ≤ 63 characters.
No existing object could carry a raw label value longer than 63 characters because Kubernetes would have rejected its creation or update.

### Annotation fallback for Category D.2 (`find*ByPod` lookups)

The four Category D.2 fixes add a new full-name annotation alongside the (now hashed) label on the hosting pod, and update the corresponding `find*ByPod` helper to read the annotation first.
Pods created by a Velero version prior to this change carry only the label, never the new annotation; the helper's fallback path (`pod.Labels[...]` when the annotation is absent) handles those pods identically to today, so a rolling upgrade does not lose in-flight PodVolumeBackup/PodVolumeRestore/DataUpload/DataDownload operations.
Because these hosting pods are short-lived and recreated on every new operation, the fallback path is only ever exercised transiently during the upgrade window, not indefinitely.

**Reserved-key precedence is itself a small, deliberate behavior change.** Today, `hostingPodLabels` is seeded with the reserved label first and any user-configured `PodLabels`/third-party label sharing that exact key overwrites it. This fix reverses that ordering (reserved key applied last) for both the existing label and the new annotation, so a user configuration that happens to collide with a reserved key can no longer silently break the corresponding `find*ByPod` lookup. This only changes behavior for the narrow, previously-unsafe case of a user-supplied `PodLabels`/`PodAnnotations` entry colliding with one of Velero's own reserved keys; every other configuration is unaffected.

### Label selector fixes for RestoreNameLabel and ScheduleNameLabel

The Category E.1 fix changes two `MatchingLabels` queries from the raw restore name to `label.GetValidName(restore.Name)`.
For restore names ≤ 63 characters the selector is unchanged.
For restore names > 63 characters the previous code silently returned zero results (the selector could never match the stored hash).
After this fix, the query correctly matches objects whose labels were written by the fix-consistent code.

The Category E.2 fix applies the equivalent idea to `ScheduleNameLabel` at four selector call sites, for schedule names > 63 characters, using the shared `label.ScheduleNameSelectorSet` helper (which reads from `ScheduleNameHashLabel` instead of `ScheduleNameLabel` once the candidate name exceeds 63 characters) rather than `label.GetValidName` in place (see Category D.1 and "Truncate without a hash suffix" under Alternatives Considered for why a bare hash-in-place fix, like E.1's, isn't sufficient for `ScheduleNameLabel`).
Unlike E.1 (a pre-existing bug), this is a regression this design would otherwise introduce itself: before Category D.1's write-side fix, a schedule name > 63 characters made `ScheduleNameLabel` an invalid label value, so Backup creation from that schedule already failed loudly; these four selectors were unreachable dead code for such schedules. After D.1 alone, Backup creation would start succeeding (the name is now labeled via `ScheduleNameHashLabel` instead) but these selectors would keep querying only `ScheduleNameLabel` with the raw name and silently match nothing — replacing a loud failure with a silent one. E.2 keeps read and write sides consistent from the same release that introduces D.1, so no such window exists.

Because Category D.1 never writes a hash into `ScheduleNameLabel` itself (long names get `ScheduleNameHashLabel` instead), the seven other readers of `ScheduleNameLabel` — `pkg/controller/restore_controller.go:432`'s `restore.Spec.ScheduleName` auto-fill (which persists into the Restore's own `Spec`, not just a local variable) and six backup-metrics read sites — can never be corrupted by a hash again: for a schedule name ≤ 63 characters they see the real name, and for one > 63 characters they'd otherwise see an absent label (empty string), never a hash. That safety came for free once the label was split in two, superseding an earlier iteration of this design that added a length check and, briefly, an unsound `Schedule`-existence check to `restore_controller.go:432` specifically. But "empty" for a long schedule name is a real information loss compared to every schedule name ≤ 63 characters, which these seven sites display in full — so Category E.2 additionally has all seven switch to `label.ScheduleDisplayName`, which prefers a new `ScheduleFullNameAnnotation` (set unconditionally alongside the label/hash-label at the same write site) and falls back to `ScheduleNameLabel` only for Backups created before this design shipped. After this, all seven display the real schedule name regardless of length, with no empty-value trade-off remaining.

### User-defined maintenance job PodLabels

Unlike Category D.2's `hostingPodLabels`, `pkg/repository/maintenance/maintenance.go`'s pod-label merge (`buildJob`, around line 601) already seeds `RepositoryNameLabel` first and then explicitly skips any user-supplied `config.PodLabels` entry whose key equals `RepositoryNameLabel` (logging a warning and continuing, rather than overwriting), and separately validates every other user-supplied label value with `validation.IsValidLabelValue` (which already enforces the 63-character limit, rejecting oversized values rather than truncating or silently accepting them).
So the reserved-key-collision and oversized-value concerns this section originally raised are already handled by existing code, unrelated to this design — no fix is needed here, unlike Category D.2's `hostingPodLabels` and E.2's `FromSchedule`, which lacked this protection before this design added it.

## Alternatives Considered

### Import `k8s.io/apiserver/pkg/storage/names`

The upstream Kubernetes API server exposes a `SimpleNameGenerator` and `MaxGeneratedNameLength` constant in `k8s.io/apiserver/pkg/storage/names`.
This is in fact the *correct* generator to model `GetValidGenerateName` on: as established in Background, every one of Velero's CRDs and built-in `GenerateName` targets use exactly this generator (`maxNameLength = 63`, `MaxGeneratedNameLength = 58`), regardless of the DNS1123Subdomain (253) limit those resources' own `metadata.name` would otherwise allow.
An earlier version of this design incorrectly assumed Velero's CRD objects were exempt from this 58-character retention and used a 248-character target instead; that assumption did not hold (see Background and Category A).
Velero still does not import `k8s.io/apiserver` as a dependency, not because its behavior differs, but because the two integer constants it would provide (`63`, `5`) are simple, stable, and already fully described by `kubernetesGeneratedNameTotalLength`/`randomSuffixLength` in `pkg/label/label.go` — adding a dependency with `apiserver`'s significant transitive footprint to obtain two constants that are unlikely to change is not worth it.
`validation.DNS1123SubdomainMaxLength` remains the correct constant for `GetValidObjectName`, since that path sets `metadata.name` directly and is never passed through `SimpleNameGenerator`.

### Enforce maximum name length on Backup and Restore objects at admission

Adding a validating admission webhook or CRD validation rule that rejects Backup and Restore names long enough to force truncation of their derived object names would prevent the root cause.
This was rejected because it is a breaking API change for users who currently create such resources and because it does not address the other affected object types (PVC names, BSL names, namespace names) which are outside Velero's control.

### CLI client-side length validation

Adding a pre-flight check in `velero backup create` and related commands to reject names that would cause downstream truncation was considered.
This is not necessary because the CLI already propagates Kubernetes API errors directly to the user, providing sufficient feedback without duplicating validation logic.

### Use a fixed-length UUID or content hash for all generated names

Replacing all derived names with a UUID or full SHA-256 hash would guarantee uniqueness and correct length.
This was rejected because it destroys the human-readable prefix that makes log messages, `kubectl get`, and debugging practical.
The hash-suffix-on-truncation approach preserves the readable prefix in the common case while providing collision resistance when truncation is needed.

### Truncate without a hash suffix (simple truncation)

Simply slicing to the maximum length without appending a hash is simpler to implement but means that two distinct long names that share the same retained prefix would produce the same truncated base.
For `GetValidObjectName` (deterministic `metadata.name`, no Kubernetes-injected randomness) that is a real collision: the second create fails with `AlreadyExists`.

An earlier version of this design used a 6-hex-character suffix (24 bits, ~16.7 million values) for all three helpers; the birthday bound on a 24-bit space is in the low thousands, not "astronomically" large. For `GetValidObjectName` — a brand-new function with no pre-existing callers or persisted state — that bound isn't clearly comfortable for a deployment that creates many thousands of long, similarly-prefixed `BackupRepository`/cache-PVC/ConfigMap objects over its lifetime, so it now uses a 16-hex-character suffix (64 bits) instead: the birthday bound there is astronomically large for any realistic object count, at the cost of 10 extra characters out of its 253-character budget, which is negligible.

**`GetValidName` keeps its existing 6-character suffix, unchanged.** `GetValidName` is not new: it already ships today with dozens of callers across the codebase (`BackupUIDLabel`, `StorageLocationLabel`, `VolumeNamespaceLabel`, `RestoreUIDLabel`, `RestoreNameLabel`, and more), each producing a label value that may already be persisted on real objects in real clusters. Lengthening its hash suffix looks like a pure improvement in isolation — CodeRabbit review correctly pointed out that a 24-bit collision for an identity-critical label like `RestoreNameLabel` is a real selector-mismatch risk, not just a nuisance (see below) — but changing the *shared* function's hash algorithm would recompute a *different* label value for every long name across *every* existing caller, not just the ones this design's Category D.1/E touch. Any object already created (before this design ships) with a long name would have a label baked in under the old 6-character algorithm; after upgrading to a hypothetical longer-hash `GetValidName`, every selector that recomputes that label to search for it — across all dozens of existing call sites, most of which are unrelated to issue #8815 — would compute a different value and silently stop finding that pre-existing object. That is a strictly worse compatibility break than the collision risk it would fix, and it is not scoped to this design's audit (Category A-F): it would need re-auditing every existing `GetValidName` caller in the codebase, which is out of scope for a name-*length* enforcement design.

`GetValidObjectName` and the new `GetValidNameLongHash` have no such legacy, for two different reasons, and so both get the longer 16-character suffix from day one: `GetValidObjectName` is an entirely new function, and `ScheduleNameLabel` (the only caller of `GetValidNameLongHash`) has never been successfully hashed before this design — today's code writes it raw and any long schedule name simply fails admission, so there is no pre-existing hashed value for any hash-length choice to be compatible or incompatible with (see Category D.1/E.2). `RestoreNameLabel`, by contrast, is *already* written via `label.GetValidName` today (`pkg/restore/restore.go:2548`'s `addRestoreLabels`), so it has the same pre-existing-legacy problem as every other `GetValidName` caller and is not a candidate for `GetValidNameLongHash`.

Given that, `RestoreNameLabel`'s 24-bit collision risk (a selector matching an unintended object, e.g. `cleanupStubVGSC` selecting the wrong restore's VGSC/VSC for two restores whose long names happen to hash-collide) is accepted as a pre-existing, already-shipped characteristic of `GetValidName`, not something this design changes for better or worse. It is no different in kind from the same risk that already exists today for every other long-named `BackupUIDLabel`/`StorageLocationLabel`/etc. value in production. If this is worth tightening, it should be its own follow-up that audits and coordinates every `GetValidName` caller through an upgrade path (e.g. a versioned hash, or a migration), which is a materially bigger change than anything in this design's scope; noted in Open Issues.

**A second, distinct collision mode for `GetValidNameLongHash`: raw values and hashed values would share the same output space if hashed in place.** An earlier version of `ScheduleNameLabel`'s fix used `GetValidNameLongHash` to hash it in place, the same way `GetValidObjectName`/`GetValidName` hash their targets in place: for a schedule name ≤ 63 characters, the value is returned unchanged; for one > 63 characters, the result is *always exactly* 63 characters. That means a genuinely-existing schedule whose name happens to be exactly 63 characters would produce a `ScheduleNameLabel` value living in the *same* 63-character space a hash could also occupy — unlike the "two long names collide with each other" risk discussed above, this is "a short (well, exactly-63-character) name coincidentally equals the hash of an unrelated long name." If that coincidence occurred, Category E.2's selectors would match backups from *both* schedules for a `--from-schedule` lookup on either one. Review correctly rejected accepting this as a residual risk (an earlier revision of this document did exactly that, and separately rejected an unsound attempted fix based on checking whether a `Schedule` with the hash's exact name happened to exist).

This is not fixable by choosing a different hash length while still hashing in place: any fixed-length hash output necessarily overlaps with the set of raw names of that same length, since Kubernetes doesn't reserve any character pattern that ordinary label values can't also take. It *is* fixable by not sharing a label key between the two cases at all: Category D.1/E.2 give `ScheduleNameLabel` a sibling label, `ScheduleNameHashLabel`, and choose between them by the *candidate name's own length* at both the write site and all four read sites — never by inspecting an existing label value's shape, which is what created the ambiguity. `ScheduleNameLabel` now holds only raw names ≤ 63 characters; `ScheduleNameHashLabel` holds only hashes of names that didn't fit. The two spaces are disjoint by construction, so the collision cannot occur regardless of hash length, and no out-of-band identifier (e.g. a `Schedule` UID lookup) is needed to disambiguate after the fact.

For `GetValidGenerateName`, Kubernetes always appends its own independent 5 random characters after truncation, so final-object-name uniqueness is already guaranteed by Kubernetes regardless of what Velero's hash contributes; the hash there only helps a human distinguish two long, truncated prefixes at a glance (e.g. in `kubectl get`), not correctness — a longer suffix would only shrink the readable prefix for no benefit, and (like `GetValidName`) it is not a new function, so the same backward-compatibility argument applies even if it were not already moot for this reason.

### Place helpers in a new `pkg/util/names` package

Placing `GetValidGenerateName` and `GetValidObjectName` in a dedicated package was considered.
The existing `pkg/label/label.go` already contains `GetValidName` with identical motivation and the same SHA-256 strategy, and the refactor extracts a shared private `getValidNameWithMaxLen` that all three functions delegate to.
Co-locating them avoids an unnecessary package, eliminates code duplication, and keeps all naming utilities in one place.

## Security Considerations

The SHA-256 hash used in the suffix is not used for any security purpose.
It is used only to reduce the probability of name collisions when two distinct long strings are truncated to the same prefix.
SHA-256 is appropriate for this purpose and is already used by the existing `GetValidName` function.

## Implementation

1. Add `GetValidGenerateName` (targeting the 58-character retained-prefix budget, not 248) and `GetValidObjectName` (16-character hash suffix, not 6) to `pkg/label/label.go` with unit tests covering short, boundary, and long inputs — including a `GetValidGenerateName` test that confirms the hash lands within the first 58 characters, and a `GetValidObjectName` test that confirms its result is 253 characters with a 16-character hash tail.
2. Apply Category A fixes (10 `GenerateName` sites) — straightforward one-line changes each.
3. Apply Category B fix (`BackupRepository` deterministic name).
4. Apply Category C fixes (`getCachePVCName` and the DataUpload snapshot-info ConfigMap name).
5. Apply Category D.1 fixes (5 selector-only label value assignments, including the new `ScheduleNameHashLabel` and `ScheduleFullNameAnnotation` constants and `pkg/builder/backup_builder.go`'s `FromSchedule` write-side split/annotation).
6. Add the four full-name pod annotation constants and apply Category D.2 fixes: at each of the four hosting-pod creation sites, change both the label map and the new annotation map to apply Velero's reserved key *last* (after user-configured/third-party entries are merged in), and update `findPVBByPod`, `findPVRByRestorePod`, `findDataUploadByPod`, `findDataDownloadByPod` to prefer the annotation with label fallback.
7. Apply Category E fixes: E.1's 2 `MatchingLabels` selectors plus the VGSC write-side fix in `pkg/restore/actions/csi/volumesnapshot_action.go`; E.2's 4 `ScheduleNameLabel` selector call sites (`pkg/cmd/cli/restore/create.go:251,313`, `pkg/controller/restore_controller.go:388`, `pkg/controller/schedule_controller.go:234`), each switched to the shared `label.ScheduleNameSelectorSet` helper; and E.2's 7 display-recovery read sites (`pkg/controller/restore_controller.go:432`, `pkg/controller/backup_controller.go:260,328,900`, `backup_finalizer_controller.go:205`, `backup_operations_controller.go:228`, `backup_deletion_controller.go:241`), each switched to the shared `label.ScheduleDisplayName` helper. All of E.2 lands in the same change as Category D.1's `ScheduleNameLabel`/`ScheduleNameHashLabel`/`ScheduleFullNameAnnotation` write-side changes so there is no release where they're inconsistent with each other.
8. Apply Category F fixes (5 `GenerateName` sites missing `CreateRetryGenerateName` wrapper).
9. Add or update unit tests for each fixed function to cover the truncation path, including: a `find*ByPod` test that verifies both the annotation path and the label-fallback path; a `find*ByPod` test (all four types) where the annotation *or* the label resolves to a real but unrelated object (no `OwnerReferences` match to the pod) to confirm the `metav1.IsControlledBy` check rejects it and falls back correctly; a test that a user-configured `PodLabels`/`PodAnnotations` entry colliding with a reserved key does not override it; a `label.ScheduleNameSelectorSet` unit test covering a name ≤ 63 characters (returns `ScheduleNameLabel`), a name > 63 characters (returns `ScheduleNameHashLabel` with the expected hash), and that it agrees with Category D.1's write-side branch for the same inputs; a Category E.2 regression test asserting that, once Category D.1 writes long schedule names via `ScheduleNameHashLabel`, a schedule name over 63 characters is still matched by all four E.2 selector read sites (`pkg/cmd/cli/restore/create.go`'s `--from-schedule` and `--allow-partially-failed` lookups, `restore_controller.go`'s most-recent-backup lookup, and `schedule_controller.checkIfBackupInNewOrProgress`) — this fix's failure mode is a silent zero-match, not an error, so it needs a test rather than relying on code review to catch a regression; a `ScheduleDisplayName` unit test covering the verified-annotation case (both the ≤ 63-character exact-match branch and the > 63-character hash-match branch), the fallback-to-label case (annotation absent, simulating a pre-upgrade Backup), the mismatched-annotation case (annotation present but doesn't match either label, falls back rather than trusting it), and both absent (returns empty string); and a `FromSchedule` test confirming it does not mutate `schedule.Labels`/`schedule.Annotations` (or the template's) in place when writing `ScheduleNameLabel`/`ScheduleNameHashLabel`/`ScheduleFullNameAnnotation`.

All changes are confined to existing functions plus five new annotation constants (the four Category D.2 full-name annotations and `ScheduleFullNameAnnotation`) and one new label constant (`ScheduleNameHashLabel`), and introduce no new CRDs, API fields, or controller reconciliation loops.

## Open Issues

- **Backup and Restore admission validation**: a follow-on enhancement could add CRD validation rules (via `x-kubernetes-validations`) to warn or reject names that would force truncation of all derived objects, giving operators early feedback rather than silently altered names.
- **`GetValidName`'s 24-bit hash suffix for `RestoreNameLabel` and other pre-existing identity-critical labels**: `GetValidName` is unchanged by this design (see "Truncate without a hash suffix" under Alternatives Considered) because lengthening its shared hash algorithm would break every existing caller's already-persisted long-name labels across an upgrade. (`ScheduleNameLabel` does not have this problem and is not in scope for this issue: Category D.1/E.2 give it the longer `GetValidNameLongHash` instead, since it was never successfully hashed at all before this design.) If the collision risk for `RestoreNameLabel` or other pre-existing identity-critical `GetValidName` callers (where a collision causes a selector to match the wrong object, as opposed to labels used only for informational display) is judged worth tightening, it needs its own design: likely a versioned or migrated hash rather than an in-place algorithm change, coordinated across every existing `GetValidName` caller, not scoped to issue #8815.
