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
  Kubernetes appends a 5-character random suffix; if the prefix exceeds 248 characters the creation is rejected.
- `DataDownload` uses `GenerateName: restore.Name + "-"` with the same failure mode.

A broader audit of the codebase found twelve distinct locations across five categories with this class of bug.
An additional audit found three `GenerateName` sites that bypass the existing `CreateRetryGenerateName` wrapper, leaving them vulnerable to spurious `AlreadyExists` failures on name collision.

## Goals

- Prevent object creation failures caused by name or label value length exceeding Kubernetes limits.
- Produce deterministic, unique, stable names when truncation is necessary.
- Introduce a minimal, reusable set of helper functions so future code is easy to write correctly.
- Fix all twelve known name-length locations identified in the audit.
- Make all seven `GenerateName` sites consistent by using `CreateRetryGenerateName`, aligning with the KEP 4420 intent for collision-safe generated names.

## Non Goals

- Enforcing length limits on user-supplied names at Velero CLI admission time (e.g., rejecting a `velero backup create` invocation with a name > 247 characters).
  The CLI already propagates the underlying Kubernetes API error to the user, which is sufficient feedback.
  Duplicate client-side validation is not needed.
- Changing the CRD schema or adding new API fields.
- Migrating objects that were already created with names derived from the old code.
  As explained in the Compatibility section, such objects could never have existed because Kubernetes itself rejects names > 253 characters at creation time.

## High-Level Design

Two new helper functions are added to `pkg/label/label.go`, following the same pattern as the existing `GetValidName` function which already handles the 63-character label limit:

**`GetValidGenerateName(prefix string) string`**
Truncates a `GenerateName` prefix to at most 248 characters.
Kubernetes appends a 5-character random suffix, so the prefix must be ≤ 248 for the total to be ≤ 253.
When truncation is needed the last 6 characters of the prefix are replaced with the first 6 characters of the SHA-256 of the original prefix, preserving uniqueness.

**`GetValidObjectName(name string) string`**
Truncates a deterministic object name to at most 253 characters using the same hash-suffix strategy.

All twelve affected call sites are updated to pass their computed name or prefix through the appropriate helper before use.

## Detailed Design

### Refactor `pkg/label/label.go`

The existing `GetValidName` function uses the same SHA-256 hash-suffix strategy that the new functions require.
Rather than duplicating the logic, `GetValidName` is refactored to delegate to a private helper `getValidNameWithMaxLen`, and the two new public functions delegate to the same helper with their respective limits:

```go
// randomSuffixLength is the number of random characters Kubernetes appends to a
// GenerateName prefix when creating an object.
const randomSuffixLength = 5

// getValidNameWithMaxLen is the shared implementation for all name-length helpers.
// If name fits within maxLen it is returned unchanged.
// Otherwise the last 6 characters are replaced with the first 6 hex characters of
// SHA-256(name) so that distinct long names remain distinct after truncation.
func getValidNameWithMaxLen(name string, maxLen int) string {
    if len(name) <= maxLen {
        return name
    }
    sha := sha256.Sum256([]byte(name))
    strSha := hex.EncodeToString(sha[:])
    charsFromName := maxLen - 6
    if charsFromName < 0 {
        return strSha[:maxLen]
    }
    return name[:charsFromName] + strSha[:6]
}

// GetValidName converts a string to a valid Kubernetes label value (≤ 63 characters).
func GetValidName(label string) string {
    return getValidNameWithMaxLen(label, validation.DNS1035LabelMaxLength)
}

// GetValidGenerateName truncates a GenerateName prefix so that the generated name
// (prefix + 5-character random suffix) fits within the Kubernetes 253-character limit.
func GetValidGenerateName(prefix string) string {
    return getValidNameWithMaxLen(prefix, validation.DNS1123SubdomainMaxLength-randomSuffixLength)
}

// GetValidObjectName truncates a deterministic object name to the Kubernetes
// 253-character DNS subdomain limit.
func GetValidObjectName(name string) string {
    return getValidNameWithMaxLen(name, validation.DNS1123SubdomainMaxLength)
}
```

`validation.DNS1035LabelMaxLength` (63) and `validation.DNS1123SubdomainMaxLength` (253) are both from `k8s.io/apimachinery/pkg/util/validation`, which is already imported by the package.

### Category A — `GenerateName` prefix > 248 characters (7 locations)

All seven locations replace the raw string with `label.GetValidGenerateName(...)`:

| File | Object | Before | After |
| --- | --- | --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:541` | DataUpload | `backup.Name + "-"` | `label.GetValidGenerateName(backup.Name + "-")` |
| `pkg/restore/actions/csi/pvc_action.go:410` | DataDownload | `restore.Name + "-"` | `label.GetValidGenerateName(restore.Name + "-")` |
| `pkg/podvolume/backupper.go:494` | PodVolumeBackup | `backup.Name + "-"` | `label.GetValidGenerateName(backup.Name + "-")` |
| `pkg/podvolume/restorer.go:260` | PodVolumeRestore | `restore.Name + "-"` | `label.GetValidGenerateName(restore.Name + "-")` |
| `pkg/cmd/cli/backup/delete.go:126` | BackupDeleteRequest | `b.Name + "-"` | `label.GetValidGenerateName(b.Name + "-")` |
| `pkg/restore/actions/dataupload_retrieve_action.go:97` | ConfigMap | `dataUpload.Name + "-"` | `label.GetValidGenerateName(dataUpload.Name + "-")` |
| `pkg/backup/actions/csi/pvc_action.go:252` | VolumeSnapshot | `"velero-" + pvc.Name + "-"` | `label.GetValidGenerateName("velero-" + pvc.Name + "-")` |

The VolumeSnapshot case deserves attention: `"velero-"` (7 chars) + pvc.Name (up to 253) + `"-"` (1 char) = up to 261 characters, exceeding the 248-character prefix limit when pvc.Name exceeds 240 characters.

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

### Category C — Derived name with suffix > 253 characters (1 location)

`pkg/exposer/cache_volume.go:83`, function `getCachePVCName`:

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

`ownerObject` is a DataDownload whose generated name can be up to 253 characters.
Appending `"-cache"` (6 characters) produces a string of up to 259 characters.
Because `getCachePVCName` is called consistently for both creation and all subsequent lookups, applying the same truncation function everywhere preserves correctness.

### Category D — Label value without `GetValidName` (2 locations)

Label values are limited to 63 characters.
Two locations set `BackupNameLabel` or `ScheduleNameLabel` using a raw name that could exceed this limit:

| File | Label | Before | After |
| --- | --- | --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:1076` | `BackupNameLabel` | `backup.Name` | `label.GetValidName(backup.Name)` |
| `pkg/builder/backup_builder.go:107` | `ScheduleNameLabel` | `schedule.Name` | `label.GetValidName(schedule.Name)` |

### Category E — Label selector inconsistency (1 location, 2 call sites)

`pkg/controller/restore_finalizer_controller.go` lines 464 and 496 query objects using `RestoreNameLabel: ctx.restore.Name` as a raw string.
However, when those label values are written (in `pkg/restore/restore.go:2146`), they are stored via `label.GetValidName(restoreName)`.
When `restore.Name` exceeds 63 characters, the stored value is a hash but the query uses the raw name, producing zero results.

Fix both call sites:

```go
// Before
client.MatchingLabels{velerov1api.RestoreNameLabel: ctx.restore.Name}

// After
client.MatchingLabels{velerov1api.RestoreNameLabel: label.GetValidName(ctx.restore.Name)}
```

### Category F — `GenerateName` without conflict retry (3 locations)

Velero's `veleroclient.CreateRetryGenerateName` wraps object creation with a retry loop on `AlreadyExists` errors, handling the rare but possible collision when Kubernetes generates the same random suffix for two objects with the same prefix.
This mirrors the intent of KEP 4420 (server-side `GenerateName` retry in Kubernetes 1.32+).

Three `GenerateName` sites bypass this wrapper and call `crClient.Create` directly:

| File | Object | Change |
| --- | --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:264` | VolumeSnapshot | `p.crClient.Create` → `veleroclient.CreateRetryGenerateName` |
| `pkg/backup/actions/csi/pvc_action.go:597` | DataUpload | `crClient.Create` → `veleroclient.CreateRetryGenerateName` |
| `pkg/restore/actions/csi/pvc_action.go:478` | DataDownload | `crClient.Create` → `veleroclient.CreateRetryGenerateName` |

For completeness, the five sites that already use `CreateRetryGenerateName` are:

| File | Object |
| --- | --- |
| `pkg/podvolume/backupper.go:376` | PodVolumeBackup |
| `pkg/podvolume/restorer.go:184` | PodVolumeRestore |
| `pkg/cmd/cli/backup/delete.go:128` | BackupDeleteRequest |
| `pkg/restore/actions/dataupload_retrieve_action.go:110` | DataUploadResult ConfigMap |
| `pkg/client/retry.go` | (the implementation itself) |

After this fix all seven `GenerateName` sites will be consistent.
Deployments running on Kubernetes 1.32+ additionally benefit from server-side retry (KEP 4420); the client-side wrapper remains harmless in that case because a server-retried success will never return `AlreadyExists` to the client.

### Locations confirmed safe (no change needed)

| Location | Reason |
| --- | --- |
| `pkg/backup/actions/csi/pvc_action.go:956` — VolumeGroupSnapshot `GenerateName` | `vgsLabelValue` is sourced from a Kubernetes label value and is therefore already ≤ 63 characters; `"velero-" + 63 + "-"` = 71 ≤ 248 |
| Exposer Pod/PVC/VS/VSC names (`ownerObject.Name`) | `ownerObject` is a DataUpload or DataDownload whose name Kubernetes guarantees to be ≤ 253 characters |
| `pkg/repository/maintenance/maintenance.go` — `RepositoryNameLabel` values | Already uses `velerolabel.ReturnNameOrHash(repo.Name)` which enforces ≤ 63 characters |
| `pkg/repository/maintenance/maintenance.go:GenerateJobName` | Already caps at 63 characters with a millisecond-based fallback |

## Compatibility

### No impact for names within current limits

For backup names ≤ 247 characters, restore names ≤ 247 characters, PVC names ≤ 240 characters, and BackupRepository key concatenations ≤ 253 characters, the helper functions return the input unchanged.
The behavior of all existing deployments operating within these limits is identical before and after this change.

### Objects that previously failed to create

Any Velero deployment that encountered these bugs received a Kubernetes API error at object creation time and the backup or restore operation failed.
No such object was ever persisted in etcd because Kubernetes itself enforces name limits at admission.
There are therefore no existing objects to migrate.

### BackupRepository name change for long BSL or namespace names

When `VolumeNamespace + "-" + BackupLocation + "-" + RepositoryType` exceeds 253 characters, `GetValidObjectName` produces a truncated-with-hash name different from the raw concatenation.
Because `BackupRepository` objects are looked up by label selector (not by name), this name change does not affect the lookup logic.
The comment at `pkg/repository/ensurer.go:73` explicitly documents this: _"Don't use name to filter/search BackupRepository, since it may be changed in future, use label instead."_
Any pre-existing BackupRepository with a concatenated name that would have exceeded 253 characters could never have been successfully created, so no existing object is affected.

### Cache PVC name for very long DataDownload names

After the Category A fixes, `DataDownload.Name` is bounded at 253 characters.
`getCachePVCName` returns `GetValidObjectName(ownerObject.Name + "-cache")`.
For `DataDownload.Name` ≤ 247 characters the cache PVC name is unchanged.
For `DataDownload.Name` > 247 characters (only possible if `restore.Name` exceeded 241 characters, at which point the DataDownload creation previously failed) the cache PVC name is truncated with a hash.
Because all code paths that reference the cache PVC call the same `getCachePVCName` function, the name is consistent between creation and lookup regardless of truncation.

### Label values for BackupNameLabel and ScheduleNameLabel

The two Category D fixes change label value assignment from a raw name to `GetValidName(name)`.
For names ≤ 63 characters `GetValidName` returns the input unchanged.
For names > 63 characters the previous code produced a label value that Kubernetes would reject, causing the update to fail.
After this fix, long names are stored as a hash.
No existing object could carry a raw label value longer than 63 characters because Kubernetes would have rejected its creation or update.

### Label selector fix for RestoreNameLabel

The Category E fix changes two `MatchingLabels` queries from the raw restore name to `label.GetValidName(restore.Name)`.
For restore names ≤ 63 characters the selector is unchanged.
For restore names > 63 characters the previous code silently returned zero results (the selector could never match the stored hash).
After this fix, the query correctly matches objects whose labels were written by the fix-consistent code.

### User-defined maintenance job PodLabels

`pkg/repository/maintenance/maintenance.go` merges user-supplied `config.PodLabels` into the job pod labels without validating each value.
A user could supply a label value longer than 63 characters, overriding the correctly hashed `RepositoryNameLabel` value.
This is a user configuration concern and is noted as a follow-up; it is not addressed by this design because it requires a decision about whether to silently truncate, warn, or reject invalid user-supplied labels.

## Alternatives Considered

### Import `k8s.io/apiserver/pkg/storage/names`

The upstream Kubernetes API server exposes a `SimpleNameGenerator` and `MaxGeneratedNameLength` constant in `k8s.io/apiserver/pkg/storage/names`.
However, this package sets `maxNameLength = 63` — the DNS label limit used for core Kubernetes resources — and `MaxGeneratedNameLength = 58`.
Velero's CRD objects follow the DNS subdomain rule (253 characters), so using `MaxGeneratedNameLength = 58` would needlessly truncate all generated names to 63 characters regardless of actual length.
Additionally, `k8s.io/apiserver` is not currently a dependency of Velero; adding it would introduce significant transitive dependencies.
The constants and logic needed are already available through the existing `k8s.io/apimachinery` dependency via `validation.DNS1123SubdomainMaxLength`.

### Enforce maximum name length on Backup and Restore objects at admission

Adding a validating admission webhook or CRD validation rule that rejects Backup and Restore names longer than 247 characters would prevent the root cause.
This was rejected because it is a breaking API change for users who currently create such resources and because it does not address the other affected object types (PVC names, BSL names, namespace names) which are outside Velero's control.

### CLI client-side length validation

Adding a pre-flight check in `velero backup create` and related commands to reject names that would cause downstream truncation was considered.
This is not necessary because the CLI already propagates Kubernetes API errors directly to the user, providing sufficient feedback without duplicating validation logic.

### Use a fixed-length UUID or content hash for all generated names

Replacing all derived names with a UUID or full SHA-256 hash would guarantee uniqueness and correct length.
This was rejected because it destroys the human-readable prefix that makes log messages, `kubectl get`, and debugging practical.
The hash-suffix-on-truncation approach preserves the readable prefix in the common case while providing collision resistance when truncation is needed.

### Truncate without a hash suffix (simple truncation)

Simply slicing to the maximum length without appending a hash is simpler to implement but means that two distinct long names that share the same prefix would produce the same object name, causing creation conflicts or silent name collisions.
The hash suffix makes this astronomically unlikely.

### Place helpers in a new `pkg/util/names` package

Placing `GetValidGenerateName` and `GetValidObjectName` in a dedicated package was considered.
The existing `pkg/label/label.go` already contains `GetValidName` with identical motivation and the same SHA-256 strategy, and the refactor extracts a shared private `getValidNameWithMaxLen` that all three functions delegate to.
Co-locating them avoids an unnecessary package, eliminates code duplication, and keeps all naming utilities in one place.

## Security Considerations

The SHA-256 hash used in the suffix is not used for any security purpose.
It is used only to reduce the probability of name collisions when two distinct long strings are truncated to the same prefix.
SHA-256 is appropriate for this purpose and is already used by the existing `GetValidName` function.

## Implementation

1. Add `GetValidGenerateName` and `GetValidObjectName` to `pkg/label/label.go` with unit tests covering short, boundary, and long inputs.
2. Apply Category A fixes (7 `GenerateName` sites) — straightforward one-line changes each.
3. Apply Category B fix (`BackupRepository` deterministic name).
4. Apply Category C fix (`getCachePVCName`).
5. Apply Category D fixes (2 label value assignments).
6. Apply Category E fixes (2 `MatchingLabels` selectors).
7. Apply Category F fixes (3 `GenerateName` sites missing `CreateRetryGenerateName` wrapper).
8. Add or update unit tests for each fixed function to cover the truncation path.

All changes are confined to existing functions and introduce no new CRDs, API fields, or controller reconciliation loops.

## Open Issues

- **User-supplied `PodLabels` in maintenance job config**: values are merged without length validation and can override correctly bounded labels.
  A follow-up issue should decide whether to silently truncate via `GetValidName`, log a warning, or return an error when a user-supplied label value exceeds 63 characters.
- **Backup and Restore admission validation**: a follow-on enhancement could add CRD validation rules (via `x-kubernetes-validations`) to warn or reject names that would force truncation of all derived objects, giving operators early feedback rather than silently altered names.
