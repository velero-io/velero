# Namespace Selection by Label in Resource Policy

## Glossary & Abbreviation

**Backup Filter**: The mechanism in Velero that determines which Kubernetes resources are collected from the cluster and written into the backup archive. Backup filters currently operate on four dimensions: namespace, resource type, label, and cluster scope.  
**Global Filter**: A filter that applies uniformly across all namespaces in a backup. All existing Velero backup filters are global filters.  
**Namespace Label Selector Filter**: A filter that dynamically includes or excludes entire namespaces from a backup based on Kubernetes label selectors applied to namespace objects. This is the capability introduced by this design.  
**Resource Policy**: An existing Velero mechanism where backup behavior rules are defined in a ConfigMap and referenced from `BackupSpec.ResourcePolicy`. Currently used for volume policies and global include/exclude policies.

## Abstract

This proposal extends Velero's `includeExcludePolicy` in the ResourcePolicy ConfigMap to support selecting namespaces by Kubernetes label selectors.
Users can dynamically include or exclude namespaces from backups without modifying `BackupSpec` or schedule specs.

## Background

Velero's backup filter system allows users to specify which resources to include or exclude from a backup. The filters operate on four dimensions:

1. **Namespace** — `IncludedNamespaces`/`ExcludedNamespaces` select which namespaces to back up
2. **Resource Type** — `IncludedResources`/`ExcludedResources` (or the newer scoped variants `Included/ExcludedClusterScopedResources`, `Included/ExcludedNamespaceScopedResources`) select which Kubernetes resource types to back up
3. **Labels** — `LabelSelector`/`OrLabelSelectors` filter individual objects by their labels
4. **Cluster Scope** — `IncludeClusterResources` controls whether cluster-scoped resources are included

All four dimensions are applied **globally** — the same filters apply uniformly throughout the entire backup operation. There is no mechanism to dynamically resolve which namespaces to include based on namespace labels.

Users managing many clusters or dynamic namespace sets need a way to declare "back up namespaces labeled `backup=weekly`" without enumerating names.
Issue [#7492](https://github.com/vmware-tanzu/velero/issues/7492) originally proposed extending `--selector` on the Backup, but the community preferred not to overload existing backup filters.
The agreed direction is to model namespace selection by label as a Resource Policy capability, extending `includeExcludePolicy` rather than adding new fields to `BackupSpec`.

Separately, issue [#9448](https://github.com/velero-io/velero/issues/9448) drove a related but distinct extension of the same ResourcePolicy ConfigMap: per-namespace, per-kind resource filtering, merged as `clusterScopedFilterPolicy` and `namespacedFilterPolicies` (see [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) and [Fine Grained Restore Filters](restore-filter-enhancement/fine-grained-restore-filters-design.md)). That work decides *which resources* are collected once a namespace is already selected; this design decides *which namespaces* are selected in the first place. The two live under different top-level ConfigMap keys and share no fields — see [Detailed Design](#detailed-design) for confirmation this design remains compatible with the merged implementation.

The existing `includeExcludePolicy` already holds reusable include/exclude resource filters.
Adding namespace label selectors here is consistent with its purpose and avoids spec sprawl.

## Goals

- Allow users to specify Kubernetes label selectors in `includeExcludePolicy` to dynamically include or exclude namespaces in a backup.

## Non-Goals

- Changing the behavior of `BackupSpec.LabelSelector` or `BackupSpec.OrLabelSelectors` (those continue to filter individual resources, not namespaces).
- Selecting cluster-scoped resources by label (a separate concern; see [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md), merged via `clusterScopedFilterPolicy`, for cluster-scoped resource filtering).
- Selecting individual namespaced resources by namespace label (resources must still be individually matched).
- Changing existing `BackupSpec` fields (`IncludedResources`, `LabelSelector`, etc.) or adding new CRD fields is explicitly avoided by this design.

## Use Cases

### Dynamic per-schedule namespace targeting

A user defines daily and weekly schedules.
Namespace owners opt their namespace into a schedule by adding a label.
The schedules never need updating as namespaces are added or removed.

```yaml
# resource-policy-weekly.yaml (ConfigMap data)
version: v1
includeExcludePolicy:
  includedNamespacesByLabel:
    - "velero-backup-schedule=weekly"
```

```yaml
# resource-policy-daily.yaml
version: v1
includeExcludePolicy:
  includedNamespacesByLabel:
    - "velero-backup-schedule=daily"
```

### Exclude sensitive namespaces by label

A cluster operator excludes any namespace labeled `confidential=true` from all backups.

```yaml
version: v1
includeExcludePolicy:
  excludedNamespacesByLabel:
    - "confidential=true"
```

### Combined include and exclude with multiple selectors

Include all namespaces labeled `team=platform` OR `team=infra`, but exclude those also labeled `env=dev`.

```yaml
version: v1
includeExcludePolicy:
  includedNamespacesByLabel:
    - "team=platform"
    - "team=infra"
  excludedNamespacesByLabel:
    - "env=dev"
```

### Require multiple labels together (AND)

Only back up namespaces that are labeled both `tier=critical` and `compliance=pci`, using `labelSelectorLogic: "AND"` instead of the default OR:

```yaml
version: v1
includeExcludePolicy:
  labelSelectorLogic: "AND"
  includedNamespacesByLabel:
    - "tier=critical"
    - "compliance=pci"
```

Without `labelSelectorLogic: "AND"`, the two entries above would be OR'd (namespaces matching either label), which is a materially different — and in this case incorrect — selection. Note `"tier=critical,compliance=pci"` as a single comma-separated selector string already expresses AND today (comma-separated requirements within one selector string are always AND'd by `labels.Parse`); `labelSelectorLogic: "AND"` is for AND'ing across separate list *entries*, useful when entries are generated/templated independently rather than authored as one string.

## High-Level Design

Two new fields, `includedNamespacesByLabel` and `excludedNamespacesByLabel`, are added to `IncludeExcludePolicy` in the ResourcePolicy ConfigMap.
Each field is a list of Kubernetes label selector strings (same syntax as `kubectl get ns -l`).

At backup time, Velero evaluates each selector against the live namespace list. If any `includedNamespacesByLabel` selector is configured, the resolved union becomes the inclusion baseline (additive with an explicit, non-empty `BackupSpec.IncludedNamespaces`); otherwise the existing "empty means all namespaces" baseline is unchanged. Namespaces matched by any `excludedNamespacesByLabel` selector are then subtracted from that baseline, same as `BackupSpec.ExcludedNamespaces` today. See [Precedence and Interaction](#precedence-and-interaction) for the exact merge order. The resolved set is logged so operators can observe which namespaces were actually selected (see [Observability](#observability)).

This design coexists with the existing `includeExcludePolicy` fields (`includedClusterScopedResources`, `excludedClusterScopedResources`, `includedNamespaceScopedResources`, `excludedNamespaceScopedResources`) and is independent of the `namespacedFilterPolicies` and `clusterScopedFilterPolicy` top-level `ResourcePolicies` keys, now merged (`internal/resourcepolicies/resource_policies.go`) per the [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) design.

## Detailed Design

### Data Structure

`IncludeExcludePolicy` in `internal/resourcepolicies/resource_policies.go` gains three new fields:

```go
type IncludeExcludePolicy struct {
    IncludedClusterScopedResources   []string `yaml:"includedClusterScopedResources"`
    ExcludedClusterScopedResources   []string `yaml:"excludedClusterScopedResources"`
    IncludedNamespaceScopedResources []string `yaml:"includedNamespaceScopedResources"`
    ExcludedNamespaceScopedResources []string `yaml:"excludedNamespaceScopedResources"`
    // New fields
    IncludedNamespacesByLabel []string `yaml:"includedNamespacesByLabel"`
    ExcludedNamespacesByLabel []string `yaml:"excludedNamespacesByLabel"`
    // LabelSelectorLogic controls how multiple entries within
    // IncludedNamespacesByLabel are combined with each other, and
    // independently how multiple entries within ExcludedNamespacesByLabel
    // are combined with each other. "OR" (default) or "AND". Empty string
    // is treated as "OR".
    LabelSelectorLogic string `yaml:"labelSelectorLogic,omitempty"`
}
```

Each entry in `includedNamespacesByLabel` / `excludedNamespacesByLabel` is a label selector string parseable by `k8s.io/apimachinery/pkg/labels.Parse`.
By default (`labelSelectorLogic` unset or `"OR"`), multiple entries within the same list are combined with OR (union): a namespace matching any selector in the list is included/excluded. Setting `labelSelectorLogic: "AND"` combines entries within each list with AND (intersection) instead: a namespace must match every selector in `includedNamespacesByLabel` to be included, and every selector in `excludedNamespacesByLabel` to be excluded. `includedNamespacesByLabel` and `excludedNamespacesByLabel` are still resolved independently of each other regardless of `labelSelectorLogic` — see [Namespace Resolution](#namespace-resolution).
Within a single selector string, comma-separated requirements are always AND (this is `labels.Parse` syntax, unrelated to `labelSelectorLogic`).

Example YAML in ResourcePolicy ConfigMap:

```yaml
version: v1
includeExcludePolicy:
  includedNamespacesByLabel:
    - "team=platform,env=prod"   # namespaces with BOTH labels
    - "team=infra"               # OR namespaces with this label
  excludedNamespacesByLabel:
    - "skip-backup=true"
```

### Validation

`IncludeExcludePolicy.Validate()` is extended to parse each selector string and return an error if any is invalid:

```go
func validateLabelSelectors(selectors []string) error {
    for _, s := range selectors {
        if strings.TrimSpace(s) == "" {
            return fmt.Errorf("label selector cannot be empty")
        }
        if _, err := labels.Parse(s); err != nil {
            return fmt.Errorf("invalid label selector %q: %w", s, err)
        }
    }
    return nil
}

func validateLabelSelectorLogic(logic string) error {
    switch logic {
    case "", "OR", "AND":
        return nil
    default:
        return fmt.Errorf("labelSelectorLogic must be \"OR\" or \"AND\", got %q", logic)
    }
}
```

An empty string is syntactically valid input to `labels.Parse` — it parses as a no-op selector that matches every namespace (equivalent to `labels.Everything()`). Left unchecked, an accidental empty entry in `includedNamespacesByLabel` would silently include all namespaces, and in `excludedNamespacesByLabel` would silently exclude all namespaces. Validation rejects empty (or whitespace-only) selector strings explicitly rather than relying on `labels.Parse` to catch it.

Validation runs at backup admission time via `prepareBackupRequest`.

Note: this validates a Kubernetes label selector string via `labels.Parse`, a distinct code path from `wildcard.ValidateNamespaceName` (`pkg/util/wildcard/expand.go`) used by the merged `namespacedFilterPolicies[].namespaces` glob patterns. `wildcard.ValidateNamespaceName` rejects `,`, `(`, `)`, `!`, `{`, `}` because it validates glob syntax; `labels.Parse` requires commas for AND'd requirements (e.g. `team=platform,env=prod`) and supports `!=`, `in`, `notin`, `!key` that glob patterns don't have. Do not reuse `wildcard.ValidateNamespaceName` for these selector strings.

### Namespace Resolution

A new helper `resolveNamespacesByLabel` is called in `prepareBackupRequest` (or `kubernetesBackupper`) after the existing namespace filter is constructed. It resolves the included and excluded selector lists **independently** — it must not net one against the other, since the caller (not this helper) is responsible for combining them with `BackupSpec.IncludedNamespaces`/`ExcludedNamespaces` (see [Precedence and Interaction](#precedence-and-interaction)). An earlier draft of this helper subtracted excluded matches from included matches internally and returned only the included list; that silently dropped the excluded set for exclude-only policies (no `includedNamespacesByLabel` configured), where the caller still needs it to subtract from an "all namespaces" baseline. It also takes `logic` ("OR" or "AND", empty treated as "OR") to control how entries within each list are combined — see [Require multiple labels together (AND)](#require-multiple-labels-together-and):

```go
// resolveNamespacesByLabel lists all cluster namespaces and returns two
// independently resolved name sets: those matching includedSelectors, and
// those matching excludedSelectors, combined per logic ("OR": any selector
// matches; "AND": every selector in the list matches; "" defaults to "OR").
// It performs no cross-suppression between the two — the caller decides
// how to combine them with BackupSpec.IncludedNamespaces/ExcludedNamespaces.
func resolveNamespacesByLabel(
    ctx context.Context,
    client crclient.Client,
    includedSelectors []string,
    excludedSelectors []string,
    logic string,
) (included []string, excluded []string, err error) {
    nsList := &corev1.NamespaceList{}
    if err := client.List(ctx, nsList); err != nil {
        return nil, nil, errors.Wrap(err, "listing namespaces")
    }

    matchSet := func(selectors []string) sets.String {
        result := sets.NewString()
        if len(selectors) == 0 {
            return result
        }
        parsedSelectors := make([]labels.Selector, 0, len(selectors))
        for _, sel := range selectors {
            parsed, _ := labels.Parse(sel) // already validated
            parsedSelectors = append(parsedSelectors, parsed)
        }
        for _, ns := range nsList.Items {
            nsLabels := labels.Set(ns.Labels)
            if logic == "AND" {
                allMatch := true
                for _, parsed := range parsedSelectors {
                    if !parsed.Matches(nsLabels) {
                        allMatch = false
                        break
                    }
                }
                if allMatch {
                    result.Insert(ns.Name)
                }
            } else { // "OR" (default, including "")
                for _, parsed := range parsedSelectors {
                    if parsed.Matches(nsLabels) {
                        result.Insert(ns.Name)
                        break
                    }
                }
            }
        }
        return result
    }

    return matchSet(includedSelectors).List(), matchSet(excludedSelectors).List(), nil
}
```

### Precedence and Interaction

`BackupSpec.IncludedNamespaces` being empty is existing Velero shorthand for "all namespaces." A naive union — `BackupSpec.IncludedNamespaces ∪ resolvedIncludedByLabel` — breaks under that shorthand: an empty `IncludedNamespaces` would expand to "all," and "all" unioned with anything is still "all," silently defeating the entire point of `includedNamespacesByLabel` (the primary use case in this design is a schedule with *no* `includedNamespaces` set, selecting only labeled namespaces).

The baseline must therefore branch on whether an include-by-label selector is *configured*, not on whether it *matched anything*. These are different signals: a configured selector that currently matches zero namespaces (e.g. nobody has labeled a namespace yet) must still produce an empty baseline, not fall through to "all namespaces" — otherwise a policy author who expects "nothing yet" gets "everything" instead, which is the opposite of fail-safe. The caller must carry this as an explicit flag alongside the resolution call, not infer it from the length of `resolveNamespacesByLabel`'s return value:

```
labelIncludeActive = len(policy.IncludedNamespacesByLabel) > 0   # config presence, NOT len(resolvedIncludedByLabel)
resolvedIncludedByLabel, resolvedExcludedByLabel, err = resolveNamespacesByLabel(ctx, client,
    policy.IncludedNamespacesByLabel, policy.ExcludedNamespacesByLabel, policy.LabelSelectorLogic)

if labelIncludeActive:
    baseline = resolvedIncludedByLabel ∪ BackupSpec.IncludedNamespaces   # explicit names still additive when both are set
              # note: if resolvedIncludedByLabel is empty here (selector configured, zero matches),
              # baseline is empty too (unless BackupSpec.IncludedNamespaces is separately non-empty) — by design.
else:
    baseline = BackupSpec.IncludedNamespaces   # empty ⇒ all namespaces, unchanged existing behavior

effective = baseline
           − BackupSpec.ExcludedNamespaces
           − resolvedExcludedByLabel
```

`excludedNamespacesByLabel` is purely subtractive and applies regardless of `labelIncludeActive` — same role as `BackupSpec.ExcludedNamespaces` today, just resolved from labels instead of names. Because `resolveNamespacesByLabel` resolves `resolvedExcludedByLabel` independently of `resolvedIncludedByLabel` (no internal netting), an exclude-only policy (`labelIncludeActive == false`) still gets a correctly populated `resolvedExcludedByLabel` to subtract from the "all namespaces" baseline.

Worked examples from the [Use Cases](#use-cases) above:
- **Dynamic per-schedule targeting**: `includedNamespacesByLabel` set (`labelIncludeActive == true`), `BackupSpec.IncludedNamespaces` empty → baseline is `resolvedIncludedByLabel` only, not all namespaces. If no namespace currently carries the label, baseline is empty and the backup selects nothing — not everything.
- **Exclude sensitive namespaces by label**: only `excludedNamespacesByLabel` set (`labelIncludeActive == false`) → baseline falls through to "all namespaces" (today's default), then `resolvedExcludedByLabel` is subtracted.

`BackupSpec.LabelSelector` and `BackupSpec.OrLabelSelectors` are unaffected — they continue to select individual resources, not namespaces.

**Hard exclusion (`velero.io/exclude-from-backup=true`)**: this is already enforced today in `prepareBackupRequest` (`pkg/controller/backup_controller.go`), which lists namespaces carrying that label and appends them directly into `request.Spec.ExcludedNamespaces` *before* resource-policy processing runs. `resolveNamespacesByLabel` and the effective-set merge above must run after that step (not before), so the `− BackupSpec.ExcludedNamespaces` term already carries the hard-excluded namespaces and the standard set-subtraction removes them — no separate re-check of the label is needed inside `resolveNamespacesByLabel` itself. This is an ordering requirement on where the new resolution call is inserted in `prepareBackupRequest`, not new logic.

### Observability

`backup.status.includedNamespaces` does not exist on `BackupStatus` today. Adding it is out of scope for the initial implementation — it would require a new `BackupStatus` field, CRD schema/deepcopy regeneration, and its own compatibility review, none of which this design specifies. Instead, the initial implementation logs during `prepareBackupRequest` so operators can see which namespaces were actually selected: the *count* of resolved namespaces at info level (`len(resolvedIncludedByLabel)`, `len(resolvedExcludedByLabel)`), and the full resolved name list at debug level. A cluster with thousands of namespaces where a selector matches a large fraction of them would otherwise spam Velero's backup logs at info level on every run; count-at-info/list-at-debug avoids that while still making the resolved names available (`--log-level debug` at install, or per-backup via `backup logs`) without changing default log volume. Populating a status field is deferred as a follow-on (see [Open Issues](#open-issues)); if picked up later, it needs its own design pass covering the schema addition and back-compat impact.

### Limitations

`includedNamespacesByLabel` and `excludedNamespacesByLabel` do not interact with the old-style global filters (`IncludedResources`/`ExcludedResources`/`IncludeClusterResources` in `BackupSpec`).
If a backup references a ResourcePolicy ConfigMap with `includeExcludePolicy` that contains the new fields AND has old-style resource filters in `BackupSpec`, the backup fails validation with a clear error — consistent with the existing behavior of `includeExcludePolicy`.

**Interaction with `namespacedFilterPolicies`**: If a ResourcePolicy ConfigMap contains both `includedNamespacesByLabel`/`excludedNamespacesByLabel` (from this design) and `namespacedFilterPolicies` (from the [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) design), the namespace label selectors determine which namespaces are included in the backup, while `namespacedFilterPolicies` determines which resources within those namespaces are collected. The two mechanisms operate at different levels and are complementary. Concretely: the merged implementation checks `BackupSpec.IncludedNamespaces`/`ExcludedNamespaces` first, then `namespacedFilterPolicies[].namespaces` (glob-matched) against whatever namespace list survives; this design's resolved include/exclude-by-label set feeds into that same effective namespace list, so `namespacedFilterPolicies` transparently applies to namespaces admitted only via a label selector.

**Not usable for Restore**: `Policies.ValidateForRestore()` (`internal/resourcepolicies/resource_policies.go`) rejects any ResourcePolicy ConfigMap whose `includeExcludePolicy` is non-nil, regardless of which fields are set. A ConfigMap using `includedNamespacesByLabel`/`excludedNamespacesByLabel` for a backup therefore cannot be reused as-is for `RestoreSpec.ResourcePolicy`. This is pre-existing `includeExcludePolicy` behavior, unchanged by this design.

**Ignored in the global backup volume policies ConfigMap**: `GetGlobalResourcePolicies` applies only the `volumePolicies` section of the cluster-wide global ConfigMap (`--global-volume-policies-configmap` style flow); it logs a warning and ignores `includeExcludePolicy` — and therefore these new fields — if present there. `includedNamespacesByLabel`/`excludedNamespacesByLabel` must be set on a per-backup `BackupSpec.ResourcePolicy` ConfigMap, not the global one.

## Alternatives Considered

### Modify `BackupSpec.LabelSelector` to select namespaces

PR [#9223](https://github.com/vmware-tanzu/velero/pull/9223) proposed treating `LabelSelector`-matched namespaces as implicitly included.
This was a breaking change and made `LabelSelector` semantics ambiguous (resource filter vs namespace filter).
Closed without merge.

### New CRD field on `BackupSpec` (e.g., `IncludedNamespacesByLabel`)

Proposed in community meeting but rejected: the community preferred not to proliferate new fields on `BackupSpec` when ResourcePolicy already serves this purpose. This is consistent with the approach taken by the [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) design, which also avoids adding new CRD fields.

### New standalone ConfigMap type

Adds unnecessary indirection without benefit over extending `includeExcludePolicy` in the existing ResourcePolicy ConfigMap.

### Match `clusterScopedFilterPolicy`'s `map[string]string` / `[]map[string]string` selector format

The merged `ResourceFilter.LabelSelector` (`map[string]string`) and `OrLabelSelectors` (`[]map[string]string`) use simple equality maps rather than parsed selector strings. That format was considered here for shape consistency within the same ResourcePolicy ConfigMap. It was rejected: namespace targeting benefits from the full `k8s.io/apimachinery/pkg/labels` selector grammar (`!=`, `in`, `notin`, `!key`) that an equality-only map cannot express, and `includedNamespacesByLabel`/`excludedNamespacesByLabel` are meant to read like `kubectl get ns -l <selector>`, which users already know. The resulting inconsistency in YAML shape across sections of the same ConfigMap (map-based for resource filters, string-based here) is accepted as a deliberate tradeoff, not an oversight.

## Security Considerations

Label selectors evaluate against live cluster state at backup time.
Namespace labels can be changed by anyone with namespace write access, so a user could opt a namespace into or out of a backup schedule by relabeling.
Cluster operators should use RBAC to control who can label namespaces if backup inclusion is security-sensitive.

No new permissions are required by Velero itself — it already has `list` access on namespaces.

## Compatibility

This is a backwards-compatible additive change.
Existing ResourcePolicy ConfigMaps without the new fields behave identically.
Existing backups and schedules are unaffected unless they reference a ConfigMap with the new fields.

Maintain full backward compatibility — existing backups with no `includedNamespacesByLabel`/`excludedNamespacesByLabel` behave exactly as they do today.

## User Perspective

- **For users not using namespace label selector filters**: Zero changes. All existing backups and workflows continue to work identically. The new YAML fields are optional.
- **For users adopting namespace label selector filters**: Add `includedNamespacesByLabel` and/or `excludedNamespacesByLabel` to the `includeExcludePolicy` section of the ResourcePolicy ConfigMap, and reference it via `BackupSpec.ResourcePolicy` (or the existing `--resource-policies-configmap` flag). The backup will dynamically resolve which namespaces to include/exclude based on namespace labels at backup time.
- **For users already using ResourcePolicy for volume policies or include/exclude policies**: Add the new fields to the existing `includeExcludePolicy` section in the same ConfigMap. All sections coexist.
- **Validation errors**: Reported at backup start when the ResourcePolicy ConfigMap contains invalid label selector strings. Consistent with how other validation errors are reported today.

## Implementation

1. Add `IncludedNamespacesByLabel` / `ExcludedNamespacesByLabel` / `LabelSelectorLogic` fields to `IncludeExcludePolicy`.
2. Extend `Validate()` to parse and validate selector strings using `k8s.io/apimachinery/pkg/labels.Parse`, and to validate `LabelSelectorLogic` is `""`, `"OR"`, or `"AND"`.
3. Implement `resolveNamespacesByLabel` helper, taking `LabelSelectorLogic` to combine entries within each list via union (OR) or intersection (AND).
4. Call resolution in `prepareBackupRequest` and merge results into the effective namespace filter.
5. No new controller-level incompatibility check is needed. `prepareBackupRequest` in `pkg/controller/backup_controller.go` already rejects any non-nil `IncludeExcludePolicy` combined with old-style filters (`collections.UseOldResourceFilters(request.Spec)`) regardless of which `IncludeExcludePolicy` fields are populated. Since the new fields live on the existing `IncludeExcludePolicy` struct, this check covers them automatically.
6. Log the count of resolved namespaces at info level, and the full resolved name list at debug level, in `prepareBackupRequest`.
7. Add unit tests for selector parsing (including the empty-string rejection), `LabelSelectorLogic` validation and OR/AND resolution behavior, independent resolution of `resolvedIncludedByLabel`/`resolvedExcludedByLabel` (including a configured include selector that matches zero namespaces, and an exclude-only policy), and precedence rules (`labelIncludeActive` baseline branch and hard-exclusion ordering).
8. Add E2E test: schedule with no `includedNamespaces`, label selector in resource policy, verify only labeled namespaces are backed up.

## Open Issues

- **Status field**: populating `backup.status.includedNamespaces` is deferred as a follow-on; it requires its own design covering the `BackupStatus` schema addition, deepcopy/CRD regeneration, and compatibility impact.
