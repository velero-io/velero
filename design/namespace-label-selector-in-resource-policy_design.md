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

The existing `includeExcludePolicy` already holds reusable include/exclude resource filters.
Adding namespace label selectors here is consistent with its purpose and avoids spec sprawl.

## Goals

- Allow users to specify Kubernetes label selectors in `includeExcludePolicy` to dynamically include or exclude namespaces in a backup.

## Non-Goals

- Changing the behavior of `BackupSpec.LabelSelector` or `BackupSpec.OrLabelSelectors` (those continue to filter individual resources, not namespaces).
- Selecting cluster-scoped resources by label (a separate concern; see [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) for cluster-scoped resource filtering).
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

## High-Level Design

Two new fields, `includedNamespacesByLabel` and `excludedNamespacesByLabel`, are added to `IncludeExcludePolicy` in the ResourcePolicy ConfigMap.
Each field is a list of Kubernetes label selector strings (same syntax as `kubectl get ns -l`).

At backup time, after existing namespace filters are resolved, Velero evaluates each selector against the live namespace list.
The union of namespaces matched by all `includedNamespacesByLabel` selectors is added to the effective included namespace set.
Namespaces matched by any `excludedNamespacesByLabel` selector are removed from that set.
The final set is stored in `backup.status.includedNamespaces` so users can observe which namespaces were actually selected.

This design coexists with the existing `includeExcludePolicy` fields (`includedClusterScopedResources`, `excludedClusterScopedResources`, `includedNamespaceScopedResources`, `excludedNamespaceScopedResources`) and is independent of the `namespacedFilterPolicies` and `clusterScopedFilterPolicy` sections described in the [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) design.

## Detailed Design

### Data Structure

`IncludeExcludePolicy` in `internal/resourcepolicies/resource_policies.go` gains two new fields:

```go
type IncludeExcludePolicy struct {
    IncludedClusterScopedResources   []string `yaml:"includedClusterScopedResources"`
    ExcludedClusterScopedResources   []string `yaml:"excludedClusterScopedResources"`
    IncludedNamespaceScopedResources []string `yaml:"includedNamespaceScopedResources"`
    ExcludedNamespaceScopedResources []string `yaml:"excludedNamespaceScopedResources"`
    // New fields
    IncludedNamespacesByLabel []string `yaml:"includedNamespacesByLabel"`
    ExcludedNamespacesByLabel []string `yaml:"excludedNamespacesByLabel"`
}
```

Each entry in `includedNamespacesByLabel` / `excludedNamespacesByLabel` is a label selector string parseable by `k8s.io/apimachinery/pkg/labels.Parse`.
Multiple entries within the same list are combined with OR (union): a namespace matching any selector in the list is included/excluded.
Within a single selector string, comma-separated requirements are AND.

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
        if _, err := labels.Parse(s); err != nil {
            return fmt.Errorf("invalid label selector %q: %w", s, err)
        }
    }
    return nil
}
```

Validation runs at backup admission time via `prepareBackupRequest`.

### Namespace Resolution

A new helper `resolveNamespacesByLabel` is called in `prepareBackupRequest` (or `kubernetesBackupper`) after the existing namespace filter is constructed:

```go
// resolveNamespacesByLabel lists all cluster namespaces and returns those
// matching any selector in includedSelectors, minus those matching any selector
// in excludedSelectors.
func resolveNamespacesByLabel(
    ctx context.Context,
    client crclient.Client,
    includedSelectors []string,
    excludedSelectors []string,
) ([]string, error) {
    nsList := &corev1.NamespaceList{}
    if err := client.List(ctx, nsList); err != nil {
        return nil, errors.Wrap(err, "listing namespaces")
    }

    excluded := sets.NewString()
    for _, sel := range excludedSelectors {
        parsed, _ := labels.Parse(sel) // already validated
        for _, ns := range nsList.Items {
            if parsed.Matches(labels.Set(ns.Labels)) {
                excluded.Insert(ns.Name)
            }
        }
    }

    included := sets.NewString()
    for _, sel := range includedSelectors {
        parsed, _ := labels.Parse(sel)
        for _, ns := range nsList.Items {
            if parsed.Matches(labels.Set(ns.Labels)) && !excluded.Has(ns.Name) {
                included.Insert(ns.Name)
            }
        }
    }

    return included.List(), nil
}
```

### Precedence and Interaction

Final effective namespace set:

```
effective = (BackupSpec.IncludedNamespaces
             ∪ resolvedIncludedByLabel)
           − BackupSpec.ExcludedNamespaces
           − resolvedExcludedByLabel
```

Where `resolvedExcludedByLabel` excludes take precedence over both `BackupSpec.IncludedNamespaces` and `resolvedIncludedByLabel`.
This ensures an operator can always exclude sensitive namespaces regardless of what the `BackupSpec` says.

The `velero.io/exclude-from-backup=true` label always takes precedence over all filters, regardless of whether the namespace matches global or label-resolved filters.

`BackupSpec.LabelSelector` and `BackupSpec.OrLabelSelectors` are unaffected — they continue to select individual resources, not namespaces.

### Observability

The resolved namespace list from label selectors is merged into `backup.status.includedNamespaces` so users can see which namespaces were actually backed up.

### Limitations

`includedNamespacesByLabel` and `excludedNamespacesByLabel` do not interact with the old-style global filters (`IncludedResources`/`ExcludedResources`/`IncludeClusterResources` in `BackupSpec`).
If a backup references a ResourcePolicy ConfigMap with `includeExcludePolicy` that contains the new fields AND has old-style resource filters in `BackupSpec`, the backup fails validation with a clear error — consistent with the existing behavior of `includeExcludePolicy`.

**Interaction with `namespacedFilterPolicies`**: If a ResourcePolicy ConfigMap contains both `includedNamespacesByLabel`/`excludedNamespacesByLabel` (from this design) and `namespacedFilterPolicies` (from the [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) design), the namespace label selectors determine which namespaces are included in the backup, while `namespacedFilterPolicies` determines which resources within those namespaces are collected. The two mechanisms operate at different levels and are complementary.

## Alternatives Considered

### Modify `BackupSpec.LabelSelector` to select namespaces

PR [#9223](https://github.com/vmware-tanzu/velero/pull/9223) proposed treating `LabelSelector`-matched namespaces as implicitly included.
This was a breaking change and made `LabelSelector` semantics ambiguous (resource filter vs namespace filter).
Closed without merge.

### New CRD field on `BackupSpec` (e.g., `IncludedNamespacesByLabel`)

Proposed in community meeting but rejected: the community preferred not to proliferate new fields on `BackupSpec` when ResourcePolicy already serves this purpose. This is consistent with the approach taken by the [Fine Grained Backup Filters](backup-filter-enhancement/fine-grained-backup-filters-design.md) design, which also avoids adding new CRD fields.

### New standalone ConfigMap type

Adds unnecessary indirection without benefit over extending `includeExcludePolicy` in the existing ResourcePolicy ConfigMap.

## Security Considerations

Label selectors evaluate against live cluster state at backup time.
Namespace labels can be changed by anyone with namespace write access, so a user could opt a namespace into or out of a backup schedule by relabeling.
Cluster operators should use RBAC to control who can label namespaces if backup inclusion is security-sensitive.

No new permissions are required by Velero itself — it already has `list` access on namespaces.

## Compatibility

This is a backwards-compatible additive change.
Existing ResourcePolicy ConfigMaps without the new fields behave identically.
Existing backups and schedules are unaffected unless they reference a ConfigMap with the new fields.

`backup.status.includedNamespaces` may be populated for the first time in cases where it was previously empty; consumers of this field should handle a non-empty list.

Maintain full backward compatibility — existing backups with no `includedNamespacesByLabel`/`excludedNamespacesByLabel` behave exactly as they do today.

## User Perspective

- **For users not using namespace label selector filters**: Zero changes. All existing backups and workflows continue to work identically. The new YAML fields are optional.
- **For users adopting namespace label selector filters**: Add `includedNamespacesByLabel` and/or `excludedNamespacesByLabel` to the `includeExcludePolicy` section of the ResourcePolicy ConfigMap, and reference it via `BackupSpec.ResourcePolicy` (or the existing `--resource-policies-configmap` flag). The backup will dynamically resolve which namespaces to include/exclude based on namespace labels at backup time.
- **For users already using ResourcePolicy for volume policies or include/exclude policies**: Add the new fields to the existing `includeExcludePolicy` section in the same ConfigMap. All sections coexist.
- **Validation errors**: Reported at backup start when the ResourcePolicy ConfigMap contains invalid label selector strings. Consistent with how other validation errors are reported today.

## Implementation

1. Add `IncludedNamespacesByLabel` / `ExcludedNamespacesByLabel` fields to `IncludeExcludePolicy`.
2. Extend `Validate()` to parse and validate selector strings using `k8s.io/apimachinery/pkg/labels.Parse`.
3. Implement `resolveNamespacesByLabel` helper.
4. Call resolution in `prepareBackupRequest` and merge results into the effective namespace filter.
5. Add validation in `backup_controller.go` to ensure `includedNamespacesByLabel`/`excludedNamespacesByLabel` are not used with old-style resource filters (`IncludedResources`/`ExcludedResources`/`IncludeClusterResources`), consistent with the existing check for `includeExcludePolicy`.
6. Populate `backup.status.includedNamespaces` with the resolved set.
7. Add unit tests for selector parsing, resolution logic, and precedence rules.
8. Add E2E test: schedule with no `includedNamespaces`, label selector in resource policy, verify only labeled namespaces are backed up.

## Open Issues

- **AND vs OR between list entries**: This design uses OR (union). Should we support AND by allowing nested lists? Deferring to a future enhancement.
- **Status field**: `backup.status.includedNamespaces` does not currently exist. If adding it is out of scope, we can log the resolved list instead and track the status field as a follow-on.
