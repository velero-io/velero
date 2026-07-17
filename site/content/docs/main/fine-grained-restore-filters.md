---
title: "Fine-Grained Restore Filters"
layout: docs
---

This guide explains how to use Velero's **fine-grained restore filters**: per-namespace, per-kind rules with independent label selectors and resource name patterns. Configuration lives in a **ResourcePolicy ConfigMap**, using the exact same format introduced for fine-grained backup filters.

For architecture and pipeline details, see the [design document](https://github.com/velero-io/velero/blob/main/design/restore-filter-enhancement/fine-grained-restore-filters-design.md).

---

## Introduction

Velero's traditional restore filters apply the same namespace list, resource types, and label selector to every namespace being restored. Common scenarios need more control:

- **Selective restore from a full backup** — restore only specific application components from a namespace, leaving out monitoring or logging resources that were also backed up.
- **Cross-environment migration** — restore StatefulSets and PVCs in a database namespace, but only Deployments and Services in a frontend namespace.
- **Filter by resource name** — restore `app-config` and `app-secret` without restoring `monitoring-config` from the same namespace.
- **Restore-time override** — apply different label selectors during restore than were used during backup to handle environment differences.

Fine-grained filters add two optional sections to the ResourcePolicy ConfigMap:

| Section | Scope | Behavior |
|---------|-------|----------|
| `namespacedFilterPolicies` | Namespaces you match (exact name or glob) | **Exclusive allowlist** — only resource kinds listed in `resourceFilters` (or covered by a catch-all) are restored for those namespaces, provided they pass global filters. |
| `clusterScopedFilterPolicy` | Cluster-scoped resources globally | **Refinement overlay** — listed kinds get per-kind label and name rules; unlisted cluster-scoped kinds still use global RestoreSpec filters. |

**Backward compatible:** if you omit the `ResourcePolicy` reference, restores behave exactly as they do today.

---

## Prerequisites and wiring

### What you need

- A ResourcePolicy ConfigMap in the Velero namespace (`velero` by default).
- Permission to create Restores that reference the ConfigMap.

### End-to-end pattern

Every example below follows the same three steps:

1. **Create or update** a ConfigMap with `data.policy` containing `version: v1` and your filter rules.
2. **Create a Restore** that includes the target namespaces and references the ConfigMap.
3. **Verify** with `velero restore describe` and inspect the restored resources.

### Minimal skeleton

Use this once; later examples show only the `policy:` body.

**ResourcePolicy ConfigMap:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-restore-filter-policy
  namespace: velero
data:
  policy: |
    version: v1
    namespacedFilterPolicies:
      - namespaces:
          - my-namespace
        resourceFilters:
          - kinds: [ConfigMap]
            labelSelector:
              app: my-app
```

**Restore:**

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: my-restore
  namespace: velero
spec:
  backupName: my-backup
  includedNamespaces:
    - my-namespace
  resourcePolicy:
    kind: configmap
    name: my-restore-filter-policy
```

**CLI equivalent:**

```bash
velero restore create my-restore \
  --from-backup my-backup \
  --include-namespaces my-namespace \
  --resource-policies-configmap my-restore-filter-policy
```

**Verify:**

```bash
velero restore describe my-restore
```

### Important: Interaction with Global Filters

The restore pipeline evaluates **global resource filters first**:
- `RestoreSpec.IncludedResources` and `RestoreSpec.ExcludedResources` act as a global gate.
- A resource kind **must** pass the global gate before per-namespace filters are evaluated.
- **A namespace policy cannot re-include a globally excluded kind.** If you globally exclude `secrets`, listing `Secret` in a namespace policy will have no effect.

---

## Examples

Each example includes: **goal**, **policy YAML**, **restore notes**, and **expected outcome**.

---

### Example 0 — Baseline (no new filters)

**Goal:** Confirm that namespaces without a `namespacedFilterPolicies` entry still use global RestoreSpec filters.

**Policy:** Omit `namespacedFilterPolicies` and `clusterScopedFilterPolicy` entirely.

**Restore:**

```yaml
spec:
  includedNamespaces:
    - ns-a
    - ns-b
  # No resourcePolicy — global filters only
```

**Expected outcome:** All resources in included namespaces follow `includedNamespaces`, `labelSelector`, `includedResources`, and related global fields — same as before this feature.

---

### Example 1 — Per-namespace kinds and labels

**Goal:** In `ns-a`, restore only ConfigMaps, Secrets, Deployments, and Pods with `app=my-app`. In `ns-b`, use global filters (no policy entry for that namespace).

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
    resourceFilters:
      - kinds: [ConfigMap, Secret, Deployment, Pod]
        labelSelector:
          app: my-app
```

**Restore:**

```yaml
spec:
  includedNamespaces:
    - ns-a
    - ns-b
  resourcePolicy:
    kind: configmap
    name: per-namespace-resource-filter-policy
```

**Expected outcome:**

- **ns-a:** Only listed kinds with label `app=my-app` (e.g. `app-config`, `app-secret`, `app-deployment`). Resources like `monitoring-config` (different labels) are excluded.
- **ns-b:** Everything allowed by global filters (no namespace policy match).

---

### Example 2 — Exact resource names

**Goal:** Restore only two ConfigMaps by exact name, optionally requiring a label.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - target-namespace
    resourceFilters:
      - kinds: [ConfigMap]
        names: [vm-1, vm-2]
        labelSelector:
          resource-type: VirtualMachine
```

**Expected outcome:** Only `vm-1` and `vm-2` ConfigMaps with `resource-type=VirtualMachine` are restored. `vm-3` and other ConfigMaps are skipped.

---

### Example 3 — Glob name patterns with exclusions

**Goal:** Restore `app-*` ConfigMaps and Secrets in `production`, but exclude temporary and debug names.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - production
    resourceFilters:
      - kinds: [ConfigMap, Secret]
        names: ["app-*"]
        excludedNames: ["*-tmp", "*-debug"]
```

**Expected outcome:**

- **Included:** `app-config`, `app-cache-config`, `app-secret`
- **Excluded:** `app-tmp-config`, `app-debug-config`, `monitoring-tmp-secret`

`excludedNames` takes precedence over `names` when both match.

---

### Example 4 — Per-kind label selectors

**Goal:** Apply different label rules to different resource types in the same namespace.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - target-namespace
    resourceFilters:
      - kinds: [ConfigMap]
        orLabelSelectors:
          - app: production-workload-1
            component: vm-group
          - app: production-workload-2
            component: vm-service
```

**Expected outcome:** ConfigMaps matching either label combination are restored; other ConfigMaps in the namespace are not.

---

### Example 5 — OR label selectors across kinds

**Goal:** Restore ConfigMaps, Secrets, or Deployments that match any of several label conditions.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
    resourceFilters:
      - kinds: [ConfigMap, Secret]
        orLabelSelectors:
          - app: my-app
          - app: monitoring
      - kinds: [Deployment]
        orLabelSelectors:
          - app: my-app
          - app: monitoring
          - component: backend
```

**Expected outcome:** Resources included if they match **any** map in `orLabelSelectors` for their kind.

---

### Example 6 — Multiple criteria on one kind

**Goal:** Combine exact names with OR label selectors for a single kind.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - target-namespace
    resourceFilters:
      - kinds: [ConfigMap]
        names: [vm-1, vm-2]
        orLabelSelectors:
          - resource-type: VirtualMachine
          - component: vm-group
          - component: vm-service
```

**Expected outcome:** Only `vm-1` and `vm-2` that also satisfy one of the label OR branches.

---

### Example 7 — One policy entry, multiple namespaces

**Goal:** Apply the same rules to `ns-a`, `ns-b`, and `production` in a single policy block.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
      - ns-b
      - production
    resourceFilters:
      - kinds: [ConfigMap]
      - kinds: [Deployment]
        labelSelector:
          tier: web
```

**Expected outcome:**

- All ConfigMaps in those namespaces (no label filter on that entry).
- Deployments with `tier=web` only.

---

### Example 8 — Namespace glob patterns and ordering

**Goal:** Different restore breadth for `team-frontend-prod`, `team-frontend-dev`, and `team-backend-test` using glob patterns.

**Note on Precedence:** Exact namespace matches always take precedence regardless of where they are listed. However, if multiple glob patterns could match a namespace, they are evaluated in the order they appear. Always list specific globs before broad globs.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  # Globs must be ordered specific-to-broad
  - namespaces:
      - "team-frontend-*"           # specific pattern match
    resourceFilters:
      - kinds: [Deployment, Service, ConfigMap]
  - namespaces:
      - "team-*"                    # broad pattern
    resourceFilters:
      - kinds: [Deployment, Service]

  # Exact matches always win, even if placed at the bottom
  - namespaces:
      - team-frontend-prod          # exact match
    resourceFilters:
      - kinds: [Deployment, Service, ConfigMap, Secret, PersistentVolumeClaim]
```

**Expected outcome:**

| Namespace | Matched policy | Kinds restored |
|-----------|----------------|-----------------|
| `team-frontend-prod` | `team-frontend-prod` (Exact match priority) | 5 kinds |
| `team-frontend-dev` | `team-frontend-*` (First matching glob) | 3 kinds |
| `team-backend-test` | `team-*` (First matching glob) | 2 kinds |

Velero uses **first-match** semantics: the first policy entry whose namespace pattern matches wins.

---

### Example 9 — Catch-all by label

**Goal:** Restore any resource kind that has a given label, without listing every kind. Kind-specific entries override the catch-all.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
    resourceFilters:
      - kinds: ["*"]                 # catch-all
        labelSelector:
          app: common-app
      - kinds: [ConfigMap, Secret]   # override for these kinds
        labelSelector:
          app: specialized-app
```

**Rules:**

- At most **one** catch-all per namespace policy entry.
- Catch-all entries **cannot** use `names` or `excludedNames`.
- Catch-all does **not** inherit `RestoreSpec.LabelSelector`.

**Expected outcome:** ConfigMaps and Secrets use `app=specialized-app`; all other kinds listed only via catch-all use `app=common-app`.

---

### Example 10 — Catch-all with per-kind name overrides

**Goal:** Pin critical Deployments and Secrets by exact name; restore everything else with a label convention.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
    resourceFilters:
      - kinds: [Deployment]
        names: [api-server, worker]
      - kinds: [Secret]
        names: [db-credentials, tls-cert]
      - kinds: ["*"]
        labelSelector:
          restore: "true"
```

**Expected outcome:**

- Deployments: only `api-server` and `worker`
- Secrets: only `db-credentials` and `tls-cert`
- Other kinds (ConfigMap, Service, …): resources with `restore=true` only

---

### Example 11 — Override-only catch-all (no label on catch-all)

**Goal:** Apply a strict name filter to one kind while restoring all other kinds without listing them or adding labels.

**Policy:**

```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
    resourceFilters:
      - kinds: [Secret]
        names: [app-secret]
      - kinds: ["*"]    # no labelSelector — all other kinds included
```

**Expected outcome:**

- Secrets: only `app-secret`
- Other kinds in `ns-a`: all instances restored (subject to global filters)

---

### Example 12 — Cluster-scoped refinement

**Goal:** Refine which cluster-scoped resources are restored by name and label, without replacing global cluster-scoped inclusion.

**Policy:**

```yaml
version: v1
clusterScopedFilterPolicy:
  resourceFilters:
    - kinds: [StorageClass]
      names: ["my-app-*"]
    - kinds: [ClusterRole, ClusterRoleBinding]
      labelSelector:
        app: my-app
```

**Restore (required):** You must still include cluster-scoped kinds on the Restore:

```yaml
spec:
  includeClusterResources: true
  resourcePolicy:
    kind: configmap
    name: cluster-scoped-filter-policy
```

**Expected outcome:**

- StorageClasses matching `my-app-*` only
- ClusterRoles and ClusterRoleBindings with `app=my-app` only
- Other cluster-scoped resources: restored according to global filters.

**Differences from namespace policies:**

- **Not** an allowlist — unlisted cluster-scoped kinds fall back to global filters.
- **No catch-all** — `kinds: []` or `kinds: ["*"]` is invalid and fails validation.

---

### Example 13 — Global `ExcludedResources` and namespace filters

**Goal:** Understand that global **exclusions** cannot be overridden per namespace.

**Restore:**
```yaml
spec:
  excludedResources:
    - secrets
```

**Policy:**
```yaml
version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-a
    resourceFilters:
      - kinds: [ConfigMap, Secret, Deployment]
        labelSelector:
          app: my-app
```

**Result:** No Secrets are restored — the namespace policy cannot re-include a globally excluded kind. Velero logs a warning at restore start if you list an excluded kind in `namespacedFilterPolicies`.

---

### Example 14 — Separate ConfigMaps for Backup and Restore

**Goal:** Understand why you cannot use a single ConfigMap for both backup and restore operations if it contains backup-specific policies.

**Policy:**

```yaml
version: v1
volumePolicies:
  - conditions:
      capacity: "0,10Gi"
    action:
      type: fs-backup
namespacedFilterPolicies:
  - namespaces:
      - production
    resourceFilters:
      - kinds: [ConfigMap, Secret]
        names: ["app-*"]
```

**Expected outcome:** The restore operation will **fail validation**. The Velero restore pipeline strictly rejects any ResourcePolicy ConfigMap containing `volumePolicies` or `includeExcludePolicy`. To avoid this, the restore-side ConfigMap should contain only the restore-supported sections (`namespacedFilterPolicies` and/or `clusterScopedFilterPolicy`).

---

### Example 15 — `velero.io/exclude-from-backup=true` always wins

**Goal:** Ensure explicitly excluded resources never appear in the restore.

If a resource was backed up (perhaps before the label was added, or manually modified in the archive) but has `velero.io/exclude-from-backup: "true"`, the restore pipeline honors it. Any item carrying this label is skipped regardless of whether it matches global or per-namespace restore filters.

---

## Concepts reference

### `resourceFilters` fields

| Field | Description |
|-------|-------------|
| `kinds` | Resource type names (e.g. `ConfigMap`, `deployments`). Empty or `["*"]` = catch-all (namespace policies only). |
| `labelSelector` | Equality labels (`key: value`), AND across keys. No `in`, `exists`, etc. — use `orLabelSelectors` for OR. |
| `orLabelSelectors` | List of label maps; match if **any** map matches (AND within each map). Mutually exclusive with `labelSelector`. |
| `names` | Exact names or glob patterns to include. |
| `excludedNames` | Patterns to exclude; wins over `names` when both match. |

### Glob pattern syntax

Name and namespace patterns use the same glob style as elsewhere in Velero (`gobwas/glob`):

- Supported: `*`, `?`, `[abc]`, `[a-z]`
- Not supported: `**`, regex, `|`, `()`, `!`, `{}`, `,`

Examples: `app-*`, `team-frontend-*`, `*-tmp`.

### Precedence cheat sheet

**Namespaces**

1. `RestoreSpec.ExcludedNamespaces` — excluded namespaces are never restored.
2. `namespacedFilterPolicies` — first matching pattern (exact match checked before globs in pattern order).
3. No match — use global RestoreSpec filters.

**Namespace-scoped resources (when a namespace policy matches)**

1. Global `RestoreSpec.IncludedResources` / `ExcludedResources` apply first.
2. Only kinds in `resourceFilters` (or catch-all) are allowlisted for restoration.
3. Per-kind `labelSelector` / `orLabelSelectors` replace global selectors.
4. Per-kind `names` / `excludedNames` filter by resource name.
5. Label `velero.io/exclude-from-backup=true` always excludes.
6. **Plugin Additional Items** bypass fine-grained filters to ensure dependencies (like PVs) are restored.

**Cluster-scoped resources**

1. Must be allowed by global cluster settings (`includeClusterResources`).
2. If `clusterScopedFilterPolicy` lists the kind, apply its label and name rules.
3. If not listed in `clusterScopedFilterPolicy`, use global RestoreSpec filters.
4. `velero.io/exclude-from-backup=true` always excludes.

### Catch-all summary

| Rule | Detail |
|------|--------|
| Syntax | `kinds: ["*"]` or `kinds: []` |
| Count | At most one catch-all per `namespacedFilterPolicies` entry |
| Names | `names` / `excludedNames` not allowed on catch-all |
| Override | Kind-specific entries take precedence over catch-all |
| Label inheritance | Does not use `RestoreSpec.LabelSelector` |
| Cluster-scoped | Catch-all **not** supported in `clusterScopedFilterPolicy` |

---

## Troubleshooting and validation

### Verify a restore

```bash
velero restore describe RESTORE_NAME
velero restore logs RESTORE_NAME
```

The output of `velero restore describe` will show the `Resource Policy` field if a ConfigMap was used.

### Common misconfigurations

| Symptom | Likely cause | Fix |
|---------|----------------|-----|
| Fewer resources than expected in `team-frontend-prod` | Broad namespace pattern listed before specific one | Reorder policies: most specific `namespaces` first |
| Namespace policy lists Secrets but none restored | `RestoreSpec.ExcludedResources` excludes `secrets` globally | Remove global exclusion or accept no Secrets |
| `ClusterRole` in namespace policy has no effect | Cluster-scoped kind in `namespacedFilterPolicies` | Move rule to `clusterScopedFilterPolicy`; check logs for warning |
| Catch-all does not use restore-wide label | By design | Set `labelSelector` on the catch-all entry |
| Cluster-scoped policy validation error on `kinds: ["*"]` | Catch-all not allowed for cluster policy | List each cluster-scoped kind explicitly |

### Velero logs

```bash
kubectl logs -n velero deployment/velero | grep -i "namespacedFilterPolicies\|clusterScopedFilterPolicy"
kubectl logs -n velero deployment/velero | grep "globally excluded by RestoreSpec.ExcludedResources"
```

### Validation errors (policy ConfigMap)

Velero validates the ResourcePolicy when a restore starts. Common errors:

| Error (summary) | Cause |
|-----------------|--------|
| `at least one namespace must be specified` | Empty `namespaces: []` |
| `at least one resourceFilter must be specified` | Empty `resourceFilters: []` |
| `names or excludedNames cannot be specified for catch-all filters` | Name patterns on catch-all entry |
| `only one catch-all resource filter is allowed` | Multiple catch-alls in one policy entry |
| `kind "X" appears in both resourceFilters[...]` | Same kind in two entries |
| `labelSelector and orLabelSelectors cannot co-exist` | Both set in one entry |
| `duplicate namespace pattern` | Same namespace string in two policy entries |
| `invalid glob pattern` | Bad characters in namespace or name pattern |
| `clusterScopedFilterPolicy... kinds must be specified (catch-all is not supported)` | Empty or `["*"]` kinds in cluster policy |

### Silent edge cases (no error)

- Namespace pattern matches no existing namespace in the backup — policy loaded but never applied.
- Kind listed but no instances in namespace — empty result, restore still succeeds.
- `excludedNames` narrows `names` — e.g. `names: ["app-*"]` + `excludedNames: ["app-config"]` excludes `app-config` only.

---

## Related links

- [Fine-grained restore filters design](https://github.com/velero-io/velero/blob/main/design/restore-filter-enhancement/fine-grained-restore-filters-design.md)
