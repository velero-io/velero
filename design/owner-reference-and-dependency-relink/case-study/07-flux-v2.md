# Case Study 07: Flux v2 (GitOps Continuous Delivery)

This case study analyzes **Flux v2**, the CNCF Graduated GitOps continuous delivery toolkit for Kubernetes. It evaluates how Velero's dynamic owner-reference restore engine coordinates multi-tiered GitOps controller pipelines, automated Helm chart lifecycle management, cross-resource ownership DAGs, and native annotation-based controller quiescing during disaster recovery and namespace migration.

---

## 1. Background & Problem Space

Flux v2 is composed of specialized Kubernetes controllers built with the `controller-runtime` library that collectively implement GitOps delivery pipelines:

- **Source Controller (`source.toolkit.fluxcd.io`):** Manages the acquisition and artifact packaging of external sources:
  - `GitRepository`: Clones and packages Git repositories.
  - `HelmRepository` / `OCIRepository`: Polls and indexes Helm charts or OCI registries.
  - `Bucket`: Pulls artifacts from S3-compatible object storage.
  - `HelmChart`: Ephemeral chart artifact definitions. Crucially, when managed by a `HelmRelease`, the `HelmChart` is generated dynamically by the `helm-controller` and owned via `metadata.ownerReferences`.
- **Kustomize Controller (`kustomize.toolkit.fluxcd.io`):**
  - `Kustomization`: Represents a declarative pipeline that fetches artifacts produced by a source (e.g. `GitRepository`), runs Kustomize overlays, applies manifests to the target cluster, and tracks resource inventories.
- **Helm Controller (`helm.toolkit.fluxcd.io`):**
  - `HelmRelease`: Declaratively manages the release lifecycle of a Helm chart. It reconciles chart values, initiates release upgrades, and owns child `HelmChart` resources.
- **Notification & Image Automation Controllers (`notification.toolkit.fluxcd.io`, `image.toolkit.fluxcd.io`):**
  - Handle webhook triggers (`Receiver`), alerting (`Alert`, `Provider`), and automated container image updates (`ImageRepository`, `ImagePolicy`, `ImageUpdateAutomation`).

Unlike systems that lack native operational silence mechanisms, Flux v2 provides **first-class annotation-based pausing**. This makes Flux v2 a textbook demonstration of Velero's automated `quiesceOnRestore` lifecycle.

---

## 2. Resource Ownership Hierarchy

Flux v2 workloads present two distinct ownership graphs: the **Helm Controller Chart Lifecycle DAG** and the **Multi-Tenant Kustomization DAG**.

### 2.1 The Helm Controller Chart Lifecycle DAG (Multi-Tier Ownership)

When a `HelmRelease` specifies inline chart configurations (`spec.chart.spec`), the `helm-controller` automatically provisions and owns a corresponding `HelmChart` in the source namespace:

```text
FLUX V2 HELM RELEASE & CHART GENERATION DAG
================================================================================

  [ HelmRepository / GitRepository (source.toolkit.fluxcd.io) ] <── Source Root
                     ▲
                     │ (spec.chart.spec.sourceRef by name)
                     │
  [ HelmRelease (helm.toolkit.fluxcd.io) ]  <── Tier 1 (Declarative Release Intent)
        │
        └── (metadata.ownerReferences) ──► [ HelmChart (source.toolkit.fluxcd.io) ]  <── Tier 2 (Generated Chart CRD)
                                                 │
                                                 └── (source-controller packages artifact)
                                                 │
                                                 ▼
                                           [ Deployed Application Workloads ]  <── Tier 3 (Managed Release)
                                           (Deployment, Service, ConfigMap, Secret)
```

### 2.2 The Multi-Tenant Kustomize DAG

In enterprise multi-tenancy or platform engineering architectures, platform teams configure a root `Kustomization` that generates and supervises tenant `Kustomization` instances:

```text
FLUX V2 MULTI-TIER KUSTOMIZE DAG
================================================================================

  [ GitRepository (source.toolkit.fluxcd.io) ]  <── Source Root
        ▲
        │ (spec.sourceRef by name)
        │
  [ Root Kustomization (flux-system) ]  <── Tier 1 (Cluster Platform Root)
        │
        ├── (ownerRef / inventory) ──► [ Tenant A Kustomization ]  <── Tier 2 (App Fleet)
        │                                    │
        │                                    └── (inventory) ──► [ App A Workloads ]  <── Tier 3
        │
        └── (ownerRef / inventory) ──► [ Tenant B Kustomization ]  <── Tier 2 (Infra Fleet)
                                             │
                                             └── (inventory) ──► [ Infra CRDs & Operators ] <── Tier 3
```

### Reference Characteristics
1. **Dynamic Child Generation (`HelmRelease` → `HelmChart`):**
   The `helm-controller` injects `metadata.ownerReferences` on the `HelmChart` with:
   - `controller: true`
   - `blockOwnerDeletion: true`
   - Target UID pointing to the `HelmRelease`.
2. **Name-Based Source References (`spec.sourceRef`):**
   `Kustomization` and `HelmRelease` reference their source roots (`GitRepository`, `HelmRepository`) by resource name, type, and namespace. These are logical name references, not foreign UID pointers.
3. **Cascading Teardown:**
   When an administrator deletes a `HelmRelease`, Kubernetes cascading deletion cleans up the underlying `HelmChart` and triggers artifact pruning in `source-controller`.

---

## 3. Catastrophic Failure Modes Without Remapping

If a Flux v2 environment is restored with legacy Velero (all `ownerReferences` stripped without remapping, and controllers unquiesced), several critical failures occur:

1. **`HelmChart` Orphanage and Chart Generation Collisions:**
   - In Phase 1A, Velero creates the `HelmRelease` with a new cluster UID and strips the ownerReference from the restored `HelmChart`.
   - Without Phase 1B remapping, the `HelmChart` has no controlling owner.
   - The active `helm-controller` inspects the cluster, fails to find a `HelmChart` matching the new `HelmRelease` UID, and attempts to create a duplicate `HelmChart` with the exact same name.
   - The creation fails with `HTTP 409 Conflict: helmcharts.source.toolkit.fluxcd.io already exists`, stalling the Helm release reconciliation permanently until manual intervention.
2. **Permanent Storage & Artifact Leakage:**
   - Because the restored `HelmChart` is detached from the `HelmRelease`, deleting the `HelmRelease` later leaves the orphaned `HelmChart` running indefinitely in etcd.
   - `source-controller` continues to fetch, package, and store multi-megabyte tarballs for the orphaned chart on local volume storage, leading to disk exhaustion.
3. **Premature Reconciliation & Cascading Restore Failures:**
   - If Flux controllers run unquiesced during Phase 1A while resources are still being imported, `kustomize-controller` and `helm-controller` immediately attempt to reconcile manifests against incomplete cluster states.
   - Missing secrets, missing CustomResourceDefinitions, or unready storage cause releases to fail with `CreateFailed` or `UpgradeFailed`.
   - In worst-case scenarios, active Flux reconciliation loops clash with Velero's object creation, triggering API server write conflicts (`HTTP 409 Conflict`) or overwriting restored annotations.

---

## 4. How the Velero Engine Handles Flux v2

Velero's owner-reference restore engine (`design.md`) natively accommodates Flux v2 through the synergy of **annotation-based quiescing** and **depth-agnostic Phase 1B remapping**.

### A. Native Annotation-Based Quiescing (`quiesceOnRestore`)

Flux v2 controllers natively support annotation-based reconciliation suspension via the official toolkit annotation:
```
<controller>.toolkit.fluxcd.io/reconcile: disabled
```

Specifically:
- `kustomize.toolkit.fluxcd.io/reconcile: "disabled"` halts `kustomize-controller`.
- `helm.toolkit.fluxcd.io/reconcile: "disabled"` halts `helm-controller`.
- `source.toolkit.fluxcd.io/reconcile: "disabled"` halts `source-controller` artifact pulling.

When configured with `quiesceOnRestore`, Velero executes the following lifecycle:

```text
PHASE 1A: CREATION WITH QUIESCE ANNOTATION
================================================================================
  1. Velero injects:
       kustomize.toolkit.fluxcd.io/reconcile: "disabled"
       velero.io/quiesced-by-restore: "<restore-name>"
  2. client.Create(kustomization) executes.
  3. Flux controller reads object from API server:
     LOG: "reconciliation is disabled via annotation"
     ACTION: Controller remains completely idle. ZERO race conditions.


PHASE 1B (PASS 1): OWNERREFERENCE REMAPPING
================================================================================
  1. Velero looks up new UID of live HelmRelease in uidMap.
  2. Velero patches HelmChart.metadata.ownerReferences with live HelmRelease UID.
  3. Ownership hierarchy is 100% restored.


UNQUIESCING (INDEPENDENT GRAPH-FREE EVALUATION)
================================================================================
  1. All dependent patches for the tree have succeeded.
  2. Velero sends JSON merge patch removing the pause annotation:
       {"metadata": {"annotations": {"kustomize.toolkit.fluxcd.io/reconcile": null}}}
  3. Flux controller detects unpause and reconciles against a fully restored, coherent cluster!
```

### B. Preservation of User Intent (The "Already Paused" Invariant)

In enterprise GitOps operations, platform engineers frequently suspend specific applications using `flux suspend kustomization <name>` or by manually setting `reconcile: disabled` before disaster strikes.

Velero enforces a strict safety invariant:
> *If an object already had `reconcile: disabled` in the backup snapshot, Velero leaves it untouched and NEVER unpauses it.*

- **Mechanism:** During Phase 1A, Velero inspects `obj.GetAnnotations()`.
- If `kustomize.toolkit.fluxcd.io/reconcile: disabled` already exists, Velero:
  1. Does **not** inject the `velero.io/quiesced-by-restore` tracking label.
  2. Does **not** register the object in `QuiescedObjects`.
  3. Skips unpausing during Phase 1B / Finalizer phases.
- The resource remains intentionally suspended after restore, honoring operator intent.

### C. GitOps Drift & Self-Healing Safety

Annotation pause (`kustomize.toolkit.fluxcd.io/reconcile: disabled`, and CAPI `cluster.x-k8s.io/paused` when Flux applies `Cluster`) still avoids `.spec` schema/`generation` problems. It is **not** ignored by Flux by default. Drift detection and SSA reconcile compare live vs git, including annotations. If git does not contain the pause key, Flux can strip it during Pass 1.

When Flux manages CAPI `Cluster`, configure `spec.driftDetection.ignore` on that Kustomization (JSON Pointer encodes `/` as `~1`):

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: capi-clusters
  namespace: flux-system
spec:
  interval: 10m
  path: ./clusters/prod
  prune: true
  sourceRef:
    kind: GitRepository
    name: fleet
  driftDetection:
    mode: enabled
    ignore:
      - target:
          group: cluster.x-k8s.io
          kind: Cluster
        paths:
          - /metadata/annotations/cluster.x-k8s.io~1paused
          - /metadata/annotations/velero.io~1quiesced-key
          - /metadata/labels/velero.io~1quiesced-by-restore
```

Alternatively `flux suspend kustomization capi-clusters -n flux-system` for the restore window, then resume after `Completed`. If this Kustomization also quiesces Flux objects, ignore the corresponding `*.toolkit.fluxcd.io/reconcile` keys the same way. Canonical write-up: [design.md Edge Cases](../design.md).

Unpausing remains a merge-patch `null` delete of the annotation key (no OpenAPI 422 on `.spec`).

---

## 5. Flux v2 ConfigMap Definition

To restore Flux v2 resources with dynamic owner-reference remapping and automated controller quiescing, deploy the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-flux
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: All Flux v2 API groups eligible for ownerReference remapping
  inScope: |
    - group: kustomize.toolkit.fluxcd.io
    - group: helm.toolkit.fluxcd.io
    - group: source.toolkit.fluxcd.io
    - group: notification.toolkit.fluxcd.io
    - group: image.toolkit.fluxcd.io

  # 2. specRefPaths: Empty (Flux v2 references sources by name/namespace, not UID)
  specRefPaths: ""

  # 3. quiesceOnRestore: Native Flux pause annotations injected during Phase 1A create
  quiesceOnRestore: |
    - group: kustomize.toolkit.fluxcd.io
      kind: Kustomization
      annotationKey: kustomize.toolkit.fluxcd.io/reconcile
      annotationValue: "disabled"
    - group: helm.toolkit.fluxcd.io
      kind: HelmRelease
      annotationKey: helm.toolkit.fluxcd.io/reconcile
      annotationValue: "disabled"
    - group: source.toolkit.fluxcd.io
      kind: GitRepository
      annotationKey: source.toolkit.fluxcd.io/reconcile
      annotationValue: "disabled"
    - group: source.toolkit.fluxcd.io
      kind: HelmRepository
      annotationKey: source.toolkit.fluxcd.io/reconcile
      annotationValue: "disabled"
    - group: source.toolkit.fluxcd.io
      kind: OCIRepository
      annotationKey: source.toolkit.fluxcd.io/reconcile
      annotationValue: "disabled"
```

### Field Breakdown
- **`inScope`:**
  - `kustomize.toolkit.fluxcd.io`: Remaps parent-child `Kustomization` hierarchies.
  - `helm.toolkit.fluxcd.io`: Remaps `HelmRelease` controlling references.
  - `source.toolkit.fluxcd.io`: Remaps child `HelmChart` resources back to their parent `HelmRelease`.
  - `notification.toolkit.fluxcd.io` & `image.toolkit.fluxcd.io`: Supports notification and image automation DAGs.
- **`specRefPaths`:** Left empty because Flux v2 uses typed name/namespace pointers (`spec.sourceRef`) rather than raw Kubernetes object UIDs.
- **`quiesceOnRestore`:** Injects `reconcile: disabled` on all root controllers during Phase 1A, preventing reconciler execution while Velero reconstitutes the cluster.

---

## 6. Lifecycle Transition & Protection Summary

| Phase | Resource State | Controller Behavior | Safety Guarantee |
| :--- | :--- | :--- | :--- |
| **Phase 1A (Create)** | Injected with `reconcile: disabled` + tracking label | Controller skips reconciliation entirely (`disabled via annotation`) | Zero race conditions; no premature chart generation; no API server write collisions. |
| **Phase 1B (Remap)** | `HelmChart.metadata.ownerReferences` patched with live `HelmRelease` UID | Controller remains paused | $O(1)$ depth-agnostic remapping reconnects ownership DAG before execution. |
| **Phase 1B (Unquiesce)**| Annotation removed via merge patch `{"reconcile": null}` | Controller detects removal and initiates reconciliation | Reconciles against a 100% complete, fully restored cluster state. |
| **Post-Restore Deletion** | Clean cascading deletion | Kubernetes GC cascades deletion of `HelmRelease` down to `HelmChart` | Zero storage leaks; zero orphan artifacts in `source-controller`. |
