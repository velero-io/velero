# Case Study 08: Argo CD (Declarative GitOps & The Quiesce Dilemma)

This case study analyzes **Argo CD**, the CNCF Graduated declarative, GitOps continuous delivery tool for Kubernetes. It evaluates how Velero's dynamic owner-reference restore engine coordinates multi-cluster `ApplicationSet` hierarchies, `Application` resource tracking models, the architectural dilemma surrounding controller quiescing without native annotations, and why spec-field mutations remain a permanent non-goal for Velero core.

---

## 1. Background & Problem Space

Argo CD automates the deployment of desired application states defined in Git repositories into Kubernetes clusters:

- **`ApplicationSet` (`argoproj.io`):** Automates the generation, multi-cluster distribution, and management of multiple `Application` resources using generators (Git directory, Git file, Cluster, List, Matrix, and PR generators).
- **`Application` (`argoproj.io`):** The core custom resource representing a deployed application instance, binding a Git repository source to a target Kubernetes cluster and namespace.
- **`AppProject` (`argoproj.io`):** A logical security perimeter providing RBAC, destination cluster/namespace allowlists, and source repository restrictions.
- **Managed Workloads (`apps`, `core`, `networking.k8s.io`, etc.):** The actual application manifests deployed by Argo CD into target namespaces.

### The Quiescing Dilemma in GitOps
Unlike Cluster API, Flux v2, and Crossplane—which support native annotation-based pausing (`cluster.x-k8s.io/paused`, `kustomize.toolkit.fluxcd.io/reconcile: disabled`, `crossplane.io/paused`)—**Argo CD currently has no native pause annotation**. Instead, Argo CD controls automated reconciliation via `.spec` fields:
```yaml
spec:
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

Because modifying `.spec` during restore triggers GitOps drift detection and immediate self-healing reversion loops, Argo CD serves as the primary case study for defining the boundaries of Velero's core quiesce engine versus external orchestration.

---

## 2. Resource Ownership Hierarchy

Argo CD architectures feature two prominent ownership DAGs: the **ApplicationSet Fleet DAG** and the **ResourceTracking DAG**.

### 2.1 The ApplicationSet Fleet DAG

When an `ApplicationSet` generates applications, the `applicationset-controller` attaches `metadata.ownerReferences` to each child `Application`:

```text
ARGO CD APPLICATIONSET FLEET OWNERSHIP DAG
================================================================================

  [ ApplicationSet (argoproj.io) ]  <── Tier 1 (Fleet Management Root)
        │
        ├── (metadata.ownerReferences) ──► [ Application (cluster-us-east) ]  <── Tier 2
        │                                        │
        │                                        └── (reconciles manifests from Git)
        │                                        │
        │                                        ▼
        │                                  [ App Workloads in us-east ]  <── Tier 3
        │
        └── (metadata.ownerReferences) ──► [ Application (cluster-eu-west) ]  <── Tier 2
                                                 │
                                                 └── (reconciles manifests from Git)
                                                 │
                                                 ▼
                                           [ App Workloads in eu-west ]  <── Tier 3
```

### 2.2 The ResourceTracking DAG (`ownerReference` Tracking Method)

Argo CD tracks which resources belong to an `Application` using one of three tracking modes (`application.resourceTrackingMethod` in `argocd-cm`):
1. `label` (legacy): `app.kubernetes.io/instance: <app-name>`
2. `annotation`: `argocd.argoproj.io/tracking-id: <app-name>:<group>/<kind>:<namespace>/<name>`
3. `annotation+ownerReference` or `ownerReference`: In addition to tracking metadata, Argo CD injects **`metadata.ownerReferences` directly onto all deployed child resources**:

```text
RESOURCE TRACKING VIA OWNERREFERENCES
================================================================================

  [ Application (argoproj.io) ]  <── Controlling Owner
        │
        ├── (metadata.ownerReferences) ──► [ Deployment (apps/v1) ]
        ├── (metadata.ownerReferences) ──► [ Service (core/v1) ]
        ├── (metadata.ownerReferences) ──► [ ConfigMap (core/v1) ]
        └── (metadata.ownerReferences) ──► [ Ingress (networking.k8s.io) ]
```

### Reference Characteristics
1. **`ApplicationSet` → `Application`:**
   - Standard Kubernetes `metadata.ownerReferences` with `controller: true` and `blockOwnerDeletion: true`.
   - Governed by `ApplicationSet.spec.syncPolicy.applicationsSync` (create, update, delete).
2. **`Application` → Deployed Workloads:**
   - When `ownerReference` tracking is enabled, deployed resources carry `ownerReferences` pointing to the `Application`'s UID.
   - If an application is deleted, Kubernetes garbage collection cascades deletion to all child workloads.

---

## 3. Catastrophic Failure Modes Without Remapping

Restoring Argo CD environments with legacy Velero (all `ownerReferences` stripped without remapping) results in severe operational failures:

1. **`ApplicationSet` Duplication and Management Lockout:**
   - In Phase 1A, Velero creates the `ApplicationSet` with a new UID and restores child `Application`s with stripped ownerReferences.
   - The active `applicationset-controller` evaluates its generators against the cluster. Because the restored `Application` resources have no valid ownerReference pointing to the new `ApplicationSet` UID, the controller treats them as unmanaged or missing.
   - Depending on configured policies, the controller either attempts to recreate duplicate applications (failing with `AlreadyExists` errors) or abandons them, leaving fleet synchronization permanently stalled.
2. **Catastrophic Resource Pruning (The "Wipeout" Disaster):**
   - If an organization uses `resourceTrackingMethod: ownerReference` and has enabled automated pruning (`spec.syncPolicy.automated.prune: true`):
   - When workloads (`Deployment`, `Service`, `StatefulSet`) are restored with stripped ownerReferences, Argo CD or the Kubernetes garbage collector considers these resources orphaned from their parent `Application`.
   - Argo CD's auto-prune controller immediately issues `DELETE` requests against the running workloads, **wiping out restored production workloads** while restore is still underway!
3. **The GitOps Self-Healing Duel (if `.spec` is Mutated):**
   - If a generic restore tool attempts to silence an Argo CD application by stripping `.spec.syncPolicy.automated` during restore, Argo CD compares the cluster object with Git.
   - Argo CD detects configuration drift (`OutOfSync`). Because automated self-heal is declared in Git, Argo CD immediately patches `.spec` back to the Git state, triggering reconciliation while Velero is still remapping UIDs.

---

## 4. How the Velero Engine Handles Argo CD

Velero's owner-reference restore engine (`design.md`) addresses Argo CD with a strict architectural separation: **dynamic metadata remapping inside Velero core**, and **controller quiescing boundaries guided by architectural safety principles**.

### A. Dynamic In-Memory Remapping (`inScope: argoproj.io`)

Velero includes `argoproj.io` in the remapping scope:
- **Phase 1A:** All `ApplicationSet`, `Application`, and workload resources are created cleanly.
- **Phase 1B (Pass 1):** Velero performs depth-agnostic $O(1)$ UID remapping:
  - Child `Application.metadata.ownerReferences` are patched with the live UID of the parent `ApplicationSet`.
  - If `resourceTrackingMethod: ownerReference` is used, deployed workloads have their `metadata.ownerReferences` patched with the live UID of the `Application`.
- **Result:** Kubernetes cascading ownership and Argo CD fleet tracking are fully preserved without manual intervention.

### B. Why `specFieldPath` is Permanently Excluded from Velero Core

A frequent question is:
> *"Why doesn't Velero add a `specFieldPath` configuration to mutate `spec.syncPolicy.automated` or `spec.paused` during restore?"*

As detailed in [`spec-field-quiesce-and-argocd-analysis.md`](../spec-field-quiesce-and-argocd-analysis.md), mutating `.spec` to achieve temporary operational quiescing is a **fundamental architectural anti-pattern**. Velero's core engine permanently excludes `specFieldPath` for five reasons:

```text
                  ┌──────────────────────────────────────────────┐
                  │              Kubernetes Object               │
                  │                                              │
                  │  metadata.annotations:                       │
                  │    cluster.x-k8s.io/paused: ""  ◄────────────┼─── RIGHT ENGINE: Tooling metadata,
                  │                                              │          uniform null deletion;
                  │                                              │          still needs ignoreDifferences
                  │                                              │          if Cluster is self-healed
                  │  spec:                                       │
                  │    syncPolicy.automated: {}     ◄────────────┼─── DANGEROUS: Desired state,
                  │                                              │          GitOps duel + 422 / generation
                  └──────────────────────────────────────────────┘          schema type ambiguity
```

1. **The GitOps Self-Healing Duel:** Mutating `.spec` causes immediate drift against Git (`OutOfSync`). If self-heal is active in Git, Argo CD immediately overwrites Velero's changes, destroying the pause during restore.
2. **Schema Heterogeneity & OpenAPI 422 Errors:** Annotations are uniformly `map[string]string`, safely unpaused via `{"<key>": null}`. In contrast, `.spec` pause fields vary across CRDs (boolean, enum, nested struct). Sending `null` to unpause frequently triggers `HTTP 422 Unprocessable Entity` from CRD OpenAPI validation.
3. **Destruction of User Intent:** Distinguishing between an application intentionally paused by an operator before backup versus an application temporarily paused by Velero becomes impossible, risking accidental unpausing of paused production clusters.
4. **Admission Webhook & CEL Failures:** Mutating `.spec` increments `metadata.generation`, tripping admission webhooks that validate field transitions.
5. **Separation of Concerns:** `.spec` declares desired application architecture. Silencing a controller during backup/restore is an operational lifecycle event, which belongs strictly in `metadata.annotations`.

### C. The `ResourceModifier` Boundary

Velero provides a generic, create-time transformation feature: `Restore.Spec.ResourceModifier`.
If administrators choose to use `ResourceModifier` to remove `spec.syncPolicy.automated` on create:

```text
Phase 1A: Object Creation
  [Backup Manifest] ──► [ResourceModifier Patches spec] ──► [client.Create()]
                                                                   │
Phase 1B: OwnerRef Remapping                                       ▼
  [Remap UIDs & Patch ownerRefs]                         Object is PAUSED
                                                                   │
Restore Finishes (Phase: Completed)                                ▼
  Velero exits. No revert mechanism exists! ───────────► Still PAUSED forever
                                                         (Requires external fix)
```

- **Stateless and One-Way:** `ResourceModifier` applies a JSON Patch before `client.Create()`. It has **no concept of post-restore execution or tracking**.
- **Velero Cannot Lift the Pause:** Velero has no mechanism to revert `ResourceModifier` patches after Phase 1B.
- **External Unpausing Responsibility:** Administrators using this pattern must lift the pause externally via post-restore orchestration:

#### Option 1: External Post-Restore Orchestration (Recommended for ResourceModifier)
A CI/CD pipeline or Kubernetes Job waits for restore completion and patches the `Application`:
```bash
# Wait for Velero restore to finish Phase 1B remapping:
kubectl wait --for=jsonpath='{.status.phase}'=Completed restore/my-cluster-restore --timeout=600s

# Re-enable automated sync via kubectl:
kubectl patch application -n argocd my-app --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}'

# Or re-enable via Argo CD CLI:
argocd app set my-app --auto-prune --self-heal
```

#### Option 2: GitOps Source-of-Truth Re-Sync (The "App-of-Apps" Pattern)
If the Argo CD `Application` is itself managed in Git via an `ApplicationSet` or root application:
1. Child applications are restored without automated sync.
2. Once Phase 1B finishes and the cluster is healthy, the administrator initiates a sync on the root Application from Git.
3. Argo CD reconciles against Git and restores `spec.syncPolicy.automated`.

### D. Upstream Community Advocacy

Rather than introducing fragile `specFieldPath` workarounds into Velero core, the Velero project actively advocates that upstream communities lacking pause annotations (specifically Argo CD) adopt a native annotation-based pausing standard:
```yaml
metadata:
  annotations:
    argocd.argoproj.io/sync-paused: "true"
    # or
    argocd.argoproj.io/reconcile: "disabled"
```

This mirrors the proven patterns in Cluster API (`cluster.x-k8s.io/paused`), Flux v2 (`kustomize.toolkit.fluxcd.io/reconcile: disabled`), and Crossplane (`crossplane.io/paused`). With an upstream pause annotation, Argo CD will seamlessly integrate into Velero's automated `quiesceOnRestore` pipeline without custom post-restore scripts.

### E. When Argo CD Manages CAPI `Cluster` (operational ignoreDifferences)

If Argo CD Applications sync CAPI `Cluster` with automated self-heal, Argo compares live vs git **including annotations**. Git usually omits `cluster.x-k8s.io/paused`, so self-heal can strip Velero's pause during Pass 1. Configure `ignoreDifferences` on that Application and set `RespectIgnoreDifferences=true` (without the sync option Argo still overwrites on sync). `/` in the annotation name is `~1` in JSON Pointer:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: capi-mgmt
  namespace: argocd
spec:
  destination:
    namespace: capi-workload
    server: https://kubernetes.default.svc
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - RespectIgnoreDifferences=true
  ignoreDifferences:
    - group: cluster.x-k8s.io
      kind: Cluster
      jsonPointers:
        - /metadata/annotations/cluster.x-k8s.io~1paused
        - /metadata/annotations/velero.io~1quiesced-key
        - /metadata/labels/velero.io~1quiesced-by-restore
```

Cluster-wide in `argocd-cm`:

```yaml
data:
  resource.customizations.ignoreDifferences.cluster.x-k8s.io_Cluster: |
    jsonPointers:
      - /metadata/annotations/cluster.x-k8s.io~1paused
      - /metadata/annotations/velero.io~1quiesced-key
      - /metadata/labels/velero.io~1quiesced-by-restore
```

Or pause self-heal for the restore: `argocd app set capi-mgmt --sync-policy none`, restore, then re-enable automated sync. Canonical write-up: [design.md Edge Cases](../design.md).

---

## 5. Argo CD ConfigMap Definition

To restore Argo CD workloads with dynamic owner-reference remapping, deploy the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-argocd
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: Argo CD core CRD group (ApplicationSet, Application, AppProject)
  # When resourceTrackingMethod is ownerReference, managed workload groups can also be included.
  inScope: |
    - group: argoproj.io
    - group: apps
      kind: Deployment
    - group: apps
      kind: StatefulSet
    - group: ""
      kind: Service
    - group: ""
      kind: ConfigMap
    - group: ""
      kind: Secret
    - group: networking.k8s.io
      kind: Ingress

  # 2. specRefPaths: Empty (Argo CD references projects, repos, and clusters by name/URL)
  specRefPaths: ""

  # 3. quiesceOnRestore: Left empty pending upstream Argo CD pause annotation adoption.
  # Spec-field mutations (spec.syncPolicy.automated) are permanently excluded from Velero core.
  quiesceOnRestore: ""
```

### Field Breakdown
- **`inScope`:**
  - `argoproj.io`: Remaps `Application` references back to parent `ApplicationSet`.
  - Workload kinds (`Deployment`, `Service`, `ConfigMap`, etc.): Ensures that when Argo CD uses `ownerReference` resource tracking, restored workloads cleanly reconnect their owner references back to the live `Application` UID.
- **`specRefPaths`:** Left empty because Argo CD does not embed foreign object UIDs inside `.spec`.
- **`quiesceOnRestore`:** Left empty. Quiescing requires either fast Phase 1B Pass 1 completion, external post-restore orchestration via `ResourceModifier`, or upstream Argo CD pause annotation adoption.

---

## 6. Architectural Comparison: Quiesce Approaches for Argo CD

| Dimension | Native Pause Annotation (Upstream Advocacy) | Out-of-Band `ResourceModifier` | Spec-Field Quiescing in Velero Core (`specFieldPath`) |
| :--- | :--- | :--- | :--- |
| **Mechanism** | `argocd.argoproj.io/sync-paused: "true"` | JSON patch removes `spec.syncPolicy.automated` on create | Velero patches `.spec.syncPolicy.automated` |
| **GitOps Drift Safety** | **Operational:** annotation engine plus `ignoreDifferences` / suspend if Argo manages the object | **Drift Detected**: Shows `OutOfSync` until re-synced | **Catastrophic**: Triggers immediate GitOps self-healing reversion duel |
| **Unpause Automation** | **100% Automated** by Velero Phase 1B unquiesce engine | **External**: Handled by CI/CD, post-restore Job, or `kubectl patch` | **Unsafe**: OpenAPI 422 errors; unknown unpause schema |
| **User Intent Preservation** | **Guaranteed**: Already-paused applications remain paused | **Lost**: All applications stripped regardless of previous state | **Lost**: Ambiguity between pre-existing pause and Velero pause |
| **Velero Core Status** | **Supported** via `quiesceOnRestore` once available upstream | **Supported** via `Restore.Spec.ResourceModifier` (stateless create-time) | **Permanent Non-Goal** (rejected per architectural invariants) |
