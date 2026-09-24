# Case Study 06: Tekton Pipelines

This case study analyzes **Tekton Pipelines** (and related components such as Tekton Triggers), the cloud-native, continuous integration and continuous delivery (CI/CD) framework. It evaluates how Velero's dynamic owner-reference restore engine coordinates multi-stage pipeline runs, dynamic workspace storage volumes, run-once batch execution semantics, and underlying container workloads during disaster recovery and namespace migration.

---

## 1. Background & Problem Space

Tekton is a cloud-native framework for creating declarative CI/CD systems on Kubernetes. Unlike traditional operators that reconcile long-running stateful applications toward a desired continuous state, Tekton combines **declarative custom resource orchestration** with **run-once batch execution lifecycles**:

- **`PipelineRun` (`tekton.dev`):** The top-level declarative run representing an execution instance of a multi-stage `Pipeline`. It instantiates tasks, manages global workspaces, and records execution status.
- **`TaskRun` (`tekton.dev`):** Represents an execution instance of an individual `Task`. It manages sequential steps and volume mounts.
- **`CustomRun` / `Run` (`tekton.dev`):** Extensible execution primitives that allow custom controllers (e.g. loops, conditional wait gates, approvals) to run as stages within a pipeline.
- **Dynamic Workspaces (`core/v1/PersistentVolumeClaim`):** When pipelines declare `volumeClaimTemplate` workspaces, Tekton's controller dynamically provisions a PVC with an `ownerReference` pointing back to the owning `PipelineRun` or `TaskRun` so the volume is automatically reclaimed upon run deletion.
- **`ResolutionRequest` (`resolution.tekton.dev`):** Ephemeral resolution requests created during pipeline initialization to fetch remote tasks and pipelines from git repositories or artifact registries.
- **`EventListener` (`triggers.tekton.dev`):** A long-running ingress controller that listens for webhooks, parses event payloads, and owns top-level workloads (`apps/v1/Deployment`, `core/v1/Service`, `core/v1/Secret`).
- **Execution `Pod` (`core/v1`):** Spawned directly by the `TaskRun` controller. Crucially, Tekton manages task execution pods strictly via `metadata.ownerReferences` rather than label selectors.

Because Tekton relies strictly on `metadata.ownerReferences` (with `controller: true` and `blockOwnerDeletion: true`) for garbage collection, status aggregation, and workspace teardown, restoring Tekton workloads into a new namespace or cluster presents unique architectural challenges.

---

## 2. Resource Ownership Hierarchy

The complete Tekton resource topology spans 4 to 5 tiers across pipeline execution, dynamic workspace storage, remote resolution, and event triggers:

```text
TEKTON PIPELINES & TRIGGERS 5-TIER OWNERSHIP HIERARCHY
================================================================================

  [ PipelineRun (tekton.dev) ]  <── Tier 1 (Root Workflow Run)
        │
        ├── (ownerRef) ──► [ TaskRun (tekton.dev) ]  <── Tier 2 (Task Execution)
        │                        │
        │                        ├── (ownerRef) ──► [ core/Pod (core/v1) ]  <── Tier 3 (Execution Container)
        │                        │
        │                        └── (ownerRef) ──► [ PersistentVolumeClaim (core/v1) ]  <── Tier 3
        │                                             (from TaskRun volumeClaimTemplate)
        │
        ├── (ownerRef) ──► [ CustomRun / Run (tekton.dev) ]  <── Tier 2 (Custom Primitives)
        │
        ├── (ownerRef) ──► [ PersistentVolumeClaim (core/v1) ]  <── Tier 2
        │                    (from PipelineRun volumeClaimTemplate)
        │
        └── (ownerRef) ──► [ ResolutionRequest (resolution.tekton.dev) ]  <── Tier 2
                             (Remote git/hub task catalog resolution)


TEKTON TRIGGERS (OPERATOR-OWNED WORKLOADS)
================================================================================

  [ EventListener (triggers.tekton.dev) ]  <── Tier 1 (Webhook Ingress Root)
        │
        ├── (ownerRef) ──► [ Deployment (apps/v1) ]  <── Tier 2 (Listener Workload)
        │                        │
        │                        └── (selector) ──► [ ReplicaSet ] ──► [ Pod ]  <── Tiers 3 & 4
        │
        ├── (ownerRef) ──► [ Service (core/v1) ]     <── Tier 2 (Listener Endpoint)
        └── (ownerRef) ──► [ Secret (core/v1) ]      <── Tier 2 (TLS / Webhook Secret)
```

### Reference Characteristics
1. **CRD-to-CRD (`PipelineRun` → `TaskRun` / `CustomRun`):** Standard Kubernetes `metadata.ownerReferences` with `controller: true` and `blockOwnerDeletion: true`.
2. **CRD-to-Storage (`PipelineRun` / `TaskRun` → `PersistentVolumeClaim`):** When workspaces declare `volumeClaimTemplate`, Tekton dynamically provisions PVCs with an `ownerReference` pointing back to the owning run for automated cleanup.
3. **CRD-to-Workload (`TaskRun` → `core/Pod`):** Unlike standard controllers (such as `Deployment`), which adopt pods via label selectors, `TaskRun` manages its execution pod directly via `metadata.ownerReferences`.
4. **Resolution Requests (`resolution.tekton.dev/ResolutionRequest`):** Ephemeral resolution requests created during pipeline initialization and owned by the calling run.
5. **Triggers (`triggers.tekton.dev/EventListener`):** Long-running webhook receivers that create and manage top-level workloads (`apps/Deployment`, `core/Service`, `core/Secret`).

---

## 3. Catastrophic Failure Modes Without Remapping

If Tekton resources are restored into a new cluster with Velero's legacy behavior (stripping all ownerReferences without remapping), the cluster encounters severe failures:

1. **Pipeline Run Storms (Run-Once Status Reset):**
   Tekton resources are batch, run-once objects whose completion state lives strictly in `.status`. If a backup containing historical `PipelineRun`s is restored with default status wiping, Tekton treats every historical pipeline as **never executed**. It immediately triggers parallel execution for all backed-up pipelines at once, causing CPU/memory exhaustion, API server throttling, duplicate CI builds, and accidental external side effects (e.g. unwanted production releases or external webhook fires).
2. **Leaked Workspace PVCs & Storage Quota Depletion:**
   Workspace volumes created via `volumeClaimTemplate` carry an `ownerReference` pointing to their `PipelineRun` or `TaskRun`. If ownerReferences are stripped, deleting completed `PipelineRun`s fails to delete the associated PVCs. Over time, dozens or hundreds of gigabytes of cloud storage volumes remain orphaned, exhausting Kubernetes storage quotas and inflating cloud infrastructure costs.
3. **Orphaned TaskRun and Execution Pods:**
   If `TaskRun` loses its ownerReference back to `PipelineRun`, pipeline lifecycle controllers cannot propagate cancellation, timeouts, or cleanups to child tasks.
4. **Broken Cascading Garbage Collection:**
   Deleting a `PipelineRun` or `EventListener` leaves behind dangling `TaskRuns`, `PVCs`, `Deployments`, and `Services`, polluting the namespace with unmanaged artifacts.
5. **Detached Triggers Ingress Workloads:**
   When an `EventListener` is restored without remapping its underlying `Deployment` and `Service`, the triggers reconciler may attempt to recreate duplicate deployments and services or fail due to naming conflicts (`alreadyExists`).

---

## 4. How the Velero Engine Handles Tekton Pipelines

Velero's owner-reference remapping engine (`design.md`) natively supports key Tekton workflows:

### A. CRD-to-CRD Remapping (`PipelineRun` → `TaskRun`)
- In Phase 1A, `ownerReferences` are stripped on object creation to prevent immediate Garbage Collector deletion.
- Velero records live UIDs in `uidMap`.
- In Phase 1B Pass 1, Velero immediately patches `TaskRun` objects with the live `PipelineRun` UID in sub-second latency, restoring the parent-child relationship before controller reconciliation.

### B. Operator-Owned Workspace PVC Remapping
Tekton's dynamically provisioned workspace PVCs carry an `ownerReference` pointing back to `PipelineRun` or `TaskRun`.
- Velero's PVC deny-list filter (`filterDeniedPVCOwnerRefs`) explicitly targets core workloads (`Pod`, `ReplicaSet`, `ReplicationController`, `Job`).
- Because `tekton.dev/PipelineRun` and `tekton.dev/TaskRun` are **not** on the deny list, Velero retains and remaps the PVC's ownerReference. When `PersistentVolumeClaim` is included in `inScope`, the restored PVC is cleanly re-linked to its parent run, preserving automatic storage reclamation upon pipeline deletion.

### C. Automatic RBAC Fallback on `blockOwnerDeletion`
Tekton controllers set `blockOwnerDeletion: true` on child `TaskRun` ownerReferences.
- If the Velero service account in the restore target cluster lacks `delete` permissions on Tekton CRDs, the Kubernetes API server rejects the patch with `HTTP 403 Forbidden`.
- Velero's built-in RBAC fallback automatically catches HTTP 403, strips `blockOwnerDeletion: true`, and reapplies the patch. The UID is remapped successfully without blocking the restore or escalating privileges.

### D. Triggers Workload Adoption (`EventListener` → `Deployment` / `Service`)
Tekton Triggers' `EventListener` creates and owns an underlying `Deployment` and `Service`.
- By including `apps/Deployment` and `core/Service` in `inScope`, Velero reconnects these workloads to the restored `EventListener` via their new UIDs.
- The `EventListener` recognizes the existing deployment and service, preventing duplicate workload creation.

### E. Namespace Mapping & Cross-Namespace Migration
Tekton pipelines and triggers can be migrated to another namespace using `--namespace-mappings <src-ns>:<target-ns>`:
- Velero ensures both parent and child map to the target namespace (`childTargetNS == ownerTargetNS`).
- If an invalid mapping attempts to split parent and child across namespaces, Velero logs a warning and safely skips patching, preventing cross-namespace ownerReference violations.

---

## 5. Tekton ConfigMap Definition

To restore Tekton Pipelines and Triggers with dynamic owner-reference remapping, apply the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-tekton
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: Tekton execution CRDs, resolution CRDs, and operator-managed workloads
  inScope: |
    - group: tekton.dev
    - group: resolution.tekton.dev
    - group: triggers.tekton.dev
    - group: ""
      kind: PersistentVolumeClaim
    - group: ""
      kind: Service
    - group: apps
      kind: Deployment

  # 2. specRefPaths: Empty (Tekton references resources strictly by name, not UID)
  specRefPaths: ""

  # 3. quiesceOnRestore: Empty (Tekton lacks native annotation-based pausing)
  quiesceOnRestore: ""
```

### Section-by-Section Rationale

| Section | Content | Rationale |
| :--- | :--- | :--- |
| **`inScope`** | `tekton.dev`, `resolution.tekton.dev`, `triggers.tekton.dev`, `PersistentVolumeClaim`, `Service`, `Deployment` | Remaps `PipelineRun -> TaskRun`, `PipelineRun -> PVC`, and `EventListener -> Deployment/Service`. Note: `core/Pod` is omitted here because it is rejected by Velero's built-in deny list (see Gap 1 below). |
| **`specRefPaths`** | *Empty / Unset* | Unlike Cluster API (which stores parent UIDs in `spec.infrastructureRef.uid`), Tekton cross-references objects strictly by **string name within the namespace** (e.g. `spec.pipelineRef.name`, `spec.taskRef.name`, `spec.workspaces[*].persistentVolumeClaim.claimName`). There are no typed UIDs in `.spec` to remap. |
| **`quiesceOnRestore`** | *Empty / Unset* | Velero's quiesce engine is strictly **annotation-based** (`specFieldPath` is permanently excluded per `spec-field-quiesce-and-argocd-analysis.md`). Tekton controls execution exclusively via `.spec` fields (`spec.status: PipelineRunPending` / `TaskRunPending`). It has no native pause annotation. |

---

## 6. Gap Analysis & Future Architectural Considerations

While core CRD-to-CRD relationships are remapped cleanly, Tekton presents three major architectural and operational challenges:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            TEKTON RESTORE GAPS                              │
├──────────────────────┬──────────────────────┬───────────────────────────────┤
│ 1. Pod Deny List     │ 2. Quiesce Mismatch  │ 3. Run-Once Status Reset      │
│                      │                      │                               │
│ TaskRun -> Pod       │ No pause annotation; │ Default resetStatus clears    │
│ blocked by hardcoded │ uses spec.status     │ completion state; triggers    │
│ DenyListGroupKinds   │ (PipelineRunPending) │ total pipeline re-execution   │
└──────────────────────┴──────────────────────┴───────────────────────────────┘
```

---

### Gap 1: Built-in `core/Pod` Deny List vs. `TaskRun` Pods

#### The Problem
In `internal/ownerref/scope.go`, `core/Pod` is an immutable entry in `DenyListGroupKinds`:

```go
var DenyListGroupKinds = []schema.GroupKind{
    {Group: "", Kind: "Pod"},
    {Group: "", Kind: "ReplicationController"},
    {Group: "apps", Kind: "ReplicaSet"},
    {Group: "batch", Kind: "Job"},
}
```

This deny list protects `kube-controller-manager` workloads: `ReplicaSet` and `Deployment` adopt pods using label selectors via `claimPods()`. Remapping ownerRefs on standard workload pods causes ownership churn and conflicts with controller adoption.

However, **Tekton does not use label selector adoption**. A `TaskRun` manages its execution pod strictly via `metadata.ownerReferences`:
1. During Phase 1A, Velero strips `ownerReferences` from the restored Pod.
2. Because `core/Pod` is on the deny list, Phase 1B **never remaps** the Pod's ownerRef.
3. The restored Pod is permanently orphaned from the `TaskRun`.
4. When the user or pipeline pruner later deletes the `TaskRun` or `PipelineRun`, Kubernetes GC deletes the `TaskRun`, **but the orphan Pod remains in the cluster indefinitely**, leading to pod and storage quota leaks.

#### Future Investigation Paths
* **Approach A: Parent-Filtered Pod Remapping (Recommended Architectural Path):**
  Mirror the design pattern already used for `PersistentVolumeClaim` (`filterDeniedPVCOwnerRefs`). Allow `core/Pod` to be eligible for ownerRef remapping **if and only if its parent GVK is NOT on the deny list**:
  - Parent is `tekton.dev/TaskRun` → **Allowed** (remap ownerRef).
  - Parent is `apps/ReplicaSet` or `batch/Job` → **Denied** (preserve legacy strip-and-adopt).
* **Approach B: Exclude Pods from Backup (Current Operational Workaround):**
  If administrators exclude Pods from the backup (`--exclude-resources=pods`), completed `TaskRuns` still retain their execution logs and task results (provided `.status` is restored; see Gap 3). If an active pipeline is re-run, Tekton simply spins up a new pod.

---

### Gap 2: Controller Quiescing in Disaster Recovery (`quiesceOnRestore`)

#### The Problem
In Disaster Recovery (DR) migrations into an empty cluster, non-completed `PipelineRuns` create race conditions:
- If a `PipelineRun` is created in Phase 1A before all its child `TaskRuns` and `PVC`s exist, active Tekton controllers detect the missing children and immediately schedule new `TaskRun`s and pods, racing against Velero.
- In Cluster API and Flux, this is solved by `quiesceOnRestore` injecting pause **annotations** (e.g. `cluster.x-k8s.io/paused: ""` or `kustomize.toolkit.fluxcd.io/reconcile: disabled`) and removing them in Phase 1B.
- **Tekton has no pause annotation.** Tekton controls pausing via:
  - `spec.status: PipelineRunPending` (TEP-0015)
  - `spec.status: TaskRunPending` (TEP-0144 / Tekton Pipelines v1.11.0+)
  - `spec.managedBy` (immutable string field delegating reconciliation)

Per the analysis in `spec-field-quiesce-and-argocd-analysis.md`, Velero's core quiesce engine **permanently excludes `specFieldPath`** because mutating `.spec` triggers GitOps self-healing duels, OpenAPI 422 schema rejections, and generation bumps.

#### Future Investigation Paths
* **Operational Workaround (One-Way ResourceModifier):**
  Use Velero's `Restore.Spec.ResourceModifier` to inject `spec.status: PipelineRunPending` at create-time. An external post-restore script or job must clear `spec.status` once the restore phase reaches `Completed`.
* **Upstream Advocacy:**
  Advocate in the Tekton community (via a TEP) for a native pause annotation (e.g. `tekton.dev/paused: "true"` or `tekton.dev/reconcile: "disabled"`). This would allow Tekton to integrate seamlessly with Velero's automated annotation-based quiescing without custom scripts.

---

### Gap 3: Run-Once / Batch Semantics & `.status` Reset

#### The Problem
Velero's default behavior during restore is to unconditionally wipe the `.status` subresource (`resetStatus()` in `pkg/restore/restore.go`).
* For declarative controllers (e.g. CAPI, Deployments), stripping `.status` is harmless because controllers reconcile `.spec` and regenerate `.status`.
* `PipelineRun` and `TaskRun` are **batch, run-once resources**. Their entire lifecycle state—whether they succeeded, failed, their start/completion times, step exit codes, and task results—lives exclusively in `.status`.
* If a backup containing historical `PipelineRun`s is restored without status:
  - Tekton sees every historical `PipelineRun` as **never having run**!
  - It immediately triggers execution for every backed-up pipeline at once, causing massive cluster load, duplicate CI runs, and unexpected external side effects.

#### Operational Requirement & Investigation
* **Mandatory Restore Flag:** Users backing up and restoring Tekton workloads **must** explicitly configure status restoration:
  ```yaml
  apiVersion: velero.io/v1
  kind: Restore
  spec:
    restoreStatus:
      includedResources:
        - "tekton.dev/*"
  ```
* **Future Enhancement:** Velero restore preflight validation could check whether `inScope` includes known run-once API groups (such as `tekton.dev`) and log a prominent warning if `restoreStatus` is not configured.

---

## 7. Summary & Action Items for Future Tekton Support

| Component / Requirement | Status in Current Engine | Recommended Investigation / Action |
| :--- | :--- | :--- |
| **`PipelineRun -> TaskRun` Remap** | **Supported** | Configure `inScope: [tekton.dev]`. |
| **Workspace PVC Remapping** | **Supported** | Configure `inScope: [PersistentVolumeClaim]`; parent filter retains link to `PipelineRun`. |
| **`EventListener -> Deployment`** | **Supported** | Configure `inScope: [apps/Deployment, core/Service]`. |
| **`TaskRun -> Pod` Remapping** | **Blocked by Deny List** | **Investigate:** Implement parent-filtered Pod remapping (allow Pod ownerRef remapping when parent is `tekton.dev/TaskRun`). |
| **Disaster Recovery Quiescing** | **Unsupported (No Annotation)** | **Investigate:** Keep `quiesceOnRestore` annotation-only; use `ResourceModifier` for `spec.status: PipelineRunPending` + external unpause, or advocate for upstream Tekton pause annotation. |
| **Historical Run Preservation** | **Requires Explicit Flag** | **Investigate:** Add restore preflight warning if `tekton.dev` is in `inScope` without `restoreStatus.includedResources`. |
