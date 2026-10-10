# Case Study 03: Knative Serving

This case study analyzes **Knative Serving**, which represents the deepest custom resource definition (CRD) ownership DAG in the mainstream Kubernetes ecosystem (spanning up to 6 tiers). It evaluates how Velero's dynamic owner-reference restore engine handles deep multi-hop hierarchies, immutable intermediate CRDs, and serverless controller coordination.

---

## 1. Background & Problem Space

Knative Serving provides declarative serverless workload management on top of Kubernetes. Rather than deploying an `apps/v1/Deployment` directly from a top-level custom resource, Knative decomposes the operational lifecycle into separate concerns:
- **Routing and Ingress:** Controlled via `Route` and internal `Ingress` CRDs.
- **Configuration and Immutability:** Managed via `Configuration` and immutable snapshot `Revision` CRDs.
- **Autoscaling:** Driven by `PodAutoscaler` and `Metric` CRDs.
- **Networking:** Orchestrated via `ServerlessService` and internal Kubernetes `Service`/`Endpoints`.
- **Workload Execution:** Handled by standard `Deployment`, `ReplicaSet`, and `Pod` resources.

Because Knative relies strictly on Kubernetes `metadata.ownerReferences` (with `controller: true` and `blockOwnerDeletion: true`) for garbage collection, reconciliation loops, and status rollups, restoring Knative manifests severe challenges if owner references are stripped or unremapped.

---

## 2. Resource Ownership Hierarchy

The complete ownership graph of a Knative Service forms a 6-tier directed acyclic graph (DAG):

```text
KNATIVE SERVING 6-TIER OWNERSHIP HIERARCHY
================================================================================

  [ Service (serving.knative.dev) ]  <── Tier 1 (User Entrypoint)
        │
        ├── (ownerRef) ──► [ Route (serving.knative.dev) ]  <── Tier 2
        │                        │
        │                        └── (ownerRef) ──► [ Ingress (networking.internal.knative.dev) ]  <── Tier 3
        │                                                 │
        │                                                 └── (ownerRef) ──► [ Gateway / HTTPRoute / VirtualService ]  <── Tier 4
        │
        └── (ownerRef) ──► [ Configuration (serving.knative.dev) ]  <── Tier 2
                                 │
                                 └── (ownerRef) ──► [ Revision (serving.knative.dev) ]  <── Tier 3 (Immutable Snapshot)
                                                          │
                                                          ├── (ownerRef) ──► [ PodAutoscaler (autoscaling.internal...) ]  <── Tier 4
                                                          │                        │
                                                          │                        ├── (ownerRef) ──► [ ServerlessService (networking.internal...) ]  <── Tier 5
                                                          │                        │                        │
                                                          │                        │                        └── (ownerRef) ──► [ Service & Endpoints (core/v1) ]  <── Tier 6
                                                          │                        │
                                                          │                        └── (ownerRef) ──► [ Metric (autoscaling...) ]  <── Tier 5
                                                          │
                                                          └── (ownerRef) ──► [ Deployment (apps/v1) ]  <── Tier 4 (Workload Root)
                                                                                   │
                                                                                   └── (selector) ──► [ ReplicaSet (apps/v1) ]  <── Tier 5
                                                                                                          │
                                                                                                          └── (selector) ──► [ Pod (core/v1) ]  <── Tier 6
```

### Reference Characteristics
- **Tier 1 to Tier 3 (`Service` → `Route` / `Configuration` → `Revision`):** High-level orchestration using standard `metadata.ownerReferences`.
- **Tier 3 (`Revision`):** An **immutable** record of code and configuration. Once created, `.spec` cannot be modified.
- **Tier 3 to Tier 4 (`Revision` → `Deployment` / `PodAutoscaler`):** The `Revision` controller reconciles child resources and attaches ownerReferences pointing to the `Revision`.
- **Tier 4 to Tier 6 (`PodAutoscaler` → `ServerlessService` → `Service`):** The autoscaler coordinates networking and metrics backends across lower tiers.
- **Tier 4 to Tier 6 (`Deployment` → `ReplicaSet` → `Pod`):** Traditional Kubernetes workload adoption governed by label selectors and controller manager adoption.

---

## 3. Catastrophic Failure Modes Without Remapping

If a Knative Serving workload is restored into a new cluster with Velero's legacy behavior (stripping all ownerReferences without remapping), the system fails in multiple catastrophic ways:

1. **Infinite Revision Regeneration Loops:**
   The `Configuration` controller continuously lists `Revisions` with matching owner references. When ownerReferences are stripped, the controller assumes no revision exists for the current generation and generates a brand-new revision (e.g. `service-00002`). This triggers a new rollout, invalidates existing traffic targets, and leaves historical revisions orphaned.
2. **Orphaned Deployments and Split Traffic:**
   Existing `Deployment` objects lose their ownerReference pointing to their `Revision`. The Knative activator and queue-proxy sidecars lose the ability to route traffic to warm pods.
3. **Autoscaler Detachment:**
   `PodAutoscaler` (KPA) and `Metric` objects become detached from their `Revision`. Knative cannot scale the deployment from zero or collect concurrency metrics, causing cold-start requests to hang indefinitely.
4. **Broken Cascading Garbage Collection:**
   Deleting the Knative `Service` leaves behind lingering `Routes`, `Revisions`, `Deployments`, and `Ingresses`, polluting cluster networking and wasting cloud resources.

---

## 4. How the Velero Engine Handles Knative Serving

Velero's owner-reference remapping engine (`design.md`) resolves Knative's multi-hop topology through several key mechanisms:

### A. Depth-Agnostic $O(1)$ Remapping Across 6 Tiers
Because Velero creates all resources in Phase 1A before executing Phase 1B remapping, intermediate parents (`Route`, `Configuration`, `Revision`, `Deployment`) are already live with assigned UIDs in `uidMap`. When Phase 1B executes, leaf resources at Tiers 4, 5, and 6 remap their parent references via simple $O(1)$ hash map lookups.

### B. Patching Immutable `Revision` Objects
A critical requirement in Knative is that `Revision.spec` is immutable. If a backup/restore tool attempts to modify `Revision.spec` during restore, Kubernetes admission webhooks reject the operation with HTTP 422 Unprocessable Entity.
- Velero **never** mutates `.spec` during owner-reference remapping.
- `metadata.ownerReferences` is part of Kubernetes object metadata. In Kubernetes, updating `metadata.ownerReferences` via JSON merge patch is permitted on immutable CRDs, allowing Velero to re-link `Revision` to `Configuration` seamlessly.

### C. Respecting Workload Boundaries (Pod Deny List)
Velero's engine enforces a permanent built-in deny list for leaf workloads:
- `core/v1/Pod`
- `apps/v1/ReplicaSet`
- `core/v1/ReplicationController`
- `batch/v1/Job`

In Knative, the `Deployment` owns the `ReplicaSet`, which owns the `Pod`. Under Velero's design:
- Knative CRDs (`serving.knative.dev`, `autoscaling.internal.knative.dev`, `networking.internal.knative.dev`) are included in `inScope`.
- `apps/v1/Deployment` is opted in via `inScope` so it reattaches to its parent `Revision`.
- `ReplicaSet` and `Pod` remain denied. The restored `Deployment` automatically adopts its `ReplicaSets` and `Pods` via label selectors, perfectly preserving Kubernetes workload mechanics without dual-controller ownership conflicts.

### D. Controller Quiescing Analysis
Knative does not currently feature a native pause annotation on `Service` or `Configuration` (unlike CAPI's `cluster.x-k8s.io/paused` or Crossplane's `crossplane.io/paused`).
- Because Phase 1B Pass 1 executes in-memory immediately inside `RestoreController` (sub-second latency for small-to-medium restores), the race window between Phase 1A creation and Phase 1B remapping is extremely narrow.
- For maximum disaster-recovery resilience, the Velero project advocates that upstream Knative adopt a native pause annotation (e.g. `serving.knative.dev/paused: ""`).

---

## 5. Knative ConfigMap Definition

To restore Knative Serving workloads with dynamic owner-reference remapping, apply the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-knative
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: Knative serving, autoscaling, networking CRD groups, and operator-owned workloads
  inScope: |
    - group: serving.knative.dev
    - group: autoscaling.internal.knative.dev
    - group: networking.internal.knative.dev
    - group: apps
      kind: Deployment
    - group: ""
      kind: Service
    - group: ""
      kind: Endpoints

  # 2. specRefPaths: Empty (Knative relies entirely on metadata.ownerReferences and label selectors)
  specRefPaths: ""

  # 3. quiesceOnRestore: Optional/Community Advocacy target
  quiesceOnRestore: ""
```

### Field Breakdown
- **`inScope`:**
  - `serving.knative.dev`: Covers `Service`, `Route`, `Configuration`, and `Revision`.
  - `autoscaling.internal.knative.dev`: Covers `PodAutoscaler` and `Metric`.
  - `networking.internal.knative.dev`: Covers `Ingress` and `ServerlessService`.
  - `apps/Deployment`: Permits `Deployment` to re-link to its parent `Revision`.
  - `core/Service` and `core/Endpoints`: Permits internal serverless services to re-link to their parent `ServerlessService`.
- **`specRefPaths`:** Left empty because Knative does not store foreign parent UIDs inside `.spec` fields.
- **`quiesceOnRestore`:** Left empty pending upstream Knative adoption of a pause annotation.
