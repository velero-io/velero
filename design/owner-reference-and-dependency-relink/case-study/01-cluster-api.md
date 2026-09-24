# Case Study 01: Cluster API (CAPI)

This case study analyzes **Cluster API (CAPI)**, the Kubernetes subproject that brings declarative, Kubernetes-style APIs to cluster creation, configuration, and management across multi-cloud, hybrid, and bare-metal infrastructure (AWS, Azure, GCP, vSphere, Docker). It evaluates how Velero's dynamic restore engine handles multi-tier infrastructure DAGs, bidirectional dual-pointer remapping (`metadata.ownerReferences` and `spec.*Ref`), out-of-order restoration tolerance, and automated controller quiescing (`cluster.x-k8s.io/paused`).

Cluster API serves as the **primary baseline reference implementation** for Velero's OwnerReference-Aware Restore & Controller Quiescing Engine (`design.md`).

---



## 1. Background & Problem Space

Cluster API automates the provisioning, upgrading, and lifecycle management of Kubernetes workload clusters by modeling machines, control planes, and cloud infrastructure as declarative Custom Resources:

- `Cluster` **(**`cluster.x-k8s.io`**):** The top-level declarative object representing the workload cluster.
- **Infrastructure Cluster (**`infrastructure.cluster.x-k8s.io`**):** Provider-specific networking, security groups, VPCs, and load balancers (e.g. `DockerCluster`, `VSphereCluster`, `AWSCluster`).
- `KubeadmControlPlane` **/ KCP (**`controlplane.cluster.x-k8s.io`**):** Manages the lifecycle of control plane nodes, PKI certificates, etcd membership, and Kubernetes upgrades.
- `MachineDeployment` **&** `MachineSet` **(**`cluster.x-k8s.io`**):** Manages horizontal scaling, rolling updates, and node health check remediations for worker machines (analogous to `Deployment` and `ReplicaSet`).
- `Machine` **(**`cluster.x-k8s.io`**):** Represents the core declarative specification of a single cluster node.
- **Bootstrap Config (**`bootstrap.cluster.x-k8s.io`**):** Generates cloud-init or ignition scripts to join a node to the cluster (e.g. `KubeadmConfig`).
- **Infrastructure Machine (**`infrastructure.cluster.x-k8s.io`**):** Represents the provider-specific physical or virtual machine instance (e.g. `DockerMachine`, `VSphereMachine`, `AWSMachine`).



### The Dual-Pointer Pattern

Unlike simpler controllers that manage child objects using only label selectors or single-directional owner references, Cluster API enforces a **bidirectional dual-pointer pattern**:

1. **Bottom-Up Ownership (`metadata.ownerReferences`):** Used by Kubernetes Garbage Collection and status aggregation (`DockerMachine` → `Machine` → `MachineSet` → `MachineDeployment` → `Cluster`).
2. **Top-Down Binding (`spec.*Ref`):** Used by CAPI reconcilers for controller delegation, where parent specs store explicit, typed `corev1.ObjectReference` fields containing the child object's `name`, `namespace`, and `uid`:
   - `Cluster.spec.infrastructureRef` → `DockerCluster` / `VSphereCluster`
   - `Cluster.spec.controlPlaneRef` → `KubeadmControlPlane`
   - `Machine.spec.infrastructureRef` → `DockerMachine` / `VSphereMachine`
   - `Machine.spec.bootstrap.configRef` → `KubeadmConfig`

Because 4 independent controller managers (`capi-controller-manager`, `kcp-controller-manager`, `cabpk-controller-manager`, and provider-specific infrastructure controllers like `capv` or `capd`) reconcile concurrently, restoring CAPI manifests severe race conditions and infrastructure failure modes if owner references and spec pointers are stripped or unremapped.

---



## 2. Resource Ownership & Spec-Ref Hierarchy

The complete Cluster API resource topology forms a 5-tier bidirectional directed acyclic graph (DAG):

```text
CLUSTER API 5-TIER TOPOLOGY: DUAL-POINTER ARCHITECTURE
================================================================================

  [ Tier 1: Cluster (cluster.x-k8s.io) ] <────────────────────────────────┐
        │                                                                 │
        ├── (spec.infrastructureRef) ──► [ DockerCluster / VSphereCluster ]│ (ownerRef)
        │                                (infrastructure.cluster.x-k8s.io) │
        │                                                                 │
        ├── (spec.controlPlaneRef) ────► [ KubeadmControlPlane (KCP) ] ───┤ (ownerRef)
        │                                (controlplane.cluster.x-k8s.io)  │
        │                                      │                          │
        │                                      │ (ownerRef)               │
        │                                      ▼                          │
        │                                [ Control Plane Machine ]        │
        │                                                                 │
        └── (ownerRef) ──► [ Tier 2: MachineDeployment (cluster.x-k8s.io) ]
                                 │
                                 └── (ownerRef) ──► [ Tier 3: MachineSet (cluster.x-k8s.io) ]
                                                          │
                                                          └── (ownerRef) ──► [ Tier 4: Machine (Worker) ]
                                                                                   │
                                                                                   ├── (spec.bootstrap.configRef) ──► [ KubeadmConfig ]  (ownerRef)
                                                                                   │                                  (bootstrap...)        │
                                                                                   │                                                        ▼
                                                                                   └── (spec.infrastructureRef) ───► [ Tier 5: DockerMachine / VSphereMachine ]
                                                                                                                     (infrastructure.cluster.x-k8s.io)
                                                                                                                     ▲
                                                                                                                     │ (ownerRef)
                                                                                                                     └───────────────────────────────┘
```



### Reference Characteristics

1. **Tier 1 to Infrastructure Cluster (`Cluster` ↔ `DockerCluster` / `VSphereCluster`):**
   - `Cluster.spec.infrastructureRef` points to `DockerCluster` (with `apiVersion`, `kind`, `name`, `uid`).
   - `DockerCluster.metadata.ownerReferences` points back to `Cluster` (`controller: true`, `blockOwnerDeletion: true`).
2. **Tier 1 to Control Plane (`Cluster` ↔ `KubeadmControlPlane`):**
   - `Cluster.spec.controlPlaneRef` points to `KubeadmControlPlane`.
   - `KubeadmControlPlane.metadata.ownerReferences` points back to `Cluster`.
3. **Tier 2 to Tier 4 Workload Hierarchy (`MachineDeployment` → `MachineSet` → `Machine`):**
   - `MachineDeployment` owns `MachineSet` via standard `metadata.ownerReferences`.
   - `MachineSet` owns worker `Machine` instances via `metadata.ownerReferences`.
4. **Tier 4 to Tier 5 Infrastructure Binding (`Machine` ↔ `DockerMachine` / `VSphereMachine`):**
   - `Machine.spec.infrastructureRef` holds the `DockerMachine` UID.
   - `DockerMachine.metadata.ownerReferences` holds the `Machine` UID.
   - `Machine.spec.bootstrap.configRef` points to `KubeadmConfig`, while `KubeadmConfig.metadata.ownerReferences` points back to `Machine`.

---



## 3. Catastrophic Failure Modes Without Remapping

If a Cluster API workload is restored with Velero's legacy behavior (stripping all ownerReferences and leaving spec pointers untouched), the system suffers catastrophic failures:

1. **Duplicate Cloud VM Provisioning & Cloud Infrastructure Sprawl:**
  When `Cluster`, `MachineSet`, or `KubeadmControlPlane` are restored without their child `Machine` references intact, controllers determine that **0 machines exist** in the cluster. CAPI controllers immediately issue calls to cloud provider APIs (e.g. vSphere, AWS EC2, Azure) to provision an entirely new fleet of virtual machines, doubling infrastructure footprint and costs.
2. **Orphaned Cloud Virtual Machines & Node Leaks:**
  If `Machine` and `VSphereMachine` lose their ownerReferences, deleting a `MachineDeployment` or `Cluster` will delete the top-level CRDs, **but the running VMs in vSphere or AWS remain running indefinitely**. This causes massive cloud billing leaks and security vulnerabilities.
3. **Instant API Server Garbage Collection Deletion:**
  If child CRDs (`DockerMachine`, `Machine`, `MachineSet`) are restored with their stale backup UIDs in `metadata.ownerReferences`, the Kubernetes API server's Garbage Collector detects that those parent UIDs do not exist and **instantly deletes all child objects from etcd**, wiping out the restored cluster in seconds.
4. **Split-Brain Control Plane Consensus:**
  If `KubeadmControlPlane` loses its connection to the `Cluster` or its control plane `Machine`, it attempts to regenerate PKI certificates, regenerate kubeconfigs, and bootstrap a new control plane from scratch, causing etcd quorum failure and split-brain consensus corruption.
5. **Broken Cascading Teardown:**
  Deleting the root `Cluster` resource leaves lingering `MachineDeployments`, `MachineSets`, `Machines`, and infrastructure CRs, completely breaking declarative cleanup.

---



## 4. How the Velero Engine Handles Cluster API

Velero's owner-reference remapping engine (`design.md`) was specifically engineered to resolve CAPI's complex operational challenges through several coordinated mechanisms:

### A. Automated Controller Quiescing (`quiesceOnRestore`)

To prevent controllers from provisioning duplicate VMs during the restore process, Velero silences CAPI controllers before any dependent resources are created:

- In Phase 1A create, when Velero creates the `Cluster` resource, it automatically injects:
  ```yaml
  metadata:
    annotations:
      cluster.x-k8s.io/paused: ""
    labels:
      velero.io/quiesced-by-restore: "<restore-name>"
  ```
- CAPI controllers (`capi-controller-manager`, `kcp`, `capv`, `capd`) inspect `annotations.IsPaused(cluster, obj)`. Detecting the pause annotation, all reconcilers immediately log `"Reconciliation is paused for this object"` and return `ctrl.Result{}, nil`.
- No cloud provider API calls are made, no VMs are created, and no controllers race against Velero while child objects are being restored.
- In Phase 1B, after all `metadata.ownerReferences` and `spec.*Ref` pointers have been remapped, Velero's graph-free unquiesce engine safely removes `cluster.x-k8s.io/paused: ""` via JSON merge patch.

If the destination `Cluster` is itself synced by Argo CD or Flux with self-heal, those controllers compare live vs git **including annotations**. Git typically omits `cluster.x-k8s.io/paused`, so self-heal strips Velero's pause during Pass 1. That is an operational GitOps configuration, not something Velero injects. Use `ignoreDifferences` / `driftDetection.ignore` (or suspend the Application/Kustomization for the restore window). Full YAML is in [design.md Edge Cases](../design.md) and the [Argo CD](./08-argo-cd.md) / [Flux v2](./07-flux-v2.md) case studies.



### B. Out-of-Order Creation Tolerance & Priority Ordering Analysis

In Velero's default restore priority ordering (`pkg/cmd/server/config/config.go`), `clusters.cluster.x-k8s.io` is positioned in `LowPriorities` (following Tanzu `clusterbootstraps.run.tanzu.vmware.com` to prevent Tanzu controllers from auto-generating unwanted default bootstrap configurations).
Consequently, non-prioritized CAPI resources—such as `bootstrap.cluster.x-k8s.io` (`KubeadmConfig`), `controlplane.cluster.x-k8s.io` (`KubeadmControlPlane`), `infrastructure.cluster.x-k8s.io` (`DockerMachine`, `VSphereMachine`), and `cluster.x-k8s.io` (`Machine`, `MachineSet`)—are restored alphabetically **before** `Cluster`.

CAPI controllers inherently tolerate this out-of-order creation:

1. **Infrastructure Controllers (**`DockerMachine`**,** `VSphereMachine`**):** Call `util.GetOwnerMachine(ctx, r.Client, infraMachine)`. Because `ownerReferences` are stripped in Phase 1A, `GetOwnerMachine` returns `nil`. The controller logs `"Waiting for Machine controller to set OwnerRef"` and returns without taking action.
2. **Control Plane (**`KubeadmControlPlane`**):** Calls `util.GetOwnerCluster(ctx, r.Client, kcp.ObjectMeta)`. With `ownerReferences` stripped, it returns `nil` and logs `"Cluster Controller has not yet set OwnerRef"`.
3. **Workload Controllers (**`MachineSet`**,** `Machine`**):** Call `util.GetClusterByName(ctx, r.Client, m.Namespace, m.Spec.ClusterName)`. While `Cluster` is waiting in `LowPriorities`, `GetClusterByName` returns `apierrors.IsNotFound(err)`, causing the reconciler to safely requeue with backoff.
4. **Transition upon Cluster Creation:** The moment Velero reaches `LowPriorities` and creates `Cluster`, Velero's `quiesceOnRestore` engine intercepts the call and injects `cluster.x-k8s.io/paused: ""`. The cluster creation event wakes up child watches, but CAPI's `annotations.IsPaused(cluster, obj)` evaluates to `true`, keeping all controllers frozen.



### C. Bidirectional Dual-Pointer Remapping in Phase 1B Pass 1

Immediately upon completing Phase 1A synchronous creation, Phase 1B Pass 1 executes in-memory remapping inside `RestoreController`:

- `metadata.ownerReferences` **Remapping:** Velero rewrites the ownerReferences on `DockerCluster`, `KubeadmControlPlane`, `MachineDeployment`, `MachineSet`, `Machine`, `DockerMachine`, and `KubeadmConfig` using the live UIDs stored in `uidMap`.
- `specRefPaths` **Remapping:** Velero walks allowlisted paths in `spec` (`Cluster.spec.infrastructureRef`, `Cluster.spec.controlPlaneRef`, `Machine.spec.infrastructureRef`, `Machine.spec.bootstrap.configRef`), looks up the child's old UID in `uidMap`, and updates the field with the live child UID.



### D. Transitive Root Propagation & Zero-Duplicate Container/VM Adoption

If an API conflict (HTTP 409) occurs while patching a leaf `DockerMachine` or `VSphereMachine`:

1. Velero traverses `parentMap` backwards via breadth-first search:
   `DockerMachine` → `Machine` → `MachineSet` → `Cluster`
2. The root `Cluster` is appended to the pending patch's `Targets` field.
3. `CanUnquiesce(Cluster)` evaluates to `false` because `Cluster` appears in `Targets`.
4. The `Cluster` remains **paused** until the leaf infrastructure machine patch succeeds.
5. Once all patches succeed, Velero unpauses the `Cluster`. CAPI controllers wake up, observe all child machines already present with matching live UIDs, and adopt the pre-existing host Docker containers or vSphere VMs **without spawning duplicate containers or VMs**.

#### Dual-Pointer SpecRef Pinning
The same transitive root propagation applies to spec-level pointers. In CAPI, `Machine` points to `VSphereMachine` via `spec.infrastructureRef`:
1. If `Machine.spec.infrastructureRef` encounters a retriable error (HTTP 409 Conflict), Velero traverses `parentMap` via BFS starting from `Machine` up to the root `Cluster`.
2. Both the spec target (`VSphereMachine`) and the root `Cluster` are recorded in `pendingPatch.Targets`.
3. `CanUnquiesce(Cluster)` returns `false` because `Cluster` is in `Targets`. This prevents CAPI from waking up while the machine is detached from its underlying infrastructure, avoiding duplicate VM provisioning.
4. If the specRef patch encounters a non-retriable error (HTTP 422 Invalid / admission rejection), Velero traverses `parentMap` to find `Cluster` and marks it `UnquiesceBlocked = true`, ensuring `Cluster` remains permanently paused (fail-safe) and forcing the restore to `RestorePhasePartiallyFailed`.



### E. Namespace Mapping & Cross-Namespace Cluster Migration

When a CAPI cluster is restored into a different namespace using `--namespace-mappings <src-ns>:<target-ns>`:

- Velero ensures both parent and child map to the target namespace (`childTargetNS == ownerTargetNS`).
- For allowlisted `specRefPaths`, if the `ObjectReference` contains a `namespace` field, Velero rewrites it through the restore `NamespaceMapping`.
- If an invalid mapping attempts to place `Cluster` in namespace A and `DockerCluster` in namespace B, Velero detects `ownerTargetNS != childTargetNS`, logs a warning, and safely skips patching, preventing invalid cross-namespace ownerReferences.



### F. Status Subresource Handling & Upstream Provider Contract

A common question in disaster recovery is whether Velero needs to preserve or restore the `.status` subresource for Cluster API Custom Resources.

**Conclusion: The `.status` subresource does NOT need to be preserved.** CAPI controllers are specifically designed to fully regenerate 100% of their status and conditions from `.spec`, live `metadata.ownerReferences`, allowlisted `spec.*Ref` pointers, and external cloud infrastructure.

#### 1. The Upstream CAPI Contract (`clusterctl move`)
The upstream Cluster API project enforces this as an architectural invariant in its provider contract ([The Cluster API Book: clusterctl Provider Contracts](https://cluster-api.sigs.k8s.io/developer/providers/contracts/clusterctl)):
> *"**Warning: Status subresource is never restored.** Every object’s `Status` subresource, including every nested field (e.g. `Status.Conditions`), is **never restored during a `move` operation**. A `Status` subresource should never contain fields that cannot be recreated or derived from information in spec, metadata, or external systems. Provider implementers should not store non-ephemeral data in the `Status`. **`Status` should be able to be fully rebuilt by controllers by observing the current state of resources.***"

Every certified CAPI infrastructure provider (CAPV for vSphere, CAPA for AWS, CAPZ for Azure, CAPD for Docker) complies with this contract to support `clusterctl move`.

#### 2. Bottom-Up Status Regeneration Flow
Once Velero completes Phase 1B Pass 1 (re-linking ownerReferences and spec pointers) and lifts `cluster.x-k8s.io/paused`, CAPI controllers reconstruct status in a deterministic, bottom-up sequence:
1. **Infrastructure Controllers (`DockerMachine`, `VSphereMachine`):** Read `spec.providerID` or VM tags, query the cloud/hypervisor API, match the running VM/container, and set `status.ready = true` and `status.addresses`.
2. **Machine Controller (`Machine`):** Connects to the workload cluster using the restored admin kubeconfig Secret (`<cluster-name>-kubeconfig`), resolves the workload Kubernetes `Node`, and reconstructs `status.nodeRef`, `status.phase = "Running"`, and conditions.
3. **Control Plane Controller (`KubeadmControlPlane`):** Contacts workload etcd and API server, verifies quorum and control plane pods, and updates `status.readyReplicas` and `status.version`.
4. **Workload Controllers (`MachineSet`, `MachineDeployment`):** Aggregate child Machine objects via label selectors and recalculate replica counts (`status.replicas`, `status.readyReplicas`, `status.availableReplicas`).
5. **Root Cluster Controller (`Cluster`):** Observes `infrastructureReady == true` and `controlPlaneReady == true`, transitioning `status.phase = "Provisioned"`.

#### 3. Why Wiping Status on Restore is Preferred
- **Truthful State Observation:** Clearing `.status` ensures that objects do not show a misleading `"Running"` or `"Ready"` status before controllers have re-authenticated with cloud APIs or verified node network connectivity.
- **Accurate Timestamps:** Condition `lastTransitionTime` timestamps accurately reflect the recovery event rather than carrying stale times from the source cluster.
- **API Efficiency:** Avoids two API calls per object (`POST` for spec, followed by `PUT /status`), halving create-phase API round trips.
- **Contrast with Batch Systems:** Unlike run-once batch systems (such as Tekton `PipelineRun` where completion state lives exclusively in `.status`), CAPI is a continuous reconciliation engine whose source of truth is external hypervisors and workload cluster etcd.

In practice, machines transition to `status.phase: Running` automatically once CAPI controllers re-reconcile live provider infrastructure after being restored with status wiped.

---



## 5. Cluster API Baseline ConfigMap Definition

To restore Cluster API workloads with dynamic owner-reference remapping and automated controller quiescing, apply the baseline ConfigMap (`velero-ownerref-config`) in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-config
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope defines API groups and kinds eligible for ownerReference remapping.
  # Enables Cluster API core, controlplane, bootstrap, infrastructure, ipam, and addons.
  # PersistentVolumeClaim is not in the CAPI baseline; opt in via a restore-level ConfigMap.
  inScope: |
    - group: cluster.x-k8s.io
    - group: controlplane.cluster.x-k8s.io
    - group: bootstrap.cluster.x-k8s.io
    - group: infrastructure.cluster.x-k8s.io
    - group: ipam.cluster.x-k8s.io
    - group: addons.cluster.x-k8s.io

  # 2. specRefPaths defines dotted spec.* paths pointing to parent/child resources whose UIDs must be remapped.
  specRefPaths: |
    - group: cluster.x-k8s.io
      kind: Cluster
      paths:
        - spec.infrastructureRef
        - spec.controlPlaneRef
    - group: cluster.x-k8s.io
      kind: Machine
      paths:
        - spec.infrastructureRef
        - spec.bootstrap.configRef

  # 3. quiesceOnRestore defines temporary pause annotations injected during Phase 1A create
  # to silence declarative controllers while dependent children are restored.
  # Annotations are removed automatically after Phase 1B remapping.
  quiesceOnRestore: |
    - group: cluster.x-k8s.io
      kind: Cluster
      annotationKey: cluster.x-k8s.io/paused
      annotationValue: ""
```



### Section-by-Section Rationale


| Section            | Content                                                                                                                                                                                                       | Rationale                                                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inScope`          | `cluster.x-k8s.io/*`, `controlplane.cluster.x-k8s.io/*`, `bootstrap.cluster.x-k8s.io/*`, `infrastructure.cluster.x-k8s.io/*`, `ipam.cluster.x-k8s.io/*`, `addons.cluster.x-k8s.io/*` | Authorizes Velero to dynamically patch `metadata.ownerReferences` across all CAPI CRDs, preserving cascading lifecycle management. `PersistentVolumeClaim` is omitted from this baseline so enabling the feature flag does not remap StatefulSet-owned PVCs. |
| `specRefPaths`     | `Cluster.spec.infrastructureRef`, `Cluster.spec.controlPlaneRef`, `Machine.spec.infrastructureRef`, `Machine.spec.bootstrap.configRef`                                                                        | Remaps top-down typed `corev1.ObjectReference` spec pointers with fresh live UIDs, ensuring controllers correctly bind parent and child resources.                    |
| `quiesceOnRestore` | `Cluster` → `cluster.x-k8s.io/paused: ""`                                                                                                                                                         | Injects pause annotation on `Cluster` creation during Phase 1A, freezing all CAPI reconcilers. Graph-free unquiescing removes the annotation upon restore completion. |


