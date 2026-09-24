# Case Studies: Multi-Hop OwnerReference Structures in the Kubernetes Ecosystem

This directory contains in-depth case studies analyzing complex, multi-hop `metadata.ownerReferences` and `spec.*Ref` dependency graphs found across prominent Kubernetes declarative ecosystems. It evaluates how Velero's **OwnerReference-Aware Restore & Controller Quiescing Engine** (`../design.md`) processes these hierarchies during disaster recovery and namespace migration.

---

## 1. Executive Summary & Ecosystem Comparison

While Cluster API (CAPI) is the primary baseline implementation for the owner-reference remapping engine, deep ownership DAGs are ubiquitous across Kubernetes operators. Declarative operators frequently decompose complex operational lifecycles into multi-tiered intermediate Custom Resource Definitions (CRDs), culminating in hierarchies that reach **3 to 6 tiers in depth**.

### Cross-Ecosystem Comparison Matrix

| System | Domain / Workload | Max Depth | Typical Ownership Hierarchy | Dual-Pointer Pattern (`spec.*Ref` + `ownerRefs`) | Upstream Pause Annotation Support | Catastrophic Failure Mode if Restored Unmapped |
| :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| **Cluster API (CAPI)** | Multi-Cloud Cluster Lifecycle | 5 | `Cluster` → `MachineDeployment` → `MachineSet` → `Machine` → `VSphereMachine` | **Yes** (`spec.infrastructureRef`, `spec.bootstrap.configRef`) | **Yes** (`cluster.x-k8s.io/paused: ""`) | Duplicate cloud VM provisioning; orphaned nodes; broken cascading teardown. |
| **cert-manager** | Automated TLS & ACME Protocol | 5 | `Certificate` → `CertificateRequest` → `Order` → `Challenge` → `Ingress/Pod` | Partial (`spec.secretName`) | **No** (Short-lived state machines) | Let's Encrypt rate-limit burnout; orphaned HTTP-01 solver ingresses and pods. |
| **Knative Serving** | Serverless Workload Orchestration | 6 | `Service` → `Configuration` → `Revision` → `Deployment` → `ReplicaSet` → `Pod` | Partial (Traffic splits, `spec.template`) | **No** (Community advocacy target) | Infinite revision regeneration loops; orphaned Deployments; decoupled autoscalers. |
| **KubeVirt** | Cloud-Native Virtualization | 5 | `VirtualMachinePool` → `VirtualMachine` → `VirtualMachineInstance` → `virt-launcher Pod` | **No** (Name-based volume binding) | **No** (Spec-field driven: `spec.running` / `spec.runStrategy`) | Split-brain VM execution; duplicate hypervisor pods; disk lock collision on PVCs. |
| **Crossplane** | Cloud Infrastructure as Code | 5 | `Claim` → `Parent XR` → `Child XR` → `Managed Resource` → `Secret` | **Yes** (`spec.resourceRefs[*]`, `spec.claimRef`) | **Yes** (`crossplane.io/paused: "true"`) | Duplicate public cloud databases/VPCs; leaked cloud infrastructure; billing spikes. |
| **Tekton Pipelines** | Cloud-Native CI/CD Orchestration | 5 | `PipelineRun` → `TaskRun` → `Pod` / `PersistentVolumeClaim` | **No** (String names in `.spec`) | **No** (Uses `spec.status: PipelineRunPending`) | Pipeline run storms upon status reset; orphaned workspace PVCs and storage leaks; permanently orphaned task pods. |
| **Flux v2** | GitOps Continuous Delivery & Helm | 4 | `GitRepository` → `Kustomization` (parent) → `Kustomization` (child); or `HelmRelease` → `HelmChart` | Partial (`spec.sourceRef` by name) | **Yes** (`kustomize.toolkit.fluxcd.io/reconcile: disabled`, `helm.toolkit.fluxcd.io/reconcile: disabled`) | Duplicate `HelmChart` generation conflicts; orphaned chart artifacts; premature reconciliation race conditions. |
| **Argo CD** | Declarative GitOps Application Delivery | 4 | `ApplicationSet` → `Application` → Managed Workloads (`ownerReference` tracking method) | Partial (`spec.project`, `spec.source`) | **No** (Uses `spec.syncPolicy.automated`; community advocacy target) | `ApplicationSet` application duplication/orphanage; catastrophic workload pruning (`prune: true`); GitOps self-healing duels if `.spec` mutated. |
| **Strimzi Kafka** | Distributed Streaming & KRaft Quorum | 5 | `Kafka` → `KafkaNodePool` → `StrimziPodSet` → `Pod` / `PersistentVolumeClaim` | **No** (Name and label-based references) | **Yes** (`strimzi.io/pause-reconciliation: "true"`) | PKI CA regeneration invalidating all broker/client TLS certs; `StrimziPodSet` collision; KRaft log split-brain; orphaned PVC storage. |
| **CloudNativePG** | Enterprise PostgreSQL & HA | 4 | `Cluster` → `Pooler` / `PersistentVolumeClaim` → `Instance Pod` / `Secret` | **No** (String names in `spec.cluster.name`) | **Yes** (`cnpg.io/reconciliationLoop: "disabled"`) | Primary split-brain election and WAL timeline fork; database credential/TLS regeneration; immediate GC deletion of instance PVCs. |

---

## 2. Architectural Analysis: Multi-Hop Mechanics in Velero

Velero's owner-reference restore engine was specifically designed to handle arbitrary depth without the algorithmic fragility of topological sorting or DAG sidecars.

```
PHASE 1A: SYNCHRONOUS OBJECT CREATION (DEPTH-AGNOSTIC)
================================================================================
  All objects created with ownerReferences stripped.
  In-memory registration: uidMap[oldBackupUID] = newLiveUID
  In-memory parent graph: parentMap[childOldUID] = []parentOldUIDs

  [ Tier 1: Root Parent ]  ──────► Created live, new UID recorded in uidMap
           │
  [ Tier 2: Intermediate ] ──────► Created live, new UID recorded in uidMap
           │
  [ Tier 3: Leaf Child ]   ──────► Created live, new UID recorded in uidMap


PHASE 1B (PASS 1): IMMEDIATE IN-MEMORY REMAPPING ($O(1)$ LOOKUP)
================================================================================
  Iterates over queued patch requests. For every object at any depth:
  liveParentUID = uidMap[backupParentUID]  ──► Merge patch metadata.ownerReferences


FAILURE RESOLUTION: TRANSITIVE QUIESCE ROOT PROPAGATION (BFS)
================================================================================
  If Tier 3 Leaf Child encounters retriable HTTP 409 Conflict:

    [ Tier 3 Patch Failed ]
              │ (Traverse parentMap via BFS)
              ▼
    [ Tier 2 Intermediate ] (Not quiesced)
              │ (Traverse parentMap via BFS)
              ▼
    [ Tier 1 Quiesced Root ] ──► Appended to Tier 3's pendingPatch.Targets[]

  Graph-Free Independent Evaluation (CanUnquiesce):
    CanUnquiesce(Tier 1 Root) evaluates to FALSE because it appears in Targets[].
    RESULT: Root stays paused until Tier 3 leaf patch succeeds!
```

### Key Architectural Guarantees for Multi-Hop Structures

1. **Depth-Agnostic $O(1)$ Remapping:**
   Because Phase 1A creates all resources prior to Phase 1B, the new UIDs for parents at *every* level already exist in `uidMap`. Remapping a 6-hop Knative chain takes the exact same $O(1)$ hash map lookup per reference as a 1-hop link.
2. **The "Leaky Intermediate" Protection (Transitive Root Propagation):**
   In declarative architectures (such as CAPI and Crossplane), intermediate resources (`MachineSet`, `Child XR`) are never directly quiesced; child controllers check whether their **root ancestor** is paused before reconciling. If a leaf node fails to patch an ownerReference or a spec-level pointer, a naive 1-hop rule would unpause the root because the leaf points to an intermediate or peer, not the root. Velero's in-memory BFS traverses `parentMap` and populates the root ancestor into `pendingPatch.Targets` (or marks it `UnquiesceBlocked` if non-retriable), guaranteeing that the root remains paused until the entire chain is healthy.
3. **Immutability Tolerance:**
   Many deep architectures contain immutable CRD tiers (e.g. Knative `Revision`). Because `metadata.ownerReferences` is part of Kubernetes object metadata rather than `.spec`, Velero can patch ownerReferences on immutable objects without triggering admission webhook rejections.
4. **Workload Boundary Enforcement:**
   Velero maintains a strict built-in deny list for leaf workloads (`core/v1/Pod`, `apps/v1/ReplicaSet`, `core/v1/ReplicationController`, `batch/v1/Job`). Intermediate controllers that manage Pods or ReplicaSets via label selectors are allowed to adopt them naturally, preventing dual-controller ownership conflicts.

---

## 3. Case Study Index

Explore the detailed analysis, architecture diagrams, and custom ConfigMaps for each ecosystem:

- **[Case Study 01: Cluster API (CAPI)](./01-cluster-api.md)**
  - Examines multi-cloud cluster lifecycle management and the primary baseline reference implementation.
  - Analyzes bidirectional dual-pointer remapping (`metadata.ownerReferences` and `spec.*Ref`), out-of-order restoration tolerance, automated controller quiescing (`cluster.x-k8s.io/paused`), status regeneration guarantees (`clusterctl move` contract), and live zero-duplicate container adoption.
  - Includes `velero-ownerref-capi.yaml`.

- **[Case Study 02: cert-manager](./02-cert-manager.md)**
  - Examines multi-stage ACME certificate issuance and challenge-solver state machines.
  - Analyzes transient HTTP-01/DNS-01 solver garbage collection and Let's Encrypt rate-limit prevention.
  - Includes `velero-ownerref-cert-manager.yaml`.

- **[Case Study 03: Knative Serving](./03-knative-serving.md)**
  - Examines the deepest CRD DAG in Kubernetes (6 tiers).
  - Analyzes immutable `Revision` metadata patching and serverless autoscaler coordination.
  - Includes `velero-ownerref-knative.yaml`.

- **[Case Study 04: KubeVirt](./04-kubevirt.md)**
  - Examines virtualization workloads and the runtime `VirtualMachineInstance` lifecycle.
  - Analyzes storage management via `cdi.kubevirt.io/DataVolume` and operator-owned PVC remapping.
  - Includes `velero-ownerref-kubevirt.yaml`.

- **[Case Study 05: Crossplane](./05-crossplane.md)**
  - Examines nested Composite Resources (XRs) and Managed Resources (MRs).
  - Analyzes array wildcard spec remapping (`spec.resourceRefs[*].uid`) and native `crossplane.io/paused` integration.
  - Includes `velero-ownerref-crossplane.yaml`.

- **[Case Study 06: Tekton Pipelines](./06-tekton.md)**
  - Examines cloud-native CI/CD workflows, dynamic workspace storage PVCs, and run-once batch execution semantics.
  - Analyzes `TaskRun -> Pod` direct ownership, built-in Pod deny list interaction, and `.status` restoration requirements.
  - Includes `velero-ownerref-tekton.yaml`.

- **[Case Study 07: Flux v2](./07-flux-v2.md)**
  - Examines GitOps continuous delivery pipelines, automated Helm chart lifecycle management, and cross-resource ownership DAGs.
  - Analyzes dynamic `HelmRelease -> HelmChart` ownerReference remapping, native annotation-based controller quiescing (`reconcile: disabled`), and preservation of operator-suspended states.
  - Includes `velero-ownerref-flux.yaml`.

- **[Case Study 08: Argo CD](./08-argo-cd.md)**
  - Examines declarative GitOps application delivery, multi-cluster `ApplicationSet` generators, and resource tracking models (`ownerReference` vs `annotation`).
  - Analyzes catastrophic workload auto-pruning prevention, the architectural dilemma of controller quiescing without native annotations, why `specFieldPath` mutations are permanently excluded from Velero core, and out-of-band `ResourceModifier` boundaries.
  - Includes `velero-ownerref-argocd.yaml`.

- **[Case Study 09: Strimzi Kafka](./09-strimzi-kafka.md)**
  - Examines stateful distributed streaming broker topologies, KRaft metadata quorums, custom pod set controllers (`StrimziPodSet`), and internal PKI certificate hierarchies.
  - Analyzes cluster and client CA preservation, direct broker PVC remapping, native annotation-based controller quiescing (`strimzi.io/pause-reconciliation: "true"`), and built-in pod deny list coordination.
  - Includes `velero-ownerref-strimzi-kafka.yaml`.

- **[Case Study 10: CloudNativePG](./10-cloudnative-pg.md)**
  - Examines enterprise high-availability PostgreSQL clusters, custom instance manager pods, and database replication timelines.
  - Analyzes direct `Cluster -> PVC` ownership remapping, primary split-brain and WAL timeline fork prevention, database credential and TLS certificate preservation, and native annotation-based controller quiescing (`cnpg.io/reconciliationLoop: "disabled"`).
  - Includes `velero-ownerref-cloudnativepg.yaml`.

---

## 4. Ready-to-Apply ConfigMap Manifests

Production-ready ConfigMap definitions conforming to the 3-section schema (`inScope`, `specRefPaths`, `quiesceOnRestore`) are provided in the [`configmaps/`](./configmaps/) directory:

- [`configmaps/velero-ownerref-capi.yaml`](./configmaps/velero-ownerref-capi.yaml)
- [`configmaps/velero-ownerref-cert-manager.yaml`](./configmaps/velero-ownerref-cert-manager.yaml)
- [`configmaps/velero-ownerref-knative.yaml`](./configmaps/velero-ownerref-knative.yaml)
- [`configmaps/velero-ownerref-kubevirt.yaml`](./configmaps/velero-ownerref-kubevirt.yaml)
- [`configmaps/velero-ownerref-crossplane.yaml`](./configmaps/velero-ownerref-crossplane.yaml)
- [`configmaps/velero-ownerref-tekton.yaml`](./configmaps/velero-ownerref-tekton.yaml)
- [`configmaps/velero-ownerref-flux.yaml`](./configmaps/velero-ownerref-flux.yaml)
- [`configmaps/velero-ownerref-argocd.yaml`](./configmaps/velero-ownerref-argocd.yaml)
- [`configmaps/velero-ownerref-strimzi-kafka.yaml`](./configmaps/velero-ownerref-strimzi-kafka.yaml)
- [`configmaps/velero-ownerref-cloudnativepg.yaml`](./configmaps/velero-ownerref-cloudnativepg.yaml)
