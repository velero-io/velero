# Case Study 09: Strimzi Kafka (Distributed Streaming & KRaft Quorum)

This case study analyzes **Strimzi Kafka**, the CNCF incubating project that brings enterprise Apache Kafka streaming clusters to Kubernetes. It evaluates how Velero's dynamic owner-reference restore engine coordinates stateful distributed broker topologies, KRaft (Kafka Raft metadata mode) controller quorums, custom pod set controllers (`StrimziPodSet`), automated internal Public Key Infrastructure (PKI) certificate hierarchies, and native annotation-based controller quiescing (`strimzi.io/pause-reconciliation: "true"`).

---

## 1. Background & Problem Space

Apache Kafka is a distributed, partitioned, replicated commit-log service requiring strict cluster coordination, durable disk persistence, and identity preservation. Strimzi orchestrates Kafka on Kubernetes through a rich hierarchy of Custom Resource Definitions (CRDs):

- **`Kafka` (`kafka.strimzi.io/v1beta2`):** The top-level root custom resource defining the overall Kafka deployment, including listener configurations, storage definitions, internal PKI generation, and optional components (Entity Operator, Kafka Exporter, Cruise Control).
- **`KafkaNodePool` (`kafka.strimzi.io/v1beta2`):** Introduced in Strimzi for KRaft and flexible broker topologies. Manages homogeneous pools of nodes with assigned roles (`controller`, `broker`, or dual-role).
- **`StrimziPodSet` (`core.strimzi.io/v1beta2`):** A specialized workload controller designed by Strimzi to replace standard Kubernetes `StatefulSet`s. `StrimziPodSet` provides deterministic pod naming, non-disruptive rolling updates, and independent volume manipulation without the rigid scale-down constraints of `StatefulSet`.
- **`KafkaTopic` & `KafkaUser` (`kafka.strimzi.io/v1beta2`):** Managed by the Entity Operator (Topic Operator and User Operator). `KafkaTopic` synchronizes topic partitions and replica configurations, while `KafkaUser` provisions client mutual TLS (mTLS) certificates or SCRAM-SHA-512 authentication credentials.
- **`KafkaConnect` & `KafkaConnector` (`kafka.strimzi.io/v1beta2`):** Manages Kafka Connect data integration runtimes and individual source/sink connectors.
- **Internal PKI & Storage Volumes (`core/v1`):**
  - **Secrets:** Cluster CA key and cert (`<cluster>-cluster-ca`, `<cluster>-cluster-ca-cert`), Clients CA key and cert (`<cluster>-clients-ca`, `<cluster>-clients-ca-cert`), broker TLS certificates (`<cluster>-kafka-brokers`), and client authentication secrets.
  - **PersistentVolumeClaims:** Dedicated high-throughput block volumes bound to each broker/controller pod (e.g. `data-<pool>-<cluster>-kafka-<id>`).
  - **Services:** Headless bootstrap discovery services (`<cluster>-kafka-bootstrap`), internal discovery services, and per-broker nodeport/loadbalancer services.

Strimzi relies heavily on `metadata.ownerReferences` to maintain lifecycle cohesion across these resources. Because Kafka is an active state machine with distributed quorum consensus and strict TLS authentication, restoring Strimzi with stripped or unremapped references leads to instant cluster failure.

---

## 2. Resource Ownership Hierarchy

The Strimzi Kafka resource topology forms a 5-tier directed acyclic graph (DAG):

```text
STRIMZI KAFKA 5-TIER TOPOLOGY (KRAFT ARCHITECTURE)
================================================================================

  [ Kafka (kafka.strimzi.io) ]  <── Tier 1 (Streaming Cluster Root)
        │
        ├── (metadata.ownerReferences) ──► [ KafkaNodePool (brokers / controllers) ]  <── Tier 2
        │                                        │
        │                                        └── (metadata.ownerReferences) ──► [ StrimziPodSet ]  <── Tier 3
        │                                                                                  │
        │                                                                                  ├── (ownerRef) ──► [ Broker Pods (core/v1) ]  <── Tier 4
        │                                                                                  │
        │                                                                                  └── (ownerRef) ──► [ Broker PVCs (core/v1) ]  <── Tier 4
        │
        ├── (metadata.ownerReferences) ──► [ Cluster CA & Clients CA (Secrets) ]  <── Tier 2
        │                                        │
        │                                        └── (signs broker certs) ────────► [ Broker TLS Secret ]  <── Tier 3
        │
        ├── (metadata.ownerReferences) ──► [ Bootstrap & Broker Services (core/v1) ]  <── Tier 2
        │
        └── (label selector / managed) ──► [ KafkaUser / KafkaTopic ]  <── Tier 2
                                                 │
                                                 └── (metadata.ownerReferences) ──► [ User Credential Secret ]  <── Tier 3
```

### Reference Characteristics

1. **`Kafka` → `KafkaNodePool` → `StrimziPodSet`:**
   - In modern KRaft mode, `KafkaNodePool` specifies node counts, JVM settings, and storage topologies.
   - The Strimzi Cluster Operator creates a `StrimziPodSet` for each pool, attaching an `ownerReference` pointing to the `KafkaNodePool` with `controller: true` and `blockOwnerDeletion: true`.
   - In legacy or non-pool deployments, `StrimziPodSet` carries an `ownerReference` pointing directly to the root `Kafka` CR.
2. **`StrimziPodSet` → `Pod` & `PersistentVolumeClaim`:**
   - `StrimziPodSet` directly owns individual broker/controller pods (`<cluster>-<pool>-<id>`) via `metadata.ownerReferences`.
   - The underlying `PersistentVolumeClaim` resources (holding the commit logs and KRaft `__cluster_metadata` state) carry `metadata.ownerReferences` linking back to the `Kafka` CR or the managing `StrimziPodSet`.
3. **Internal PKI Secret Ownership (`Kafka` → CA Secrets → Broker Secrets):**
   - The Cluster CA (`<cluster>-cluster-ca`) and Clients CA (`<cluster>-clients-ca`) are generated as Kubernetes Secrets with `metadata.ownerReferences` pointing to the root `Kafka` CR.
   - Broker TLS certificate Secrets (`<cluster>-kafka-brokers`) are owned by the `Kafka` CR.
4. **`KafkaUser` → Credential Secrets:**
   - When a `KafkaUser` is defined with `authentication.type: tls`, the User Operator issues a client certificate and private key in a Secret named after the user.
   - The resulting Secret carries an `ownerReference` pointing to the `KafkaUser` CR.

---

## 3. Catastrophic Failure Modes Without Remapping

Restoring Strimzi Kafka with legacy Velero (all `ownerReferences` stripped without remapping, and controllers unquiesced) triggers severe cascading failures:

1. **PKI & CA Regeneration (Enterprise mTLS Shattering):**
   - In Phase 1A, Velero restores CA secrets (`<cluster>-cluster-ca`, `<cluster>-clients-ca`) with stripped ownerReferences.
   - If the Strimzi Cluster Operator reconciles concurrently while ownerReferences are missing, it assumes cluster PKI has not been bootstrapped.
   - The operator immediately generates a **new self-signed CA private key and certificate**.
   - The new CA automatically invalidates all existing broker TLS certificates and client user certificates. Every running Kafka producer, consumer, and streaming application across the organization is instantly locked out with SSL handshake failures (`SSLHandshakeException: Received fatal alert: certificate_unknown`).
2. **`StrimziPodSet` Orphanage & Broker Pod Collisions:**
   - When the `KafkaNodePool` or `Kafka` CR is created with a new UID, the existing `StrimziPodSet` (restored with stripped ownerReferences) appears unmanaged.
   - The active Strimzi Cluster Operator attempts to create a fresh `StrimziPodSet` with the same name.
   - The API server rejects the creation with `HTTP 409 Conflict: strimzipodsets.core.strimzi.io already exists`, leaving the cluster operator in an error loop and halting cluster reconciliation.
3. **KRaft Metadata Quorum Corruption & Split-Brain:**
   - KRaft controller nodes rely on persistent storage mounted at precise broker IDs and log directory paths to maintain Raft consensus (`__cluster_metadata-0`).
   - If broker pods or PVCs are restored without intact ownership and start out-of-order against an active operator, a newly spawned controller node may initialize an empty metadata log, causing partition epoch divergence, loss of topic definitions, and split-brain metadata consensus.
4. **Permanent Storage Orphanage (Leaked High-Throughput PVCs):**
   - If `PersistentVolumeClaim`s lose their `ownerReferences` to the managing `Kafka` or `StrimziPodSet`, deleting a decommissioned Kafka cluster removes the CRDs but leaves terabytes of provisioned NVMe block storage volumes orphaned in the cloud provider, resulting in massive recurring infrastructure costs.
5. **Entity Operator Connection Storms:**
   - If the Entity Operator (Topic Operator / User Operator) starts reconciling before Kafka broker listeners are fully established and authenticated, it enters a crash-loop backoff, failing to synchronize `KafkaTopic` and `KafkaUser` custom resources.

---

## 4. How the Velero Engine Handles Strimzi Kafka

Velero's owner-reference restore engine (`design.md`) completely prevents these failure modes through automated two-pass dynamic remapping and native controller quiescing:

```text
PHASE 1A: SYNCHRONOUS OBJECT CREATION & QUIESCING
================================================================================
  1. Injects annotation: strimzi.io/pause-reconciliation: "true" onto:
     - Kafka (kafka.strimzi.io)
     - KafkaNodePool (kafka.strimzi.io)
     - KafkaConnect (kafka.strimzi.io)
  2. Creates Kafka, KafkaNodePool, StrimziPodSet, Secrets, ConfigMaps, PVCs cleanly.
  3. Strimzi Cluster Operator detects pause annotation:
     -> Reconciliation is completely halted!
     -> No CA regeneration, no duplicate StrimziPodSet creation, no broker race.
  4. Records in-memory mappings: uidMap[oldBackupUID] = newLiveUID.


PHASE 1B (PASS 1): DYNAMIC IN-MEMORY REMAPPING
================================================================================
  1. Remaps StrimziPodSet.metadata.ownerReferences -> live KafkaNodePool UID.
  2. Remaps KafkaNodePool.metadata.ownerReferences -> live Kafka UID.
  3. Remaps CA Secrets & Broker Secrets -> live Kafka UID.
  4. Remaps User Credential Secrets -> live KafkaUser UID.
  5. Remaps PersistentVolumeClaims -> live Kafka / StrimziPodSet UID.
  6. Evaluates Built-in Pod Deny List:
     -> Raw broker Pods (core/v1/Pod) are skipped from direct remapping.
     -> StrimziPodSet controller naturally adopts/manages broker pods.


UNQUIESCE RESOLUTION: GRAPH-FREE EVALUATION
================================================================================
  1. All pending patches for CA Secrets, PVCs, and StrimziPodSets succeed.
  2. CanUnquiesce(Kafka) evaluates to TRUE.
  3. Velero removes annotation: strimzi.io/pause-reconciliation from Kafka & NodePools.
  4. Strimzi Cluster Operator awakens:
     -> Discovers intact, live CA certificates (preserves existing PKI).
     -> Discovers existing, remapped StrimziPodSets.
     -> Connects to restored PVCs and verifies KRaft log consistency.
     -> Kafka cluster starts cleanly with zero data loss and valid client mTLS!
```

### Key Architectural Guarantees for Strimzi

1. **Native Pause Annotation Integration (`strimzi.io/pause-reconciliation: "true"`):**
   Strimzi natively supports reconciliation pausing via annotations. In Phase 1A create, Velero injects `strimzi.io/pause-reconciliation: "true"`. The Strimzi operator updates its status condition to `ReconciliationPaused: True` and immediately yields, allowing Velero to restore all secrets, PVCs, and intermediate CRDs without racing against active reconcilers.
2. **PKI & CA Secret Preservation:**
   Because CA secrets are remapped to the new `Kafka` UID *before* the operator is unquiesced, the operator detects the existing CA on its first active reconciliation cycle, entirely preventing catastrophic CA regeneration.
3. **Storage Binding via Name and OwnerReference:**
   Strimzi volumes bind using deterministic PVC naming conventions combined with `metadata.ownerReferences`. Velero preserves the PVC names and re-attaches the live UIDs, ensuring that broker pods mount the exact storage volumes containing their partition data.
4. **Workload Boundary Enforcement (Pod Deny List):**
   Velero's built-in deny list skips `core/v1/Pod` remapping. The restored `StrimziPodSet` claims the broker pods naturally, avoiding conflicting ownership metadata.

---

## 5. Strimzi Kafka ConfigMap Definition

To restore Strimzi Kafka workloads with dynamic owner-reference remapping and automated controller quiescing, deploy the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-strimzi-kafka
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope defines API groups and kinds eligible for ownerReference remapping.
  # Enables Strimzi Kafka core resources, pod sets, secrets, PVCs, and services.
  inScope: |
    - group: kafka.strimzi.io
    - group: core.strimzi.io
    - group: ""
      kind: PersistentVolumeClaim
    - group: ""
      kind: Secret
    - group: ""
      kind: ConfigMap
    - group: ""
      kind: Service

  # 2. specRefPaths: Empty (Strimzi references clusters and pools by logical name and labels).
  specRefPaths: ""

  # 3. quiesceOnRestore: Native Strimzi pause annotations injected during Phase 1A create.
  quiesceOnRestore: |
    - group: kafka.strimzi.io
      kind: Kafka
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
    - group: kafka.strimzi.io
      kind: KafkaNodePool
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
    - group: kafka.strimzi.io
      kind: KafkaConnect
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
    - group: kafka.strimzi.io
      kind: KafkaMirrorMaker2
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
    - group: kafka.strimzi.io
      kind: KafkaBridge
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
    - group: kafka.strimzi.io
      kind: KafkaTopic
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
    - group: kafka.strimzi.io
      kind: KafkaUser
      annotationKey: strimzi.io/pause-reconciliation
      annotationValue: "true"
```

### Field Breakdown

- **`inScope`:**
  - `kafka.strimzi.io`: Remaps parent-child links between `KafkaNodePool`, `KafkaTopic`, `KafkaUser`, and `Kafka`.
  - `core.strimzi.io`: Remaps `StrimziPodSet` back to `KafkaNodePool` or `Kafka`.
  - `PersistentVolumeClaim`: Restores ownership links on broker storage volumes, ensuring cascading garbage collection and lifecycle protection.
  - `Secret`: Remaps cluster CA, clients CA, broker TLS, and user authentication secrets.
  - `ConfigMap` & `Service`: Remaps broker bootstrap, metrics, and network routing configurations.
- **`specRefPaths`:** Left empty (`""`) because Strimzi links components using logical resource names and labels (e.g. `spec.cluster: my-cluster`, `strimzi.io/cluster: my-cluster`) rather than foreign object UIDs.
- **`quiesceOnRestore`:** Configures `strimzi.io/pause-reconciliation: "true"` across all Strimzi custom resources. This silences the Cluster Operator, Topic Operator, and User Operator during Phase 1A creation until Phase 1B remapping completes.

---

## 6. Architectural Evaluation & Operational Comparison

| Operational Dimension | Legacy Velero Restore (Stripped OwnerRefs) | Restore Without Quiescing | Velero Dynamic Remapping + Quiescing Engine |
| :--- | :--- | :--- | :--- |
| **PKI & CA Stability** | **Catastrophic Failure**: CA regenerated; all broker/client TLS certs invalidated. | **Race Condition**: Operator may regenerate CA before secrets are restored. | **100% Preserved**: Quiesced operator awaits restored CA secrets; mTLS remains fully intact. |
| **Workload Controller (`StrimziPodSet`)** | **Orphaned**: Operator attempts duplicate creation; fails with `HTTP 409 Conflict`. | **Collision**: StrimziPodSet creation races against restore. | **Clean Adoption**: Re-linked to `KafkaNodePool`; adopts existing broker pods. |
| **Storage Binding (PVCs)** | **Detached**: PVCs lose ownerReferences; deleted clusters leak cloud storage volumes. | **Uncertain**: PVCs may be adopted or orphaned depending on timing. | **Fully Bound**: PVC ownerReferences restored to live UIDs; cascading GC preserved. |
| **Consensus & Quorum (KRaft / ZooKeeper)** | **Split-Brain Risk**: Controllers start with out-of-sync storage mounts; log divergence. | **High Risk**: Premature broker startup corrupts metadata logs. | **Orderly Startup**: Brokers start only after storage and identity mappings are finalized. |
| **Operator Reconciliation Duel** | **Severe**: Operator fights restored resources continuously. | **Severe**: High API server write pressure and lock conflicts. | **Zero Contention**: Operator remains paused until all resources are in a consistent state. |
