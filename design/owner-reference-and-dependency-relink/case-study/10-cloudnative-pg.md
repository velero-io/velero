# Case Study 10: CloudNativePG (Enterprise PostgreSQL & High Availability)

This case study analyzes **CloudNativePG (CNPG)**, the leading Kubernetes-native operator for managing highly available enterprise PostgreSQL database clusters. It evaluates how Velero's dynamic owner-reference restore engine coordinates stateful database instance topologies, custom instance manager pods, operator-owned PersistentVolumeClaims, automated PKI certificate and credential hierarchies, and native annotation-based controller quiescing (`cnpg.io/reconciliationLoop: "disabled"`).

---

## 1. Background & Problem Space

PostgreSQL is a relational database management system with rigorous ACID transactional requirements, Write-Ahead Logging (WAL), and streaming replication timelines. CloudNativePG orchestrates PostgreSQL on Kubernetes through specialized Custom Resource Definitions (CRDs):

- **`Cluster` (`postgresql.cnpg.io/v1`):** The primary root custom resource representing a PostgreSQL cluster. It defines node count (primary and read-only standbys), storage specifications, high-availability policies, WAL archiving, backup configurations, and bootstrap modes (initdb, recovery, pg_basebackup).
- **`Pooler` (`postgresql.cnpg.io/v1`):** Manages a deployment of PgBouncer connection poolers sitting between client applications and the PostgreSQL cluster, handling authentication pass-through and connection reuse.
- **`Backup` & `ScheduledBackup` (`postgresql.cnpg.io/v1`):** Manages on-demand and cron-scheduled physical backups using Barman Cloud or Kubernetes volume snapshots.
- **`Publication` & `Subscription` (`postgresql.cnpg.io/v1`):** Declarative abstractions for PostgreSQL logical replication between clusters.
- **Instance Pods & Custom Instance Manager (`core/v1/Pod`):**
  - Unlike many database operators that rely on Kubernetes `StatefulSet`s, **CloudNativePG manages instance pods directly** (`<cluster>-1`, `<cluster>-2`, `<cluster>-3`).
  - CNPG uses a custom instance manager injected as the init and PID 1 process inside the PostgreSQL container. This gives the operator fine-grained control over fencing, promotion, failover, WAL archiving, and rolling updates without the rigid scale-down limitations of `StatefulSet`.
- **Operator-Owned Storage & Secrets (`core/v1`):**
  - **PersistentVolumeClaims:** Dedicated PVCs for database data (`<cluster>-1`, `<cluster>-2`, etc. for `$PGDATA`) and dedicated WAL storage (`<cluster>-1-wal`, etc.). **Crucially, CloudNativePG attaches `metadata.ownerReferences` directly from the `Cluster` CR to every instance PVC**.
  - **Secrets:** Generated server PKI certificates (`<cluster>-server-ca`, `<cluster>-server`), client PKI certificates (`<cluster>-client-ca`), and database credentials (`<cluster>-superuser`, `<cluster>-app`). All carry `metadata.ownerReferences` pointing to the `Cluster` CR.
  - **Services:** High-availability routing endpoints (`<cluster>-rw` for primary read-write, `<cluster>-ro` for replicas, `<cluster>-r` for any instance, and `<cluster>-any` for internal replication).

Because PostgreSQL instances must agree on WAL log sequence numbers (LSN) and election epochs, restoring CloudNativePG with stripped or unremapped references leads to instant primary split-brain and permanent database corruption.

---

## 2. Resource Ownership Hierarchy

The CloudNativePG resource topology forms a 4-tier directed acyclic graph (DAG):

```text
CLOUDNATIVEPG 4-TIER TOPOLOGY (HIGH AVAILABILITY ARCHITECTURE)
================================================================================

  [ Cluster (postgresql.cnpg.io) ]  <── Tier 1 (PostgreSQL Cluster Root)
        │
        ├── (metadata.ownerReferences) ──► [ Pooler / PgBouncer (postgresql.cnpg.io) ]  <── Tier 2
        │                                        │
        │                                        └── (ownerRef) ──► [ PgBouncer Deployment / Pods ]  <── Tier 3
        │
        ├── (metadata.ownerReferences) ──► [ PersistentVolumeClaims (core/v1) ]  <── Tier 2
        │                                        │ (<cluster>-1, <cluster>-2, <cluster>-3: PGDATA + WAL)
        │                                        │
        │                                        └── (mounted by) ──► [ PostgreSQL Instance Pods ]  <── Tier 3
        │
        ├── (metadata.ownerReferences) ──► [ Server & Client PKI Secrets (core/v1) ]  <── Tier 2
        │                                        │ (<cluster>-server-ca, <cluster>-server)
        │
        ├── (metadata.ownerReferences) ──► [ Database Credential Secrets (core/v1) ]  <── Tier 2
        │                                        │ (<cluster>-app, <cluster>-superuser)
        │
        ├── (metadata.ownerReferences) ──► [ High-Availability Services (core/v1) ]  <── Tier 2
        │                                        │ (<cluster>-rw, <cluster>-ro, <cluster>-r, <cluster>-any)
        │
        └── (metadata.ownerReferences) ──► [ ScheduledBackup / Backup (postgresql.cnpg.io) ]  <── Tier 2
```

### Reference Characteristics

1. **Direct `Cluster` → `PersistentVolumeClaim` Ownership:**
   - In CloudNativePG, instance storage volumes (`<cluster>-1`, `<cluster>-2`, `<cluster>-3`) are directly owned by the `Cluster` custom resource.
   - The PVCs carry `metadata.ownerReferences` pointing to `Cluster` with `controller: true` and `blockOwnerDeletion: true`.
   - This design ensures that Kubernetes garbage collection cleans up disk claims when a database cluster is deleted, preventing storage leaks.
2. **`Cluster` → PKI & Credential Secrets:**
   - The operator generates internal CA certificates and user credentials during cluster bootstrap.
   - All generated Secrets carry `metadata.ownerReferences` pointing to `Cluster`.
3. **`Cluster` → `Pooler` & `Service`:**
   - Connection poolers (`Pooler`) and Kubernetes Services (`<cluster>-rw`, `<cluster>-ro`) carry `metadata.ownerReferences` pointing to `Cluster`.
   - `Pooler` specifies the target cluster via plain string name (`spec.cluster.name: <cluster-name>`), while tracking lifecycle and deletion through `metadata.ownerReferences`.
4. **Instance Pod Lifecycle Management:**
   - Pods are created by the CNPG controller and linked to both the `Cluster` and the instance PVCs.
   - CNPG instance pods mount existing PVCs based on predictable ordinal naming (`<cluster>-<index>`).

---

## 3. Catastrophic Failure Modes Without Remapping

Restoring CloudNativePG with legacy Velero (all `ownerReferences` stripped without remapping, and controllers unquiesced) triggers catastrophic data and operational failures:

1. **Split-Brain Primary Election & WAL Timeline Fork (Permanent Data Corruption):**
   - In Phase 1A, Velero creates the `Cluster` CR with a new cluster UID and restores instance PVCs with stripped ownerReferences.
   - If the CloudNativePG operator reconciles while PVC ownership is missing or in-flight, it fails to associate existing instance volumes with the cluster.
   - The operator may conclude that the cluster is uninitialized and execute a **fresh `initdb` on a newly provisioned volume**, or elect an arbitrary standby instance as the primary while the real primary's volume is still restoring.
   - Standby promotion on divergent storage creates a new WAL timeline history (`history mismatch`). When the original primary volume is eventually attached, its WAL timeline diverges from the new primary, causing unrecoverable replication forks and permanent database corruption.
2. **Database Credential & PKI Regeneration (Application Authentication Lockout):**
   - If database secret credentials (`<cluster>-app`, `<cluster>-superuser`) and server TLS certificates are restored without valid ownerReferences, the CNPG operator treats them as missing.
   - The operator regenerates new random database passwords and issues new server TLS certificates.
   - All application microservices connecting with previously backed-up credentials immediately fail with `FATAL: password authentication failed for user "app"`, causing widespread application downtime across the organization.
3. **Instant API Server Garbage Collection of Live Database Volumes:**
   - If instance PVCs are restored with stale parent UIDs in `metadata.ownerReferences`, the Kubernetes API server's Garbage Collector determines that the parent `Cluster` does not exist.
   - The Garbage Collector immediately issues `DELETE` requests against the restored PVCs, **wiping out live production database storage in seconds**.
4. **Permanent Storage Orphanage (Leaked High-IOPS Cloud Disks):**
   - If `PersistentVolumeClaim`s are restored with stripped ownerReferences and never remapped, deleting the database `Cluster` CR deletes the metadata but leaves expensive, multi-terabyte high-IOPS NVMe disks orphaned in the cloud provider indefinitely.
5. **Connection Pooler (PgBouncer) Routing Blackholes:**
   - If `Pooler` loses its `metadata.ownerReferences` to `Cluster`, PgBouncer instances fail to track primary failover events.
   - Client traffic routed through PgBouncer continues attempting to write to demoted standbys or terminating pods, leading to query failures (`FATAL: cannot execute INSERT in a read-only transaction`).

---

## 4. How the Velero Engine Handles CloudNativePG

Velero's owner-reference restore engine (`design.md`) resolves these challenges through dynamic two-pass remapping and native controller quiescing:

```text
PHASE 1A: SYNCHRONOUS OBJECT CREATION & QUIESCING
================================================================================
  1. Injects annotation: cnpg.io/reconciliationLoop: "disabled" onto:
     - Cluster (postgresql.cnpg.io)
     - Pooler (postgresql.cnpg.io)
  2. Creates Cluster, Pooler, Secrets, ConfigMaps, PVCs cleanly.
  3. CloudNativePG controller inspects annotation:
     -> Reconciliation loop is completely skipped!
     -> No premature initdb, no split-brain primary election, no credential regeneration.
  4. Records in-memory mappings: uidMap[oldBackupUID] = newLiveUID.


PHASE 1B (PASS 1): DYNAMIC IN-MEMORY REMAPPING
================================================================================
  1. Remaps PersistentVolumeClaims (<cluster>-1, -2, -3) -> live Cluster UID.
  2. Remaps Database Credential Secrets (<cluster>-app, -superuser) -> live Cluster UID.
  3. Remaps Server/Client TLS PKI Secrets -> live Cluster UID.
  4. Remaps Services (<cluster>-rw, -ro, -r, -any) -> live Cluster UID.
  5. Remaps Pooler (PgBouncer) -> live Cluster UID.
  6. Evaluates Built-in Pod Deny List:
     -> Raw instance Pods (core/v1/Pod) are skipped from direct remapping.
     -> CNPG controller creates/boots instance manager pods against remapped PVCs.


UNQUIESCE RESOLUTION: GRAPH-FREE EVALUATION
================================================================================
  1. All pending patches for database PVCs, secrets, and poolers succeed.
  2. CanUnquiesce(Cluster) evaluates to TRUE.
  3. Velero removes annotation: cnpg.io/reconciliationLoop from Cluster & Pooler.
  4. CloudNativePG controller awakens:
     -> Discovers existing, remapped instance PVCs with intact $PGDATA.
     -> Inspects WAL records and identifies the latest consistent primary.
     -> Discovers existing, remapped credential Secrets and TLS certificates.
     -> Elects the valid primary, starts streaming replication standbys, and activates services.
```

### Key Architectural Guarantees for CloudNativePG

1. **Native Pause Annotation Integration (`cnpg.io/reconciliationLoop: "disabled"`):**
   CloudNativePG natively honors the `cnpg.io/reconciliationLoop: "disabled"` annotation. When injected during Phase 1A creation, the CNPG operator immediately pauses reconciliation for that cluster. This provides complete silence during storage restoration and UID patching.
2. **Direct PVC Ownership Re-attachment:**
   Because CNPG assigns `metadata.ownerReferences` directly from `Cluster` to `PersistentVolumeClaim`, Velero's Phase 1B pass updates every PVC with the new `Cluster` UID. This preserves cascading garbage collection upon deletion and prevents stale-UID deletion by the API server.
3. **Database Credential & PKI Integrity:**
   Database passwords and server TLS certificates in Secrets are re-linked to the live `Cluster` UID before the operator unquiesces. The operator discovers existing credentials and avoids generating new passwords, ensuring existing applications authenticate seamlessly.
4. **Workload Boundary Enforcement (Pod Deny List):**
   Velero skips direct remapping of `core/v1/Pod`. Once unquiesced, the CNPG operator manages instance pod creation cleanly, injecting its custom instance manager binary and configuring PostgreSQL parameters against the restored PVC storage.

---

## 5. CloudNativePG ConfigMap Definition

To restore CloudNativePG workloads with dynamic owner-reference remapping and automated controller quiescing, deploy the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-cloudnativepg
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope defines API groups and kinds eligible for ownerReference remapping.
  # Enables CloudNativePG database clusters, poolers, secrets, PVCs, and services.
  inScope: |
    - group: postgresql.cnpg.io
    - group: ""
      kind: PersistentVolumeClaim
    - group: ""
      kind: Secret
    - group: ""
      kind: ConfigMap
    - group: ""
      kind: Service

  # 2. specRefPaths: Empty (CloudNativePG references clusters by string name in spec.cluster.name).
  specRefPaths: ""

  # 3. quiesceOnRestore: Native CNPG pause annotations injected during Phase 1A create.
  quiesceOnRestore: |
    - group: postgresql.cnpg.io
      kind: Cluster
      annotationKey: cnpg.io/reconciliationLoop
      annotationValue: "disabled"
    - group: postgresql.cnpg.io
      kind: Pooler
      annotationKey: cnpg.io/reconciliationLoop
      annotationValue: "disabled"
```

### Field Breakdown

- **`inScope`:**
  - `postgresql.cnpg.io`: Remaps parent-child relationships between `Cluster`, `Pooler`, `Backup`, and `ScheduledBackup`.
  - `PersistentVolumeClaim`: Restores direct ownership links from `Cluster` to instance storage volumes (`<cluster>-<index>` for `$PGDATA` and WAL).
  - `Secret`: Remaps database user passwords (`<cluster>-app`, `<cluster>-superuser`) and server/client TLS certificates.
  - `ConfigMap` & `Service`: Remaps cluster configurations and high-availability endpoints (`<cluster>-rw`, `<cluster>-ro`).
- **`specRefPaths`:** Left empty (`""`) because CloudNativePG references target clusters using plain string names (e.g. `spec.cluster.name: my-pg-cluster`) rather than foreign object UIDs.
- **`quiesceOnRestore`:** Configures `cnpg.io/reconciliationLoop: "disabled"` on `Cluster` and `Pooler`. This halts the CNPG instance manager and reconciler during Phase 1A object creation, completely eliminating split-brain primary elections and credential regeneration during restoration.

---

## 6. Architectural Evaluation & Operational Comparison

| Operational Dimension | Legacy Velero Restore (Stripped OwnerRefs) | Restore Without Quiescing | Velero Dynamic Remapping + Quiescing Engine |
| :--- | :--- | :--- | :--- |
| **Data Consistency & WAL Timeline** | **Catastrophic Failure**: Unowned PVCs trigger `initdb` or wrong primary election; divergent WAL timeline. | **High Risk**: Reconciler races against PVC restore; potential split-brain failover. | **100% Consistent**: Quiesced operator discovers existing PVCs and WAL history; elects consistent primary. |
| **Database Credentials & PKI** | **Regenerated**: Operator generates new passwords and TLS certs; all applications fail auth. | **Race Condition**: Operator may regenerate secrets before restore finishes. | **100% Preserved**: Restored secrets remapped to live `Cluster` UID before unquiescing. |
| **Storage Volume Ownership (PVCs)** | **Detached**: PVCs lose `ownerReferences`; deleted clusters leak expensive cloud block storage. | **Uncertain**: PVCs may be adopted or orphaned depending on restore order. | **Fully Remapped**: Direct `Cluster -> PVC` ownerReferences restored with live UIDs. |
| **Connection Pooling (PgBouncer)** | **Desynchronized**: `Pooler` loses ownership; fails to track primary failovers. | **Flapping**: PgBouncer pods flap as cluster reconciles out-of-order. | **Clean Lifecycle**: `Pooler` reconnected to `Cluster`; routes traffic cleanly to primary. |
| **Operator Reconciliation Duel** | **Continuous**: Operator attempts to recreate resources or boots instances into broken state. | **Severe**: High contention on API server; lock timeouts on database initialization. | **Zero Contention**: Operator remains paused until all resources are in a consistent state. |
