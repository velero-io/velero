# Case Study 04: KubeVirt

This case study analyzes **KubeVirt**, the leading open-source project for running virtual machine workloads natively on Kubernetes. It evaluates how Velero's dynamic owner-reference restore engine coordinates stateful virtual machine pools, declarative VM definitions, runtime virtual machine instances (VMIs), and underlying Containerized Data Importer (CDI) storage volumes.

---

## 1. Background & Problem Space

KubeVirt integrates traditional virtualization into Kubernetes by modeling virtual machines as Kubernetes Custom Resources:
- **`VirtualMachinePool` (`pool.kubevirt.io`):** Manages horizontal scaling and rolling updates of homogeneous virtual machines (analogous to `Deployment`).
- **`VirtualMachine` (`kubevirt.io`):** Represents the declarative desired state of a VM (power state, CPU/RAM specifications, disk attachments).
- **`VirtualMachineInstance` / VMI (`kubevirt.io`):** Represents the active, running execution of a VM.
- **`virt-launcher` Pod (`core/v1`):** The Kubernetes container encapsulating the `libvirtd` and `qemu-kvm` hypervisor process.
- **`DataVolume` (`cdi.kubevirt.io`):** Orchestrates storage provisioning, disk image downloads, and volume snapshot imports.
- **`PersistentVolumeClaim` / PVC (`core/v1`):** The underlying raw block or filesystem storage backing the virtual machine disk.

KubeVirt relies strictly on `metadata.ownerReferences` to link `VirtualMachine` to its running `VirtualMachineInstance`, and to link `DataVolume` to its generated `PersistentVolumeClaim`.

---

## 2. Resource Ownership Hierarchy

The complete KubeVirt resource topology spans 4 to 5 tiers:

```text
KUBEVIRT 4-TO-5 TIER WORKLOAD & STORAGE HIERARCHY
================================================================================

  [ VirtualMachinePool (pool.kubevirt.io) ]  <── Tier 1 (Fleet Management)
        │
        └── (ownerRef) ──► [ VirtualMachine / VM (kubevirt.io) ]  <── Tier 2 (Declarative Spec)
                                 │
                                 ├── (ownerRef) ──► [ VirtualMachineInstance / VMI (kubevirt.io) ]  <── Tier 3 (Runtime State)
                                 │                        │
                                 │                        └── (ownerRef) ──► [ virt-launcher Pod (core/v1) ]  <── Tier 4
                                 │
                                 └── (spec.dataVolumeTemplates / ownerRef) ──► [ DataVolume (cdi.kubevirt.io) ]  <── Tier 3
                                                                                   │
                                                                                   └── (ownerRef) ──► [ PersistentVolumeClaim (core/v1) ]  <── Tier 4
                                                                                                          │
                                                                                                          └── (ownerRef) ──► [ cdi-importer Pod (core/v1) ]  <── Tier 5
```

### Reference Characteristics
1. **VM to VMI Relationship:** `VirtualMachine` owns `VirtualMachineInstance` via `metadata.ownerReferences` with `controller: true` and `blockOwnerDeletion: true`.
2. **VMI to virt-launcher Pod:** The VMI controller manages the execution pod directly, attaching an ownerReference from the `virt-launcher` pod to the VMI.
3. **DataVolume to PVC:** CDI `DataVolume` controllers automatically generate and own the underlying `PersistentVolumeClaim` with `blockOwnerDeletion: true`.

---

## 3. Catastrophic Failure Modes Without Remapping

If KubeVirt resources are restored with stripped or unremapped owner references, the cluster experiences catastrophic operational failures:

1. **Split-Brain VM Execution & Duplicate VMIs:**
   When a `VirtualMachine` is restored with `running: true`, its controller checks for existing child VMIs matching its UID. If the ownerReference on the restored VMI is missing or invalid, the controller assumes the VM is shut down and creates a brand-new VMI.
2. **Storage Lock Collisions & Volume Corruption:**
   The duplicate VMI attempts to spin up a new `virt-launcher` Pod and attach the same underlying `PersistentVolumeClaim` (which is typically `ReadWriteOnce`). This immediately triggers Kubernetes `Multi-Attach error for volume` or, worse, concurrent `qemu` disk writes that corrupt the virtual disk image.
3. **Storage Orphanage (Leaked PVCs):**
   If `DataVolume` fails to re-link to its `PersistentVolumeClaim`, deleting a virtual machine or data volume leaves raw multi-gigabyte cloud block storage volumes orphaned in the cluster.
4. **Pool Disconnect:**
   `VirtualMachinePool` loses ownership of child `VirtualMachine` instances, triggering unwanted scale-down or duplicate VM creation during pool reconciliations.

---

## 4. Storage Binding Deep Dive: Name-Based vs. UID-Based

A critical architectural distinction between KubeVirt and Cluster API is that **KubeVirt disk attachments do not use UID-based object references**.

### Volume Attachment Manifest Structure
In a `VirtualMachine` spec, disks bind to storage strictly by resource name in the same namespace:

```yaml
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: fedora-vm
  namespace: workloads
spec:
  running: true
  template:
    spec:
      domain:
        devices:
          disks:
            - name: rootdisk
              disk:
                bus: virtio
      volumes:
        - name: rootdisk
          dataVolume:
            name: fedora-root-dv            # Plain string name, NO UID
        - name: datadisk
          persistentVolumeClaim:
            claimName: fedora-data-pvc      # Plain string name, NO UID
```

### Comparison with Cluster API (CAPI)

| Characteristic | Cluster API (CAPI) | KubeVirt |
| :--- | :--- | :--- |
| **Reference Structure** | Typed `corev1.ObjectReference` (`apiVersion`, `kind`, `name`, `uid`) | Inline struct with plain string `name` or `claimName` |
| **Stores Object UID?** | **Yes** (e.g., `Cluster.spec.infrastructureRef.uid`) | **No** (`dataVolume.name` and `claimName` are strings only) |
| **Namespace Boundary** | Same namespace or cross-namespace | Strictly within the same namespace |
| **UID Remapping Required?** | **Yes** (stale UIDs break reconciler Lookups) | **No** (Velero preserves resource names by default) |
| **Need for `specRefPaths`?** | **Required** in `velero-ownerref-config` | **Not required**; volume attachment binds naturally by name |

Because KubeVirt volume references do not store UIDs, Velero does **not** need to traverse `spec.template.spec.volumes` to rewrite UIDs. Setting `specRefPaths: ""` in the ConfigMap is completely safe and intentional.

---

## 5. Restoration Modes & Upstream Best Practices

When backing up and restoring KubeVirt clusters with Velero, two distinct restoration patterns exist:

```text
MODE 1: UPSTREAM RECOMMENDED DECLARATIVE RESTORE (VMIs EXCLUDED)
================================================================================
  Backup:  VM + DataVolume + PVC  (Exclude: VMI, Pods)
     │
  Restore: Creates VM (unrunning) + PVCs + DVs
     │
  Launch:  virt-controller generates fresh VMI tailored to destination nodes


MODE 2: FULL-GRAPH RESTORE (VMIs INCLUDED)
================================================================================
  Backup:  VM + VMI + DataVolume + PVC
     │
  Restore: Creates VM + VMI (ownerRef stripped)
     │
  Phase 1B: Patch remapped ownerRef (VMI -> VM live UID in < 1s)
     │
  Adopt:   virt-controller adopts restored VMI directly
```

### 5.1 Mode 1 (Recommended): Declarative Restore (VMIs Excluded)

#### Upstream Architectural Recommendation
According to official KubeVirt architecture documentation ([KubeVirt Backup & Restore Integration](https://github.com/kubevirt/kubevirt/blob/main/docs/backup-restore-integration.md)):
> *"If a VirtualMachineInstance is owned by a VirtualMachine, it should **not be restored**. The KubeVirt controller will recreate the resource based on the VirtualMachine definition."*

#### Why Excluding VMIs is Preferred
1. **Node Topology Independence:** A `VirtualMachineInstance` contains node-specific runtime state in its `status` and `spec.nodeSelector`, including the specific worker node where `virt-launcher` was executing. Restoring an active VMI into a disaster recovery cluster with different node names, CPU features, or hardware virtualization capabilities causes scheduling failures.
2. **Ephemeral Runtime Artifact:** The VMI is equivalent to a `Pod` in core Kubernetes. Just as Velero does not need to restore `ReplicaSet`-owned pods when the `Deployment` is present, Velero does not need to restore `VirtualMachine`-owned VMIs.
3. **Eliminates Race Conditions:** If `VirtualMachineInstance` is restored before or concurrently with `VirtualMachine`, `virt-controller` can misinterpret the unlinked VMI as orphaned or start duplicate launcher pods.
4. **Volume Binding Synchronization:** `DataVolume` and `PersistentVolumeClaim` resources can take minutes to restore, populate, and bind. In declarative restore, the VM remains powered off (`spec.running: false`) until storage is fully bound, preventing disk corruption.

#### Backup and Restore CLI Commands for Mode 1
```bash
# Backup excluding runtime artifacts:
velero backup create kv-backup \
  --include-namespaces workloads \
  --exclude-resources virtualmachineinstances.kubevirt.io,pods

# Restore:
velero restore create kv-restore \
  --from-backup kv-backup
```

### 5.2 Mode 2: Full-Graph Restore (VMIs Included)

Despite upstream guidance, users frequently back up full namespaces without resource exclusions (`velero backup create --include-namespaces workloads`). In this scenario, both `VirtualMachine` and `VirtualMachineInstance` are captured.

#### Failure Modes When VMIs Are Restored Without Remapping
1. **Immediate GC Deletion (If ownerRefs are preserved without remapping):**
   If Velero were to restore `VirtualMachineInstance` with its original `metadata.ownerReferences` intact, the `uid` points to the old `VirtualMachine` UID from the source cluster. Kubernetes Garbage Collection immediately detects that the parent UID does not exist and cascade-deletes the VMI within milliseconds.
2. **Orphaned Runtime VMIs (If ownerRefs are stripped):**
   Velero's default behavior strips `metadata.ownerReferences`. The VMI is restored as an unmanaged standalone instance. `virt-controller` does not recognize the VMI as belonging to the restored `VirtualMachine` and attempts to instantiate a **second, duplicate VMI**, causing multi-attach storage lockouts.
3. **Controller Race Conditions:**
   If `virt-controller` is active when `VirtualMachine` is created with `spec.running: true`, it may create a new VMI before Velero can restore and re-link the original VMI from the backup archive.

### 5.3 The Controller Quiescing Dilemma in KubeVirt

Unlike Cluster API, which natively respects `cluster.x-k8s.io/paused: ""` annotations, KubeVirt's `virt-controller` does **not** support annotation-based halt mechanisms:
- There is no `kubevirt.io/paused` or `kubevirt.io/stop` annotation.
- `virt-controller` reconciliation is driven strictly by spec fields:
  - `spec.running: false` (boolean)
  - `spec.runStrategy: "Halted"` (enum: `Always`, `RerunOnFailure`, `Manual`, `Halted`, `Once`)

Mutating `.spec` to achieve temporary quiescing in Velero core is rejected as an anti-pattern (see [`spec-field-quiesce-and-argocd-analysis.md`](../spec-field-quiesce-and-argocd-analysis.md)). Therefore, for KubeVirt under the core engine, controller coordination relies on **sub-second Phase 1B Pass 1 execution** or domain plugins.

---

## 6. How the Velero Engine Handles KubeVirt

Velero's owner-reference remapping engine (`design.md`) resolves KubeVirt's multi-hop topology through several targeted features:

### A. Operator-Owned PVC Remapping (Deny List Precision)
A primary challenge in virtualized environments is distinguishing between ephemeral workload PVCs and operator-owned storage volumes:
- Velero implements a **built-in deny list** for PVCs whose parents are core workloads (`Pod`, `ReplicaSet`, `ReplicationController`, `Job`). This prevents ephemeral pod-bound PVCs from retaining invalid parent links.
- However, when a PVC is owned by an **operator CRD** (such as `cdi.kubevirt.io/DataVolume` or `kubevirt.io/VirtualMachine`), the parent GroupKind is **not** on the deny list.
- When `PersistentVolumeClaim` is included in `inScope`, Velero successfully patches `metadata.ownerReferences` on the live PVC, linking it back to the newly restored `DataVolume` with its live UID.

### B. Immediate Phase 1B Pass 1 Execution
Because `virt-launcher` pods are hypervisor containers running live operating systems, avoiding duplicate VMI creation is critical:
- In Phase 1A, all CRDs (`VirtualMachine`, `VirtualMachineInstance`, `DataVolume`) are created synchronously.
- Immediately after creation finishes, Phase 1B Pass 1 executes in-memory remapping inside `RestoreController`.
- The live UID of the `VirtualMachine` is patched onto the `VirtualMachineInstance` in sub-second latency. When the KubeVirt controller reconciles the `VirtualMachine`, it immediately finds its matching child VMI and takes no disruptive action.

### C. virt-launcher Pod Handling
The `virt-launcher` Pod is technically a `core/v1/Pod`. Under Velero's built-in deny list, Pod ownerReferences are stripped on restore.
- For stopped virtual machines (`running: false`), backing up and restoring `VirtualMachine` and `DataVolume` is sufficient; KubeVirt starts fresh `virt-launcher` pods upon power-on.
- For running virtual machines restored during active disaster recovery, restoring the VMI alongside the `VirtualMachine` allows the KubeVirt controller to re-adopt or gracefully restart the `virt-launcher` Pod once the VM → VMI hierarchy is intact.

---

## 7. KubeVirt ConfigMap Definition

To restore KubeVirt environments with dynamic owner-reference remapping, apply the following ConfigMap in the `velero` namespace (see [`configmaps/velero-ownerref-kubevirt.yaml`](./configmaps/velero-ownerref-kubevirt.yaml)):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-kubevirt
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: KubeVirt virtualization, CDI storage, pool management, and operator-owned PVCs
  inScope: |
    - group: kubevirt.io
    - group: cdi.kubevirt.io
    - group: pool.kubevirt.io
    - group: snapshot.kubevirt.io
    - group: ""
      kind: PersistentVolumeClaim

  # 2. specRefPaths: Empty (KubeVirt uses name-based volume bindings and metadata.ownerReferences)
  specRefPaths: ""

  # 3. quiesceOnRestore: Left empty (virt-controller does not support annotation pausing)
  quiesceOnRestore: ""
```

### Field Breakdown
- **`inScope`:**
  - `kubevirt.io`: Covers `VirtualMachine`, `VirtualMachineInstance`, `VirtualMachineInstanceReplicaSet`, and `VirtualMachineInstanceMigration`.
  - `cdi.kubevirt.io`: Covers `DataVolume`, `CDIConfig`, and `DataSource`.
  - `pool.kubevirt.io`: Covers `VirtualMachinePool`.
  - `snapshot.kubevirt.io`: Covers `VirtualMachineSnapshot` and `VirtualMachineSnapshotContent`.
  - `PersistentVolumeClaim`: Allows Velero to remap ownerReferences pointing from storage volumes to `DataVolumes` (bypassing the core workload deny list).
- **`specRefPaths`:** Left empty because KubeVirt does not embed parent UIDs within `.spec.volumes`.
- **`quiesceOnRestore`:** Left empty. The sub-second execution of Phase 1B Pass 1 provides sufficient coordination for KubeVirt controllers without requiring spec mutations.

---

## 8. Architectural Evaluation & Plugin Strategy

| Approach | Mechanism | Core Complexity | Quiescing Safety | Recommended Use Case |
| :--- | :--- | :---: | :---: | :--- |
| **Option 1: External ConfigMap Integration** | Generic ownerRef remapping via `velero-ownerref-kubevirt` ConfigMap | **Zero** | Basic (sub-second Phase 1B) | **Standard / Mode 1 (Declarative Restore)** |
| **Option 2: Dedicated KubeVirt Plugin** | `RestoreItemActionV2` plugin (`velero-plugin-for-kubevirt`) handling `spec.running: false` and CDI sync | Low | **Highest (Domain-aware)** | **Enterprise VM lifecycle / Mode 2** |
| **Option 3: Core Spec-Field Engine** | Generic JSONPath spec mutator in Velero core | High | Medium (Admission conflict risk) | **Rejected (Anti-pattern)** |

### Strategic Recommendation
1. **Velero Core Scope (Option 1):** Keep Velero core clean and focused on standard declarative CRDs and annotation-based pausing. Support KubeVirt via the external ConfigMap, which provides complete coverage for upstream-recommended Mode 1 restores and clean DataVolume → PVC re-linking.
2. **Advanced Enterprise Virtualization (Option 2):** For environments requiring complex live-VM orchestration, CDI importer progress gating, or `spec.running` mutations, implement a dedicated `RestoreItemAction` plugin. This preserves clean boundaries between generic Kubernetes backup mechanics and virtualization-specific lifecycle hooks.
