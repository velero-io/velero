# Case Study 05: Crossplane

This case study analyzes **Crossplane**, the cloud-native framework that turns Kubernetes into a universal control plane for multi-cloud infrastructure. It evaluates how Velero's dynamic restore engine manages nested Composite Resources (XRs), Managed Resources (MRs), array-based spec pointer remapping (`spec.resourceRefs[*]`), and native `crossplane.io/paused` controller quiescing.

---

## 1. Background & Problem Space

Crossplane uses Kubernetes custom resources to provision and manage remote cloud infrastructure (e.g. AWS RDS, GCP CloudSQL, Azure VNets). It organizes resources into a layered abstraction:
- **Composite Resource Claim (`Claim`):** The developer-facing, namespace-scoped custom resource (e.g. `AppEnvironmentClaim`, `PostgreSQLInstance`).
- **Composite Resource (`XR`):** The cluster-scoped composite resource that implements the claim and orchestrates underlying resources.
- **Nested Composition (`Child XR`):** Complex architectures compose XRs within other XRs (e.g. an `XAppEnvironment` orchestrates an `XPostgreSQLInstance` and an `XNetworkTopology`).
- **Managed Resources (`MR`):** High-fidelity representations of cloud APIs (e.g. `rds.aws.upbound.io/v1beta1/Instance`, `ec2.aws.upbound.io/v1beta1/VPC`).
- **Connection Secrets (`core/v1/Secret`):** Kubernetes Secrets containing DB connection credentials, API keys, and endpoints emitted by Managed Resources.

Crossplane exhibits the exact **dual-pointer reference model** found in Cluster API: it relies on `metadata.ownerReferences` for Kubernetes garbage collection and lifecycle binding, while simultaneously embedding parent-child UIDs in array-based spec pointers (`spec.resourceRefs`).

---

## 2. Resource Ownership Hierarchy

In Crossplane nested compositions, the resource hierarchy forms a 5-tier bidirectional DAG:

```text
CROSSPLANE 5-TIER NESTED COMPOSITION DAG
================================================================================

  [ Claim (e.g. database.example.org/PostgreSQLInstance) ]  <── Tier 1 (Namespaced Entrypoint)
        │  ▲
        │  │ spec.claimRef (with UID) / metadata.ownerReferences
        ▼  │
  [ Composite Resource / XR (e.g. database.example.org/XPostgreSQLInstance) ]  <── Tier 2 (Cluster-Scoped Root)
        │  ▲
        │  │ spec.resourceRefs[*] (with UIDs) / metadata.ownerReferences
        ▼  │
  [ Child Composite Resource / XR (e.g. network.example.org/XNetworkTopology) ]  <── Tier 3 (Intermediate Component)
        │  ▲
        │  │ spec.resourceRefs[*] (with UIDs) / metadata.ownerReferences
        ▼  │
  [ Managed Resource / MR (e.g. rds.aws.upbound.io/Instance) ]  <── Tier 4 (Cloud Infrastructure Provider)
        │  ▲
        │  │ spec.writeConnectionSecretToRef / metadata.ownerReferences
        ▼  │
  [ Connection Secret (core/v1/Secret) ]  <── Tier 5 (Runtime Credentials)
```

### Reference Characteristics
1. **Bidirectional Claim ↔ XR Binding:**
   - The `Claim` owns the `XR` (or vice-versa depending on creation flow), linked via `metadata.ownerReferences`.
   - The `XR` explicitly embeds `spec.claimRef.uid` to bind exclusively to that claim.
2. **Array-Based Child References (`spec.resourceRefs`):**
   - The Composite Resource maintains an array of typed references:
     ```yaml
     spec:
       resourceRefs:
         - apiVersion: database.aws.upbound.io/v1beta1
           kind: RDSInstance
           name: my-rds-xyz
           uid: 8b06b6f7-4148-4cb9-b88a-6b45f4dc67d1
     ```
   - If the `uid` in this array does not match the live child MR, Crossplane considers the composed resource broken or unmanaged.
3. **Managed Resource to Secret:**
   - The Managed Resource writes sensitive connection details to a `core/v1/Secret` and sets `metadata.ownerReferences` on the Secret so it is deleted when the database is decommissioned.

---

## 3. Catastrophic Failure Modes Without Remapping

Because Crossplane communicates directly with external cloud provider APIs (AWS, Azure, GCP), restoring Crossplane without owner-reference and spec pointer remapping results in catastrophic financial and infrastructure failures:

1. **Duplicate Public Cloud Infrastructure Provisioning:**
   When an XR is restored with stale UIDs in `spec.resourceRefs`, or when an MR is restored without its parent ownerReference, the Crossplane composition controller concludes that the desired cloud resources do not exist. It immediately triggers AWS/GCP/Azure API calls to provision duplicate multi-AZ databases, duplicate VPCs, and duplicate load balancers.
2. **Runaway Cloud Billing Spikes:**
   Duplicate provisioning of enterprise cloud infrastructure (e.g. multi-node RDS clusters, provisioned IOPS SSD storage) causes immediate and massive cost overruns.
3. **Broken Connection Secret Rotation:**
   Connection secrets detached from Managed Resources cannot be updated when cloud databases rotate credentials, leading to application connection failures.
4. **Leaked External Infrastructure on Deletion:**
   When a user deletes a restored `Claim` or `XR`, the absence of proper cascading ownership leaves the actual cloud databases running indefinitely in AWS/Azure/GCP.

---

## 4. How the Velero Engine Handles Crossplane

Velero's owner-reference restore engine (`design.md`) provides complete, native coordination for Crossplane:

### A. Dotted Path Array Wildcard Traversal (`spec.resourceRefs[*]`)
Crossplane embeds child references inside a slice of `corev1.ObjectReference`. Velero's `specRefPaths` engine supports wildcard array traversal:
- Configuration:
  ```yaml
  paths:
    - spec.claimRef
    - spec.resourceRefs[*]
  ```
- During Phase 1B remapping, Velero walks the `spec.resourceRefs` array, extracts each child reference, performs an $O(1)$ lookup in `uidMap`, and updates `ref.UID` to the live child UID. If `resourceVersion` is present in the reference map, Velero nullifies it to prevent optimistic concurrency errors.

### B. Native Controller Quiescing (`crossplane.io/paused`)
Crossplane natively supports declarative controller pausing. Adding the annotation `crossplane.io/paused: "true"` to any Composite Resource or Managed Resource silences its reconciler.
- In Phase 1A create, Velero injects:
  ```yaml
  metadata:
    annotations:
      crossplane.io/paused: "true"
      velero.io/quiesced-key: "crossplane.io/paused"
      velero.io/quiesced-by-restore: "<restore-name>"
  ```
- Crossplane controllers immediately halt reconciliation and make zero cloud API calls.
- In Phase 1B, after all `ownerReferences` and `spec.resourceRefs` have been patched, Velero's graph-free unquiesce engine safely removes the pause annotation.

### C. Multi-Hop Transitive Root Propagation in Action
If a deeply nested Managed Resource (Tier 4 `RDSInstance`) fails to patch due to an API server conflict (HTTP 409):
1. Velero's Phase 1B engine traverses `parentMap` backwards via BFS:
   `RDSInstance` → `Child XR` → `Parent XR / Claim`
2. The root `Claim` and `XR` are appended to the pending patch's `Targets` field.
3. When `CanUnquiesce` evaluates the root `Claim` or `XR`, it finds the root in `pendingPatch.Targets` and keeps the root **paused**.
4. Cloud controllers remain frozen until the entire chain is patched, preventing duplicate cloud provisioning.

This BFS pin requires composed objects to carry `metadata.ownerReferences` to the XR (typical Crossplane composition). Parent-side `spec.resourceRefs[*]` is rewritten on the XR itself; it is **not** a reverse index. Composed resources that do not ownerRef the XR (adopt-existing, some Composition Functions) are out of scope for this design; see [future-work/reverse-index-parent-side-inventories.md](../future-work/reverse-index-parent-side-inventories.md).

---

## 5. Crossplane ConfigMap Definition

To restore Crossplane compositions and managed infrastructure with dynamic owner-reference remapping, apply the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-crossplane
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: Crossplane core, package, composition groups, custom XR groups, provider groups, and secrets
  inScope: |
    - group: apiextensions.crossplane.io
    - group: pkg.crossplane.io
    - group: database.example.org
    - group: database.aws.upbound.io
    - group: ec2.aws.upbound.io
    - group: s3.aws.upbound.io
    - group: azure.upbound.io
    - group: gcp.upbound.io
    - group: ""
      kind: Secret

  # 2. specRefPaths: Remap bidirectional claimRef and array-based resourceRefs[*] UIDs
  specRefPaths: |
    - group: database.example.org
      kind: XPostgreSQLInstance
      paths:
        - spec.claimRef
        - spec.resourceRefs[*]
    - group: database.aws.upbound.io
      kind: RDSInstance
      paths:
        - spec.writeConnectionSecretToRef

  # 3. quiesceOnRestore: Native pause annotation for Crossplane Composite and Managed Resources
  quiesceOnRestore: |
    - group: database.example.org
      kind: XPostgreSQLInstance
      annotationKey: crossplane.io/paused
      annotationValue: "true"
    - group: database.aws.upbound.io
      kind: RDSInstance
      annotationKey: crossplane.io/paused
      annotationValue: "true"
```

### Field Breakdown
- **`inScope`:**
  - `database.example.org`: Covers custom Composite Resources (XRs) and Claims instantiated from Compositions.
  - `apiextensions.crossplane.io`, `pkg.crossplane.io`: Covers CompositeResourceDefinitions, Compositions, and provider packages.
  - `database.aws.upbound.io`, `ec2.aws.upbound.io`, `s3.aws.upbound.io`: Covers Upbound official cloud providers for AWS (extendable to GCP/Azure providers).
  - `core/Secret`: Allows connection credentials to retain ownerReferences back to their originating Managed Resource.
- **`specRefPaths`:**
  - `spec.claimRef`: Rewrites the claim UID on the Composite Resource (`XPostgreSQLInstance`).
  - `spec.resourceRefs[*]`: Uses array wildcard matching to rewrite live UIDs for every composed child resource.
  - `spec.writeConnectionSecretToRef`: Rewrites connection secret target pointers on Managed Resources (`RDSInstance`).
- **`quiesceOnRestore`:**
  - Injects Crossplane's official `crossplane.io/paused: "true"` annotation into runtime Composite Resources (`XPostgreSQLInstance`) and Managed Resources (`RDSInstance`) to freeze all cloud reconciliation until Phase 1B remapping completes. (Quiesce annotations apply to running XR/MR instances, not to `CompositeResourceDefinition` meta-CRDs).
