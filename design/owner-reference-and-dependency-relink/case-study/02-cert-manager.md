# Case Study 02: cert-manager (ACME Flow)

This case study analyzes **cert-manager**, the standard Kubernetes certificate management controller. It evaluates how Velero's dynamic owner-reference restore engine coordinates multi-stage Public Key Infrastructure (PKI) state machines, Automated Certificate Management Environment (ACME) challenge solvers, and transient solver ingress/pod lifecycle management.

---

## 1. Background & Problem Space

cert-manager automates the issuance and renewal of TLS certificates from Let's Encrypt, HashiCorp Vault, Venafi, or internal CAs. For public ACME issuers, cert-manager breaks certificate issuance into a multi-tiered state machine:
- **`Certificate` (`cert-manager.io`):** The primary declarative resource defining desired DNS names, issuer references, and renewal schedules.
- **`CertificateRequest` (`cert-manager.io`):** An ephemeral custom resource containing a Certificate Signing Request (CSR) generated during renewal or initial issuance.
- **`Order` (`acme.cert-manager.io`):** Represents an ACME order with an upstream CA (e.g. Let's Encrypt), orchestrating required domain validations.
- **`Challenge` (`acme.cert-manager.io`):** Manages an individual domain validation test (HTTP-01 or DNS-01).
- **HTTP-01 Solver Resources (`networking.k8s.io/Ingress`, `core/v1/Pod`):** Ephemeral ingress rules and HTTP server pods spawned to solve Let's Encrypt challenge requests.
- **TLS Secret (`core/v1/Secret`):** The final output containing the issued `tls.crt` and `tls.key`.

cert-manager relies on `metadata.ownerReferences` across all stages to garbage-collect stale challenges, orders, and solver pods once a certificate is successfully issued or renewed.

---

## 2. Resource Ownership Hierarchy

The complete ACME challenge ownership graph spans 4 to 5 tiers across multiple API groups:

```text
CERT-MANAGER ACME 5-TIER STATE MACHINE DAG
================================================================================

  [ Certificate (cert-manager.io) ]  <── Tier 1 (User Declarative Intent)
        │
        ├── (spec.secretName / ownerRef) ──► [ Secret (tls secret, core/v1) ]  <── Tier 2 (Output)
        │
        └── (ownerRef) ──► [ CertificateRequest (cert-manager.io) ]  <── Tier 2 (CSR)
                                 │
                                 └── (ownerRef) ──► [ Order (acme.cert-manager.io) ]  <── Tier 3 (ACME Order)
                                                          │
                                                          └── (ownerRef) ──► [ Challenge (acme.cert-manager.io) ]  <── Tier 4 (Validation)
                                                                                   │
                                                                                   ├── (HTTP-01 ownerRef) ──► [ Ingress (networking.k8s.io) ]  <── Tier 5
                                                                                   │                                │
                                                                                   │                                └── (ownerRef) ──► [ Pod (core/v1) ]
                                                                                   │
                                                                                   └── (DNS-01 ownerRef)  ──► [ Secret / DNS-Job (core/v1) ]  <── Tier 5
```

### Reference Characteristics
1. **Tier 1 to Tier 3 (`Certificate` → `CertificateRequest` → `Order`):** Strict single-controlling-owner references (`controller: true`, `blockOwnerDeletion: true`).
2. **Tier 3 to Tier 4 (`Order` → `Challenge`):** The `Order` reconciler creates one or more `Challenge` resources per domain.
3. **Tier 4 to Tier 5 (`Challenge` → `Ingress` / `Pod`):** cert-manager injects high-priority HTTP path routing rules (`/.well-known/acme-challenge/*`) into the ingress controller, owned by the active `Challenge`.

---

## 3. Catastrophic Failure Modes Without Remapping

If cert-manager resources are restored without owner-reference remapping (especially during active issuance or full cluster DR), several failure modes emerge:

1. **Let's Encrypt Rate-Limit Burnout:**
   If an active `Order` or `Challenge` loses its ownerReference back to `CertificateRequest`, cert-manager considers the order abandoned and initiates a brand-new ACME order with Let's Encrypt. Because Let's Encrypt enforces strict rate limits (e.g. 50 new orders per week per registered domain, and 5 duplicate certificates per week), runaway renewal loops can lock a production domain out of SSL certificates for an entire week.
2. **Routing Hijacking via Leaked Solver Ingresses:**
   HTTP-01 solvers create temporary `Ingress` resources to intercept challenge traffic. If the `Challenge` → `Ingress` ownerReference is broken, deleting the completed challenge fails to delete the solver ingress. This lingering ingress rule continues to intercept HTTP traffic, corrupting application routing.
3. **Stale Secrets and Failed Automated Renewal:**
   If the TLS `Secret` loses its ownerReference pointing to `Certificate`, cert-manager may fail to update the existing secret on renewal, or an operator deleting a deprecated certificate may leave unmanaged private keys lingering in etcd.

---

## 4. How the Velero Engine Handles cert-manager

Velero's owner-reference restore engine (`design.md`) accommodates cert-manager's operational patterns through several architectural mechanisms:

### A. Operational Best Practice: Clean Lifecycle Remapping
In typical backup workflows, operators often back up only `Certificate`, `Issuer`/`ClusterIssuer`, and `Secret`, allowing cert-manager to re-issue certificates as needed. However, in **full cluster disaster recovery** or live migration, ongoing `CertificateRequest`, `Order`, and `Challenge` objects are captured in the backup snapshot.
- Velero includes both `cert-manager.io` and `acme.cert-manager.io` in the remapping scope.
- In Phase 1A, all objects are created cleanly.
- In Phase 1B Pass 1, Velero immediately reconnects `Challenge` → `Order` → `CertificateRequest` → `Certificate`.
- When cert-manager reconciles, it recognizes the ongoing challenge state, completes validation, issues the secret, and automatically cleans up the child solver resources via native Kubernetes garbage collection.

### B. Ingress Workload Boundary Handling
While Velero permanently denies leaf workloads (`Pod`), it allows standard networking resources (`networking.k8s.io/Ingress`, `core/v1/Service`) to be included in `inScope`:
- By adding `networking.k8s.io` to `inScope`, the ephemeral challenge solver Ingress successfully remaps its ownerReference to the live `Challenge` CR.
- When the ACME challenge completes, Kubernetes cascading garbage collection cleanly removes the solver Ingress, ensuring application routing is never corrupted.

### C. Namespace Mapping Compatibility & Cross-Namespace Migration
Velero's owner-reference remapping engine is fully compatible with Velero's standard namespace remapping (`--namespace-mappings <src-ns>:<target-ns>`):
- **Same-Namespace Integrity Enforced:** Kubernetes requires that namespaced objects only own or be owned by objects in the exact same namespace (or cluster-scoped parents).
- **Synchronized Remapping:** When an entire namespace is migrated from `source-ns` to `target-ns`, Velero tracks the child's live target namespace (`childTargetNS == target-ns`) and resolves the parent's mapped namespace (`mapNamespace(ownerSrcNS, mapping) == target-ns`). Because both parent and child map to `target-ns`, the entire 5-tier ownership DAG is reconstructed cleanly within the target namespace.
- **Namespace Split Protection:** If a user configures an invalid or divergent mapping where a parent and child are routed to different namespaces, Velero detects `ownerTargetNS != childTargetNS`, logs a warning, and skips patching that ownerReference, preventing invalid cross-namespace links from corrupting the cluster.

---

## 5. cert-manager ConfigMap Definition

To restore cert-manager workloads and active certificate state machines with dynamic owner-reference remapping, apply the following ConfigMap in the `velero` namespace:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: velero-ownerref-cert-manager
  namespace: velero
  labels:
    velero.io/plugin-config: ""
data:
  # 1. inScope: cert-manager core, ACME protocols, solver networking, and TLS secrets
  inScope: |
    - group: cert-manager.io
    - group: acme.cert-manager.io
    - group: networking.k8s.io
      kind: Ingress
    - group: ""
      kind: Secret
    - group: ""
      kind: Service

  # 2. specRefPaths: Empty (cert-manager relies on metadata.ownerReferences and spec.secretName)
  specRefPaths: ""

  # 3. quiesceOnRestore: Empty (ACME controllers do not require quiescing)
  quiesceOnRestore: ""
```

### Field Breakdown
- **`inScope`:**
  - `cert-manager.io`: Covers `Certificate`, `CertificateRequest`, `Issuer`, and `ClusterIssuer`.
  - `acme.cert-manager.io`: Covers `Order` and `Challenge`.
  - `networking.k8s.io/Ingress`: Allows ephemeral HTTP-01 solver ingresses to maintain owner references back to their `Challenge`.
  - `core/Secret`: Allows TLS secrets to remain bound to their `Certificate`.
  - `core/Service`: Allows challenge solver backend services to re-link to solver ingresses/challenges.
- **`specRefPaths`:** Left empty because cert-manager uses standard resource names rather than foreign UIDs inside `.spec`.
- **`quiesceOnRestore`:** Left empty. ACME operations are resilient to sub-second remapping latency in Phase 1B Pass 1.
