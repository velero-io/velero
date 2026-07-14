---
title: "Per-BSL Worker Identity"
layout: docs
---

By default, Velero runs every object-store plugin (AWS, Azure, GCP, ...) as a child
process of the single Velero server pod. Those plugins therefore share the Velero
server pod's identity: its ServiceAccount, its projected service-account token, and its
identity-related environment variables. Because pod/workload identity is a *pod-level*
property, every BackupStorageLocation (BSL) that relies on pod-based authentication such
as **Azure AD Workload Identity**, **AWS IRSA**, or **GCP Workload Identity** is stuck
with the single identity of the Velero pod.

The **per-BSL worker identity** feature lets a BSL run its object-store operations in a
dedicated, long-lived *worker pod* under its own Kubernetes ServiceAccount and projected
token volumes. This makes multi-tenant setups possible: a team can bring its own
ServiceAccount (bound to its own cloud identity) in its own namespace and back up to its
own storage account, without the central Velero deployment being granted access to every
tenant identity.

File-based per-BSL credentials (`spec.credential`) already work today and are unaffected;
this feature specifically enables *pod/workload* identity to vary per BSL.

## How it works

When a BSL sets `spec.worker`, Velero:

1. Reconciles a worker **Deployment** and **Service** (one per worker-backed BSL),
   cloning the plugin runtime (image, plugin init containers, `/plugins` and `/scratch`
   volumes, security contexts, image pull secrets, and non-identity environment) from the
   Velero server Deployment — but **dropping** the server's credential Secret volumes and
   identity environment variables so the central identity is never inherited.
2. Runs the worker under `spec.worker.serviceAccountName`, with the pod labels,
   annotations and projected token volumes you specify, so the cloud's admission webhook
   (or the projected tokens themselves) provide the worker's identity.
3. Proxies the object-store operations from the Velero server to the worker over a
   mutually authenticated TLS gRPC connection. All higher-level backup-store operations
   (persist, validate, sync, delete, download) automatically run under the worker's
   identity.

```
Central Velero pod                         Per-BSL worker pod (tenant SA + WI token)
------------------                         -----------------------------------------
backup/restore/sync controllers            velero backup-store-server
  -> backupStoreGetter.Get(bsl)              -> loads /plugins (inherited init containers)
     -> remote ObjectStore  === mTLS gRPC ===>  provider plugin (Azure WI / IRSA / GCP)
                                                  -> tenant storage
```

The Velero server continues to own all serialization, layout, and compression logic; only
the provider plugin's object-store calls are relocated into the worker pod.

## Enabling the feature

The feature is opt-in and gated behind the `EnableBSLWorkerIdentity` feature flag on the
Velero **server**. Add it at install time:

```bash
velero install \
  --features=EnableBSLWorkerIdentity \
  # ... other flags
```

or add `EnableBSLWorkerIdentity` to the `--features` argument of the Velero server
Deployment. BSLs that do not set `spec.worker` are unaffected regardless of the flag.

## Example: Azure AD Workload Identity

This example creates a worker-backed BSL that writes to a tenant's storage account under a
tenant-owned managed identity, using [Azure AD Workload
Identity](https://azure.github.io/azure-workload-identity/docs/).

1. Create the ServiceAccount in the tenant namespace, annotated with the tenant's managed
   identity client ID, and establish a federated credential for it (see the Azure
   Workload Identity docs and the [Velero plugin for Microsoft
   Azure](https://github.com/vmware-tanzu/velero-plugin-for-microsoft-azure) for details):

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: tenant-a-backup
     namespace: tenant-a
     annotations:
       azure.workload.identity/client-id: "<TENANT_MANAGED_IDENTITY_CLIENT_ID>"
   ```

2. Create the BackupStorageLocation referencing that ServiceAccount:

   ```yaml
   apiVersion: velero.io/v1
   kind: BackupStorageLocation
   metadata:
     name: tenant-a
     namespace: velero
   spec:
     provider: velero.io/azure
     objectStorage:
       bucket: tenant-a-backups
     config:
       resourceGroup: tenant-a-rg
       storageAccount: tenantastorage
       useAAD: "true"
     worker:
       serviceAccountName: tenant-a-backup
       namespace: tenant-a
       podLabels:
         azure.workload.identity/use: "true"
       tokenVolumes:
         - audience: api://AzureADTokenExchange
           mountPath: /var/run/secrets/azure/tokens
           path: azure-identity-token
   ```

Velero creates the worker Deployment/Service in the `tenant-a` namespace running as
`tenant-a-backup`. The Azure Workload Identity webhook (triggered by the
`azure.workload.identity/use: "true"` pod label) injects the federated token, and the
Azure plugin authenticates as the tenant's managed identity.

## Example: AWS IRSA / GCP Workload Identity

The mechanism is provider-agnostic. For **AWS IRSA**, annotate the worker ServiceAccount
with `eks.amazonaws.com/role-arn` and set the appropriate `config` on the BSL; the EKS Pod
Identity webhook injects the web-identity token. For **GCP Workload Identity**, annotate
the worker ServiceAccount with `iam.gke.io/gcp-service-account`. In both cases you can also
mount an explicit projected token via `worker.tokenVolumes` when no injecting webhook is
present.

## Security considerations

- **Mutual TLS.** Velero manages a self-signed CA (stored as a Secret in the Velero
  namespace) and issues a per-worker server certificate (SAN = worker Service DNS) plus a
  central client certificate. Both ends verify each other, so an unauthorized pod cannot
  call a worker and a rogue endpoint cannot impersonate one. The central client
  certificate is only ever mounted into the Velero pod. The CA is long-lived and worker
  server certificates are reissued automatically by the worker controller before they
  expire; the worker reloads the renewed certificate from its mounted Secret without a
  restart.
- **No central identity leakage.** The worker pod spec deliberately excludes the Velero
  server's credential Secret volumes and a denylist of identity environment variables
  (`AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, `AWS_ROLE_ARN`,
  `AWS_WEB_IDENTITY_TOKEN_FILE`, `GOOGLE_APPLICATION_CREDENTIALS`, ...). The worker only
  holds the tenant's own identity.
- **Cross-namespace workers widen blast radius.** Because the tenant ServiceAccount and
  token live in the tenant namespace, the worker generally runs there. Velero's default
  install binds its ServiceAccount to `cluster-admin`, so it can already create the
  worker Deployment/Service/Secret; if you use a narrower role, grant `create`/`update`/
  `delete` on `deployments` (apps) and `services`/`secrets` (core) in the worker
  namespaces (see the generated `config/rbac/role.yaml`).
- **Restrict access with NetworkPolicy.** Restrict the worker Service so only the Velero
  pod can reach its gRPC port. A tenant with pod-exec access in their own namespace still
  only holds their own identity (which they already control), and mTLS prevents them from
  driving other tenants' workers.

## Limitations

- One long-lived worker pod is created per worker-backed BSL, which adds resource
  overhead. Idle scale-down is a possible future enhancement.
- Backup data streams from the Velero pod to the worker and then to storage, adding one
  network hop.
- Worker pods run the Velero server image and upgrade together with the Velero server, so
  there is no version skew.

See the [BackupStorageLocation API type](api-types/backupstoragelocation.md) for the full
list of `worker` fields.
