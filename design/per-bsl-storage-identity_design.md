# Per-BackupStorageLocation Pod Identity for Object-Store Plugins

## Abstract

This proposal adds core Velero support for running a `BackupStorageLocation`'s (BSL) object-store operations in a dedicated, long-lived worker pod that runs under a per-BSL Kubernetes ServiceAccount and its projected service-account-token volumes.
This lets each BSL consume a distinct pod-based identity (Azure AD Workload Identity, AWS IRSA, or GCP Workload Identity) instead of being limited to the single identity of the Velero server pod.

## Background

Velero object-store plugins (for example the AWS, Azure, and GCP provider plugins) are launched by the Velero server as child processes via hashicorp/go-plugin.
Each plugin subprocess is started with `exec.Cmd` and inherits the full environment of the Velero server pod, and it runs inside that pod, so it shares the pod's ServiceAccount, its projected service-account token, and pod-scoped environment variables such as `AZURE_FEDERATED_TOKEN_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`, and `AWS_ROLE_ARN`.

Pod/workload identity is fundamentally a property of the pod: the federated token is projected into the pod based on the pod's ServiceAccount, and provider admission webhooks inject the identity environment variables at pod admission time.
Because every object-store plugin for every BSL runs inside the one Velero server pod, all BSLs that use pod-based authentication are forced to use the single identity of the Velero pod.
File-based per-BSL credentials already work today (`BackupStorageLocation.Spec.Credential` is resolved to a file and passed to the plugin as `config["credentialsFile"]`), but pod-based identity cannot be varied per BSL.
The Velero plugin for Microsoft Azure documents this exact limitation for additional BackupStorageLocations when using Workload Identity.

The driving use case is multi-tenancy: a team brings its own ServiceAccount and a corresponding federated managed identity in its own namespace, and wants a BSL that writes backups to its own storage account under its own identity, without the central Velero deployment being granted access to every tenant identity.

## Goals

- Allow a `BackupStorageLocation` to reference a ServiceAccount / identity distinct from the Velero deployment, and run all of that BSL's object-store operations under the referenced identity.
- Support pod-based identity (Azure AD Workload Identity, AWS IRSA, GCP Workload Identity) per BSL without granting the central Velero pod access to the tenant identities.

## Non Goals

- Changing the third-party provider plugins (AWS/Azure/GCP): they continue to work unmodified as long as the pod they run in carries the correct identity and environment.
- Per-BSL identity for the node-agent data path (fs-backup / data-mover), volume snapshotters, or item-action plugins: this proposal covers object-store / backup-store operations only.
- Automatic creation of the tenant's cloud-side identity, federated credential, or ServiceAccount: those remain the tenant's responsibility, as they are today for the Velero pod.

## High-Level Design

The Velero `persistence.objectBackupStore` type (the `BackupStore` implementation) is a thin wrapper whose roughly thirty methods all delegate to the eight methods of the `velero.ObjectStore` plugin interface (`Init`, `PutObject`, `GetObject`, `ObjectExists`, `ListCommonPrefixes`, `ListObjects`, `DeleteObject`, `CreateSignedURL`).
Because that eight-method interface is the single choke point through which every backup-store operation flows, we relocate only the `velero.ObjectStore` (the provider plugin) into a dedicated per-BSL worker pod and proxy those eight methods over the network.
Every higher-level operation, and therefore every one of the roughly ten controllers that call `backupStoreGetter.Get` (backup, backup-finalizer, backup-operations, restore, restore-finalizer, restore-operations, download-request, backup-sync, backup-deletion, and BSL validation), automatically runs under the worker's identity, with no change to controller signatures and with serialization, layout, and compression logic remaining in the central Velero pod.

When a BSL opts in, a new controller reconciles it into a long-lived worker Deployment and Service.
The worker pod's base spec is cloned from the running Velero server Deployment (image, `/plugins`, environment, volumes, image pull secrets, security context), then its ServiceAccount, namespace, pod labels/annotations, and projected token volumes are overridden so the pod runs under the tenant identity, and its command is set to a new server sub-command.
The central Velero process, when building the backup store for such a BSL, dials the worker's Service over mutually authenticated TLS and uses a remote `velero.ObjectStore` backed by that connection instead of a local plugin subprocess.

## Detailed Design

### Reused, unchanged building blocks

The gRPC contract for the object store already exists and is reused as-is:
the proto `service ObjectStore` (`pkg/plugin/proto/ObjectStore.proto`) defines `PutObject` as a client-streaming RPC, `GetObject` as a server-streaming RPC (16 KiB chunks), and the remaining six methods as unary RPCs.
The `framework.ObjectStoreGRPCServer` and `framework.ObjectStoreGRPCClient` types (`pkg/plugin/framework/object_store_server.go`, `object_store_client.go`) already implement both sides of that proto.
Today go-plugin binds this contract to a loopback socket with no mTLS; this proposal adds a network mTLS transport in front of the same contract, and does not change the proto or the message-level streaming logic.

### API changes

A new optional field is added to `BackupStorageLocationSpec` in `pkg/apis/velero/v1/backupstoragelocation_types.go`:

```go
// Worker, when set, runs this BSL's object-store operations in a dedicated
// worker pod under a distinct identity, instead of in the Velero server process.
// +optional
Worker *BackupStorageLocationWorker `json:"worker,omitempty"`
```

```go
// BackupStorageLocationWorker configures the dedicated worker pod that runs
// object-store operations for a BackupStorageLocation under a distinct identity.
type BackupStorageLocationWorker struct {
	// ServiceAccountName is the ServiceAccount the worker pod runs as.
	// It must exist in Namespace and carry the desired pod/workload identity.
	ServiceAccountName string `json:"serviceAccountName"`

	// Namespace is where the worker pod runs. Defaults to the Velero namespace.
	// The ServiceAccount must live in this namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// PodLabels are added to the worker pod, e.g. azure.workload.identity/use: "true".
	// +optional
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// PodAnnotations are added to the worker pod.
	// +optional
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// TokenVolumes declares explicit projected service-account-token volumes for
	// portability when no provider admission webhook injects them automatically.
	// +optional
	TokenVolumes []ProjectedServiceAccountToken `json:"tokenVolumes,omitempty"`

	// Resources overrides the worker container resource requirements.
	// +optional
	Resources *corev1api.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector overrides worker pod scheduling.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations overrides worker pod tolerations.
	// +optional
	Tolerations []corev1api.Toleration `json:"tolerations,omitempty"`
}

// ProjectedServiceAccountToken configures one projected SA-token volume mounted
// into the worker pod.
type ProjectedServiceAccountToken struct {
	// Audience of the token (provider specific, e.g. "api://AzureADTokenExchange").
	Audience string `json:"audience"`
	// ExpirationSeconds is the requested token lifetime.
	// +optional
	ExpirationSeconds *int64 `json:"expirationSeconds,omitempty"`
	// Path is the file name the token is projected to, under the mount directory.
	Path string `json:"path"`
	// MountPath is the directory the token volume is mounted at in the container.
	MountPath string `json:"mountPath"`
}
```

The CRD, generated deepcopy code, and the BSL builder in `pkg/builder` are regenerated/extended accordingly.
`BackupStorageLocation.Validate()` is extended to require `ServiceAccountName` when `Worker` is set and to reject a `Worker` when the whole feature is disabled.
The feature is gated behind a new feature flag `EnableBSLWorkerIdentity` (defined next to `EnableCSI` in `pkg/apis/velero/v1/constants.go`), so the default behavior is unchanged.

### Worker runtime: `velero backup-store-server`

A new hidden cobra command `velero backup-store-server` is added under `pkg/cmd/cli`, modeled on `velero data-mover backup` and `velero repo-maintenance`.
Its flags are `--provider`, `--listen` (the TCP address to bind), `--tls-cert`, `--tls-key`, `--tls-ca` (mounted from the per-worker TLS Secret), and the standard `--log-level` / `--log-format`.
On startup it discovers plugins from `/plugins` exactly as the server does (the worker pod inherits the Velero Deployment's plugin init containers, so `/plugins` is populated), obtains the local `velero.ObjectStore` for `--provider` through the normal plugin manager (a go-plugin subprocess to the provider binary, now running inside the worker pod under the tenant identity), wraps it in `framework.ObjectStoreGRPCServer`, and serves the `ObjectStore` proto on a `grpc.Server` configured with mutual TLS on `--listen`.
The provider plugin subprocess inherits the worker pod's environment and projected token, so Workload Identity / IRSA is picked up transparently.

### Central side: remote object store

A new `velero.ObjectStore` implementation dials a worker Service over mTLS and forwards each of the eight methods using `framework.ObjectStoreGRPCClient` and the existing proto (including the streaming `StreamReadCloser` used by `GetObject`).
A new `RemoteObjectStoreGetter` implements the existing `persistence.ObjectStoreGetter` interface (`GetObjectStore(provider string) (velero.ObjectStore, error)`); it resolves a BSL to its worker Service DNS name (`<worker-service>.<worker-namespace>.svc`), establishes and caches the mTLS connection, and returns the remote object store.

Integration happens at exactly one place, `persistence.objectBackupStoreGetter.Get` (`pkg/persistence/object_store.go`).
When `location.Spec.Worker != nil`, `Get` builds the remote object store through the `RemoteObjectStoreGetter` instead of using the local plugin manager passed in by the caller, and it skips the local `credentialsFile` resolution (the worker uses its pod identity, not a credentials file).
All other behavior is unchanged: the bucket/prefix/config map is still assembled and passed to `ObjectStore.Init` over the wire, and the returned value is still the existing `objectBackupStore` wrapper, so every `BackupStore` method keeps working without modification.

### Worker pod spec inheritance

A helper reads the live `velero` Deployment (as `pkg/repository/maintenance/maintenance.go` already does with `cli.Get(..., Name: "velero" ...)`) and clones the relevant pod-spec fields using the existing `pkg/util/velero` `Get*FromVeleroServer` helpers (image, env, envFrom, volumes, volume mounts, image pull secrets, pod and container security contexts, and an allow-listed subset of labels/annotations/tolerations).
It then applies the worker overrides: `ServiceAccountName`, `Namespace`, the `PodLabels`/`PodAnnotations`, the `TokenVolumes` (rendered as `projected` volumes with `serviceAccountToken` sources and matching volume mounts), optional `Resources`/`NodeSelector`/`Tolerations`, `RestartPolicy: Always`, and `Command`/`Args` set to `velero backup-store-server ...`.
The image is pinned to the Velero server image so the worker and the server upgrade together.

### Worker lifecycle controller

A new controller reconciles BackupStorageLocations that set `Worker`.
For each such BSL it ensures a worker Deployment (single replica) and a ClusterIP Service in the worker namespace, plus a per-worker TLS Secret (see Security Considerations), all owned/tracked for cleanup.
It adds a finalizer to the BSL (the BSL controller has no finalizer today) so the Deployment, Service, and Secret are deleted when the BSL is deleted or when `Worker` is cleared.
It reflects worker readiness into BSL status: the BSL is only considered usable once its worker Deployment is available, so backups are not attempted against a not-yet-ready identity.
It reacts to `Worker` spec changes by updating the Deployment.
The controller is registered in `pkg/cmd/server/server.go`, and the worker-aware `ObjectBackupStoreGetter` is constructed at the existing single injection seam (`server.go` line ~570) so no other controller wiring changes.

### End-to-end data flow (backup persist)

The backup controller generates the tarball and metadata in the central pod as it does today.
`backupStoreGetter.Get(bsl)` returns the `objectBackupStore` wrapping the remote object store; `PutBackup` serializes each file and calls `objectStore.PutObject`, which streams 16 KiB chunks over mTLS gRPC to the worker; the worker's local provider plugin, running under the tenant Workload Identity, writes to the tenant storage account.
Validation (`IsValid` → `ListCommonPrefixes`), backup sync (`ListObjects`/`GetObject`), deletion (`DeleteObject`), download (`CreateSignedURL`), and restore reads (`GetObject`) all proxy through the same connection and identity.

## Alternatives Considered

Ephemeral worker pod per operation (the VGDP data-mover micro-service model, `pkg/exposer` + `pkg/datamover`): a pod is spawned per operation and signals completion via a CR.
This is a good fit for discrete, infrequent, long-running work, but it is awkward for the frequent and interactive object-store operations here (validation and sync run on timers; download-URL generation is synchronous and latency-sensitive), and it would pay pod-startup cost on every operation, so a long-lived per-BSL worker was chosen.

Proxying at the higher-level `BackupStore` interface instead of `ObjectStore`: this would require serializing roughly thirty methods and moving tarball/serialization logic into the worker, for no benefit, since all `BackupStore` methods already funnel through the eight `ObjectStore` methods.

Caller authentication via Kubernetes `TokenReview` instead of mTLS: the worker could validate the central pod's ServiceAccount token on each call rather than using client certificates.
This is simpler to bootstrap but couples the data path to the API server's availability and to token audiences; mTLS with a Velero-managed CA is proposed for v1, with `TokenReview` noted as a possible future option.

Putting the worker pod overrides in a referenced ConfigMap (as repository maintenance does) rather than inline on the BSL spec: this keeps the BSL smaller but adds indirection; the inline `Worker` struct is proposed for discoverability, and can be revisited.

## Security Considerations

Isolation between the central pod and workers, and between tenants, is enforced by mutually authenticated TLS plus network policy.
Velero manages a self-signed CA stored as a Secret in the Velero namespace; it issues a server certificate for each worker (SAN set to the worker Service DNS name) and a client certificate for the central pod, and both sides verify each other.
This prevents an unauthorized pod from calling a worker and prevents a rogue endpoint from impersonating a worker.
Certificate material and rotation are managed by the worker controller.

Because a tenant's ServiceAccount and projected token live in the tenant's namespace, the worker pod generally runs in that namespace, which means Velero creates a Deployment/Service/Secret there.
Velero's default install binds its ServiceAccount to `cluster-admin`, so this is already authorized, but it widens the blast radius; the design recommends a narrower dedicated ClusterRole for worker management and documents a NetworkPolicy that restricts worker Service access to the Velero pod.
The projected token in the worker is the tenant's own identity, so exposing it to the tenant's namespace is acceptable; the central client certificate, by contrast, must be protected and is only mounted into the Velero pod.
A threat-model section in the docs covers a tenant with pod-exec access in their own namespace.

## Compatibility

The feature is entirely opt-in and gated behind the `EnableBSLWorkerIdentity` feature flag; BSLs without a `Worker` field behave exactly as today, running object-store plugins in-process in the Velero pod.
The new BSL field is optional and additive, so existing BSL manifests and the CRD remain backward compatible.
No provider plugin changes are required.
Worker pods use the Velero server image, so version skew between the central process and workers is avoided across upgrades.

## Implementation

Implementation is incremental and mostly parallelizable after the API lands.
The design proposal (this document) is landed first as its own PR with a tracking issue.
Then: the API field, types, CRD/deepcopy regeneration, builder, validation, and feature flag; the `backup-store-server` runtime command serving the ObjectStore proto over mTLS; the central remote object store and `RemoteObjectStoreGetter`; the routing integration in `objectBackupStoreGetter.Get`; the worker pod-spec inheritance helper; the worker lifecycle controller with BSL finalizer and readiness gating; mTLS/CA management; RBAC scoping and NetworkPolicy guidance; server wiring and feature-flag plumbing; user documentation with per-provider setup; and unit plus end-to-end tests (an Azure Workload Identity happy path and a generic mock-provider path).
Each code PR includes a `changelogs/unreleased/<pr>-<user>` entry.

## Open Issues

- Whether v1 should restrict worker pods to the Velero namespace (requiring the tenant to place the ServiceAccount there) and defer arbitrary tenant namespaces to a follow-up, to limit the cross-namespace surface.
- Whether idle workers should scale to zero (or start on demand) to bound the one-pod-per-BSL resource cost.
- Final choice between Velero-managed mTLS and `TokenReview`-based caller authentication.
