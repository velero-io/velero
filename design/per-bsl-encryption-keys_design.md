# Design proposal: per-BackupStorageLocation repository encryption keys

## Abstract

Currently Velero derives the encryption password for every backup repository from a single shared Secret named `velero-repo-credentials`.
This design proposes generating and managing a unique repository encryption key per BackupStorageLocation (BSL) while retaining the legacy shared Secret as a fallback.
The change improves cryptographic isolation between backup locations and removes reliance on a single shared password without breaking existing repositories.

## Background

Velero stores backup data in object storage through BackupStorageLocations.
Each location is associated with one or more BackupRepositories that are encrypted at rest by Kopia or the block data mover.
Today every repository is unlocked with the same password read from the `velero-repo-credentials` Secret in the Velero namespace.
If that single Secret is compromised, all backups across all BSLs become readable.
Additionally, the current implementation does not auto-generate encryption keys and relies on credential infrastructure provided by administrators.
This proposal changes the key lifecycle so that each BSL receives its own randomly generated encryption key stored in a dedicated Kubernetes Secret.

## Goals

- Provide per-BSL encryption key isolation for backup repositories.
- Maintain backward compatibility with existing repositories that use the shared `velero-repo-credentials` Secret.
- Generate strong, cryptographically random encryption keys instead of relying on static or reused passwords.
- Ensure repository providers and uploaders use the correct key for the BSL being accessed.

## Non Goals

- Changing BackupStorageLocation or BackupRepository CRD schemas.
- Rotating or migrating existing keys automatically.
- Removing the legacy shared `velero-repo-credentials` Secret.
- Supporting custom user-provided per-BSL passwords in this iteration.
- Changing the encryption algorithm or repository format.

## High-Level Design

A new `keys` package under `pkg/repository/keys` manages the lifecycle of repository encryption keys.
It exposes functions to ensure the legacy shared key exists and to ensure a per-BSL key exists.
Per-BSL Secrets are named `velero-repo-credentials-<bsl-name>` and are created lazily when a repository is initialized or prepared.
The `unifiedRepoProvider`, repository `manager`, and uploader providers (`kopia` and `block`) are updated to accept a Kubernetes Secrets client and a BSL name so they can select the appropriate Secret.
If a per-BSL Secret is missing, the system transparently falls back to the legacy shared Secret, preserving existing behavior.

## Detailed Design

### Encryption key lifecycle

#### Legacy shared key

`EnsureCommonRepositoryKey(secretClient, namespace)` checks for the legacy Secret `velero-repo-credentials`.
If the Secret does not exist, it creates one with a 32-byte cryptographically random password encoded as 64 hex characters.
Existing Secrets are left untouched to preserve currently configured passwords.
The legacy Secret key `repository-password` is unchanged.

#### Per-BSL key

`EnsureBSLRepositoryKey(secretClient, namespace, bslName)` checks for `velero-repo-credentials-<bsl-name>`.
If the Secret does not exist, it creates one with a 32-byte cryptographically random password encoded as 64 hex characters.
The Secret is labeled with `velero.io/bsl-name: <bsl-name>` and `velero.io/secret-type: bsl-repo-credentials` for identification and future selection.
Existing per-BSL Secrets are not overwritten to avoid changing the key of an existing repository.

#### Key selection

`BSLRepoKeySelector(secretClient, namespace, bslName)` returns a `SecretKeySelector` for the per-BSL Secret when it exists.
If the per-BSL Secret does not exist or the BSL name is empty, it returns a selector for the legacy shared Secret.
This supports both new and existing repositories without explicit migration.

### Repository provider changes

#### NewUnifiedRepoProvider signature

```go
func NewUnifiedRepoProvider(
    credentialGetter credentials.CredentialGetter,
    secretClient corev1client.SecretsGetter,
    namespace string,
    repoBackend string,
    log logrus.FieldLogger,
) Provider
```

The `unifiedRepoProvider` struct adds `secretClient` and `namespace` fields.
`InitRepo` and `PrepareRepo` call `ensureBSLKey(param)` before constructing repository options.
`ensureBSLKey` invokes `keys.EnsureBSLRepositoryKey` for the BSL referenced by `param.BackupLocation.Name`.
`GetPassword` retrieves `param.BackupLocation.Name` and uses `keys.BSLRepoKeySelector` to choose the correct Secret.
`BoostRepoConnect` in `datapath` passes `nil` for `secretClient` because it is a connection-only path that does not create keys.

### Repository manager changes

#### NewManager signature

```go
func NewManager(
    namespace string,
    client client.Client,
    repoLocker *repository.RepoLocker,
    credentialFileStore credentials.FileStore,
    credentialSecretStore credentials.SecretStore,
    secretClient corev1client.SecretsGetter,
    log logrus.FieldLogger,
) Manager
```

The Velero server and maintenance CLI pass `kubeClient.CoreV1()` as the `secretClient`.
The Kopia provider inside `manager` is constructed with the secret client and namespace.

### Uploader provider changes

#### Provider constructors

```go
func NewKopiaUploaderProvider(
    requestorType string,
    ctx context.Context,
    credGetter *credentials.CredentialGetter,
    backupRepo *velerov1api.BackupRepository,
    repoKeySelector *corev1api.SecretKeySelector,
    log logrus.FieldLogger,
) (Provider, error)

func NewBlockUploaderProvider(
    requestorType string,
    ctx context.Context,
    credGetter *credentials.CredentialGetter,
    backupRepo *velerov1api.BackupRepository,
    repoKeySelector *corev1api.SecretKeySelector,
    log logrus.FieldLogger,
) (Provider, error)
```

`NewUploaderProvider` accepts a `repoKeySelector` and passes it to the selected uploader.
Both `kopiaProvider` and `blockProvider` store the selector and use it in `GetPassword`.
If the selector is nil, they fall back to `keys.RepoKeySelector()`.

### Secret naming and labeling

Per-BSL Secret name: `velero-repo-credentials-<bsl-name>`.
Per-BSL Secret labels:
- `velero.io/bsl-name: <bsl-name>`
- `velero.io/secret-type: bsl-repo-credentials`

## Alternatives Considered

### Single shared key with manual rotation

Keep the existing single shared Secret and document key rotation procedures.
This was rejected because it does not provide isolation between BSLs and leaves all backups exposed if the single Secret is compromised.

### User-supplied per-BSL keys

Allow users to create and reference their own Secrets per BSL.
This was rejected for this iteration because it requires CRD changes, CLI or UX work, and migration tooling.
It can be added later without conflicting with the auto-generated key approach.

### Cluster-wide unique Secret per BackupRepository

Generate a unique key per `BackupRepository` instead of per `BackupStorageLocation`.
This was rejected because repositories for the same BSL are logically grouped and rotating keys per repository would complicate restore operations and repository maintenance.

## Security Considerations

- Per-BSL keys limit the blast radius of a compromised Secret to a single BSL.
- Newly generated keys use `crypto/rand` and are 32 bytes (256 bits) of entropy, encoded as 64 hex characters.
- Existing Secrets are never overwritten, preventing accidental key rotation that could lock out repositories.
- The legacy `velero-repo-credentials` Secret remains a fallback, so existing backups remain accessible.
- Secret labels allow administrators to identify which BSL a Secret belongs to.
- Velero's existing RBAC on Secrets should already restrict access to the Velero namespace; this design does not change RBAC requirements.

## Compatibility

- Existing repositories that already use the shared `velero-repo-credentials` Secret continue to work unchanged.
- New BSLs automatically receive a dedicated Secret on first repository initialization or preparation.
- The fallback from per-BSL selector to shared selector is transparent to callers.
- No CRD changes are required, so existing BackupStorageLocation and BackupRepository objects remain valid.
- Downgrades require the per-BSL Secret to remain present; downgrading to a Velero version that does not understand the per-BSL Secret will still use the legacy shared Secret because the repositories were originally created with it.

## Implementation

The implementation is split into three layers.

1. Key management package (`pkg/repository/keys`):
   - Add `EnsureBSLRepositoryKey`, `BSLRepoKeySelector`, `GetBSLSecretName`, and `bslSecretName`.
   - Change `EnsureCommonRepositoryKey` to generate a random password if the legacy Secret is missing.
   - Add unit tests for all new functions and the updated `RepoKeySelector`.

2. Repository provider and manager:
   - Update `NewUnifiedRepoProvider`, `NewManager`, server initialization, and maintenance CLI to pass a Kubernetes secret client and namespace.
   - Call `ensureBSLKey` in `InitRepo` and `PrepareRepo`.
   - Use `BSLRepoKeySelector` in `GetPassword`.

3. Uploader providers:
   - Update `NewUploaderProvider`, `NewKopiaUploaderProvider`, and `NewBlockUploaderProvider` to accept and use a `repoKeySelector`.
   - Use the per-BSL selector in `GetPassword` with fallback to the legacy selector.

## Open Issues

- Should Velero migrate existing repositories from the shared key to a per-BSL key automatically, or should that remain a manual operation?
- Should the per-BSL Secret name be configurable through an annotation or remain hard-coded?
- Do we need an administrative command to list, delete, or rotate per-BSL encryption keys?
