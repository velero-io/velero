# Design proposal: per-BackupRepository encryption keys

## Abstract

Currently Velero derives the encryption password for every backup repository from a single shared Secret named `velero-repo-credentials`.
This design proposes generating and managing a unique repository encryption key per BackupRepository (i.e., per BackupStorageLocation per source namespace) while retaining the legacy shared Secret as a fallback.
The change improves cryptographic isolation between repositories and removes reliance on a single shared password without breaking existing repositories.

## Background

Velero stores backup data in object storage through BackupStorageLocations.
For each BackupStorageLocation and source namespace combination, Velero creates a BackupRepository that is encrypted at rest by Kopia or the block data mover.
Today every repository is unlocked with the same password read from the `velero-repo-credentials` Secret in the Velero namespace.
If that single Secret is compromised, all backups across all BSLs and namespaces become readable.
A key that is scoped only to the BackupStorageLocation would not improve isolation because the same BSL can be shared by multiple BackupRepositories in different source namespaces.
This proposal changes the key lifecycle so that each BackupRepository receives its own randomly generated encryption key stored in a dedicated Kubernetes Secret.

## Goals

- Provide per-BackupRepository encryption key isolation.
- Maintain backward compatibility with existing repositories that use the shared `velero-repo-credentials` Secret.
- Generate strong, cryptographically random encryption keys instead of relying on static or reused passwords.
- Ensure repository providers and uploaders use the correct key for the BackupRepository being accessed.

## Non Goals

- Changing BackupStorageLocation or BackupRepository CRD schemas.
- Rotating or migrating existing keys automatically.
- Removing the legacy shared `velero-repo-credentials` Secret.
- Supporting custom user-provided per-BackupRepository passwords in this iteration.
- Changing the encryption algorithm or repository format.

## High-Level Design

A new `keys` package under `pkg/repository/keys` manages the lifecycle of repository encryption keys.
It exposes functions to ensure the legacy shared key exists and to ensure a per-BackupRepository key exists.
Per-BackupRepository Secrets are derived from the BackupStorageLocation name and the source namespace (the namespace of the BackupRepository) and are created lazily when a repository is initialized or prepared.
The `unifiedRepoProvider`, repository `manager`, and uploader providers (`kopia` and `block`) are updated to accept a Kubernetes Secrets client and the BackupRepository identity so they can select the appropriate Secret.
If a per-BackupRepository Secret is missing, the system transparently falls back to the legacy shared Secret, preserving existing behavior.

## Detailed Design

### Encryption key lifecycle

#### Legacy shared key

`EnsureCommonRepositoryKey(secretClient, namespace)` checks for the legacy Secret `velero-repo-credentials`.
If the Secret does not exist, it creates one with a 32-byte cryptographically random password encoded as 64 hex characters.
Existing Secrets are left untouched to preserve currently configured passwords.
The legacy Secret key `repository-password` is unchanged.

#### Per-BackupRepository key

`EnsureBackupRepositoryKey(secretClient, namespace, backupRepo)` checks for the Secret that corresponds to the BackupRepository.
The Secret name is derived from the BackupStorageLocation name and the BackupRepository's source namespace.
If the Secret does not exist, it creates one with a 32-byte cryptographically random password encoded as 64 hex characters.
The Secret is labeled with `velero.io/bsl-name: <bsl-name>`, `velero.io/source-namespace: <namespace>`, and `velero.io/secret-type: backup-repo-credentials` for identification and future selection.
Existing per-BackupRepository Secrets are not overwritten to avoid changing the key of an existing repository.

#### Key selection

`BackupRepositoryKeySelector(secretClient, namespace, backupRepo)` returns a `SecretKeySelector` for the per-BackupRepository Secret when it exists.
If the per-BackupRepository Secret does not exist or the BackupRepository identity is empty, it returns a selector for the legacy shared Secret.
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
`InitRepo` and `PrepareRepo` call `ensureBackupRepositoryKey(param)` before constructing repository options.
`ensureBackupRepositoryKey` invokes `keys.EnsureBackupRepositoryKey` for the BackupRepository referenced by `param.BackupRepo` and its associated `param.BackupLocation`.
`GetPassword` uses `keys.BackupRepositoryKeySelector` to choose the correct Secret based on `param.BackupRepo` and `param.BackupLocation`.
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
The caller computes the selector from the BackupRepository and BackupStorageLocation before invoking `NewUploaderProvider`.

### Secret naming and labeling

Per-BackupRepository Secret name is derived from the BackupStorageLocation name and the source namespace.
For example: `velero-repo-credentials-<bsl-name>-<source-namespace>`.
If the generated name exceeds Kubernetes limits, a deterministic hash of the BSL name and source namespace may be used.
Per-BackupRepository Secret labels:
- `velero.io/bsl-name: <bsl-name>`
- `velero.io/source-namespace: <source-namespace>`
- `velero.io/secret-type: backup-repo-credentials`

## Alternatives Considered

### Single shared key with manual rotation

Keep the existing single shared Secret and document key rotation procedures.
This was rejected because it does not provide any isolation between repositories and leaves all backups exposed if the single Secret is compromised.

### Per-BackupStorageLocation key

Generate a unique key per BackupStorageLocation.
This was rejected because a single BSL can be used by multiple BackupRepositories in different source namespaces, so a per-BSL key would still be shared across those repositories.
Per-BackupRepository isolation is required for meaningful cryptographic separation.

### User-supplied per-BackupRepository keys

Allow users to create and reference their own Secrets per BackupRepository.
This was rejected for this iteration because it requires CRD changes, CLI or UX work, and migration tooling.
It can be added later without conflicting with the auto-generated key approach.

## Security Considerations

- Per-BackupRepository keys limit the blast radius of a compromised Secret to a single repository.
- Newly generated keys use `crypto/rand` and are 32 bytes (256 bits) of entropy, encoded as 64 hex characters.
- Existing Secrets are never overwritten, preventing accidental key rotation that could lock out repositories.
- The legacy `velero-repo-credentials` Secret remains a fallback, so existing backups remain accessible.
- Secret labels allow administrators to identify which BSL and source namespace a Secret belongs to.
- Velero's existing RBAC on Secrets should already restrict access to the Velero namespace; this design does not change RBAC requirements.

## Compatibility

- Existing repositories that already use the shared `velero-repo-credentials` Secret continue to work unchanged.
- New BackupRepositories automatically receive a dedicated Secret on first repository initialization or preparation.
- The fallback from per-BackupRepository selector to shared selector is transparent to callers.
- No CRD changes are required, so existing BackupStorageLocation and BackupRepository objects remain valid.
- Downgrades require the per-BackupRepository Secret to remain present; downgrading to a Velero version that does not understand the per-BackupRepository Secret will still use the legacy shared Secret because the repositories were originally created with it.

## Implementation

The implementation is split into three layers.

1. Key management package (`pkg/repository/keys`):
   - Add `EnsureBackupRepositoryKey`, `BackupRepositoryKeySelector`, and helper functions to derive the Secret name from the BSL and source namespace.
   - Change `EnsureCommonRepositoryKey` to generate a random password if the legacy Secret is missing.
   - Add unit tests for all new functions and the updated `RepoKeySelector`.

2. Repository provider and manager:
   - Update `NewUnifiedRepoProvider`, `NewManager`, server initialization, and maintenance CLI to pass a Kubernetes secret client and namespace.
   - Call `ensureBackupRepositoryKey` in `InitRepo` and `PrepareRepo` using `param.BackupRepo` and `param.BackupLocation`.
   - Use `BackupRepositoryKeySelector` in `GetPassword`.

3. Uploader providers:
   - Update `NewUploaderProvider`, `NewKopiaUploaderProvider`, and `NewBlockUploaderProvider` to accept and use a `repoKeySelector`.
   - Use the per-BackupRepository selector in `GetPassword` with fallback to the legacy selector.

## Open Issues

- Should Velero migrate existing repositories from the shared key to a per-BackupRepository key automatically, or should that remain a manual operation?
- Should the per-BackupRepository Secret name be fully hard-coded from BSL and source namespace, or should it support an annotation override?
- Do we need an administrative command to list, delete, or rotate per-BackupRepository encryption keys?
