# Dynamic Resource Autocompletion for Velero CLI

## Abstract

Velero CLI has no dynamic shell completion for resource names ([#9782](https://github.com/vmware-tanzu/velero/issues/9782)).
Tab-completing `velero backup describe <TAB>` produces no suggestions, even when backups exist on the cluster.
This proposal adds dynamic completion for all commands that take Velero resource names as positional arguments or flag values (using cobra's built-in completion callbacks).

## Background

Shell completion is a standard UX feature in Kubernetes CLI tooling.
Tools like `kubectl`, `oc`, and `helm` all provide dynamic completions that query the cluster to suggest resource names.
Velero's `velero completion` command generates completion scripts, but the CLI does not register any completion callbacks, so tab-completing resource names produces no suggestions.
Cobra's completion infrastructure already supports dynamic completion across all shell types (bash, zsh, fish); Velero just needs to register the callbacks.

## Goals

- Add dynamic shell completion for all 20 commands that accept existing Velero resource names as positional arguments.
- Add dynamic flag completion for 9 flags that reference existing Velero resources.
- Fail silently when the cluster is unreachable, matching the behavior of `kubectl`.

## Non Goals

- Completing positional arguments for commands that take new resource names (e.g., `velero backup create <new-name>`).
- Completing flags that take non-resource values (e.g., `--include-namespaces`, `--labels`).
- Adding completion for hidden internal commands (`data-mover`, `pod-volume`, `repo-maintenance`).
- Caching cluster state across tab presses.

## High-Level Design

A centralized set of completion functions is added to `pkg/cmd/cli/completion_functions.go`.
Each function takes a `client.Factory`, returns a closure matching cobra's completion function signature, and lists resources of a specific type from the cluster.
Each command constructor wires the appropriate completion function onto its `cobra.Command` via `ValidArgsFunction` or `RegisterFlagCompletionFunc`.

## Detailed Design

### Completion functions

A new file `pkg/cmd/cli/completion_functions.go` provides six public functions:

| Function | Resource listed |
|---|---|
| `CompleteBackupNames(f client.Factory)` | `BackupList` |
| `CompleteRestoreNames(f client.Factory)` | `RestoreList` |
| `CompleteScheduleNames(f client.Factory)` | `ScheduleList` |
| `CompleteBackupStorageLocationNames(f client.Factory)` | `BackupStorageLocationList` |
| `CompleteVolumeSnapshotLocationNames(f client.Factory)` | `VolumeSnapshotLocationList` |
| `CompleteBackupRepositoryNames(f client.Factory)` | `BackupRepositoryList` |

All six delegate to a single private `completeNames` helper that uses `meta.ExtractList()` and `meta.Accessor()` to extract names from any `ObjectList` type.

The completion closure:

- Lists resources in the configured namespace with a **3-second context timeout**.
- Filters by `strings.HasPrefix(name, toComplete)`.
- Removes names already present in `args` to avoid re-suggesting previously typed arguments.
- Returns `cobra.ShellCompDirectiveNoFileComp` in all cases (success or failure).
- Fails silently on any error (client construction, API call, extraction), returning no suggestions.

### Commands wired with `ValidArgsFunction`

| Package | Commands | Completion function |
|---|---|---|
| `backup` | get, describe, delete, logs, download | `CompleteBackupNames` |
| `restore` | get, describe, delete, logs | `CompleteRestoreNames` |
| `schedule` | get, describe, delete, pause, unpause | `CompleteScheduleNames` |
| `backuplocation` | get, set, delete | `CompleteBackupStorageLocationNames` |
| `snapshotlocation` | get, set | `CompleteVolumeSnapshotLocationNames` |
| `repo` | get | `CompleteBackupRepositoryNames` |

### Flags wired with `RegisterFlagCompletionFunc`

| Command | Flag | Completion function |
|---|---|---|
| `backup create` | `--from-schedule` | `CompleteScheduleNames` |
| `backup create` | `--storage-location` | `CompleteBackupStorageLocationNames` |
| `backup create` | `--volume-snapshot-locations` * | `CompleteVolumeSnapshotLocationNames` |
| `schedule create` | `--storage-location` | `CompleteBackupStorageLocationNames` |
| `schedule create` | `--volume-snapshot-locations` * | `CompleteVolumeSnapshotLocationNames` |
| `restore create` | `--from-backup` | `CompleteBackupNames` |
| `restore create` | `--from-schedule` | `CompleteScheduleNames` |
| `debug` | `--backup` | `CompleteBackupNames` |
| `debug` | `--restore` | `CompleteRestoreNames` |

\* See Open Issues — comma-separated values.

## Alternatives Considered

The approach follows the standard cobra pattern for dynamic completion. No alternative designs were considered.

## Security Considerations

Completion functions issue read-only list requests using the user's existing kubeconfig credentials.
No new permissions are required beyond what the user already has.
Users without list permission receive empty completions, consistent with kubectl's behavior.

## Compatibility

Existing command behavior is unaffected.
`ValidArgsFunction` is only invoked during shell completion; it has no effect on normal command execution.
Completion respects the `--namespace` flag and `VELERO_NAMESPACE` environment variable.

## Testing

Unit tests in `pkg/cmd/cli/completion_functions_test.go` cover:

- **Core logic:** Table-driven tests across all six resource types: empty cluster, full match, prefix filtering, no match.
- **Error resilience:** Factory errors return nil completions without panicking.
- **Wrapper isolation:** Each `Complete*Names` wrapper returns only its own resource type.

## Open Issues

- **Single-argument commands:** Commands like `backup download` and `backup logs` accept exactly one positional argument, but cobra still calls the completion function after one arg is provided.
The completion function should check `len(args)` and return no suggestions when the maximum arg count is reached.
The approach (parameter on the helper vs. per-command wrapper) is TBD.

- **Comma-separated flag values:** `--volume-snapshot-locations` accepts comma-separated values.
Completion only works for the first value because `toComplete` contains the full string including commas.
Completing subsequent values would require comma-aware splitting, similar to how kubectl handles this.

- **Bash v1 to v2 migration:** The current bash completion generator already supports dynamic completion through cobra's `__complete` mechanism, so migration to v2 is not required for this feature.
A separate migration could be considered for other benefits (cleaner generated scripts, ActiveHelp support) but would require users to regenerate their completion scripts.
