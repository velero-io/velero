# Dynamic Resource Autocompletion for Velero CLI

## Abstract

Velero CLI currently has no dynamic shell completion for resource names.
Tab-completing `velero backup describe <TAB>` produces no suggestions, even when backups exist on the cluster.
This proposal adds dynamic completion for all commands that take Velero resource names as positional arguments or flag values, using cobra's `ValidArgsFunction` and `RegisterFlagCompletionFunc` mechanisms.

## Background

Shell completion is a standard UX feature in Kubernetes CLI tooling.
Tools like `kubectl`, `oc`, and `helm` all provide dynamic completions that query the cluster to suggest resource names.
Velero's `velero completion` command generates static completion scripts using cobra's v1 API (`GenBashCompletion`), which only completes command and flag names.
Cobra v1.8.1 (Velero's current version) supports dynamic completion via `ValidArgsFunction` on `cobra.Command` and `RegisterFlagCompletionFunc` for flag values, but Velero does not use either.

The bash v1 completion generator (`GenBashCompletion`) does not invoke `ValidArgsFunction` callbacks.
Cobra provides a v2 generator (`GenBashCompletionV2`) that does.
The zsh and fish generators already support `ValidArgsFunction` natively.

## Goals

- Add dynamic shell completion for all 20 commands that accept existing Velero resource names as positional arguments.
- Add dynamic flag completion for 5 flags that reference existing Velero resources (`--from-backup`, `--from-schedule`, `--storage-location`, `--volume-snapshot-locations`).
- Fail silently when the cluster is unreachable, matching the behavior of `oc` and `kubectl`.

## Non Goals

- Completing positional arguments for commands that take new resource names (e.g., `velero backup create <new-name>`).
- Completing flags that take non-resource values (e.g., `--include-namespaces`, `--labels`).
- Adding completion for hidden internal commands (`data-mover`, `pod-volume`, `repo-maintenance`).
- Caching cluster state across tab presses.

## High-Level Design

A centralized set of completion functions is added to `pkg/cmd/cli/completion_functions.go`.
Each function takes a `client.Factory`, returns a closure matching cobra's `ValidArgsFunction` signature, and lists resources of a specific type from the cluster.
Each command constructor wires the appropriate completion function onto its `cobra.Command` via `ValidArgsFunction` or `RegisterFlagCompletionFunc`.
The bash completion generator is switched from v1 to v2 to enable dynamic completion support.

## Detailed Design

### Completion functions

A new file `pkg/cmd/cli/completion_functions.go` in the `cli` package provides six public functions:

| Function | Resource listed |
|---|---|
| `CompleteBackupNames(f client.Factory)` | `velerov1api.BackupList` |
| `CompleteRestoreNames(f client.Factory)` | `velerov1api.RestoreList` |
| `CompleteScheduleNames(f client.Factory)` | `velerov1api.ScheduleList` |
| `CompleteBackupStorageLocationNames(f client.Factory)` | `velerov1api.BackupStorageLocationList` |
| `CompleteVolumeSnapshotLocationNames(f client.Factory)` | `velerov1api.VolumeSnapshotLocationList` |
| `CompleteBackupRepositoryNames(f client.Factory)` | `velerov1api.BackupRepositoryList` |

Each function returns a `func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)` closure.
The closure:

1. Calls `f.KubebuilderClient()` to get a controller-runtime client.
2. Lists resources in `f.Namespace()`.
3. Filters names by `strings.HasPrefix(name, toComplete)`.
4. Returns the matching names with `cobra.ShellCompDirectiveNoFileComp`.

If either the client construction or the list call fails, the function returns `nil, cobra.ShellCompDirectiveNoFileComp` (silent failure, no file completion fallback).

A package-level type alias keeps the function signatures readable:

```go
type completionFunc = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)
```

Note: `cobra.ValidArgsFunction` is not an exported type in cobra v1.8.1.
It is only the inline type of the `ValidArgsFunction` field on `cobra.Command`.
The type alias is used for return types of the completion helper functions and is directly assignable to the field.

### Commands wired with `ValidArgsFunction`

Each `New*Command` constructor sets `c.ValidArgsFunction` after creating the command and before returning it.
Because Velero exposes both `velero backup get` and `velero get backups` via the same constructor function (`backup.NewGetCommand`), both command trees get completion automatically.

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
| `backup create` | `--volume-snapshot-locations` | `CompleteVolumeSnapshotLocationNames` |
| `restore create` | `--from-backup` | `CompleteBackupNames` |
| `restore create` | `--from-schedule` | `CompleteScheduleNames` |

The return value of `RegisterFlagCompletionFunc` is discarded (`_ =`) because it only fails if the named flag does not exist, which would be a compile-time coding error.

### Bash completion v1 to v2 migration

In `pkg/cmd/cli/completion/completion.go`, the bash case is changed from:

```go
cmd.Root().GenBashCompletion(os.Stdout)
```

to:

```go
cmd.Root().GenBashCompletionV2(os.Stdout, true)
```

The `true` parameter includes completion descriptions.
Zsh and fish generators are unchanged as they already support `ValidArgsFunction`.

### Client construction

Completion functions use `f.KubebuilderClient()`, which constructs a REST config and a controller-runtime client with the Velero scheme on each invocation.
This is the same client used by the commands themselves.
The factory is captured by closure from the command constructor, so no changes to `completion.NewCommand()` or the root command wiring are needed.

## Alternatives Considered

### Generic completion function using Go generics

A single generic function parameterized by list type and item type was considered to avoid the six similar functions.
This was rejected because the list types do not share a common interface for extracting item names (no `GetItems()` method), so the generic version would need function parameters for constructing the list and extracting names, making it no simpler than individual functions.

### Passing the factory to the completion command

It was considered whether `completion.NewCommand()` should receive `client.Factory` to register completion callbacks centrally.
This is unnecessary because `ValidArgsFunction` is set per-command-instance in each constructor, and cobra's hidden `__complete` command handles runtime dispatch.
The completion command only generates the shell script.

## Security Considerations

Completion functions issue read-only list requests to the Kubernetes API server using the user's existing kubeconfig credentials.
No new permissions are required beyond what the user already has for the commands themselves.
No data is written, cached, or transmitted to external services.

## Compatibility

The bash completion output format changes from v1 to v2.
Users who have previously generated and sourced bash completion scripts will need to regenerate them with `velero completion bash`.
This is the expected workflow when upgrading any CLI tool.
Zsh and fish completion scripts are unchanged in format.

Existing command behavior is unaffected.
The `ValidArgsFunction` field is only invoked during shell completion; it has no effect on normal command execution.

## Implementation

The implementation is contained in a single commit on the `feature/dynamic-cli-completion` branch.
It touches 24 files (1 new, 23 modified) with 201 insertions and 1 deletion.
All existing tests pass without modification.
