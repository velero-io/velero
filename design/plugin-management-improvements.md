# Enhanced Plugin Management Design

## Glossary & Abbreviation

**Plugin**: A Velero plugin is a binary that implements one or more of Velero's plugin interfaces (e.g., ObjectStore, VolumeSnapshotter, BackupItemAction).

**Built-in Plugin**: A plugin registered by the Velero server binary itself at startup, as opposed to a plugin provided by an external init container.

**Init Container**: A Kubernetes init container added to the Velero deployment to install an external plugin binary before the server starts.

**ServerStatusRequest (SSR)**: A Velero CRD used to query live metadata about the running Velero server, including its version and the list of registered plugins. See [ServerStatusRequest types][1].

**PluginInfo**: The struct within `ServerStatusRequestStatus` that describes a single registered plugin (name and kind).

## Background

Velero supports a plugin system where external plugins are installed by adding init containers to the Velero deployment.
Some plugins are built into the server binary itself (e.g., all `velero.io/*` BackupItemActions and RestoreItemActions).
`velero plugin get` shows all registered plugins regardless of origin, but currently gives users no way to distinguish built-in plugins from external ones.

This leads to two concrete problems.
First, users cannot tell which plugins can be safely removed:

```console
$ velero plugin get
NAME                              KIND
velero.io/pod                     BackupItemAction
velero.io/pv                      BackupItemAction
velero.io/service-account         BackupItemAction
velero.io/aws                     ObjectStore
velero.io/aws                     VolumeSnapshotter
...
```

Second, `velero plugin remove` requires the exact init container name or image string, not the plugin name visible in `velero plugin get`.
Attempting to use the friendly name fails with a confusing error:

```console
$ velero plugin remove velero.io/aws
An error occurred: init container velero.io/aws not found in Velero server deployment
```

Users expect `velero plugin remove velero.io/aws` to work, and they expect a clear error when trying to remove a plugin that cannot be removed (see [issue 3210][3]).

## Goals

- Expose whether each plugin is built-in via the `ServerStatusRequest` API.
- Display built-in status in `velero plugin get` CLI output.
- Allow `velero plugin remove <plugin-name>` to resolve a plugin name to its backing init container.
- Refuse removal of built-in plugins with a descriptive error message.
- Preserve backwards compatibility for `velero plugin remove <image|container-name>`.

## Non-Goals

- Changing how plugins are discovered or registered at runtime.
- Adding a plugin package or registry system.
- Redesigning how external plugins are distributed or packaged.
- Supporting removal of multiple plugins in a single command invocation.

## Solution

### Built-in Plugin Detection

The Velero plugin framework already tracks which binary registered each plugin via `PluginIdentifier.Command`.
At `ServerStatusRequest` processing time, the server compares each plugin's `Command` to `os.Args[0]`.
If they match, the plugin was registered by the server binary and is marked built-in.
External plugins are always registered by init container binaries, which have distinct binary paths from the server binary.

### Plugin Removal by Name

Plugin names shown in `velero plugin get` contain a `/` (e.g., `velero.io/aws`).
Init container names and images may also contain `/` (e.g., `docker.io/myrepo/plugin:v1`), so the presence of `/` alone does not identify an argument as a plugin name.
The removal command therefore always attempts an exact match on container name or image first.
Only when no exact match is found and the argument contains `/` does the command perform a server status lookup and name-to-container resolution using heuristics.

The resolution falls back gracefully: if the server is unavailable or does not respond, the command skips the built-in check and proceeds directly to container matching.
This preserves compatibility with environments where the server is temporarily unreachable.

### CLI Output

A `BuiltIn` column is added to `velero plugin get` to give operators an at-a-glance view of which plugins are mandatory and which can be removed.
The column displays `true` for built-in plugins and is empty for external plugins, avoiding visual noise for the common case.

## Detailed Design

### API Changes

Two optional fields are added to `PluginInfo` in `pkg/apis/velero/v1/server_status_request_types.go`.
Both are `omitempty` to preserve API compatibility with older clients and servers:

```go
type PluginInfo struct {
    Name string `json:"name"`
    Kind string `json:"kind"`

    // Command is the command/binary that registered the plugin on the server.
    // For built-in Velero plugins this will be the Velero server binary.
    // This field is for informational/diagnostic purposes.
    // +optional
    Command string `json:"command,omitempty"`

    // BuiltIn indicates whether the plugin is provided by the Velero server
    // binary and cannot be removed by changing init containers.
    // +optional
    BuiltIn bool `json:"builtIn,omitempty"`
}
```

### Server-Side Detection

`GetInstalledPluginInfo` in `internal/velero/serverstatusrequest.go` is updated to populate the new fields.
For each registered plugin, `Command` is set to the binary path that registered it, and `BuiltIn` is set to `true` when that path matches `os.Args[0]` (the running server binary).

### CLI Output Changes

The plugin table printer in `pkg/cmd/util/output/plugin_printer.go` adds a `BuiltIn` column.
The value is rendered as a boolean; because `BuiltIn` uses `omitempty` in JSON, external plugins will show an empty cell rather than `false`, keeping the output readable:

```console
NAME                              KIND                  BUILTIN
velero.io/pod                     BackupItemAction      true
velero.io/pv                      BackupItemAction      true
velero.io/service-account         BackupItemAction      true
velero.io/aws                     ObjectStore
velero.io/aws                     VolumeSnapshotter
```

### Plugin Removal Workflow

`velero plugin remove` ([remove.go][2]) accepts `NAME | IMAGE | PLUGIN-NAME`.
The full resolution sequence is:

**Step 1 — Exact match (always runs first):**
Scan the Velero deployment's init containers for a container whose `name` or `image` exactly equals the argument.
If found, remove it immediately using the existing patch behavior.

**Step 2 — Name resolution (only when no exact match and argument contains `/`):**

1. Query the server via `ServerStatusRequest`.
   - If the request fails or times out, skip the built-in check and proceed to step 2b.
   - If the named plugin is found and `BuiltIn == true`, refuse with:
     `"plugin <name> is built-in and cannot be removed"`
   - If the named plugin is not found in the server status, proceed to step 2b.

2. Apply heuristics to find an init container for the plugin:
   - Sanitized name: replace `/`, `_`, `.` with `-` in the argument and compare to container name.
   - Last-segment substring: extract the final path segment (e.g., `aws` from `velero.io/aws`) and check whether it appears as a substring in any container name or image.

3. If zero candidates match, error with the list of current init containers and their images.
4. If multiple candidates match, error requesting the user to specify the container name or image directly.
5. If exactly one candidate matches, remove it using the existing patch behavior.

The heuristic substring match on the last path segment can produce false positives when multiple init containers share a common word.
Users can always fall back to the exact image or container name form to disambiguate.

## Alternatives Considered

### Built-in detection: explicit annotation vs. `os.Args[0]` comparison

An alternative is to require plugin authors to annotate or register their plugins with an explicit `BuiltIn: true` field, rather than inferring it from the binary path.
This was rejected because it requires changes to the plugin registration API and backward-incompatible updates to all plugin implementations.
The `os.Args[0]` comparison requires no changes outside the server itself and is reliable in practice: init container binaries run from different paths than the server binary.

### Name resolution: explicit mapping annotation vs. heuristic matching

An alternative is to require operators to annotate each init container with the plugin names it provides (e.g., `velero.io/plugin-names: "velero.io/aws"`).
This would give deterministic, zero-ambiguity resolution.
It was deferred rather than rejected: it requires user-visible configuration changes and documentation updates, whereas heuristic matching covers the common case (one plugin per init container, image name mirrors plugin name) with no operator action.
Explicit annotation support can be added later without breaking the heuristic path.

## Compatibility

- **API**: The new `Command` and `BuiltIn` fields on `PluginInfo` are optional with `omitempty`. Older clients that do not know about these fields will receive them silently and can ignore them. A new client talking to an old server will receive neither field and should treat absent `BuiltIn` as `false`.
- **CLI**: `velero plugin remove <image|container-name>` continues to function exactly as before. The new resolution path is only reached when no exact match is found and the argument contains `/`.

## Security Considerations

- The `Command` field exposes the binary path used to register each plugin (e.g., `/usr/local/bin/velero`). This is path metadata already visible to anyone with access to the Velero pod, and adds no new attack surface.
- The `ServerStatusRequest` is a read-only status resource. Adding informational fields does not introduce elevated privileges.
- The built-in guard prevents accidental removal of mandatory plugins. Removal still requires permissions to patch the Velero `Deployment`, which is an existing cluster-admin-level requirement.

[1]: pkg/apis/velero/v1/server_status_request_types.go
[2]: pkg/cmd/cli/plugin/remove.go
[3]: https://github.com/vmware-tanzu/velero/issues/3210
