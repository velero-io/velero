---
title: "Plugins"
layout: docs
---

Velero has a plugin architecture that allows users to add their own custom functionality to Velero backups & restores without having to modify/recompile the core Velero binary. To add custom functionality, users simply create their own binary containing implementations of Velero's plugin kinds (described below), plus a small amount of boilerplate code to expose the plugin implementations to Velero. This binary is added to a container image that serves as an init container for the Velero server pod and copies the binary into a shared emptyDir volume for the Velero server to access.

Multiple plugins, of any type,  can be implemented in this binary.

A fully-functional [sample plugin repository][1] is provided to serve as a convenient starting point for plugin authors.

## Plugin Naming

When naming your plugin, keep in mind that the name needs to conform to these rules:
- have two parts separated by '/'
- none of the above parts can be empty
- the prefix is a valid DNS subdomain name
- a plugin with the same name cannot already exist

### Some examples:

```
- example.io/azure
- 1.2.3.4/5678
- example-with-dash.io/azure
```

You will need to give your plugin(s) a name when registering them by calling the appropriate `RegisterX` function: <https://github.com/velero-io/velero/blob/0e0f357cef7cf15d4c1d291d3caafff2eeb69c1e/pkg/plugin/framework/server.go#L42-L60>

## Plugin Kinds

Velero currently supports the following kinds of plugins:

- **Object Store** - persists and retrieves backups, backup logs and restore logs
- **Volume Snapshotter** - creates volume snapshots (during backup) and restores volumes from snapshots (during restore)
- **Backup Item Action** - executes arbitrary logic for individual items prior to storing them in a backup file
- **Restore Item Action** - executes arbitrary logic for individual items prior to restoring them into a cluster

## Plugin Logging

Velero provides a [logger][2] that can be used by plugins to log structured information to the main Velero server log or
per-backup/restore logs. It also passes a `--log-level` flag to each plugin binary, whose value is the value of the same
flag from the main Velero process. This means that if you turn on debug logging for the Velero server via `--log-level=debug`,
plugins will also emit debug-level logs. See the [sample repository][1] for an example of how to use the logger within your plugin.

## Plugin Configuration

Velero uses a ConfigMap-based convention for providing configuration to plugins. If your plugin needs to be configured at runtime, 
define a ConfigMap like the following:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  # any name can be used; Velero uses the labels (below)
  # to identify it rather than the name
  name: my-plugin-config
  
  # must be in the namespace where the velero deployment
  # is running
  namespace: velero
  
  labels:
    # this value-less label identifies the ConfigMap as
    # config for a plugin (i.e. the built-in change storageclass
    # restore item action plugin)
    velero.io/plugin-config: ""
    
    # add a label whose key corresponds to the fully-qualified
    # plugin name (e.g. mydomain.io/my-plugin-name), and whose
    # value is the plugin type (BackupItemAction, RestoreItemAction,
    # ObjectStore, or VolumeSnapshotter)
    <fully-qualified-plugin-name>: <plugin-type>

data:
  # add your configuration data here as key-value pairs
```

Then, in your plugin's implementation, you can read this ConfigMap to fetch the necessary configuration. See the [restic restore action][3]
for an example of this -- in particular, the `getPluginConfig(...)` function.

## Feature Flags

Velero will pass any known features flags as a comma-separated list of strings to the `--features` argument.

Once parsed into a `[]string`, the features can then be registered using the `NewFeatureFlagSet` function and queried with `features.Enabled(<featureName>)`.

## Environment Variables

Velero adds the `LD_LIBRARY_PATH` into the list of environment variables to provide the convenience for plugins that requires C libraries/extensions in the runtime.

[1]: https://github.com/velero-io/velero-plugin-example
[2]: https://github.com/velero-io/velero/blob/v1.4.0/pkg/plugin/logger.go
[3]: https://github.com/velero-io/velero/blob/v1.4.0/pkg/restore/restic_restore_action.go
