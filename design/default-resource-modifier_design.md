# Server Default Restore Resource Modifier

- [Server Default Restore Resource Modifier](#server-default-restore-resource-modifier)
    - [Abstract](#abstract)
    - [Background](#background)
    - [Goals](#goals)
    - [Non Goals](#non-goals)
    - [High-Level Design](#high-level-design)
    - [Detailed Design](#detailed-design)
        - [Server Configuration](#server-configuration)
        - [Restore API Change](#restore-api-change)
        - [Controller Logic](#controller-logic)
        - [Restore CLI](#restore-cli)
        - [Restore Describe Output](#restore-describe-output)
        - [Install Path](#install-path)
        - [Curated Default ConfigMap Example](#curated-default-configmap-example)
    - [Alternatives Considered](#alternatives-considered)
    - [Security Considerations](#security-considerations)
    - [Compatibility](#compatibility)
    - [Implementation](#implementation)
    - [Open Issues](#open-issues)

## Abstract

This proposal introduces a server-level default restore resource modifier for Velero.
A new `--default-resource-modifier-configmap` flag on the Velero server references a ConfigMap containing resource modifier rules that apply automatically to every restore, eliminating the need for per-restore configuration for common transformations like stripping stale CNI annotations.

## Background

When pods are backed up, CNI-managed annotations may be present that carry pod-specific networking state such as IP addresses, MAC addresses, and routes.
Restoring these stale values can cause networking failures because the CNI expects to inject fresh values and the restored annotations may conflict with the new cluster's network state.

The following annotations are commonly affected:

| Annotation | CNI |
|---|---|
| `k8s.ovn.org/pod-networks` | OVN-Kubernetes |
| `k8s.v1.cni.cncf.io/network-status` | Multus |
| `k8s.v1.cni.cncf.io/networks-status` | Multus |

Today, users can strip these annotations using [Resource Modifiers](https://velero.io/docs/main/restore-resource-modifiers/), but this requires authoring a ConfigMap and referencing it on every restore via `--resource-modifier-configmap`.
This is not discoverable for users unfamiliar with the feature and adds friction for a problem that affects most OpenShift and multi-CNI deployments.

Velero already strips certain annotations during restore as built-in behavior (e.g., `volume.kubernetes.io/selected-node` from PVCs).
This proposal extends that concept by allowing administrators to configure a default set of resource modifier rules at the server level.

## Goals

- Allow Velero administrators to configure a default resource modifier ConfigMap that applies to all restores without per-restore configuration.
- Provide a mechanism for individual restores to opt out of the default modifier.
- Ship a documented example ConfigMap that strips well-known CNI annotations.

## Non Goals

- Auto-creating a default ConfigMap during `velero install`. The mechanism is opt-in; administrators create and configure the ConfigMap.
- Merging default and per-restore resource modifier rules. When a per-restore modifier is specified, it takes exclusive precedence over the default.
- Supporting non-ConfigMap sources for default modifiers (e.g., CRDs, inline rules).
- Stripping CNI annotations via a built-in RestoreItemAction plugin. The resource modifier mechanism is the right abstraction for this.

## High-Level Design

A new `--default-resource-modifier-configmap` server flag references a ConfigMap name in the Velero namespace.
During restore, if no per-restore resource modifier is specified, the server loads and applies the default ConfigMap's rules.
When a per-restore modifier is specified via `--resource-modifier-configmap`, it takes exclusive precedence and the default is not applied.
A new `--skip-default-resource-modifier` flag on `velero restore create` allows opting out of the default per-restore.

This follows the existing pattern used by `--backup-repository-configmap` and `--repo-maintenance-job-configmap`.

## Detailed Design

### Server Configuration

Add a new field to the server `Config` struct and bind it as a CLI flag.

In `pkg/cmd/server/config/config.go`:

```go
type Config struct {
    // ... existing fields ...
    DefaultResourceModifierConfigMap string
}
```

```go
func (c *Config) BindFlags(flags *pflag.FlagSet) {
    // ... existing flags ...
    flags.StringVar(
        &c.DefaultResourceModifierConfigMap,
        "default-resource-modifier-configmap",
        c.DefaultResourceModifierConfigMap,
        "The name of a ConfigMap in the Velero namespace containing default resource modifier rules applied to all restores. "+
            "Ignored when a per-restore resource modifier is specified.",
    )
}
```

The default value is an empty string, meaning no default modifier is configured.
No change to `GetDefaultConfig()` is needed.

### Restore API Change

Add a new field to `RestoreSpec` for opting out of the default modifier.

In `pkg/apis/velero/v1/restore_types.go`:

```go
type RestoreSpec struct {
    // ... existing fields ...

    // SkipDefaultResourceModifier controls whether the server-configured default
    // resource modifier is applied to this restore.
    // When true, the default modifier is skipped even if configured on the server.
    // Has no effect when a per-restore ResourceModifier is specified.
    // +optional
    // +nullable
    SkipDefaultResourceModifier *bool `json:"skipDefaultResourceModifier,omitempty"`
}
```

This follows the existing RestoreSpec convention where optional booleans use `*bool` with `+nullable` (e.g., `RestorePVs`, `PreserveNodePorts`, `IncludeClusterResources`).
This preserves the ability to distinguish "unset" from "explicit false" if needed in the future.


### Controller Logic

Thread the new config value through to the restore controller and implement the precedence logic.

In `pkg/controller/restore_controller.go`, add a field to `restoreReconciler`:

```go
type restoreReconciler struct {
    // ... existing fields ...
    defaultResourceModifierConfigMap string
}
```

Update `NewRestoreReconciler` to accept and store the new parameter.

In `pkg/cmd/server/server.go`, pass `s.config.DefaultResourceModifierConfigMap` to `NewRestoreReconciler`.

Refactor `validateAndComplete` to use a shared helper for ConfigMap loading and implement the precedence logic:

```go
func (r *restoreReconciler) validateAndComplete(restore *api.Restore) (backupInfo, *resourcemodifiers.ResourceModifiers) {
    // ... existing validation logic (unchanged) ...

    // Resource modifier resolution: per-restore takes exclusive precedence over default.
    var resourceModifiers *resourcemodifiers.ResourceModifiers

    if restore.Spec.ResourceModifier != nil &&
        strings.EqualFold(restore.Spec.ResourceModifier.Kind, resourcemodifiers.ConfigmapRefType) {
        // Per-restore modifier specified: use it exclusively, ignore default.
        resourceModifiers = r.loadResourceModifierConfigMap(
            restore, restore.Spec.ResourceModifier.Name, false,
        )
    } else if r.defaultResourceModifierConfigMap != "" && !boolptr.IsSetToTrue(restore.Spec.SkipDefaultResourceModifier) {
        // No per-restore modifier: apply server default if configured and not skipped.
        resourceModifiers = r.loadResourceModifierConfigMap(
            restore, r.defaultResourceModifierConfigMap, true,
        )
    }

    return info, resourceModifiers
}
```

Extract the ConfigMap loading into a helper to avoid code duplication:

```go
// loadResourceModifierConfigMap loads and validates a resource modifier ConfigMap.
// When isDefault is true, errors are non-fatal (logged as warnings, returns nil).
// When isDefault is false, errors are added to restore.Status.ValidationErrors.
func (r *restoreReconciler) loadResourceModifierConfigMap(
    restore *api.Restore, cmName string, isDefault bool,
) *resourcemodifiers.ResourceModifiers {
    cm := &corev1api.ConfigMap{}
    if err := r.kbClient.Get(
        context.Background(),
        client.ObjectKey{Namespace: restore.Namespace, Name: cmName},
        cm,
    ); err != nil {
        if isDefault {
            r.logger.WithError(err).Warnf(
                "Failed to retrieve default resource modifier configmap %s/%s, skipping",
                restore.Namespace, cmName,
            )
            return nil
        }
        restore.Status.ValidationErrors = append(restore.Status.ValidationErrors,
            fmt.Sprintf("failed to get resource modifiers configmap %s/%s", restore.Namespace, cmName))
        return nil
    }

    modifiers, err := resourcemodifiers.GetResourceModifiersFromConfig(cm)
    if err != nil {
        if isDefault {
            r.logger.WithError(err).Warnf(
                "Error parsing default resource modifier configmap %s/%s, skipping",
                restore.Namespace, cmName,
            )
            return nil
        }
        restore.Status.ValidationErrors = append(restore.Status.ValidationErrors,
            errors.Wrapf(err, "Error in parsing resource modifiers provided in configmap %s/%s",
                restore.Namespace, cmName).Error())
        return nil
    }

    if err = modifiers.Validate(); err != nil {
        if isDefault {
            r.logger.WithError(err).Warnf(
                "Validation error in default resource modifier configmap %s/%s, skipping",
                restore.Namespace, cmName,
            )
            return nil
        }
        restore.Status.ValidationErrors = append(restore.Status.ValidationErrors,
            errors.Wrapf(err, "Validation error in resource modifiers provided in configmap %s/%s",
                restore.Namespace, cmName).Error())
        return nil
    }

    source := "per-restore"
    if isDefault {
        source = "default"
    }
    r.logger.Infof("Retrieved %s resource modifiers from configmap %s/%s", source, restore.Namespace, cmName)
    return modifiers
}
```

Key design decisions in this logic:

1. **Exclusive precedence**: When a per-restore modifier is specified, the default is not applied at all.
This is the simplest mental model and avoids complex merge semantics.
Users who want both default and custom rules can copy the default rules into their per-restore ConfigMap.

2. **Non-fatal default errors**: If the default ConfigMap is missing or invalid, log a warning and proceed without it.
A misconfigured default should not break all restores cluster-wide.
Per-restore modifier errors remain fatal (validation errors), preserving current behavior.

3. **SkipDefaultResourceModifier**: Allows opting out per-restore without specifying a per-restore modifier.
Has no effect when a per-restore modifier is specified (it already takes precedence).

### Restore CLI

Add a `--skip-default-resource-modifier` flag to `velero restore create`.

In `pkg/cmd/cli/restore/create.go`:

```go
type CreateOptions struct {
    // ... existing fields ...
    SkipDefaultResourceModifier bool
}
```

```go
func (o *CreateOptions) BindFlags(flags *pflag.FlagSet) {
    // ... existing flags ...
    flags.BoolVar(&o.SkipDefaultResourceModifier, "skip-default-resource-modifier", false,
        "Skip applying the server-configured default resource modifier for this restore")
}
```

Set the field on the RestoreSpec when building the Restore object.
Only set it when the flag is true (using `boolptr.True()`) to leave it nil otherwise, consistent with how other `*bool` fields are handled:

```go
if o.SkipDefaultResourceModifier {
    restore.Spec.SkipDefaultResourceModifier = boolptr.True()
}
```

### Restore Describe Output

Update the restore describer in `pkg/cmd/util/output/restore_describer.go` to show which resource modifier was applied and its source.
The describe output should reflect the resolved state:

- When the default resource modifier was applied, display its ConfigMap name and source:
  ```
  Default Resource Modifier:  default-restore-resource-modifiers
  ```
- When the default was skipped because `SkipDefaultResourceModifier` is true:
  ```
  Default Resource Modifier:  skipped (SkipDefaultResourceModifier=true)
  ```
- When the default was skipped because a per-restore modifier was specified, no extra output is needed since the per-restore modifier is already displayed under the existing `Resource Modifier` field.
- When the default was ignored due to a validation or retrieval error, the warning is already logged to the restore log. The describe output should not surface transient errors.

### Install Path

Add the flag to the install CLI and deployment builder so administrators can configure it during installation.

In `pkg/install/deployment.go`, add a `defaultResourceModifierConfigMap` field to `podTemplateConfig` with an option function:

```go
func WithDefaultResourceModifierConfigMap(name string) podTemplateOption {
    return func(c *podTemplateConfig) {
        c.defaultResourceModifierConfigMap = name
    }
}
```

In the `Deployment()` function, append the CLI arg:

```go
if len(c.defaultResourceModifierConfigMap) > 0 {
    args = append(args, fmt.Sprintf("--default-resource-modifier-configmap=%s",
        c.defaultResourceModifierConfigMap))
}
```

Wire it through `VeleroOptions` in `pkg/install/resources.go` and the install CLI in `pkg/cmd/cli/install/install.go`.

Add a builder method to `pkg/builder/restore_builder.go`:

```go
func (b *RestoreBuilder) SkipDefaultResourceModifier(val bool) *RestoreBuilder {
    b.object.Spec.SkipDefaultResourceModifier = &val
    return b
}
```

### Curated Default ConfigMap Example

Provide a ready-to-use ConfigMap in `examples/default-resource-modifier-cni.yaml` that strips well-known CNI annotations:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: default-restore-resource-modifiers
  namespace: velero
data:
  resource-modifiers.yaml: |
    version: v1
    resourceModifierRules:
    - conditions:
        groupResource: pods
      mergePatches:
      - patchData: |
          metadata:
            annotations:
              k8s.ovn.org/pod-networks: null
              k8s.v1.cni.cncf.io/network-status: null
              k8s.v1.cni.cncf.io/networks-status: null
```

This uses JSON Merge Patch to remove annotations by setting them to `null`.
Administrators can extend this ConfigMap with additional CNI-specific annotations (Calico, Cilium, etc.) or other stale metadata as needed.

Usage:
```bash
# Create the ConfigMap
kubectl apply -f examples/default-resource-modifier-cni.yaml

# Configure the Velero server to use it
# Option 1: During install
velero install --default-resource-modifier-configmap=default-restore-resource-modifiers ...

# Option 2: Edit existing deployment
kubectl -n velero edit deploy velero
# Add: --default-resource-modifier-configmap=default-restore-resource-modifiers
```

## Alternatives Considered

**Merge default and per-restore rules**: Instead of exclusive precedence, concatenate default and per-restore rules so both apply.
This avoids users having to copy default rules when specifying per-restore modifiers.
However, it introduces complexity around rule ordering and makes it harder to reason about what transformations will be applied.
It also makes it impossible to fully override the default for a specific restore without the `SkipDefaultResourceModifier` flag.
Exclusive precedence was chosen for simplicity.
Merge semantics can be revisited in a future enhancement if user demand warrants it.

**Built-in RestoreItemAction plugin**: Implement CNI annotation stripping as a built-in RIA plugin rather than using the resource modifier mechanism.
This would hard-code the logic and make it less configurable.
The resource modifier mechanism already supports this use case and is more flexible.

**Validate default ConfigMap at server startup**: Validate the ConfigMap when the server starts rather than at restore time.
Rejected because the ConfigMap may be created after the server starts and should not require a server restart to take effect.

**Auto-create default ConfigMap during install**: Have `velero install` automatically create the CNI-stripping ConfigMap.
Rejected for the initial release to minimize the change surface and let administrators opt in.
Can be added later as a default behavior or install flag.

## Security Considerations

No new security surface.
The default ConfigMap resides in the Velero namespace and is subject to the same RBAC controls as existing resource modifier ConfigMaps.
Only users with access to create/edit ConfigMaps in the Velero namespace can modify the default modifier rules.

## Compatibility

Fully backward compatible.
When `--default-resource-modifier-configmap` is not set (the default), behavior is identical to current Velero.
No changes to existing per-restore resource modifier behavior.
The new `SkipDefaultResourceModifier` field in RestoreSpec defaults to `false` and has no effect when no default modifier is configured.

## Implementation

1. Add `DefaultResourceModifierConfigMap` to `Config` struct and bind the CLI flag.
2. Add `SkipDefaultResourceModifier` to `RestoreSpec` and regenerate deepcopy/CRD.
3. Thread the config to `restoreReconciler` via `NewRestoreReconciler`.
4. Refactor `validateAndComplete` with `loadResourceModifierConfigMap` helper.
5. Add `--skip-default-resource-modifier` to the restore CLI.
6. Wire through the install path (deployment builder, install CLI).
7. Add unit tests for all precedence and error scenarios.
8. Create the example ConfigMap.
9. Update user documentation.
10. Add E2E test for default resource modifier.


## Open Issues

- Should additional CNI annotations (Calico, Cilium) be included in the curated example ConfigMap?
Feedback from the community on which annotations are commonly problematic would be helpful.
