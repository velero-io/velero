# Global Backup Volume Policies for Velero

## Background

Velero supports [resource policies](./Implemented/handle-backup-of-volumes-by-resources-filters.md) (commonly referred to as "volume policies") that let a user control how volumes are handled during a backup — for example, whether a volume is skipped, backed up via file-system backup (`fs-backup`), snapshotted, or handled by a custom plugin.

Today these policies are defined per-backup:

1. A user creates a ConfigMap in the Velero install namespace whose single data key holds a `ResourcePolicies` YAML document (`volumePolicies` and the related include/exclude and fine-grained filter policies).
2. The user opts a specific backup into that ConfigMap with the CLI flag `--resource-policies-configmap`, which sets `Backup.Spec.ResourcePolicy` as a reference to the ConfigMap.
3. When the backup is processed, velero loads the referenced ConfigMap, unmarshals the YAML, builds a `Policies` object, and applies it when performing the backup.

The limitation today is that volume policies are strictly opt-in **per backup**. An administrator, who usually has the best knowledge of the environment, may want a baseline behavior to apply to *every* backup in the cluster (for example, "always skip volumes from the `gp2` storage class", or "always use `fs-backup` for NFS volumes"). However, today they must remember to attach the same ConfigMap to every backup and every schedule. There is no way to express a cluster-wide default volume policy that is enforced regardless of what an individual backup requests.

## Goals

- Introduce "global backup volume policies" that an administrator configures once when the Velero server starts.
- Expose it as a Velero server CLI parameter that points to a ConfigMap in the Velero install namespace.
- When a backup runs, merge the global backup volume policies with the backup's own resource policies ConfigMap (if any) and use the merged result as the effective resource policies for that backup.
- Keep the existing per-backup `--resource-policies-configmap` behavior fully backward compatible when no global policy is configured.

## Non Goals

- Changing the schema of the `ResourcePolicies`/`volumePolicies` YAML itself.
- Defining global defaults for anything other than resource policies (e.g. it does not introduce new global backup spec defaults).
- Supporting per-namespace or per-schedule global policy overrides. The "global policies" is a single, server-wide configuration.
- Hot-reloading the global policies ConfigMap without a server restart is out of scope for the initial implementation.
- Support setting other filters in "resource policies" (e.g. include/exclude or fine-grained filters) in the global policy is out of scope for the initial implementation. Only `volumePolicies` will be supported in the global policy for now.

## Design

A new Velero server flag, `--global-backup-volume-policies-configmap`, accepts the name of a ConfigMap that lives in the Velero install namespace. The ConfigMap has the exact same format as an existing per-backup resource policies ConfigMap (a single data key holding a `ResourcePolicies` YAML document).

The flag value is plumbed from the server `Config` into the `backupReconciler`. During `prepareBackupRequest`, in addition to loading the backup's own resource policy (referenced by `Backup.Spec.ResourcePolicy`), Velero loads the global policy ConfigMap. The two `ResourcePolicies` documents are then **merged** into a single effective `ResourcePolicies`, which is compiled into a `Policies` object, validated, and stored on `request.ResPolicies` exactly as today. The rest of the backup pipeline is unchanged because it only consumes `request.ResPolicies`.

```
                     server flag --global-backup-volume-policies-configmap
                                     |
                                     v
   Backup.Spec.ResourcePolicy   global policies ConfigMap (install ns)
            |                            |
            v                            v
      backup-level ResourcePolicies   global ResourcePolicies
                     \                 /
                      \               /
                       v             v
                     merge() -> effective ResourcePolicies
                                     |
                                     v
                          Policies (compiled + validated)
                                     |
                                     v
                          request.ResPolicies (unchanged consumers)
```

### Volume Policy only

The resource policies ConfigMap schema includes both volume policies and include/exclude/fine-grained filter policies. The global backup volume policy only applies to the `volumePolicies` section of the schema. If the global ConfigMap includes any include/exclude/fine-grained filter policies, they are ignored and not merged into the effective policy.  In this case, a warning message will be printed in the Velero server logs. 
This is a design choice because only the volume policies are more tied to the environment where velero runs, and are more likely to be something an administrator would want to enforce globally. The include/exclude/fine-grained filter policies are more tied to the specific backup use case, and it would be less intuitive for an administrator to have those apply globally across all backups.

### Validation

Velero will validate the global backup volume policies ConfigMap at server startup. If the ConfigMap is missing or invalid, the server will fail to start and log an error.  This ensures any mistakes in configuration will be caught early.
It should also make sure the validation happens for each backup, because the ConfigMap could be updated or removed after the server starts. If the global policies ConfigMap is missing or invalid at backup time, the backup CR will be put into "FailedValidation" phase, with an appropriate error message in the logs.

### Merge semantics

The merge combines two `ResourcePolicies` documents: the global policy (`G`) and the backup-level policy (`B`). The guiding principle is that the global policy provides a baseline, and the backup-level policy is layered with it.

- **`volumePolicies`**: `volumePolicies` is an ordered list where the *first* matching policy wins (per the existing `Policies.match` logic). The merged list is the concatenation of the backup-level policies followed by the global policies:

  ```
  merged.volumePolicies = B.volumePolicies ++ G.volumePolicies
  ```

  This gives a backup the ability to override the global baseline for a specific volume (because its policy is evaluated first), while still inheriting all global rules that the backup does not override.

When only the global policy is configured (the backup does not reference a resource policy), the effective policy is the global policy alone. When only the backup policy exists (no global policy configured), behavior is identical to today.

#### Example

Global policy ConfigMap (set on the server with `--global-backup-volume-policies-configmap=global-volume-policy`):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: global-volume-policy
  namespace: velero
data:
  policies.yaml: |
    version: v1
    volumePolicies:
      - conditions:
          storageClass:
            - gp2
        action:
          type: skip
```

Backup-level policy ConfigMap (referenced with `velero backup create --resource-policies-configmap backup01`):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backup01
  namespace: velero
data:
  policies.yaml: |
    version: v1
    volumePolicies:
      - conditions:
          nfs: {}
        action:
          type: fs-backup
```

Effective (merged) volume policies used for the backup — backup rules first, then global:

```yaml
version: v1
volumePolicies:
  - conditions:
      nfs: {}
    action:
      type: fs-backup
  - conditions:
      storageClass:
        - gp2
    action:
      type: skip
```

### Output of `velero backup describe`

Currently, the `velero backup describe` command shows the backup-level resource policy.  We should update the CLI to make sure the global volume policies are also shown in the output, so that user will not need to check the parameter of velero server.

## Implementation

- **Server flag and config.** Add a new field (e.g. `GlobalBackupVolumePoliciesConfigMap`) to the server `Config` struct in `pkg/cmd/server/config/config.go`, register the `--global-backup-volume-policies-configmap` flag in `Config.BindFlags`, and leave its default empty in `GetDefaultConfig` so the feature stays opt-in.
- **Plumb the value into the reconciler.** In `pkg/cmd/server/server.go`, pass the configured ConfigMap name (along with the Velero install namespace) into `controller.NewBackupReconciler`. Add a corresponding parameter and store it as a field on the `backupReconciler` struct in `pkg/controller/backup_controller.go`.
- **Load and merge the policies.** In `internal/resourcepolicies/resource_policies.go`, add a new function (e.g. `GetResourcePoliciesFromBackupWithGlobal`) that, in addition to loading the backup-referenced ConfigMap as `GetResourcePoliciesFromBackup` does today, also loads the global ConfigMap from the install namespace via the existing `getResourcePoliciesFromConfig` helper. After that the function merges the two `ResourcePolicies` documents according to the semantics described above.
- **Call site.** Update `prepareBackupRequest` in `pkg/controller/backup_controller.go` (currently calling `GetResourcePoliciesFromBackup`) to apply the merged policies from the new function. The rest of the backup pipeline remains unchanged.
- **CLI describe output.** Update `DescribeResourcePolicies` in `pkg/cmd/util/output/backup_describer.go` and `DescribeResourcePoliciesInSF` in `pkg/cmd/util/output/backup_structured_describer.go` to also surface the global volume policy ConfigMap that contributed to the backup.

## Security Considerations

The Global Backup Volume Policy is read from a ConfigMap in the Velero install namespace, the same trust boundary as existing resource policy ConfigMaps and Velero's own configuration. Setting it requires the ability to pass server flags / edit the Velero deployment, which is already an administrative privilege. No new data is exposed and no new external access patterns are introduced.

## Compatibility

- The feature is fully opt-in. If `--global-backup-volume-policies-configmap` is not set (the default), behavior is byte-for-byte identical to today.
- Existing per-backup `--resource-policies-configmap` usage is unchanged; it is simply merged with the global baseline when one is configured.
- Backups created before this feature, and backups that reference no resource policy, transparently start honoring the global policy once it is configured. This is the intended behavior of a "global" policy, but operators should be aware that introducing a global policy changes the effective behavior of backups that previously had no resource policy.
- The behavior of scheduled backup may change when a global backup volume policy is introduced, because the scheduled backup will start honoring the global volume policies. This is an expected change, but administrators should be aware of this when introducing a global policy to an existing velero instance with scheduled backups.
- The merged policy is computed at backup time and is reflected wherever `request.ResPolicies` is consumed. `velero backup describe` should be updated to indicate when a global policy contributed to a backup.

## Alternatives Considered

- **Global policies applied only when a backup has no policy of its own.** Simpler, but it makes the global policy a fallback default rather than an enforced baseline, and it cannot express "always do X in addition to whatever the backup wants". Merging is more expressive.
- **Global precedence over backup-level policies** (global volume policies evaluated first). Rejected as the default because it would prevent backups from overriding the baseline for specific volumes.
