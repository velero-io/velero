# Per-restore resource priorities

## Abstract

This proposal adds an optional `spec.resourcePriorities` field to the Restore CRD.
It changes the restore order of the resource types it names for that one restore, and it is combined with the server's `--restore-resource-priorities` instead of replacing it.
Users list only the types they want to move, every other server type keeps its server position, and no server type can be dropped.
It addresses the first part of [#4045](https://github.com/velero-io/velero/issues/4045).

## Background

Velero restores resource types in one server-wide order, set by `velero server --restore-resource-priorities` (defaults in `pkg/cmd/server/config/config.go`, `defaultRestorePriorities`).
The list has a high part and a low part, separated by `-`.
`getOrderedResources` in `pkg/restore/restore.go` returns the high list, then every other type in the backup sorted alphabetically, then the low list.
`getOrderedResourceCollection` resolves each entry through discovery and skips a type that was already processed, so the first occurrence of a type wins.
CRDs are always restored first in a separate pass, and discovery is refreshed after it.
Ordering is by type: Velero restores all items of one type before it moves to the next type (apart from additional items returned by plugins).

A Restore cannot change this order today.
[#4045](https://github.com/velero-io/velero/issues/4045) asks for that.
Its motivating case is Antrea: its controller Pod is restored before its Tier custom resources, so the running controller creates its default Tiers first and its admission webhook rejects the restored Tiers as overlapping.
A simpler form of the same failure is a `ValidatingWebhookConfiguration` with `failurePolicy: Fail` for a custom resource type `widgets.demo.example.com`: `validatingwebhookconfigurations.admissionregistration.k8s.io` sorts before `widgets.demo.example.com`, so the webhook exists before any Widget and every Widget create is rejected.
The issue also asks to defer only a controller's own Pods and Deployments, which needs per-object ordering (see Non Goals).

The server list is easy to break.
In [#9885](https://github.com/velero-io/velero/issues/9885) a user set the server flag to a list copied from the Helm chart comments.
Like the docs at the time, that list did not contain `datauploads.velero.io`, so DataUploads were restored alphabetically after the PVCs and data mover PVC restore failed.
The maintainers explained there that the list replaces the defaults, that the order of the default entries is delicate, and that the list is normally only edited to insert custom resources.
A per-restore field exposes the same risk to every restore author, so a plain replace list would repeat #9885 at a larger scale.
The design therefore lets a user define part of the list and combines it with the server list.

[#10665](https://github.com/velero-io/velero/pull/10665) already fixed slice aliasing in `getOrderedResources` and `types.Priorities`, so building per-restore lists from the server value is safe.

## Goals

- Let one Restore move the resource types it names, while every other type keeps the server order.
- Keep Velero's own required orders safe: never drop a server type, and reject a per-restore order that breaks the order Velero's volume and pod workflows need.
- Show which order a restore used, in the Restore status, `velero restore describe` and the restore log.

## Non Goals

- Per-object ordering, the second part of #4045 (for example, deferring only one controller's Pods while other Pods keep their place).
This design orders whole types, so moving `pods` moves every Pod in the restore.
The open design PR [#10662](https://github.com/velero-io/velero/pull/10662) (restore-side ownerReference relinking) is a different feature: it runs after objects are created and does not change the order, so the two designs are independent.
- Dependency-aware automatic ordering.
- Changes to the server flag, its syntax or its defaults.
Accepting `...` in the server flag, and a server startup warning when the server list breaks a required pair, are possible follow-ups.
- Inserting a type between two arbitrary server entries without restating the entries after it (see Open Issues).

## High-Level Design

A Restore gets an optional `spec.resourcePriorities` with a `highPriorities` and a `lowPriorities` list, the same two parts as the server flag.
The restore controller combines them with the server list: every type the spec names is placed where the spec puts it, and every server type the spec does not name stays where the server list has it.
The entry `"..."` stands for the server's list at that position.
When it is missing, it is implied at the start of the high list and at the end of the low list, so the common case of adding a few types needs no placeholder at all.
The controller validates the result against a short table of order pairs that Velero depends on, records the effective order in `status.effectiveResourcePriorities`, and passes it to the restorer.
The ordering code (`getOrderedResources`) does not change.
A new `velero restore create --resource-priorities` flag uses the server flag's syntax.

## Detailed Design

### API

In `pkg/apis/velero/v1/restore_types.go`, add a field to `RestoreSpec` after `SkipDefaultResourceModifier`:

```go
type RestoreSpec struct {
	// existing fields

	// ResourcePriorities changes the restore order for this restore only.
	// It is combined with the server's --restore-resource-priorities:
	// the types named here are placed where they are written, and every
	// other server type keeps its server position. Server types cannot be removed.
	// The entry "..." stands for the server's list at that position.
	// When nil, or when both lists are empty, the server order is used unchanged.
	// +optional
	// +nullable
	ResourcePriorities *RestoreResourcePriorities `json:"resourcePriorities,omitempty"`
}

// RestoreResourcePriorities lists resource types as they are stored in the
// backup: <plural>.<group>, for example deployments.apps, or the bare plural
// for core types, for example pods.
type RestoreResourcePriorities struct {
	// HighPriorities are restored before the types that are restored alphabetically.
	// "..." stands for the server's high list. When "..." is missing, it is
	// implied at the start of this list.
	// +optional
	// +nullable
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=317
	// +kubebuilder:validation:items:Pattern=`^(\.\.\.|[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)$`
	HighPriorities []string `json:"highPriorities,omitempty"`

	// LowPriorities are restored after the types that are restored alphabetically.
	// "..." stands for the server's low list. When "..." is missing, it is
	// implied at the end of this list.
	// +optional
	// +nullable
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=317
	// +kubebuilder:validation:items:Pattern=`^(\.\.\.|[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)$`
	LowPriorities []string `json:"lowPriorities,omitempty"`
}
```

Add a field to `RestoreStatus` after `HookStatus`:

```go
type RestoreStatus struct {
	// existing fields

	// EffectiveResourcePriorities is the order this restore used: the server's
	// --restore-resource-priorities combined with spec.resourcePriorities.
	// Types in neither list are restored alphabetically between the two lists.
	// It is set only when spec.resourcePriorities has at least one entry.
	// +optional
	// +nullable
	EffectiveResourcePriorities *EffectiveResourcePriorities `json:"effectiveResourcePriorities,omitempty"`
}

// EffectiveResourcePriorities is the resource order a restore used.
type EffectiveResourcePriorities struct {
	// +optional
	// +nullable
	HighPriorities []string `json:"highPriorities,omitempty"`
	// +optional
	// +nullable
	LowPriorities []string `json:"lowPriorities,omitempty"`
}
```

The API types are separate from `types.Priorities` (`pkg/types/priority.go`), because that type has no JSON tags and lives outside `pkg/apis`.
The status type has no schema markers on purpose.
It copies the server list verbatim, and the server flag is not validated, so a pattern on status could make the API server reject the controller's status patch.
`controller-gen` v0.16.5 (the version in `hack/build-image/Dockerfile`) supports the `items:` markers.

The Antrea case from #4045:

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: antrea-restore
  namespace: velero
spec:
  backupName: antrea-backup
  resourcePriorities:
    highPriorities:
    - tiers.crd.antrea.io
    lowPriorities:
    - pods
    - replicasets.apps
    - deployments.apps
    - daemonsets.apps
    - statefulsets.apps
    - jobs.batch
    - mutatingwebhookconfigurations.admissionregistration.k8s.io
    - validatingwebhookconfigurations.admissionregistration.k8s.io
status:
  phase: InProgress
  effectiveResourcePriorities:
    highPriorities: [customresourcedefinitions, namespaces, storageclasses, volumesnapshotclass.snapshot.storage.k8s.io, volumesnapshotcontents.snapshot.storage.k8s.io, volumesnapshots.snapshot.storage.k8s.io, datauploads.velero.io, persistentvolumes, persistentvolumeclaims, clusterroles, roles, serviceaccounts, clusterrolebindings, rolebindings, secrets, configmaps, limitranges, priorityclasses, clusterclasses.cluster.x-k8s.io, endpoints, services, tiers.crd.antrea.io]
    lowPriorities: [pods, replicasets.apps, deployments.apps, daemonsets.apps, statefulsets.apps, jobs.batch, mutatingwebhookconfigurations.admissionregistration.k8s.io, validatingwebhookconfigurations.admissionregistration.k8s.io, clusterbootstraps.run.tanzu.vmware.com, clusters.cluster.x-k8s.io, clusterresourcesets.addons.cluster.x-k8s.io, apps.kappctrl.k14s.io, packageinstalls.packaging.carvel.dev]
```

The status shown is what a server with the default list writes.
Users write the placeholder as a quoted YAML string, `- "..."`.
It is also valid unquoted inside an indented list, but `...` at column 0 is a YAML document end marker, so the docs always quote it.

### Combine algorithm

In short, for the docs: the types you list are restored in the order you list them, and `"..."` stands for the server's list.
Without `"..."`, your high types come after the server's high list and your low types come before the server's low list.
A server type you name moves to where you name it, and every server type you do not name keeps its place.

Inputs:

- `SH` and `SL`: the server's high and low lists, parsed from `--restore-resource-priorities` exactly as today.
- `UH` and `UL`: `spec.resourcePriorities.highPriorities` and `lowPriorities`, after validation.
- `P`: the placeholder `"..."`.
- `canonical(s)`: the name table in the next section; for any other name it returns `s` unchanged.

Steps:

1. If `spec.resourcePriorities` is nil, or both lists are empty, nothing is combined.
The restorer uses its server list through the same code path as today.
2. Remove `customresourcedefinitions` (in either spelling) from `UH`, because the CRD pass always restores CRDs first.
3. Let `N` be the set of `canonical(u)` for every entry `u` in `UH` and `UL` that is not `P`.
4. Let `SH'` be `SH` without the entries whose canonical name is in `N`, in server order.
Let `SL'` be `SL` without them, in server order.
5. If `UH` has no `P`, put one at its start.
If `UL` has no `P`, put one at its end.
6. The effective high list `EH` is `UH` with `P` replaced by the entries of `SH'` and every other entry replaced by its canonical name.
The effective low list `EL` is built from `UL` and `SL'` in the same way.
7. `getOrderedResources` runs unchanged on `types.Priorities{HighPriorities: EH, LowPriorities: EL}`.
The order is `EH`, then every other type in the backup alphabetically, then `EL`.

The function is pure, uses no discovery, and returns new slices.
It never writes to the server value or to the Restore object.

Properties, each covered by a unit test:

- No server type is dropped.
A server type the spec does not name keeps its list and its order relative to the other server types the spec does not name.
- The spec's entries appear in the order they are written.
- An unset or empty spec gives the server lists unchanged.
- If the spec names every server type and has no `"..."`, `EH` and `EL` are exactly what was written (after canonical names), apart from `customresourcedefinitions`, which stays at the front.
So pasting a full list still behaves as a full list, and a paste that misses a server type keeps that type at its server position instead of dropping it, which is the #9885 case.

Spec entries are emitted as canonical names so that they match the type names stored in the backup.
For example, `clusterroles` moved into the low list must remove `clusterroles.rbac.authorization.k8s.io` from the alphabetical middle, which only a literal match does.
Server entries the spec does not name are emitted as written, as today.

The placeholder `"..."` cannot be a resource or group name, because its DNS labels are empty.
It needs no quoting in a shell and no escaping in JSON.
Other tokens were rejected: `*` already means "all types" in `includedResources` and is a YAML alias indicator, `$server` is expanded by shells, and `-` is the existing separator.

### Names and matching

Two entries name the same type when their canonical names are equal.
Most entries are already canonical (`<plural>.<group>`, or the bare plural for core types).
The default server list also uses a few other spellings, which a user who writes the backup's own name would otherwise never match:

| Spelling in the default server list | Canonical name |
|---|---|
| `customresourcedefinitions` | `customresourcedefinitions.apiextensions.k8s.io` |
| `storageclasses` | `storageclasses.storage.k8s.io` |
| `volumesnapshotclass.snapshot.storage.k8s.io` | `volumesnapshotclasses.snapshot.storage.k8s.io` |
| `clusterroles`, `roles`, `clusterrolebindings`, `rolebindings` | the same name plus `.rbac.authorization.k8s.io` |
| `priorityclasses` | `priorityclasses.scheduling.k8s.io` |

A unit test asserts that every entry of `defaultRestorePriorities` is either canonical or in this table, so a later change to the defaults cannot silently break matching.
Fixing the singular `volumesnapshotclass` entry in the defaults is a separate small change, and it stays safe because of this table.

Other spellings (short names such as `deploy`, singulars such as `deployment.apps`) are not normalized, because that needs discovery and custom resource types only exist after the CRD pass.
Two safety nets cover them.
Validation rejects the aliases of the types in the required order table (check 5, table below), so the order check cannot be bypassed by a spelling.
At restore time, any spec entry whose type was already restored under another entry produces a restore warning (see Restore execution).

The rejected aliases are held in `GuardedPriorityAliases` in `pkg/types/priority.go`, a `map[string]string` from each alias to its canonical name.
For each type in the required order table it holds the short names, the singular, the plural without its group, and the singular with its group.
Short names are the ones API discovery reports, as `kubectl api-resources` shows them.
For built-in types they come from the Kubernetes v1.36 API server, for the snapshot types from the external-snapshotter CRDs (`client/config/crd`, v8.6.0, the client version in `go.mod`), and for DataUploads from Velero's own CRD.
No alias is a spelling in the name table above, and no canonical name or default list entry is an alias.

| Canonical name | Rejected aliases | Short names from |
|---|---|---|
| `pods` | `po`, `pod` | Kubernetes |
| `persistentvolumes` | `pv`, `persistentvolume` | Kubernetes |
| `persistentvolumeclaims` | `pvc`, `persistentvolumeclaim` | Kubernetes |
| `replicasets.apps` | `rs`, `replicaset`, `replicasets`, `replicaset.apps` | Kubernetes |
| `deployments.apps` | `deploy`, `deployment`, `deployments`, `deployment.apps` | Kubernetes |
| `daemonsets.apps` | `ds`, `daemonset`, `daemonsets`, `daemonset.apps` | Kubernetes |
| `statefulsets.apps` | `sts`, `statefulset`, `statefulsets`, `statefulset.apps` | Kubernetes |
| `jobs.batch` | `job`, `jobs`, `job.batch` | none; Kubernetes defines no short name for Jobs |
| `volumesnapshots.snapshot.storage.k8s.io` | `vs`, `volumesnapshot`, `volumesnapshots`, `volumesnapshot.snapshot.storage.k8s.io` | external-snapshotter CRD |
| `volumesnapshotcontents.snapshot.storage.k8s.io` | `vsc`, `vscs`, `volumesnapshotcontent`, `volumesnapshotcontents`, `volumesnapshotcontent.snapshot.storage.k8s.io` | external-snapshotter CRD |
| `datauploads.velero.io` | `du`, `dataupload`, `datauploads`, `dataupload.velero.io` | `+kubebuilder:resource:shortName=du` in `pkg/apis/velero/v2alpha1/data_upload_types.go` (`config/crd/v2alpha1/bases/velero.io_datauploads.yaml`) |

These are the 11 types of the 10 pairs in the required order table.
`volumesnapshotclasses.snapshot.storage.k8s.io` (short name `vsclass`) is not in a pair, so it is not guarded, and its default spelling stays in the name table.

### Validation

Validation runs in `restoreReconciler.validateAndComplete` (`pkg/controller/restore_controller.go`), next to the `ExistingVolumeDataPolicy` check, only when `spec.resourcePriorities` has at least one entry in either list.
A nil field and `resourcePriorities: {}` (or two empty lists) are the same: no validation, no status, no combine and no describe block.
It uses no discovery and no backup contents.
Each problem appends one message, prefixed `Invalid resourcePriorities: `, to `restore.Status.ValidationErrors`, and the restore goes to `FailedValidation` as today.
The reconciler gets the server list through a new `NewRestoreReconciler` parameter, from the same `s.config.RestoreResourcePriorities` value that the restorer already gets.

At the start, `validateAndComplete` clears `status.effectiveResourcePriorities`.
The Restore CRD has no status subresource, so a client could set status when it creates the object.

Checks:

1. Each entry is `"..."` or a lowercase DNS-style name (the CRD pattern above).
This rejects empty strings, whitespace, commas, uppercase Kinds and `group/version` forms.
Targeted hints: for `-`, `the separator of the server flag; use highPriorities and lowPriorities`; for `…` (U+2026, which some editors and phones make from three dots) and `..`, `did you mean "..."?`; for `*`, `"..." stands for the server list`.
The controller repeats the schema checks as a second check, and the CLI runs the same function, which is where the hints matter most.
2. `"..."` appears at most once in each list.
3. No type appears twice, within a list or across the two lists, compared by canonical name.
So `clusterroles` and `clusterroles.rbac.authorization.k8s.io` together are a duplicate.
4. `customresourcedefinitions` is rejected in `lowPriorities` ("CRDs are always restored first").
In `highPriorities` it is accepted and ignored, so a pasted default list still validates.
5. The aliases in `GuardedPriorityAliases` (see the alias table in Names and matching) are rejected with the canonical name, for example `use "deployments.apps" instead of "deploy"`.
6. Required order.
For each pair `(a, b)` in the table below, it is an error if the server order restores `a` before `b` and the effective order restores `b` before `a`.
Positions are compared as today's ordering does: an index in the high list, then the alphabetical middle (two middle types compare by name, as `sort.Strings` does), then an index in the low list.
A pair that the server list already breaks is skipped, so a custom server flag never fails a restore that did not cause the problem, and an unset spec can never fail.

| Must be restored first | Before | Reason (from the comments on `defaultRestorePriorities`) |
|---|---|---|
| `volumesnapshotcontents.snapshot.storage.k8s.io` | `volumesnapshots.snapshot.storage.k8s.io` | contents hold the handle to the storage snapshot |
| `volumesnapshots.snapshot.storage.k8s.io` | `persistentvolumeclaims` | PVCs use the VolumeSnapshot as their data source |
| `datauploads.velero.io` | `persistentvolumeclaims` | data mover PVC restore reads the DataUpload results ([#9885](https://github.com/velero-io/velero/issues/9885)) |
| `persistentvolumes` | `persistentvolumeclaims` | PVCs bind to the restored PVs |
| `persistentvolumeclaims` | `pods` | pods mount the PVCs |
| `pods` | `replicasets.apps`, `daemonsets.apps`, `statefulsets.apps`, `jobs.batch` | pod volume restores run before controllers adopt the pods |
| `replicasets.apps` | `deployments.apps` | ReplicaSets are adopted by Deployments |

Example message:

```
Invalid resourcePriorities: this order restores replicasets.apps before pods, but Velero needs pods first (pod volume restores run before controllers adopt the pods). List replicasets.apps after pods in the same list, or name neither.
```

The table only covers orders that Velero's own workflows need.
Other rules of the default list (for example "Endpoints go before Services") hold as long as the spec does not name those types.
Which pairs belong in the table, and which should only warn, is Open Issue 1.

On success, the controller sets `status.effectiveResourcePriorities` to `EH` and `EL`.
The existing patch that moves the restore to `InProgress` persists it.

The CLI runs checks 1 to 5 locally with the same function before it creates the Restore.
Check 6 needs the server list, so only the controller runs it.

Not validation errors:

- Entries that discovery cannot resolve, or types that are not in the backup, are logged and skipped as today.
This keeps one spec reusable across backups and lets it name custom resource types whose CRDs come from the backup.
- Types excluded by `includedResources`, `excludedResources`, namespace filters or the resource filter policy are skipped as today.
The order never includes anything, and `datauploads.velero.io` stays in `resourceMustHave`.

### Restore execution

- `pkg/restore.Request` gets `ResourcePriorities *types.Priorities`.
`runValidatedRestore` sets it, only when a spec list has an entry, from the same pure function the validation used.
- `kubernetesRestorer.RestoreWithResolvers` uses `*req.ResourcePriorities` when it is non-nil, and `kr.resourcePriorities` otherwise.
The restorer never reads the user-writable status.
- `restoreContext.execute` logs the order it uses, once, right after "Starting restore of backup":

```
level=info msg="Restore resource priorities (source=spec): <effective high list>,-,<effective low list>"
level=info msg="Restore resource priorities (source=server): <server high list>,-,<server low list>"
```

The value is built with `types.Priorities.String()`, so it is valid `--restore-resource-priorities` syntax.
Users can find it with `velero restore logs <name> | grep 'Restore resource priorities'`, which is also how they can see the server list.
- `getOrderedResourceCollection` records which list entry processed each type.
When an entry that the spec placed reaches the existing "already processed" skip, it adds a Velero restore warning, for example:

```
resourcePriorities entry "cm" was not applied: configmaps was already restored earlier (entry "configmaps"); use the name stored in the backup
```

This catches every spelling that did not match, including a server flag that spells a type differently from the spec.
It is added only for spec entries, so restores without the field get no new warnings.
- `getOrderedResources` and the CRD pass do not change.

### Worked examples

All rows use the default server list.
`SH` is its 23 high entries and `SL` its 5 low entries.
MWC and VWC are `mutatingwebhookconfigurations.admissionregistration.k8s.io` and `validatingwebhookconfigurations.admissionregistration.k8s.io`.

| # | Case | `highPriorities` | `lowPriorities` | Effective high | Effective low | Result |
|---|---|---|---|---|---|---|
| 1 | Unset | not set | not set | `SH` | `SL` | Today's code path |
| 2 | Antrea (#4045) | `tiers.crd.antrea.io` | `pods, replicasets.apps, deployments.apps, daemonsets.apps, statefulsets.apps, jobs.batch, MWC, VWC` | `SH` without `pods, replicasets.apps`, then `tiers.crd.antrea.io` | the 8 spec entries, then `SL` | Valid |
| 3 | Fail-closed webhook | not set | `VWC` | `SH` | `VWC`, then `SL` | Valid |
| 4 | Webhook after the server low types | not set | `"...", VWC` | `SH` | `SL`, then `VWC` | Valid |
| 5 | ResourceQuota first ([#8100](https://github.com/velero-io/velero/issues/8100)) | `resourcequotas, "..."` | not set | `resourcequotas`, then `SH` | `SL` | Valid |
| 6 | Insert in the middle | `"...", resourcequotas, pods, replicasets.apps, clusterclasses.cluster.x-k8s.io, endpoints, services` | not set | `SH` with `resourcequotas` just before `pods` | `SL` | Valid; the entries after the insertion point are restated |
| 7 | The #9885 paste (17 entries, no `datauploads.velero.io`) | the pasted list | not set | `customresourcedefinitions, datauploads.velero.io`, the 4 RBAC types, `priorityclasses, endpoints, services`, then the rest of the paste | `SL` without the 2 CAPI types the paste moved to high | Valid; `datauploads.velero.io` stays before PVs and PVCs |
| 8 | Move pods only | not set | `pods` | `SH` without `pods` | `pods`, then `SL` | `FailedValidation`: ReplicaSets, DaemonSets, StatefulSets and Jobs would come before pods |
| 9 | Move DataUploads last | not set | `datauploads.velero.io` | `SH` without it | `datauploads.velero.io`, then `SL` | `FailedValidation`: PVCs would come before DataUploads |
| 10 | PVCs first | `persistentvolumeclaims, "..."` | not set | `persistentvolumeclaims`, then `SH` without it | `SL` | `FailedValidation`: 3 storage pairs reversed |
| 11 | Backup name of a default type | not set | `clusterroles.rbac.authorization.k8s.io` | `SH` without `clusterroles` | `clusterroles.rbac.authorization.k8s.io`, then `SL` | Valid; matched through the name table |
| 12 | Unguarded short name in the low list | not set | `cm` | `SH` | `cm`, then `SL` | Valid, plus the "not applied" restore warning, because discovery resolves `cm` to `configmaps`, which was already restored from `SH` |

In row 7 the server types that the paste left out move to the front of the high list, so RBAC, Endpoints and Services now come before Namespaces.
The paste also moves CAPI Clusters and ClusterResourceSets to the high list, ahead of Tanzu ClusterBootstraps, which the comments on the server defaults say must come first.
Validation accepts both moves, because the required order table covers only the volume and pod orders (see Open Issues), and describe shows them in the effective order.
The same 17 entries as a server flag restore DataUploads after the PVCs, which is the #9885 failure.

Restore order for two sample backups (first time each type is restored; Namespaces are created when the first item in them is restored, so they are left out):

| Case | Backup contains | Today | With the spec |
|---|---|---|---|
| Row 2 | Antrea CRDs and CRs (Tiers, ClusterGroups, ClusterNetworkPolicies), ClusterRoles, ClusterRoleBindings, ServiceAccounts, Secrets, ConfigMaps, Services, Endpoints, EndpointSlices, Pods, ReplicaSets, Deployments, DaemonSets, ControllerRevisions, MWC, VWC | clusterroles, serviceaccounts, clusterrolebindings, secrets, configmaps, **pods, replicasets.apps**, endpoints, services, clustergroups, clusternetworkpolicies, controllerrevisions.apps, **daemonsets.apps, deployments.apps**, endpointslices, **MWC**, tiers, VWC | clusterroles, serviceaccounts, clusterrolebindings, secrets, configmaps, endpoints, services, **tiers**, clustergroups, clusternetworkpolicies, controllerrevisions.apps, endpointslices, **pods, replicasets.apps, deployments.apps, daemonsets.apps, MWC, VWC** |
| Row 3 | CRD for Widgets, 3 Widgets, a fail-closed VWC for them, a Deployment with its ReplicaSet and Pods, Secrets, ConfigMaps, Services, Endpoints, EndpointSlices | secrets, configmaps, pods, replicasets.apps, endpoints, services, deployments.apps, endpointslices, **VWC, widgets** | secrets, configmaps, pods, replicasets.apps, endpoints, services, deployments.apps, endpointslices, **widgets, VWC** |

Row 2 matches the order the issue asks for: the defaults, then the Tiers, then the other Antrea CRs, then the controller Pod, ReplicaSet and Deployment, then the webhook configurations.
Today the controller Pod and the mutating webhook come before the Tiers.

### CLI

`velero restore create` gets a `--resource-priorities` flag (`pkg/cmd/cli/restore/create.go`), next to `--skip-default-resource-modifier`.
It uses the server flag's syntax, `high1,high2,-,low1,low2`.
The flag is a plain string (`flags.StringVar`), parsed once with `types.Priorities.Set` on a zero value.

- `a,b` sets only the high list; the server's low list is kept.
- `-,x` sets only the low list; the server's high list is kept.
- `a,-,x` sets both.
- No flag, or `-` alone, leaves the field nil.
- If the flag is given twice, the second value replaces the first, as for any string flag, and only that value is parsed.

Help text:

```
Change the restore order for this restore. Same syntax as the server's
--restore-resource-priorities (high1,high2,-,low1,low2), but combined with the
server's list: types you list go where you list them, and all other server types
keep their place. "..." marks where the server's list goes; without it, your high
types go after the server's high list and your low types before the server's low
list. Use the names stored in the backup, for example deployments.apps.
```

Examples:

```shell
velero restore create antrea-restore --from-backup antrea-backup \
  --resource-priorities 'tiers.crd.antrea.io,-,pods,replicasets.apps,deployments.apps,daemonsets.apps,statefulsets.apps,jobs.batch,mutatingwebhookconfigurations.admissionregistration.k8s.io,validatingwebhookconfigurations.admissionregistration.k8s.io'

velero restore create widgets-restore --from-backup widgets-backup \
  --resource-priorities '-,validatingwebhookconfigurations.admissionregistration.k8s.io'

velero restore create --from-backup app-backup --resource-priorities 'resourcequotas,...'
```

`Validate()` runs validation checks 1 to 5 before anything is created, for example `--resource-priorities: "…" is not a resource name; did you mean "..."?`.
After `Create`, the CLI checks that the returned Restore still has `spec.resourcePriorities`.
If the field is gone, the cluster's Restore CRD is older than the CLI and pruned it, and the CLI prints: `warning: the Restore CRD on this cluster does not support resourcePriorities; the server order will be used. Upgrade the Velero CRDs.`

`pkg/builder/restore_builder.go` gets `ResourcePriorities(high, low []string)`.
Schedules have no restore template, so nothing changes for schedules.

### Describe output

`velero restore describe` prints a block after the resource policy block (`pkg/cmd/util/output/restore_describer.go`), only when at least one list in `spec.resourcePriorities` is non-empty, the same rule as validation:

```
Resource Priorities:
  Requested High:  tiers.crd.antrea.io
  Requested Low:   pods,replicasets.apps,deployments.apps,daemonsets.apps,statefulsets.apps,jobs.batch,mutatingwebhookconfigurations.admissionregistration.k8s.io,validatingwebhookconfigurations.admissionregistration.k8s.io
  Effective High:  customresourcedefinitions,namespaces,storageclasses,volumesnapshotclass.snapshot.storage.k8s.io,volumesnapshotcontents.snapshot.storage.k8s.io,volumesnapshots.snapshot.storage.k8s.io,datauploads.velero.io,persistentvolumes,persistentvolumeclaims,clusterroles,roles,serviceaccounts,clusterrolebindings,rolebindings,secrets,configmaps,limitranges,priorityclasses,clusterclasses.cluster.x-k8s.io,endpoints,services,tiers.crd.antrea.io*
  Effective Low:   pods*,replicasets.apps*,deployments.apps*,daemonsets.apps*,statefulsets.apps*,jobs.batch*,mutatingwebhookconfigurations.admissionregistration.k8s.io*,validatingwebhookconfigurations.admissionregistration.k8s.io*,clusterbootstraps.run.tanzu.vmware.com,clusters.cluster.x-k8s.io,clusterresourcesets.addons.cluster.x-k8s.io,apps.kappctrl.k14s.io,packageinstalls.packaging.carvel.dev
  (* placed by this restore. Other types in the backup are restored alphabetically between High and Low. CRDs are always restored first.)
```

- Requested comes from the spec, as written, including any `"..."`.
- Effective comes from `status.effectiveResourcePriorities`.
An entry is marked when its canonical name is named in the spec.
- If a spec list is non-empty but the status is empty after the restore left `New` and did not fail validation, describe prints `Effective:  <not recorded; the Velero server may not support spec.resourcePriorities>`.
- "Not applied" warnings appear in the existing Warnings section.
- Restores without the field, or with `resourcePriorities: {}`, print nothing new, so existing output does not change.

The structured describer (`restore_structured_describer.go`) adds `specInfo["resourcePriorities"]` with `highPriorities` and `lowPriorities`, and a top-level `effectiveResourcePriorities` with `highPriorities`, `lowPriorities` and `placedByRestore`.

### Documentation

- `site/content/docs/main/restore-reference.md`: a new "Change the order for one restore" subsection under "Restore order".
It gives the rules paragraph from the combine section, the naming rule, the required order table, the Antrea and webhook recipes, and how to see the effective order.
It warns that moving `pods` later moves every Pod in the restore and requires moving every controller type in the restore after it.
It also states that the server flag replaces the part it is given, while the per-restore field combines.
- `site/content/docs/main/api-types/restore.md`: the new spec field in the sample Restore.
- A changelog entry in `changelogs/unreleased/`.

## Alternatives Considered

**Replace the server list.**
The spec list would be used instead of the server list, as sketched in #4045 in 2024.
This is the error-prone option: it is the #9885 failure, now available to every restore author.
It also ties a stored Restore to the defaults of the Velero version it was written for: when a later version adds a default, as happened with `datauploads.velero.io`, a replace list silently leaves it out.
Combining already behaves as replace when the spec names every server type, so replace adds nothing except the ability to drop server types.

**Anchored merge.**
A run of spec entries would be placed at the position of the next server type it names, so a type can be inserted in the middle of the server list without restating the rest.
It needs two asymmetric rules (one for each list), users must know the server list to use anchors, and inside the high list a named server type can only move earlier.
For example, `[services, pods]` would pull `services` ahead of `endpoints`, which breaks a default rule without the user asking for it.

**Relative placement.**
Each entry would be a struct `{resource, position, anchor}` with positions such as `First`, `Before`, `After`, `BeforeUnlisted`, `AfterUnlisted` and `Last`.
It is the most expressive option and has the best schema (enum and map list).
It costs six positions, anchor chains, a cycle check and a set of pinned types, anchors depend on the exact spelling of the server list, and the Antrea case needs seven structs or seven repeated CLI flags.
It could be added later as a sibling field of the same struct if users need mid-list placement (Open Issue 2).

**Insert only.**
Extra types would only be appended to the server high list and prepended to the server low list.
It cannot move a default type, but the Antrea case needs `pods` and `replicasets.apps` moved later.
This design behaves exactly as insert only when the spec names no server type.

**Removal syntax.**
A way to send a server type back to the alphabetical middle was left out on purpose: it is the #9885 failure.

**A ConfigMap reference,** like `resourceModifier` and `resourcePolicy`.
It needs an extra lookup, RBAC and parsing for what is usually a short list.
It could be added later if users want to share one order across many restores.

**A single string in flag syntax** (`resourcePriorities: "a,b,-,c"`).
It is not idiomatic for a CRD and cannot be validated by the schema.
The CLI accepts this syntax instead.

**Discovery-based matching during validation.**
It would accept every spelling, but custom resource types only exist after the CRD pass, so the combine would move into the restorer after the status is written.
The name table plus the "not applied" warning cover the common cases without that.

**Per-object deferral by label**, the second part of #4045.
It needs a new restore phase model and is out of scope (see Non Goals).

## Security Considerations

The field only reorders types that the restore already restores.
It cannot include a type, a namespace or an item that the restore filters exclude, and it needs no new RBAC.
The required order check stops a restore author from breaking Velero's own volume workflows by mistake.
The status field is written by the controller and never read by the restorer, so a forged status cannot change the order.
List length is limited by the schema, and validation is linear in the list length.

## Compatibility

- The field is optional and additive.
A restore without it runs through today's code path; the only new output is one Info line in the restore log.
- The server flag, its syntax and its defaults do not change.
The per-restore field uses the same syntax with a different meaning (combine instead of replace), which the help text and docs state.
- Old CRD with a new CLI: the velero CLI creates Restores through a controller-runtime client, so an old CRD prunes the field silently.
The CLI detects this after `Create` and warns.
`kubectl`, which validates fields strictly by default, rejects the unknown field instead.
- New CRD with an old server: the server ignores the field, the restore uses the server order, and describe shows `Effective: <not recorded>`.
- The upgrade docs already say to upgrade the CRDs first.
- Downgrade: stored Restores keep the field, and an older server ignores it.
- The backup format does not change.

## Implementation

The author (abd-ulbasit) will implement this for v1.20, in one implementation PR after this design is approved.
The design doc moves to `design/Implemented/` in that PR.
The PR can be split (API, combine and controller first; CLI, describe and docs second) if reviewers prefer.

1. `pkg/apis/velero/v1/restore_types.go`: the spec field, the status field and the two types.
Regenerate `zz_generated.deepcopy.go` and `config/crd/v1/bases/velero.io_restores.yaml` with controller-gen v0.16.5 (`hack/update-3generated-crd-code.sh`).
CI does not check that the generated CRD is current, so a unit test asserts that the embedded Restore CRD has `spec.resourcePriorities`.
2. `pkg/types/priority.go`: `const PriorityPlaceholder = "..."`, `CanonicalPriorityName(s string) string` with the name table, `GuardedPriorityAliases` with the alias table, `ValidatePriorityEntries(high, low []string) []string` (checks 1 to 5) and `CombinePriorities(server Priorities, high, low []string) Priorities`.
The CLI can import `pkg/types` without an import cycle.
3. `pkg/util/velero/restore/priorities.go` (new; the controller already imports this package): the required order table, `RequiredOrderViolations(server, effective types.Priorities) []string`, and `EffectiveResourcePriorities(server types.Priorities, spec *velerov1api.RestoreResourcePriorities) (types.Priorities, bool)`.
4. `pkg/controller/restore_controller.go`: a `resourcePriorities types.Priorities` field and `NewRestoreReconciler` parameter, validation in `validateAndComplete`, and `Request.ResourcePriorities` in `runValidatedRestore`.
`pkg/cmd/server/server.go` passes `s.config.RestoreResourcePriorities`, and the other `NewRestoreReconciler` callers (mostly tests) are updated.
5. `pkg/restore/request.go` and `pkg/restore/restore.go`: `Request.ResourcePriorities`, its use in `RestoreWithResolvers`, the log line in `execute`, and the "not applied" warning in `getOrderedResourceCollection`.
6. `pkg/cmd/cli/restore/create.go` and `pkg/builder/restore_builder.go`: the flag, its validation, the spec field, the pruned-field warning and the builder setter.
7. `pkg/cmd/util/output/restore_describer.go` and `restore_structured_describer.go`: the describe block and structured keys.
8. Docs and changelog as listed above.

### Test plan

- `pkg/types/priority_test.go`: `CombinePriorities` table cases for every row of the worked examples, a randomized property test (no server type dropped or duplicated, spec order kept, unnamed server order kept, empty spec gives the server lists, a spec that names every server type without `"..."` gives exactly the spec, apart from `customresourcedefinitions`, which stays at the front), and a check that the inputs are not modified.
`ValidatePriorityEntries` cases for `""`, whitespace, `-`, `…`, `..`, `*`, uppercase, `apps/v1/deployments`, the placeholder twice, a duplicate across lists by canonical name, CRDs in the low list and every alias in `GuardedPriorityAliases`.
It also checks that no alias is a spelling in the name table or a canonical name.
- `pkg/cmd/server/config/config_test.go`: every `defaultRestorePriorities` entry is canonical or in the name table.
- `pkg/util/velero/restore/priorities_test.go`: each required pair, a server list that already breaks a pair, rows 2, 8, 9 and 10, and a check that the canonical names in `types.GuardedPriorityAliases` are exactly the types in the required order table.
- `pkg/controller/restore_controller_test.go`: `TestValidateAndCompleteWithResourcePriorities`, following `TestValidateAndCompleteWithResourceModifierSpecified`.
Cases: valid lists set the status, each invalid input fails validation with its message, an empty struct is treated as unset, an unset spec leaves the status empty, and a client-written status is cleared.
- `pkg/restore/restore_test.go`: extend `TestRestoreResourcePriorities` with an expected order per case and cases with `Request.ResourcePriorities`.
Add a "not applied" warning case (`cm` in the low list; `test.ConfigMaps` in `pkg/test/resources.go` has the short name `cm`, so the test discovery helper resolves it to `configmaps`), and a case that runs a restore with the field and then one without it on the same restorer to show nothing leaks into later restores.
`Test_getOrderedResources` does not change.
- `pkg/cmd/cli/restore/create_test.go`: `a,b`, `-,x`, `a,-,x`, an entry with `...`, an invalid entry, and no flag.
- `pkg/cmd/util/output/restore_describer_test.go` and `restore_structured_describer_test.go`: the block with the spec set, with the status missing, and no block without the field or with an empty struct.
- Optional e2e test, if maintainers want one: the fail-closed webhook scenario from row 3, which fails today and completes with the field set.

## Open Issues

1. Which pairs should fail validation and which should only warn?
This design makes every pair in the table an error.
The pod controller pairs (`daemonsets.apps`, `statefulsets.apps`, `jobs.batch`) go beyond the storage pairs, and they make the Antrea recipe longer.
A warning at restore time, only when the backup contains the type, is the alternative for them.
2. Is placing types before or after the whole server list enough for v1.20?
Mid-list insertion needs the following server entries restated (row 6).
Anchors on single entries (see Relative placement) could come now or as a later sibling field.
3. Should `status.effectiveResourcePriorities` be recorded on every restore?
That would let users see the server list in describe, at the cost of 1 to 2 KB per Restore and changed expectations in existing controller tests.
This design records it only when the spec is set, and the log line shows the server list for every restore.
Exposing the server list through `ServerStatusRequest`, so the CLI can preview the effective order, is another option.
4. Should the server flag also accept `"..."` (meaning the default list), so operators can extend the defaults without copying them?
That would remove the #9885 failure at its source, and it would be a separate change.
5. Should the required order table also cover the other rules in the comments on the server defaults?
Examples are ServiceAccounts before Secrets, Secrets and ConfigMaps before pods, and Tanzu ClusterBootstraps before CAPI Clusters (row 7).
This design keeps the table to the orders Velero's own volume and pod workflows need, so that a restore only fails for those.
