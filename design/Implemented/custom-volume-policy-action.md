# Add custom volume policy action

## Abstract

Currently, velero supports 3 different volume policy actions:
snapshot, fs-backup, and skip, which tell Velero how to handle backing
up PVC contents. Any other policy action is not allowed. This prevents
third party BackupItemAction (BIA) plugins which might want to perform
different actions on PVC via defined volume policies.

## Background

An external BIA plugin that wants to back up volumes via some custom
means (i.e. not CSI snapshots or fs-backup with kopia) is not able to
make use of the existing volume policy API. While the plugin could use
something like PVC annotations instead, this won't integrate with
existing volume policies, which is desirable in case the user wants to
specify some PVCs to use the custom plugin while leaving others using
CSI snapshots or fs-backup.

## Goals

- Add a fourth valid volume policy action "custom"
- Make use of the existing action parameters field to distinguish between multiple custom actions.

## Non Goals

- Implementing custom action logic in velero repo

## High-Level Design

A new VolumeActionType with the value "custom" will be added to
`internal/resourcepolicies`. When the action is "custom", velero will
not perform a snapshot or use fs-backup on the PVC. If there is no
registered plugin which implements the desired custom action, then it
will be equivalent to the "skip" action. Since there could be
different plugins that implement custom actions, when making the API
call (defined below) the plugin should also pass in a partial action
parameters map containing the portion of the map that identifies the
custom plugin as belonging to a particular external
implementation. For example, there might be a custom BIA that's
looking for a `custom` volume policy action with the parameter
`myCustomAction=true`. The volume policy action would be defined like
this:

```yaml
  action:
    type: custom
    parameters:
	  myCustomAction: true
```

In `internal/volumehelper/volume_policy_helper.go` a new interface
method will be added, similar to `ShouldPerformSnapshot` but it takes
a partial parameter map as an additional input, since for custom
actions to match, the action type must be `custom`, but also there may
be some parameter that needs to match (to distinguish between
different custom actions). We also want a way for the plugin to get
the parameter map for the action. This should probably just return the
map rather than the Action struct is under `internal`.

```go
type VolumeHelper interface {
	ShouldPerformSnapshot(obj runtime.Unstructured, groupResource schema.GroupResource) (bool, error)
	ShouldPerformFSBackup(volume corev1api.Volume, pod corev1api.Pod) (bool, error)
	ShouldPerformCustomAction(obj runtime.Unstructured, groupResource schema.GroupResource, map[string]any) (bool, error)
	GetActionParameters(obj runtime.Unstructured, groupResource schema.GroupResource) (map[string]any, error)
}
```

In addition, since the VolumeHelper interface is expected to be called by external plugins, the interface (but not the implementation) should be moved from `internal/volumehelper` to `pkg/util/volumehelper`.

In `pkg/plugin/utils/volumehelper/volume_policy_helper.go`, a new helper func will be added which delegates to the internal volumehelper.NewVolumeHelperImplWithNamespaces

```go
func NewVolumeHelper(
	volumePolicy *resourcepolicies.Policies,
	snapshotVolumes *bool,
	logger logrus.FieldLogger,
	client crclient.Client,
	defaultVolumesToFSBackup bool,
	backupExcludePVC bool,
	namespaces []string,
) (VolumeHelper, error) {
```


## Alternative Considered

An alternate approach was to create a new server arg to allow
user-defined parameters. That was rejected in favor of this approach,
as the explicitly-supported "custom" option integrates more easily
into a supportable plugin-callable API.
