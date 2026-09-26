# Enhance Velero plugin with context object to implement timeout

Adding context object to the functions of the Velero plugin to allow plugin implementation being aware of the timeout and taking action such as cleanup before the operation being cancelled.

## Goals

- Enhance Velero plugin interface with context object to implement timeout in the plugin code.
- Ensure backward compatible to previous version of the plugin to avoid forcing all plugin vendors upgrade their code in lockstep.
- Enhance all Velero plugin interfaces: BackupActionItem, DeleteActionItem, ObjectStore, RestoreItemAction, VolumeSnapshotter.

## Non Goals

- Higher level implementation of timeout

## Background

Currently, the all Velero plugin functions are executed without timeout.  If the function takes too long to execute or hang during the operation, the higher level functions would be blocked and affect the users.  For example, in Application Consistent backup operation, the pod would be quiesced before persistent volumes being snapshotted, then it would be unquiesced.  Between these quiesce and unquiesce operations, user operations are completely blocked.  If snapshot operation being executed in a plugin and the plugin code hang or take longer than expected, the user operations would fail.  To avoid this, the plugin functions need to be executed with a timeout and these function may also want to handle these timeout event to clean up accordingly.  The existing code in the plugin framework does pass golang context between gRPC client and gRPC server but the gRPC server functions completely ignore this context object and not passing it to the plugin interface.  This enhancement will serve as primitive level to allow the context object being passed to plugin function.  Another enhancement will be needed to add higher level implementation of timeout to Velero backup and restore datapath to facilitate timeout and other usage of context object.

## High-Level Design

Adding context object to the functions of the Velero plugin.  This context object can be used to set timeout for the operation by the caller.  To ensure backward compatibility and avoid forcing all plugin vendor upgrade their code in lock-step, a new interface would be created to wrap around the existing interface and new functions would be created with additional parameter ctx context.Context as the first parameter.  The plugin vendor can decide to implement new function (with context) or keep using existing one.

## Detailed Design

### Sample enhancement
Below is the sample for BackupItemAction interface.  Similar enhancement will be done for other plugin interfaces.

```go
// BackupItemAction is an actor that performs an operation on an individual item being backed up.
type BackupItemAction interface {
	// AppliesTo returns information about which resources this action should be invoked for.
	// A BackupItemAction's Execute function will only be invoked on items that match the returned
	// selector. A zero-valued ResourceSelector matches all resources.
	AppliesTo() (ResourceSelector, error)

	// Execute allows the ItemAction to perform arbitrary logic with the item being backed up,
	// including mutating the item itself prior to backup. The item (unmodified or modified)
	// should be returned, along with an optional slice of ResourceIdentifiers specifying
	// additional related items that should be backed up.
	Execute(item runtime.Unstructured, backup *api.Backup) (runtime.Unstructured, []ResourceIdentifier, error)
}

type BackupItemActionV2 interface {
	BackupItemAction

	ExecuteWithContext(ctx context.Context, item runtime.Unstructured, backup *api.Backup) (runtime.Unstructured, []ResourceIdentifier, error)
}

```
The gRPC server side function will be enhanced to switch between new interface function with context object (if exists) or old function.

```go
func (s *BackupItemActionGRPCServer) Execute(ctx context.Context, req *proto.ExecuteRequest) (response *proto.ExecuteResponse, err error) {
	...
	implv2, ok := impl.(BackupItemActionV2)
	if ok {
		updatedItem, additionalItems, err = implv2.ExecuteWithContext(ctx, &item, &backup)
	} else {
		updatedItem, additionalItems, err = impl.Execute(&item, &backup)
	}
	...
}
```

### List of all interface functions to added
- BackupItemAction.ExecuteWithContext
- DeleteItemAction.ExecuteWithContext
- ObjectStore.PutObjectWithContext
- ObjectStore.ObjectExistsWithContext
- ObjectStore.GetObjectWithContext
- ObjectStore.ListCommonPrefixesWithContext
- ObjectStore.ListObjectsWithContext
- ObjectStore.DeleteObjectWithContext
- RestoreItemAction.ExecuteWithContext
- VolumeSnapshotter.CreateVolumeFromSnapshotWithContext
- VolumeSnapshotter.GetVolumeInfoWithContext
- VolumeSnapshotter.CreateSnapshotWithContext
- VolumeSnapshotter.DeleteSnapshotWithContext

## Compatibility

Backward compatible with previous version of Velero plugins.

