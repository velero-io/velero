# Pre-Backup, Post-Backup, Pre-Restore, and Post-Restore Action Plugin Hooks

## Abstract

Velero should provide a way to trigger actions before and after each backup and restore.
**Important**: These proposed plugin hooks are fundamentally different from the existing plugin hooks, BackupItemAction and RestoreItemAction, which are triggered per resource item during backup and restore, respectively.
The proposed plugin hooks are to be executed only once: pre-backup (before backup starts), post-backup (after the backup is completed and uploaded to object storage, including volumes snapshots), pre-restore (before restore starts) and post-restore (after the restore is completed, including volumes are restored).

### PreBackup and PostBackup Actions

For the backup,  the sequence of events of Velero backup are the following:

```
New Backup Request
 |--> Validation of the request
       |--> Set Backup Phase "In Progress"
            | --> Start Backup
                  | --> Discover all Plugins
                        |--> Check if Backup Exists
                             |--> Backup all K8s Resource Items
                                  |--> Perform all Volumes Snapshots
                                        |--> Wait async operations
                                            |--> Final Backup Phase is determined
                                               |--> Persist Backup and Logs on Object Storage
```
We propose the pre-backup and post-backup plugin hooks to be executed in this sequence:

```
New Backup Request
 |--> Validation of the request
       |--> Set Backup Phase "In Progress"
            | --> Start Backup
                  | --> Discover all Plugins
                        |--> Check if Backup Exists
                             |--> **PreBackupActions** are executed, logging actions on existent backup log file
                                   |--> Backup all K8s Resource Items
                                        |--> Perform all Volumes Snapshots
                                            |--> Wait async operations
                                                |--> Final Backup Phase is determined
                                                    |--> Persist Backup and logs on Object Storage
                                                       |--> **PostBackupActions** are executed, logging to its own file
```
These plugin hooks will be invoked:

- PreBackupAction: plugin actions are executed after the backup object is created and validated but before the backup is being processed, more precisely _before_ function [c.backupper.BackupWithResolvers](https://github.com/vmware-tanzu/velero/blob/7deae4cbf5443fabe65eda165ac41594598ec0d5/pkg/controller/backup_controller.go#L646). If the PreBackupActions return an err, the backup object is not processed and the Backup phase will be set as `FailedPreBackupActions`.

- PostBackupAction: plugin actions are executed after the backup is finished and persisted, more precisely _at the end_ of function [backupFinalizerReconciler.Reconcile](https://github.com/vmware-tanzu/velero/blob/7deae4cbf5443fabe65eda165ac41594598ec0d5/pkg/controller/backup_finalizer_controller.go#L205).

The proposed plugin hooks will execute actions that will have statuses on their own:
`Backup.Status.PreBackupActionsStatuses` and `Backup.Status.PostBackupActionsStatuses` which will be an array of a proposed struct `ActionStatus` with PluginName, StartTimestamp, CompletionTimestamp and Phase.

### PreRestore and PostRestore Actions

For the restore,  the sequence of events of Velero restore are the following:
```
New Restore Request
 |--> Validation of the request
      |--> Checks if restore is from a backup or a schedule
           |--> Fetches backup
                |--> Set Restore Phase "In Progress"
                     |--> Start Restore
                          |--> Discover all Plugins
                               |--> Download backup file to temp
                                    |--> Fetch list of volumes snapshots
                                         |--> Restore K8s items, including PVs
                                            |--> Wait async operations
                                                |--> Final Restore Phase is determined
                                                    |--> Persist Restore logs on Object Storage
```
We propose the pre-restore and post-restore plugin hooks to be executed in this sequence:
```
New Restore Request
 |--> Validation of the request
      |--> Checks if restore is from a backup or a schedule
           |--> Fetches backup
                |--> Set Restore Phase "In Progress"
                     |--> Start Restore
                          |--> Discover all Plugins
                                |--> Download backup file to temp
                                         |--> Fetch list of volumes snapshots
                                            |--> **PreRestoreActions** are executed, logging actions on existent backup log file
                                              |--> Restore K8s items, including PVs
                                                 |--> Wait async operations
                                                    |--> Final Restore Phase is determined
                                                            |--> Persist Restore logs on Object Storage
                                                                |--> **PostRestoreActions** are executed, logging to its own file
```

These plugin hooks will be invoked:

- PreRestoreAction: plugin actions are executed after the restore object is created and validated and before the backup object is fetched, more precisely in function `runValidatedRestore` _after_ function [info.backupStore.GetBackupVolumeSnapshots](https://github.com/vmware-tanzu/velero/blob/7deae4cbf5443fabe65eda165ac41594598ec0d5/pkg/controller/restore_controller.go#L450). If the PreRestoreActions return an err, the restore object is not processed and the Restore phase will be set a `FailedPreRestoreActions`.
  
- PostRestoreAction: plugin actions are executed after the restore finishes processing all items and volumes snapshots are restored and logs persisted.
    * In case async operations are finished: in function `restoreController.Reconcile` _after_ [updating restore status](https://github.com/vmware-tanzu/velero/blob/7deae4cbf5443fabe65eda165ac41594598ec0d5/pkg/controller/restore_controller.go#L219C1-L219C1).
    * In case async operations in progress: in function `restoreOperationsController.Reconcile` _after_ [updating restore status](https://github.com/vmware-tanzu/velero/blob/7deae4cbf5443fabe65eda165ac41594598ec0d5/pkg/controller/restore_operations_controller.go#L201) and only if restore in terminal phase .

The proposed plugin hooks will execute actions that will have statuses on their own:
`Restore.Status.PreRestoreActionsStatuses` and `Restore.Status.PostRestoreActionsStatuses` which will be an array of a proposed struct `ActionStatus` with PluginName, StartTimestamp, CompletionTimestamp and Phase.

## Background

Increasingly, Velero is employed for workload migrations across different Kubernetes clusters.
Using Velero for migrations requires an atomic operation involving a Velero backup on a source cluster followed by a Velero restore on a destination cluster.

It is common during these migrations to perform many actions inside and outside Kubernetes clusters.
**Attention**: these actions are not per resource item, but they are actions to be executed _once_ before and/or after the migration itself (remember, migration in this context is Velero Backup + Velero Restore).

One important use case driving this proposal is migrating stateful workloads at scale across different clusters/storage backends.
Today, Velero's Restic integration is the response for such use cases, but there are some limitations:

- Quiesce/unquiesce workloads: Pod hooks are useful for quiescing/unquiescing workloads, but platform engineers often do not have the luxury/visibility/time/knowledge to go through each pod in order to add specific commands to quiesce/unquiesce workloads.
- Orphan PVC/PV pairs: PVCs/PVs that do not have associated running pods are not backed up and consequently, are not migrated.

Aiming to address these two limitations, and separate from this proposal, we would like to write a Velero plugin that takes advantage of the proposed Pre-Backup plugin hook. This plugin will be executed _once_ (not per resource item) prior backup. It will scale down the applications setting `.spec.replicas=0` to all deployments, statefulsets, daemonsets, replicasets, etc. and will start a small-footprint staging pod that will mount all PVC/PV pairs. Similarly, we would like to write another plugin that will utilize the proposed Post-Restore plugin hook. This plugin will unquiesce migrated applications by killing the staging pod and reinstating original `.spec.replicas` values after the Velero restore is completed.

Other examples of plugins that can use the proposed plugin hooks are:

- PostBackupAction: trigger a Velero Restore after a successful Velero backup (and complete the migration operation).
- PreRestoreAction: pre-expand the cluster's capacity via Cluster API to avoid starvation of cluster resources before the restore.
- PostRestoreAction: call actions to be performed outside Kubernetes clusters, such as configure a global load balancer (GLB) that enables the new cluster.

The post backup actions will be executed after the backup is uploaded (persisted) on the disk. The logs of post-backup actions will be uploaded on the disk once the actions are completed.

The post restore actions will be executed after the restore is uploaded (persisted) on the disk. The logs of post-restore actions will be uploaded on the disk once the actions are completed.

This design seeks to provide missing extension points. This proposal's scope is to only add the new plugin hooks, not the plugins themselves.

## Goals

- Provide PreBackupAction, PostBackupAction, PreRestoreAction, and PostRestoreAction APIs for plugins to implement.
- Update Velero backup and restore creation logic to invoke registered PreBackupAction and PreRestoreAction plugins before processing the backup and restore respectively.
- Update Velero backup and restore complete logic to invoke registered PostBackupAction and PostRestoreAction plugins the objects are uploaded on disk.
- Create one `ActionStatus` struct to keep track of execution of the plugin hooks. This struct has PluginName, StartTimestamp, CompletionTimestamp and Phase.
- Add sub statuses for the plugins on Backup object: `Backup.Status.PreBackupActionsStatuses` and `Backup.Status.PostBackupActionsStatuses`. They will be flagged as optional and nullable. They will be populated only each plugin registered for the PreBackup and PostBackup hooks, respectively.
- Add sub statuses for the plugins on Restore object: `Backup.Status.PreRestoreActionsStatuses` and `Backup.Status.PostRestoreActionsStatuses`. They will be flagged as optional and nullable. They will be populated only each plugin registered for the PreRestore and PostRestore hooks, respectively.
- that will be populated optionally if Pre/Post Backup/Restore.

## Non-Goals

- Specific implementations of the PreBackupAction, PostBackupAction, PreRestoreAction and PostRestoreAction API beyond test cases.
- For migration specific actions (Velero Backup + Velero Restore), add disk synchronization during the validation of the Restore (making sure the newly created backup will show during restore)

## High-Level Design

The Velero backup controller package will be modified for `PreBackupAction` and `PostBackupAction`.

The PreBackupAction plugin API will resemble the BackupItemAction plugin hook design, but with the fundamental difference that it will receive only as input the Velero `Backup` object created.
It will not receive any resource list items because the backup is not yet running at that stage.
In addition, the `PreBackupAction` interface will only have an `Execute()` method since the plugin will be executed once per Backup creation, not per item.

The Velero backup controller will be modified so that if there are any PreBackupAction plugins registered, they will be

The PostBackupAction plugin API will resemble the BackupItemAction plugin design, but with the fundamental difference that it will receive only as input the Velero `Backup` object without any resource list items.
By this stage, the backup has already been executed, with items backed up and volumes snapshots processed and persisted.
The `PostBackupAction` interface will only have an `Execute()` method since the plugin will be executed only once per Backup, not per item.

If there are any PostBackupAction plugins registered, they will be executed after the backup is finished and persisted, more precisely _after_ function [c.runBackup](https://github.com/vmware-tanzu/velero/blob/74476db9d791fa91bba0147eac8ec189820adb3d/pkg/controller/backup_controller.go#L274).

The Velero restore controller package will be modified for `PreRestoreAction` and `PostRestoreAction`.

The PreRestoreAction plugin API will resemble the RestoreItemAction plugin design, but with the fundamental difference that it will receive only as input the Velero `Restore` object created.
It will not receive any resource list items because the restore has not yet been running at that stage.
In addition, the `PreRestoreAction` interface will only have an `Execute()` method since the plugin will be executed only once per Restore creation, not per item.

The Velero restore controller will be modified so that if there are any PreRestoreAction plugins registered, they will be executed after the restore object is created and validated and before the backup object is fetched, more precisely in function `runValidatedRestore` _after_ function [info.backupStore.GetBackupVolumeSnapshots](https://github.com/vmware-tanzu/velero/blob/7c75cd6cf854064c9a454e53ba22cc5881d3f1f0/pkg/controller/restore_controller.go#L460). If the PreRestoreActions return an err, the restore object is not processed and the Restore phase will be set a `FailedPreRestoreActions`.

The PostRestoreAction plugin API will resemble the RestoreItemAction plugin design, but with the fundamental difference that it will receive only as input the Velero `Restore` object without any resource list items.
At this stage, the restore has already been executed.
The `PostRestoreAction` interface will only have an `Execute()` method since the plugin will be executed only once per Restore, not per item.

If any PostRestoreAction plugins are registered, they will be executed after the restore finishes processing all items and volumes snapshots are restored and logs persisted, more precisely in function `processRestore` _after_ setting [`restore.Status.CompletionTimestamp`](https://github.com/vmware-tanzu/velero/blob/7c75cd6cf854064c9a454e53ba22cc5881d3f1f0/pkg/controller/restore_controller.go#L273).

## Detailed Design

### New Status struct

To keep the status of the plugins, we propose the following struct:

```go
type ActionStatus struct {
    // PluginName is the name of the registered plugin
    // retrieved by the PluginManager as id.Name
    // +optional
    // +nullable
    PluginName string `json:"pluginName,omitempty"`

    // StartTimestamp records the time the plugin started.
    // +optional
    // +nullable
    StartTimestamp *metav1.Time `json:"startTimestamp,omitempty"`

    // CompletionTimestamp records the time the plugin was completed.
    // +optional
    // +nullable
    CompletionTimestamp *metav1.Time `json:"completionTimestamp,omitempty"`

    // Phase is the current state of the Action.
    // +optional
    // +nullable
    Phase ActionPhase `json:"phase,omitempty"`
}

// ActionPhase is a string representation of the lifecycle phase of an action being executed by a plugin
// of a Velero backup.
// +kubebuilder:validation:Enum=InProgress;Completed;Failed
type ActionPhase string

const (
    // ActionPhaseInProgress means the action has being executed
    ActionPhaseInProgress ActionPhase = "InProgress"

    // ActionPhaseCompleted means the action finished successfully
    ActionPhaseCompleted ActionPhase = "Completed"

    // ActionPhaseFailed means the action failed
    ActionPhaseFailed ActionPhase = "Failed"
)

```

### Backup Status of the Plugins

The `Backup` Status section will have the follow:

```go
type BackupStatus struct {
    (...)
    // PreBackupActionsStatuses contains information about the pre backup plugins's execution.
    // Note that this information is will be only populated if there are prebackup plugins actions
    // registered
    // +optional
    // +nullable
    PreBackupActionsStatuses *[]ActionStatus `json:"preBackupActionsStatuses,omitempty"`

    // PostBackupActionsStatuses contains information about the post backup plugins's execution.
    // Note that this information is will be only populated if there are postbackup plugins actions
    // registered
    // +optional
    // +nullable
    PostBackupActionsStatuses *[]ActionStatus `json:"postBackupActionsStatuses,omitempty"`

}
```

### Restore Status of the Plugins

The `Restore` Status section will have the follow:

```go
type RestoreStatus struct {
    (...)
    // PreRestoreActionsStatuses contains information about the pre Restore plugins's execution.
    // Note that this information is will be only populated if there are preRestore plugins actions
    // registered
    // +optional
    // +nullable
    PreRestoreActionsStatuses *[]ActionStatus `json:"preRestoreActionsStatuses,omitempty"`

    // PostRestoreActionsStatuses contains information about the post restore plugins's execution.
    // Note that this information is will be only populated if there are postrestore plugins actions
    // registered
    // +optional
    // +nullable
    PostRestoreActionsStatuses *[]ActionStatus `json:"postRestoreActionsStatuses,omitempty"`

}
```

### New Backup and Restore Phases

#### New Backup Phase: FailedPreBackupActions

In case the PreBackupActionsStatuses has at least one `ActionPhase` = `Failed`, it means al least one of the plugins returned an error and consequently, the backup will not move forward. The final status of the Backup object will be set as `FailedPreBackupActions`:

```go

// BackupPhase is a string representation of the lifecycle phase
// of a Velero backup.
// +kubebuilder:validation:Enum=New;FailedValidation;FailedPreBackupActions;InProgress;Uploading;UploadingPartialFailure;Completed;PartiallyFailed;Failed;Deleting
type BackupPhase string

const (

    (...)

    // BackupPhaseFailedPreBackupActions means one or more the Pre Backup Actions has failed
    // and therefore backup will not run.
    BackupPhaseFailedPreBackupActions BackupPhase = "FailedPreBackupActions"

    (...)
)

```

#### New Restore Phase FailedPreRestoreActions

In case the PreRestoreActionsStatuses has at least one `ActionPhase` = `Failed`, it means al least one of the plugins returned an error and consequently, the restore will not move forward. The final status of the Restore object will be set as `FailedPreRestoreActions`:

```go

// RestorePhase is a string representation of the lifecycle phase
// of a Velero restore
// +kubebuilder:validation:Enum=New;FailedValidation;FailedPreRestoreActions;InProgress;Completed;PartiallyFailed;Failed
type RestorePhase string

const (

    (...)

    // RestorePhaseFailedPreRestoreActions means one or more the Pre Restore Actions has failed
    // and therefore restore will not run.
    RestorePhaseFailedPreRestoreActions BackupPhase = "FailedPreRestoreActions"

    (...)
)

```

### New Interface types

#### PreBackupAction

The `PreBackupAction` interface is as follows:

```go
// PreBackupAction provides a hook into the backup process before it begins.
type PreBackupAction interface {
    // Execute the PreBackupAction plugin providing it access to the Backup that
    // is being executed
    Execute(backup *api.Backup) error
}
```

`PreBackupAction` will be defined in `pkg/plugin/velero/pre_backup_action.go`.

#### PostBackupAction

The `PostBackupAction` interface is as follows:

```go
// PostBackupAction provides a hook into the backup process after it completes.
type PostBackupAction interface {
    // Execute the PostBackupAction plugin providing it access to the Backup that
    // has been completed
    Execute(backup *api.Backup) error
}
```

`PostBackupAction` will be defined in `pkg/plugin/velero/post_backup_action.go`.

#### PreRestoreAction

The `PreRestoreAction` interface is as follows:

```go
// PreRestoreAction provides a hook into the restore process before it begins.
type PreRestoreAction interface {
    // Execute the PreRestoreAction plugin providing it access to the Restore that
    // is being executed
    Execute(restore *api.Restore) error
}
```

`PreRestoreAction` will be defined in `pkg/plugin/velero/pre_restore_action.go`.

#### PostRestoreAction

The `PostRestoreAction` interface is as follows:

```go
// PostRestoreAction provides a hook into the restore process after it completes.
type PostRestoreAction interface {
    // Execute the PostRestoreAction plugin providing it access to the Restore that
    // has been completed
    Execute(restore *api.Restore) error
}
```

`PostRestoreAction` will be defined in `pkg/plugin/velero/post_restore_action.go`.

### New BackupStore Interface Methods

For the persistence of the logs originated from the PostBackup and PostRestore plugins, create two additional methods on `BackupStore` interface:

```go
type BackupStore interface {
    (...)
    PutPostBackuplog(backup string, log io.Reader) error
    PutPostRestoreLog(backup, restore string, log io.Reader) error
    (...)
```

The implementation of these new two methods will go hand-in-hand with the changes of uploading phases rebase.


### Generate Protobuf Definitions and Client/Servers

In `pkg/plugin/proto`, add the following:

1. Protobuf definitions will be necessary for PreBackupAction in `pkg/plugin/proto/PreBackupAction.proto`.

```protobuf
message PreBackupActionExecuteRequest {
    ...
}

service PreBackupAction {
    rpc Execute(PreBackupActionExecuteRequest) returns (Empty)
}
```

Once these are written, then a client and server implementation can be written in `pkg/plugin/framework/pre_backup_action_client.go` and `pkg/plugin/framework/pre_backup_action_server.go`, respectively.

2. Protobuf definitions will be necessary for PostBackupAction in `pkg/plugin/proto/PostBackupAction.proto`.

```protobuf
message PostBackupActionExecuteRequest {
    ...
}

service PostBackupAction {
    rpc Execute(PostBackupActionExecuteRequest) returns (Empty)
}
```

Once these are written, then a client and server implementation can be written in `pkg/plugin/framework/post_backup_action_client.go` and `pkg/plugin/framework/post_backup_action_server.go`, respectively.

3. Protobuf definitions will be necessary for PreRestoreAction in `pkg/plugin/proto/PreRestoreAction.proto`.

```protobuf
message PreRestoreActionExecuteRequest {
    ...
}

service PreRestoreAction {
    rpc Execute(PreRestoreActionExecuteRequest) returns (Empty)
}
```

Once these are written, then a client and server implementation can be written in `pkg/plugin/framework/pre_restore_action_client.go` and `pkg/plugin/framework/pre_restore_action_server.go`, respectively.

4. Protobuf definitions will be necessary for PostRestoreAction in `pkg/plugin/proto/PostRestoreAction.proto`.

```protobuf
message PostRestoreActionExecuteRequest {
    ...
}

service PostRestoreAction {
    rpc Execute(PostRestoreActionExecuteRequest) returns (Empty)
}
```

Once these are written, then a client and server implementation can be written in `pkg/plugin/framework/post_restore_action_client.go` and `pkg/plugin/framework/post_restore_action_server.go`, respectively.

### Restartable Delete Plugins

Similar to the `RestoreItemAction` and `BackupItemAction` plugins, restartable processes will need to be implemented (with the difference that there is no `AppliedTo()` method).

In `pkg/plugin/clientmgmt/`, add

1. `restartable_pre_backup_action.go`, creating the following unexported type:

```go
type restartablePreBackupAction struct {
    key                 kindAndName
    sharedPluginProcess RestartableProcess
}

func newRestartablePreBackupAction(name string, sharedPluginProcess RestartableProcess) *restartablePreBackupAction {
    // ...
}

func (r *restartablePreBackupAction) getPreBackupAction() (velero.PreBackupAction, error) {
    // ...
}

func (r *restartablePreBackupAction) getDelegate() (velero.PreBackupAction, error) {
    // ...
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *restartablePreBackupAction) Execute(input *velero.PreBackupActionInput) (error) {
    // ...
}
```

2. `restartable_post_backup_action.go`, creating the following unexported type:

```go
type restartablePostBackupAction struct {
    key                 kindAndName
    sharedPluginProcess RestartableProcess
}

func newRestartablePostBackupAction(name string, sharedPluginProcess RestartableProcess) *restartablePostBackupAction {
    // ...
}

func (r *restartablePostBackupAction) getPostBackupAction() (velero.PostBackupAction, error) {
    // ...
}

func (r *restartablePostBackupAction) getDelegate() (velero.PostBackupAction, error) {
    // ...
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *restartablePostBackupAction) Execute(input *velero.PostBackupActionInput) (error) {
    // ...
}
```

3. `restartable_pre_restore_action.go`, creating the following unexported type:

```go
type restartablePreRestoreAction struct {
    key                 kindAndName
    sharedPluginProcess RestartableProcess
}

func newRestartablePreRestoreAction(name string, sharedPluginProcess RestartableProcess) *restartablePreRestoreAction {
    // ...
}

func (r *restartablePreRestoreAction) getPreRestoreAction() (velero.PreRestoreAction, error) {
    // ...
}

func (r *restartablePreRestoreAction) getDelegate() (velero.PreRestoreAction, error) {
    // ...
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *restartablePreRestoreAction) Execute(input *velero.PreRestoreActionInput) (error) {
    // ...
}
```

4. `restartable_post_restore_action.go`, creating the following unexported type:

```go
type restartablePostRestoreAction struct {
    key                 kindAndName
    sharedPluginProcess RestartableProcess
}

func newRestartablePostRestoreAction(name string, sharedPluginProcess RestartableProcess) *restartablePostRestoreAction {
    // ...
}

func (r *restartablePostRestoreAction) getPostRestoreAction() (velero.PostRestoreAction, error) {
    // ...
}

func (r *restartablePostRestoreAction) getDelegate() (velero.PostRestoreAction, error) {
    // ...
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *restartablePostRestoreAction) Execute(input *velero.PostRestoreActionInput) (error) {
    // ...
}
```

### Plugin Manager Changes

Add the following methods to the `Manager` interface in `pkg/plugin/clientmgmt/manager.go`:

```go
type Manager interface {
    ...
    // Get PreBackupAction returns a PreBackupAction plugin for name.
    GetPreBackupAction(name string) (PreBackupAction, error)

    // Get PreBackupActions returns the all PreBackupAction plugins.
    GetPreBackupActions() ([]PreBackupAction, error)

    // Get PostBackupAction returns a PostBackupAction plugin for name.
    GetPostBackupAction(name string) (PostBackupAction, error)

    // GetPostBackupActions returns the all PostBackupAction plugins.
    GetPostBackupActions() ([]PostBackupAction, error)

    // Get PreRestoreAction returns a PreRestoreAction plugin for name.
    GetPreRestoreAction(name string) (PreRestoreAction, error)

    // Get PreRestoreActions returns the all PreRestoreAction plugins.
    GetPreRestoreActions() ([]PreRestoreAction, error)

    // Get PostRestoreAction returns a PostRestoreAction plugin for name.
    GetPostRestoreAction(name string) (PostRestoreAction, error)

    // GetPostRestoreActions returns the all PostRestoreAction plugins.
    GetPostRestoreActions() ([]PostRestoreAction, error)

}
```

`GetPreBackupAction` and `GetPreBackupActions` will invoke the `restartablePreBackupAction` implementations.
`GetPostBackupAction` and `GetPostBackupActions` will invoke the `restartablePostBackupAction` implementations.
`GetPreRestoreAction` and `GetPreRestoreActions` will invoke the `restartablePreRestoreAction` implementations.
`GetPostRestoreAction` and `GetPostRestoreActions` will invoke the `restartablePostRestoreAction` implementations.

### How to invoke the Plugins

#### Getting Pre/Post Backup Actions

Getting Actions on `backup_controller.go` in `runBackup`:

```go

    backupLog.Info("Getting PreBackup actions")
    preBackupActions, err := pluginManager.GetPreBackupActions()
    if err != nil {
        return err
    }

    backupLog.Info("Getting PostBackup actions")
    postBackupActions, err := pluginManager.GetPostBackupActions()
    if err != nil {
        return err
    }
```

#### Pre Backup Actions Plugins

Calling the Pre Backup actions:

```go
    for _, preBackupAction := range preBackupActions {
        err := preBackupAction.Execute(backup.Backup)
        if err != nil {
            backup.Backup.Status.Phase = velerov1api.BackupPhaseFailedPreBackupActions
            return err
        }
    }
```

#### Post Backup Actions Plugins

Calling the Post Backup actions:

```go
    for _, postBackupAction := range postBackupActions {
        err := postBackupAction.Execute(backup.Backup)
        if err != nil {
            postBackupLog.Error(err)
        }
    }
```

#### Getting Pre/Post Restore Actions

Getting Actions on `restore_controller.go` in `runValidatedRestore`:

```go

    restoreLog.Info("Getting PreRestore actions")
    preRestoreActions, err := pluginManager.GetPreRestoreActions()
    if err != nil {
        return errors.Wrap(err, "error getting pre-restore actions")
    }

    restoreLog.Info("Getting PostRestore actions")
    postRestoreActions, err := pluginManager.GetPostRestoreActions()
    if err != nil {
        return errors.Wrap(err, "error getting post-restore actions")
    }
```

#### Pre Restore Actions Plugins

Calling the Pre Restore actions:

```go
    for _, preRestoreAction := range preRestoreActions {
        err := preRestoreAction.Execute(restoreReq.Restore)
        if err != nil {
            restoreReq.Restore.Status.Phase = velerov1api.RestorePhaseFailedPreRestoreActions
            return errors.Wrap(err, "error executing pre-restore action")
        }
    }
```

#### Post Restore Actions Plugins

Calling the Post Restore actions:

```go
    for _, postRestoreAction := range postRestoreActions {
        err := postRestoreAction.Execute(restoreReq.Restore)
        if err != nil {
            postRestoreLog.Error(err.Error())
        }
    }
```

### Giving the User the Option to Skip the Execution of the Plugins

Velero plugins are loaded as init containers. If plugins are unloaded, they trigger a restart of the Velero controller.
Not mentioning if one plugin does get loaded for any reason (i.e., docker hub image pace limit), Velero does not start.
In other words, the constant load/unload of plugins can disrupt the Velero controller, and they cannot be the only method to run the actions from these plugins selectively.
As part of this proposal, we want to give the velero user the ability to skip the execution of the plugins via annotations on the Velero CR backup and restore objects.
If one of these exists, the given plugin, referenced below as `plugin-name`, will be skipped.

Backup Object Annotations:

```
   <plugin-name>/prebackup=skip
   <plugin-name>/postbackup=skip
```

Restore Object Annotations:

```
   <plugin-name>/prerestore=skip
   <plugin-name>/postrestore=skip
```

## Alternatives Considered

An alternative to these plugin hooks is to implement all the pre/post backup/restore logic _outside_ Velero.
In this case, one would need to write an external controller that works similar to what [Konveyor Crane](https://github.com/konveyor/mig-controller/blob/master/pkg/controller/migmigration/quiesce.go) does today when quiescing applications.
We find this a viable way, but we think that Velero users can benefit from Velero having greater embedded capabilities, which will allow users to write or load plugins extensions without relying on an external components.

## Security Considerations

The plugins will only be invoked if loaded per a user's discretion.
It is recommended to check security vulnerabilities before execution.

## Compatibility

In terms of backward compatibility, this design should stay compatible with most Velero installations that are upgrading.
If plugins are not present, then the backup/restore process should proceed the same way it worked before their inclusion.

## Implementation

The implementation dependencies are roughly in the order as they are described in the [Detailed Design](#detailed-design) section.

## Open Issues
