## Timeout for Plugins 
This document proposes a solution that allows user to specify timeout during backup for all plugin executions on an object of specific resource types.

## Background
The execution of plugins in either Backup or Restore datapath is blocking call.  If the plugin code does not behave as expected and return within certain period of time, the application may fail.  For example in App Consistent backup, the application pod will be quiesced while plugin being executed so user operations are blocked until the plugin execution completes and pod is unquiesced.  If for some reason the plugin execution takes longer than certain threshold or hang, the application starts to fail user operations.

## Goals
- Enable user to specify timeout during backup for all plugin executions on an object of specific resource types.

## Non-goals
- Restore data path may require similar timeout but it is beyond the scope of this change due to the complexity of dependency between restoring objects.

## Alternatives Considered
- Set timeout for the entire Velero Backup or Restore to avoid the hanging of the backup or restore workflow.  This only helps in some scenario but it will not help the AppConsistent pod being quiesced for too long.
- Set timeout for each plugin being executed on an object.  In cases that multiple plugins being executed on an object, the total time of these plugin executions may be still greater than the limit even though individual timeout of each plugin would be smaller than timeout.


## High-Level Design
- Enhance the BackupSpec to contain the map of resource type (Kind) to the timeout of executing all plugins being executed on an object of that resource type.
   type BackupSpec struct {
      ...
      TotalPluginsTimeouts map[string]int `json:"totalPluginsTimeouts,omitempty"` //map of resource type to total plugins timeout (in milliseconds)
   }
- During backup an item, if the item's type match with the type specify in the TotalPluginsTimeouts map, all the plugins will have to be executed within that timeout.  If item's type is not in the map, then execute the plugins without timeout.

### Changes to item_backupper.go
- In itemBackupper.backupItem, use the resource type of the item to look up the TotalPluginsTimeouts.  If the timeout exists, create a goroutine to run executeActions to make sure that function would be done within the specified timeout or cancel it.  If timeout does not exist, the run executeAction directly as before.

### Changes to velero CLI
Add new flag "--total-plugins-timeouts" to Velero backup create command which takes a string of key-values pairs which represents the map between resource type and the total plugins timeout of such resource type.  The key-value pairs are separated by semicolon.

Example:
>velero backup create mybackup --total-plugins-timeouts "persistentvolumeclaims=30000,pods=60000"

