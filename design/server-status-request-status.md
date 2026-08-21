# Server Status to Reflect Backup Storage Location Readiness

## Abstract

Use the Server Status Request (SSR) resource to store a new field that helps to gauge the status of the Velero server.
The Velero server depends on many components, including at least one available Backup Storage Location (BSL).
Have the BSL controller update the Velero server status based on the availability of one or more BSLs.

## Background

Velero depends on various components in order to be able to do a backup and/or restore, such as the Backup Storage Locations (BSLs).
Instead of looking at the statuses of one or more BSLs to determine if Velero is ready to do a backup and/or restore, it would be more convenient to able to read from a single SSR that contains the Velero server status.
For this design doc, the server status will be derived only from BSL availability, but in the future, other components such as Restic daemonset status can be incorporated.

## Goals

- Create an SSR during Velero installation.
- Create a new Velero command, `velero server status` that will read from the SSR resource.
- The BSL controller will continuously update the server status.
- Redo the existing Velero command, `velero version` to not create a new SSR, but rather read from the one created during installation.

## Non-Goals

- Components other than the BSL controller will not update SSR server status.
- Behavior for the `velero get plugins` which creates an SSR and reads the plugins portion of the SSR status will not be changed.

## High-Level Design

There are two parts to this design: (1) Updating the SSR resource, and (2) Updating the BSL controller.

A new and unique SSR resource is created every time the `velero version` command is run.
The proposed change is to create an SSR during Velero installation and it is this resource that will be updated and retained.
Running `velero version` will no longer create a new SSR but will instead obtain information from the existing one.
A new command `velero server status` will be created that will also read and output information from the existing SSR.
The server statuses that will be added will be "Ready", "Partially Ready", and "Waiting".
These statuses will be stored in the a new field in SSR called `.status.serverStatus`.

When either `velero version` or `velero server status` command is run, the output will look something similar to

```bash
Client:
     Version: v1.6.1
     Git commit: -
Server:
    Version: v1.7.0
    Status: Partially Ready
```

The BSL controller will check each of the BSL resources for their statuses which are, "Available" and "Unavailable".
Here is how the BSL controller will update the SSR resource:

- All BSLs have the "Available" status => Server status will show as "Ready.
- There is at least one BSL that is "Available" and at least one that is "Unavailable" => Server status will show as "Partially Ready".
- All BSLs are "Unavailable" => Server status will show as "Waiting".

## Detailed Design

The design can be broken up into two parts: (1) Updating the SSR resource, and (2) Updating the BSL controller.

### SSR Resource Changes

I propose that an SSR called, "velero-server-status", be created during Velero installation.
The SSR can be added within the [AllResources function](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/install/resources.go#L246) located in pkg/install/resources.go.
The [SSR type](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/apis/velero/v1/server_status_request_types.go#L35) will need to be updated with additional constants that will serve as server status values.

SSR controller will not delete SSRs with the name `velero-server-status`, but will continue to delete SSRs created by the `velero get plugins` command.
SSRs will be retained by returning early with an if statement that checks the SSR's name in the switch case, [velerov1api.ServerStatusRequestPhaseProcessed](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/controller/server_status_request_controller.go#L108).
The if statement condition will look like,

```go
if statusRequest.Name == "velero-server-status" {
    return ctrl.Result{}, nil
}
// Existing expiration and deletion logic will be kept.
```

Note the `velero-server-status` SSR object will stay in the processed phase while the BSL controller continues to update the server status.

A new command, `velero server status`, will be created by adding a NewCommand(f client.Factory) function in [pkg/cmd/cli/server-status/server_status.go](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/cmd/cli/serverstatus/server_status.go).
Cobra will need to be updated accordingly to make the new command functional.

Currently, an SSR resource is created every time the `velero version` command is run. The command calls a method, [GetServerStatus](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/cmd/cli/version/version.go#L77) that both creates and waits for the SSR object to be updated by the SSR controller.
The method is called on the [DefaultServerStatusGetter](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/cmd/cli/serverstatus/server_status.go#L36) object.

Whenever the `velero server status` or the `velero version` command is called, I propose the [DefaultServerStatusGetter](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/cmd/cli/serverstatus/server_status.go#L36) be replaced with a new object, `VeleroServerStatusGetter`.
It will implement the [ServerStatusGetter](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/cmd/cli/serverstatus/server_status.go#L32) interface, necessarily having a GetServerStatus method that will retrieve the already existing SSR named `velero-server-status`.

The new server status information will be displayed by modifying the [printVersion(...) function](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/cmd/cli/version/version.go#L68) in pkg/cmd/cli/version/version.go.
This line will be added:

```go
fmt.Fprintf(w, "\tStatus: %s\n", serverStatus.Status.ServerStatus)
```

### BSL Controller Changes

The BSL controller [loops through](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/controller/backup_storage_location_controller.go#L79) all the BSL resources and checks if they are valid.
I can use two variables declared preceding the for loop, [unavailableErrors](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/controller/backup_storage_location_controller.go#L77) and [anyVerified](https://github.com/vmware-tanzu/velero/blob/afe43b2c9d86ed6f9a0dab679f8292cf94743903/pkg/controller/backup_storage_location_controller.go#L78) to determine how to set the server status object.

The logic to be added will be similar to the following:

```go
status := "Waiting" // Will use constants for the status.

if anyVerified {
    status = "Ready"
}

if len(unavailableErrors) > 0 {
    status = "Partially Ready"
}
```

I'll create a function called updateServerStatus that will look for the `velero-server-status` SSR and update the status with the SSR's `.status.serverStatus` determined in the above code block.

## Alternatives Considered

[Issue #2488](https://github.com/vmware-tanzu/velero/issues/2488) mentions checking for a default BSL before setting the server status as ready.
Sukarna Grandhi brought up in the Oct. 19, 2021 Velero Community meeting that default BSL is no longer necessary and should not affect the server status.
For this reason, default BSL is ignored for determining server status.

[Issue #2488](https://github.com/vmware-tanzu/velero/issues/2488) also mentions a "Pending" BSL state, however it does not exist and I don't think it's needed to determine BSL readiness.
For this reason, the "Pending" status will not be added in this design doc.

## Security Considerations

No sensitive data is being generated and therefore will not be be displayed nor exposed by the new/updated commands.

## Compatibility

A new command will be created that will have the exact same output as an existing command, `velero version`.
Although the new command will be redundant, the old one will be kept for backward compatibility.
A new command, `velero server status` will be created as it describes more accurately what is being displayed.

## Implementation

I (@codegold79) will be able to get the design implemented for Velero the 1.8 RC version.
I can probably submit a PR by early November 2021.

## Open Issues

@brito-rafa brought up updating the server status with the installation status of Restic.
During the Velero Sprint meeting Oct. 19, 2021, I asked about incorporating Restic status to the server status.
@dsu-igeek advised that I create an issue for it and add the Restic status after the BSL design (this doc) is adopted.
Here is [issue #4258](https://github.com/vmware-tanzu/velero/issues/4258).
