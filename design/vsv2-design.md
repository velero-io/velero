# Design for VolumeSnapshotter v2 API

## Abstract
This design includes the changes to the VolumeSnapshotter api design as required by the [Item Action Progress Monitoring](Implemented/general-progress-monitoring.md) feature.
The VolumeSnapshotter v2 interface will have two new methods.
If there are any additional VolumeSnapshotter API changes that are needed in the same Velero release cycle as this change, those can be added here as well.

## Background
This API change is needed to facilitate long-running plugin actions that may not be complete when the Execute() method returns.
The existing snapshotID returned by CreateSnapshot will be used as the operation ID.
This will allow long-running plugin actions to continue in the background while Velero moves on to the next plugin, the next item, etc.

## Goals
- Allow for VolumeSnapshotter CreateSnapshot() to initiate a long-running operation and report on operation status.

## Non Goals
- Allowing velero control over when the long-running operation begins.


## High-Level Design
As per the [Plugin Versioning](Implemented/plugin-versioning.md) design, a new VolumeSnapshotterv2 plugin `.proto` file will be created to define the GRPC interface.
v2 go files will also be created in `plugin/clientmgmt/volumesnapshotter` and `plugin/framework/volumesnapshotter`, and a new PluginKind will be created.
The velero Backup process will be modified to reference v2 plugins instead of v1 plugins.
An adapter will be created so that any existing VolumeSnapshotter v1 plugin can be executed as a v2 plugin when executing a backup.

## Detailed Design

### proto changes (compiled into golang by protoc)

The v2 VolumeSnapshotter.proto will be like the current v1 version with the following changes:
The VolumeSnapshotter service gets two new rpc methods:
```
service VolumeSnapshotter {
    rpc Init(VolumeSnapshotterInitRequest) returns (Empty);
    rpc CreateVolumeFromSnapshot(CreateVolumeRequest) returns (CreateVolumeResponse);
    rpc GetVolumeInfo(GetVolumeInfoRequest) returns (GetVolumeInfoResponse);
    rpc CreateSnapshot(CreateSnapshotRequest) returns (CreateSnapshotResponse);
    rpc DeleteSnapshot(DeleteSnapshotRequest) returns (Empty);
    rpc GetVolumeID(GetVolumeIDRequest) returns (GetVolumeIDResponse);
    rpc SetVolumeID(SetVolumeIDRequest) returns (SetVolumeIDResponse);
    rpc Progress(VolumeSnapshotterProgressRequest) returns (VolumeSnapshotterProgressResponse);
    rpc Cancel(VolumeSnapshotterCancelRequest) returns (google.protobuf.Empty);
}
```
To support these new rpc methods, we define new request/response message types:
```
message VolumeSnapshotterProgressRequest {
    string plugin = 1;
    string snapshotID = 2;
}

message VolumeSnapshotterProgressResponse {
    generated.OperationProgress progress = 1;
}

message VolumeSnapshotterCancelRequest {
    string plugin = 1;
    string operationID = 2;
}

```
One new shared message type will be needed, as defined in the v2 BackupItemAction design:
```
message OperationProgress {
    bool completed = 1;
    string err = 2;
    int64 completed = 3;
    int64 total = 4;
    string operationUnits = 5;
    string description = 6;
    google.protobuf.Timestamp started = 7;
    google.protobuf.Timestamp updated = 8;
}
```

A new PluginKind, `VolumeSnapshotterV2`, will be created, and the backup process will be modified to use this plugin kind.
See [Plugin Versioning](Implemented/plugin-versioning.md) for more details on implementation plans, including v1 adapters, etc.


## Compatibility
The included v1 adapter will allow any existing VolumeSnapshotter plugin to work as expected, with no-op Progress() and Cancel() methods.

## Implementation
This will be implemented during the Velero 1.11 development cycle.
