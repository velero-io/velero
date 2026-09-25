# Design to clean up restore-created VolumeSnapshotContent after PVC hydration

## Terminology

* VSC: VolumeSnapshotContent
* VS: VolumeSnapshot
* PVC: PersistentVolumeClaim
* RIA: RestoreItemAction

## Abstract

When Velero restores a backup that used CSI snapshots (without data mover), a VolumeSnapshotContent (VSC) and VolumeSnapshot (VS) are created with a `Retain` DeletionPolicy. After the PVC is bound and the data hydration from the snapshot is complete, the VS and VSC are no longer needed. However, they are never cleaned up the VSC remains as an orphaned cluster-scoped resource indefinitely. 
This design proposes using the existing RIA v2 async operation mechanism to track PVC hydration completion and clean up the VS/VSC at the right time.

Related issue: [vmware-tanzu/velero#9186](https://github.com/vmware-tanzu/velero/issues/9186)

## Background

In the current CSI snapshot restore flow (non-data-mover path):

1. `PVCRestoreItemAction.Execute()` sets the PVC's data source to a VolumeSnapshot and returns the VS as an additional item.
2. `VolumeSnapshotRestoreItemAction.Execute()` restores the VS with a generated name and sets `DeletionPolicy` annotation to `Retain`. It returns the bound VSC as an additional item.
3. `VolumeSnapshotContentRestoreItemAction.Execute()` restores the VSC with a generated name, sets `DeletionPolicy` to `Retain`, and points `Source.SnapshotHandle` to the backed-up snapshot handle.

The `Retain` DeletionPolicy is set intentionally during restore to prevent premature snapshot deletion if the VS is deleted before data hydration completes. However, this means:

- Deleting the restored namespace (which deletes the namespaced VS) does **not** cascade-delete the cluster-scoped VSC.
- Deleting the backup does **not** clean up restore-created VSCs backup deletion only handles backup-created VSCs (identified by `velero.io/backup-name` labels).
- The VSC is left as `Retained` and never deleted, leaking cluster resources and potentially storage provider snapshots.

### Current Code Flow

The `PVCRestoreItemAction` already supports async operations for the **data mover** path  it returns an `operationID` and implements `Progress()` to poll the `DataDownload` status. However, for the **CSI snapshot** path (non-data-mover), no `operationID` is returned, so Velero does not track PVC hydration and the restore completes immediately without waiting or cleaning up.

## Goals

- Clean up the restore-created VS and VSC after PVC data hydration is complete.
- Make the restore status accurately reflect the PV-via-snapshot restoration flow.
- Leverage the existing RIA v2 async operation infrastructure (no new controllers or CRDs).
- Introducing a new GC controller for orphaned VSCs.


## Approaches Considered

### Approach 1: GC Controller

**Description:** Introduce a new controller that periodically scans for restore-created VS/VSC objects and deletes them when the associated PVC is bound.

**Pros:**
- Decoupled from the restore lifecycle — cleanup happens independently.
- Works even if the restore process itself fails or is interrupted.

**Cons:**
- Adds operational complexity — a new controller to maintain, configure, and debug.
- Requires a reliable way to identify "restore-created" VS/VSC objects (labels/annotations).
- Polling-based — introduces latency between PVC readiness and cleanup.


### Approach 2: Async Operation in PVC RestoreItemAction (Selected)

**Description:** Extend the existing `PVCRestoreItemAction` to return an `operationID` for CSI snapshot restores (not just data mover restores). Implement `Progress()` to poll the PVC bound status and the VSC's `ReadyToUse` status. Once hydration is complete, change the VSC's `DeletionPolicy` to `Delete`, delete the VS (which cascades to delete the VSC), and report the operation as complete.

**Pros:**
- Leverages the existing RIA v2 async operation infrastructure — no new controllers, CRDs, or reconciliation loops.
- Makes the restore status accurate — the restore transitions through `WaitingForPluginOperations` → `Finalizing` → `Completed`, reflecting actual PV readiness.
- Cleanup is deterministic and tied to PVC readiness, not time-based polling.
- Consistent with the data mover path, which already uses this pattern.
- Aligns with maintainer consensus: @reasonerjt stated "If we can make the status of the Restore accurate to reflect the flow of restoring the PV via snapshot, we can trigger the deletion of the VSC at the right time. This is a better approach than GC." ([comment](https://github.com/vmware-tanzu/velero/issues/9186#issuecomment-3301602678)).
- @blackpiglet confirmed "the VS and VSC status should be checked, too" ([comment](https://github.com/vmware-tanzu/velero/issues/9186#issuecomment-3430621161)).

**Cons:**
- Restore duration increases — the restore won't complete until PVC hydration finishes, which may take a long time for large volumes. This is actually a feature (accurate status) but is a behavior change.

**Selection:** Using Approach 2:

## Detailed Design

### Overview

The changes are confined to `pkg/restore/actions/csi/pvc_action.go`. The existing `pvcRestoreItemAction` struct already has the `crClient` field needed to query Kubernetes resources.

#### Restore Phase Transition Graphs
Current Flow (CSI Snapshot Restore : No Data Mover)

```
┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│   New   │────▶│  InProgress  │────▶│  Finalizing  │────▶│  Completed  │
└─────────┘     └──────────────┘     └──────────────┘     └─────────────┘
                                                                          
                 No operationID                                           
                 returned for CSI     PVC hydration        VS/VSC are     
                 snapshot path ─▶     NOT tracked ─▶       NEVER cleaned  
                 skips async          goes straight         up (orphaned)  
                 operation tracking   to Finalizing                                              
```

Problem: Since no operationID is returned, Velero skips WaitingForPluginOperations entirely. The restore completes immediately without waiting for PVC hydration and without cleaning up the VS/VSC.

New Flow (CSI Snapshot Restore)

```
┌─────────┐     ┌──────────────┐     ┌───────────────────────────────┐     ┌──────────────┐     ┌─────────────┐
│   New   │────▶│  InProgress  │────▶│  WaitingForPluginOperations   │────▶│  Finalizing  │────▶│  Completed  │
└─────────┘     └──────────────┘     └───────────────────────────────┘     └──────────────┘     └─────────────┘
                                                    │                                                          
                PVCRestoreItemAction                │ restoreOperationsReconciler                              
                now returns an                      │ periodically calls Progress()                            
                operationID for CSI                 │ on PVCRestoreItemAction:                                 
                snapshot path too                   │                                                          
                                                    │  ┌─────────────────────────────┐                         
                                                    │  │ Progress() checks:          │                         
                                                    ├──│  1. PVC Bound?              │                         
                                                    │  │  2. VSC ReadyToUse?         │                         
                                                    │  │  3. VS ReadyToUse?          │                         
                                                    │  └─────────────────────────────┘                         
                                                    │                                                          
                                                    │  Once all checks pass:                                   
                                                    │  ┌─────────────────────────────┐                         
                                                    └──│ Cleanup:                    │                         
                                                       │  1. VSC DeletionPolicy ─▶   │                         
                                                       │     Change to "Delete"      │                         
                                                       │  2. Delete VS               │                         
                                                       │     (cascades to delete VSC)│                         
                                                       │  3. Report operation        │                         
                                                       │     complete                │                         
                                                       └─────────────────────────────┘                         
```

Error/Partial Failure Paths

```
┌─────────┐     ┌──────────────┐     ┌─────────────────────────────────────────────┐     ┌──────────────────────────────┐     ┌────────────────────┐
│   New   │────▶│  InProgress  │──┬─▶│  WaitingForPluginOperations                 │──┬─▶│  Finalizing                  │────▶│  Completed         │
└─────────┘     └──────────────┘  │  └─────────────────────────────────────────────┘  │  └──────────────────────────────┘     └────────────────────┘
                                  │                     │                              │                                                             
                                  │      error during   │                              │                                                             
                                  │      Progress()     ▼                              │                                                             
                                  │  ┌─────────────────────────────────────────────┐   │  ┌──────────────────────────────┐     ┌────────────────────┐
                                  │  │  WaitingForPluginOperationsPartiallyFailed  │───┴─▶│  FinalizingPartiallyFailed   │────▶│  PartiallyFailed   │
                                  │  └─────────────────────────────────────────────┘      └──────────────────────────────┘     └────────────────────┘
                                  │                                                                                                                  
                                  │  (fatal error during InProgress)                                                                                 
                                  └──────────────────────────────────────────────────────────────────────────────────────────▶┌────────────────────┐
                                                                                                                             │  Failed            │
                                                                                                                             └────────────────────┘

```

### Changes to `PVCRestoreItemAction.Execute()`

In the CSI snapshot restore branch (the `else` block after the data mover check), generate an `operationID` and store the VS/VSC names as metadata for later use by `Progress()`:

```go
} else {
    // CSI restore
    vsName, nameOK := pvcFromBackup.Annotations[velerov1api.VolumeSnapshotLabel]
    if !nameOK {
        logger.Info("Skipping PVCRestoreItemAction for PVC, PVC does not have a CSI VolumeSnapshot.")
        return &velero.RestoreItemActionExecuteOutput{
            UpdatedItem: input.Item,
        }, nil
    }

    newVSName := util.GenerateSha256FromRestoreUIDAndVsName(string(input.Restore.UID), vsName)

    p.log.Debugf("Setting PVC source to VolumeSnapshot new name: %s", newVSName)
    resetPVCSourceToVolumeSnapshot(&pvc, newVSName)

    additionalItems = append(additionalItems, velero.ResourceIdentifier{
        GroupResource: kuberesource.VolumeSnapshots,
        Name:          vsName,
        Namespace:     pvc.Namespace,
    })

    // Generate operationID for CSI snapshot restore to track hydration
    operationID = label.GetValidName(
        string(velerov1api.AsyncOperationIDPrefixDataDownload) +
            string(input.Restore.UID) + "." + string(pvcFromBackup.UID))

    // Store VS/VSC name and PVC info in annotations for Progress() to use
    kubeutil.AddAnnotations(&pvc.ObjectMeta, map[string]string{
        "velero.io/csi-restore-vs-name":  newVSName,
        "velero.io/csi-restore-vsc-name": newVSName, // VS and VSC share the same generated name
    })
}