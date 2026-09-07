# Data-only restore design

## Abstract
Support to restore only the data in the backup volume without restoring the k8s resources.

## Background
In some disaster recovery scenarios, the user only wants to restore the data in the volumes, because only specific volume's data is corrupted, but Velero doesn't support that yet. The design aims to address that missing function.

## Goals
- Support to restore only volume data for the filesystem-based backup.
- Support the in-place volume data restore, which means the data will be restored into existing volumes, instead of creating new volumes.
- Can filter the volumes that needs data restore.

## Non Goals
- Doesn't support the snapshot-based backup at phase one, because there is no easy way to read data from snapshot directly. To support the in-place restore method, may need to introduce a way to provision an intermediate volume created from the snapshot, then restore data from the intermediate volume.
- Cannot filter restored volume by name. It's convenient to specify the wanted volume by name, but the Velero backup and restore don't have that function yet, the feature will not also aim to introduce new resource filters.

## Detailed Design
A new parameter `DataOnly` is added to the `RestoreSpec` structure. The default value of `DataOnly` is `false`.

``` go
type RestoreSpec struct {
    ......
	// DataOnly specify whether to only restore volume data and related k8s resources
	// without any other k8s resources.
	DataOnly *bool `json:"dataOnly"`
    ......
}
```

### Restore CLI change
The `--data-only` parameter is added to the `velero restore create` CLI.
Both `--data-only` and `--data-only=true` mean enabling the data-only restore feature.
Both `--data-only=false` and not specifying the parameter mean disabling the data-only restore feature.

The `velero restore describe` CLI should display the data-restored PVCs' information.
The `velero restore describe` CLI should also display the `--data-only` parameter value.

### Resource Filtering
The restore provided filters only apply to the referenced backup included `PersistentVolumeClaims` resources.
The user can use the filters(including `IncludedNamespaces`, `ExcludedNamespaces`, `LabelSelector` and `OrLabelSelectors`) to select which volume data to restore.

The restore can include `IncludedResources`, `ExcludedResources`, `NamespaceMappings`, `ResourceModifierConfigMap`, `StatusExcludeResources` and `StatusIncludeResources`, but those parameters have no effect.
The `DataOnly` parameter's description should explain that.

The resource collector should be limited to PersistentVolumeClaim, Pod and DataUpload resources.
PVC should be filtered based on their volume data backup method, only PodVolumeBackup and DataUpload are kept. The kept PVCs are store into restoreContext.

``` go
type restoreContext struct {
	...
	DataOnlyRestorePVCs []types.NamespacedName
	...
}
```

Then only the pod mounting those PVCs are handled.
If the PVC is not mounted by any Pod, then the data restore of this PVC is skipped too.

### Restore Plugin Actions
Need to limit the applicable actions for the data-only restore.
Only the DataUploadRetrieveAction, InitRestoreHookPodAction and PodVolumeRestoreAction are relevant.

### Use PodVolumeRestore to restore the DataUpload
1. The data-only restore will use the existing way to read DataUpload information into ConfigMap, and clean the ConfigMap when restore completes.
1. The Velero filters the PVCs included in the backup by the restore's filters. 
1. Then Velero should get the DataUpload's ConfigMap for the filtered PVCs.
1. Generate the PodVolumeRestore according to the DataUpload's ConfigMap information.
1. Add restore-wait InitContainer into the PVC-mounting pod.

The following is the same to existing filesystem restore.

### Use PodVolumeRestore to restore PodVolumeBackup

1. The Velero filters the PVCs included in the backup by the restore's filters. 
1. Then Velero should get the PodVolumeBackup for the filtered PVCs.
1. Generate the PodVolumeRestore according to the PodVolumeBackup information.
1. Add restore-wait InitContainer into the PVC-mounting pod.

The following is the same to existing filesystem restore.

### Restore Hooks
The InitContainer Hook and the Exec Hook are still supported as before.

## Alternatives Considered
### Using PodVolumeRestore to write data into existing workload
At the beginning of this design, this design aims to implement a low-cost workaround to surpass the PodVolumeRestore reconcile checking.
This is a description of that [POC](https://github.com/vmware-tanzu/velero/issues/7345#issuecomment-1933305981). The POC tried to bypass the restored pod's restore-wait InitContainer check, then by drafting a PodVolumeRestore, the user can restore data into the existing workload.

The disadvantage of this POC is that the restored data is written directly into the existing volume. There is no guarantee of the data integrity if stale data is left in it. The user needs to ensure the target volume is clean, or that mixing restored data with existing data is acceptable.

### Filters for the restored volume
At first, the plan is that the user needs to explicitly give the mapping between the backed-up volume and the target pod's volume is the correct way, because the cluster environment may be quite different from the backed-up point.
It is indeed convenient for the users if they can choose the mapping.
The downside of this approach is, without the default setting, the user needs to specify mapping rules.
That increases the feature's usage difficulty.
Another issue is the flexibility seems too much. The user may try to restore big data into small volume by accident.

Another consideration of the filter is not allowing any filter when the data-only restore feature is enabled.
Then the Velero can decide what to restore when there is not enough k8s resource in the cluster, e.g. the pod mounting the volume doesn't exist.
After thinking about it twice, it's reasonable to let the user use the existing restore filters to select which volume to restore.
The Velero should emit an error or warning if the data restore condition cannot be performed.

### In-place restore or restore into new volumes
There was a discussion about going which direction, in-place restore, or new volume restore.
Either way has its own pros and cons.
The in-place restore can support granular-restore, and it's more friendly to the GitOps scenario.
The downside is that filesystem-based backup can support the in-place way easily, but snapshot-based backup needs more effort to do that. 
On the opposite, the new-volume way can support both snapshot-based and filesystem-based backups, but introducing a new volume impacts the existing workload.

The current decision is choosing the in-place way, and only support the file-system-based backup at phase one, then try to work out a neat way to support the snapshot-based backup, and add granular restore ability upon the in-place data restore.

## Security Considerations
No security issue is identified.

## Compatibility
No compatibility issue is identified.

## Implementation
1. Implement the CLI checking logic.
1. Use PodVolumeRestore to restore the data into existing volumes.
1. Generate volumes restore result. Display the result in the `velero restore describe` output.
1. Add E2E test case.

## Open Issues
None.