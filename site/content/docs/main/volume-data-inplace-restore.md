---
title: "Volume Data In-place Restore"
layout: docs
---

By default, Velero only restores PersistentVolume (PV) data when provisioning a new PersistentVolumeClaim (PVC). If a target PVC already exists in the cluster, Velero skips volume data restoration and leaves the existing volume untouched.

The **Volume Data In-place Restore** feature allows you to restore backup data directly into an existing, bound PVC and its underlying PV without deleting the PVC or PV first. You can overwrite the entire volume (*in-place full restore*) or restore only changed and missing data (*in-place incremental restore*).

**Warning:** An in-place restore overwrites data on your existing storage volume. Always take a backup of the target volume before initiating an in-place restore (such as a CSI snapshot backup without data movement). You must stop workloads and remove all consuming Pods before starting the restore.

## Supported Backup Methods

In-place restore support depends on the backup method:

{{< table caption="In-place restore support matrix" >}}
| Backup Method | Full Restore | Incremental Restore |
| --- | --- | --- |
| CSI snapshot with Velero block data mover (`velero-block`) | Yes | Yes |
| CSI snapshot with Velero file system data mover (`velero-fs`) | Yes | Yes |
| File System Backup (PodVolumeBackup / Kopia) | Yes | Yes |
| CSI snapshot without data movement | No | No |
| Native snapshot (cloud provider snapshot without CSI) | No | No |
{{< /table >}}

## In-place Restore Options

You configure in-place restore using the following CLI flags or `Restore` spec fields:

### Existing Volume Data Policy

Specify `--existing-volume-data-policy` on the CLI or `existingVolumeDataPolicy` in the `Restore` spec:

{{< table caption="Existing volume data policies" >}}
| Policy Value | Behavior |
| --- | --- |
| `""` or `none` (default) | Does not perform an in-place restore. If the target PVC already exists, Velero leaves the volume untouched. |
| `full` | Overwrites all data on the existing volume with the backup data. |
| `incremental` | Restores only data that has changed or is missing since the backup, skipping unchanged data. |
{{< /table >}}

The policy applies to all eligible volumes in the restore. If a target PVC does not exist in the cluster, Velero falls back to standard restore behavior and provisions a new PVC and PV regardless of whether the policy is set to `full` or `incremental`.

#### How Incremental Restore Works by Backup Type

When you set `--existing-volume-data-policy=incremental`, Velero uses different mechanisms to detect and restore changed data depending on the backup method:

- **CSI snapshot with block data mover (`velero-block`)**:
  - Operates at the raw block level for both `Block` and `Filesystem` volume modes.
  - Velero creates a temporary CSI snapshot of the existing target volume to serve as a baseline.
  - Using CSI Changed Block Tracking (CBT), Velero calculates the delta blocks between the target volume baseline snapshot and the backup snapshot.
  - Velero only transfers and overwrites modified or missing blocks, leaving unchanged blocks untouched on storage.
  - If the CSI driver or storage provider does not support CBT, or if a baseline snapshot cannot be created, Velero automatically falls back to an in-place full restore.

- **File system restores (CSI snapshot with `velero-fs` and File System Backup)**:
  - Operates at the file system level for `Filesystem` volume mode.
  - Does not require a baseline snapshot or storage CBT support.
  - Velero compares file metadata (such as modification timestamps and file sizes) between the target volume and the backup.
  - Velero only restores modified, missing, or corrupted files, skipping files that match the backup.
  - Extra files that exist on the target volume but not in the backup remain untouched by default, unless you specify `--delete-extra-files`.

### Existing Resource Policy vs. Existing Volume Data Policy

The `--existing-volume-data-policy` flag governs volume data restoration. It is independent of `--existing-resource-policy`, which controls Kubernetes resource manifests (such as Pod, Service, or PVC specifications). Setting `--existing-resource-policy=update` alone updates the PVC object metadata in Kubernetes, but does **not** restore or overwrite volume data.

### Deleting Extra Files (`--delete-extra-files`)

For file system restores (File System Backup and CSI file system data movement `velero-fs`), the target volume might contain files that do not exist in the backup.

By default, Velero keeps these extra files. To remove files on the target volume that are absent from the backup, specify `--delete-extra-files` on the CLI or set `uploaderConfig.deleteExtraFiles: true` in the `Restore` spec.

**Note:**
- `--delete-extra-files` only applies to file system restores (`velero-fs` and File System Backup).
- It has no effect on block data movement (`velero-block`), which operates at the block level.
- It is ignored when `--existing-volume-data-policy` is `none` or unset.

### Allowing Volume Identity Mismatch (`--allow-existing-volume-mismatch`)

By default, Velero validates that the existing PVC is bound to the same storage volume handle recorded in the backup. If the volume handle differs, Velero aborts the restore for that volume to prevent accidental data overwrites.

If you intentionally recreated or reverted the volume (for example, from a storage snapshot backup after a failed operation), the CSI volume handle will differ. To permit the in-place restore to proceed, specify `--allow-existing-volume-mismatch` on the CLI or set `allowExistingVolumeMismatch: true` in the `Restore` spec. Velero logs a warning instead of failing the check.

## Prerequisites and Workload Preparation

Before initiating an in-place restore, complete the following preparations. Velero does not automatically stop or delete workloads for you.

### 1. Take a Pre-restore Backup

An in-place restore directly overwrites existing storage. Always take a safety backup of your target namespace or volumes before restoring, for example, a CSI snapshot backup without data movement:

```bash
velero backup create pre-restore-backup \
  --include-namespaces <namespace> \
  --snapshot-volumes=true
```

### 2. Stop Consuming Workloads

Ensure no active Pods are using the target PVCs. Active Pods can cause data corruption and block PVC operations due to Kubernetes PVC protection and `ReadWriteOncePod` access constraints.

Prepare your workloads based on the backup method:

- **For CSI Snapshot Data Movement (`velero-block` and `velero-fs`):**
  - **Deployments and StatefulSets:** Scale replicas to zero:
    ```bash
    kubectl scale deployment <deployment-name> -n <namespace> --replicas=0
    kubectl scale statefulset <statefulset-name> -n <namespace> --replicas=0
    ```
    Wait until all Pods are fully terminated.
  - **Jobs and CronJobs:** Suspend active CronJobs and delete any running Jobs and their Pods.
  - **DaemonSets:** Temporarily delete the DaemonSet (retaining PVCs and PVs), or cordon and drain nodes to terminate consuming Pods.
  - **Operator-Managed Workloads (for example, ArgoCD or Flux):** Pause reconciliation or synchronization, then delete the managed Pods.
  - **External Consumers:** Disconnect any out-of-cluster storage clients (such as direct NFS or iSCSI mounts).

- **For File System Backup (PodVolumeRestore):**
  - **Delete the workload controllers** (Deployments, StatefulSets, etc.) while keeping the PVCs and PVs in the cluster:
    ```bash
    kubectl delete deployment <deployment-name> -n <namespace> --cascade=foreground
    ```
    **Important:** Do not merely scale controllers to zero for File System Backup. File System Backup restores data through an init container in the restored Pod created by Velero. A controller scaled to zero immediately terminates that restored Pod. Include the workload controllers in the restore so Velero recreates them with the required restore init container.

### 3. Verify Pre-flight Requirements

Velero automatically validates the following conditions before modifying storage:

- **PVC is not in use:** The target PVC must not be mounted by non-terminal Pods (Pods in `Pending`, `Running`, or `Terminating` phases block the restore).
- **PVC is bound:** The target PVC must be in `Bound` phase and, unless `--allow-existing-volume-mismatch` is set, bound to the original volume handle.
- **Sufficient capacity:** The target PV storage capacity must be equal to or larger than the backed-up data size.

## Run an In-place Restore

### Using the Velero CLI

#### In-place Full Restore

To restore all volume data into existing volumes:

```bash
velero restore create <restore-name> \
  --from-backup <backup-name> \
  --existing-volume-data-policy=full \
  --wait
```

#### In-place Incremental Restore

To restore only changed or missing data, and remove files absent from the backup on file system volumes:

```bash
velero restore create <restore-name> \
  --from-backup <backup-name> \
  --existing-volume-data-policy=incremental \
  --delete-extra-files \
  --wait
```

#### In-place Restore with Volume Mismatch Allowed

To restore into existing PVCs whose underlying volume handles have changed since the backup:

```bash
velero restore create <restore-name> \
  --from-backup <backup-name> \
  --existing-volume-data-policy=full \
  --allow-existing-volume-mismatch \
  --wait
```

### Using a Restore Custom Resource

You can also submit a `Restore` custom resource YAML manifest:

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: inplace-restore-sample
  namespace: velero
spec:
  backupName: sample-backup
  existingVolumeDataPolicy: incremental
  allowExistingVolumeMismatch: false
  uploaderConfig:
    deleteExtraFiles: true
```

Apply the manifest using `kubectl`:

```bash
kubectl apply -f restore.yaml
```

## Cross-Namespace In-place Restore

You can perform an in-place restore into a different namespace using `--namespace-mappings`:

```bash
velero restore create <restore-name> \
  --from-backup <backup-name> \
  --namespace-mappings <source-namespace>:<target-namespace> \
  --existing-volume-data-policy=full
```

### Cross-Namespace Incremental Block Restore (Clone-and-Restore)

For CSI block data mover (`velero-block`), Changed Block Tracking cannot calculate deltas across different namespaces directly. To perform a fast incremental restore into another namespace:

1. **Snapshot the source PVC:** Take a manual CSI `VolumeSnapshot` of the source PVC.
2. **Create a clone PVC in the target namespace:** Create a PVC in the destination namespace with its `dataSource` pointing to the `VolumeSnapshot`. Ensure the PVC name matches the expected restore name and is `Bound`.
3. **Ensure no workloads access the clone PVC.**
4. **Run the incremental restore:**
   ```bash
   velero restore create <restore-name> \
     --from-backup <backup-name> \
     --namespace-mappings <source-namespace>:<target-namespace> \
     --existing-volume-data-policy=incremental
   ```
   Velero detects the `VolumeSnapshot` in the destination PVC's `dataSource`, uses it as the CBT baseline, and writes only the changed blocks.
5. **Clean up:** Delete the temporary snapshot resources once the restore completes.
