---
title: "CSI Snapshot Data Movement"
layout: docs
---

CSI Snapshot Data Movement is built according to the [Volume Snapshot Data Movement design][1] and is specifically designed to move CSI snapshot data to a backup storage location.  
CSI Snapshot Data Movement takes CSI snapshots through the CSI plugin in nearly the same way as [CSI snapshot backup][2]. However, it doesn't stop after a snapshot is taken. Instead, it tries to access the snapshot data through various data movers and back up the data to a backup storage connected to the data movers.  
Consequently, the volume data is backed up to a pre-defined backup storage in a consistent manner.  
After the backup completes, the CSI snapshot will be removed by Velero and the snapshot data space will be released on the storage side.  

CSI Snapshot Data Movement is useful in below scenarios:
- For on-premises users, the storage usually doesn't support durable snapshots, so it is impossible/less efficient/cost ineffective to keep volume snapshots by the storage, as required by the [CSI snapshot backup][2]. This feature helps to move the snapshot data to a storage with lower cost and larger scale for long time preservation.    
- For public cloud users, this feature helps users to fulfil the multiple cloud strategy. It allows users to back up volume snapshots from one cloud provider and preserve or restore the data to another cloud provider. Then users will be free to flow their business data across cloud providers based on Velero backup and restore.  

Besides, Velero [File System Backup][3] which could also back up the volume data to a pre-defined backup storage. CSI Snapshot Data Movement works together with [File System Backup][3] to satisfy different requirements for the above scenarios. And whenever available, CSI Snapshot Data Movement should be used in preference since the [File System Backup][3] reads data from the live PV, in which way the data is not captured at the same point in time, so is less consistent.  
Moreover, CSI Snapshot Data Movement brings more possible ways of data access, i.e., accessing the data from the block level, either fully or incrementally.  
On the other hand, there are quite some cases that CSI snapshot is not available (i.e., you need a volume snapshot plugin for your storage platform, or you're using EFS, NFS, emptyDir, local, or any other volume type that doesn't have a native snapshot), then [File System Backup][3] will be the only option.  

### Built-in Data Movers: File System vs. Block Data Mover

CSI Snapshot Data Movement supports both Velero built-in data movers and customized data movers. For the details of how Velero works with customized data movers, check the [Volume Snapshot Data Movement design][1].

Velero Built-in Data Mover (VBDM) provides two data movers:
1. **Velero File System Data Mover (`velero-fs`)**:
   - Reads volume data through the file system and writes to the backup repository via Velero's built-in uploader (Kopia).
   - Serves as the default data mover when `--data-mover velero` or no data mover parameter is specified.
   - Ideal for volumes backed by file storage (e.g., AWS EFS, Azure Files, CephFS, NFS), or when the storage does not support block-level Changed Block Tracking (CBT).

2. **Velero Block Data Mover (`velero-block`)**:
   - Accesses snapshot data directly at the raw block level, bypassing file system traversal.
   - Integrates with the [Kubernetes CSI Changed Block Tracking (CBT) API][23] (`SnapshotMetadataService`) to identify allocated blocks (for full backups) and changed blocks (for incremental backups).
   - Provides significant performance and efficiency advantages:
     - **Higher throughput and lower resource usage**: Avoids file system scanning overhead, particularly beneficial for large volumes or file systems with millions of small files.
     - **True incremental backups via CBT**: Only transfers changed blocks since the previous snapshot, substantially minimizing network transfer, backup storage footprint, and backup duration (lowering TCO).
     - **Volume mode flexibility**: Backs up both `FileSystem` and `Block` volumeMode volumes (as long as backed by block storage). On restore, writes raw block data and can rebind to either `FileSystem` or `Block` mode target PVCs.
     - **OS independence**: Does not require host filesystem drivers for the volume's filesystem format.
   - For more technical details, see the [Block Data Mover Design][24].

Both built-in data movers read/write snapshot data from/to the Unified Repository.

Velero built-in data mover restores both volume data and metadata, so the data mover pods need to run as root user.

### Comparing Backup Approaches: Block Data Mover vs. File System Data Mover vs. File System Backup

The following table summarizes the key differences among the three approaches to back up volume data:

| Capability / Scenario | Block Data Mover | File System Data Mover | File System Backup |
| :--- | :--- | :--- | :--- |
| **Data Source** | CSI VolumeSnapshot | CSI VolumeSnapshot | Live, mounted workload Pod volume |
| **Point-in-Time Consistency** | Yes (crash-consistent) | Yes (crash-consistent) | No |
| **Storage Backend** | Block storage only (EBS, Azure Disk, Ceph RBD, CNS, etc.) | File storage and Block storage (EFS, Azure Files, CephFS, etc.) | Any storage (including local, emptyDir, HostPath, NFS) |
| **CSI Snapshot Required?** | Yes | Yes | No |
| **Supported Volume Modes** | `Block` mode and `FileSystem` mode | `FileSystem` mode only | `FileSystem` mode only |
| **Node OS for Data Mover** | Linux nodes only | Linux and Windows nodes | Linux and Windows nodes |
| **Incremental Mechanism** | CSI Changed Block Tracking (CBT) | File attributes check | File metadata check |
| **Incremental Efficiency for Large Files** | **Very High** (reads and uploads only changed blocks) | **Low** (must scan entire file on change) | **Low** (must scan entire file on change) |
| **Performance with Huge Number of Small Files** | **Very High** (raw sequential block I/O, no filesystem syscall overhead) | **Low** (millions of inode lookups and file system calls) | **Low** (millions of inode lookups and file system calls) |
| **Data Deduplication** | yes (fix sized) | yes (variable sized) | yes (variable sized)|
| **Data Encryption At Rest** | yes | yes | yes |

#### When to Use Each Approach

- **Use Block Data Mover whenever possible if:**
  - The volume is backed by block storage.
  - The storage provider has a CSI driver supporting volume snapshots.
  - The CSI driver supports the Kubernetes CSI Changed Block Tracking (CBT) API (for optimal incremental efficiency), or you have workloads with huge numbers of small files where block-level streaming is vastly superior even without CBT.
  - You are backing up database or transactional workloads with large data files (e.g., PostgreSQL, MySQL, MongoDB, Elasticsearch).
  - You are backing up raw block volumes (`volumeMode: Block`).

- **Use File System Data Mover when:**
  - The volume is backed by file storage systems such as AWS EFS, Azure Files (SMB/NFS), CephFS, or NFS, which do not expose block-level device access.
  - CSI snapshots are supported for the storage.

- **Use File System Backup (`fs-backup`) only when:**
  - CSI volume snapshots are not available (e.g., storage platform lacks a CSI driver or snapshot plugin, or you are backing up local volumes, `emptyDir`, `hostPath`, or non-CSI NFS shares).
  - *Caution*: File System Backup reads directly from the live filesystem while workload pods are writing. File modifications during backup can lead to inconsistent backups. Whenever CSI snapshots are available, CSI Snapshot Data Movement should always be preferred.

#### Why Incremental Backup for File System Data Mover Is Low Efficiency for Large Files

The file system data mover and File System Backup operate at the file and directory abstraction level:
1. **Full File Scanning on Modification**: When a file is modified (detected via attributes such as modification timestamp `mtime` or file size), the file system uploader must **read the entire file from beginning to end**.
2. **Severe Overhead on Large Files**: In workloads like databases or virtual machine disks where single data files can span tens or hundreds of gigabytes (or even terabytes), even a minor change (e.g., writing a few kilobytes to a database transaction log or modifying a few table pages) forces the file system data mover to re-read and hash the entire multi-gigabyte file. This leads to massive disk read I/O, heavy CPU utilization, and prolonged backup windows, even though the actual amount of changed data transferred to the repository is small.

In contrast, the **Block Data Mover** queries the CSI CBT API directly for changed block ranges. It completely skips unchanged regions and reads *only* the specific blocks that were modified directly from the block device using direct I/O, drastically reducing I/O, CPU consumption, and backup time.

#### Benefits of Block Data Mover Even Without CBT

Even in environments where CSI Changed Block Tracking (CBT) is unavailable (e.g., storage platforms that have not yet implemented the CBT API, or when falling back to a full backup), the block data mover provides substantial advantages over the file system data mover:

1. **Elimination of Filesystem Metadata Bottlenecks**:
   - In file systems containing hundreds of thousands or millions of small files (e.g., source code repositories, web asset caches, machine learning datasets), `velero-fs` must execute individual POSIX system calls (`stat`, `lstat`, `opendir`, `readdir`, `open`, `read`, `close`) for every file and directory.
   - This causes massive metadata lookup overhead, inode lock contention, directory cache thrashing, and high memory usage, severely throttling backup throughput.
   - In contrast, Block Data Mover opens the underlying disk as a raw block device using direct I/O. It completely ignores filesystem metadata, directory hierarchies, and inode trees, reading the volume sequentially as a contiguous stream of blocks at raw disk line speeds.

2. **Predictable Throughput Independent of File Count**:
   - With Block Data Mover, backup throughput depends strictly on the physical size of the volume (or allocated blocks), rather than the number, depth, or distribution of files.
   - Backing up a 100 GB volume with 5 million small files takes the same amount of time as backing up a 100 GB volume containing a single large file.

3. **Faster Restoration**:
   - During restore, Block Data Mover writes raw blocks directly to the target block device using direct I/O and leverages the SCSI commands to zero-out unallocated blocks quickly.
   - It avoids the immense overhead of creating millions of individual files, directory paths, and setting permissions/timestamps one by one.

## Setup CSI Snapshot Data Movement

## Prerequisites

 1. The source cluster is Kubernetes version 1.20 or greater.
 2. The source cluster is running a CSI driver capable of supporting volume snapshots at the [v1 API level][4].
 3. CSI Snapshot Data Movement requires the Kubernetes [MountPropagation feature][5].
 4. Specific prerequisites for Block Data Mover:
    - Block storage backend: The volume must be backed by block storage (e.g., AWS EBS, Azure Managed Disk, Ceph RBD, VMware CNS block volumes, etc.). Volumes backed by file storage (NFS, EFS, Azure Files, etc.) cannot use the block data mover.
    - Kubernetes CSI Changed Block Tracking (CBT): For block-level incremental backup and allocated block tracking, the CSI driver and storage platform must support the [Kubernetes CSI Changed Block Tracking (CBT) API][23] (`SnapshotMetadataService`).
    - Linux cluster nodes: Block data mover pods mount raw block devices. In heterogeneous clusters with both Linux and Windows nodes, block data mover pods must run on Linux nodes. (Windows workloads backed by block storage can still be protected and restored from Linux nodes).
    - CBT Service Account (if required): If the CSI SnapshotMetadataService requires authentication via a specific ServiceAccount, configure `csiSnapshotMetadataServiceConfigs` in the `node-agent-config` ConfigMap.


### Install Velero Node Agent

Velero Node Agent is a Kubernetes daemonset that hosts Velero data movement controllers and launches data mover pods. 
If you are using Velero built-in data mover, Node Agent must be installed. To install Node Agent, use the `--use-node-agent` flag.  
Velero built-in data mover doesn't require the host path for pod volumes into Node Agent pods. The installation by default creates it in order to support fs-backup. If you don't use fs-backup and want to remove it from Node Agent, you can specify the `--node-agent-disable-host-path` flag.  

```bash
velero install --use-node-agent --node-agent-disable-host-path
```

#### CSI Snapshot Metadata Service (CBT) Configuration

When using the Velero block data mover (`velero-block`), the data mover pod communicates with the CSI driver's `SnapshotMetadataService` to query allocated or changed blocks. If your CSI driver's CBT service requires authentication with a dedicated Kubernetes service account, you can configure it in the `node-agent-config` ConfigMap under `csiSnapshotMetadataServiceConfigs`:

```json
{
  "csiSnapshotMetadataServiceConfigs": {
    "saName": "<cbt-service-account-name>"
  }
}
```

Specify the ConfigMap during Velero installation:
```bash
velero install --use-node-agent --node-agent-configmap=<ConfigMap-Name> ...
```

When configured, Velero automatically passes `--cbt-sa-name=<cbt-service-account-name>` to the data mover pod. For more details on configuring node-agent, see [Node-agent Configuration][25].

### Configure A Backup Storage Location

At present, Velero backup repository supports object storage as the backup storage. Velero gets the parameters from the 
[BackupStorageLocation][8] to compose the URL to the backup storage.  
Velero's known object storage providers are included here [supported providers][9], for which, Velero pre-defines the endpoints. If you want to use a different backup storage, make sure it is S3 compatible and you provide the correct bucket name and endpoint in BackupStorageLocation. Velero handles the creation of the backup repo prefix in the backup storage, so make sure it is specified in BackupStorageLocation correctly.  

Velero creates one backup repository per namespace. For example, if backing up 2 namespaces, namespace1 and namespace2, using kopia repository on AWS S3, the full backup repo path for namespace1 would be `https://s3-us-west-2.amazonaws.com/bucket/kopia/ns1` and for namespace2 would be `https://s3-us-west-2.amazonaws.com/bucket/kopia/ns2`.  

There may be additional installation steps depending on the cloud provider plugin you are using. You should refer to the [plugin specific documentation][9] for the must up to date information.  

**Note:** Currently, Velero creates a secret named `velero-repo-credentials` in the velero install namespace, containing a default backup repository password.
You can update the secret with your own password encoded as base64 prior to the first backup (i.e., [File System Backup][3], snapshot data movements) targeting to the backup repository. The value of the key to update is  
```
data:
  repository-password: <custom-password>
```
Backup repository is created during the first execution of backup targeting to it after installing Velero with node agent. If you update the secret password after the first backup which created the backup repository, then Velero will not be able to connect with the older backups.  

## Install Velero with CSI support on source cluster

On source cluster, Velero needs to manipulate CSI snapshots through the CSI volume snapshot APIs, so you must enable the `EnableCSI` feature flag on the Velero server.  

To integrate Velero with the CSI volume snapshot APIs, you must enable the `EnableCSI` feature flag.

From release-1.14, the `github.com/velero-io/velero-plugin-for-csi` repository, which is the Velero CSI plugin, is merged into the `github.com/velero-io/velero` repository.
The reasons to merge the CSI plugin are:
* The VolumeSnapshot data mover depends on the CSI plugin, it's reasonabe to integrate them.
* This change reduces the Velero deploying complexity.
* This makes performance tuning easier in the future.

As a result, no need to install Velero CSI plugin anymore.

```bash
velero install \
--features=EnableCSI \
--plugins=<object storage plugin> \
...
```

### Configure storage class on target cluster

For Velero built-in data movement, CSI facilities are not required necessarily in the target cluster. On the other hand, Velero built-in data movement creates a PVC with the same specification as it is in the source cluster and expects the volume to be provisioned similarly. For example, the same storage class should be working in the target cluster.  
By default, Velero won't restore storage class resources from the backup since they are cluster scope resources. However, if you specify the `--include-cluster-resources` restore flag, they will be restored. For a cross provider scenario, the storage class from the source cluster is probably not usable in the target cluster.  
In either of the above cases, the best practice is to create a working storage class in the target cluster with the same name as it in the source cluster. In this way, even though `--include-cluster-resources` is specified, Velero restore will skip restoring the storage class since it finds an existing one.  
Otherwise, if the storage class name in the target cluster is different, you can change the PVC's storage class name during restore by the [changing PV/PVC storage class][10] method. You can also configure to skip restoring the storage class resources from the backup since they are not usable.  

### Priority Class Configuration

For Velero built-in data mover, data mover pods launched during CSI snapshot data movement will use the priority class name configured in the node-agent configmap. The node-agent daemonset itself gets its priority class from the `--node-agent-priority-class-name` flag during Velero installation. This can help ensure proper scheduling behavior in resource-constrained environments. For more details on configuring data mover pod resources, see [Data Movement Pod Resource Configuration][11].

### Customized Data Movers

If you are using a customized data mover, follow the data mover's instructions for any further prerequisites.  
For Velero side configurations mentioned above, the installation and configuration of node-agent may not be required.  


## To back up

Velero uses a custom resource `DataUpload` to drive the data movement. The selected data mover watches and reconciles these CRs.  
Velero allows users to decide whether CSI snapshot data should be moved, which data mover to use, and whether to perform a full or incremental backup.

### Data Mover Selection

The data mover can be chosen per backup using the `--data-mover` flag:
- `velero` (default): Uses the default built-in data mover (currently refers to `velero-fs`).
- `velero-block`: Uses the Velero block data mover.
- `velero-fs`: Uses the Velero file system data mover.
- `<custom-data-mover>`: Uses a customized data mover plugin.

### Backup Type Selection

Velero supports selecting the backup type via the `--backup-type` flag:
- `Incremental` (default):
  - **For `velero-block`**: Velero interacts with the CSI SnapshotMetadataService to retrieve changed blocks since the previous snapshot, and backs up only those changed blocks to the backup repository. Unchanged blocks share the same data with the parent snapshots.
  - **For `velero-fs`**: Velero uploads newly added or modified files based on file attributes.
- `Full`:
  - **For `velero-block`**: Velero queries the CSI SnapshotMetadataService for all allocated blocks in the volume and backs them up. Unallocated regions are treated as zeroes and deduplicated in the backup repository.
  - **For `velero-fs`**: Velero scans and uploads all files in the volume.

### Backup Commands

To take an incremental backup with the Velero block data mover:

```bash
velero backup create NAME --snapshot-move-data --data-mover velero-block OPTIONS...
```

To take a full backup with the Velero block data mover:

```bash
velero backup create NAME --snapshot-move-data --data-mover velero-block --backup-type Full OPTIONS...
```

To take a backup with the Velero file system data mover:

```bash
velero backup create NAME --snapshot-move-data --data-mover velero-fs OPTIONS...
```

Or using a customized data mover:

```bash
velero backup create NAME --snapshot-move-data --data-mover DATA-MOVER-NAME OPTIONS...
```

### Mixing Data Movers via Volume Policy

In many environments, a single backup may protect volumes from different storage backends—such as block storage volumes (e.g., AWS EBS) alongside file storage volumes (e.g., AWS EFS, Azure Files) or storage classes that lack CBT support.

You can mix `velero-block` and `velero-fs` within the same backup by defining a Volume Policy. Under the `snapshot` action in the policy, configure `parameters.dataMover` as `velero-block` or `velero-fs`:

```yaml
volumePolicies:
- conditions:
    storageClass:
    - fast-ebs-sc
  action:
    type: snapshot
    parameters:
      dataMover: velero-block
- conditions:
    storageClass:
    - efs-sc
  action:
    type: snapshot
    parameters:
      dataMover: velero-fs
```

Volumes matched by the volume policy conditions will use the specified data mover, while any other volumes will fall back to the backup's `--data-mover` setting. For more details on configuring volume policies, see [Resource Filtering & Volume Policy][26].

### Fallback to Full Backup

For incremental backups using `velero-block`, Velero will automatically fall back to a full backup of all allocated blocks in the following situations:
- The CSI SnapshotMetadataService returns an error
- The critical information is missing or cannot be retrieved from the parent snapshot.
- The parent snapshot is missing in the backup repository.

When fallback occurs, unallocated regions are still skipped and identical data blocks remain deduplicated by the backup repository. The backup description will clearly indicate that a fallback took place: `Backup Type: Incremental (fallen back to Full)`. In addition, the reason for the fallback is captured in the `status.activities` field of the corresponding `DataUpload` CR.

### Monitoring Backup Progress

When the backup starts, you will see the `VolumeSnapshot` and `VolumeSnapshotContent` objects created, but after the backup finishes, the objects will disappear.  
After snapshots are created, you will see one or more `DataUpload` CRs created.  
You may also see some intermediate objects (i.e., pods, PVCs, PVs) created in the Velero namespace or cluster scope; these assist data movers in transferring data and are automatically deleted after completion.  

The phase of a `DataUpload` CR transitions through several states and eventually reaches a terminal state: `Completed`, `Failed`, or `Cancelled`. While the `DataUpload` is in progress, progress is displayed with `BYTES DONE` (amount of data processed so far) and `TOTAL BYTES` (estimated total volume data). Upon completion, these two numbers will match. In addition, `INCREMENTAL BYTES` indicates the amount of data that is new or changed since the last backup. For `velero-block`, this represents the volume data identified as changed by CBT:

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

By default, `INCREMENTAL BYTES` is not displayed in the `kubectl get` output. Use `-o wide` to view it:

```bash
kubectl -n velero get datauploads -o wide -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

When the backup completes, you can inspect detailed information:

```bash
velero backup describe YOUR_BACKUP_NAME --details
```

In the `--details` output, each volume's `Data Movement` section displays the configured data mover, the backup type, the uploader type, and the transferred/incremental data size:

```
    Data Movement:
        Operation ID: velero-backup-xxxx.pvc-yyyy
        Data Mover: velero-block
        Backup Type: Incremental
        Uploader Type: velero-block
        Moved data Size (bytes): 10737418240
        Incremental data Size (bytes): 104857600
        Result: Completed
```

If an incremental backup fell back to full, it will show:
```
        Backup Type: Incremental (fallen back to Full)
```

You can also view the full `DataUpload` custom resource:

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -o yaml
```

In the `DataUpload` status:
- `status.activities`: Lists operational activity and progress messages encountered during data movement, such as incremental fallback reasons.
- `status.message`: Describes the terminal status if the operation failed or was cancelled.

## To restore

You do not need to specify data mover information when creating a restore. Velero automatically retrieves the configurations (data mover type, backup mode, uploader) from the backup metadata.

To restore from your Velero backup:

```bash
velero restore create --from-backup BACKUP_NAME OPTIONS...
```

When the restore starts, you will see one or more `DataDownload` CRs created.  
You may also see some intermediate objects (i.e., pods, PVCs, PVs) created in Velero namespace or the cluster scope, they are to help data movers to move data. And they will be removed after the restore completes.  
The phase of a `DataDownload` CR changes several times during the restore process and finally goes to one of the terminal status, `Completed`, `Failed` or `Cancelled`. You can see the phase changes as well as the data download progress by watching the DataDownload CRs:  

```bash
kubectl -n velero get datadownloads -l velero.io/restore-name=YOUR_RESTORE_NAME -w
```

When the restore completes, view details about the restore:

```bash
velero restore describe YOUR_RESTORE_NAME --details
```

Sample output in `--details`:
```
    Data Movement:
        Operation ID: velero-restore-xxxx.pvc-yyyy
        Data Mover: velero-block
        Uploader Type: velero-block
        Restore Type: full
        Restored data Size (bytes): 10737418240
```

You can also view the `DataDownload` custom resources directly:

```bash
kubectl -n velero get datadownloads -l velero.io/restore-name=YOUR_RESTORE_NAME -o yaml
```

Similar to `DataUpload`, `status.activities` captures operational activities during data download, while `status.message` describes terminal failure or cancellation details.

## Limitations

- **[Velero Block Data Mover] Linux Node Execution**: Block data mover pods mount raw block devices. Because Windows containers do not support raw block mode volumes, block data mover pods can only run on Linux nodes. However, Windows workloads backed by block storage can still be backed up and restored using the block data mover as long as the data mover pods run on Linux nodes.
- **[Velero File System Data Mover] Filesystem Identity Preservation**: On volumes where the underlying filesystem enforces mount-constant identity (Azure Files SMB/CIFS, Azure Blob via blobfuse, GCP Cloud Storage FUSE, and similar), data download's `chown`/`chmod` can report success while changing nothing, silently losing file ownership (and on FUSE mounts, permission bits). See [File Ownership and Permission Preservation](file-system-backup.md#file-ownership-and-permission-preservation) for details and remediation.
- **[Velero Built-in Data Mover] Static Encryption Key**: At present, Velero uses a static, common encryption key for all backup repositories it creates. **This means that anyone who has access to your backup storage can decrypt your backup data**. Ensure you limit access to the backup storage appropriately.

## Troubleshooting

Run the following checks:

Are your Velero server and daemonset pods running?

```bash
kubectl get pods -n velero
```

Does your backup repository exist, and is it ready?

```bash
velero repo get

velero repo get REPO_NAME -o yaml
```

Are there any errors in your Velero backup/restore?

```bash
velero backup describe BACKUP_NAME --details
velero backup logs BACKUP_NAME

velero restore describe RESTORE_NAME --details
velero restore logs RESTORE_NAME
```

When reviewing backup details, check whether an incremental backup fell back to full:
- Look for `Backup Type: Incremental (fallen back to Full)` under `Data Movement`. This indicates that CBT metadata retrieval was unsuccessful or the parent snapshot was missing.
- Inspect the specific reason for fallback from `status.activities` on the `DataUpload` CR:
  ```bash
  kubectl -n velero get datauploads -l velero.io/backup-name=BACKUP_NAME -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .status.activities}{"  - "}{.}{"\n"}{end}{end}'
  ```

What is the status of your `DataUpload` and `DataDownload`?

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=BACKUP_NAME -o yaml

kubectl -n velero get datadownloads -l velero.io/restore-name=RESTORE_NAME -o yaml
```

Key fields to check in the CR status:
- `status.phase`: Displays the current lifecycle phase (e.g., `Accepted`, `Prepared`, `InProgress`, `Completed`, `Failed`, `Cancelled`).
- `status.activities`: Lists events and progress messages that occurred during data movement (such as fallback details or warnings).
- `status.message`: Details the reason when the CR reaches a terminal failure or cancelled status.

Is there any useful information in the Velero server or data mover pod logs?

```bash
kubectl -n velero logs deploy/velero
kubectl -n velero logs DAEMON_POD_NAME
```

For block data mover:
- Verify that data mover pods are being scheduled on Linux nodes.
- If using CSI CBT, verify that the CSI driver's `SnapshotMetadataService` is healthy and reachable.
- If the CBT service requires authentication, confirm that `csiSnapshotMetadataServiceConfigs.saName` is configured with the correct service account name in the `node-agent-config` ConfigMap.

**NOTE**: You can increase the verbosity of the pod logs by adding `--log-level=debug` as an argument to the container command in the deployment/daemonset pod template spec.  

If you are using a customized data mover, follow the data mover's instruction for additional troubleshooting methods.  


## How backup and restore work

CSI snapshot data movement is a combination of CSI snapshot and data movement, which is jointly executed by Velero server, CSI plugin and the data mover. 
This section lists general concepts of how CSI snapshot data movement backup and restore work. For detailed mechanisms and workflows, refer to the [Volume Snapshot Data Movement design][1], [VGDP Micro Service For Volume Snapshot Data Movement design][18], and the [Block Data Mover design][24].  

### Custom resource and controllers

Velero has three custom resource definitions and associated controllers:

- `DataUpload` - represents a data upload of a volume snapshot. The CSI plugin creates one `DataUpload` per CSI snapshot. Data movers need to handle these CRs to finish the data upload process.  
Velero built-in data mover runs a controller for this resource on each node (in node-agent daemonset). Controllers from different nodes may handle one CR in different phases, but finally the data transfer is done by a data mover pod in one node.  

- `DataDownload` - represents a data download of a volume snapshot.  The CSI plugin creates one `DataDownload` per volume to be restored. Data movers need to handle these CRs to finish the data upload process.  
Velero built-in data mover runs a controller for this resource on each node (in node-agent daemonset). Controllers from different nodes may handle one CR in different phases, but finally the data transfer is done by a data mover pod in one node. 

- `BackupRepository` - represents/manages the lifecycle of Velero's backup repositories. Velero creates a backup repository per namespace when the first CSI snapshot backup/restore for a namespace is requested. You can see information about your Velero's backup repositories by running `velero repo get`.  
This CR is used by Velero built-in data movers, customized data movers may or may not use it.  

For other resources or controllers involved by customized data movers, check the data mover's instructions.  

### Backup

Velero backs up resources for CSI snapshot data movement backup in the same way as other backup types. When it encounters a PVC, specific logic is executed:  

- When it finds a PVC object, Velero invokes the CSI plugin through a Backup Item Action.  
- The CSI plugin creates a CSI snapshot for the PVC by creating the `VolumeSnapshot` and `VolumeSnapshotContent` objects.  
- The CSI plugin checks if data movement is required. If so, it evaluates any configured Volume Policies  and the backup's `backupType`, creates a `DataUpload` CR, and returns to the Velero backup workflow.  
- Velero continues backing up other resources, including additional PVC objects.  
- The Velero backup controller periodically queries the data movement status from the CSI plugin (configurable via `--item-operation-sync-frequency` Velero server parameter, default is 10s). The CSI plugin checks the phase of the `DataUpload` CRs.  
- When all `DataUpload` CRs reach a terminal state (`Completed`, `Failed`, or `Cancelled`), the Velero backup persists all metadata and completes.  
- If a `DataUpload` CR does not reach a terminal state within the configured timeout, it is cancelled (configurable via `--item-operation-timeout`, default is `4 hours`).  

#### Data Mover Execution during Backup

When Velero built-in data mover processes the `DataUpload` CR:
- **For Block Data Mover**:
  - The CSI Snapshot Exposer provisions an intermediate `BackupPVC` in `volumeMode: Block`, regardless of whether the source volume was `volumeMode: FileSystem` or `volumeMode: Block`.
  - The data mover pod queries the CSI driver's `SnapshotMetadataService` via gRPC:
    - For full backups, it retrieves all allocated block extents.
    - For incremental backups, it retrieves only the blocks changed since the parent backup.
  - The block device is opened with direct I/O. An asynchronous reader reads allocated or changed blocks guided by the CBT, while an asynchronous writer uploads the blocks to the Unified Repository.
  - For incremental backups, changed blocks are directly saved to the Unified Repository with deduplication, only metadata is copied from the parent object in the Unified Repository, no extra data is copied or moved.
- **For File System Data Mover**:
  - The CSI Snapshot Exposer provisions the intermediate `BackupPVC` in `volumeMode: FileSystem`.
  - The data mover pod mounts the file system and walks the directory hierarchy, backing up files to the Unified Repository using Kopia uploader with deduplication.

### Restore

Velero restores resources for CSI snapshot data movement restore in the same way as other restore types. When it encounters a PVC, specific logic is executed: 

- When it finds a PVC object, Velero calls the CSI plugin through a Restore Item Action.  
- The CSI plugin checks the backup metadata. If data movement was involved, it creates a `DataDownload` CR populated with the appropriate data mover type and returns to the restore workflow.  
- Velero continues restoring other resources, including other PVC objects.  
- The Velero restore controller periodically (according to `--item-operation-sync-frequency` Velero server parameter, default every 10s) queries the data movement status from the CSI plugin.  
- When all `DataDownload` CRs reach a terminal state (`Completed`, `Failed`, or `Cancelled`), the restore finishes.  

#### Data Mover Execution during Restore

When Velero built-in data mover processes the `DataDownload` CR:
- **For Block Data Mover**:
  - The Generic Restore Exposer provisions an intermediate restore volume in `volumeMode: Block`.
  - The block uploader reads block objects from the Unified Repository and writes them directly to the block device using direct I/O.
  - Zero blocks are unmapped or zeroed out, avoiding unnecessary data write operations.
  - If the target PVC has `volumeMode: FileSystem`, Kubernetes does not allow directly binding a block PV to a filesystem PVC. The exposer creates a FileSystem mode PV, and binds it to the target PVC.
- **For File System Data Mover (`velero-fs`)**:
  - The Generic Restore Exposer provisions the target volume in `volumeMode: FileSystem`.
  - The data mover pod mounts the volume and restores files, directory structures, and file attributes from the Unified Repository.

### Backup Deletion

When a backup is created, a snapshot is saved into the repository for the volume data as a reference to the volume data stored in the repository.  
When deleting a backup, Velero calls the repository to delete the repository snapshot. The repository snapshot disappears immediately after the backup is deleted. The volume data backed up in the repository then becomes orphaned, and the repository relies on maintenance jobs to delete the orphaned data.  
As a result, after you delete a backup, the backup storage size does not reduce until a full repository maintenance job completes successfully. Ensure that periodical repository maintenance jobs run and complete successfully.  

For the **file system data mover**:
- Kopia uploader may keep internal snapshots that are automatically managed during routine backups or purged during repository maintenance.

Even after deleting all backups and their backup data (via repository maintenance), repository metadata remains to preserve the repository instance. If you stop using the backup repository, you can empty the backup storage manually.  

### Parallelism

Velero calls the CSI plugin concurrently for volumes, so `DataUpload`/`DataDownload` CRs are created concurrently.  
How `DataUpload`/`DataDownload` CRs are processed across nodes and within a node depends on the data mover and node-agent configuration:

For Velero built-in data movers, the Kubernetes scheduler mounts the snapshot volume or restore volume associated with a `DataUpload`/`DataDownload` CR to a specific node, where the local `DataUpload`/`DataDownload` controller processes it.  
By default, a controller in one node handles one request at a time. You can configure higher concurrency per node using [node-agent Concurrency Configuration][14]. Snapshot and restore volumes spread across different nodes are processed in parallel, while volumes on the same node are processed concurrently according to your concurrency configuration.  

The preparation process of mounting volumes may create intermediate objects. To control the number of pending intermediate objects, configure the [node-agent Prepare Queue Length][20].  

You can monitor which node is processing each CR and observe progress:

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

```bash
kubectl -n velero get datadownloads -l velero.io/restore-name=YOUR_RESTORE_NAME -w
```

For each individual volume, parallelism operates as follows:  
- **File System Data Mover**: Files within the volume are processed in parallel. You can control concurrency using the `--parallel-files-upload` backup flag or `--parallel-files-download` restore flag. If omitted, Velero defaults to the number of CPU cores in the node hosting the data mover pod.  
- **Block Data Mover**: Block data is processed sequentially with a dedicated reader and writer running asynchronously connected by an internal ring buffer. Sequential I/O provides optimal throughput for block devices. Concurrency across different volumes is handled via node-agent load concurrency.  

Notice that Golang 1.25 and later respects the CPU limit set to the pods to decide the physical threads provisioned to the pod processes (see [Container-aware GOMAXPROCS][22] for more details), so for Velero 1.18 (which consumes Golang 1.25) and later, if you set a CPU limit to the data mover pods, you may not get the expected performance (e.g., backup/restore throughput) with the default parallelism. The outcome may or may not be obvious varying on your volume data. If it is required, you could customize `--parallel-files-upload` or `--parallel-files-download` according to the CPU limit set to the data mover pods.  

### Restart and resume
When Velero server is restarted, if the resource backup/restore has completed, so the backup/restore has excceded `InProgress` status and is waiting for the completion of the data movements, Velero will recapture the status of the running data movements and resume the execution.  
When node-agent is restarted, Velero tries to recapture the status of the running data movements and resume the execution; if the resume fails, the data movements are canceled.  

### Cancellation

At present, Velero backup and restore doesn't support end to end cancellation that is launched by users.  
However, Velero cancels the `DataUpload`/`DataDownload` in below scenarios automatically:
- When Velero server is restarted and the backup/restore is in `InProgress` status
- When node-agent is restarted and the resume of an existing `DataUpload`/`DataDownload` fails  
- When an ongoing backup/restore is deleted
- When a backup/restore does not finish before the item operation timeout (default value is `4 hours`)

Customized data movers that support cancellation could cancel their ongoing tasks and clean up any intermediate resources. If you are using Velero built-in data mover, the cancellation is supported.  

### Support ReadOnlyRootFilesystem setting
When the Velero server pod's SecurityContext sets the `ReadOnlyRootFileSystem` parameter to true, the Velero server pod's filesystem is running in read-only mode. Then the backup deletion may fail, because the repository needs to write some cache and configuration data into the pod's root filesystem.

```
Errors: /error to connect repo with storage: error to connect to repository: unable to write config file: unable to create config directory: mkdir /home/cnb/udmrepo: read-only file system
```

The workaround is making those directories as ephemeral k8s volumes, then those directories are not counted as pod's root filesystem.
The `user-name` is the Velero pod's running user name. The default value is `cnb`.

``` yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: velero
  namespace: velero
spec:
  template:
    spec:
      containers:
      - name: velero
        ......
        volumeMounts:
          ......
          - mountPath: /home/<user-name>/udmrepo
            name: udmrepo
          - mountPath: /home/<user-name>/.cache
            name: cache
          ......
      volumes:
        ......
        - emptyDir: {}
          name: udmrepo
        - emptyDir: {}
          name: cache
        ......
```

At present, Velero doesn't allow setting the `ReadOnlyRootFileSystem` parameter on data mover pods, so the root filesystem for the data mover pods is always writable.  

### Resource Consumption

Both the uploader and repository consume remarkable CPU/memory during the backup/restore, especially for massive small files or large backup size cases.  

For Velero built-in data mover, Velero uses [BestEffort as the QoS][13] for data mover pods (so no CPU/memory request/limit is set), so that backups/restores wouldn't fail due to resource throttling in any cases.  
If you want to constraint the CPU/memory usage, you need to [Customize Data Mover Pod Resource Limits][11]. The CPU/memory consumption is always related to the scale of data to be backed up/restored, refer to [Performance Guidance][12] for more details, so it is highly recommended that you perform your own testing to find the best resource limits for your data.  

During the restore, the repository may also cache data/metadata so as to reduce the network footprint and speed up the restore. The repository uses its own policy to store and clean up the cache.  
For Kopia repository, by default, the cache is stored in the data mover pod's root file system. If your root file system space is limited, the data mover pods may be evicted due to running out of the ephemeral storage, which causes the restore fails. To cope with this problem, Velero allows you:
- configure a limit of the cache size per backup repository, for more details, check [Backup Repository Configuration][17].  
- configure a dedicated volume for cache data, for more details, check [Data Movement Cache Volume][21].  


### Node Selection

The node where a data movement backup/restore runs is decided by the data mover.  

For Velero built-in data movers, the Kubernetes scheduler mounts the snapshot volume or restore volume associated with a `DataUpload`/`DataDownload` CR to a specific node, and the local data mover controller runs the data transfer on that node.  

- **Linux Node Requirement for Block Data Mover**: The block data mover can only run on Linux nodes because Windows containers do not support raw block devices.
- **Backup Node Selection**: You can customize which node(s) should or should not run data movement backup pods using [Data Movement Backup Node Selection][15].
- **Restore Node Selection and Windows Workloads**: For normal restores, node selection cannot be configured directly because data movement restore pods must often run on the same node where the restored workload is scheduled. When restoring Windows workloads using the block data mover, Velero ignores Windows-specific selected nodes and instead determines volume topology from the storage class and PV, ensuring that the restore pod is scheduled on a compatible Linux node that can access the storage volume.

### BackupPVC Configuration

The `BackupPVC` serves as an intermediate Persistent Volume Claim (PVC) utilized during data movement backup operations, providing efficient access to data.
In complex storage environments, optimizing `BackupPVC` configurations can significantly enhance the performance of backup operations. [This document][16] outlines advanced configuration options for `BackupPVC`, allowing users to fine-tune access modes and storage class settings based on their storage provider's capabilities. Note that for the block data mover, the `BackupPVC` is always created with `volumeMode: Block`.

### RestorePVC Configuration

The `RestorePVC` serves as an intermediate Persistent Volume Claim (PVC) utilized during data movement restore operations, providing efficient access to data.  
Sometimes, `RestorePVC` needs to be configured to increase the performance of restore operations. [This document][19] outlines advanced configuration options for `RestorePVC`, allowing users to fine-tune access modes and storage class settings based on their storage provider's capabilities. Note that for the block data mover, the intermediate `RestorePVC` is provisioned with `volumeMode: Block` during data restore and rebound appropriately to match the target PVC.


[1]: https://github.com/velero-io/velero/pull/5968
[2]: csi.md
[3]: file-system-backup.md
[4]: https://kubernetes.io/blog/2020/12/10/kubernetes-1.20-volume-snapshot-moves-to-ga/
[5]: https://kubernetes.io/docs/concepts/storage/volumes/#mount-propagation
[7]: https://docs.microsoft.com/en-us/azure/aks/azure-files-dynamic-pv
[8]: api-types/backupstoragelocation.md
[9]: supported-providers.md
[10]: restore-reference.md#changing-pv/pvc-Storage-Classes
[11]: data-movement-pod-resource-configuration.md
[12]: performance-guidance.md
[13]: https://kubernetes.io/docs/concepts/workloads/pods/pod-qos/
[14]: node-agent-concurrency.md
[15]: data-movement-node-selection.md
[16]: data-movement-backup-pvc-configuration.md
[17]: backup-repository-configuration.md
[18]: https://github.com/velero-io/velero/pull/7576
[19]: data-movement-restore-pvc-configuration.md
[20]: node-agent-prepare-queue-length.md
[21]: data-movement-cache-volume.md
[22]: https://tip.golang.org/doc/go1.25#container-aware-gomaxprocs:~:text=Runtime%C2%B6-,Container%2Daware%20GOMAXPROCS,-%C2%B6
[23]: https://kubernetes.io/blog/2025/09/25/csi-changed-block-tracking/
[24]: https://github.com/velero-io/velero/blob/main/design/block-data-mover/block-data-mover.md
[25]: supported-configmaps/node-agent-configmap.md
[26]: resource-filtering.md


