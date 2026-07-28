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

CSI Snapshot Data Movement supports both built-in data mover and customized data movers. For the details of how Velero works with customized data movers, check the [Volume Snapshot Data Movement design][1]. Velero provides a built-in data mover which uses Velero built-in uploaders (at present the available uploader is Kopia uploader) to read the snapshot data and write to the Unified Repository (by default implemented by Kopia repository).    

Velero built-in data mover restores both volume data and metadata, so the data mover pods need to run as root user.

### Priority Class Configuration

For Velero built-in data mover, data mover pods launched during CSI snapshot data movement will use the priority class name configured in the node-agent configmap. The node-agent daemonset itself gets its priority class from the `--node-agent-priority-class-name` flag during Velero installation. This can help ensure proper scheduling behavior in resource-constrained environments. For more details on configuring data mover pod resources, see [Data Movement Pod Resource Configuration][11].

## Setup CSI Snapshot Data Movement

## Prerequisites

 1. The source cluster is Kubernetes version 1.20 or greater.
 2. The source cluster is running a CSI driver capable of support volume snapshots at the [v1 API level][4].
 3. CSI Snapshot Data Movement requires the Kubernetes [MountPropagation feature][5].


### Install Velero Node Agent

Velero Node Agent is a Kubernetes daemonset that hosts Velero data movement controllers and launches data mover pods. 
If you are using Velero built-in data mover, Node Agent must be installed. To install Node Agent, use the `--use-node-agent` flag.  
Velero built-in data mover doesn't require the host path for pod volumes into Node Agent pods. The installation by default creates it in order to support fs-backup. If you don't use fs-backup and want to remove it from Node Agent, you can specify the `--node-agent-disable-host-path` flag.  

```
velero install --use-node-agent --node-agent-disable-host-path
```

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

### Customized Data Movers

If you are using a customized data mover, follow the data mover's instructions for any further prerequisites.  
For Velero side configurations mentioned above, the installation and configuration of node-agent may not be required.  


## To back up

Velero uses a new custom resource `DataUpload` to drive the data movement. The selected data mover will watch and reconcile the CRs.  
Velero allows users to decide whether the CSI snapshot data should be moved per backup.  
Velero also allows users to select the data mover to move the CSI snapshot data per backup.  
The both selections are simply done by a parameter when running the backup.  

To take a backup with Velero's built-in data mover:

```bash
velero backup create NAME --snapshot-move-data OPTIONS...
```

Or if you want to use a customized data mover:
```bash
velero backup create NAME --snapshot-move-data --data-mover DATA-MOVER-NAME OPTIONS...
```

When the backup starts, you will see the `VolumeSnapshot` and `VolumeSnapshotContent` objects created, but after the backup finishes, the objects will disappear.  
After snapshots are created, you will see one or more `DataUpload` CRs created.  
You may also see some intermediate objects (i.e., pods, PVCs, PVs) created in Velero namespace or the cluster scope, they are to help data movers to move data. And they will be removed after the backup completes.  
The phase of a `DataUpload` CR changes several times during the backup process and finally goes to one of the terminal status, `Completed`, `Failed` or `Cancelled`. You can see the phase changes as well as the data upload progress by watching the `DataUpload` CRs. While the `DataUpload` is being processed, progress is shown with `BYTES DONE` representing the amount of volume data that has been processed so far and `TOTAL BYTES` representing the estimated total volume data. Upon completion, these two numbers will be the same. In addition, once the `DataUpload` is done, `INCREMENTAL BYTES` will be filled in with the amount of data which is new or changed since the last backup of this volume. Note that the actual uploaded content may be smaller than `INCREMENTAL BYTES` due to kopia deduplication, compression, etc.  

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

By default, `INCREMENTAL BYTES` is not displayed in the `kubectl get` output. To see this extended field, the `-o wide` arg is needed:
```bash
kubectl -n velero get datauploads -o wide -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

When the backup completes, you can view information about the backups:

```bash
velero backup describe YOUR_BACKUP_NAME
```
```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -o yaml
```  

## To restore

You don't need to set any additional information when creating a data mover restore. The configurations are automatically retrieved from the backup, i.e., whether data movement should be involved and which data mover conducts the data movement.    

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

When the restore completes, view information about your restores:

```bash
velero restore describe YOUR_RESTORE_NAME
```
```bash
kubectl -n velero get datadownloads -l velero.io/restore-name=YOUR_RESTORE_NAME -o yaml
```

## Limitations

- CSI and CSI snapshot support both file system volume mode and block volume mode. At present, block mode is only supported for non-Windows platforms, because the block mode code invokes some system calls that are not present in the Windows platform.  
- [Velero built-in data mover] At present, Velero uses a static, common encryption key for all backup repositories it creates. **This means 
that anyone who has access to your backup storage can decrypt your backup data**. Make sure that you limit access 
to the backup storage appropriately. 
- [Velero built-in data mover] Even though the backup data could be incrementally preserved, for a single file data, Velero built-in data mover leverages on deduplication to find the difference to be saved. This means that large files (such as ones storing a database) will take a long time to scan for data  deduplication, even if the actual difference is small.  

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
velero backup describe BACKUP_NAME
velero backup logs BACKUP_NAME

velero restore describe RESTORE_NAME
velero restore logs RESTORE_NAME
```

What is the status of your `DataUpload` and `DataDownload`?

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=BACKUP_NAME -o yaml

kubectl -n velero get datadownloads -l velero.io/restore-name=RESTORE_NAME -o yaml
```

Is there any useful information in the Velero server or daemonset pod logs?

```bash
kubectl -n velero logs deploy/velero
kubectl -n velero logs DAEMON_POD_NAME
```

**NOTE**: You can increase the verbosity of the pod logs by adding `--log-level=debug` as an argument to the container command in the deployment/daemonset pod template spec.  

If you are using a customized data mover, follow the data mover's instruction for additional troubleshooting methods.  


## How backup and restore work

CSI snapshot data movement is a combination of CSI snapshot and data movement, which is jointly executed by Velero server, CSI plugin and the data mover. 
This section lists some general concept of how CSI snapshot data movement backup and restore work. For the detailed mechanisms and workflows, you can check the [Volume Snapshot Data Movement design][1] and [VGDP Micro Service For Volume Snapshot Data Movement design][18].  

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

Velero backs up resources for CSI snapshot data movement backup in the same way as other backup types. When it encounters a PVC, particular logics will be conducted:  

- When it finds a PVC object, Velero calls CSI plugin through a Backup Item Action.  
- CSI plugin first takes a CSI snapshot to the PVC by creating the `VolumeSnapshot` and  `VolumeSnapshotContent`.  
- CSI plugin checks if a data movement is required, if so it creates a `DataUpload` CR and then returns to Velero backup.  
- Velero now is able to back up other resources, including other PVC objects.  
- Velero backup controller periodically queries the data movement status from CSI plugin, the period is configurable through the Velero server parameter `--item-operation-sync-frequency`, by default it is 10s. On the call, CSI plugin turns to check the phase of the `DataUpload` CRs.  
- When all the `DataUpload` CRs come to a terminal state (i.e., `Completed`, `Failed` or `Cancelled`), Velero backup persists all the necessary information and finish the backup.  

- CSI plugin expects a data mover to handle the `DataUpload` CR. If no data mover is configured for the backup, Velero built-in data mover will handle it.  
- If the `DataUpload` CR does not reach to the terminal state with in the given time, the `DataUpload` CR will be cancelled. You can set the timeout value per backup through the `--item-operation-timeout` parameter, the default value is `4 hours`.  

- Velero built-in data mover creates a volume from the CSI snapshot and transfer the data to the backup storage according to the backup storage location defined by users.  
- After the volume is created from the CSI snapshot, Velero built-in data mover waits for Kubernetes to provision the volume, this may take some time varying from storage providers, but if the provision cannot be finished in a given time, Velero built-in data mover will cancel this `DataUpload` CR. The timeout is configurable through a node-agent's parameter `data-mover-prepare-timeout`, the default value is 30 minutes.  
- Velero built-in data mover launches a data mover pod to transfer the data from the provisioned volume to the backup storage.  
- When the data transfer completes or any error happens, Velero built-in data mover sets the `DataUpload` CR to the terminal state, either `Completed` or `Failed`.  
- Velero built-in data mover also monitors the cancellation request to the `DataUpload` CR, once that happens, it cancels its ongoing activities, cleans up the intermediate resources and set the `DataUpload` CR to `Cancelled`.  
- Throughout the data transfer, Velero built-in data mover monitors the status of the data mover pod and deletes it after `DataUpload` CR is set to the terminal state.    

### Restore

Velero restores resources for CSI snapshot data movement restore in the same way as other restore types. When it encounters a PVC, particular logics will be conducted: 

- When it finds a PVC object, Velero calls CSI plugin through a Restore Item Action.  
- CSI plugin checks the backup information, if a data movement was involved, it creates a `DataDownload` CR and then returns to Velero restore.  
- Velero is now able to restore other resources, including other PVC objects.  
- Velero restore controller periodically queries the data movement status from CSI plugin, the period is configurable through the Velero server parameter `--item-operation-sync-frequency`, by default it is 10s. On the call, CSI plugin turns to check the phase of the `DataDownload` CRs.  
- When all `DataDownload` CRs come to a terminal state (i.e., `Completed`, `Failed` or `Cancelled`), Velero restore will finish.  

- CSI plugin expects the same data mover for the backup to handle the `DataDownload` CR. If no data mover was configured for the backup, Velero built-in data mover will handle it.  
- If the `DataDownload` CR does not reach to the terminal state with in the given time, the `DataDownload` CR will be cancelled. You can set the timeout value per backup through the same `--item-operation-timeout` parameter.  

- Velero built-in data mover creates a volume with the same specification of the source volume.  
- Velero built-in data mover waits for Kubernetes to provision the volume, this may take some time varying from storage providers, but if the provision cannot be finished in a given time, Velero built-in data mover will cancel this `DataDownload` CR. The timeout is configurable through the same node-agent's parameter `data-mover-prepare-timeout`.  
- After the volume is provisioned, Velero built-in data mover starts a data mover pod to transfer the data from the backup storage according to the backup storage location defined by users.  
- When the data transfer completes or any error happens, Velero built-in data mover sets the `DataDownload` CR to the terminal state, either `Completed` or `Failed`.  
- Velero built-in data mover also monitors the cancellation request to the `DataDownload` CR, once that happens, it cancels its ongoing activities, cleans up the intermediate resources and set the `DataDownload` CR to `Cancelled`.  
- Throughout the data transfer, Velero built-in data mover monitors the status of the data mover pod and deletes it after `DataDownload` CR is set to the terminal state.  

### Backup Deletion
When a backup is created, a snapshot is saved into the repository for the volume data. The snapshot is a reference to the volume data saved in the repository.  
When deleting a backup, Velero calls the repository to delete the repository snapshot. So the repository snapshot disappears immediately after the backup is deleted. Then the volume data backed up in the repository turns to orphan, but it is not deleted by this time. The repository relies on the maintenance functionalitiy to delete the orphan data.  
As a result, after you delete a backup, you don't see the backup storage size reduces until some full maintenance jobs completes successfully. And for the same reason, you should check and make sure that the periodical repository maintenance job runs and completes successfully.  

Even after deleting all the backups and their backup data (by repository maintenance), the backup storage is still not empty, some repository metadata are there to keep the instance of the backup repository.  
Furthermore, Velero never deletes these repository metadata, if you are sure you'll never usage the backup repository, you can empty the backup storage manually.  

For Velero built-in data mover, Kopia uploader may keep some internal snapshots which is not managed by Velero. In normal cases, the internal snapshots are deleted along with running of backups.  
However, if you run a backup which aborts halfway(some internal snapshots are thereby generated) and never run new backups again, some internal snapshots may be left there. In this case, since you stop using the backup repository, you can delete the entire repository metadata from the backup storage manually.  


### Parallelism

Velero calls the CSI plugin concurrently for the volume, so `DataUpload`/`DataDownload` CRs are created concurrently by the CSI plugin. For more details about the call between Velero and CSI plugin, check the [Volume Snapshot Data Movement design][1].  
In which manner the `DataUpload`/`DataDownload` CRs are processed is totally decided by the data mover you select for the backup/restore.  

For Velero built-in data mover, it uses Kubernetes' scheduler to mount a snapshot volume/restore volume associated to a `DataUpload`/`DataDownload` CR into a specific node, and then the `DataUpload`/`DataDownload` controller (in node-agent daemonset) in that node will handle the `DataUpload`/`DataDownload`.  
By default, a `DataUpload`/`DataDownload` controller in one node handles one request at a time. You can configure more parallelism per node by [node-agent Concurrency Configuration][14].  
That is to say, the snapshot volumes/restore volumes may spread in different nodes, then their associated `DataUpload`/`DataDownload` CRs will be processed in parallel; while for the snapshot volumes/restore volumes in the same node, by default, their associated `DataUpload`/`DataDownload` CRs are processed sequentially and can be processed concurrently according to your [node-agent Concurrency Configuration][14].  

The prepare process of mounting the snapshot volume/restore volume may generate multiple intermediate objects, to make a control of the intermediate objects, you can configure the [node-agent Prepare Queue Length][20].  

You can check in which node the `DataUpload`/`DataDownload` CRs are processed and their parallelism by watching the `DataUpload`/`DataDownload` CRs:

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

```bash
kubectl -n velero get datadownloads -l velero.io/restore-name=YOUR_RESTORE_NAME -w
```

For each volume, the parallelism is like below:  
- If it is a file system mode volume, files in the volume are processed in parallel. You can use `--parallel-files-upload` backup flag or `--parallel-files-download` restore flag to control how many files are processed in parallel. Otherwise, if they are not set, Velero by default refers to the number of CPU cores in the node (where the backup/restore is running) for the parallelism. That is to say, the parallelism is not affected by the CPU request/limit set to the data mover pods.  
- If it is a block mode volume, there is no parallelism, the block data is processed sequentially.  

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

At present, Velero doesn't allow to set `ReadOnlyRootFileSystem` parameter to data mover pods, so the root filesystem for the data mover pods are always writable.  

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

For Velero built-in data mover, it uses Kubernetes' scheduler to mount a snapshot volume/restore volume associated to a `DataUpload`/`DataDownload` CR into a specific node, and then the data movement backup/restore will happen in that node.  
For the backup, you can intervene this scheduling process through [Data Movement Backup Node Selection][15], so that you can decide which node(s) should/should not run the data movement backup for various purposes.  
For the restore, this is not supported because sometimes the data movement restore must run in the same node where the restored workload pod is scheduled.  

### BackupPVC Configuration

The `BackupPVC` serves as an intermediate Persistent Volume Claim (PVC) utilized during data movement backup operations, providing efficient access to data.
In complex storage environments, optimizing `BackupPVC` configurations can significantly enhance the performance of backup operations. [This document][16] outlines advanced configuration options for `BackupPVC`, allowing users to fine-tune access modes and storage class settings based on their storage provider's capabilities.  

### RestorePVC Configuration

The `RestorePVC` serves as an intermediate Persistent Volume Claim (PVC) utilized during data movement restore operations, providing efficient access to data.  
Sometimes, `RestorePVC` needs to be configured to increase the performance of restore operations. [This document][19] outlines advanced configuration options for `RestorePVC`, allowing users to fine-tune access modes and storage class settings based on their storage provider's capabilities.  


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


