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

The way for Velero built-in data mover to access the snapshot data is based on the hostpath access by Velero node-agent, so the node-agent pods need to run as root user and even under privileged mode in some environments, as same as [File System Backup][3].  

## Setup CSI Snapshot Data Movement

## Prerequisites

 1. The source cluster is Kubernetes version 1.20 or greater.
 2. The source cluster is running a CSI driver capable of support volume snapshots at the [v1 API level][4].
 3. CSI Snapshot Data Movement requires the Kubernetes [MountPropagation feature][5].


### Install Velero Node Agent

Velero Node Agent is a Kubernetes daemonset that hosts Velero data movement modules, i.e., data mover controller, uploader & repository. 
If you are using Velero built-in data mover, Node Agent must be installed. To install Node Agent, use the `--use-node-agent` flag. 

```
velero install --use-node-agent
```

### Configure Node Agent DaemonSet spec

After installation, some PaaS/CaaS platforms based on Kubernetes also require modifications the node-agent DaemonSet spec. 
The steps in this section are only needed if you are installing on RancherOS, Nutanix, OpenShift, VMware Tanzu Kubernetes Grid 
Integrated Edition (formerly VMware Enterprise PKS), or Microsoft Azure.  


**RancherOS**


Update the host path for volumes in the node-agent DaemonSet in the Velero namespace from `/var/lib/kubelet/pods` to 
`/opt/rke/var/lib/kubelet/pods`.  

```yaml
hostPath:
  path: /var/lib/kubelet/pods
```

to

```yaml
hostPath:
  path: /opt/rke/var/lib/kubelet/pods
```
**Nutanix**

Update the host path for volumes in the node-agent DaemonSet in the Velero namespace from `/var/lib/kubelet/pods` to
`/var/nutanix/var/lib/kubelet`.

```yaml
hostPath:
  path: /var/lib/kubelet/pods
```

to

```yaml
hostPath:
  path: /var/nutanix/var/lib/kubelet
```

**OpenShift**


To mount the correct hostpath to pods volumes, run the node-agent pod in `privileged` mode.

1. Add the `velero` ServiceAccount to the `privileged` SCC:

    ```
    oc adm policy add-scc-to-user privileged -z velero -n velero
    ```

2. Modify the DaemonSet yaml to request a privileged mode:

    ```diff
    @@ -67,3 +67,5 @@ spec:
                  value: /credentials/cloud
                - name: VELERO_SCRATCH_DIR
                  value: /scratch
    +          securityContext:
    +            privileged: true
    ```

    or

    ```shell
    oc patch ds/node-agent \
      --namespace velero \
      --type json \
      -p '[{"op":"add","path":"/spec/template/spec/containers/0/securityContext","value": { "privileged": true}}]'
    ```

If node-agent is not running in a privileged mode, it will not be able to access snapshot volumes within the mounted 
hostpath directory because of the default enforced SELinux mode configured in the host system level. You can 
[create a custom SCC][6] to relax the 
security in your cluster so that node-agent pods are allowed to use the hostPath volume plugin without granting 
them access to the `privileged` SCC.  

By default a userland openshift namespace will not schedule pods on all nodes in the cluster.  

To schedule on all nodes the namespace needs an annotation:  

```
oc annotate namespace <velero namespace> openshift.io/node-selector=""
```

This should be done before velero installation.  

Or the ds needs to be deleted and recreated:  

```
oc get ds node-agent -o yaml -n <velero namespace> > ds.yaml
oc annotate namespace <velero namespace> openshift.io/node-selector=""
oc create -n <velero namespace> -f ds.yaml
```

**VMware Tanzu Kubernetes Grid Integrated Edition (formerly VMware Enterprise PKS)**  

You need to enable the `Allow Privileged` option in your plan configuration so that Velero is able to mount the hostpath.  

The hostPath should be changed from `/var/lib/kubelet/pods` to `/var/vcap/data/kubelet/pods`

```yaml
hostPath:
  path: /var/vcap/data/kubelet/pods
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

On source cluster, Velero needs to manipulate CSI snapshots through the CSI volume snapshot APIs, so you must enable the `EnableCSI` feature flag and install the Velero [CSI plugin][2] on the Velero server.  

Both of these can be added with the `velero install` command.

```bash
velero install \
--features=EnableCSI \
--plugins=<object storage plugin>,velero/velero-plugin-for-csi:v0.6.0 \
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
The phase of a `DataUpload` CR changes several times during the backup process and finally goes to one of the terminal status, `Completed`, `Failed` or `Cancelled`. You can see the phase changes as well as the data upload progress by watching the `DataUpload` CRs:  

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -w
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

- CSI and CSI snapshot support both file system volume mode and block volume mode. At present, Velero built-in data mover doesn't support 
block mode volume or volume snapshot. 
- [Velero built-in data mover] At present, Velero uses a static, common encryption key for all backup repositories it creates. **This means 
that anyone who has access to your backup storage can decrypt your backup data**. Make sure that you limit access 
to the backup storage appropriately. 
- [Velero built-in data mover] Even though the backup data could be incrementally preserved, for a single file data, Velero built-in data mover leverages on deduplication to find the difference to be saved. This means that large files (such as ones storing a database) will take a long time to scan for data  deduplication, even if the actual difference is small.
- [Velero built-in data mover] You may need to [customize the resource limits][11] to make sure backups complete successfully for massive small files or large backup size cases, for more details refer to [Velero file system level backup performance guide][12]. 
- The block mode is supported by the Kopia uploader, but it only supports non-Windows platforms, because the block mode code invokes some system calls that are not present in the Windows platform.

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
This section lists some general concept of how CSI snapshot data movement backup and restore work. For the detailed mechanisms and workflows, you can check the [Volume Snapshot Data Movement design][1].  

### Custom resource and controllers

Velero has three custom resource definitions and associated controllers:

- `DataUpload` - represents a data upload of a volume snapshot. The CSI plugin creates one `DataUpload` per CSI snapshot. Data movers need to handle these CRs to finish the data upload process.  
Velero built-in data mover runs a controller for this resource on each node (in node-agent daemonset). Controllers from different nodes may handle one CR in different phases, but finally the data transfer is done by one single controller which will call uploaders from the backend.  

- `DataDownload` - represents a data download of a volume snapshot.  The CSI plugin creates one `DataDownload` per volume to be restored. Data movers need to handle these CRs to finish the data upload process.  
Velero built-in data mover runs a controller for this resource on each node (in node-agent daemonset). Controllers from different nodes may handle one CR in different phases, but finally the data transfer is done by one single controller which will call uploaders from the backend. 

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
- When the data transfer completes or any error happens, Velero built-in data mover sets the `DataUpload` CR to the terminal state, either `Completed` or `Failed`.  
- Velero built-in data mover also monitors the cancellation request to the `DataUpload` CR, once that happens, it cancels its ongoing activities, cleans up the intermediate resources and set the `DataUpload` CR to `Cancelled`.  

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
- After the volume is provisioned, Velero built-in data mover starts to transfer the data from the backup storage according to the backup storage location defined by users.  
- When the data transfer completes or any error happens, Velero built-in data mover sets the `DataDownload` CR to the terminal state, either `Completed` or `Failed`.  
- Velero built-in data mover also monitors the cancellation request to the `DataDownload` CR, once that happens, it cancels its ongoing activities, cleans up the intermediate resources and set the `DataDownload` CR to `Cancelled`.  


### Parallelism

Velero calls the CSI plugin concurrently for the volume, so `DataUpload`/`DataDownload` CRs are created concurrently by the CSI plugin. For more details about the call between Velero and CSI plugin, check the [Volume Snapshot Data Movement design][1].  
In which manner the `DataUpload`/`DataDownload` CRs are processed is totally decided by the data mover you select for the backup/restore.  

For Velero built-in data mover, it uses Kubernetes' scheduler to mount a snapshot volume/restore volume associated to a `DataUpload`/`DataDownload` CR into a specific node, and then the `DataUpload`/`DataDownload` controller (in node-agent daemonset) in that node will handle the `DataUpload`/`DataDownload`.  
At present, a `DataUpload`/`DataDownload` controller in one node handles one request at a time.  
That is to say, the snapshot volumes/restore volumes may spread in different nodes, then their associated `DataUpload`/`DataDownload` CRs will be processed in parallel; while for the snapshot volumes/restore volumes in the same node, their associated `DataUpload`/`DataDownload` CRs are processed sequentially.  

You can check in which node the `DataUpload`/`DataDownload` CRs are processed and their parallelism by watching the `DataUpload`/`DataDownload` CRs:

```bash
kubectl -n velero get datauploads -l velero.io/backup-name=YOUR_BACKUP_NAME -w
```

```bash
kubectl -n velero get datadownloads -l velero.io/restore-name=YOUR_RESTORE_NAME -w
```

### Cancellation

At present, Velero backup and restore doesn't support end to end cancellation that is launched by users.  
However, Velero cancels the `DataUpload`/`DataDownload` in below scenarios automatically:
- When Velero server is restarted
- When node-agent is restarted  
- When an ongoing backup/restore is deleted
- When a backup/restore does not finish before the item operation timeout (default value is `4 hours`)

Customized data movers that support cancellation could cancel their ongoing tasks and clean up any intermediate resources. If you are using Velero built-in data mover, the cancellation is supported.  


[1]: https://github.com/velero-io/velero/pull/5968
[2]: csi.md
[3]: file-system-backup.md
[4]: https://kubernetes.io/blog/2020/12/10/kubernetes-1.20-volume-snapshot-moves-to-ga/
[5]: https://kubernetes.io/docs/concepts/storage/volumes/#mount-propagation
[6]: https://docs.openshift.com/container-platform/3.11/admin_guide/manage_scc.html
[7]: https://docs.microsoft.com/en-us/azure/aks/azure-files-dynamic-pv
[8]: api-types/backupstoragelocation.md
[9]: supported-providers.md
[10]: restore-reference.md#changing-pv/pvc-Storage-Classes
[11]: customize-installation.md#customize-resource-requests-and-limits
[12]: performance-guidance.md
