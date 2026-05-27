---
title: "File System Backup"
layout: docs
---

Velero supports backing up and restoring Kubernetes volumes attached to pods from the file system of the volumes, called 
File System Backup (FSB shortly) or Pod Volume Backup. The data movement is fulfilled by using modules from free open-source 
backup tools [restic][1] and [kopia][2]. This support is considered beta quality. Please see the list of [limitations](#limitations) 
to understand if it fits your use case.  

Velero allows you to take snapshots of persistent volumes as part of your backups if you’re using one of
the supported cloud providers’ block storage offerings (Amazon EBS Volumes, Azure Managed Disks, Google Persistent Disks).
It also provides a plugin model that enables anyone to implement additional object and block storage backends, outside the
main Velero repository.  

Velero's File System Backup is an addition to the aforementioned snapshot approaches. Its pros and cons are listed below:  
Pros:  
- It is capable of backing up and restoring almost any type of Kubernetes volume. Therefore, if you need a volume snapshot 
plugin for your storage platform, or if you're using EFS, AzureFile, NFS, emptyDir, local, or any other volume type that doesn't 
have a native snapshot concept, FSB might be for you.  
- It is not tied to a specific storage platform, so you could save the backup data to a different storage platform from 
the one backing Kubernetes volumes, for example, a durable storage.

Cons:
- It backs up data from the live file system, so the backup data is less consistent than the snapshot approaches.
- It access the file system from the mounted hostpath directory, so the pods need to run as root user and even under 
privileged mode in some environments.  

**NOTE:** hostPath volumes are not supported, but the [local volume type][5] is supported.  

## Setup File System Backup

### Prerequisites

- Understand how Velero performs [file system backup](#how-backup-and-restore-work).
- [Download][4] the latest Velero release.
- Kubernetes v1.16.0 or later are required. Velero's File System Backup requires the Kubernetes [MountPropagation feature][6].

### Install Velero Node Agent

Velero Node Agent is a Kubernetes daemonset that hosts FSB modules, i.e., restic, kopia uploader & repository.  
To install Node Agent, use the `--use-node-agent` flag in the `velero install` command. See the [install overview][3] for more 
details on other flags for the install command.  

```
velero install --use-node-agent
```

When using FSB on a storage that doesn't have Velero support for snapshots, the `--use-volume-snapshots=false` flag prevents an 
unused `VolumeSnapshotLocation` from being created on installation.  

At present, Velero FSB supports object storage as the backup storage only. Velero gets the parameters from the 
[BackupStorageLocation `config`](api-types/backupstoragelocation.md) to compose the URL to the backup storage. Velero's known object 
storage providers are include here [supported providers](supported-providers.md), for which, Velero pre-defines the endpoints; if you 
want to use a different backup storage, make sure it is S3 compatible and you provide the correct bucket name and endpoint in 
BackupStorageLocation. Alternatively, for Restic, you could set the `resticRepoPrefix` value in BackupStorageLocation. For example, 
on AWS, `resticRepoPrefix` is something like `s3:s3-us-west-2.amazonaws.com/bucket` (note that `resticRepoPrefix` doesn't work for Kopia). 
Velero handles the creation of the backup repo prefix in the backup storage, so make sure it is specified in BackupStorageLocation correctly.  

Velero creates one backup repo per namespace. For example, if backing up 2 namespaces, namespace1 and namespace2, using kopia 
repository on AWS S3, the full backup repo path for namespace1 would be `https://s3-us-west-2.amazonaws.com/bucket/kopia/ns1` and 
for namespace2 would be `https://s3-us-west-2.amazonaws.com/bucket/kopia/ns2`.  

There may be additional installation steps depending on the cloud provider plugin you are using. You should refer to the 
[plugin specific documentation](supported-providers.md) for the must up to date information.  

### Configure Node Agent DaemonSet spec

After installation, some PaaS/CaaS platforms based on Kubernetes also require modifications the node-agent DaemonSet spec. 
The steps in this section are only needed if you are installing on RancherOS, OpenShift, VMware Tanzu Kubernetes Grid 
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


**OpenShift**


To mount the correct hostpath to pods volumes, run the node-agent pod in `privileged` mode.

1. Add the `velero` ServiceAccount to the `privileged` SCC:

    ```
    $ oc adm policy add-scc-to-user privileged -z velero -n velero
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


If node-agent is not running in a privileged mode, it will not be able to access pods volumes within the mounted 
hostpath directory because of the default enforced SELinux mode configured in the host system level. You can 
[create a custom SCC](https://docs.openshift.com/container-platform/3.11/admin_guide/manage_scc.html) to relax the 
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


**Microsoft Azure**

If you are using [Azure Files][8], you need to add `nouser_xattr` to your storage class's `mountOptions`. 
See [this restic issue][9] for more details.  

You can use the following command to patch the storage class:

```bash
kubectl patch storageclass/<YOUR_AZURE_FILE_STORAGE_CLASS_NAME> \
  --type json \
  --patch '[{"op":"add","path":"/mountOptions/-","value":"nouser_xattr"}]'
```

## To back up

Velero supports two approaches of discovering pod volumes that need to be backed up using FSB:  

- Opt-in approach: Where every pod containing a volume to be backed up using FSB must be annotated 
with the volume's name.
- Opt-out approach: Where all pod volumes are backed up using FSB, with the ability to opt-out any 
volumes that should not be backed up.

The following sections provide more details on the two approaches.  

### Using the opt-out approach

In this approach, Velero will back up all pod volumes using FSB with the exception of:  

- Volumes mounting the default service account token, Kubernetes Secrets, and ConfigMaps
- Hostpath volumes

It is possible to exclude volumes from being backed up using the `backup.velero.io/backup-volumes-excludes` 
annotation on the pod.  

Instructions to back up using this approach are as follows:  

1. Run the following command on each pod that contains volumes that should **not** be backed up using FSB

    ```bash
    kubectl -n YOUR_POD_NAMESPACE annotate pod/YOUR_POD_NAME backup.velero.io/backup-volumes-excludes=YOUR_VOLUME_NAME_1,YOUR_VOLUME_NAME_2,...
    ```
    where the volume names are the names of the volumes in the pod spec.

    For example, in the following pod:

    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: app1
      namespace: sample
    spec:
      containers:
      - image: k8s.gcr.io/test-webserver
        name: test-webserver
        volumeMounts:
        - name: pvc1-vm
          mountPath: /volume-1
        - name: pvc2-vm
          mountPath: /volume-2
      volumes:
      - name: pvc1-vm
        persistentVolumeClaim:
          claimName: pvc1
      - name: pvc2-vm
          claimName: pvc2
    ```
    to exclude FSB of volume `pvc1-vm`, you would run:

    ```bash
    kubectl -n sample annotate pod/app1 backup.velero.io/backup-volumes-excludes=pvc1-vm
    ```

2. Take a Velero backup:

    ```bash
    velero backup create BACKUP_NAME --default-volumes-to-fs-backup OTHER_OPTIONS
    ```

    The above steps uses the opt-out approach on a per backup basis.

    Alternatively, this behavior may be enabled on all velero backups running the `velero install` command with 
    the `--default-volumes-to-fs-backup` flag. Refer [install overview][10] for details.  

3. When the backup completes, view information about the backups:

    ```bash
    velero backup describe YOUR_BACKUP_NAME
    ```
    ```bash
    kubectl -n velero get podvolumebackups -l velero.io/backup-name=YOUR_BACKUP_NAME -o yaml
    ```

### Using opt-in pod volume backup

Velero, by default, uses this approach to discover pod volumes that need to be backed up using FSB. Every pod 
containing a volume to be backed up using FSB must be annotated with the volume's name using the 
`backup.velero.io/backup-volumes` annotation.  

Instructions to back up using this approach are as follows:

1. Run the following for each pod that contains a volume to back up:

    ```bash
    kubectl -n YOUR_POD_NAMESPACE annotate pod/YOUR_POD_NAME backup.velero.io/backup-volumes=YOUR_VOLUME_NAME_1,YOUR_VOLUME_NAME_2,...
    ```

    where the volume names are the names of the volumes in the pod spec.

    For example, for the following pod:

    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: sample
      namespace: foo
    spec:
      containers:
      - image: k8s.gcr.io/test-webserver
        name: test-webserver
        volumeMounts:
        - name: pvc-volume
          mountPath: /volume-1
        - name: emptydir-volume
          mountPath: /volume-2
      volumes:
      - name: pvc-volume
        persistentVolumeClaim:
          claimName: test-volume-claim
      - name: emptydir-volume
        emptyDir: {}
    ```

    You'd run:

    ```bash
    kubectl -n foo annotate pod/sample backup.velero.io/backup-volumes=pvc-volume,emptydir-volume
    ```

    This annotation can also be provided in a pod template spec if you use a controller to manage your pods.  

1. Take a Velero backup:

    ```bash
    velero backup create NAME OPTIONS...
    ```

1. When the backup completes, view information about the backups:

    ```bash
    velero backup describe YOUR_BACKUP_NAME
    ```
    ```bash
    kubectl -n velero get podvolumebackups -l velero.io/backup-name=YOUR_BACKUP_NAME -o yaml
    ```

## To restore

Regardless of how volumes are discovered for backup using FSB, the process of restoring remains the same.  

1. Restore from your Velero backup:

    ```bash
    velero restore create --from-backup BACKUP_NAME OPTIONS...
    ```

1. When the restore completes, view information about your pod volume restores:

    ```bash
    velero restore describe YOUR_RESTORE_NAME
    ```
    ```bash
    kubectl -n velero get podvolumerestores -l velero.io/restore-name=YOUR_RESTORE_NAME -o yaml
    ```

## Limitations

- `hostPath` volumes are not supported. [Local persistent volumes][5] are supported.
- At present, Velero uses a static, common encryption key for all backup repositories it creates. **This means 
that anyone who has access to your backup storage can decrypt your backup data**. Make sure that you limit access 
to the backup storage appropriately.
- An incremental backup chain will be maintained across pod reschedules for PVCs. However, for pod volumes that 
are *not* PVCs, such as `emptyDir` volumes, when a pod is deleted/recreated (for example, by a ReplicaSet/Deployment), 
the next backup of those volumes will be full rather than incremental, because the pod volume's lifecycle is assumed 
to be defined by its pod.
- Even though the backup data could be incrementally preserved, for a single file data, FSB leverages on deduplication 
to find the difference to be saved. This means that large files (such as ones storing a database) will take a long time 
to scan for data deduplication, even if the actual difference is small.
- You may need to [customize the resource limits](customize-installation/#customize-resource-requests-and-limits) 
to make sure backups complete successfully for massive small files or large backup size cases, for more details refer to 
[Velero File System Backup Performance Guide](/docs/main/performance-guidance).
- Velero's File System Backup reads/writes data from volumes by accessing the node's filesystem, on which the pod is running. 
For this reason, FSB can only backup volumes that are mounted by a pod and not directly from the PVC. For orphan PVC/PV pairs 
(without running pods), some Velero users overcame this limitation running a staging pod (i.e. a busybox or alpine container 
with an infinite sleep) to mount these PVC/PV pairs prior taking a Velero backup.  

## Customize Restore Helper Container

Velero uses a helper init container when performing a FSB restore. By default, the image for this container is 
`velero/velero-restore-helper:<VERSION>`, where `VERSION` matches the version/tag of the main Velero image. 
You can customize the image that is used for this helper by creating a ConfigMap in the Velero namespace with the alternate image.  

In addition, you can customize the resource requirements for the init container, should you need.  

The ConfigMap must look like the following:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  # any name can be used; Velero uses the labels (below)
  # to identify it rather than the name
  name: fs-restore-action-config
  # must be in the velero namespace
  namespace: velero
  # the below labels should be used verbatim in your
  # ConfigMap.
  labels:
    # this value-less label identifies the ConfigMap as
    # config for a plugin (i.e. the built-in restore
    # item action plugin)
    velero.io/plugin-config: ""
    # this label identifies the name and kind of plugin
    # that this ConfigMap is for.
    velero.io/pod-volume-restore: RestoreItemAction
data:
  # The value for "image" can either include a tag or not;
  # if the tag is *not* included, the tag from the main Velero
  # image will automatically be used.
  image: myregistry.io/my-custom-helper-image[:OPTIONAL_TAG]

  # "cpuRequest" sets the request.cpu value on the restore init containers during restore.
  # If not set, it will default to "100m". A value of "0" is treated as unbounded.
  cpuRequest: 200m

  # "memRequest" sets the request.memory value on the restore init containers during restore.
  # If not set, it will default to "128Mi". A value of "0" is treated as unbounded.
  memRequest: 128Mi

  # "cpuLimit" sets the request.cpu value on the restore init containers during restore.
  # If not set, it will default to "100m". A value of "0" is treated as unbounded.
  cpuLimit: 200m

  # "memLimit" sets the request.memory value on the restore init containers during restore.
  # If not set, it will default to "128Mi". A value of "0" is treated as unbounded.
  memLimit: 128Mi

  # "secCtxRunAsUser" sets the securityContext.runAsUser value on the restore init containers during restore.
  secCtxRunAsUser: 1001

  # "secCtxRunAsGroup" sets the securityContext.runAsGroup value on the restore init containers during restore.
  secCtxRunAsGroup: 999

  # "secCtxAllowPrivilegeEscalation" sets the securityContext.allowPrivilegeEscalation value on the restore init containers during restore.
  secCtxAllowPrivilegeEscalation: false

  # "secCtx" sets the securityContext object value on the restore init containers during restore.
  # This key override  `secCtxRunAsUser`, `secCtxRunAsGroup`, `secCtxAllowPrivilegeEscalation` if `secCtx.runAsUser`, `secCtx.runAsGroup` or `secCtx.allowPrivilegeEscalation` are set.
  secCtx: |
    capabilities:
      drop:
      - ALL
      add: []
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsUser: 1001
    runAsGroup: 999

```

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

What is the status of your pod volume backups/restores?

```bash
kubectl -n velero get podvolumebackups -l velero.io/backup-name=BACKUP_NAME -o yaml

kubectl -n velero get podvolumerestores -l velero.io/restore-name=RESTORE_NAME -o yaml
```

Is there any useful information in the Velero server or daemon pod logs?

```bash
kubectl -n velero logs deploy/velero
kubectl -n velero logs DAEMON_POD_NAME
```

**NOTE**: You can increase the verbosity of the pod logs by adding `--log-level=debug` as an argument
to the container command in the deployment/daemonset pod template spec.

## How backup and restore work

### How Velero integrates with Restic
Velero integrate Restic binary directly, so the operations are done by calling Restic commands:
- Run `restic init` command to initialize the [restic repository](https://restic.readthedocs.io/en/latest/100_references.html#terminology)
- Run `restic prune` command periodically to prune restic repository
- Run `restic backup` commands to backup pod volume data
- Run `restic restore` commands to restore pod volume data

### How Velero integrates with Kopia
Velero integrate Kopia modules into Velero's code, primarily two modules:
- Kopia Uploader: Velero makes some wrap and isolation around it to create a generic file system uploader, 
which is used to backup pod volume data
- Kopia Repository: Velero integrates it with Velero's Unified Repository Interface, it is used to preserve the backup data and manage 
the backup storage  

For more details, refer to [kopia architecture](https://kopia.io/docs/advanced/architecture/) and 
Velero's [Unified Repository design](https://github.com/velero-io/velero/pull/4926)

### Custom resource and controllers
Velero has three custom resource definitions and associated controllers:

- `BackupRepository` - represents/manages the lifecycle of Velero's backup repositories. Velero creates 
a backup repository per namespace when the first FSB backup/restore for a namespace is requested. The backup 
repository is backed by restic or kopia, the `BackupRepository` controller invokes restic or kopia internally, 
refer to [restic integration](#how-velero-integrates-with-restic) and [kopia integration](#how-velero-integrates-with-kopia) 
for details.

    You can see information about your Velero's backup repositories by running `velero repo get`.

- `PodVolumeBackup` - represents a FSB backup of a volume in a pod. The main Velero backup process creates
one or more of these when it finds an annotated pod. Each node in the cluster runs a controller for this
resource (in a daemonset) that handles the `PodVolumeBackups` for pods on that node. `PodVolumeBackup` is backed by 
restic or kopia, the controller invokes restic or kopia internally, refer to [restic integration](#how-velero-integrates-with-restic) 
and [kopia integration](#how-velero-integrates-with-kopia) for details.

- `PodVolumeRestore` - represents a FSB restore of a pod volume. The main Velero restore process creates one
or more of these when it encounters a pod that has associated FSB backups. Each node in the cluster runs a
controller for this resource (in the same daemonset as above) that handles the `PodVolumeRestores` for pods
on that node. `PodVolumeRestore` is backed by restic or kopia, the controller invokes restic or kopia internally, 
refer to [restic integration](#how-velero-integrates-with-restic) and [kopia integration](#how-velero-integrates-with-kopia) for details.  

### Path selection
Velero's FSB supports two data movement paths, the restic path and the kopia path. Velero allows users to select 
between the two paths:
- For backup, the path is specified at the installation time through the `uploader-type` flag, the valid value is 
either `restic` or `kopia`, or default to `restic` if the value is not specified. The selection is not allowed to be 
changed after the installation.
- For restore, the path is decided by the path used to back up the data, it is automatically selected. For example, 
if you've created a backup with restic path, then you reinstall Velero with `uploader-type=kopia`, when you create 
a restore from the backup, the restore still goes with restic path.

### Backup

1. Based on configuration, the main Velero backup process uses the opt-in or opt-out approach to check each pod 
that it's backing up for the volumes to be backed up using FSB.  
2. When found, Velero first ensures a backup repository exists for the pod's namespace, by:
    - checking if a `BackupRepository` custom resource already exists
    - if not, creating a new one, and waiting for the `BackupRepository` controller to init/connect it
3. Velero then creates a `PodVolumeBackup` custom resource per volume listed in the pod annotation  
4. The main Velero process now waits for the `PodVolumeBackup` resources to complete or fail  
5. Meanwhile, each `PodVolumeBackup` is handled by the controller on the appropriate node, which:
    - has a hostPath volume mount of `/var/lib/kubelet/pods` to access the pod volume data
    - finds the pod volume's subdirectory within the above volume
    - based on the path selection, Velero invokes restic or kopia for backup
    - updates the status of the custom resource to `Completed` or `Failed`
6. As each `PodVolumeBackup` finishes, the main Velero process adds it to the Velero backup in a file named 
`<backup-name>-podvolumebackups.json.gz`. This file gets uploaded to object storage alongside the backup tarball. 
It will be used for restores, as seen in the next section.  

### Restore

1. The main Velero restore process checks each existing `PodVolumeBackup` custom resource in the cluster to backup from.  
2. For each `PodVolumeBackup` found, Velero first ensures a backup repository exists for the pod's namespace, by:
    - checking if a `BackupRepository` custom resource already exists
    - if not, creating a new one, and waiting for the `BackupRepository` controller to connect it (note that
    in this case, the actual repository should already exist in backup storage, so the Velero controller will simply
    check it for integrity and make a location connection)
3. Velero adds an init container to the pod, whose job is to wait for all FSB restores for the pod to complete (more
on this shortly)
4. Velero creates the pod, with the added init container, by submitting it to the Kubernetes API. Then, the Kubernetes 
scheduler schedules this pod to a worker node. If the pod fails to be scheduled for 
some reason (i.e. lack of cluster resources), the FSB restore will not be done.
5. Velero creates a `PodVolumeRestore` custom resource for each volume to be restored in the pod
6. The main Velero process now waits for each `PodVolumeRestore` resource to complete or fail
7. Meanwhile, each `PodVolumeRestore` is handled by the controller on the appropriate node, which:
    - has a hostPath volume mount of `/var/lib/kubelet/pods` to access the pod volume data
    - waits for the pod to be running the init container
    - finds the pod volume's subdirectory within the above volume
    - based on the path selection, Velero invokes restic or kopia for restore
    - on success, writes a file into the pod volume, in a `.velero` subdirectory, whose name is the UID of the Velero 
    restore that this pod volume restore is for
    - updates the status of the custom resource to `Completed` or `Failed`
8. The init container that was added to the pod is running a process that waits until it finds a file
within each restored volume, under `.velero`, whose name is the UID of the Velero restore being run
9. Once all such files are found, the init container's process terminates successfully and the pod moves
on to running other init containers/the main containers.

Velero won't restore a resource if a that resource is scaled to 0 and already exists in the cluster. If Velero restored the 
requested pods in this scenario, the Kubernetes reconciliation loops that manage resources would delete the running pods 
because its scaled to be 0. Velero will be able to restore once the resources is scaled up, and the pods are created and remain running.

## 3rd party controllers

### Monitor backup annotation

Velero does not provide a mechanism to detect persistent volume claims that are missing the File System Backup annotation.

To solve this, a controller was written by Thomann Bits&Beats: [velero-pvc-watcher][7]

[1]: https://github.com/restic/restic
[2]: https://github.com/kopia/kopia
[3]: customize-installation.md#enable-restic-integration
[4]: https://github.com/velero-io/velero/releases/
[5]: https://kubernetes.io/docs/concepts/storage/volumes/#local
[6]: https://kubernetes.io/docs/concepts/storage/volumes/#mount-propagation
[7]: https://github.com/bitsbeats/velero-pvc-watcher
[8]: https://docs.microsoft.com/en-us/azure/aks/azure-files-dynamic-pv
[9]: https://github.com/restic/restic/issues/1800
[10]: customize-installation.md#default-pod-volume-backup-to-file-system-backup
