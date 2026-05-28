---
title: "Restic Integration"
layout: docs
---

Velero supports backing up and restoring Kubernetes volumes using a free open-source backup tool called [restic][1]. This support is considered beta quality. Please see the list of [limitations](#limitations) to understand if it fits your use case.

Velero allows you to take snapshots of persistent volumes as part of your backups if you’re using one of
the supported cloud providers’ block storage offerings (Amazon EBS Volumes, Azure Managed Disks, Google Persistent Disks).
It also provides a plugin model that enables anyone to implement additional object and block storage backends, outside the
main Velero repository.

Velero's Restic integration was added to give you an out-of-the-box solution for backing up and restoring almost any type of Kubernetes volume. This integration is an addition to Velero's capabilities, not a replacement for existing functionality. If you're running on AWS, and taking EBS snapshots as part of your regular Velero backups, there's no need to switch to using Restic. However, if you need a volume snapshot plugin for your storage platform, or if you're using EFS, AzureFile, NFS, emptyDir,
local, or any other volume type that doesn't have a native snapshot concept, Restic might be for you.

Restic is not tied to a specific storage platform, which means that this integration also paves the way for future work to enable
cross-volume-type data migrations.

**NOTE:** hostPath volumes are not supported, but the [local volume type][4] is supported.

## Setup Restic

### Prerequisites

- Understand how Velero performs [backups with the Restic integration](#how-backup-and-restore-work-with-restic).
- [Download][3] the latest Velero release.
- Kubernetes v1.16.0 and later. Velero's Restic integration requires the Kubernetes [MountPropagation feature][6].

### Install Restic

To install Restic, use the `--use-restic` flag in the `velero install` command. See the [install overview][2] for more details on other flags for the install command.

```
velero install --use-restic
```

When using Restic on a storage provider that doesn't have Velero support for snapshots, the `--use-volume-snapshots=false` flag prevents an unused `VolumeSnapshotLocation` from being created on installation.

Velero handles the creation of the restic repo prefix for Amazon, Azure, and GCP plugins, if you are using a different [provider plugin](supported-providers.md), then you will need to make sure the `resticRepoPrefix` is set in the [BackupStorageLocation  `config`](api-types/backupstoragelocation.md). The value for `resticRepoPrefix` should be the cloud storage URL where all namespace restic repos will be created. Velero creates one restic repo per namespace. For example, if backing up 2 namespaces, namespace1 and namespace2, using restic on AWS, the `resticRepoPrefix` would be something like `s3:s3-us-west-2.amazonaws.com/bucket/restic` and the full restic repo path for namespace1 would be `s3:s3-us-west-2.amazonaws.com/bucket/restic/ns1` and for namespace2 would be `s3:s3-us-west-2.amazonaws.com/bucket/restic/ns2`.

There may be additional installation steps depending on the cloud provider plugin you are using. You should refer to the [plugin specific documentation](supported-providers.md) for the must up to date information.

### Configure Restic DaemonSet spec

After installation, some PaaS/CaaS platforms based on Kubernetes also require modifications the Restic DaemonSet spec. The steps in this section are only needed if you are installing on RancherOS, OpenShift, VMware Tanzu Kubernetes Grid Integrated Edition (formerly VMware Enterprise PKS), or Microsoft Azure.


**RancherOS**


Update the host path for volumes in the Restic DaemonSet in the Velero namespace from `/var/lib/kubelet/pods` to `/opt/rke/var/lib/kubelet/pods`.

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


To mount the correct hostpath to pods volumes, run the Restic pod in `privileged` mode.

1. Add the `velero` ServiceAccount to the `privileged` SCC:

    ```
    $ oc adm policy add-scc-to-user privileged -z velero -n velero
    ```

2. For OpenShift version  >= `4.1`, modify the DaemonSet yaml to request a privileged mode:

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
    oc patch ds/restic \
      --namespace velero \
      --type json \
      -p '[{"op":"add","path":"/spec/template/spec/containers/0/securityContext","value": { "privileged": true}}]'
    ```

3. For OpenShift version  < `4.1`, modify the DaemonSet yaml to request a privileged mode and mount the correct hostpath to pods volumes.

    ```diff
    @@ -35,7 +35,7 @@ spec:
                secretName: cloud-credentials
            - name: host-pods
              hostPath:
    -            path: /var/lib/kubelet/pods
    +            path: /var/lib/origin/openshift.local.volumes/pods
            - name: scratch
              emptyDir: {}
          containers:
    @@ -67,3 +67,5 @@ spec:
                  value: /credentials/cloud
                - name: VELERO_SCRATCH_DIR
                  value: /scratch
    +          securityContext:
    +            privileged: true
    ```

    or

    ```shell
    oc patch ds/restic \
      --namespace velero \
      --type json \
      -p '[{"op":"add","path":"/spec/template/spec/containers/0/securityContext","value": { "privileged": true}}]'

    oc patch ds/restic \
      --namespace velero \
      --type json \
      -p '[{"op":"replace","path":"/spec/template/spec/volumes/0/hostPath","value": { "path": "/var/lib/origin/openshift.local.volumes/pods"}}]'
    ```


If Restic is not running in a privileged mode, it will not be able to access pods volumes within the mounted hostpath directory because of the default enforced SELinux mode configured in the host system level. You can [create a custom SCC](https://docs.openshift.com/container-platform/3.11/admin_guide/manage_scc.html) to relax the security in your cluster so that Restic pods are allowed to use the hostPath volume plug-in without granting them access to the `privileged` SCC.

By default a userland openshift namespace will not schedule pods on all nodes in the cluster.

To schedule on all nodes the namespace needs an annotation:

```
oc annotate namespace <velero namespace> openshift.io/node-selector=""
```

This should be done before velero installation.

Or the ds needs to be deleted and recreated:

```
oc get ds restic -o yaml -n <velero namespace> > ds.yaml
oc annotate namespace <velero namespace> openshift.io/node-selector=""
oc create -n <velero namespace> -f ds.yaml
```

**VMware Tanzu Kubernetes Grid Integrated Edition (formerly VMware Enterprise PKS)**

You need to enable the `Allow Privileged` option in your plan configuration so that Restic is able to mount the hostpath.

The hostPath should be changed from `/var/lib/kubelet/pods` to `/var/vcap/data/kubelet/pods`

```yaml
hostPath:
  path: /var/vcap/data/kubelet/pods
```


**Microsoft Azure**

If you are using [Azure Files][8], you need to add `nouser_xattr` to your storage class's `mountOptions`. See [this restic issue][9] for more details.

You can use the following command to patch the storage class:

```bash
kubectl patch storageclass/<YOUR_AZURE_FILE_STORAGE_CLASS_NAME> \
  --type json \
  --patch '[{"op":"add","path":"/mountOptions/-","value":"nouser_xattr"}]'
```

## To back up

Velero supports two approaches of discovering pod volumes that need to be backed up using Restic:

- Opt-in approach: Where every pod containing a volume to be backed up using Restic must be annotated with the volume's name.
- Opt-out approach: Where all pod volumes are backed up using Restic, with the ability to opt-out any volumes that should not be backed up.

The following sections provide more details on the two approaches.

### Using the opt-out approach

In this approach, Velero will back up all pod volumes using Restic with the exception of:

- Volumes mounting the default service account token, Kubernetes Secrets, and ConfigMaps
- Hostpath volumes

It is possible to exclude volumes from being backed up using the `backup.velero.io/backup-volumes-excludes` annotation on the pod.

Instructions to back up using this approach are as follows:

1. Run the following command on each pod that contains volumes that should **not** be backed up using Restic

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
    to exclude Restic backup of volume `pvc1-vm`, you would run:

    ```bash
    kubectl -n sample annotate pod/app1 backup.velero.io/backup-volumes-excludes=pvc1-vm
    ```

2. Take a Velero backup:

    ```bash
    velero backup create BACKUP_NAME --default-volumes-to-restic OTHER_OPTIONS
    ```

    The above steps uses the opt-out approach on a per backup basis.

    Alternatively, this behavior may be enabled on all velero backups running the `velero install` command with the `--default-volumes-to-restic` flag. Refer [install overview][11] for details.

3. When the backup completes, view information about the backups:

    ```bash
    velero backup describe YOUR_BACKUP_NAME
    ```
    ```bash
    kubectl -n velero get podvolumebackups -l velero.io/backup-name=YOUR_BACKUP_NAME -o yaml
    ```

### Using opt-in pod volume backup

Velero, by default, uses this approach to discover pod volumes that need to be backed up using Restic. Every pod containing a volume to be backed up using Restic must be annotated with the volume's name using the `backup.velero.io/backup-volumes` annotation.

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

Regardless of how volumes are discovered for backup using Restic, the process of restoring remains the same.

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

- `hostPath` volumes are not supported. [Local persistent volumes][4] are supported.
- Those of you familiar with [restic][1] may know that it encrypts all of its data. Velero uses a static,
common encryption key for all Restic repositories it creates. **This means that anyone who has access to your
bucket can decrypt your Restic backup data**. Make sure that you limit access to the Restic bucket
appropriately.
- An incremental backup chain will be maintained across pod reschedules for PVCs. However, for pod volumes that are *not*
PVCs, such as `emptyDir` volumes, when a pod is deleted/recreated (for example, by a ReplicaSet/Deployment), the next backup of those
volumes will be full rather than incremental, because the pod volume's lifecycle is assumed to be defined by its pod.
- Restic scans each file in a single thread. This means that large files (such as ones storing a database) will take a long time to scan for data deduplication, even if the actual
difference is small.
- If you plan to use Velero's Restic integration to backup 100GB of data or more, you may need to [customize the resource limits](/docs/main/customize-installation/#customize-resource-requests-and-limits) to make sure backups complete successfully.
- Velero's Restic integration backs up data from volumes by accessing the node's filesystem, on which the pod is running. For this reason, Velero's Restic integration can only backup volumes that are mounted by a pod and not directly from the PVC. For orphan PVC/PV pairs (without running pods), some Velero users overcame this limitation running a staging pod (i.e. a busybox or alpine container with an infinite sleep) to mount these PVC/PV pairs prior taking a Velero backup.

## Customize Restore Helper Container

Velero uses a helper init container when performing a Restic restore. By default, the image for this container is `velero/velero-restic-restore-helper:<VERSION>`,
where `VERSION` matches the version/tag of the main Velero image. You can customize the image that is used for this helper by creating a ConfigMap in the Velero namespace with
the alternate image.

In addition, you can customize the resource requirements for the init container, should you need.

The ConfigMap must look like the following:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  # any name can be used; Velero uses the labels (below)
  # to identify it rather than the name
  name: restic-restore-action-config
  # must be in the velero namespace
  namespace: velero
  # the below labels should be used verbatim in your
  # ConfigMap.
  labels:
    # this value-less label identifies the ConfigMap as
    # config for a plugin (i.e. the built-in restic restore
    # item action plugin)
    velero.io/plugin-config: ""
    # this label identifies the name and kind of plugin
    # that this ConfigMap is for.
    velero.io/restic: RestoreItemAction
data:
  # The value for "image" can either include a tag or not;
  # if the tag is *not* included, the tag from the main Velero
  # image will automatically be used.
  image: myregistry.io/my-custom-helper-image[:OPTIONAL_TAG]

  # "cpuRequest" sets the request.cpu value on the restic init containers during restore.
  # If not set, it will default to "100m". A value of "0" is treated as unbounded.
  cpuRequest: 200m

  # "memRequest" sets the request.memory value on the restic init containers during restore.
  # If not set, it will default to "128Mi". A value of "0" is treated as unbounded.
  memRequest: 128Mi

  # "cpuLimit" sets the request.cpu value on the restic init containers during restore.
  # If not set, it will default to "100m". A value of "0" is treated as unbounded.
  cpuLimit: 200m

  # "memLimit" sets the request.memory value on the restic init containers during restore.
  # If not set, it will default to "128Mi". A value of "0" is treated as unbounded.
  memLimit: 128Mi

  # "secCtxRunAsUser" sets the securityContext.runAsUser value on the restic init containers during restore.
  secCtxRunAsUser: 1001

  # "secCtxRunAsGroup" sets the securityContext.runAsGroup value on the restic init containers during restore.
  secCtxRunAsGroup: 999

  # "secCtxAllowPrivilegeEscalation" sets the securityContext.allowPrivilegeEscalation value on the restic init containers during restore.
  secCtxAllowPrivilegeEscalation: false

  # "secCtx" sets the securityContext object value on the restic init containers during restore.
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

Does your Restic repository exist, and is it ready?

```bash
velero restic repo get

velero restic repo get REPO_NAME -o yaml
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

## How backup and restore work with Restic

Velero has three custom resource definitions and associated controllers:

- `ResticRepository` - represents/manages the lifecycle of Velero's [restic repositories][5]. Velero creates
a Restic repository per namespace when the first Restic backup for a namespace is requested. The controller
for this custom resource executes Restic repository lifecycle commands -- `restic init`, `restic check`,
and `restic prune`.

    You can see information about your Velero's Restic repositories by running `velero restic repo get`.

- `PodVolumeBackup` - represents a Restic backup of a volume in a pod. The main Velero backup process creates
one or more of these when it finds an annotated pod. Each node in the cluster runs a controller for this
resource (in a daemonset) that handles the `PodVolumeBackups` for pods on that node. The controller executes
`restic backup` commands to backup pod volume data.

- `PodVolumeRestore` - represents a Restic restore of a pod volume. The main Velero restore process creates one
or more of these when it encounters a pod that has associated Restic backups. Each node in the cluster runs a
controller for this resource (in the same daemonset as above) that handles the `PodVolumeRestores` for pods
on that node. The controller executes `restic restore` commands to restore pod volume data.

### Backup

1. Based on configuration, the main Velero backup process uses the opt-in or opt-out approach to check each pod that it's backing up for the volumes to be backed up using Restic.
1. When found, Velero first ensures a Restic repository exists for the pod's namespace, by:
    - checking if a `ResticRepository` custom resource already exists
    - if not, creating a new one, and waiting for the `ResticRepository` controller to init/check it
1. Velero then creates a `PodVolumeBackup` custom resource per volume listed in the pod annotation
1. The main Velero process now waits for the `PodVolumeBackup` resources to complete or fail
1. Meanwhile, each `PodVolumeBackup` is handled by the controller on the appropriate node, which:
    - has a hostPath volume mount of `/var/lib/kubelet/pods` to access the pod volume data
    - finds the pod volume's subdirectory within the above volume
    - runs `restic backup`
    - updates the status of the custom resource to `Completed` or `Failed`
1. As each `PodVolumeBackup` finishes, the main Velero process adds it to the Velero backup in a file named `<backup-name>-podvolumebackups.json.gz`. This file gets uploaded to object storage alongside the backup tarball. It will be used for restores, as seen in the next section.

### Restore

1. The main Velero restore process checks each existing `PodVolumeBackup` custom resource in the cluster to backup from.
1. For each `PodVolumeBackup` found, Velero first ensures a Restic repository exists for the pod's namespace, by:
    - checking if a `ResticRepository` custom resource already exists
    - if not, creating a new one, and waiting for the `ResticRepository` controller to init/check it (note that
    in this case, the actual repository should already exist in object storage, so the Velero controller will simply
    check it for integrity)
1. Velero adds an init container to the pod, whose job is to wait for all Restic restores for the pod to complete (more
on this shortly)
1. Velero creates the pod, with the added init container, by submitting it to the Kubernetes API. Then, the Kubernetes scheduler schedules this pod to a worker node, and the pod must be in a running state. If the pod fails to start for some reason (i.e. lack of cluster resources), the Restic restore will not be done.
1. Velero creates a `PodVolumeRestore` custom resource for each volume to be restored in the pod
1. The main Velero process now waits for each `PodVolumeRestore` resource to complete or fail
1. Meanwhile, each `PodVolumeRestore` is handled by the controller on the appropriate node, which:
    - has a hostPath volume mount of `/var/lib/kubelet/pods` to access the pod volume data
    - waits for the pod to be running the init container
    - finds the pod volume's subdirectory within the above volume
    - runs `restic restore`
    - on success, writes a file into the pod volume, in a `.velero` subdirectory, whose name is the UID of the Velero restore
    that this pod volume restore is for
    - updates the status of the custom resource to `Completed` or `Failed`
1. The init container that was added to the pod is running a process that waits until it finds a file
within each restored volume, under `.velero`, whose name is the UID of the Velero restore being run
1. Once all such files are found, the init container's process terminates successfully and the pod moves
on to running other init containers/the main containers.

Velero won't restore a resource if a that resource is scaled to 0 and already exists in the cluster. If Velero restored the requested pods in this scenario, the Kubernetes reconciliation loops that manage resources would delete the running pods because its scaled to be 0. Velero will be able to restore once the resources is scaled up, and the pods are created and remain running.

## 3rd party controllers

### Monitor backup annotation

Velero does not provide a mechanism to detect persistent volume claims that are missing the Restic backup annotation.

To solve this, a controller was written by Thomann Bits&Beats: [velero-pvc-watcher][7]

[1]: https://github.com/restic/restic
[2]: customize-installation.md#enable-restic-integration
[3]: https://github.com/velero-io/velero/releases/
[4]: https://kubernetes.io/docs/concepts/storage/volumes/#local
[5]: http://restic.readthedocs.io/en/latest/100_references.html#terminology
[6]: https://kubernetes.io/docs/concepts/storage/volumes/#mount-propagation
[7]: https://github.com/bitsbeats/velero-pvc-watcher
[8]: https://docs.microsoft.com/en-us/azure/aks/azure-files-dynamic-pv
[9]: https://github.com/restic/restic/issues/1800
[11]: customize-installation.md#default-pod-volume-backup-to-restic
