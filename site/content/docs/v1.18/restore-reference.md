---
title: "Restore Reference"
layout: docs
---

The page outlines how to use the `velero restore` command, configuration options for restores, and describes the main process Velero uses to perform restores.

## Restore command-line options
To see all commands for restores, run `velero restore --help`.

To see all options associated with a specific command, provide the `--help` flag to that command. For example,  `velero restore create --help` shows all options associated with the `create` command.

```Usage:
  velero restore [command]

Available Commands:
  create      Create a restore
  delete      Delete restores
  describe    Describe restores
  get         Get restores
  logs        Get restore logs
```

## Detailed Restore workflow

The following is an overview of Velero's restore process that starts after you run `velero restore create`.

1. The Velero client makes a call to the Kubernetes API server to create a [`Restore`](api-types/restore.md) object.

1. The `RestoreController` notices the new Restore object and performs validation.

1. The `RestoreController` fetches basic information about the backup being restored, like the [BackupStorageLocation](locations.md) (BSL). It also fetches a tarball of the cluster resources in the backup, any volumes that will be restored using File System Backup, and any volume snapshots to be restored.

1. The `RestoreController` then extracts the tarball of backup cluster resources to the /tmp folder and performs some pre-processing on the resources, including:

    * Sorting the resources to help Velero decide the [restore order](#resource-restore-order) to use.

    * Attempting to discover the resources by their Kubernetes [Group Version Resource (GVR)](https://kubernetes.io/docs/reference/using-api/api-concepts/). If a resource is not discoverable, Velero will exclude it from the restore. See more about how [Velero backs up API versions](#backed-up-api-versions).

    * Applying any configured [resource filters](resource-filtering.md).

    * Verify the target namespace, if you have configured  [`--namespace-mappings`](#restoring-into-a-different-namespace) restore option.


1. The `RestoreController` begins restoring the eligible resources one at a time. Velero extracts the current resource into a Kubernetes resource object. Depending on the type of resource and restore options you specified, Velero will make the following modifications to the resource or preparations to the target cluster before attempting to create the resource:

    * The `RestoreController` makes sure the target namespace exists. If the target namespace does not exist, then the `RestoreController` will create a new one on the cluster.

    * If the resource is a Persistent Volume (PV), the `RestoreController` will [rename](#persistent-volume-rename) the PV and [remap](#restoring-into-a-different-namespace) its namespace.

    * If the resource is a Persistent Volume Claim (PVC), the `RestoreController` will modify the [PVC metadata](#pvc-restore).

    * Execute the resource’s `RestoreItemAction` [custom plugins](custom-plugins/), if you have configured one.

    * Update the resource object’s namespace if you've configured [namespace remapping](#restoring-into-a-different-namespace).

    * The `RestoreController` adds a `velero.io/backup-name` label with the backup name and a `velero.io/restore-name` with the restore name to the resource. This can help you easily identify restored resources and which backup they were restored from.

1. The `RestoreController` creates the resource object on the target cluster. If the resource is a PV then the `RestoreController` will restore the PV data from the [durable snapshot](#durable-snapshot-pv-restore), [File System Backup](#file-system-backup-pv-restore), or [CSI snapshot](#csi-pv-restore) depending on how the PV was backed up.

    If the resource already exists in the target cluster, which is determined by the Kubernetes API during resource creation, the `RestoreController` will skip the resource. The only [exception](#restore-existing-resource-policy) are Service Accounts, which Velero will attempt to merge differences between the backed up ServiceAccount into the ServiceAccount on the target cluster. You can [change the default existing resource restore policy](#restore-existing-resource-policy) to update resources instead of skipping them using the `--existing-resource-policy`.

1. Once the resource is created on the target cluster, Velero may take some additional steps or wait for additional processes to complete before moving onto the next resource to restore.

    * If the resource is a Pod, the `RestoreController` will execute any [Restore Hooks](restore-hooks.md) and wait for the hook to finish.
    * If the resource is a PV restored by File System Backup, the `RestoreController` waits for File System Backup’s restore to complete. The `RestoreController` sets a timeout for any resources restored with File System Backup during a restore. The default timeout is 4 hours, but you can configure this be setting using `--fs-backup-timeout` restore option.
    * If the resource is a Custom Resource Definition, the `RestoreController` waits for its availability in the cluster. The timeout is 1 minute.

    If any failures happen finishing these steps, the `RestoreController` will log an error in the restore result and will continue restoring.

## Restore order

By default, Velero will restore resources in the following order:

**High priorities** (restored first):

* Custom Resource Definitions
* Namespaces
* StorageClasses
* VolumeSnapshotClass
* VolumeSnapshotContents
* VolumeSnapshots
* DataUploads
* PersistentVolumes
* PersistentVolumeClaims
* ClusterRoles
* Roles
* ServiceAccounts
* ClusterRoleBindings
* RoleBindings
* Secrets
* ConfigMaps
* LimitRanges
* PriorityClasses
* Pods
* ReplicaSets
* ClusterClasses
* Endpoints
* Services

**Low priorities** (restored last):

* ClusterBootstraps
* Clusters
* ClusterResourceSets
* Apps (kappctrl)
* PackageInstalls (carvel)

Any resource not listed is restored alphabetically between the high and low priorities.

It's recommended that you use the default order for your restores. You are able to customize this order if you need to by setting the `--restore-resource-priorities` flag on the Velero server and specifying a different resource order. This customized order will apply to all future restores. You don't have to specify all resources in the `--restore-resource-priorities` flag. The priority list contains two parts which are split by the `-` element. Resources before `-` are restored first as high priorities, resources after `-` are restored last as low priorities, and any resource not in the list will be restored alphabetically between the high and low priorities.

```shell
velero server \
--restore-resource-priorities=customresourcedefinitions,namespaces,storageclasses,\
volumesnapshotclass.snapshot.storage.k8s.io,volumesnapshotcontents.snapshot.storage.k8s.io,\
volumesnapshots.snapshot.storage.k8s.io,datauploads.velero.io,persistentvolumes,\
persistentvolumeclaims,clusterroles,roles,serviceaccounts,clusterrolebindings,rolebindings,\
secrets,configmaps,limitranges,priorityclasses,pods,replicasets.apps,\
clusterclasses.cluster.x-k8s.io,endpoints,services,-,\
clusterbootstraps.run.tanzu.vmware.com,clusters.cluster.x-k8s.io,\
clusterresourcesets.addons.cluster.x-k8s.io,apps.kappctrl.k14s.io,\
packageinstalls.packaging.carvel.dev
```


## Restoring Persistent Volumes and Persistent Volume Claims

Velero has three approaches when restoring a PV, depending on how the backup was taken.

1. When restoring a snapshot, Velero statically creates the PV and then binds it to a restored PVC. Velero's PV rename and remap process is used only in this case because this is the only case where Velero creates the PV resource directly.
1. When restoring with File System Backup, Velero uses Kubernetes’ [dynamic provision process](https://kubernetes.io/docs/concepts/storage/dynamic-provisioning/) to provision the PV after creating the PVC. In this case, the PV object is not actually created by Velero.
1. When restoring with the [CSI plugin](csi.md), the PV is created from a CSI snapshot by the CSI driver. Velero doesn’t create the PV directly. Instead Velero creates a PVC with its DataSource referring to the CSI VolumeSnapshot object.

### Snapshot PV Restore

PV data backed up by durable snapshots is restored by VolumeSnapshot plugins. Velero calls the plugins’ interface to create a volume from a snapshot. The plugin returns the volume’s `volumeID`. This ID is created by storage vendors and will be updated in the PV object created by Velero, so that the PV object is connected to the volume restored from a snapshot.

### File System Backup PV Restore

For more information on File System Backup restores, see the [File System Backup](file-system-backup.md#restore) page.

### CSI PV Restore

A PV backed up by CSI snapshots is restored by the [CSI plugin](csi). This happens when restoring the PVC object that has been snapshotted by CSI. The CSI VolumeSnapshot object name is specified with the PVC during backup as the annotation `velero.io/volume-snapshot-name`. After validating the VolumeSnapshot object, Velero updates the PVC by adding a `DataSource` field and setting its value to the VolumeSnapshot name.

### Persistent Volume Rename

When restoring PVs, if the PV being restored does not exist on the target cluster, Velero will create the PV using the name from the backup. Velero will rename a PV before restoring if both of the following conditions are met:

1. The PV already exists on the target cluster.
1. The PV’s claim namespace has been [remapped](#restoring-into-a-different-namespace).

If both conditions are met, Velero will create the PV with a new name. The new name is the prefix `velero-clone-` and a random UUID. Velero also preserves the original name of the PV by adding an annotation `velero.io/original-pv-name` to the restored PV object.

If you attempt to restore the PV's referenced PVC into its original namespace without remapping the namespace, Velero will not rename the PV. If a PV's referenced PVC exists already for that namespace, the restored PV creation attempt will fail, with an `Already Exist` error from the Kubernetes API Server.

### PVC Restore

PVC objects are created the same way as other Kubernetes resources during a restore, with some specific changes:
* For a dynamic binding PVCs, Velero removes the fields related to bindings from the PVC object. This enables the default Kubernetes [dynamic binding process](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#binding) to be used for this PVC. The fields include:
    * volumeName
    * pv.kubernetes.io/bind-completed annotation
    * pv.kubernetes.io/bound-by-controller annotation
* For a PVC that is bound by Velero Restore, if the target PV has been renamed by the [PV restore process](#persistent-volume-rename), the RestoreController renames the `volumeName` field of the PVC object.

### Changing PV/PVC Storage Classes

Velero can change the storage class of persistent volumes and persistent volume claims during restores. To configure a storage class mapping, create a config map in the Velero namespace like the following:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  # any name can be used; Velero uses the labels (below)
  # to identify it rather than the name
  name: change-storage-class-config
  # must be in the velero namespace
  namespace: velero
  # the below labels should be used verbatim in your
  # ConfigMap.
  labels:
    # this value-less label identifies the ConfigMap as
    # config for a plugin (i.e. the built-in restore item action plugin)
    velero.io/plugin-config: ""
    # this label identifies the name and kind of plugin
    # that this ConfigMap is for.
    velero.io/change-storage-class: RestoreItemAction
data:
  # add 1+ key-value pairs here, where the key is the old
  # storage class name and the value is the new storage
  # class name.
  <old-storage-class>: <new-storage-class>
```
### Changing Image Repositories  
Velero can change the image name of pod/deployment/statefulsets/daemonset/replicaset/replicationcontroller/job/cronjob during restores. To configure a image name mapping, create a config map in the Velero namespace like the following:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  # any name can be used; Velero uses the labels (below)
  # to identify it rather than the name
  name: change-image-name-config
  # must be in the velero namespace
  namespace: velero
  # the below labels should be used verbatim in your
  # ConfigMap.
  labels:
    # this value-less label identifies the ConfigMap as
    # config for a plugin (i.e. the built-in restore item action plugin)
    velero.io/plugin-config: ""
    # this label identifies the name and kind of plugin
    # that this ConfigMap is for.
    velero.io/change-image-name: RestoreItemAction
data:
  # add 1+ key-value pairs here, where the key can be any
  # words that ConfigMap accepts. 
  # the value should be：
  # "<old_image_name_sub_part><delimiter><new_image_name_sub_part>"
  # for current implementation the <delimiter> can only be ","
  # e.x: in case your old image name is 1.1.1.1:5000/abc:test
  "case1":"1.1.1.1:5000,2.2.2.2:3000"
  "case2":"5000,3000"
  "case3":"abc:test,edf:test"
  "case5":"test,latest"
  "case4":"1.1.1.1:5000/abc:test,2.2.2.2:3000/edf:test"
  # Please note that image name may contain more than one part that
  # matching the replacing words.
  # e.x:in case your old image names are:
  # dev/image1:dev and dev/image2:dev
  # you want change to:
  # test/image1:dev and test/image2:dev
  # the suggested replacing rule is:
  "case5":"dev/,test/"
  # this will avoid unexpected replacement to the second "dev".
```

### PVC selected-node

Velero removes PVC's `volume.kubernetes.io/selected-node` annotation during restore, so that the restored PVC could be provisioned appropriately according to ```WaitForFirstConsumer``` rules, storage topologies and the restored pod's schedule result, etc.  

For more information of how this selected-node annotation matters to PVC restore, see issue https://github.com/velero-io/velero/issues/9053.  

## Restoring into a different namespace

Velero can restore resources into a different namespace than the one they were backed up from. To do this, use the `--namespace-mappings` flag:

```bash
velero restore create <RESTORE_NAME> \
  --from-backup <BACKUP_NAME> \
  --namespace-mappings old-ns-1:new-ns-1,old-ns-2:new-ns-2
```

For example, A Persistent Volume object has a reference to the Persistent Volume Claim’s namespace in the field `Spec.ClaimRef.Namespace`. If you specify that Velero should remap the target namespace during the restore, Velero will change the  `Spec.ClaimRef.Namespace` field on the PV object from `old-ns-1` to `new-ns-1`.

## Restore existing resource policy

By default, Velero is configured to be non-destructive during a restore. This means that it will never overwrite data that already exists in your cluster. When Velero attempts to create a resource during a restore, the resource being restored is compared to the existing resources on the target cluster. If the resource already exists in the target cluster, Velero skips restoring the current resource and moves onto the next resource to restore, without making any changes to the target cluster.

An exception to the default restore policy is ServiceAccounts. When restoring a ServiceAccount that already exists on the target cluster, Velero will attempt to merge the fields of the ServiceAccount from the backup into the existing ServiceAccount. Secrets and ImagePullSecrets are appended from the backed-up ServiceAccount. Velero adds any non-existing labels and annotations from the backed-up ServiceAccount to the existing resource, leaving the existing labels and annotations in place.

You can change this policy for a restore by using the `--existing-resource-policy` restore flag. The available options
are `none` (default) and `update`. If you choose to update existing resources during a restore
(`--existing-resource-policy=update`), Velero will attempt to update an existing resource to match the resource from the backup: 

* If the existing resource in the target cluster is the same as the resource Velero is attempting to restore, Velero will add a `velero.io/backup-name` label with the backup name and a `velero.io/restore-name` label with the restore name to the existing resource. If patching the labels fails, Velero adds a restore error and continues restoring the next resource.

* If the existing resource in the target cluster is different from the backup, Velero will first try to patch the existing resource to match the backup resource. If the patch is successful, Velero will add a `velero.io/backup-name` label with the backup name and a `velero.io/restore-name` label with the restore name to the existing resource. If the patch fails, Velero adds a restore warning and tries to add the `velero.io/backup-name` and `velero.io/restore-name` labels on the resource. If the labels patch also fails, then Velero logs a restore error and continues restoring the next resource.

You can also configure the existing resource policy in a [Restore](api-types/restore.md) object.

**NOTE:** 
* Update of a resource only applies to the Kubernetes resource data such as its spec. It may not work as expected for certain resource types such as PVCs and Pods. In case of PVCs for example, data in the PV is not restored or overwritten in any way.
* `update` existing resource policy works in a best-effort way, which means when restore's `--existing-resource-policy` is set to `update`, Velero will try to update the resource if the resource already exists, if the update fails, Velero will fall back to the default non-destructive way in the restore, and just logs a warning without failing the restore.

## Restore "status" field of objects

By default, Velero will remove the `status` field of an object before it's restored. This is because the value `status` field is typically set by the controller during reconciliation.  However, some custom resources are designed to store environment specific information in the `status` field, and it is important to preserve such information during restore.

You can use `--status-include-resources` and `--status-exclude-resources` flags to select the resources whose `status` field will be restored by Velero.  If there are resources selected via these flags, velero will trigger another API call to update the restored object to restore `status` field after it's created.

## Object-Level Resource Status Restoration

Starting from Velero 1.16, Velero now supports object-level control over status restoration during restores. Previously, status restoration could only be configured at the resource type level using the `restoreStatus` field in the Restore CR. With this enhancement, users and controllers can now specify status restoration at the individual resource instance level using the annotation:
```yaml
metadata:
  annotations:
    velero.io/restore-status: "true"
```
This feature provides fine-grained control over status restoration, allowing users and controllers to mark specific objects for status restore while keeping others unaffected.

Velero determines whether to restore the status of an object based on the following precedence:
1.	Object-Level Annotation (`velero.io/restore-status`)
- If the annotation is present with a valid value ("true" or "false"), it overrides the global `restoreStatus` setting.
- "true" → Status will be restored for this object, even if the resource type is not included in `restoreStatus.includedResources`.
- "false" → Status will not be restored for this object, even if the resource type is included in `restoreStatus.includedResources`.
2.	Restore CR (`restoreStatus` Field)
•	If the annotation is missing or invalid, Velero falls back to the `restoreStatus` configuration in the Restore CR.
•	Objects of resource types listed in `restoreStatus.includedResources` will have their status restored.
•	Objects of resource types excluded from `restoreStatus.excludedResources` will not have their status restored.
3.	Default Behavior
•	If an object has no annotation and its resource type is not included in `restoreStatus.includedResources`, status restoration is skipped.

Let's go over some examples:

1. Restore Status for a Specific Object: If you want Velero to restore the status for a specific resource instance regardless of global restore settings, add the annotation:
```yaml
metadata:
  annotations:
    velero.io/restore-status: "true"
```
Even if the resource type is not listed in `restoreStatus.includedResources`, this object’s status will be restored.

2. Prevent Status Restore for a Specific Object: If you want to exclude a specific object from status restoration, even if its resource type is included in `restoreStatus.includedResources`, use:
```yaml
metadata:
  annotations:
    velero.io/restore-status: "false"
```
This ensures that this specific object will not have its status restored.

3. Restore Status Based on Resource Type: If you want to restore the status for all objects of a resource type, use the `restoreStatus` field in the Restore CR:
```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: restore-with-status
  namespace: velero
spec:
  restoreStatus:
    includedResources:
      - foo.bar.io
```
All `foo.bar.io` objects will have their status restored, except those that have `velero.io/restore-status`: "false" annotation.

4.  Default Behavior (No Annotations & No Restore Spec): If no `velero.io/restore-status` annotation is set and the resource type is not listed in `restoreStatus.includedResources`, Velero skips restoring status for that object. This maintains the existing default behavior.

## Write Sparse files
If using fs-restore or CSI snapshot data movements, it's supported to write sparse files during restore by the below command:
```bash
velero restore create <RESTORE_NAME> --from-backup <BACKUP_NAME> --write-sparse-files --wait
``` 

## Parallel Files Download
If using fs-restore or CSI snapshot data movements, it's possible to configure one option for parallel file downloads during the restore by Kopia uploader using the command below:
```bash
velero restore create <RESTORE_NAME> --from-backup <BACKUP_NAME> --parallel-files-download <NUM> --wait
``` 

## Removing a Restore object

There are two ways to delete a Restore object:

1. Deleting with `velero restore delete` will delete the Custom Resource representing the restore, along with its individual log and results files. It will not delete any objects that were created by the restore in your cluster.
2. Deleting with `kubectl -n velero delete restore` will delete the Custom Resource representing the restore. It will not delete restore log or results files from object storage, or any objects that were created during the restore in your cluster.

## What happens to NodePorts and HealthCheckNodePort when restoring Services

During a restore, Velero deletes **Auto assigned** NodePorts and HealthCheckNodePort by default and Services get new **auto assigned** nodePorts and healthCheckNodePort after restore.

Velero auto detects **explicitly specified** NodePorts using **`last-applied-config`** annotation and **`managedFields`**. They are **preserved** after restore. NodePorts can be explicitly specified as `.spec.ports[*].nodePort` field on Service definition.

Velero will do the same to the `HealthCheckNodePort` as `NodePorts`.

### Always Preserve NodePorts and HealthCheckNodePort

It is not always possible to set nodePorts and healthCheckNodePort explicitly on some big clusters because of operational complexity. As the Kubernetes [NodePort documentation](https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport) states, "if you want a specific port number, you can specify a value in the `nodePort` field. The control plane will either allocate you that port or report that the API transaction failed. This means that you need to take care of possible port collisions yourself. You also have to use a valid port number, one that's inside the range configured for NodePort use.""

The clusters which are not explicitly specifying nodePorts may still need to restore original NodePorts in the event of a disaster. Auto assigned nodePorts are typically defined on Load Balancers located in front of cluster. Changing all these nodePorts on Load Balancers is another operation complexity you are responsible for updating after disaster if nodePorts are changed.

Use the `velero restore create ` command's `--preserve-nodeports` flag to preserve Service nodePorts and healthCheckNodePort always, regardless of whether nodePorts are explicitly specified or not. This flag is used for preserving the original nodePorts and healthCheckNodePort from a backup and can be used as `--preserve-nodeports` or `--preserve-nodeports=true`. If this flag is present, Velero will not remove the nodePorts and healthCheckNodePort when restoring a Service, but will try to use the nodePorts from the backup.

Trying to preserve nodePorts and healthCheckNodePort may cause port conflicts when restoring on situations below:

- If the nodePort from the backup is already allocated on the target cluster then Velero prints error log as shown below and continues the restore operation.

  ```
  time="2020-11-23T12:58:31+03:00" level=info msg="Executing item action for services" logSource="pkg/restore/restore.go:1002" restore=velero/test-with-3-svc-20201123125825

  time="2020-11-23T12:58:31+03:00" level=info msg="Restoring Services with original NodePort(s)" cmd=_output/bin/linux/amd64/velero logSource="pkg/restore/service_action.go:61" pluginName=velero restore=velero/test-with-3-svc-20201123125825

  time="2020-11-23T12:58:31+03:00" level=info msg="Attempting to restore Service: hello-service" logSource="pkg/restore/restore.go:1107" restore=velero/test-with-3-svc-20201123125825

  time="2020-11-23T12:58:31+03:00" level=error msg="error restoring hello-service: Service \"hello-service\" is invalid: spec.ports[0].nodePort: Invalid value: 31536: provided port is already allocated" logSource="pkg/restore/restore.go:1170" restore=velero/test-with-3-svc-20201123125825
  ```

- If the nodePort from the backup is not in the nodePort range of target cluster then Velero prints error log as below and continues with the restore operation. Kubernetes default nodePort range is 30000-32767 but on the example cluster nodePort range is 20000-22767 and tried to restore Service with nodePort 31536.

  ```
  time="2020-11-23T13:09:17+03:00" level=info msg="Executing item action for services" logSource="pkg/restore/restore.go:1002" restore=velero/test-with-3-svc-20201123130915

  time="2020-11-23T13:09:17+03:00" level=info msg="Restoring Services with original NodePort(s)" cmd=_output/bin/linux/amd64/velero logSource="pkg/restore/service_action.go:61" pluginName=velero restore=velero/test-with-3-svc-20201123130915

  time="2020-11-23T13:09:17+03:00" level=info msg="Attempting to restore Service: hello-service" logSource="pkg/restore/restore.go:1107" restore=velero/test-with-3-svc-20201123130915

  time="2020-11-23T13:09:17+03:00" level=error msg="error restoring hello-service: Service \"hello-service\" is invalid: spec.ports[0].nodePort: Invalid value: 31536: provided port is not in the valid range. The range of valid ports is 20000-22767" logSource="pkg/restore/restore.go:1170" restore=velero/test-with-3-svc-20201123130915
  ```
