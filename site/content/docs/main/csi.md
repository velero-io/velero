---
title: "Container Storage Interface Snapshot Support in Velero"
layout: docs
---

Integrating Container Storage Interface (CSI) snapshot support into Velero enables Velero to backup and restore CSI-backed volumes using the [Kubernetes CSI Snapshot APIs](https://kubernetes.io/docs/concepts/storage/volume-snapshots/).

By supporting CSI snapshot APIs, Velero can support any volume provider that has a CSI driver, without requiring a Velero-specific plugin to be available. This page gives an overview of how to add support for CSI snapshots to Velero.

## Notice
From release-1.14, the `github.com/vmware-tanzu/velero-plugin-for-csi` repository, which is the Velero CSI plugin, is merged into the `github.com/vmware-tanzu/velero` repository.
The reasons to merge the CSI plugin are:
* The VolumeSnapshot data mover depends on the CSI plugin, it's reasonabe to integrate them.
* This change reduces the Velero deploying complexity.
* This makes performance tuning easier in the future.

As a result, no need to install Velero CSI plugin anymore.

## Prerequisites

 1. Your cluster is Kubernetes version 1.20 or greater.
 1. Your cluster is running a CSI driver capable of support volume snapshots at the [v1 API level](https://kubernetes.io/blog/2020/12/10/kubernetes-1.20-volume-snapshot-moves-to-ga/).
 1. When restoring CSI VolumeSnapshots across clusters, the name of the CSI driver in the destination cluster is the same as that on the source cluster to ensure cross cluster portability of CSI VolumeSnapshots

**NOTE:** Not all cloud provider's CSI drivers guarantee snapshot durability, meaning that the VolumeSnapshot and VolumeSnapshotContent objects may be stored in the same object storage system location as the original PersistentVolume and may be vulnerable to data loss. You should refer to your cloud provider's documentation for more information on configuring snapshot durability.  Since v0.3.0 the velero team will provide official support for CSI plugin when they are used with AWS and Azure drivers.

## Installing Velero with CSI support

To integrate Velero with the CSI volume snapshot APIs, you must enable the `EnableCSI` feature flag.

```bash
velero install \
--features=EnableCSI \
--plugins=<object storage plugin> \
...
```

To include the status of CSI objects associated with a Velero backup in `velero backup describe` output, run `velero client config set features=EnableCSI`.
See [Enabling Features][1] for more information about managing client-side feature flags.

## Implementation Choices

This section documents some of the choices made during implementing the CSI snapshot.

 1. VolumeSnapshots created by the Velero CSI plugins are retained only for the lifetime of the backup even if the `DeletionPolicy` on the VolumeSnapshotClass is set to `Retain`. To accomplish this, during deletion of the backup the prior to deleting the VolumeSnapshot, VolumeSnapshotContent object is patched to set its `DeletionPolicy` to `Delete`. Deleting the VolumeSnapshot object will result in cascade delete of the VolumeSnapshotContent and the snapshot in the storage provider.
 2. VolumeSnapshotContent objects created during a `velero backup` that are dangling, unbound to a VolumeSnapshot object, will be discovered, using labels, and deleted on backup deletion.
 3. The Velero CSI plugins, to backup CSI backed PVCs, will choose the VolumeSnapshotClass in the cluster based on the following logic:
    1. **Default Behavior Based On Annotation:**
    You can specify a default VolumeSnapshotClass for VolumeSnapshots that don't request any particular class to bind to by adding the snapshot.storage.kubernetes.io/is-default-class: "true" annotation.
    For example, if you want to create a VolumeSnapshotClass for the CSI driver `disk.csi.cloud.com` for taking snapshots of disks created with `disk.csi.cloud.com` based storage classes, you can create a VolumeSnapshotClass like this:
        ```yaml
        apiVersion: snapshot.storage.k8s.io/v1
        kind: VolumeSnapshotClass
        metadata:
          name: test-snapclass-by-annotation
          annotations:
            snapshot.storage.kubernetes.io/is-default-class: "true"
        driver: disk.csi.cloud.com
       ```    
       Note: If multiple CSI drivers exist, a default VolumeSnapshotClass can be specified for each of them.
    2. **Default Behavior Based On Label:**
    You can simply create a VolumeSnapshotClass for a particular driver and put a label on it to indicate that it is the default VolumeSnapshotClass for that driver.  For example, if you want to create a VolumeSnapshotClass for the CSI driver `disk.csi.cloud.com` for taking snapshots of disks created with `disk.csi.cloud.com` based storage classes, you can create a VolumeSnapshotClass like this:
        ```yaml
        apiVersion: snapshot.storage.k8s.io/v1
        kind: VolumeSnapshotClass
        metadata:
          name: test-snapclass-by-label
          labels:
            velero.io/csi-volumesnapshot-class: "true"
        driver: disk.csi.cloud.com
        ```
        Note: For each driver type, there should only be 1 VolumeSnapshotClass with the label `velero.io/csi-volumesnapshot-class: "true"`.

    2. **Choose VolumeSnapshotClass for a particular Backup Or Schedule:**
    If you want to use a particular VolumeSnapshotClass for a particular backup or schedule, you can add a annotation to the backup or schedule to indicate which VolumeSnapshotClass to use.  For example, if you want to use the VolumeSnapshotClass `test-snapclass` for a particular backup for snapshotting PVCs of `disk.csi.cloud.com`, you can create a backup like this:
        ```yaml
        apiVersion: velero.io/v1
        kind: Backup
        metadata:
          name: test-backup
          annotations:
            velero.io/csi-volumesnapshot-class_disk.csi.cloud.com: "test-snapclass"
        spec:
            includedNamespaces:
            - default
        ```
        Note: Please ensure all your annotations are in lowercase. And follow the following format: `velero.io/csi-volumesnapshot-class_<driver name> = <VolumeSnapshotClass Name>`

    3. **Choose VolumeSnapshotClass for a particular StorageClass:**
    If you want to use a particular VolumeSnapshotClass for a particular StorageClass, you can add an annotation to the StorageClass to indicate which VolumeSnapshotClass to use. For example, if you want to use the VolumeSnapshotClass `test-snapclass` for a particular backup for snapshotting PVCs of a given StorageClass, you can annotate it:
        ```yaml
        apiVersion: storage/v1
        kind: StorageClass
        metadata:
          name: test-storageclass
          annotations:
            velero.io/csi-volumesnapshot-class: "test-snapclass"
        ```

    4. **Choosing VolumeSnapshotClass for a particular PVC:**
    If you want to use a particular VolumeSnapshotClass for a particular PVC, you can add a annotation to the PVC to indicate which VolumeSnapshotClass to use. This overrides any annotation added to backup or schedule. For example, if you want to use the VolumeSnapshotClass `test-snapclass` for a particular PVC, you can create a PVC like this:
        ```yaml
        apiVersion: v1
        kind: PersistentVolumeClaim
        metadata:
          name: test-pvc
          annotations:
            velero.io/csi-volumesnapshot-class: "test-snapclass"
        spec:
            accessModes:
            - ReadWriteOnce
            resources:
                requests:
                storage: 1Gi
            storageClassName: disk.csi.cloud.com
        ```
 4. The VolumeSnapshot objects will be removed from the cluster after the backup is uploaded to the object storage, so that the namespace that is backed up can be deleted without removing the snapshot in the storage provider if the `DeletionPolicy` is `Delete`.  

## How it Works - Overview

Velero's CSI support does not rely on the Velero VolumeSnapshotter plugin interface.

Instead, Velero uses a collection of BackupItemAction plugins that act first against PersistentVolumeClaims.

When this BackupItemAction sees PersistentVolumeClaims pointing to a PersistentVolume backed by a CSI driver, it will choose the VolumeSnapshotClass with the same driver name that has the `velero.io/csi-volumesnapshot-class` label to create a CSI VolumeSnapshot object with the PersistentVolumeClaim as a source.
This VolumeSnapshot object resides in the same namespace as the PersistentVolumeClaim that was used as a source.

From there, the CSI external-snapshotter controller will see the VolumeSnapshot and create a VolumeSnapshotContent object, a cluster-scoped resource that will point to the actual, disk-based snapshot in the storage system.
The external-snapshotter plugin will call the CSI driver's snapshot method, and the driver will call the storage system's APIs to generate the snapshot.
Once an ID is generated and the storage system marks the snapshot as usable for restore, the VolumeSnapshotContent object will be updated with a `status.snapshotHandle` and the `status.readyToUse` field will be set.

Velero will include the generated VolumeSnapshot and VolumeSnapshotContent objects in the backup tarball, as well as
upload all VolumeSnapshots and VolumeSnapshotContents objects in a JSON file to the object storage system. **Note that
only Kubernetes objects are uploaded to the object storage, not the data in snapshots.**

From v1.16, when Velero synchronizes backups into a new cluster, the VolumeSnapshotClass that is chosen to take
snapshot will be synced into the cluster, so that Velero can manage backup expiration appropriately.


The `DeletionPolicy` on the VolumeSnapshotContent will be the same as the `DeletionPolicy` on the VolumeSnapshotClass that was used to create the VolumeSnapshot. Setting a `DeletionPolicy` of `Retain` on the VolumeSnapshotClass will preserve the volume snapshot in the storage system for the lifetime of the Velero backup and will prevent the deletion of the volume snapshot, in the storage system, in the event of a disaster where the namespace with the VolumeSnapshot object may be lost.

When the Velero backup expires, the VolumeSnapshot objects will be deleted and the VolumeSnapshotContent objects will be updated to have a `DeletionPolicy` of `Delete`, to free space on the storage system.

**Note:** The AWS, Microsoft Azure, and Google Cloud Platform (GCP) Velero plugins version 1.4 and later are able to snapshot and restore persistent volumes provisioned by a CSI driver via the APIs of the cloud provider, without having to install Velero CSI plugins. See the [AWS](https://github.com/vmware-tanzu/velero-plugin-for-aws), [Microsoft Azure](https://github.com/vmware-tanzu/velero-plugin-for-microsoft-azure), and [Google Cloud Platform (GCP)](https://github.com/vmware-tanzu/velero-plugin-for-gcp) Velero plugin repo for more information on supported CSI drivers.
From v1.14, no need to install the CSI plugin, because it is integrated into the Velero code base.

[1]: customize-installation.md#enable-server-side-features
