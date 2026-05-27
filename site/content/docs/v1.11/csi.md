---
title: "Container Storage Interface Snapshot Support in Velero"
layout: docs
---

Integrating Container Storage Interface (CSI) snapshot support into Velero enables Velero to backup and restore CSI-backed volumes using the [Kubernetes CSI Snapshot APIs](https://kubernetes.io/docs/concepts/storage/volume-snapshots/).

By supporting CSI snapshot APIs, Velero can support any volume provider that has a CSI driver, without requiring a Velero-specific plugin to be available. This page gives an overview of how to add support for CSI snapshots to Velero  through CSI plugins. For more information about specific components, see the [plugin repo](https://github.com/vmware-tanzu/velero-plugin-for-csi/).

## Prerequisites

 1. Your cluster is Kubernetes version 1.20 or greater.
 1. Your cluster is running a CSI driver capable of support volume snapshots at the [v1 API level](https://kubernetes.io/blog/2020/12/10/kubernetes-1.20-volume-snapshot-moves-to-ga/).
 1. When restoring CSI VolumeSnapshots across clusters, the name of the CSI driver in the destination cluster is the same as that on the source cluster to ensure cross cluster portability of CSI VolumeSnapshots

**NOTE:** Not all cloud provider's CSI drivers guarantee snapshot durability, meaning that the VolumeSnapshot and VolumeSnapshotContent objects may be stored in the same object storage system location as the original PersistentVolume and may be vulnerable to data loss. You should refer to your cloud provider's documentation for more information on configuring snapshot durability.  Since v0.3.0 the velero team will provide official support for CSI plugin when they are used with AWS and Azure drivers.

## Installing Velero with CSI support

To integrate Velero with the CSI volume snapshot APIs, you must enable the `EnableCSI` feature flag and install the Velero [CSI plugins][2] on the Velero server.

Both of these can be added with the `velero install` command.

```bash
velero install \
--features=EnableCSI \
--plugins=<object storage plugin>,velero/velero-plugin-for-csi:v0.5.0 \
...
```

To include the status of CSI objects associated with a Velero backup in `velero backup describe` output, run `velero client config set features=EnableCSI`.
See [Enabling Features][1] for more information about managing client-side feature flags. You can also view the image on [Docker Hub][3].

## Implementation Choices

This section documents some of the choices made during implementation of the Velero [CSI plugins][2]:

 1. VolumeSnapshots created by the Velero CSI plugins are retained only for the lifetime of the backup even if the `DeletionPolicy` on the VolumeSnapshotClass is set to `Retain`. To accomplish this, during deletion of the backup the prior to deleting the VolumeSnapshot, VolumeSnapshotContent object is patched to set its `DeletionPolicy` to `Delete`. Deleting the VolumeSnapshot object will result in cascade delete of the VolumeSnapshotContent and the snapshot in the storage provider.
 1. VolumeSnapshotContent objects created during a `velero backup` that are dangling, unbound to a VolumeSnapshot object, will be discovered, using labels, and deleted on backup deletion.
 1. The Velero CSI plugins, to backup CSI backed PVCs, will choose the VolumeSnapshotClass in the cluster that has the same driver name and also has the `velero.io/csi-volumesnapshot-class` label set on it, like
    ```yaml
      velero.io/csi-volumesnapshot-class: "true"
    ```
 1. The VolumeSnapshot objects will be removed from the cluster after the backup is uploaded to the object storage, so that the namespace that is backed up can be deleted without removing the snapshot in the storage provider if the `DeletionPolicy` is `Delete`.  

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

When Velero synchronizes backups into a new cluster, VolumeSnapshotContent objects and the VolumeSnapshotClass that is chosen to take
snapshot will be synced into the cluster as well, so that Velero can manage backup expiration appropriately.


The `DeletionPolicy` on the VolumeSnapshotContent will be the same as the `DeletionPolicy` on the VolumeSnapshotClass that was used to create the VolumeSnapshot. Setting a `DeletionPolicy` of `Retain` on the VolumeSnapshotClass will preserve the volume snapshot in the storage system for the lifetime of the Velero backup and will prevent the deletion of the volume snapshot, in the storage system, in the event of a disaster where the namespace with the VolumeSnapshot object may be lost.

When the Velero backup expires, the VolumeSnapshot objects will be deleted and the VolumeSnapshotContent objects will be updated to have a `DeletionPolicy` of `Delete`, to free space on the storage system.

For more details on how each plugin works, see the [CSI plugin repo][2]'s documentation.

**Note:** The AWS, Microsoft Azure, and Google Cloud Platform (GCP) Velero plugins version 1.4 and later are able to snapshot and restore persistent volumes provisioned by a CSI driver via the APIs of the cloud provider, without having to install Velero CSI plugins. See the [AWS](https://github.com/velero-io/velero-plugin-for-aws), [Microsoft Azure](https://github.com/velero-io/velero-plugin-for-microsoft-azure), and [Google Cloud Platform (GCP)](https://github.com/velero-io/velero-plugin-for-gcp) Velero plugin repo for more information on supported CSI drivers.

[1]: customize-installation.md#enable-server-side-features
[2]: https://github.com/vmware-tanzu/velero-plugin-for-csi/
[3]: https://hub.docker.com/repository/docker/velero/velero-plugin-for-csi
