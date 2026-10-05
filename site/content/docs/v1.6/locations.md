---
title: "Backup Storage Locations and Volume Snapshot Locations"
layout: docs
---

## Overview

Velero has two custom resources, `BackupStorageLocation` and `VolumeSnapshotLocation`, that are used to configure where Velero backups and their associated persistent volume snapshots are stored.

A `BackupStorageLocation` is defined as a bucket or a prefix within a bucket under which all Velero data is stored and a set of additional provider-specific fields (AWS region, Azure storage account, etc.). Velero assumes it has control over the location you provide so you should use a dedicated bucket or prefix. If you provide a prefix, then the rest of the bucket is safe to use for multiple purposes. The [API documentation][1] captures the configurable parameters for each in-tree provider.

A `VolumeSnapshotLocation` is defined entirely by provider-specific fields (AWS region, Azure resource group, Portworx snapshot type, etc.) The [API documentation][2] captures the configurable parameters for each in-tree provider.

The user can pre-configure one or more possible `BackupStorageLocations` and one or more `VolumeSnapshotLocations`, and can select *at backup creation time* the location in which the backup and associated snapshots should be stored.

This configuration design enables a number of different use cases, including:

- Take snapshots of more than one kind of persistent volume in a single Velero backup. For example, in a cluster with both EBS volumes and Portworx volumes
- Have some Velero backups go to a bucket in an eastern USA region, and others go to a bucket in a western USA region, or to a different storage provider
- For volume providers that support it, like Portworx, you can have some snapshots stored locally on the cluster and have others stored in the cloud

## Limitations / Caveats

- Velero supports multiple credentials for `BackupStorageLocations`, allowing you to specify the credentials to use with any `BackupStorageLocation`.
  However, use of this feature requires support within the plugin for the object storage provider you wish to use.
  All [plugins maintained by the Velero team][5] support this feature.
  If you are using a plugin from another provider, please check their documentation to determine if this feature is supported.

- Velero only supports a single set of credentials for `VolumeSnapshotLocations`.
  Velero will always use the credentials provided at install time (stored in the `cloud-credentials` secret) for volume snapshots.

- Volume snapshots are still limited by where your provider allows you to create snapshots. For example, AWS and Azure do not allow you to create a volume snapshot in a different region than where the volume is. If you try to take a Velero backup using a volume snapshot location with a different region than where your cluster's volumes are, the backup will fail.

- Each Velero backup has one `BackupStorageLocation`, and one `VolumeSnapshotLocation` per volume provider. It is not possible (yet) to send a single Velero backup to multiple backup storage locations simultaneously, or a single volume snapshot to multiple locations simultaneously. However, you can always set up multiple scheduled backups that differ only in the storage locations used if redundancy of backups across locations is important.

- Cross-provider snapshots are not supported. If you have a cluster with more than one type of volume, like EBS and Portworx, but you only have a `VolumeSnapshotLocation` configured for EBS, then Velero will **only** snapshot the EBS volumes.

- Restic data is stored under a prefix/subdirectory of the main Velero bucket, and will go into the bucket corresponding to the `BackupStorageLocation` selected by the user at backup creation time.

- Velero's backups are split into 2 pieces - the metadata stored in object storage, and snapshots/backups of the persistent volume data. Right now, Velero *itself* does not encrypt either of them, instead it relies on the native mechanisms in the object and snapshot systems. A special case is restic, which backs up the persistent volume data at the filesystem level and send it to Velero's object storage.

- Velero's compression for object metadata is limited, using Golang's tar implementation. In most instances, Kubernetes objects are limited to 1.5MB in size, but many don't approach that, meaning that compression may not be necessary. Note that restic has not yet implemented compression, but does have de-deduplication capabilities.

## Examples

Let's look at some examples of how you can use this configuration mechanism to address some common use cases:

### Take snapshots of more than one kind of persistent volume in a single Velero backup

During server configuration:

```shell
velero snapshot-location create ebs-us-east-1 \
    --provider aws \
    --config region=us-east-1

velero snapshot-location create portworx-cloud \
    --provider portworx \
    --config type=cloud
```

During backup creation:

```shell
velero backup create full-cluster-backup \
    --volume-snapshot-locations ebs-us-east-1,portworx-cloud
```

Alternately, since in this example there's only one possible volume snapshot location configured for each of our two providers (`ebs-us-east-1` for `aws`, and `portworx-cloud` for `portworx`), Velero doesn't require them to be explicitly specified when creating the backup:

```shell
velero backup create full-cluster-backup
```

### Have some Velero backups go to a bucket in an eastern USA region (default), and others go to a bucket in a western USA region

In this example, two `BackupStorageLocations` will be created within the same account but in different regions.
They will both use the credentials provided at install time and stored in the `cloud-credentials` secret.
If you need to configure unique credentials for each `BackupStorageLocation`, please refer to the [later example][8].

During server configuration:

```shell
velero backup-location create backups-primary \
    --provider aws \
    --bucket velero-backups \
    --config region=us-east-1 \
    --default

velero backup-location create backups-secondary \
    --provider aws \
    --bucket velero-backups \
    --config region=us-west-1
```

A "default" backup storage location (BSL) is where backups get saved to when no BSL is specified at backup creation time.

You can change the default backup storage location at any time by setting the `--default` flag using the
`velero backup-location set` command and configure a different location to be the default.

Examples:

```shell
velero backup-location set backups-secondary --default
```



During backup creation:

```shell
velero backup create full-cluster-backup
```

Or:

```shell
velero backup create full-cluster-alternate-location-backup \
    --storage-location backups-secondary
```

### For volume providers that support it (like Portworx), have some snapshots be stored locally on the cluster and have others be stored in the cloud

During server configuration:

```shell
velero snapshot-location create portworx-local \
    --provider portworx \
    --config type=local

velero snapshot-location create portworx-cloud \
    --provider portworx \
    --config type=cloud
```

During backup creation:

```shell
# Note that since in this example you have two possible volume snapshot locations for the Portworx
# provider, you need to explicitly specify which one to use when creating a backup. Alternately,
# you can set the --default-volume-snapshot-locations flag on the `velero server` command (run by
# the Velero deployment) to specify which location should be used for each provider by default, in
# which case you don't need to specify it when creating a backup.
velero backup create local-snapshot-backup \
    --volume-snapshot-locations portworx-local
```

Or:

```shell
velero backup create cloud-snapshot-backup \
    --volume-snapshot-locations portworx-cloud
```

### Use a single location

If you don't have a use case for more than one location, it's still easy to use Velero. Let's assume you're running on AWS, in the `us-west-1` region:

During server configuration:

```shell
velero backup-location create backups-primary \
    --provider aws \
    --bucket velero-backups \
    --config region=us-west-1 \
    --default

velero snapshot-location create ebs-us-west-1 \
    --provider aws \
    --config region=us-west-1
```

During backup creation:

```shell
# Velero will automatically use your configured backup storage location and volume snapshot location.
# Nothing needs to be specified when creating a backup.
velero backup create full-cluster-backup
```

### Create a storage location that uses unique credentials

It is possible to create additional `BackupStorageLocations` that use their own credentials.
This enables you to save backups to another storage provider or to another account with the storage provider you are already using.

If you create additional `BackupStorageLocations` without specifying the credentials to use, Velero will use the credentials provided at install time and stored in the `cloud-credentials` secret.
Please see the [earlier example][9] for details on how to create multiple `BackupStorageLocations` that use the same credentials.

#### Prerequisites
- This feature requires support from the [object storage provider plugin][5] you wish to use.
  All plugins maintained by the Velero team support this feature.
  If you are using a plugin from another provider, please check their documentation to determine if this is supported.
- The [plugin for the object storage provider][5] you wish to use must be [installed][6].
- You must create a file with the object storage credentials. Follow the instructions provided by your object storage provider plugin to create this file.

Once you have installed the necessary plugin and created the credentials file, create a [Kubernetes Secret][7] in the Velero namespace that contains these credentials:

```shell
kubectl create secret generic -n velero credentials --from-file=bsl=</path/to/credentialsfile>
```

This will create a secret named `credentials` with a single key (`bsl`) which contains the contents of your credentials file.
Next, create a `BackupStorageLocation` that uses this Secret by passing the Secret name and key in the `--credential` flag.
When interacting with this `BackupStroageLocation` in the future, Velero will fetch the data from the key within the Secret you provide.

For example, a new `BackupStorageLocation` with a Secret would be configured as follows:

```bash
velero backup-location create <bsl-name> \
  --provider <provider> \
  --bucket <bucket> \
  --config region=<region> \
  --credential=<secret-name>=<key-within-secret>
```

The `BackupStorageLocation` is ready to use when it has the phase `Available`.
You can check the status with the following command:

```bash
velero backup-location get
```

To use this new `BackupStorageLocation` when performing a backup, use the flag `--storage-location <bsl-name>` when running `velero backup create`.
You may also set this new `BackupStorageLocation` as the default with the command `velero backup-location set --default <bsl-name>`.

### Modify the credentials used by an existing storage location

By default, `BackupStorageLocations` will use the credentials provided at install time and stored in the `cloud-credentials` secret in the Velero namespace.
You can modify these existing credentials by [editing the `cloud-credentials` secret][10], however, these changes will apply to all locations using this secret.
This may be the desired outcome, for example, in the case where you wish to rotate the credentials used for a particular account.

You can also opt to modify an existing `BackupStorageLocation` such that it uses its own credentials by using the `backup-location set` command.

If you have a credentials file that you wish to use for a `BackupStorageLocation`, follow the instructions above to create the Secret with that file in the Velero namespace.

Once you have created the Secret, or have an existing Secret which contains the credentials you wish to use for your `BackupStorageLocation`, set the credential to use as follows:

```bash
velero backup-location set <bsl-name> \
  --credential=<secret-name>=<key-within-secret>
```

## Additional Use Cases

1. If you're using Azure's AKS, you may want to store your volume snapshots outside of the "infrastructure" resource group that is automatically created when you create your AKS cluster. This is possible using a `VolumeSnapshotLocation`, by specifying a `resourceGroup` under the `config` section of the snapshot location. See the [Azure volume snapshot location documentation][3] for details.

1. If you're using Azure, you may want to store your Velero backups across multiple storage accounts and/or resource groups/subscriptions. This is possible using a `BackupStorageLocation`, by specifying a `storageAccount`, `resourceGroup` and/or `subscriptionId`, respectively, under the `config` section of the backup location. See the [Azure backup storage location documentation][4] for details.



[1]: api-types/backupstoragelocation.md
[2]: api-types/volumesnapshotlocation.md
[3]: https://github.com/velero-io/velero-plugin-for-microsoft-azure/blob/main/volumesnapshotlocation.md
[4]: https://github.com/velero-io/velero-plugin-for-microsoft-azure/blob/main/backupstoragelocation.md
[5]: /plugins
[6]: overview-plugins.md
[7]: https://kubernetes.io/docs/concepts/configuration/secret/
[8]: #create-a-storage-location-that-uses-unique-credentials
[9]: #have-some-velero-backups-go-to-a-bucket-in-an-eastern-usa-region-default-and-others-go-to-a-bucket-in-a-western-usa-region
[10]: https://kubernetes.io/docs/concepts/configuration/secret/#editing-a-secret
