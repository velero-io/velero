---
title: "Cluster migration"
layout: docs
---

Velero's backup and restore capabilities make it a valuable tool for migrating your data between clusters. Cluster migration with Velero is based on Velero's [object storage sync](how-velero-works.md#object-storage-sync) functionality, which is responsible for syncing Velero resources from your designated object storage to your cluster. This means that to perform cluster migration with Velero you must point each Velero instance running on clusters involved with the migration to the same cloud object storage location.

This page outlines a cluster migration scenario and some common configurations you will need to start using Velero to begin migrating data.

## Before migrating your cluster

Before migrating you should consider the following,

* Velero does not natively support the migration of persistent volumes snapshots across cloud providers. If you would like to migrate volume data between cloud platforms, enable [File System Backup](file-system-backup.md), which will backup volume contents at the filesystem level.
* Velero doesn't support restoring into a cluster with a lower Kubernetes version than where the backup was taken.
* Migrating workloads across clusters that are not running the same version of Kubernetes might be possible, but some factors need to be considered before migration, including the compatibility of API groups between clusters for each custom resource. If a Kubernetes version upgrade breaks the compatibility of core/native API groups, migrating with Velero will not be possible without first updating the impacted custom resources. For more information about API group versions, please see [EnableAPIGroupVersions](enable-api-group-versions-feature.md).
* The Velero plugin for AWS and Azure does not support migrating data between regions. If you need to do this, you must use [File System Backup](file-system-backup.md).


## Migration Scenario

This scenario steps through the migration of resources from Cluster 1 to Cluster 2. In this scenario, both clusters are using the same cloud provider, AWS, and Velero's [AWS plugin](https://github.com/velero-io/velero-plugin-for-aws).

1. On Cluster 1, make sure Velero is installed and points to an object storage location using the `--bucket` flag.

    ```
    velero install --provider aws --image velero/velero:v1.8.0 --plugins velero/velero-plugin-for-aws:v1.4.0 --bucket velero-migration-demo --secret-file xxxx/aws-credentials-cluster1 --backup-location-config region=us-east-2 --snapshot-location-config region=us-east-2
    ```

    During installation, Velero creates a Backup Storage Location called `default` inside the `--bucket` your provided in the install command, in this case `velero-migration-demo`. This is the location that Velero will use to store backups. Running `velero backup-location get` will show the backup location of Cluster 1.


    ```
    velero backup-location get
    NAME      PROVIDER   BUCKET/PREFIX           PHASE       LAST VALIDATED                  ACCESS MODE   DEFAULT
    default   aws        velero-migration-demo   Available   2022-05-13 13:41:30 +0800 CST   ReadWrite     true
    ```

1. Still on Cluster 1, make sure you have a backup of your cluster. Replace `<BACKUP-NAME>` with a name for your backup.

    ```
    velero backup create <BACKUP-NAME>
    ```

    Alternatively, you can create a [scheduled backup](https://velero.io/docs/main/backup-reference/#schedule-a-backup) of your data with the Velero `schedule` operation. This is the recommended way to make sure your data is automatically backed up according to the schedule you define.

    The default backup retention period, expressed as TTL (time to live), is 30 days (720 hours); you can use the `--ttl <DURATION>` flag to change this as necessary. See [how velero works](how-velero-works.md#set-a-backup-to-expire) for more information about backup expiry.

1. On Cluster 2, make sure that Velero is installed. Note that the install command below has the same `region` and `--bucket` location as the install command for Cluster 1. The Velero plugin for AWS does not support migrating data between regions.

    ```
    velero install --provider aws --image velero/velero:v1.8.0 --plugins velero/velero-plugin-for-aws:v1.4.0 --bucket velero-migration-demo --secret-file xxxx/aws-credentials-cluster2 --backup-location-config region=us-east-2 --snapshot-location-config region=us-east-2
    ```

    Alternatively you could configure `BackupStorageLocations` and `VolumeSnapshotLocations` after installing Velero on Cluster 2, pointing to the `--bucket` location and  `region` used by Cluster 1. To do this you can use to `velero backup-location create` and `velero snapshot-location create` commands.

    ```
    velero backup-location create bsl --provider aws --bucket velero-migration-demo --config region=us-east-2 --access-mode=ReadOnly
    ```

    Its recommended that you configure the `BackupStorageLocations` as read-only
    by using the `--access-mode=ReadOnly` flag for `velero backup-location create`. This will make sure that the backup is not deleted from the object store by mistake during the restore. See `velero backup-location –help` for more information about the available flags for this command.

    ```
    velero snapshot-location create vsl --provider aws --config region=us-east-2
    ```
    See `velero snapshot-location –help` for more information about the available flags for this command.


1.  Continuing on Cluster 2, make sure that the Velero Backup object created on Cluster 1 is available. `<BACKUP-NAME>` should be the same name used to create your backup of Cluster 1.

    ```
    velero backup describe <BACKUP-NAME>
    ```

    Velero resources are [synchronized](how-velero-works.md#object-storage-sync) with the backup files in object storage. This means that the Velero resources created by Cluster 1's backup will be synced to Cluster 2 through the shared Backup Storage Location. Once the sync occurs, you will be able to access the backup from Cluster 1 on Cluster 2 using Velero commands. The default sync interval is 1 minute, so you may need to wait before checking for the backup's availability on Cluster 2. You can configure this interval with the `--backup-sync-period` flag to the Velero server on Cluster 2.

1.  On Cluster 2, once you have confirmed that the right backup is available, you can restore everything to Cluster 2.

    ```
    velero restore create --from-backup <BACKUP-NAME>
    ```

    Make sure `<BACKUP-NAME>` is the same backup name from Cluster 1.

## Verify Both Clusters

Check that the Cluster 2 is behaving as expected:

1.  On Cluster 2, run:

    ```
    velero restore get
    ```

1.  Then run:

    ```
    velero restore describe <RESTORE-NAME-FROM-GET-COMMAND>
    ```

    Your data that was backed up from Cluster 1 should now be available on Cluster 2.

If you encounter issues, make sure that Velero is running in the same namespace in both clusters.


## Notice
If the two clusters couldn't share the snapshots generated by backup, for example migration from EKS to AKS, then please consider using [the file system backup](file-system-backup.md) or [the snapshot data mover](csi-snapshot-data-movement.md).