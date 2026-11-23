---
title: "Manual Testing Requirements for Velero"
layout: docs
---

Although we have automated unit and end-to-end tests, there is still a need for Velero to undergo manual tests during a release.
This document outlines the manual test operations that Velero needs to correctly perform in order to be considered ready for release.

## Current test cases

The following are test cases that are currently performed as part of a Velero release.

### Install

- Verify that Velero CRDs are compatible with the earliest and latest versions of Kubernetes that we support:
  - Kubernetes v1.12
  - Kubernetes v1.20

### Upgrade

- Verify that Velero upgrade instructions work

### Basic functionality

The "Backup and Restore" test cases below describe general backup and restore functionality that needs to run successfully on all the following providers that we maintain plugins for:
- AWS
- GCP
- Microsoft Azure
- VMware vSphere

#### Backup and Restore

- Verify that a backup and restore using Volume Snapshots can be performed
- Verify that a backup and restore using File System Backup can be performed
- Verify that a backup of a cluster workload can be restored in a new cluster
- Verify that an installation using the latest version can be used to restore from backups created with the last 3 versions.
  - e.g. Install Velero 1.6 and use it to restore backups from Velero v1.3, v1.4, v1.5.

### Working with Multiple Providers

The following are test cases that exercise Velero behaviour when interacting with multiple providers:

- Verify that a backup and restore to multiple BackupStorageLocations using the same provider with unique credentials can be performed
- Verify that a backup and restore to multiple BackupStorageLocations using different providers with unique credentials can be performed
- Verify that a backup and restore that includes volume snapshots using different providers for the snapshots and object storage can be performed
  - e.g. perform a backup and restore using AWS for the VolumeSnapshotLocation and Azure Blob Storage as the BackupStorageLocation

## Future test cases

The following are test cases that are not currently performed as part of a Velero release but cases that we will want to cover with future releases.

### Schedules

- Verify that schedules create a backup upon creation and create Backup resources at the correct frequency

### Resource management

- Verify that deleted backups are successfully removed from object storage
- Verify that backups that have been removed from object storage can still be deleted with `velero delete backup`
- Verify that Volume Snapshots associated with a deleted backup are removed
- Verify that backups that exceed their TTL are deleted
- Verify that existing backups in object storage are synced to Velero

### Backup repository test cases

- Verify that backup repository maintenance is performed as the specified interval

### Backup Hooks

- Verify that a pre backup hook provided via pod annotation is performed during backup
- Verify that a pre backup hook provided via Backup spec is performed during backup
- Verify that a post backup hook provided via pod annotation is performed during backup
- Verify that a post backup hook provided via Backup spec is performed during backup

### Restore Hooks

- Verify that an InitContainer restore hook provided via pod annotation is performed during restore
- Verify that an InitContainer restore hook provided via Restore spec is performed during restore
- Verify that an InitContainer restore hook provided via Restore spec is performed during restore that includes restoring File System Backup volumes
- Verify that an Exec restore hook provided via pod annotation is performed during restore
- Verify that an Exec restore hook provided via Restore spec is performed during restore


#### Resource filtering

- Verify that backups and restores correctly apply the following resource filters:
  - `--include-namespaces`
  - `--include-resources`
  - `--include-cluster-resources`
  - `--exclude-namespaces`
  - `--exclude-resources`
  - `velero.io/exclude-from-backup=true` label

- Since v1.11, new resource filters are added. The new filters only work for backup, and cannot work with old filters (`--include-resources`, `--exclude-resources` and `--include-cluster-resources`). Need to verify backups correctly apply the following new resource filters:
  - `--exclude-cluster-scoped-resources`
  - `--include-cluster-scoped-resources`
  - `--exclude-namespace-scoped-resources` 
  - `--include-namespace-scoped-resources`
