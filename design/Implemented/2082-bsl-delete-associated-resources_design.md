# Delete Backup and Restic Repo Resources when BSL is Deleted

## Abstract

Issue #2082 requested that with the command `velero backup-location delete <bsl name>` (implemented in Velero 1.6 with #3073), the following will be deleted:

- associated Velero backups (to be clear, these are custom Kubernetes resources called "backups" that are stored in the API server)
- associated Restic repositories (custom Kubernetes resources called "resticrepositories")

This design doc explains how the request will be implemented.

## Background

When a BSL resource is deleted from its Velero namespace, the associated custom Kubernetes resources, backups and Restic repositories, can no longer be used.
It makes sense to clean those resources up when a BSL is deleted.

## Goals

Update the `velero backup-location delete <bsl name>` command to delete associated backup and Restic repository resources in the same Velero namespace.

## Non Goals

[It was suggested](https://github.com/vmware-tanzu/velero/issues/2082#issuecomment-827951311) to fix bug #2697 alongside this issue.
However, I think that should be fixed separately because although it is similar (restore objects are not being deleted), it is also quite different.
One is adding a command feature update (this issue) and the other is a bug fix and each affect different parts of the code base.

## High-Level Design

Update the `velero backup-location delete <bsl name>` command to do the following:

- find in the same Velero namespace from which the BSL was deleted the associated backup resources and Restic repositories, called "backups.velero.io" and "resticrepositories.velero.io" respectively
- delete the resources found

The above logic will be added to [where BSLs are deleted](https://github.com/vmware-tanzu/velero/blob/main/pkg/cmd/cli/backuplocation/delete.go).

## Alternative Considered

I had considered deleting the backup files (the ones in json format and tarballs) in the BSL itself.
However, a standard use case is to back up a cluster and then restore into a new cluster.
Deleting the backup storage location in either location is not expected to remove all of the backups in the backup storage location and should not be done.
