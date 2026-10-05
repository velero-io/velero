---
title: "FAQ"
layout: docs
---

## When is it appropriate to use Velero instead of etcd's built in backup/restore?

Etcd's backup/restore tooling is good for recovering from data loss in a single etcd cluster. For
example, it is a good idea to take a backup of etcd prior to upgrading etcd itself. For more
sophisticated management of your Kubernetes cluster backups and restores, we feel that Velero is
generally a better approach. It gives you the ability to throw away an unstable cluster and restore
your Kubernetes resources and data into a new cluster, which you can't do easily just by backing up
and restoring etcd.

Examples of cases where Velero is useful:

* you don't have access to etcd (e.g. you're running on GKE)
* backing up both Kubernetes resources and persistent volume state
* cluster migrations
* backing up a subset of your Kubernetes resources
* backing up Kubernetes resources that are stored across multiple etcd clusters (for example if you
  run a custom apiserver)

## Will Velero restore my Kubernetes resources exactly the way they were before?

Yes, with some exceptions. For example, when Velero restores pods it deletes the `nodeName` from the
pod so that it can be scheduled onto a new node. You can see some more examples of the differences
in [pod_action.go](https://github.com/velero-io/velero/blob/v1.3.0/pkg/restore/pod_action.go)

## I'm using Velero in multiple clusters. Should I use the same bucket to store all of my backups?

We **strongly** recommend that each Velero instance use a distinct bucket/prefix combination to store backups.
Having multiple Velero instances write backups to the same  bucket/prefix combination can lead to numerous 
problems - failed backups, overwritten backups, inadvertently deleted backups, etc., all of which can be 
avoided by using a separate bucket + prefix per Velero instance. 

It's fine to have multiple Velero instances back up to the same bucket if each instance uses its own
prefix within the bucket. This can be configured in your `BackupStorageLocation`, by setting the 
`spec.objectStorage.prefix` field. It's also fine to use a distinct bucket for each Velero instance, 
and not to use prefixes at all.

Related to this, if you need to restore a backup that was created in cluster A into cluster B, you may 
configure cluster B with a backup storage location that points to cluster A's bucket/prefix. If you do
this, you should configure the storage location pointing to cluster A's bucket/prefix in `ReadOnly` mode
via the `--access-mode=ReadOnly` flag on the `velero backup-location create` command. This will ensure no
new backups are created from Cluster B in Cluster A's bucket/prefix, and no existing backups are deleted
or overwritten.
