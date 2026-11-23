---
title: "Debugging Restores"
layout: docs
---

## Example

When Velero finishes a Restore, its status changes to "Completed" regardless of whether or not there are issues during the process. The number of warnings and errors are indicated in the output columns from `velero restore get`:

```
NAME                          BACKUP          STATUS      WARNINGS   ERRORS    CREATED                         SELECTOR
backup-test-20170726180512    backup-test     Completed   155        76        2017-07-26 11:41:14 -0400 EDT   <none>
backup-test-20170726180513    backup-test     Completed   121        14        2017-07-26 11:48:24 -0400 EDT   <none>
backup-test-2-20170726180514  backup-test-2   Completed   0          0         2017-07-26 13:31:21 -0400 EDT   <none>
backup-test-2-20170726180515  backup-test-2   Completed   0          1         2017-07-26 13:32:59 -0400 EDT   <none>
```

To delve into the warnings and errors into more detail, you can use `velero restore describe`:

```bash
velero restore describe backup-test-20170726180512
```

The output looks like this:

```
Name:         backup-test-20170726180512
Namespace:    velero
Labels:       <none>
Annotations:  <none>

Backup:  backup-test

Namespaces:
  Included:  *
  Excluded:  <none>

Resources:
  Included:        serviceaccounts
  Excluded:        nodes, events, events.events.k8s.io
  Cluster-scoped:  auto

Namespace mappings:  <none>

Label selector:  <none>

Restore PVs:  auto

Preserve Service NodePorts:  auto

Phase:  Completed

Validation errors:  <none>

Warnings:
  Velero:     <none>
  Cluster:    <none>
  Namespaces:
    velero:       serviceaccounts "velero" already exists
                  serviceaccounts "default" already exists
    kube-public:  serviceaccounts "default" already exists
    kube-system:  serviceaccounts "attachdetach-controller" already exists
                  serviceaccounts "certificate-controller" already exists
                  serviceaccounts "cronjob-controller" already exists
                  serviceaccounts "daemon-set-controller" already exists
                  serviceaccounts "default" already exists
                  serviceaccounts "deployment-controller" already exists
                  serviceaccounts "disruption-controller" already exists
                  serviceaccounts "endpoint-controller" already exists
                  serviceaccounts "generic-garbage-collector" already exists
                  serviceaccounts "horizontal-pod-autoscaler" already exists
                  serviceaccounts "job-controller" already exists
                  serviceaccounts "kube-dns" already exists
                  serviceaccounts "namespace-controller" already exists
                  serviceaccounts "node-controller" already exists
                  serviceaccounts "persistent-volume-binder" already exists
                  serviceaccounts "pod-garbage-collector" already exists
                  serviceaccounts "replicaset-controller" already exists
                  serviceaccounts "replication-controller" already exists
                  serviceaccounts "resourcequota-controller" already exists
                  serviceaccounts "service-account-controller" already exists
                  serviceaccounts "service-controller" already exists
                  serviceaccounts "statefulset-controller" already exists
                  serviceaccounts "ttl-controller" already exists
    default:      serviceaccounts "default" already exists

Errors:
  Velero:     <none>
  Cluster:    <none>
  Namespaces: <none>
```

## Structure

Errors appear for incomplete or partial restores. Warnings appear for non-blocking issues, for example, the
restore looks "normal" and all resources referenced in the backup exist in some form, although some
of them may have been pre-existing.

Both errors and warnings are structured in the same way:

* `Velero`: A list of system-related issues encountered by the Velero server. For example, Velero couldn't read a directory.

* `Cluster`: A list of issues related to the restore of cluster-scoped resources.

* `Namespaces`: A map of namespaces to the list of issues related to the restore of their respective resources.
