---
title: "Examples"
layout: docs
---

After you set up the Velero server, you can clone the examples used in the following sections by running the following:
```
git clone https://github.com/velero-io/velero.git
cd velero
```

## Basic example (without PersistentVolumes)

1. Start the sample nginx app:

    ```bash
    kubectl apply -f examples/nginx-app/base.yaml
    ```

1. Create a backup:

    ```bash
    velero backup create nginx-backup --include-namespaces nginx-example
    ```

1. Simulate a disaster:

    ```bash
    kubectl delete namespaces nginx-example
    ```

    Wait for the namespace to be deleted.

1. Restore your lost resources:

    ```bash
    velero restore create --from-backup nginx-backup
    ```

## Snapshot example (with PersistentVolumes)

> NOTE: For Azure, you must run Kubernetes version 1.7.2 or later to support PV snapshotting of managed disks.

1. Start the sample nginx app:

    ```bash
    kubectl apply -f examples/nginx-app/with-pv.yaml
    ```

1. Create a backup with PV snapshotting:

    ```bash
    velero backup create nginx-backup --include-namespaces nginx-example
    ```

1. Simulate a disaster:

    ```bash
    kubectl delete namespaces nginx-example
    ```

    Because the default [reclaim policy][1] for dynamically-provisioned PVs is "Delete", these commands should trigger your cloud provider to delete the disk that backs the PV. Deletion is asynchronous, so this may take some time. **Before continuing to the next step, check your cloud provider to confirm that the disk no longer exists.**

1. Restore your lost resources:

    ```bash
    velero restore create --from-backup nginx-backup
    ```

[1]: https://kubernetes.io/docs/concepts/storage/persistent-volumes/#reclaiming
