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

1. Create a backup and wait for it to finish.

    ```bash
    velero backup create nginx-backup --include-namespaces nginx-example --wait
    ```

1. Simulate a disaster by deleting the namespace only if the backup phase is `Completed`.

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

1. Create a backup with PV snapshotting and wait for it to finish. The `--csi-snapshot-timeout` flag sets the timeout for creating a CSI snapshot. The default is 10 minutes.

    ```bash
    velero backup create nginx-pv-backup --include-namespaces nginx-example --csi-snapshot-timeout=20m --wait
    ```

1. Simulate a disaster by deleting the namespace only if the backup phase is `Completed`.

    ```bash
    kubectl delete namespaces nginx-example
    ```

    Because the default [reclaim policy][1] for dynamically-provisioned PVs is "Delete", these commands should trigger your cloud provider to delete the disk that backs the PV. Deletion is asynchronous, so this may take some time. **Before continuing to the next step, check your cloud provider to confirm that the disk no longer exists.**

1. Restore your lost resources:

    ```bash
    velero restore create --from-backup nginx-pv-backup
    ```

[1]: https://kubernetes.io/docs/concepts/storage/persistent-volumes/#reclaiming
