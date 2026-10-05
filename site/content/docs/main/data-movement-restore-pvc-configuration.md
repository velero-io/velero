---
title: "RestorePVC Configuration for Data Movement Restore"
layout: docs
---

`RestorePVC`  is an intermediate PVC to write data during the data movement restore operation.

In some scenarios users may need to configure some advanced options of the `restorePVC` so that the data movement restore operation could perform better. Specifically:
- For a volume with `WaitForFirstConsumer` mode, theoretically, the data mover pod should not be created until the restored is scheduled to a node; and the data movement should happen in that node only (because the pod may not run in every node because of topology constraints). This significantly degrades the parallelism of data movement restores; and this also prevents Velero from restoring a volume without a pod mounted. On the other hand, users must know their topology constrains if they have, or they must know in which nodes their restored workload pods can be scheduled. Therefore, in the backup/restore context, it is fine not to strictly follow the rule of `WaitForFirstConsumer` mode, instead, users should be allowed to configure to ignore the rule if they are aware that there is no topology constraints in their environments or they know how to select the nodes for restore pods to run appropriately.

Velero introduces a new section in the node agent configuration ConfigMap (the name of this ConfigMap is passed using `--node-agent-configmap` velero server argument) called `restorePVC`, through which you can specify the following configurations:

- `ignoreDelayBinding`: If this flag is set, the data movement restore will ignore the delay binding requirements from `WaitForFirstConsumer` mode, create the restore pod and provision the volume associated to an arbitrary node. When multiple volume restores happen in parallel, the restore pods will be spread evenly to all the nodes.

- `secretNames`: a list of secret names to copy from the target (restore) namespace to the Velero namespace before the restorePVC is created, and delete after the DataDownload completes. This is needed for CSI drivers that require namespace-scoped secrets to provision the volume, for example ODF/ceph-csi encrypted volumes that fetch a KMS token secret (`ceph-csi-kms-token`) from the PVC's namespace. Without this, the restorePVC created in the Velero namespace fails to provision because the secret only exists in the target namespace.

- `configMapNames`: a list of configmap names to copy from the target (restore) namespace to the Velero namespace before the restorePVC is created, and delete after the DataDownload completes. This is needed for CSI drivers that require namespace-scoped configmaps to provision the volume, for example a tenant-specific ceph-csi KMS connection override configmap (`ceph-csi-kms-config`).


The users can specify the ConfigMap name during velero installation by CLI:
`velero install --node-agent-configmap=<ConfigMap-Name>`

A sample of `restorePVC` config as part of the ConfigMap would look like:
```json
{
    "restorePVC": {
        "ignoreDelayBinding": true,
        "secretNames": ["ceph-csi-kms-token"],
        "configMapNames": ["ceph-csi-kms-config"]
    }
}
```

**Note on encrypted volumes:** unlike `backupPVC` (which is keyed per source storage class), `restorePVC` is a single config that applies to all restore PVCs. The copied secrets/configmaps are labeled `velero.io/backup-pvc-secret=<DataDownload UID>` and deleted when the DataDownload completes (or on failure).

**Note:** 
- If `ignoreDelayBinding` is set, the restored volume is provisioned in the storage areas associated to an arbitrary node, if the restored pod cannot be scheduled to that node, e.g., because of topology constraints, the data mover restore still completes, but the workload is not usable since the restored pod cannot mount the restored volume
- At present, node selection is not supported for data mover restore, so the restored volume may be attached to any node in the cluster; once node selection is supported and enabled, the restored volume will be attached to one of the selected nodes only. In this way, node selection and `ignoreDelayBinding` can work together even though the environment is with topology constraints

## Related Documentation

- [Node-agent Configuration](supported-configmaps/node-agent-configmap.md) - Complete reference for all configuration options
- [Node-agent Concurrency](node-agent-concurrency.md) - Configure concurrent operations per node
- [Node Selection for Data Movement](data-movement-node-selection.md) - Configure which nodes run data movement
- [Data Movement Pod Resource Configuration](data-movement-pod-resource-configuration.md) - Configure pod resources
- [BackupPVC Configuration](data-movement-backup-pvc-configuration.md) - Configure backup storage
- [RestorePVC Configuration](data-movement-restore-pvc-configuration.md) - Configure restore storage
- [Cache PVC Configuration](data-movement-cache-volume.md) - Configure restore data mover storage
