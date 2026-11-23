---
title: "Cache PVC Configuration for Data Movement Restore"
layout: docs
---

Velero data movement restore (i.e., for CSI snapshot data movement and fs-backup) may request the backup repository to cache data locally so as to reduce the data request from the remote backup storage.  
The cache behavior is decided by the specific backup repository, and Velero allows you to configure a cache limit for the backup repositories who support it (i.e., kopia repository). For more details, see [Backup Repository Configuration][1].  
The size of cache may significantly impact on the performance. Specifically, if the cache size is too small, the restore throughput will be severely reduced and much more data would be downloaded from the backup storage.  
By default, the cache data location is in the data mover pods' root disk. In some environments, the pods' root disk size is very limited, so a large cache size would cause the data mover pods evicted because of running out of ephemeral disk.  

To cope with the problems and guarantee the data mover pods always run with a fine tuned local cache, Velero supports dedicated cache PVCs for data movement restore, for CSI snapshot data movement and fs-backup.  

By default, Velero data mover pods run without cache PVCs. To enable cache PVC, you need to fill the cache PVC configurations in the node-agent configMap.  

A sample of cache PVC configuration as part of the ConfigMap would look like:
```json
{
    "cachePVC": {
        "residentThresholdInMB": 1024,
        "storageClass": "sc-wffc"
    }
}
```

To create the configMap, save something like the above sample to a file and then run below commands:  
```shell
kubectl create cm node-agent-config -n velero --from-file=<json file name>
```

A must-have field in the configuration is `storageClass` which tells Velero which storage class is used to provision the cache PVC. Velero relies on Kubernetes dynamic provision process to provision the PVC, static provision is not supported.  

The cache PVC behavior could be further fine tuned through `residentThresholdInMB`. Its value is compared to the size of the backup, if the size is smaller than this value, no cache PVC would be created when restoring from the backup. This ensures that cache PVCs are not created in vain when the backup size is too small and can be accommodated in the data mover pods' root disk.  

This configuration decides whether and how to provision cache PVCs, but it doesn't decide their size. Instead, the size is decided by the specific backup repository. Specifically, Velero asks a cache limit from the backup repository and uses this limit to calculate the cache PVC size.  
The cache limit is decided by the backup repository itself, for Kopia repository, if `cacheLimitMB` is specified in the backup repository configuration, its value will be used; otherwise, a default limit (5 GB) is used.  
Then Velero inflates the limit by 20% by considering the non-payload overheads and delay cache cleanup behavior varying on backup repositories.    

Take Kopia repository and the above cache PVC configuration for example:  
- When `cacheLimitMB` is not available for the repository, a 6GB cache PVC is created for the backup that is larger than 1GB; otherwise, no cache volume is created
- When `cacheLimitMB` is specified as `10240` for the repository, a 12GB cache PVC is created for the backup that is larger than 1GB; otherwise, no cache volume is created  

To enable both the node-agent configMap and backup repository configMap, specify the flags in velero installation by CLI:
`velero install --node-agent-configmap=<ConfigMap-Name> --backup-repository-configmap=<ConfigMap-Name>`

## Related Documentation

- [Node-agent Configuration](supported-configmaps/node-agent-configmap.md) - Complete reference for all configuration options
- [Node-agent Concurrency](node-agent-concurrency.md) - Configure concurrent operations per node
- [Node Selection for Data Movement](data-movement-node-selection.md) - Configure which nodes run data movement
- [Data Movement Pod Resource Configuration](data-movement-pod-resource-configuration.md) - Configure pod resources
- [BackupPVC Configuration](data-movement-backup-pvc-configuration.md) - Configure backup storage
- [RestorePVC Configuration](data-movement-restore-pvc-configuration.md) - Configure restore storage
- [Cache PVC Configuration](data-movement-cache-volume.md) - Configure restore data mover storage

[1]: backup-repository-configuration.md
