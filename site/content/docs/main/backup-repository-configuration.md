---
title: "Backup Repository Configuration"
layout: docs
---

Velero uses selectable backup repositories for various backup/restore methods, i.e., [file-system backup][1], [CSI snapshot data movement][2], etc. To achieve the best performance, backup repositories may need to be configured according to the running environments.  

Velero uses a BackupRepository CR to represent the instance of the backup repository. Now, a new field `repositoryConfig` is added to support various configurations to the underlying backup repository.  

Velero also allows you to specify configurations before the BackupRepository CR is created through a configMap. The configurations in the configMap will be copied to the BackupRepository CR when it is created at the due time.  
The configMap should be in the same namespace where Velero is installed. If multiple Velero instances are installed in different namespaces, there should be one configMap in each namespace which applies to Velero instance in that namespace only. The name of the configMap should be specified in the Velero server parameter `--backup-repository-configmap`.  


The users can specify the ConfigMap name during velero installation by CLI:
`velero install --backup-repository-configmap=<ConfigMap-Name>`

Conclusively, you have two ways to add/change/delete configurations of a backup repository:  
- If the BackupRepository CR for the backup repository is already there, you should modify the `repositoryConfig` field. The new changes will be applied to the backup repository at the due time, it doesn't require Velero server to restart.   
- Otherwise, you can create the backup repository configMap as a template for the BackupRepository CRs that are going to be created.  

The backup repository configMap is repository type (i.e., kopia, restic) specific, so for one repository type, you only need to create one set of configurations, they will be applied to all BackupRepository CRs of the same type. Whereas, the changes of `repositoryConfig` field apply to the specific BackupRepository CR only, you may need to change every BackupRepository CR of the same type.  

Below is an example of the BackupRepository configMap with the configurations:  
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: <config-name>
  namespace: velero
data:
  <kopia>: |
    {
      "cacheLimitMB": 2048,
      "fullMaintenanceInterval": "fastGC",
      "ThrottleUploadBytes": "838860800",
      "ThrottleDownloadBytes": "838860800"
    }
  <other-repository-type>: |
    {
      "cacheLimitMB": 1024   
    } 
```

To create the configMap, you need to save something like the above sample to a file and then run below commands:  
```shell
kubectl apply -f <yaml-file-name>
```

When and how the configurations are used is decided by the backup repository itself. Though you can specify any configuration to the configMap or `repositoryConfig`, the configuration may/may not be used by the backup repository, or the configuration may be used at an arbitrary time.  

Below is the supported configurations by Velero and the specific backup repository.  
***Kopia repository:***  
`cacheLimitMB`: specifies the size limit(in MB) for the local data cache. The more data is cached locally, the less data may be downloaded from the backup storage, so the better performance may be achieved. Practically, you can specify any size that is smaller than the free space so that the disk space won't run out. This parameter is for repository connection, that is, you could change it before connecting to the repository. E.g., before a backup/restore/maintenance.  

`fullMaintenanceInterval`: The full maintenance interval defaults to kopia defaults of 24 hours. Override options below allows for faster removal of deleted velero backups from kopia repo.
- normalGC: 24 hours
- fastGC: 12 hours
- eagerGC: 6 hours

Per kopia [Maintenance Safety](https://kopia.io/docs/advanced/maintenance/#maintenance-safety), it is expected that velero backup deletion will not result in immediate kopia repository data removal. Reducing full maintenance interval using above options should help reduce time taken to remove blobs not in use.

On the other hand, the not-in-use data will be deleted permanently after the full maintenance, so shorter full maintenance intervals may weaken the data safety if they are used incorrectly.

`ThrottleUploadBytes`: specifies the maximum upload speed in bytes per second for the repository. This can be used to throttle the upload bandwidth. The value should be specified as a string representing bytes per second (e.g., "838860800" for ~800 MB/s). This parameter applies during repository operations that write data.

`ThrottleDownloadBytes`: specifies the maximum download speed in bytes per second for the repository. This can be used to throttle the download bandwidth. The value should be specified as a string representing bytes per second (e.g., "838860800" for ~800 MB/s). This parameter applies during repository operations that read data.

`ThrottleReadOPS`: specifies the maximum number of read operations per second. This can be used to throttle the rate of read operations to the storage backend.

`ThrottleWriteOPS`: specifies the maximum number of write operations per second. This can be used to throttle the rate of write operations to the storage backend.

`ThrottleListOPS`: specifies the maximum number of list operations per second. This can be used to throttle the rate of list operations to the storage backend.

[1]: file-system-backup.md
[2]: csi-snapshot-data-movement.md
