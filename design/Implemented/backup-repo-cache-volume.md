# Backup Repository Cache Volume Design

## Glossary & Abbreviation

**Backup Storage**: The storage to store the backup data. Check [Unified Repository design][1] for details.  
**Backup Repository**: Backup repository is layered between BR data movers and Backup Storage to provide BR related features that is introduced in [Unified Repository design][1].  
**Velero Generic Data Path (VGDP)**: VGDP is the collective of modules that is introduced in [Unified Repository design][1]. Velero uses these modules to finish data transfer for various purposes (i.e., PodVolume backup/restore, Volume Snapshot Data Movement). VGDP modules include uploaders and the backup repository.  
**Data Mover Pods**: Intermediate pods which hold VGDP and complete the data transfer. See [VGDP Micro Service for Volume Snapshot Data Movement][2] and [VGDP Micro Service For fs-backup][3] for details.  
**Repository Maintenance Pods**: Pods for [Repository Maintenance Jobs][4], which holds VGDP to run repository maintenance.    

## Background

According to the [Unified Repository design][1] Velero uses selectable backup repositories for various backup/restore methods, i.e., fs-backup, volume snapshot data movement, etc. Some backup repositories may need to cache data on the client side for various repository operation, so as to accelerate the execution.  
In the existing [Backup Repository Configuration][5], we allow users to configure the cache data size (`cacheLimitMB`). However, the cache data is still stored in the root file system of data mover pods/repository maintenance pods, so stored in the root file system of the node. This is not good enough, reasons:  
- In many distributions, the node's system disk size is predefined, non configurable and limit, e.g., the system disk size may be 20G or less
- Velero supports concurrent data movements in each node. The cache in each of the concurrent data mover pods could quickly run out of the system disk and cause problems like pod eviction, failure of pod creation, degradation of Kubernetes QoS, etc.  

We need to allow users to prepare a dedicated location, e.g., a dedictated volume, for the cache.  
Not all backup repositories or not all backup repository operations require cache, we need to define the details when and how the cache is used.  

## Goals

- Create a mechanism for users to configure cache volumes for various pods running VGDP
- Design the workflow to assign the cache volume pod path to backup repositories
- Describe when and how the cache volume is used 

## Non-Goals

- The solution is based on [Unified Repository design][1], [VGDP Micro Service for Volume Snapshot Data Movement][2] and [VGDP Micro Service For fs-backup][3], legacy data paths are not supported. E.g., when a pod volume restore (PVR) runs with legacy Restic path, if any data is cached, the cache still resides in the root file system.  

## Solution

### Cache Data

Varying on backup repositoires, cache data may include payload data or repository metadata, e.g., indexes to the payload data chunks.  

Payload data is highly related to the backup data, and normally take the majority of the repository data as well as the cache data.

Repository metadata is related to the backup repository's chunking algorithm, data chunk mapping method, etc, and so the size is not proportional to the backup data size.  
On the other hand for some backup repository, in extreme cases, the repository metadata may be significantly large. E.g., Kopia's indexes are per chunks, if there are huge number of small files in the repository, Kopia's index data may be in the same level of or even larger than the payload data.    
However, in the cases that repository metadata data become the majority, other bottlenecks may emerge and concurrency of data movers may be significantly constrained, so the requirement to cache volumes may go away.  

Therefore, for now we only consider the cache volume requirement for payload data, and leave the consideration for metadata as a future enhancement.  

### Scenarios

Backup repository cache varies on backup repositories and backup repository operation during VGDP runs. Below are the scenarios when VGDP runs:
- Data Upload for Backup: this is the process to upload/write the backup data into the backup repository, e.g., DataUpload or PodVolumeBackup. The pieces of data is almost directly written to the repository, sometimes with a small group staying shortly in the local place. That is to say, there should not be large scale data cached for this scenario, so we don't prepare dedicated cache for this scenario.
- Repository Maintenance: Repository maintenance most often visits the backup repository's metadata and sometimes it needs to visit the file system directories from the backed up data. On the other hand, it is not practical to run concurrent maintenance jobs in one node. So the cache data is neither large nor affect the root file system too much. Therefore, we don't need to prepare dedicated cache for this scenario.
- Data Download for Restore: this is the process to download/read the backup data from the backup repository during restore, e.g., DataDownload or PodVolumeRestore. For backup repositories for which data are stored in remote backup storages (e.g., Kopia repository stores data in remote object stores), large scale of data are cached locally to accerlerate the restore. Therefore, we need dedicate cache volumes for this scenario.  
- Backup Deletion: During this scenario, backup repository is connected, metadata is enumerated to find the repository snapshot representing the backup data. That is to say, only metadata is cached if any. Therefore, dedicated cache volumes are not required in this scenario.

The above analyses are based on the common behavior of backup repositories and they are not considering the case that backup repository metadata takes majority or siginficant proportion of the cache data.   
As a conclusion of the analyses, we will create dedicated cache volumes for restore scenarios.  
For other scenarios, we can add them regarded to the future changes/requirements. The mechanism to expose and connect the cache volumes should work for all scenarios. E.g., if we need to consider the backup repository metadata case, we may need cache volumes for backup and repository maintenance as well, then we can just reuse the same cache volume provision and connection mechanism to backup and repository maintenance scenarios.   

### Cache Data and Lifecycle

If available, one cache volume is dedicately assigned to one data mover pod. That is, the cached data is destroyed when the data mover pod completes. Then the backup repository instance also closes.    
Cache data are fully managed by the specific backup repository. So the backup repository may also have its own way to GC the cache data.  
That is to say, cache data GC may be launched by the backup repository instance during the running of the data mover pod; then the left data are automatically destroyed when the data mover pod and the cache PVC are destroyed (cache PVC's `reclaimPolicy` is always `Deleted`, so once the cache PVC is destroyed, the volume will also be destroyed). So no specially logics are needed for cache data GC.  

### Data Size

Cache volumes take storage space and cluster resources (PVC, PV), therefore, cache volumes should be created only when necessary and the volumes should be with reasonable size based on the cache data size:  
- It is not a good bargain to have cache volumes for small backups, small backups will use resident cache location (the cache location in the root file system)
- The cache data size has a limit, the existing `cacheLimitMB` is used for this purpose. E.g., it could be set as 1024 for a 1TB backup, which means 1GB of data is cached and the old cache data exceeding this size will be cleared. Therefore, it is meaningless to set the cache volume size much larger than `cacheLimitMB`

### Cache Volume Size

The cache volume size is calculated from below factors (for Restore scenarios):  
- **Limit**: The limit of the cache data, that is represented by `cacheLimitMB`, the default value is 5GB
- **backupSize**: The size of the backup as a reference to evaluate whether to create a cache volume. It doesn't mean the backup data really decides the cache data all the time, it is just a reference to evaluate the scale of the backup, small scale backups may need small cache data. Sometimes, backupSize is not irrelevant to the size of cache data, in this case, ResidentThreshold should not be set, Limit will be used directly. It is unlikely that backupSize is unavailable, but once that happens, ResidentThreshold is ignored, Limit will be used directly.  
- **ResidentThreshold**: The minimum backup size that a cache volume is created
- **InflationPercentage**: Considering the overhead of the file system and the possible delay of the cache cleanup, there should be an inflation for the final volume size vs. the logical size, otherwise, the cache volume may be overrun. This inflation percentage is hardcoded, e.g., 20%. 

A formula is as below:  
```
cacheVolumeSize = ((backupSize != 0 ? (backupSize > residentThreshold ? limit : 0) : limit) * (100 + inflationPercentage)) / 100
```
Finally, the `cacheVolumeSize` will be rounded up to GiB considering the UX friendliness, storage friendliness and management friendliness.    

### PVC/PV

The PVC for a cache volume is created in Velero namespace and a storage class is required for the cache PVC. The PVC's accessMode is `ReadWriteOnce` and volumeMode is `FileSystem`, so the storage class provided should support this specification. Otherwise, if the storageclass doesn't support either of the specifications, the data mover pod may be hang in `Pending` state until a timeout setting with the data movement (e.g. `prepareTimeout`) and the data movement will finally fail.  
It is not expected that the cache volume is retained after data mover pod is deleted, so the `reclaimPolicy` for the storageclass must be `Delete`.  

To detect the problems in the storageclass and fail earlier, a validation is applied to the storageclass and once the validation fails, the cache configuration will be ignored, so the data mover pod will be created without a cache volume.  

### Cache Volume Configurations

Below configurations are introduced:
- **residentThresholdMB**: the minimum data size(in MB) to be processed (if available) that a cache volume is created
- **cacheStorageClass**: the name of the storage class to provision the cache PVC

Not like `cacheLimitMB` which is set to and affect the backup repository, the above two configurations are actually data mover configurations of how to create cache volumes to data mover pods; and the two configurations don't need to be per backup repository. So we add them to the node-agent Configuration.  

### Sample

Below are some examples of the node-agent configMap with the configurations:

Sample-1:  
```json
{
    "cacheVolume": {
        "storageClass": "sc-1",
        "residentThresholdMB": 1024        
    }
}
```

Sample-2:  
```json
{
    "cacheVolume": {
        "storageClass": "sc-1",       
    }
}
```

Sample-3:  
```json
{
    "cacheVolume": {
        "residentThresholdMB": 1024        
    }
}
```

**sample-1**: This is a valid configuration. Restores with backup data size larger than 1G will be assigned a cache volume using storage class `sc-1`.  
**sample-2**: This is a valid configuration. Data mover pods are always assigned a cache volume using storage class `sc-1`.  
**sample-3**: This is not a valid configuration because the storage class is absent. Velero gives up creating a cache volume.   

To create the configMap, users need to save something like the above sample to a json file and then run below command:
```
kubectl create cm <ConfigMap name> -n velero --from-file=<json file name>
```

The cache volume configurations will be visited by node-agent server, so they also need to specify the `--node-agent-configmap` to the `velero node-agent` parameters.  

## Detailed Design

### Backup and Restore

The restore needs to know the backup size so as to calculate the cache volume size, some new fields are added to the DataDownload and PodVolumeRestore CRDs.  

`snapshotSize` field is also added to DataDownload and PodVolumeRestore's `spec`:
```yaml
          spec:
              snapshotID:
                description: SnapshotID is the ID of the Velero backup snapshot to
                  be restored from.
                type: string
              snapshotSize:
                description: SnapshotSize is the logical size of the snapshot.
                format: int64
                type: integer
```

`snapshotSize` represents the total size of the backup; during restore, the value is transferred from DataUpload/PodVolumeBackup's `Status.Progress.TotalBytes` to DataDownload/PodVolumeRestore.    

It is unlikely that `Status.Progress.TotalBytes` from DataUpload/PodVolumeBackup is unavailable, but once it happens, according to the above formula, `residentThresholdMB` is ignored, cache volume size is calculated directly from cache limit for the corresponding backup repository.  

### Exposer

Cache volume configurations are retrieved by node-agent and passed through DataDownload/PodVolumeRestore to GenericRestore exposer/PodVolume exposer.  
The exposers are responsible to calculate cache volume size, create cache PVCs and mount them to the restorePods.  
If the calculated cache volume size is 0, or any of the critical parameters is missing (e.g., cache volume storage class), the exposers ignore the cache volume configuration and continue with creating restorePods without cache volumes, so no impact to the result of the restore.  

Exposers mount the cache volume to a predefined directory and pass the directory to the data mover pods through the `cache-volume-path` parameter.  

Below data structure is added to the exposers' expose parameters:  

```go
type GenericRestoreExposeParam struct {
	// RestoreSize specifies the data size for the volume to be restored
	RestoreSize int64

	// CacheVolume specifies the info for cache volumes
	CacheVolume *CacheVolumeInfo
}

type PodVolumeExposeParam struct {
	// RestoreSize specifies the data size for the volume to be restored
	RestoreSize int64

	// CacheVolume specifies the info for cache volumes
	CacheVolume *repocache.CacheConfigs
}

type CacheConfigs struct {
	// StorageClass specifies the storage class for cache volumes
	StorageClass string

	// Limit specifies the maximum size of the cache data
	Limit int64

	// ResidentThreshold specifies the minimum size of the cache data to create a cache volume
	ResidentThreshold int64
}
```

### Data Mover Pods

Data mover pods retrieve the cache volume directory from `cache-volume-path` parameter and pass it to Unified Repository.  
If the directory is empty, Unified Repository uses the resident location for data cache, that is, the root file system.  

### Kopia Repository

Kopia repository supports cache directory configuration for both metadata and data. The existing `SetupConnectOptions` is modified to customize the `CacheDirectory`:  

```go
func SetupConnectOptions(ctx context.Context, repoOptions udmrepo.RepoOptions) repo.ConnectOptions {
    ...

	return repo.ConnectOptions{
		CachingOptions: content.CachingOptions{
			CacheDirectory: cacheDir,
			...
		},
		...
	}
}
```  


[1]: ./unified-repo-and-kopia-integration/unified-repo-and-kopia-integration.md
[2]: ./vgdp-micro-service/vgdp-micro-service.md
[3]: ./vgdp-micro-service-for-fs-backup/vgdp-micro-service-for-fs-backup.md
[4]: ./repo_maintenance_job_config.md
[5]: ./backup-repo-config.md