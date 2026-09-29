---
title: "Node-agent Prepare Queue Length"
layout: docs
---

During [CSI Snapshot Data Movement][1], Velero built-in data mover launches data mover pods to run the data transfer.  
During [fs-backup][2], Velero also launches data mover pods to run the data transfer.  
Other intermediate resources may also be created along with the data mover pods, i.e., PVCs, VolumeSnapshots, VolumeSnapshotContents, etc.  

Velero uses [node-agent Concurrency Configuration][3] to control the number of concurrent data transfer activities across the nodes, by default, the concurrency is 1 per node.  

when the parallelism across the available nodes are much lower than the total number of volumes to be backed up/restored, the intermediate objects may exist for much longer time unnecessarily, which takes unnecessary resources from the cluster.  
The available nodes are decided by various factors, e.g., node OS type (linux or Windows), [Node Selection][4] (for CSI Snapshot Data Movement only), etc.  

Velero allows you to configure the `prepareQueueLength` in node-agent Configuration, which defines the maximum number of `DataUpload`/`DataDownload`/`PodVolumeBackup`/`PodVolumeRestore` CRs under the preparation statuses but are not yet processed by any node (e.g., in phases of `Accepted`, `Prepared`). In this way, the number of intermediate objects are constrained.  

### Sample
Here is a sample of the configMap with ```prepareQueueLength```:  
```json
{
    "loadConcurrency": {
        "prepareQueueLength": 10
    }
}
``` 

To create the configMap, save something like the above sample to a json file and then run below command:
```
kubectl create cm node-agent-config -n velero --from-file=<json file name>
```

To provide the configMap to node-agent, edit the node-agent daemonset and add the ```- --node-agent-configmap`` argument to the spec:
1. Open the node-agent daemonset spec  
```
kubectl edit ds node-agent -n velero
```
2. Add ```- --node-agent-configmap``` to ```spec.template.spec.containers```  
```
spec:
  template:
    spec:
      containers:
      - args:
        - --node-agent-configmap=<configMap name>
```

## Related Documentation

- [Node-agent Configuration](supported-configmaps/node-agent-configmap.md) - Complete reference for all configuration options
- [Node-agent Concurrency](node-agent-concurrency.md) - Configure concurrent operations per node
- [Node Selection for Data Movement](data-movement-node-selection.md) - Configure which nodes run data movement
- [Data Movement Pod Resource Configuration](data-movement-pod-resource-configuration.md) - Configure pod resources
- [BackupPVC Configuration](data-movement-backup-pvc-configuration.md) - Configure backup storage
- [RestorePVC Configuration](data-movement-restore-pvc-configuration.md) - Configure restore storage
- [Cache PVC Configuration](data-movement-cache-volume.md) - Configure restore data mover storage

[1]: csi-snapshot-data-movement.md
[2]: file-system-backup.md
[3]: node-agent-concurrency.md
[4]: data-movement-node-selection.md
