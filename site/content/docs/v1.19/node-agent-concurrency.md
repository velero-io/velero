---
title: "Node-agent Concurrency"
layout: docs
---

Velero node-agent is a daemonset hosting modules to complete the concrete tasks of backups/restores, i.e., file system backup/restore, CSI snapshot data movement.  
Varying from the data size, data complexity, resource availability, the tasks may take a long time and remarkable resources (CPU, memory, network bandwidth, etc.). These tasks make the loads of node-agent.

Node-agent concurrency configurations allow you to configure the concurrent number of node-agent loads per node. When the resources are sufficient in nodes, you can set a large concurrent number, so as to reduce the backup/restore time; otherwise, the concurrency should be reduced, otherwise, the backup/restore may encounter problems, i.e., time lagging, hang or OOM kill.

To set Node-agent concurrency configurations, a configMap should be created manually. The configMap should be in the same namespace where Velero is installed. If multiple Velero instances are installed in different namespaces, there should be one configMap in each namespace which applies to node-agent in that namespace only. The name of the configMap should be specified in the node-agent server parameter ```--node-agent-configmap```.
Node-agent server checks these configurations at startup time. Therefore, you could edit this configMap any time, but in order to make the changes effective, node-agent server needs to be restarted.

The users can specify the ConfigMap name during velero installation by CLI:
`velero install --node-agent-configmap=<ConfigMap-Name>`

### Global concurrent number
You can specify a concurrent number that will be applied to all nodes if the per-node number is not specified. This number is set through ```globalConfig``` field in ```loadConcurrency```.
The number starts from 1 which means there is no concurrency, only one load is allowed. There is no roof limit. If this number is not specified or not valid, a hard-coded default value will be used, the value is set to 1.

### Per-node concurrent number
You can specify different concurrent number per node, for example, you can set 3 concurrent instances in Node-1, 2 instances in Node-2 and 1 instance in Node-3.  
The range of Per-node concurrent number is the same with Global concurrent number. Per-node concurrent number is preferable to Global concurrent number, so it will overwrite the Global concurrent number for that node.

Per-node concurrent number is implemented through ```perNodeConfig``` field in ```loadConcurrency```.
```perNodeConfig``` is a list of ```RuledConfigs``` each item of which matches one or more nodes by label selectors and specify the concurrent number for the matched nodes.  
Here is an example of the ```perNodeConfig``:
```
"nodeSelector: kubernetes.io/hostname=node1; number: 3"
"nodeSelector: beta.kubernetes.io/instance-type=Standard_B4ms; number: 5"
```
The first element means the node with host name ```node1``` gets the Per-node concurrent number of 3.
The second element means all the nodes with label ```beta.kubernetes.io/instance-type``` of value ```Standard_B4ms``` get the Per-node concurrent number of 5.
At least one node is expected to have a label with the specified ```RuledConfigs``` element (rule). If no node is with this label, the Per-node rule makes no effect.
If one node falls into more than one rules, e.g., if node1 also has the label ```beta.kubernetes.io/instance-type=Standard_B4ms```, the smallest number (3) will be used.

### Sample
A sample of the complete ConfigMap is as below:
```json
{
    "loadConcurrency": {
        "globalConfig": 2,
        "perNodeConfig": [
            {
                "nodeSelector": {
                    "matchLabels": {
                        "kubernetes.io/hostname": "node1"
                    }
                },
                "number": 3
            },
            {
                "nodeSelector": {
                    "matchLabels": {
                        "beta.kubernetes.io/instance-type": "Standard_B4ms"
                    }
                },
                "number": 5
            }
        ]
    }
}
```
To create the ConfigMap, save something like the above sample to a json file and then run below command:
```
kubectl create cm <ConfigMap name> -n velero --from-file=<json file name>
```
To provide the ConfigMap to node-agent, edit the node-agent daemonset and add the ```- --node-agent-configmap``` argument to the spec:
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
        - --node-agent-configmap=<ConfigMap name>
```

## Related Documentation

- [Node-agent Configuration](supported-configmaps/node-agent-configmap.md) - Complete reference for all configuration options
- [Node-agent Concurrency](node-agent-concurrency.md) - Configure concurrent operations per node
- [Node Selection for Data Movement](data-movement-node-selection.md) - Configure which nodes run data movement
- [Data Movement Pod Resource Configuration](data-movement-pod-resource-configuration.md) - Configure pod resources
- [BackupPVC Configuration](data-movement-backup-pvc-configuration.md) - Configure backup storage
- [RestorePVC Configuration](data-movement-restore-pvc-configuration.md) - Configure restore storage
- [Cache PVC Configuration](data-movement-cache-volume.md) - Configure restore data mover storage
