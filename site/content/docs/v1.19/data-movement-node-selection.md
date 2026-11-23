---
title: "Node Selection for Data Movement"
layout: docs
---

Velero node-agent is a DaemonSet hosting the data movement modules to complete the concrete work of backups/restores.
Varying from the data size, data complexity, resource availability, the data movement may take a long time and remarkable resources (CPU, memory, network bandwidth, etc.) during the backup and restore.

Velero data movement backup and restore support to constrain the nodes where it runs. This is helpful in below scenarios:
- Prevent the data movement from running in specific nodes because users have more critical workloads in the nodes
- Constrain the data movement to run in specific nodes because these nodes have more resources than others
- Constrain the data movement to run in specific nodes because the storage allows volume/snapshot provisions in these nodes only

Velero introduces a new section in the node-agent ConfigMap, called ```loadAffinity```, through which users can specify the nodes to/not to run data movement, in the affinity and anti-affinity flavors.

**Important**: Currently, only the first element in the `loadAffinity` array is used. Any additional elements after the first one will be ignored. If you need to specify multiple conditions, combine them within a single `loadAffinity` element using both `matchLabels` and `matchExpressions`.

### Example of Incorrect Usage (Multiple Array Elements)

The following configuration will NOT work as intended:

```json
{
    "loadAffinity": [
        {
            "nodeSelector": {
                "matchLabels": {
                    "environment": "production"
                }
            }
        },
        {
            "nodeSelector": {
                "matchLabels": {
                    "disk-type": "ssd"
                }
            }
        }
    ]
}
```

In this example, you might expect data movement to run only on nodes that are BOTH in production AND have SSD disks. However, **only the first condition (environment=production) will be applied**. The second array element will be completely ignored.

### Correct Usage (Combined Conditions)

To achieve the intended behavior, combine all conditions into a single array element:

```json
{
    "loadAffinity": [
        {
            "nodeSelector": {
                "matchLabels": {
                    "environment": "production",
                    "disk-type": "ssd"
                }
            }
        }
    ]
}
```

If it is not there, a ConfigMap should be created manually. The ConfigMap should be in the same namespace where Velero is installed. If multiple Velero instances are installed in different namespaces, there should be one ConfigMap in each namespace which applies to node-agent in that namespace only. The name of the ConfigMap should be specified in the node-agent server parameter ```--node-agent-configmap```.
The node-agent server checks these configurations at startup time. Therefore, users could edit this ConfigMap any time, but in order to make the changes effective, node-agent server needs to be restarted.

The users can specify the ConfigMap name during velero installation by CLI:
`velero install --node-agent-configmap=<ConfigMap-Name>`

## Node Selection manner

### Affinity
Affinity configuration means allowing the data movement to run in the nodes specified. There are two ways to define it:
-  It could be defined by `MatchLabels`. The labels defined in `MatchLabels` means a `LabelSelectorOpIn` operation by default, so in the current context, they will be treated as affinity rules. In the above sample, it defines to run data movement in nodes with label `beta.kubernetes.io/instance-type` of value `Standard_B4ms` (Run data movement in `Standard_B4ms` nodes only).
- It could be defined by `MatchExpressions`. The labels are defined in `Key` and `Values` of `MatchExpressions` and the `Operator` should be defined as `LabelSelectorOpIn` or `LabelSelectorOpExists`. In the above sample, it defines to run data movement in nodes with label `kubernetes.io/hostname` of values `node-1`, `node-2` and `node-3` (Run data movement in `node-1`, `node-2` and `node-3` only).

### Anti-affinity
Anti-affinity configuration means preventing the data movement from running in the nodes specified. Below is the way to define it:
- It could be defined by `MatchExpressions`. The labels are defined in `Key` and `Values` of `MatchExpressions` and the `Operator` should be defined as `LabelSelectorOpNotIn` or `LabelSelectorOpDoesNotExist`. In the above sample, it disallows data movement to run in nodes with label `xxx/critial-workload`.

## How to create the LoadAffinity ConfigMap and apply to the NodeAgent

To create the ConfigMap, save something like the above sample to a json file and then run below command:
```
kubectl create cm <ConfigMap name> -n velero --from-file=<json file name>
```

To provide the ConfigMap to node-agent, edit the node-agent DaemonSet and add the ```- --node-agent-configmap``` argument to the spec:
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

## Examples

### LoadAffinity
Here is a sample of the ConfigMap with ```loadAffinity```:
```json
{
    "loadAffinity": [
        {
            "nodeSelector": {
                "matchLabels": {
                    "beta.kubernetes.io/instance-type": "Standard_B4ms"
                },
                "matchExpressions": [
                    {
                        "key": "kubernetes.io/hostname",
                        "values": [
                            "node-1",
                            "node-2",
                            "node-3"
                        ],
                        "operator": "In"
                    },
                    {
                        "key": "xxx/critial-workload",
                        "operator": "DoesNotExist"
                    }
                ]          
            }
        }
    ]
}
```

This example demonstrates how to use both `matchLabels` and `matchExpressions` in the same single LoadAffinity element.

### LoadAffinity with StorageClass (Note: Only First Element Used)

``` json
{
    "loadAffinity": [
        {
            "nodeSelector": {
                "matchLabels": {
                    "beta.kubernetes.io/instance-type": "Standard_B4ms"
                }
            }
        },
        {
            "nodeSelector": {
                "matchExpressions": [
                    {
                        "key": "kubernetes.io/os",
                        "values": [
                            "linux"
                        ],
                        "operator": "In"
                    }
                ]
            },
            "storageClass": "kibishii-storage-class"
        }
    ]
}
```

This sample demonstrates how the `loadAffinity` elements with `StorageClass` field and without `StorageClass` field setting work together. If the VGDP mounting volume is created from StorageClass `kibishii-storage-class`, its pod will run Linux nodes.

The other VGDP instances will run on nodes, which instance type is `Standard_B4ms`.

### LoadAffinity interacts with BackupPVC

``` json
{
    "loadAffinity": [
        {
            "nodeSelector": {
                "matchLabels": {
                    "beta.kubernetes.io/instance-type": "Standard_B4ms"
                }
            },
            "storageClass": "kibishii-storage-class"
        },
        {
            "nodeSelector": {
                "matchLabels": {
                    "beta.kubernetes.io/instance-type": "Standard_B2ms"
                }
            },
            "storageClass": "worker-storagepolicy"
        }
    ],
    "backupPVC": {
        "kibishii-storage-class": {
            "storageClass": "worker-storagepolicy"
        }
    }
}
```

Velero data mover supports to use different StorageClass to create backupPVC by [design](https://github.com/velero-io/velero/pull/7982).

In this example, if the backup target PVC's StorageClass is `kibishii-storage-class`, its backupPVC should use StorageClass `worker-storagepolicy`. Because the final StorageClass is `worker-storagepolicy`, the backupPod uses the loadAffinity specified by `loadAffinity`'s elements with `StorageClass` field set to `worker-storagepolicy`. backupPod will be assigned to nodes, which instance type is `Standard_B2ms`.

### LoadAffinity interacts with RestorePVC

``` json
{
    "loadAffinity": [
        {
            "nodeSelector": {
                "matchLabels": {
                    "beta.kubernetes.io/instance-type": "Standard_B4ms"
                }
            },
            "storageClass": "kibishii-storage-class"
        }
    ],
    "restorePVC": {
        "ignoreDelayBinding": false
    }
}
```

#### StorageClass's bind mode is WaitForFirstConsumer

``` yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: kibishii-storage-class
parameters:
  svStorageClass: worker-storagepolicy
provisioner: csi.vsphere.vmware.com
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
```

If restorePVC should be created from StorageClass `kibishii-storage-class`, and it's volumeBindingMode is `WaitForFirstConsumer`.
Although `loadAffinityPerStorageClass` has a section matches the StorageClass, the `ignoreDelayBinding` is set `false`, the Velero exposer will wait until the target Pod scheduled to a node, and returns the node as SelectedNode for the restorePVC.
As a result, the `loadAffinityPerStorageClass` will not take affect.

#### StorageClass's bind mode is Immediate

``` yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: kibishii-storage-class
parameters:
  svStorageClass: worker-storagepolicy
provisioner: csi.vsphere.vmware.com
reclaimPolicy: Delete
volumeBindingMode: Immediate
```

Because the StorageClass volumeBindingMode is `Immediate`, although `ignoreDelayBinding` is set to `false`, restorePVC will not be created according to the target Pod.

The restorePod will be assigned to nodes, which instance type is `Standard_B4ms`.

## Related Documentation

- [Node-agent Configuration](supported-configmaps/node-agent-configmap.md) - Complete reference for all configuration options
- [Node-agent Concurrency](node-agent-concurrency.md) - Configure concurrent operations per node
- [Node Selection for Data Movement](data-movement-node-selection.md) - Configure which nodes run data movement
- [Data Movement Pod Resource Configuration](data-movement-pod-resource-configuration.md) - Configure pod resources
- [BackupPVC Configuration](data-movement-backup-pvc-configuration.md) - Configure backup storage
- [RestorePVC Configuration](data-movement-restore-pvc-configuration.md) - Configure restore storage
- [Cache PVC Configuration](data-movement-cache-volume.md) - Configure restore data mover storage
