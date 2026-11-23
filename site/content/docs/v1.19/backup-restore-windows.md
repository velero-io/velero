---
title: "Backup Restore Windows Workloads"
layout: docs
---

## Prerequisites

Velero supports to backup and restore Windows workloads, either stateless or stateful.  
To keep compatibility to the existing Velero plugins, Velero server runs in linux nodes only, so Velero requires at least one linux node in the cluster. And it is not recommended to run Velero server in control plane, so a linux worker node is required. For resource requirement of the linux node for Velero server, see [Customize resource requests and limits][1].  

Velero is built and tested with `windows/amd64/ltsc2022` container only, older Windows versions, i.e., Windows Server 2019, are not supported.  

For volume backups, CSI and CSI snapshot should be supported by the storage.  

## Installation

As mentioned in [Image building][2], a hybrid image is provided for all platforms, so you don't need to set different images for linux and Windows clusters, you can always use the all-in-one image, e.g., `velero/velero:v1.16.0` or `velero/velero:main`.  

In order to backup/restore volumes for stateful workloads, Velero node-agent needs to run in the Windows nodes. Velero provides a dedicated daemonset for Windows nodes, called `node-agent-windows`.  
Therefore, in a typical cluster with linux and Windows nodes, there are two daemonsets for Velero node-agent, the existing `node-agent` daemonset for linux nodes, and the `node-agent-windows` daemonset for Windows nodes.  
If you want to install `node-agent` daemonset, specify `--use-node-agent` parameter in `velero install` command; and if you want to install `node-agent-windows` daemonset, specify `--use-node-agent-windows` parameter.  

## Resource backup restore

Resource backup/restore for Windows workloads is done by the Velero server the same as for linux workloads.  

Since Velero server is running in linux nodes only, all the existing plugins, i.e., BIA, RIA, BackupStore plugins, could be started by Velero in a cluster with Windows nodes. However, whether or how the plugins are functional for Windows workloads is decided by the plugins themselves.  
It is recommended that plugin providers do a thorough test with Velero in Windows cluster environments, and:
- If they need to support Windows workloads, make the necessary modification to ensure their plugins work well with Windows workloads
- If they don't want to support Windows workloads, or part of the Windows workloads, they need to ensure the plugins won't cause any failure or crash when they process the undesired Windows workload items

## Volume backup restore

Below is the support status for Windows workload volumes for different backup methods:
- CSI snapshot data movement: block volumes (i.e., vSphere CNS Block Volume, Azure Disk, AWS EBS, GCP Persistent Disk, etc.) are fully supported; file volumes (i.e., vSphere CNS File Volume, Azure File, AWS EFS, GCP Filestore, etc.) are not tested or officially supported. This is the same for linux workloads
- CSI snapshot backup: block volumes (i.e., vSphere CNS Block Volume, Azure Disk, AWS EBS, GCP Persistent Disk, etc.) are fully supported; file volumes (i.e., vSphere CNS File Volume, Azure File, AWS EFS, GCP Filestore, etc.) are not tested or officially supported. This is the same for linux workloads
- native snapshot backup: supported the same as for linux workloads
- file system backup: at present, NOT supported

For volume backups/restores conducted through Velero plugins, the support status is decided by the plugins themselves.  

### CSI snapshot data movement

During backup, Velero automatically identifies the OS type of the workload and schedules data mover pods to the right nodes. Specifically, for a linux workload, linux nodes in the cluster will be used; for a Windows workload, Windows nodes in the cluster will be used.  
You could view the OS type that a data mover pod is running with from the DataUpload status's `nodeOS` field.   

Velero takes several measures to deduce the OS type for volumes of workloads, from PVCs, VolumeAttach CRs, nodes and storage classes. If Velero fails to deduce the OS type, it falls back to linux, then the data mover pods will be scheduled to linux nodes. As a result, the data mover pods may not be able to start and the corresponding DataUploads will be cancelled because of timeout, so the backup will be partially failed.  

Therefore, it is highly recommended you provide a dedicated storage class for Windows workloads volumes, and set `csi.storage.k8s.io/fstype` correctly. E.g., for linux workload volumes, set `csi.storage.k8s.io/fstype=ext4`; for Windows workload volumes set `csi.storage.k8s.io/fstype=ntfs`.  
Specifically, if you have X number of storage classes for linux workloads, you need to create another X number of storage classes for Windows workloads.  
This is helpful for Velero to deduce the right OS type successfully all the time, especially when you are backing up the following kinds of volumes belonging to a Windows workload:
- The PVC is with Immediate mode
- There is no pod mounting the PVC at the time of backup

For restore, Velero automatically inherits the OS type from backup, so no deduction process is required.  

For other information, check [CSI Snapshot Data Movement][3].  


## Backup Repository Maintenance job

Backup Repository Maintenance jobs and pods are supported to run in Windows nodes, that is, you can take full node resources in a cluster with Windows nodes for Backup Repository Maintenance. For more information, check [Repository Maintenance][4].  

## Backup restore hooks

Pre/post backup/restore hooks are supported for Windows workloads, the commands run in the same Windows nodes hosting the workload pods. For more information, check [Backup Hooks][5] and [Restore Hooks][6].  

## Limitations

NTFS extended attributes/advanced features are not supported, i.e., Security Descriptors, System/Hidden/ReadOnly attributes, Creation Time, NTFS Streams, etc. That is, after backup/restore, these data will be lost.  



[1]: customize-installation.md#customize-resource-requests-and-limits
[2]: build-from-source.md#image-building
[3]: csi-snapshot-data-movement.md
[4]: repository-maintenance.md
[5]: backup-hooks.md
[6]: restore-hooks.md