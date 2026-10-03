---
title: "How to use CSI Volume Snapshotting with Velero"
excerpt: In the Velero 1.4 release, we introduced support for CSI snapshotting v1beta1 APIs. This post provides step-by-step instructions on setting up a CSI environment in Azure, installing Velero 1.4 with the velero-plugin-for-csi, and a demo of this feature in action.
author_name: Ashish Amarnath
image: /img/posts/csi-announce-blog.jpg
# Tag should match author to drive author pages
tags: ['Velero Team', 'Ashish Amarnath']
---

In the recent [1.4 release of Velero](https://github.com/velero-io/velero/releases), we announced a new feature of supporting CSI snapshotting using the [Kubernetes CSI Snapshot Beta APIs](https://kubernetes.io/docs/concepts/storage/volume-snapshots/).
With this capability of CSI volume snapshotting, Velero can now support any volume provider that has a CSI driver with snapshotting capability, without requiring a Velero-specific volume snapshotter plugin to be available.

This post has the necessary instructions for you to start using this feature.

## Getting Started

Using the CSI volume snapshotting features in Velero involves the following steps.

1. Set up a CSI environment with a driver supporting the Kubernetes CSI snapshot beta APIs.
1. Install Velero with CSI snapshotting feature enabled.
1. Deploy `csi-app`: a stateful application that uses CSI backed volumes that we will backup and restore.
1. Use Velero to backup and restore the `csi-app`.

## Set up a CSI environment.

As the [Kubernetes CSI Snapshot Beta API](https://kubernetes.io/docs/concepts/storage/volume-snapshots/) is available starting from Kubernetes `1.17`, you need to run Kubernetes `1.17` or later.

This post uses an AKS cluster running Kubernetes `1.17`, with Azure disk CSI driver as an example.

Following instructions to install the Azure disk CSI driver from [here](https://github.com/kubernetes-sigs/azuredisk-csi-driver/blob/master/docs/install-csi-driver-master.md) run the below command

```bash 
curl -skSL https://raw.githubusercontent.com/kubernetes-sigs/azuredisk-csi-driver/master/deploy/install-driver.sh | bash -s master snapshot -- 
```

This script will deploy the following CSI components, CRDs, and necessary RBAC:

- [`deployment.apps/csi-azuredisk-controller`](https://github.com/kubernetes-sigs/azuredisk-csi-driver/blob/master/deploy/csi-azuredisk-controller.yaml)
- [`daemonset.apps/csi-azuredisk-node`](https://github.com/kubernetes-sigs/azuredisk-csi-driver/blob/master/deploy/csi-azuredisk-node.yaml)
- [`deployment.apps/csi-snapshot-controller`](https://github.com/kubernetes-sigs/azuredisk-csi-driver/blob/master/deploy/csi-snapshot-controller.yaml)

## Install Velero with CSI support enabled

The CSI volume snapshot capability is currently, as of Velero 1.4, a beta feature behind the `EnableCSI` feature flag and is not enabled by default.

Following instructions from our [docs website](https://velero.io/docs/csi/), install Velero with the [velero-plugin-for-csi](https://github.com/vmware-tanzu/velero-plugin-for-csi) and using the Azure Blob Store as our BackupStorageLocation. Please refer to our [velero-plugin-for-microsoft-azure documentation](https://github.com/velero-io/velero-plugin-for-microsoft-azure) for instructions on setting up the BackupStorageLocation. Please note that the BackupStorageLocation should be set up before installing Velero.

Install Velero by running the below command

```bash
velero install \ 
--provider azure \ 
--plugins velero/velero-plugin-for-microsoft-azure:v1.1.0,velero/velero-plugin-for-csi:v0.1.1 \ 
--bucket $BLOB_CONTAINER \ 
--secret-file <PATH_TO_CREDS_FILE>/aks-creds \ 
--backup-location-config resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,storageAccount=$AZURE_STORAGE_ACCOUNT_NAME,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID \ 
--snapshot-location-config apiTimeout=5m,resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID \ 
--image velero/velero:v1.4.0 \ 
--features=EnableCSI 
```

## Deploy a stateful application with CSI backed volumes

Before installing the stateful application with CSI backed volumes, install the storage class and the volume snapshot class for the Azure disk CSI driver by applying the below `yaml` to our cluster.

```yaml
apiVersion: storage.k8s.io/v1 
kind: StorageClass 
metadata: 
  name: disk.csi.azure.com 
provisioner: disk.csi.azure.com 
parameters: 
  skuname: StandardSSD_LRS 
reclaimPolicy: Delete 
volumeBindingMode: Immediate 
allowVolumeExpansion: true
---
apiVersion: snapshot.storage.k8s.io/v1beta1 
kind: VolumeSnapshotClass 
metadata: 
  name: csi-azuredisk-vsc 
driver: disk.csi.azure.com 
deletionPolicy: Retain 
parameters:
  tags: 'foo=aaa,bar=bbb' 
```

NOTE: The above `yaml` was sourced from [StorageClass](https://github.com/kubernetes-sigs/azuredisk-csi-driver/blob/master/deploy/example/storageclass-azuredisk-csi.yaml) and [VolumeSnapshotClass](https://github.com/kubernetes-sigs/azuredisk-csi-driver/blob/master/deploy/example/snapshot/storageclass-azuredisk-snapshot.yaml).


Deploy the stateful application that is using CSI backed PVCs, in the `csi-app` namespace by applying the below yaml.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: csi-app
---
kind: Pod
apiVersion: v1
metadata:
  namespace: csi-app
  name: csi-nginx
spec:
  nodeSelector:
    kubernetes.io/os: linux
  containers:
    - image: nginx
      name: nginx
      command: [ "sleep", "1000000" ]
      volumeMounts:
        - name: azuredisk01
          mountPath: "/mnt/azuredisk"
  volumes:
    - name: azuredisk01
      persistentVolumeClaim:
        claimName: pvc-azuredisk
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  namespace: csi-app
  name: pvc-azuredisk
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: disk.csi.azure.com
---
```

For demonstration purposes, instead of relying on the application writing data to the mounted CSI volume, exec into the pod running the stateful application to write data into `/mnt/azuredisk`, where the CSI volume is mounted.
This is to let us get a consistent checksum value of the data and verify that the data on restore is exactly same as that in the backup.

```bash
$ kubectl -n csi-app exec -ti csi-nginx bash 
root@csi-nginx:/# while true; do echo -n "FOOBARBAZ " >> /mnt/azuredisk/foobar; done 
^C 
root@csi-nginx:/# cksum /mnt/azuredisk/foobar 
2279846381 1726530 /mnt/azuredisk/foobar 
```

## Back Up

Back up the `csi-app` namespace by running the below command

```bash
$ velero backup create csi-b2 --include-namespaces csi-app --wait 
Backup request "csi-b2" submitted successfully. 
Waiting for backup to complete. You may safely press ctrl-c to stop waiting - your backup will continue in the background. 
.................. 
Backup completed with status: Completed. You may check for more information using the commands `velero backup describe csi-b2` and `velero backup logs csi-b2`.
```

## Restore

Before restoring from the backup simulate a disaster by running

```bash
kubectl delete ns csi-app
```

Once the namespace has been deleted, restore the `csi-app` from the backup `csi-b2`.

```bash
$ velero create restore --from-backup csi-b2 --wait 
Restore request "csi-b2-20200518085136" submitted successfully. 
Waiting for restore to complete. You may safely press ctrl-c to stop waiting - your restore will continue in the background. 
.... 
Restore completed with status: Completed. You may check for more information using the commands `velero restore describe csi-b2-20200518085136` and `velero restore logs csi-b2-20200518085136`. 
```

Now that the restore has completed and our `csi-nginx` pod is `Running`, confirm that contents of `/mnt/azuredisk/foobar` have been correctly restored.

```bash
$ kubectl -n csi-app exec -ti csi-nginx bash 
root@csi-nginx:/# cksum /mnt/azuredisk/foobar 
2279846381 1726530 /mnt/azuredisk/foobar 
root@csi-nginx:/# 
```

The stateful application that we deployed has been successfully restored with its data intact.
And that's all it takes to backup and restore a stateful application that uses CSI backed volumes!

## Community Engagement

Please try out the CSI support in Velero 1.4. Feature requests, suggestions, bug reports, PRs are all welcome.

Get in touch with us on [Kubernetes Slack #velero](https://kubernetes.slack.com/archives/C6VCGP4MT), [Twitter](https://twitter.com/projectvelero), or [Our weekly community calls](https://velero.io/community/)


## Resources

More details about CSI volume snapshotting and its support in Velero may be found in the following links:

- [Kubernetes 1.17 Feature: Kubernetes Volume Snapshot Moves to Beta](https://kubernetes.io/blog/2019/12/09/kubernetes-1-17-feature-cis-volume-snapshot-beta/) for more information on the CSI beta snapshot APIs.
- Prerequisites to use this feature is available [on our website](https://velero.io/docs/csi).
- [Kubernetes CSI docs](https://kubernetes-csi.github.io/docs/sidecar-containers.html): To understand components in a CSI environment
- [Velero plugin for CSI snapshots](https://github.com/vmware-tanzu/velero-plugin-for-csi) for implementation details of the CSI plugin.
