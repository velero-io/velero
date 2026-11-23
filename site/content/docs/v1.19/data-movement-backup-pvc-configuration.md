---
title: "BackupPVC Configuration for Data Movement Backup"
layout: docs
---

`BackupPVC`  is an intermediate PVC to access data from during the data movement backup operation.

In some scenarios users may need to configure some advanced options of the backupPVC so that the data movement backup
operation could perform better. Specifically:
- For some storage providers, when creating a read-only volume from a snapshot, it is very fast; whereas, if a writable volume
  is created from the snapshot, they need to clone the entire disk data, which is time consuming. If the `backupPVC`'s `accessModes` is
  set as `ReadOnlyMany`, the volume driver is able to tell the storage to create a read-only volume, which may dramatically shorten the
  snapshot expose time. On the other hand,  `ReadOnlyMany` is not supported by all volumes. Therefore, users should be allowed to configure
  the `accessModes` for the `backupPVC`.
- Some storage providers create one or more replicas when creating a volume, the number of replicas is defined in the storage class.
  However, it doesn't make any sense to keep replicas when an intermediate volume used by the backup. Therefore, users should be allowed
  to configure another storage class specifically used by the `backupPVC`.
- In SELinux-enabled clusters, such as OpenShift, when using the above-mentioned readOnly access mode setting, SELinux relabeling of the
  volume is not possible. Therefore for these clusters, when setting `readOnly` for a storage class, users must also disable relabeling.
  Note that this option is not consistent with the Restricted pod security policy, so if Velero pods must run with a restricted policy,
  disabling relabeling (and therefore readOnly volume mounting) is not possible.

Velero introduces a new section in the node agent configuration ConfigMap (the name of this ConfigMap is passed using `--node-agent-configmap` velero server argument)
called `backupPVC`, through which you can specify the following
configurations:

- `storageClass`: This specifies the storage class to be used for the backupPVC. If this value does not exist or is empty then by 
default the source PVC's storage class will be used.

- `readOnly`: This is a boolean value. If set to `true` then `ReadOnlyMany` will be the only value set to the backupPVC's access modes. Otherwise 
`ReadWriteOnce` value will be used.

- `spcNoRelabeling`: This is a boolean value. If set to `true`, then `pod.Spec.SecurityContext.SELinuxOptions.Type` will be set to `spc_t`. From
  the SELinux point of view, this will be considered a "Super Privileged Container" which means that selinux enforcement will be disabled and
  volume relabeling will not occur. This field is ignored if `readOnly` is `false`.

- `readWriteOncePod`: This is a boolean value. If set to `true`, then `ReadWriteOncePod` will be the only value set to the backupPVC's access modes. On
  SELinux-enabled clusters the kubelet applies the SELinux label to a `ReadWriteOncePod` volume at mount time (`-o context=`) instead of recursively
  relabeling every file on the volume, which can take hours on volumes with a high file count. It requires a CSI driver that advertises SELinux mount
  support (`CSIDriver.spec.seLinuxMount: true`) and a storage class that supports creating `ReadWriteOncePod` PVCs from a snapshot. This field is ignored
  if `readOnly` is `true`.

The users can specify the ConfigMap name during velero installation by CLI:
`velero install --node-agent-configmap=<ConfigMap-Name>`

- `annotations`: permits to set annotations on the backupPVC itself. typically useful for some CSI provider which cannot mount
  a VolumeSnapshot without a custom annotation.

- `secretNames`: a list of secret names to copy from the source PVC's namespace to the Velero namespace before the backupPVC is
  created, and delete after the DataUpload completes. This is needed for CSI drivers that require namespace-scoped secrets to
  provision the volume, for example ODF/ceph-csi encrypted volumes that fetch a KMS token secret (`ceph-csi-kms-token`) from the
  PVC's namespace. Without this, the backupPVC created in the Velero namespace fails to provision because the secret only exists
  in the source namespace.

- `configMapNames`: a list of configmap names to copy from the source PVC's namespace to the Velero namespace before the backupPVC
  is created, and delete after the DataUpload completes. This is needed for CSI drivers that require namespace-scoped configmaps to
  provision the volume, for example a tenant-specific ceph-csi KMS connection override configmap (`ceph-csi-kms-config`).

A sample of `backupPVC` config as part of the ConfigMap would look like:
```json
{
    "backupPVC": {
        "storage-class-1": {
            "storageClass": "backupPVC-storage-class",
            "readOnly": true
        },
        "storage-class-2": {
            "storageClass": "backupPVC-storage-class"
        },
        "storage-class-3": {
            "readOnly": true,
            "annotations": {
              "some-csi.provider.io/readOnlyClone": true
            }
        },
        "storage-class-4": {
            "readOnly": true,
            "spcNoRelabeling": true
        },
        "ocs-storagecluster-ceph-rbd-encrypted": {
            "secretNames": ["ceph-csi-kms-token"],
            "configMapNames": ["ceph-csi-kms-config"]
        },
        "storage-class-5": {
            "readWriteOncePod": true
        }
    }
}
```

**Note on encrypted volumes:** the copied secrets/configmaps are labeled `velero.io/backup-pvc-secret=<DataUpload UID>` and
deleted when the DataUpload completes (or on failure). If concurrent DataUploads from different namespaces need a secret with the same
name but different content in the Velero namespace, they conflict. For ceph-csi,
this can be avoided by configuring a unique
[`tenantTokenName` per tenant](https://github.com/ceph/ceph-csi/blob/devel/docs/design/proposals/encryption-with-vault-tokens.md#example-of-the-kms-configuration-file-for-vault-tokens).

**Note:** 
- Users should make sure that the storage class specified in `backupPVC` config should exist in the cluster and can be used by the
`backupPVC`, otherwise the corresponding DataUpload CR will stay in `Accepted` phase until timeout (data movement prepare timeout value is 30m by default).
- If the users are setting `readOnly` value as `true` in the `backupPVC` config then they must also make sure that the storage class that is being used for
`backupPVC` should support creation of `ReadOnlyMany` PVC from a snapshot, otherwise the corresponding DataUpload CR will stay in `Accepted` phase until
timeout (data movement prepare timeout value is 30m by default).
- In an SELinux-enabled cluster, any time users set `readOnly=true` they must also set `spcNoRelabeling=true`. There is no need to set `spcNoRelabeling=true`
if the volume is not readOnly.
- `readWriteOncePod` and `readOnly` are mutually exclusive. If both are set to `true`, `readOnly` wins, `readWriteOncePod` is ignored and a warning is logged.
- `readWriteOncePod` is an alternative to `readOnly`+`spcNoRelabeling` for SELinux-enabled clusters whose storage does not support `ReadOnlyMany`
(for example Ceph RBD in Filesystem mode or LVM). Users must make sure the storage class used for `backupPVC` supports creating a `ReadWriteOncePod` PVC from
a snapshot, otherwise the corresponding DataUpload CR will stay in `Accepted` phase until timeout.
- If any of the above problems occur, then the DataUpload CR is `canceled` after timeout, and the backupPod and backupPVC will be deleted, and the backup
will be marked as `PartiallyFailed`.

## Related Documentation

- [Node-agent Configuration](supported-configmaps/node-agent-configmap.md) - Complete reference for all configuration options
- [Node-agent Concurrency](node-agent-concurrency.md) - Configure concurrent operations per node
- [Node Selection for Data Movement](data-movement-node-selection.md) - Configure which nodes run data movement
- [Data Movement Pod Resource Configuration](data-movement-pod-resource-configuration.md) - Configure pod resources
- [BackupPVC Configuration](data-movement-backup-pvc-configuration.md) - Configure backup storage
- [RestorePVC Configuration](data-movement-restore-pvc-configuration.md) - Configure restore storage
- [Cache PVC Configuration](data-movement-cache-volume.md) - Configure restore data mover storage