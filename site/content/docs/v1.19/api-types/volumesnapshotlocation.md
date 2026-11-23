---
title: "Velero Volume Snapshot Location"
layout: docs
---

## Volume Snapshot Location

A volume snapshot location is the location in which to store the volume snapshots created for a backup.

Velero can be configured to take snapshots of volumes from multiple providers. Velero also allows you to configure multiple possible `VolumeSnapshotLocation` per provider, although you can only select one location per provider at backup time.

Each VolumeSnapshotLocation describes a provider + location. These are represented in the cluster via the `VolumeSnapshotLocation` CRD. Velero must have at least one `VolumeSnapshotLocation` per cloud provider.

A sample YAML `VolumeSnapshotLocation` looks like the following:

```yaml
apiVersion: velero.io/v1
kind: VolumeSnapshotLocation
metadata:
  name: aws-default
  namespace: velero
spec:
  provider: aws
  credential:
    name: secret-name
    key: key-in-secret
  config:
    region: us-west-2
    profile: "default"
```

### Parameter Reference

The configurable parameters are as follows:

#### Main config parameters

{{< table caption="Main config parameters" >}}
| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `provider` | String | Required Field | The name for whichever storage provider will be used to create/store the volume snapshots. See [your volume snapshot provider's plugin documentation](../supported-providers) for the appropriate value to use. |
| `config` | map string string | None (Optional) |  Provider-specific configuration keys/values to be passed to the volume snapshotter plugin. See [your volume snapshot provider's plugin documentation](../supported-providers) for details. |
| `credential` | [corev1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#secretkeyselector-v1-core) | Optional Field | The credential information to be used with this location. |
| `credential/name` | String | Optional Field | The name of the secret within the Velero namespace which contains the credential information. |
| `credential/key` | String | Optional Field | The key to use within the secret. |
{{< /table >}}
