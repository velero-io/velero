---
title: "Velero Backup Storage Locations"
layout: docs
---

## Backup Storage Location

Velero can store backups in a number of locations. These are represented in the cluster via the `BackupStorageLocation` CRD.

Velero must have at least one `BackupStorageLocation`. By default, this is expected to be named `default`, however the name can be changed by specifying `--default-backup-storage-location` on `velero server`.  Backups that do not explicitly specify a storage location will be saved to this `BackupStorageLocation`.

A sample YAML `BackupStorageLocation` looks like the following:

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  backupSyncPeriod: 2m0s
  provider: aws
  objectStorage:
    bucket: myBucket
  credential:
    name: secret-name
    key: key-in-secret
  config:
    region: us-west-2
    profile: "default"
```

### Example with self-signed certificate

When using object storage with self-signed certificates, you can specify the CA certificate:

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  provider: aws
  objectStorage:
    bucket: velero-backups
    # Base64 encoded CA certificate (deprecated - use caCertRef instead)
    caCert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR1VENDQXFHZ0F3SUJBZ0lVTWRiWkNaYnBhcE9lYThDR0NMQnhhY3dVa213d0RRWUpLb1pJaHZjTkFRRUwKQlFBd2JERUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjTQpEVk5oYmlCR2NtRnVZMmx6WTI4eEdEQVdCZ05WQkFvTUQwVjRZVzF3YkdVZ1EyOXRjR0Z1ZVRFV01CUUdBMVVFCkF3d05aWGhoYlhCc1pTNXNiMk5oYkRBZUZ3MHlNekEzTVRBeE9UVXlNVGhhRncweU5EQTNNRGt4T1RVeU1UaGEKTUd3eEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUNEQXBEWEJ4cG1iM0p1YVdFeEZqQVVCZ05WQkFjTURWTmgKYmlCR2NtRnVZMmx6WTI4eEdEQVdCZ05WQkFvTUQwVjRZVzF3YkdVZ1EyOXRjR0Z1ZVRFV01CUUdBMVVFQXd3TgpaWGhoYlhCc1pTNXNiMk5oYkRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBS1dqCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
  config:
    region: us-east-1
    s3Url: https://minio.example.com
```

#### Using a CA Certificate with Secret Reference (Recommended)

The recommended approach is to use `caCertRef` to reference a Secret containing the CA certificate:

```yaml
# First, create a Secret containing the CA certificate
apiVersion: v1
kind: Secret
metadata:
  name: storage-ca-cert
  namespace: velero
type: Opaque
data:
  ca-bundle.crt: <base64-encoded-certificate>

---
# Then reference it in the BackupStorageLocation
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  provider: aws
  objectStorage:
    bucket: myBucket
    caCertRef:
      name: storage-ca-cert
      key: ca-bundle.crt
  # ... other configuration
```

**Note:** You cannot specify both `caCert` and `caCertRef` in the same BackupStorageLocation. The `caCert` field is deprecated and will be removed in a future version.

### Parameter Reference

The configurable parameters are as follows:

#### Main config parameters

{{< table caption="Main config parameters" >}}
| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `provider` | String | Required Field | The name for whichever object storage provider will be used to store the backups. See [your object storage provider's plugin documentation](../supported-providers) for the appropriate value to use. |
| `objectStorage` | ObjectStorageLocation | Required Field | Specification of the object storage for the given provider. |
| `objectStorage/bucket` | String | Required Field | The storage bucket where backups are to be uploaded. |
| `objectStorage/prefix` | String | Optional Field | The directory inside a storage bucket where backups are to be uploaded. |
| `objectStorage/caCert` | String | Optional Field | **Deprecated**: Use `caCertRef` instead. A base64 encoded CA bundle to be used when verifying TLS connections |
| `objectStorage/caCertRef` | [corev1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#secretkeyselector-v1-core) | Optional Field | Reference to a Secret containing a CA bundle to be used when verifying TLS connections. The Secret must be in the same namespace as the BackupStorageLocation. |
| `objectStorage/caCertRef/name` | String | Required Field (when using caCertRef) | The name of the Secret containing the CA certificate bundle |
| `objectStorage/caCertRef/key` | String | Required Field (when using caCertRef) | The key within the Secret that contains the CA certificate bundle |
| `config` | map[string]string | None (Optional) | Provider-specific configuration keys/values to be passed to the object store plugin. See [your object storage provider's plugin documentation](../supported-providers) for details. |
| `accessMode` | String | `ReadWrite` | How Velero can access the backup storage location. Valid values are `ReadWrite`, `ReadOnly`. |
| `backupSyncPeriod` | metav1.Duration | Optional Field | How frequently Velero should synchronize backups in object storage. Default is Velero's server backup sync period. Set this to `0s` to disable sync. |
| `validationFrequency` | metav1.Duration | Optional Field | How frequently Velero should validate the object storage . Default is Velero's server validation frequency. Set this to `0s` to disable validation. Default 1 minute. |
| `credential` | [corev1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#secretkeyselector-v1-core) | Optional Field | The credential information to be used with this location. |
| `credential/name` | String | Optional Field | The name of the secret within the Velero namespace which contains the credential information. |
| `credential/key` | String | Optional Field | The key to use within the secret. |
| `worker` | BackupStorageLocationWorker | Optional Field | When set, this location's object-store operations run in a dedicated worker pod under a distinct pod identity instead of in the Velero server process. Requires the `EnableBSLWorkerIdentity` feature flag. See [Per-BSL worker identity](../bsl-worker-identity). |
{{< /table >}}

#### Worker config parameters

Set `worker` to run this location's object-store operations under a per-BSL pod identity
(e.g. a distinct Azure AD Workload Identity, AWS IRSA role, or GCP Workload Identity)
rather than the Velero server pod's identity. Requires the `EnableBSLWorkerIdentity`
feature flag on the Velero server. See [Per-BSL worker identity](../bsl-worker-identity)
for the full guide.

{{< table caption="Worker config parameters" >}}
| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `worker/serviceAccountName` | String | Required Field | The Kubernetes ServiceAccount the worker pod runs as. Must exist in the worker namespace and be bound to the tenant identity. |
| `worker/namespace` | String | Velero namespace | Namespace to run the worker pod in. Defaults to the Velero namespace. |
| `worker/podLabels` | map[string]string | Optional Field | Extra labels added to the worker pod, e.g. `azure.workload.identity/use: "true"` so an admission webhook injects the identity. |
| `worker/podAnnotations` | map[string]string | Optional Field | Extra annotations added to the worker pod. |
| `worker/tokenVolumes` | []ProjectedServiceAccountToken | Optional Field | Explicit projected service-account-token volumes to mount into the worker, for providers/setups without an injecting webhook. |
| `worker/tokenVolumes/audience` | String | Required Field | The audience the projected token is issued for (e.g. `api://AzureADTokenExchange`). |
| `worker/tokenVolumes/expirationSeconds` | int64 | Optional Field | Requested token expiration in seconds. |
| `worker/tokenVolumes/mountPath` | String | Required Field | Directory the token volume is mounted at inside the worker container. |
| `worker/tokenVolumes/path` | String | Required Field | File name for the token within `mountPath`. |
| `worker/resources` | [corev1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#resourcerequirements-v1-core) | Optional Field | Resource requests/limits for the worker container. |
| `worker/nodeSelector` | map[string]string | Optional Field | Node selector for scheduling the worker pod. |
| `worker/tolerations` | [][corev1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#toleration-v1-core) | Optional Field | Tolerations for scheduling the worker pod. |
{{< /table >}}