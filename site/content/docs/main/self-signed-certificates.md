---
title: "Use Velero with a storage provider secured by a self-signed certificate"
layout: docs
---

If you are using an S3-Compatible storage provider that is secured with a self-signed certificate, connections to the object store may fail with a `certificate signed by unknown authority` message.
To proceed, provide a certificate bundle when adding the storage provider.

## Trusting a self-signed certificate during installation

When using the `velero install` command, you can use the `--cacert` flag to provide a path
to a PEM-encoded certificate bundle to trust.

```bash
velero install \
    --plugins <PLUGIN_CONTAINER_IMAGE [PLUGIN_CONTAINER_IMAGE]>
    --provider <YOUR_PROVIDER> \
    --bucket <YOUR_BUCKET> \
    --secret-file <PATH_TO_FILE> \
    --cacert <PATH_TO_CA_BUNDLE>
```

Velero will then automatically use the provided CA bundle to verify TLS connections to
that storage provider when backing up and restoring.

## Trusting a self-signed certificate using Kubernetes Secrets (Recommended)

The recommended approach for managing CA certificates is to store them in a Kubernetes Secret and reference them in the BackupStorageLocation using `caCertRef`. This provides better security and easier certificate management:

1. Create a Secret containing your CA certificate:

```bash
kubectl create secret generic storage-ca-cert \
  --from-file=ca-bundle.crt=<PATH_TO_CA_BUNDLE> \
  -n velero
```

2. Create or update your BackupStorageLocation to reference the Secret:

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  provider: <YOUR_PROVIDER>
  objectStorage:
    bucket: <YOUR_BUCKET>
    caCertRef:
      name: storage-ca-cert
      key: ca-bundle.crt
  # ... other configuration
```

### Benefits of using Secrets

- **Security**: Certificates are stored encrypted in etcd
- **Certificate Rotation**: Update the Secret to rotate certificates without modifying the BackupStorageLocation
- **RBAC**: Control access to certificates using Kubernetes RBAC
- **Separation of Concerns**: Keep sensitive certificate data separate from configuration

## Trusting a self-signed certificate with the Velero client

**Note**: As of Velero v1.15, the CLI automatically discovers certificates configured in the BackupStorageLocation. If you have configured certificates using either `caCert` (deprecated) or `caCertRef` (recommended) in your BSL, you no longer need to specify the `--cacert` flag for backup describe, download, or logs commands.

### Automatic Certificate Discovery

The Velero CLI automatically discovers and uses CA certificates from the BackupStorageLocation configuration. The resolution order is:

1. **`--cacert` flag** (if provided) - Takes highest precedence
2. **`caCertRef`** - References a Secret containing the certificate (recommended)
3. **`caCert`** - Inline certificate in the BSL (deprecated)

Examples:

```bash
# Automatic discovery (no flag needed if BSL has caCertRef or caCert configured)
velero backup describe my-backup
velero backup download my-backup
velero backup logs my-backup

# Manual override (takes precedence over BSL configuration)
velero backup describe my-backup --cacert <PATH_TO_CA_BUNDLE>
```

### Configuring CA Certificates in BackupStorageLocation

You can configure CA certificates in the BackupStorageLocation using either method:

1. **Using `caCertRef` (Recommended)**:

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
       caCertRef:
         name: storage-ca-cert
         key: ca-bundle.crt
     config:
       region: us-east-1
   ```

2. **Using inline `caCert` (Deprecated)**:

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
       caCert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi4uLiAoYmFzZTY0IGVuY29kZWQgY2VydGlmaWNhdGUgY29udGVudCkgLi4uCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
     config:
       region: us-east-1
   ```

When the CA certificate is configured in the BackupStorageLocation using either method, Velero client commands will automatically discover and use it without requiring the `--cacert` flag.

## Error with client certificate with custom S3 server

In case you are using a custom S3-compatible server, you may encounter that the backup fails with an error similar to one below.

```text
rpc error: code = Unknown desc = RequestError: send request failed caused by:
Get https://minio.com:3000/k8s-backup-bucket?delimiter=%2F&list-type=2&prefix=: remote error: tls: alert(116)
```

Error 116 represents certificate required as seen here in [error codes](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2).
Velero as a client does not include its certificate while performing SSL handshake with the server.
From [TLS 1.3 spec](https://tools.ietf.org/html/rfc8446), verifying client certificate is optional on the server.
You will need to change this setting on the server to make it work.

## Skipping TLS verification

**Note:** The `--insecure-skip-tls-verify` flag is insecure and susceptible to man-in-the-middle attacks and meant to help your testing and developing scenarios in an on-premises environment. Using this flag in production is not recommended.

Velero provides a way for you to skip TLS verification on the object store when using the [AWS provider plugin](https://github.com/velero-io/velero-plugin-for-aws) or [File System Backup](file-system-backup.md) by passing the `--insecure-skip-tls-verify` flag with the following Velero commands,

* velero backup describe
* velero backup download
* velero backup logs
* velero restore describe
* velero restore log

If true, the object store's TLS certificate will not be checked for validity before Velero or backup repository connects to the object storage. You can permanently skip TLS verification for an object store by setting `Spec.Config.InsecureSkipTLSVerify` to true in the [BackupStorageLocation](api-types/backupstoragelocation.md) CRD.

Note that Velero's File System Backup uses Restic or Kopia to do data transfer between object store and Kubernetes cluster disks. This means that when you specify `--insecure-skip-tls-verify` in Velero operations that involve File System Backup, Velero will convey this information to Restic or Kopia. For example, for Restic, Velero will add the Restic global command parameter `--insecure-tls` to Restic commands.
