---
title: "Velero Install CLI"
layout: docs
---

This document serves as a guide to using the `velero install` CLI command to install `velero` server components into your kubernetes cluster.

_NOTE_: `velero install` will, by default, use the CLI's version information to determine the version of the server components to deploy. This behavior may be overridden by using the `--image` flag. Refer to [Building Server Component Container Images][1].

## Usage

This section explains some of the basic flags supported by the `velero install` CLI command. For a complete explanation of the flags, please run `velero install --help`

```bash
velero install \
    --plugins <PLUGIN_CONTAINER_IMAGE [PLUGIN_CONTAINER_IMAGE]>
    --provider <YOUR_PROVIDER> \
    --bucket <YOUR_BUCKET> \
    --secret-file <PATH_TO_FILE> \
    --velero-pod-cpu-request <CPU_REQUEST> \
    --velero-pod-mem-request <MEMORY_REQUEST> \
    --velero-pod-cpu-limit <CPU_LIMIT> \
    --velero-pod-mem-limit <MEMORY_LIMIT> \
    [--use-restic] \
    [--default-volumes-to-restic] \
    [--restic-pod-cpu-request <CPU_REQUEST>] \
    [--restic-pod-mem-request <MEMORY_REQUEST>] \
    [--restic-pod-cpu-limit <CPU_LIMIT>] \
    [--restic-pod-mem-limit <MEMORY_LIMIT>]
```

The values for the resource requests and limits flags follow the same format as [Kubernetes resource requirements][3]
For plugin container images, please refer to our [supported providers][2] page.

## Examples

This section provides examples that serve as a starting point for more customized installations.

```bash
velero install --provider gcp --plugins velero/velero-plugin-for-gcp:v1.0.0 --bucket mybucket --secret-file ./gcp-service-account.json

velero install --provider aws --plugins velero/velero-plugin-for-aws:v1.0.0 --bucket backups --secret-file ./aws-iam-creds --backup-location-config region=us-east-2 --snapshot-location-config region=us-east-2 --use-restic

velero install --provider azure --plugins velero/velero-plugin-for-microsoft-azure:v1.0.0 --bucket $BLOB_CONTAINER --secret-file ./credentials-velero --backup-location-config resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,storageAccount=$AZURE_STORAGE_ACCOUNT_NAME[,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID] --snapshot-location-config apiTimeout=<YOUR_TIMEOUT>[,resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID]
```

[1]: build-from-source.md#making-images-and-updating-velero
[2]: supported-providers.md
[3]: https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/
