---
title: "Supported Kubernetes Versions"
layout: docs
---

- In general, Velero works on Kubernetes version 1.7 or later (when Custom Resource Definitions were introduced).
- Restic support requires Kubernetes version 1.10 or later, or an earlier version with the mount propagation feature enabled. See [Restic Integration][17].

# Compatible Storage Providers

Velero supports a variety of storage providers for different backup and snapshot operations. Velero has a plugin system which allows anyone to add compatibility for additional backup and volume storage platforms without modifying the Velero codebase.

## Backup Storage Providers

| Provider                  | Owner    | Contact                         |
|---------------------------|----------|---------------------------------|
| [AWS S3][2]               | Velero Team | [Slack][10], [GitHub Issue][11] |
| [Azure Blob Storage][3]   | Velero Team | [Slack][10], [GitHub Issue][11] |
| [Google Cloud Storage][4] | Velero Team | [Slack][10], [GitHub Issue][11] |

## S3-Compatible Backup Storage Providers

Velero uses [Amazon's Go SDK][12] to connect to the S3 API. Some third-party storage providers also support the S3 API, and users have reported the following providers work with Velero:

_Note that these providers are not regularly tested by the Velero team._

 * [IBM Cloud][5]
 * [Minio][9]
 * Ceph RADOS v12.2.7
 * [DigitalOcean][7]
 * Quobyte
 * [NooBaa][16]
 * [Oracle Cloud][23]

_Some storage providers, like Quobyte, may need a different [signature algorithm version][15]._

## Volume Snapshot Providers

| Provider                         | Owner           | Contact                         |
|----------------------------------|-----------------|---------------------------------|
| [AWS EBS][2]                     | Velero Team        | [Slack][10], [GitHub Issue][11] |
| [Azure Managed Disks][3]         | Velero Team        | [Slack][10], [GitHub Issue][11] |
| [Google Compute Engine Disks][4] | Velero Team        | [Slack][10], [GitHub Issue][11] |
| [Restic][1]                      | Velero Team        | [Slack][10], [GitHub Issue][11] |
| [Portworx][6]                    | Portworx        | [Slack][13], [GitHub Issue][14] |
| [DigitalOcean][7]                | StackPointCloud |                                 |
| [OpenEBS][18]                     | OpenEBS       | [Slack][19], [GitHub Issue][20] |
| [AlibabaCloud][21]                     | AlibabaCloud       |  [GitHub Issue][22] |
| [HPE][24]                        | HPE                | [Slack][25], [GitHub Issue][26] |

### Adding a new plugin

To write a plugin for a new backup or volume storage system, take a look at the [example repo][8].

After you publish your plugin, open a PR that adds your plugin to the appropriate list.

[1]: restic.md
[2]: aws-config.md
[3]: azure-config.md
[4]: gcp-config.md
[5]: ibm-config.md
[6]: https://docs.portworx.com/scheduler/kubernetes/ark.html
[7]: https://github.com/StackPointCloud/ark-plugin-digitalocean
[8]: https://github.com/velero-io/velero-plugin-example/
[9]: get-started.md
[10]: https://kubernetes.slack.com/messages/velero
[11]: https://github.com/velero-io/velero/issues
[12]: https://github.com/aws/aws-sdk-go
[13]: https://portworx.slack.com/messages/px-k8s
[14]: https://github.com/portworx/ark-plugin/issues
[15]: api-types/backupstoragelocation.md#aws
[16]: http://www.noobaa.com/
[17]: restic.md
[18]: https://github.com/openebs/velero-plugin
[19]: https://openebs-community.slack.com/
[20]: https://github.com/openebs/velero-plugin/issues
[21]: https://github.com/AliyunContainerService/velero-plugin
[22]: https://github.com/AliyunContainerService/velero-plugin/issues
[23]: oracle-config.md
[24]: https://github.com/hpe-storage/velero-plugin
[25]: https://slack.hpedev.io/
[26]: https://github.com/hpe-storage/velero-plugin/issues
