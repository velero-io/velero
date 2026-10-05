---
title: "Providers"
layout: docs
---

Velero supports a variety of storage providers for different backup and snapshot operations. Velero has a plugin system which allows anyone to add compatibility for additional backup and volume storage platforms without modifying the Velero codebase.

## Velero supported providers

| Provider                          | Object Store        | Volume Snapshotter           | Plugin Provider Repo                    | Setup Instructions            |
|-----------------------------------|---------------------|------------------------------|-----------------------------------------|-------------------------------|
| [Amazon Web Services (AWS)][7]    | AWS S3              | AWS EBS                      | [Velero plugin for AWS][8]              | [AWS Plugin Setup][35]        |
| [Google Cloud Platform (GCP)][11] | Google Cloud Storage| Google Compute Engine Disks  | [Velero plugin for GCP][12]             | [GCP Plugin Setup][36]        |
| [Microsoft Azure][9]              | Azure Blob Storage  | Azure Managed Disks          | [Velero plugin for Microsoft Azure][10] | [Azure Plugin Setup][37]      |

Contact: [#Velero Slack][28], [GitHub Issues][29]

## Community supported providers

| Provider                  | Object Store                 | Volume Snapshotter                 | Plugin Documentation   | Contact                         |
|---------------------------|------------------------------|------------------------------------|------------------------|---------------------------------|
| [Portworx][31]            | 🚫                           | Portworx Volume                    | [Portworx][32]         | [Slack][33], [GitHub Issue][34] |
| [DigitalOcean][15]        | DigitalOcean Object Storage  | DigitalOcean Volumes Block Storage | [StackPointCloud][16]  |                                 |
| [OpenEBS][17]             | 🚫                           | OpenEBS CStor Volume               | [OpenEBS][18]          | [Slack][19], [GitHub Issue][20] |
| [AlibabaCloud][21]        | Alibaba Cloud OSS            | Alibaba Cloud                      | [AlibabaCloud][22]     | [GitHub Issue][23]              |
| [Hewlett Packard][24]     | 🚫                           | HPE Storage                        | [Hewlett Packard][25]  | [Slack][26], [GitHub Issue][27] |

## S3-Compatible object store providers

Velero's AWS Object Store plugin uses [Amazon's Go SDK][0] to connect to the AWS S3 API. Some third-party storage providers also support the S3 API, and users have reported the following providers work with Velero:

_Note that these storage providers are not regularly tested by the Velero team._

 * [IBM Cloud][1]
 * [Oracle Cloud][2]
 * [Minio][3]
 * [DigitalOcean][4]
 * [NooBaa][5]
 * Ceph RADOS v12.2.7
 * Quobyte
 * [Cloudian HyperStore][38]

_Some storage providers, like Quobyte, may need a different [signature algorithm version][6]._

## Non-supported volume snapshots

In the case you want to take volume snapshots but didn't find a plugin for your provider, Velero has support for snapshotting using restic. Please see the [restic integration][30] documentation.

[0]: https://github.com/aws/aws-sdk-go
[1]: contributions/ibm-config.md
[2]: contributions/oracle-config.md
[3]: contributions/minio.md
[4]: https://github.com/StackPointCloud/ark-plugin-digitalocean
[5]: http://www.noobaa.com/
[6]: https://github.com/velero-io/velero-plugin-for-aws/blob/main/backupstoragelocation.md
[7]: https://aws.amazon.com
[8]: https://github.com/velero-io/velero-plugin-for-aws
[9]: https://azure.com
[10]: https://github.com/velero-io/velero-plugin-for-microsoft-azure
[11]: https://cloud.google.com
[12]: https://github.com/velero-io/velero-plugin-for-gcp
[15]: https://www.digitalocean.com/
[16]: https://github.com/StackPointCloud/ark-plugin-digitalocean
[17]: https://openebs.io/
[18]: https://github.com/openebs/velero-plugin
[19]: https://openebs-community.slack.com/
[20]: https://github.com/openebs/velero-plugin/issues
[21]: https://www.alibabacloud.com/
[22]: https://github.com/AliyunContainerService/velero-plugin
[23]: https://github.com/AliyunContainerService/velero-plugin/issues
[24]: https://www.hpe.com/us/en/storage.html
[25]: https://github.com/hpe-storage/velero-plugin
[26]: https://slack.hpedev.io/
[27]: https://github.com/hpe-storage/velero-plugin/issues
[28]: https://kubernetes.slack.com/messages/velero
[29]: https://github.com/velero-io/velero/issues
[30]: restic.md
[31]: https://portworx.com/
[32]: https://docs.portworx.com/scheduler/kubernetes/ark.html
[33]: https://portworx.slack.com/messages/px-k8s
[34]: https://github.com/portworx/ark-plugin/issues
[35]: https://github.com/velero-io/velero-plugin-for-aws#setup
[36]: https://github.com/velero-io/velero-plugin-for-gcp#setup
[37]: https://github.com/velero-io/velero-plugin-for-microsoft-azure#setup
[38]: https://www.cloudian.com/
