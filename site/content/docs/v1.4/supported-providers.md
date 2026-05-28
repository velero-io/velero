---
title: "Providers"
layout: docs
---

Velero supports a variety of storage providers for different backup and snapshot operations. Velero has a plugin system which allows anyone to add compatibility for additional backup and volume storage platforms without modifying the Velero codebase.

## Velero supported providers

{{< table caption="Velero supported providers" >}}

| Provider                          | Object Store        | Volume Snapshotter           | Plugin Provider Repo                    | Setup Instructions            |
|-----------------------------------|---------------------|------------------------------|-----------------------------------------|-------------------------------|
| [Amazon Web Services (AWS)](https://aws.amazon.com)    | AWS S3              | AWS EBS                      | [Velero plugin for AWS](https://github.com/velero-io/velero-plugin-for-aws)              | [AWS Plugin Setup](https://github.com/velero-io/velero-plugin-for-aws#setup)        |
| [Google Cloud Platform (GCP)](https://cloud.google.com) | Google Cloud Storage| Google Compute Engine Disks  | [Velero plugin for GCP](https://github.com/velero-io/velero-plugin-for-gcp)             | [GCP Plugin Setup](https://github.com/velero-io/velero-plugin-for-gcp#setup)        |
| [Microsoft Azure](https://azure.com)              | Azure Blob Storage  | Azure Managed Disks          | [Velero plugin for Microsoft Azure](https://github.com/velero-io/velero-plugin-for-microsoft-azure) | [Azure Plugin Setup](https://github.com/velero-io/velero-plugin-for-microsoft-azure#setup)      |
| [VMware vSphere](https://github.com/velero-io/velero-plugin-for-vsphere)              | 🚫                  | vSphere Volumes              | [VMware vSphere](https://github.com/velero-io/velero-plugin-for-vsphere)                    | [vSphere Plugin Setup](https://github.com/velero-io/velero-plugin-for-vsphere#velero-plugin-for-vsphere-installation-and-configuration-details)    |
| [Container Storage Interface (CSI)](https://github.com/vmware-tanzu/velero-plugin-for-csi/)| 🚫                 | CSI Volumes                  | [Velero plugin for CSI](https://github.com/vmware-tanzu/velero-plugin-for-csi/)             | [CSI Plugin Setup](https://github.com/vmware-tanzu/velero-plugin-for-csi#kinds-of-plugins-included)        |
{{< /table >}}

Contact: [#Velero Slack](https://kubernetes.slack.com/messages/velero), [GitHub Issues](https://github.com/velero-io/velero/issues)

## Community supported providers
{{< table caption="Community supported providers" >}}

| Provider                  | Object Store                 | Volume Snapshotter                 | Plugin Documentation   | Contact                         |
|---------------------------|------------------------------|------------------------------------|------------------------|---------------------------------|
| [AlibabaCloud](https://www.alibabacloud.com/)        | Alibaba Cloud OSS            | Alibaba Cloud                      | [AlibabaCloud](https://github.com/AliyunContainerService/velero-plugin)     | [GitHub Issue](https://github.com/AliyunContainerService/velero-plugin/issues)              |
| [DigitalOcean](https://www.digitalocean.com/)        | DigitalOcean Object Storage  | DigitalOcean Volumes Block Storage | [StackPointCloud](https://github.com/StackPointCloud/ark-plugin-digitalocean)  |                                 |
| [Hewlett Packard](https://www.hpe.com/us/en/storage.html)     | 🚫                           | HPE Storage                        | [Hewlett Packard](https://github.com/hpe-storage/velero-plugin)  | [Slack](https://slack.hpedev.io/), [GitHub Issue](https://github.com/hpe-storage/velero-plugin/issues) |
| [OpenEBS](https://openebs.io/)             | 🚫                           | OpenEBS CStor Volume               | [OpenEBS](https://github.com/openebs/velero-plugin)          | [Slack](https://openebs-community.slack.com/), [GitHub Issue](https://github.com/openebs/velero-plugin/issues) |
| [OpenStack](https://www.openstack.org/) | Swift | Cinder | [OpenStack](https://github.com/Lirt/velero-plugin-for-openstack) | [GitHub Issue](https://github.com/Lirt/velero-plugin-for-openstack/issues) |
| [Portworx](https://portworx.com/)            | 🚫                           | Portworx Volume                    | [Portworx](https://docs.portworx.com/scheduler/kubernetes/ark.html)         | [Slack](https://portworx.slack.com/messages/px-k8s), [GitHub Issue](https://github.com/portworx/ark-plugin/issues) |
| [Storj](https://storj.io)               | Storj Object Storage         | 🚫                                 | [Storj](https://github.com/storj-thirdparty/velero-plugin)            | [GitHub Issue](https://github.com/storj-thirdparty/velero-plugin/issues)              |
{{< /table >}}

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
[25]: https://github.com/hpe-storage/velero-plugin
[30]: restic.md
[36]: https://github.com/velero-io/velero-plugin-for-gcp#setup
[38]: https://www.cloudian.com/
