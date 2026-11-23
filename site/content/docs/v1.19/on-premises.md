---
title: "On-Premises Environments"
layout: docs
---

You can run Velero in an on-premises cluster in different ways depending on your requirements.

### Selecting an object storage provider

You must select an object storage backend that Velero can use to store backup data. [Supported providers][0] contains information on various
options that are supported or have been reported to work by users.

If you do not already have an object storage system, [MinIO][2] is an open-source S3-compatible object storage system that can be installed on-premises and is compatible with Velero. The details of configuring it for production usage are out of scope for Velero's documentation, but an [evaluation install guide][3] using MinIO is provided for convenience.

### (Optional) Selecting volume snapshot providers

If you need to back up persistent volume data, you must select a volume backup solution. [Supported providers][0] contains information on the supported options.

For example, if you use [Portworx][4] for persistent storage, you can install their Velero plugin to get native Portworx snapshots as part of your Velero backups.

If there is no native snapshot plugin available for your storage platform, you can use Velero's [File System Backup][1], which provides a platform-agnostic file-level backup solution for volume data.

### Air-gapped deployments

In an air-gapped deployment, there is no access to the public internet, and therefore no access to public container registries.

In these scenarios, you will need to make sure that you have an internal registry, such as [Harbor][5], installed and the Velero core and plugin images loaded into your internal registry.

Below you will find instructions to downloading the Velero images to your local machine, tagging them, then uploading them to your custom registry.

#### Preparing the Velero image

First, download the Velero image, tag it for the your private registry, then upload it into the registry so that it can be pulled by your cluster.

```bash
PRIVATE_REG=<your private registry>
VELERO_VERSION=<version of Velero you're targeting, for example v1.4.0>

docker pull velero/velero:$VELERO_VERSION
docker tag velero/velero:$VELERO_VERSION $PRIVATE_REG/velero:$VELERO_VERSION
docker push $PRIVATE_REG/velero:$VELERO_VERSION
```

#### Preparing plugin images

Next, repeat these steps for any plugins you may need. This example will use the AWS plugin, but the plugin name should be replaced with the plugins you will need.

```bash
PRIVATE_REG=<your private registry>
PLUGIN_VERSION=<version of plugin you're targeting, for example v1.0.2>

docker pull velero/velero-plugin-for-aws:$PLUGIN_VERSION
docker tag velero/velero-plugin-for-aws:$PLUGIN_VERSION $PRIVATE_REG/velero-plugin-for-aws:$PLUGIN_VERSION
docker push $PRIVATE_REG/velero-plugin-for-aws:$PLUGIN_VERSION
```

#### Preparing the restore helper image (optional)

If you are using File System Backup, you will also need to upload the restore helper image.

```bash
PRIVATE_REG=<your private registry>
VELERO_VERSION=<version of Velero you're targeting, for example v1.4.0>

docker pull velero/velero-restore-helper:$VELERO_VERSION
docker tag velero/velero-restore-helper:$VELERO_VERSION $PRIVATE_REG/velero-restore-helper:$VELERO_VERSION
docker push $PRIVATE_REG/velero-restore-helper:$VELERO_VERSION
```

#### Pulling specific architecture images (optional)

Velero uses Docker manifests for its images, allowing Docker to pull the image needed based on your client machine's architecture.

If you need to pull a specific image, you should replace the `velero/velero` image with the specific architecture image, such as `velero/velero-arm`.

To see an up-to-date list of architectures, be sure to enable Docker experimental features and use `docker manifest inspect velero/velero` (or whichever image you're interested in), and join the architecture string to the end of the image name with `-`.

#### Installing Velero

By default, `velero install` will use the public `velero/velero` image. When using an air-gapped deployment, use your private registry's image for Velero and your private registry's images for any plugins.

```bash
velero install \
 --image=$PRIVATE_REG/velero:$VELERO_VERSION \
 --plugins=$PRIVATE_REG/velero-plugin-for-aws:$PLUGIN_VERSION \
<....>
```


[0]: supported-providers.md
[1]: file-system-backup.md
[2]: https://min.io
[3]: contributions/minio.md
[4]: https://portworx.com
[5]: https://goharbor.io/
