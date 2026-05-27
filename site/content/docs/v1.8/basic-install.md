---
title: "Basic Install"
layout: docs
---

Use this doc to get a basic installation of Velero.
Refer [this document](customize-installation.md) to customize your installation.

## Prerequisites

- Access to a Kubernetes cluster, v1.16 or later, with DNS and container networking enabled.
- `kubectl` installed locally

Velero uses object storage to store backups and associated artifacts. It also optionally integrates with supported block storage systems to snapshot your persistent volumes. Before beginning the installation process, you should identify the object storage provider and optional block storage provider(s) you'll be using from the list of [compatible providers][0].

Velero supports storage providers for both cloud-provider environments and on-premises environments. For more details on on-premises scenarios, see the [on-premises documentation][2].

### Velero on Windows

Velero does not officially support Windows. In testing, the Velero team was able to backup stateless Windows applications only. The restic integration and backups of stateful applications or PersistentVolumes were not supported.

If you want to perform your own testing of Velero on Windows, you must deploy Velero as a Windows container. Velero does not provide official Windows images, but its possible for you to build your own Velero Windows container image to use. Note that you must build this image on a Windows node.

## Install the CLI

### Option 1: MacOS - Homebrew

On macOS, you can use [Homebrew](https://brew.sh) to install the `velero` client:

```bash
brew install velero
```

### Option 2: GitHub release

1. Download the [latest release][1]'s tarball for your client platform.
1. Extract the tarball:

   ```bash
   tar -xvf <RELEASE-TARBALL-NAME>.tar.gz
   ```

1. Move the extracted `velero` binary to somewhere in your `$PATH` (`/usr/local/bin` for most users).

### Option 3: Windows - Chocolatey

On Windows, you can use [Chocolatey](https://chocolatey.org/install) to install the [velero](https://chocolatey.org/packages/velero) client:

```powershell
choco install velero
```

## Install and configure the server components

There are two supported methods for installing the Velero server components:

- the `velero install` CLI command
- the [Helm chart](https://vmware-tanzu.github.io/helm-charts/)

Velero uses storage provider plugins to integrate with a variety of storage systems to support backup and snapshot operations. The steps to install and configure the Velero server components along with the appropriate plugins are specific to your chosen storage provider. To find installation instructions for your chosen storage provider, follow the documentation link for your provider at our [supported storage providers][0] page

_Note: if your object storage provider is different than your volume snapshot provider, follow the installation instructions for your object storage provider first, then return here and follow the instructions to [add your volume snapshot provider][4]._

## Command line Autocompletion

Please refer to [this part of the documentation][5].

[0]: supported-providers.md
[1]: https://github.com/velero-io/velero/releases/latest
[2]: on-premises.md
[3]: overview-plugins.md
[4]: customize-installation.md#install-an-additional-volume-snapshot-provider
[5]: customize-installation.md#optional-velero-cli-configurations