---
title: "Rapid iterative Velero development with Tilt "
layout: docs
---

## Overview
This document describes how to use [Tilt](https://tilt.dev) with any cluster for a simplified
workflow that offers easy deployments and rapid iterative builds.

This setup allows for continuing deployment of the Velero server and, if specified, any provider plugin or the restic daemonset.
It does this work by:

1. Deploying the necessary Kubernetes resources, such as the Velero CRDs and Velero deployment
1. Building a local binary for Velero and (if specified) provider plugins as a `local_resource`
1. Invoking `docker_build` to live update any binary into the container/init container and trigger a re-start

Tilt will look for configuration files under `velero/tilt-resources`. Most of the
files in this directory are gitignored so you may configure your setup according to your needs.

## Prerequisites
1. [Docker](https://docs.docker.com/install/) v19.03 or newer
1. A Kubernetes cluster v1.12 or greater (does not have to be Kind)
1. [Tilt](https://docs.tilt.dev/install.html) v0.12.0 or newer
1. Clone the [Velero project](https://github.com/velero-io/velero) repository
   locally
1. Access to an S3 object storage
1. Clone any [provider plugin(s)](https://velero.io/plugins/) you want to make changes to and deploy (optional, must be configured to be deployed by the Velero Tilt's setup, [more info below](#provider-plugins))

Note: To properly configure any plugin you use, please follow the plugin's documentation.

## Getting started

### tl;dr
- Copy all sample files under `velero/tilt-resources/examples` into `velero/tilt-resources`.
- Configure the `velero_v1_backupstoragelocation.yaml` file, and the `cloud` file for the storage credentials/secret.

- Run `tilt up`.

### Create a Tilt settings file
Create a configuration file named `tilt-settings.json` and place it in your local copy of `velero/tilt-resources`. Alternatively,
you may copy and paste the sample file found in  `velero/tilt-resources/examples`.

Here is an example:

```json
{
    "default_registry": "",
    "enable_providers": [
        "aws",
        "gcp",
        "azure",
        "csi"
    ],
    "providers": {
        "aws": "../velero-plugin-for-aws",
        "gcp": "../velero-plugin-for-gcp",
        "azure": "../velero-plugin-for-microsoft-azure",
        "csi": "../velero-plugin-for-csi"
    },
    "allowed_contexts": [
        "development"
    ],
    "enable_restic": false,
    "create_backup_locations": true,
    "setup-minio": true,
    "enable_debug": false,
    "debug_continue_on_start": true
}
```

#### tilt-settings.json fields
**default_registry** (String, default=""): The image registry to use if you need to push images. See the [Tilt
*documentation](https://docs.tilt.dev/api.html#api.default_registry) for more details.

**provider_repos** (Array[]String, default=[]): A list of paths to all the provider plugins you want to make changes to. Each provider must have a
`tilt-provider.json` file describing how to build the provider.

**enable_providers** (Array[]String, default=[]): A list of the provider plugins to enable. See [provider plugins](provider-plugins)
for more details. Note: when not making changes to a plugin, it is not necessary to load them into
Tilt: an existing image and version might be specified in the Velero deployment instead, and Tilt will load that.

**allowed_contexts** (Array, default=[]): A list of kubeconfig contexts Tilt is allowed to use. See the Tilt documentation on
*[allow_k8s_contexts](https://docs.tilt.dev/api.html#api.allow_k8s_contexts) for more details. Note: Kind is automatically allowed.

**enable_restic** (Bool, default=false): Indicate whether to deploy the restic Daemonset. If set to `true`, Tilt will look for a `velero/tilt-resources/restic.yaml`  file
containing the configuration of the Velero restic DaemonSet.

**create_backup_locations** (Bool, default=false): Indicate whether to create one or more backup storage locations. If set to `true`, Tilt will look for a `velero/tilt-resources/velero_v1_backupstoragelocation.yaml` file
containing at least one configuration for a Velero backup storage location.

**setup-minio** (Bool, default=false): Configure this to  `true` if you want to configure backup storage locations in a Minio instance running inside your cluster.

**enable_debug** (Bool, default=false): Configure this to  `true` if you want to debug the velero process using [Delve](https://github.com/go-delve/delve).

**debug_continue_on_start** (Bool, default=true): Configure this to  `true` if you want the velero process to continue on start when in debug mode. See [Delve CLI documentation](https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv.md).

### Create Kubernetes resource files to deploy
All needed Kubernetes resource files are provided as ready to use samples in the `velero/tilt-resources/examples` directory. You only have to move them to the `velero/tilt-resources` level.

Because the Velero Kubernetes deployment as well as the restic DaemonSet contain the configuration
for any plugin to be used, files for these resources are expected to be provided by the user so you may choose
which provider plugin to load as a init container. Currently, the sample files provided are configured with all the
plugins supported by Velero, feel free to remove any of them as needed.

For Velero to operate fully, it also needs at least one backup
storage location. A sample file is provided that needs to be modified with the specific
configuration for your object storage. See the next sub-section for more details on this.

### Configure a backup storage location
You will have to configure the `velero/tilt-resources/velero_v1_backupstoragelocation.yaml` with the proper values according to your storage provider. Read the [plugin documentation](https://velero.io/plugins/)
to learn what field/value pairs are required for your particular provider's backup storage location configuration.

Below are some ways to configure a backup storage location for Velero.
#### As a storage with a service provider
Follow the provider documentation to provision the storage. We have a [list of all known object storage providers](supported-providers/) with corresponding plugins for Velero.

#### Using MinIO as an object storage
Note: to use MinIO as an object storage, you will need to use the [`AWS` plugin](https://github.com/velero-io/velero-plugin-for-aws), and configure the storage location with the `spec.provider` set to `aws` and the `spec.config.region` set to `minio`. Example:
```
spec:
  config:
    region: minio
    s3ForcePathStyle: "true"
    s3Url: http://minio.velero.svc:9000
  objectStorage:
    bucket: velero
  provider: aws
```

Here are two ways to use MinIO as the storage:

1) As a MinIO instance running inside your cluster (don't do this for production!)

    In the `tilt-settings.json` file, set `"setup-minio": true`. This will configure a Kubernetes deployment containing a running
instance of MinIO inside your cluster. There are [extra steps](contributions/minio/#expose-minio-outside-your-cluster-with-a-service)
necessary to expose MinIO outside the cluster. 

    To access this storage, you will need to expose MinIO outside the cluster by forwarding the MinIO port to the local machine using kubectl port-forward -n <velero-namespace> svc/minio 9000. Update the BSL configuration to use that as its "public URL" by adding `publicUrl: http://localhost:9000` to the BSL config. This is necessary to do things like download a backup file.

    Note: with this setup, when your cluster is terminated so is the storage and any backup/restore in it.

1) As a standalone MinIO instance running locally in a Docker container

    See [these instructions](https://github.com/velero-io/velero/discussions/3381) to run MinIO locally on your computer, as a standalone as opposed to running it on a Pod.

Please see our [locations documentation](locations/) to learn more how backup locations work.

### Configure the provider credentials (secret)
Whatever object storage provider you use, configure the credentials for in the `velero/tilt-resources/cloud` file. Read the [plugin documentation](https://velero.io/plugins/)
to learn what field/value pairs are required for your provider's credentials. The Tilt file will invoke Kustomize to create the secret under the hard-coded key `secret.cloud-credentials.data.cloud` in the Velero namespace.

There is a sample credentials file properly formatted for a MinIO storage credentials in `velero/tilt-resources/examples/cloud`.

### Configure debugging with Delve
If you would like to debug the Velero process, you can enable debug mode by setting the field `enable_debug` to `true` in your `tilt-resources/tile-settings.json` file.
This will enable you to debug the process using [Delve](https://github.com/go-delve/delve).
By enabling debug mode, the Velero executable will be built in debug mode (using the flags `-gcflags="-N -l"` which disables optimizations and inlining), and the process will be started in the Velero deployment using [`dlv exec`](https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv_exec.md).

The debug server will accept connections on port 2345 and Tilt is configured to forward this port to the local machine.
Once Tilt is [running](#run-tilt) and the Velero resource is ready, you can connect to the debug server to begin debugging.
To connect to the session, you can use the Delve CLI locally by running `dlv connect 127.0.0.1:2345`. See the [Delve CLI documentation](https://github.com/go-delve/delve/tree/master/Documentation/cli) for more guidance on how to use Delve.
Delve can also be used within a number of [editors and IDEs](https://github.com/go-delve/delve/blob/master/Documentation/EditorIntegration.md).

By default, the Velero process will continue on start when in debug mode.
This means that the process will run until a breakpoint is set.
You can disable this by setting the field `debug_continue_on_start` to `false` in your `tilt-resources/tile-settings.json` file.
When this setting is disabled, the Velero process will not continue to run until a `continue` instruction is issued through your Delve session.

When exiting your debug session, the CLI and editor integrations will typically ask if the remote process should be stopped.
It is important to leave the remote process running and just disconnect from the debugging session.
By stopping the remote process, that will cause the Velero container to stop and the pod to restart.
If backups are in progress, these will be left in a stale state as they are not resumed when the Velero pod restarts.

### Run Tilt!
To launch your development environment, run:

``` bash
tilt up
```

This will output the address to a web browser interface where you can monitor Tilt's status and the logs for each Tilt resource. After a brief amount of time, you should have a running development environment, and you should now be able to
create backups/restores and fully operate Velero.

Note: Running `tilt down` after exiting out of Tilt [will delete all resources](https://docs.tilt.dev/cli/tilt_down.html) specified in the Tiltfile.

Tip: Create an alias to `velero/_tuiltbuild/local/velero` and you won't have to run `make local` to get a refreshed version of the Velero CLI, just use the alias.

Please see the documentation for [how Velero works](how-velero-works/).

## Provider plugins
A provider must supply a `tilt-provider.json` file describing how to build it. Here is an example:

```json
{
  "plugin_name": "velero-plugin-for-aws",
  "context": ".",
  "image": "velero/velero-plugin-for-aws",
  "live_reload_deps": [
    "velero-plugin-for-aws"
  ],
  "go_main": "./velero-plugin-for-aws"
}
```

## Live updates
Each provider plugin configured to be deployed by Velero's Tilt setup has a `live_reload_deps` list. This defines the files and/or directories that Tilt
should monitor for changes. When a dependency is modified, Tilt rebuilds the provider's binary **on your local
machine**, copies the binary to the init container, and triggers a restart of the Velero container. This is significantly faster
than rebuilding the container image for each change. It also helps keep the size of each development image as small as
possible (the container images do not need the entire go toolchain, source code, module dependencies, etc.).
