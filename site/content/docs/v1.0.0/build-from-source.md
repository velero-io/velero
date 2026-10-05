---
title: "Build from source"
layout: docs
---

* [Prerequisites][1]
* [Getting the source][2]
* [Build][3]
* [Test][12]
* [Run][7]
* [Vendoring dependencies][10]

## Prerequisites

* Access to a Kubernetes cluster, version 1.7 or later.
* A DNS server on the cluster
* `kubectl` installed
* [Go][5] installed (minimum version 1.8)

## Getting the source

### Option 1) Get latest (recommended)

```bash
mkdir $HOME/go
export GOPATH=$HOME/go
go get github.com/velero-io/velero
```

Where `go` is your [import path][4] for Go.

For Go development, it is recommended to add the Go import path (`$HOME/go` in this example) to your path.

### Option 2) Release archive
Download the archive named `Source code` from the [release page][22] and extract it in your Go import path as `src/github.com/velero-io/velero`.

Note that the Makefile targets assume building from a git repository. When building from an archive, you will be limited to the `go build` commands described below.

## Build
There are a number of different ways to build `velero` depending on your needs. This section outlines the main possibilities.

To build the `velero` binary on your local machine, compiled for your OS and architecture, run:

```bash
go build ./cmd/velero
```

or:

```bash
make local
```

The latter will place the compiled binary under `$PWD/_output/bin/$GOOS/$GOARCH`, and will splice version and git commit information in so that `velero version` displays proper output. `velero install` will also use the version information to determine which tagged image to deploy.

To build the `velero` binary targeting `linux/amd64` within a build container on your local machine, run:

```bash
make build
```

See the **Cross compiling** section below for details on building for alternate OS/architecture combinations.

To build a Velero container image, first set the `$REGISTRY` environment variable. For example, if you want to build the `gcr.io/my-registry/velero:main` image, set `$REGISTRY` to `gcr.io/my-registry`. Optionally, set the `$VERSION` environment variable to change the image tag. Then, run:

```bash
make container
```

To push your image to a registry, run:

```bash
make push
```

### Update generated files

The following files are automatically generated from the source code:

* The clientset
* Listers
* Shared informers
* Documentation
* Protobuf/gRPC types

Run `make update` to regenerate files if you make the following changes:

* Add/edit/remove command line flags and/or their help text
* Add/edit/remove commands or subcommands
* Add new API types

Run [generate-proto.sh][13] to regenerate files if you make the following changes:

* Add/edit/remove protobuf message or service definitions. These changes require the [proto compiler][14] and compiler plugin `protoc-gen-go` version v1.0.0.

### Cross compiling

By default, `make build` builds an `velero` binary for `linux-amd64`.
To build for another platform, run `make build-<GOOS>-<GOARCH>`.
For example, to build for the Mac, run `make build-darwin-amd64`.
All binaries are placed in `_output/bin/<GOOS>/<GOARCH>`-- for example, `_output/bin/darwin/amd64/velero`.

Velero's `Makefile` has a convenience target, `all-build`, that builds the following platforms:

* linux-amd64
* linux-arm
* linux-arm64
* darwin-amd64
* windows-amd64

## 3. Test

To run unit tests, use `make test`. You can also run `make verify` to ensure that all generated
files (clientset, listers, shared informers, docs) are up to date.

## 4. Run

### Prerequisites

When running Velero, you will need to ensure that you set up all of the following:

* Appropriate RBAC permissions in the cluster
  * Read access for all data from the source cluster and namespaces
  * Write access to the target cluster and namespaces
* Cloud provider credentials
  * Read/write access to volumes
  * Read/write access to object storage for backup data
* A [BackupStorageLocation][20] object definition for the Velero server
* (Optional) A [VolumeSnapshotLocation][21] object definition for the Velero server, to take PV snapshots

### Create a cluster

To provision a cluster on AWS using Amazon’s official CloudFormation templates, here are two options:

* EC2 [Quick Start for Kubernetes][17]

* eksctl - [a CLI for Amazon EKS][18]

### Option 1: Run your Velero server locally

Running the Velero server locally can speed up iterative development. This eliminates the need to rebuild the Velero server
image and redeploy it to the cluster with each change.

#### 1. Set environment variables

Set the appropriate environment variable for your cloud provider:

AWS: [AWS_SHARED_CREDENTIALS_FILE][15]

GCP: [GOOGLE_APPLICATION_CREDENTIALS][16]

Azure:

  1. AZURE_CLIENT_ID

  2. AZURE_CLIENT_SECRET

  3. AZURE_SUBSCRIPTION_ID

  4. AZURE_TENANT_ID

  5. AZURE_STORAGE_ACCOUNT_ID

  6. AZURE_STORAGE_KEY

  7. AZURE_RESOURCE_GROUP

#### 2. Create required Velero resources in the cluster

You can use the `velero install` command to install velero into your cluster, then remove the deployment from the cluster, leaving you
with all of the required in-cluster resources.

##### Example

This examples assumes you are using an existing cluster in AWS.

Using the `velero` binary that you've built, run `velero install`:

```bash
# velero install requires a credentials file to exist, but we will
# not be using it since we're running the server locally, so just
# create an empty file to pass to the install command.
touch fake-credentials-file

velero install \
  --provider aws \
  --bucket $BUCKET \
  --backup-location-config region=$REGION \
  --snapshot-location-config region=$REGION \
  --secret-file ./fake-credentials-file

# 'velero install' creates an in-cluster deployment of the
# velero server using an official velero image, but we want
# to run the velero server on our local machine using the
# binary we built, so delete the in-cluster deployment.
kubectl --namespace velero delete deployment velero

rm fake-credentials-file
```

#### 3. Start the Velero server locally

* Make sure the `velero` binary you build is in your `PATH`, or specify the full path.

* Start the server: `velero server [CLI flags]`. The following CLI flags may be useful to customize, but see `velero server --help` for full details:
  * `--kubeconfig`: set the path to the kubeconfig file the Velero server uses to talk to the Kubernetes apiserver (default `$KUBECONFIG`)
  * `--namespace`: the set namespace where the Velero server should look for backups, schedules, restores (default `velero`)
  * `--log-level`: set the Velero server's log level (default `info`)
  * `--plugin-dir`: set the directory where the Velero server looks for plugins (default `/plugins`)
  * `--metrics-address`: set the bind address and port where Prometheus metrics are exposed (default `:8085`)

### Option 2: Run your Velero server in a deployment

1. Ensure you've built a `velero` container image and either loaded it onto your cluster's nodes, or pushed it to a registry (see [build][3]).

1. Install Velero into the cluster (the example below assumes you're using AWS):

    ```bash
    velero install \
      --provider aws \
      --image $YOUR_CONTAINER_IMAGE \
      --bucket $BUCKET \
      --backup-location-config region=$REGION \
      --snapshot-location-config region=$REGION \
      --secret-file $YOUR_AWS_CREDENTIALS_FILE
    ```

## 5. Vendoring dependencies

If you need to add or update the vendored dependencies, see [Vendoring dependencies][11].

[0]: ../README.md
[1]: #prerequisites
[2]: #getting-the-source
[3]: #build
[4]: https://blog.golang.org/organizing-go-code
[5]: https://golang.org/doc/install
[6]: https://github.com/velero-io/velero/tree/main/examples
[7]: #run
[8]: config-definition.md
[10]: #vendoring-dependencies
[11]: vendoring-dependencies.md
[12]: #test
[13]: https://github.com/velero-io/velero/blob/main/hack/generate-proto.sh
[14]: https://grpc.io/docs/quickstart/go.html#install-protocol-buffers-v3
[15]: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#the-shared-credentials-file
[16]: https://cloud.google.com/docs/authentication/getting-started#setting_the_environment_variable
[17]: https://aws.amazon.com/quickstart/architecture/heptio-kubernetes/
[18]: https://eksctl.io/
[19]: ../examples/README.md
[20]: api-types/backupstoragelocation.md
[21]: api-types/volumesnapshotlocation.md
[22]: https://github.com/velero-io/velero/releases
