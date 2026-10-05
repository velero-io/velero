---
title: "Build from source"
layout: docs
---

## Prerequisites

* Access to a Kubernetes cluster, version 1.7 or later.
* A DNS server on the cluster
* `kubectl` installed
* [Go][5] installed (minimum version 1.8)

## Get the source

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

When building by using `make`, it will place the binaries under `_output/bin/$GOOS/$GOARCH`. For example, you will find the binary for darwin here: `_output/bin/darwin/amd64/velero`, and the binary for linux here: `_output/bin/linux/amd64/velero`. `make` will also splice version and git commit information in so that `velero version` displays proper output.

Note: `velero install` will also use the version information to determine which tagged image to deploy. If you would like to overwrite what image gets deployed, use the `image` flag (see below for instructions on how to build images).

### Build the binary

To build the `velero` binary on your local machine, compiled for your OS and architecture, run one of these two commands:

```bash
go build ./cmd/velero
```

```bash
make local
```

### Cross compiling

To build the velero binary targeting linux/amd64 within a build container on your local machine, run:

```bash
make build
```

For any specific platform, run `make build-<GOOS>-<GOARCH>`.

For example, to build for the Mac, run `make build-darwin-amd64`.

Velero's `Makefile` has a convenience target, `all-build`, that builds the following platforms:

* linux-amd64
* linux-arm
* linux-arm64
* linux-ppc64le
* darwin-amd64
* windows-amd64

## Making images and updating Velero

If after installing Velero you would like to change the image used by its deployment to one that contains your code changes, you may do so by updating the image:

```bash
kubectl -n velero set image deploy/velero velero=myimagerepo/velero:$VERSION
```

To build a Velero container image, you need to configure `buildx` first.

### Buildx

Docker Buildx is a CLI plugin that extends the docker command with the full support of the features provided by Moby BuildKit builder toolkit. It provides the same user experience as docker build with many new features like creating scoped builder instances and building against multiple nodes concurrently.

More information in the [docker docs][23] and in the [buildx github][24] repo.

### Image building

Set the `$REGISTRY` environment variable. For example, if you want to build the `gcr.io/my-registry/velero:main` image, set `$REGISTRY` to `gcr.io/my-registry`. If this variable is not set, the default is `velero`.

Optionally, set the `$VERSION` environment variable to change the image tag or `$BIN` to change which binary to build a container image for. Then, run:

```bash
make container
```
_Note: To build build container images for both `velero` and `velero-restic-restore-helper`, run: `make all-containers`_

### Publishing container images to a registry

To publish container images to a registry, the following one time setup is necessary:

1. If you are building cross platform container images
    ```bash
    $ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    ```
1. Create and bootstrap a new docker buildx builder
    ```bash
    $ docker buildx create --use --name builder
      builder
    $ docker buildx inspect --bootstrap
      [+] Building 2.6s (1/1) FINISHED
      => [internal] booting buildkit                                2.6s
      => => pulling image moby/buildkit:buildx-stable-1             1.9s
      => => creating container buildx_buildkit_builder0             0.7s
    Name:   builder
    Driver: docker-container

    Nodes:
    Name:      builder0
    Endpoint:  unix:///var/run/docker.sock
    Status:    running
    Platforms: linux/amd64, linux/arm64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6
    ```
    NOTE: Without the above setup, the output of `docker buildx inspect --bootstrap` will be:
    ```bash
    $ docker buildx inspect --bootstrap
    Name:   default
    Driver: docker

    Nodes:
    Name:      default
    Endpoint:  default
    Status:    running
    Platforms: linux/amd64, linux/arm64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v6
    ```
    And the `REGISTRY=myrepo BUILDX_OUTPUT_TYPE=registry make container` will fail with the below error:
    ```bash
    $ REGISTRY=ashishamarnath BUILDX_PLATFORMS=linux/arm64 BUILDX_OUTPUT_TYPE=registry make container
    auto-push is currently not implemented for docker driver
    make: *** [container] Error 1
    ```

Having completed the above one time setup, now the output of `docker buildx inspect --bootstrap` should be like

```bash
$ docker buildx inspect --bootstrap
Name:   builder
Driver: docker-container

Nodes:
Name:      builder0
Endpoint:  unix:///var/run/docker.sock
Status:    running
Platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/386, linux/arm/v7, linux/arm/v
```

Now build and push the container image by running the `make container` command with `$BUILDX_OUTPUT_TYPE` set to `registry`
```bash
$ REGISTRY=myrepo BUILDX_OUTPUT_TYPE=registry make container
```

### Cross platform building

Docker `buildx` platforms supported:
* `linux/amd64`
* `linux/arm64`
* `linux/arm/v7`
* `linux/ppc64le`

For any specific platform, run `BUILDX_PLATFORMS=<GOOS>/<GOARCH> make container`

For example, to build an image for arm64, run:

```bash
BUILDX_PLATFORMS=linux/arm64 make container
```
_Note: By default, `$BUILDX_PLATFORMS` is set to `linux/amd64`_

With `buildx`, you can also build all supported platforms at the same time and push a multi-arch image to the registry. For example:

```bash
REGISTRY=myrepo VERSION=foo BUILDX_PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7,linux/ppc64le BUILDX_OUTPUT_TYPE=registry make all-containers
```
_Note: when building for more than 1 platform at the same time, you need to set `BUILDX_OUTPUT_TYPE` to `registry` as local multi-arch images are not supported [yet][25]._

Note: if you want to update the image but not change its name, you will have to trigger Kubernetes to pick up the new image. One way of doing so is by deleting the Velero deployment pod:

```bash
kubectl -n velero delete pods -l deploy=velero
```

[4]: https://blog.golang.org/organizing-go-code
[5]: https://golang.org/doc/install
[22]: https://github.com/velero-io/velero/releases
[23]: https://docs.docker.com/buildx/working-with-buildx/
[24]: https://github.com/docker/buildx
[25]: https://github.com/moby/moby/pull/38738
