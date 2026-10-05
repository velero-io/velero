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

#### Build local image

If you want to build an image with the same OS type and CPU architecture with your local machine, you can keep most the build parameters as default.  
Run below command to build the local image:  
```bash
make container
```
Optionally, set the `$VERSION` environment variable to change the image tag or `$BIN` to change which binary to build a container image for.  
Optionally, you can set the `$REGISTRY` environment variable. For example, if you want to build the `gcr.io/my-registry/velero:main` image, set `$REGISTRY` to `gcr.io/my-registry`. If this variable is not set, the default is `velero`.  
The image is preserved in the local machine, you can run `docker push` to push the image to the specified registry, or if not specified, docker hub by default.  

#### Build hybrid image

You can also build a hybrid image that supports multiple OS types or CPU architectures. A hybrid image contains a manifest list with one or more manifests each of which maps to a single `os type/arch/os version` configuration.  
Below `os type/arch/os version` configurations are tested and supported:
* `linux/amd64`
* `linux/arm64`
* `windows/amd64/ltsc2022`

The hybrid image must be pushed to a registry as the local system doesn't support all the manifests in the image. So `BUILDX_OUTPUT_TYPE` parameter must be set as `registry`.  
By default, `$REGISTRY` is set as `velero`, you can change it to your own registry.  

To build a hybrid image, the following one time setup is necessary:

1. If you are building cross platform container images
    ```bash
    $ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
    ```
2. Create and bootstrap a new docker buildx builder
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

Now build and push the container image by running the `make container` command with `$BUILDX_OUTPUT_TYPE` set to `registry`.

Blow command builds a hybrid image with single configuration `linux/amd64`:  
```bash
$ REGISTRY=myrepo BUILDX_OUTPUT_TYPE=registry make container
```

Blow command builds a hybrid image with configurations `linux/amd64` and `linux/arm64`:  
```bash
$ REGISTRY=myrepo BUILDX_OUTPUT_TYPE=registry BUILD_ARCH=amd64,arm64 make container
```

Blow command builds a hybrid image with configurations `linux/amd64`, `linux/arm64` and `windows/amd64/ltsc2022`:  
```bash
$ REGISTRY=myrepo BUILDX_OUTPUT_TYPE=registry BUILD_OS=linux,windows BUILD_ARCH=amd64,arm64 make container
```

Note: if you want to update the image but not change its name, you will have to trigger Kubernetes to pick up the new image. One way of doing so is by deleting the Velero deployment pod and node-agent pods:

```bash
kubectl -n velero delete pods -l deploy=velero
```

[4]: https://blog.golang.org/organizing-go-code
[5]: https://golang.org/doc/install
[22]: https://github.com/velero-io/velero/releases
[23]: https://docs.docker.com/buildx/working-with-buildx/
[24]: https://github.com/docker/buildx
