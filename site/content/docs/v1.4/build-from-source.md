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

To build a Velero container image, first set the `$REGISTRY` environment variable. For example, if you want to build the `gcr.io/my-registry/velero-amd64:main` image, set `$REGISTRY` to `gcr.io/my-registry`. If this variable is not set, the default is `velero`.

Optionally, set the `$VERSION` environment variable to change the image tag. Then, run:

```bash
make container
```

For any specific platform, run `ARCH=<GOOS>-<GOARCH> make container`

For example, to build an image for the Power (ppc64le), run:

```bash
ARCH=linux-ppc64le make container
```
_Note: By default, ARCH is set to linux-amd64_

To push your image to the registry. For example, if you want to push the `gcr.io/my-registry/velero-amd64:main` image, run:

```bash
make push
```

For any specific platform, run `ARCH=<GOOS>-<GOARCH> make push`

For example, to push image for the Power (ppc64le), run:

```bash
ARCH=linux-ppc64le make push
```
_Note: By default, ARCH is set to linux-amd64_

To create and push your manifest to the registry. For example, if you want to create and push the `gcr.io/my-registry/velero:main` manifest, run:

```bash
make manifest
```

For any specific platform, run `MANIFEST_PLATFORMS=<GOARCH> make manifest`

For example, to create and push manifest only for amd64, run:

```bash
MANIFEST_PLATFORMS=amd64 make manifest
```
_Note: By default, MANIFEST_PLATFORMS is set to amd64, ppc64le_

To run the entire workflow, run:

`REGISTRY=<$REGISTRY> VERSION=<$VERSION> ARCH=<GOOS>-<GOARCH> MANIFEST_PLATFORMS=<GOARCH> make container push manifest`

For example, to run the workflow only for amd64

```bash
REGISTRY=myrepo VERSION=foo MANIFEST_PLATFORMS=amd64 make container push manifest
```

_Note: By default, ARCH is set to linux-amd64_

For example, to run the workflow only for ppc64le

```bash
REGISTRY=myrepo VERSION=foo ARCH=linux-ppc64le MANIFEST_PLATFORMS=ppc64le make container push manifest
```

For example, to run the workflow for all supported platforms

```bash
REGISTRY=myrepo VERSION=foo make all-containers all-push all-manifests
```

Note: if you want to update the image but not change its name, you will have to trigger Kubernetes to pick up the new image. One way of doing so is by deleting the Velero deployment pod:

```bash
kubectl -n velero delete pods -l deploy=velero
```

[4]: https://blog.golang.org/organizing-go-code
[5]: https://golang.org/doc/install
[22]: https://github.com/velero-io/velero/releases
