---
title: "Image tagging policy"
layout: docs
---

This document describes Velero's image tagging policy.

## Released versions

`gcr.io/heptio-images/velero:<SemVer>`

Velero follows the [Semantic Versioning](http://semver.org/) standard for releases. Each tag in the `github.com/velero-io/velero` repository has a matching image, e.g. `gcr.io/heptio-images/velero:v1.0.0`.

### Latest

`gcr.io/heptio-images/velero:latest`

The `latest` tag follows the most recently released version of Velero.

## Development

`gcr.io/heptio-images/velero:main`

The `main` tag follows the latest commit to land on the `main` branch.
