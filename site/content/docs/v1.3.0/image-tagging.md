---
title: "Image tagging policy"
layout: docs
---

This document describes Velero's image tagging policy.

## Released versions

`velero/velero:<SemVer>`

Velero follows the [Semantic Versioning](http://semver.org/) standard for releases. Each tag in the `github.com/velero-io/velero` repository has a matching image, e.g. `velero/velero:v1.0.0`.

### Latest

`velero/velero:latest`

The `latest` tag follows the most recently released version of Velero.

## Development

`velero/velero:main`

The `main` tag follows the latest commit to land on the `main` branch.
