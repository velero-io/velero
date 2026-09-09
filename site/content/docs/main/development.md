---
title: "Development "
layout: docs
---

## Update generated files

Run `make update` to regenerate files if you make the following changes:

* Add/edit/remove command line flags and/or their help text
* Add/edit/remove commands or subcommands
* Add new API types
* Add/edit/remove plugin protobuf message or service definitions

The following files are automatically generated from the source code:

* CRDs
* Documentation
* Protobuf/gRPC types

You can run `make verify` to ensure that all generated files (CRDs, docs) are up to date.

## Linting

You can run `make lint` which executes golangci-lint inside the build image, or `make local-lint` which executes outside of the build image.
Both `make lint` and `make local-lint` will only run the linter against changes.

Use `lint-all` to run the linter against the entire code base.

The default linters are defined in the `Makefile` via the `LINTERS` variable.

You can also override the default list of linters by  running the command

`$ make lint LINTERS=gosec`

## Test

To run unit tests, use `make test`.

## Using the main branch

If you are developing or using the main branch, note that you may need to update the Velero CRDs to get new changes as other development work is completed.

```bash
velero install --crds-only --dry-run -o yaml | kubectl apply -f -
```

**NOTE:** You could change the default CRD API version (v1beta1 _or_ v1) if Velero CLI can't discover the Kubernetes preferred CRD API version. The Kubernetes version < 1.16 preferred CRD API version is v1beta1; the Kubernetes version >= 1.16 preferred CRD API version is v1.


## Dependency management

Velero is written in Go and uses [Go modules](https://go.dev/ref/mod) to manage its dependencies. Direct and indirect dependencies are declared in `go.mod` and pinned in `go.sum`.

The project keeps dependencies up to date and responds to upstream security fixes as follows:

* [Dependabot](https://docs.github.com/en/code-security/dependabot) is configured in [`.github/dependabot.yml`](https://github.com/velero-io/velero/blob/main/.github/dependabot.yml) to open pull requests for Go module and GitHub Actions updates on a weekly schedule. Updates are grouped to reduce noise.
* Dependency update pull requests follow the same review process as any other change: they must pass CI and be approved by a maintainer before merging.
* Security-relevant updates are prioritized. Vulnerabilities in dependencies that affect Velero are handled through the [security release process](https://github.com/velero-io/.github/blob/main/SECURITY.md).
* New direct dependencies should be kept to a minimum and use a license compatible with Velero's [Apache 2.0 license](https://github.com/velero-io/velero/blob/main/LICENSE).
