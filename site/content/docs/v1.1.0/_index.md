---
version: v1.1.0
---
![100]

[![Build Status][1]][2]

## Overview

Velero (formerly Heptio Ark) gives you tools to back up and restore your Kubernetes cluster resources and persistent volumes. Velero lets you:

* Take backups of your cluster and restore in case of loss.
* Migrate cluster resources to other clusters.
* Replicate your production cluster to development and testing clusters.

Velero consists of:

* A server that runs on your cluster
* A command-line client that runs locally

You can run Velero in clusters on a cloud provider or on-premises. For detailed information, see [Compatible Storage Providers][99].

## Installation

We strongly recommend that you use an [official release][6] of Velero. The tarballs for each release contain the
`velero` command-line client. Follow the [installation instructions][28] to get started.

_The code and sample YAML files in the main branch of the Velero repository are under active development and are not guaranteed to be stable. Use them at your own risk!_

## More information

[The documentation][29] provides a getting started guide, plus information about building from source, architecture, extending Velero, and more.

Please use the version selector at the top of the site to ensure you are using the appropriate documentation for your version of Velero.

## Troubleshooting

If you encounter issues, review the [troubleshooting docs][30], [file an issue][4], or talk to us on the [#velero channel][25] on the Kubernetes Slack server.

## Contributing

If you are ready to jump in and test, add code, or help with documentation, follow the instructions on our [Start contributing](https://velero.io/docs/main/start-contributing/) documentation for guidance on how to setup Velero for development.

## Changelog

See [the list of releases][6] to find out about feature changes.

[1]: https://travis-ci.org/velero-io/velero.svg?branch=main
[2]: https://travis-ci.org/velero-io/velero

[4]: https://github.com/velero-io/velero/issues
[6]: https://github.com/velero-io/velero/releases

[9]: https://kubernetes.io/docs/setup/
[10]: https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-with-homebrew-on-macos
[11]: https://kubernetes.io/docs/tasks/tools/install-kubectl/#tabset-1
[12]: https://github.com/kubernetes/kubernetes/blob/main/cluster/addons/dns/README.md
[14]: https://github.com/kubernetes/kubernetes

[24]: https://groups.google.com/forum/#!forum/projectvelero
[25]: https://kubernetes.slack.com/messages/velero

[28]: install-overview.md
[29]: https://velero.io/docs/main/
[30]: troubleshooting.md

[99]: support-matrix.md
[100]: img/velero.png
