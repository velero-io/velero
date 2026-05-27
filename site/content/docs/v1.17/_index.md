---
toc: "false"
cascade:
  version: v1.17
  toc: "true"
---
![100]

[![Build Status][1]][2]

## Overview

Velero (formerly Heptio Ark) gives you tools to back up and restore your Kubernetes cluster resources and persistent volumes. You can run Velero with a cloud provider or on-premises. Velero lets you:

* Take backups of your cluster and restore in case of loss.
* Migrate cluster resources to other clusters.
* Replicate your production cluster to development and testing clusters.

Velero consists of:

* A server that runs on your cluster
* A command-line client that runs locally

## Documentation

This site is our documentation home with installation instructions, plus information about customizing Velero for your needs, architecture, extending Velero, contributing to Velero and more.

Please use the version selector at the top of the site to ensure you are using the appropriate documentation for your version of Velero.

## Troubleshooting

If you encounter issues, review the [troubleshooting docs][30], [file an issue][4], or talk to us on the [#velero-users channel][25] on the Kubernetes Slack server.

## Contributing

If you are ready to jump in and test, add code, or help with documentation, follow the instructions on our [Start contributing](https://velero.io/docs/v1.17.0/start-contributing/) documentation for guidance on how to setup Velero for development.

## Changelog

See [the list of releases][6] to find out about feature changes.

[1]: https://github.com/velero-io/velero/workflows/Main%20CI/badge.svg
[2]: https://github.com/velero-io/velero/actions?query=workflow%3A"Main+CI"

[4]: https://github.com/velero-io/velero/issues
[6]: https://github.com/velero-io/velero/releases

[9]: https://kubernetes.io/docs/setup/
[10]: https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-with-homebrew-on-macos
[11]: https://kubernetes.io/docs/tasks/tools/install-kubectl/#tabset-1
[12]: https://github.com/kubernetes/kubernetes/blob/main/cluster/addons/dns/README.md
[14]: https://github.com/kubernetes/kubernetes
[24]: https://groups.google.com/forum/#!forum/projectvelero
[25]: https://kubernetes.slack.com/messages/velero-users

[30]: troubleshooting.md

[100]: img/velero.png
