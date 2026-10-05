---
title: Velero is an Open Source Tool to Back up and Migrate Kubernetes Clusters
slug: Velero-is-an-Open-Source-Tool-to-Back-up-and-Migrate-Kubernetes-Clusters # Velero.io word list : ignore
# image: https://placehold.it/200x200
excerpt: Velero is an open source tool to safely back up, recover, and migrate Kubernetes clusters and persistent volumes. It works both on premises and in a public cloud.
author_name: Velero Team
# author_avatar: https://placehold.it/64x64
categories: ['kubernetes']
# Tag should match author to drive author pages
tags: ['Velero Team']
---
Velero is an open source tool to safely back up, recover, and migrate Kubernetes clusters and persistent volumes. It works both on premises and in a public cloud. Velero consists of a server process running as a deployment in your Kubernetes cluster and a command-line interface (CLI) with which DevOps teams and platform operators configure scheduled backups, trigger ad-hoc backups, perform restores, and more.

## What Makes Velero Stand Out?
Unlike other tools which directly access the Kubernetes etcd database to perform backups and restores, Velero uses the Kubernetes API to capture the state of cluster resources and to restore them when necessary. This API-driven approach has a number of key benefits:

* Backups can capture subsets of the cluster’s resources, filtering by namespace, resource type, and/or label selector, providing a high degree of flexibility around what’s backed up and restored.
* Users of managed Kubernetes offerings often do not have access to the underlying etcd database, so direct backups/restores of it are not possible.
* Resources exposed through aggregated API servers can easily be backed up and restored even if they’re stored in a separate etcd database.

Additionally, Velero enables you to backup and restore your applications’ persistent data alongside their configurations, using either your storage platform’s native snapshot capability or an integrated file-level backup tool called [restic](https://restic.net/).

## Hats Off to the Community!
Since Velero was initially released in August 2017, we’ve had nearly 70 contributors to the project, with a ton of support from the community. We also recently reached 2000 stars on GitHub. We are excited to keep building our great community and project.

### Join the Community
* Twitter ([@projectvelero](https://twitter.com/projectvelero))
* Slack ([#velero](https://kubernetes.slack.com/messages/velero) on Kubernetes)
* Google Group ([projectvelero](groups.google.com/forum/#!forum/projectvelero))


We are continuing to work towards Velero 1.0 and would love your help working on the items in our roadmap. If you’re interested in contributing, we have a number of GitHub issues labeled as [Good First Issue](https://github.com/velero-io/velero/issues?q=is%3Aopen+is%3Aissue+label%3A%22Good+first+issue%22) and [Help Wanted](https://github.com/velero-io/velero/issues?q=is%3Aopen+is%3Aissue+label%3A%22Help+wanted%22), including items related to Prometheus metrics, the CLI UX, improved documentation, and more. We are more than happy to work with new and existing contributors alike.

_Previously posted at: <https://blogs.vmware.com/cloudnative/2019/02/28/velero-v0-11-delivers-an-open-source-tool-to-back-up-and-migrate-kubernetes-clusters/>_ <!-- Velero.io word list : ignore -->
