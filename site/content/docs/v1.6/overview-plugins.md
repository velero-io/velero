---
title: "Velero plugin system"
layout: docs
---

Velero uses storage provider plugins to integrate with a variety of storage systems to support backup and snapshot operations.

For server installation, Velero requires that at least one plugin is added (with the `--plugins` flag). The plugin will be either of the type object store or volume snapshotter, or a plugin that contains both. An exception to this is that when the user is not configuring a backup storage location or a snapshot storage location at the time of install, this flag is optional.

Any plugin can be added after Velero has been installed by using the command `velero plugin add <registry/image:version>`.

Example with a dockerhub image: `velero plugin add velero/velero-plugin-for-aws:v1.0.0`.

In the same way, any plugin can be removed by using the command `velero plugin remove <registry/image:version>`.

## Creating a new plugin

Anyone can add integrations for any platform to provide additional backup and volume storage without modifying the Velero codebase. To write a plugin for a new backup or volume storage platform, take a look at our [example repo][1] and at our documentation for [Custom plugins][2].

## Adding a new plugin

After you publish your plugin on your own repository, open a PR that adds a link to it under the appropriate list of [supported providers][3] page in our documentation.

You can also add the [`velero-plugin` GitHub Topic][4] to your repo, and it will be shown under the aggregated list of repositories automatically.

[1]: https://github.com/velero-io/velero-plugin-example/
[2]: custom-plugins.md
[3]: supported-providers.md
[4]: https://github.com/topics/velero-plugin
