---
title: Announcing a new GitHub home for Velero
slug: announcing-gh-move
image: /img/posts/vmware-tanzu.png
excerpt: The next Velero release (v1.2) will be built out of a new GitHub organization, and we have significant changes to our plugins.
author_name: Carlisia Thompson
author_avatar: /img/contributors/carlisia-thompson.png
categories: ['velero']
# Tag should match author to drive author pages
tags: ['Carlisia Thompson']
---

## Big announcement

We are now part of a brand new GitHub organization: [VMware Tanzu][1]. VMware Tanzu is a new family of projects, products and services for the cloud native world. With the Velero project being a cloud native technology that extends Kubernetes, it is only natural that it would be moved to sit alongside all the other VMware-supported cloud native repositories. You can read more about this change in this [VMware blog post][2].

## The new Velero

The new Velero repository can now be found at [github.com/velero-io/velero](https://github.com/velero-io/velero). Past issues, pull requests, commits, contributors, etc., have all been moved to this repo.

The next Velero release, version 1.2, will be built out of this new repository and is slated to come out at the end of October. The main [set of changes][5] for version 1.2 is the restructuring around how we will be handling all Object Store and Volume Snapshotter plugins. Previously, Velero included both types of plugins for AWS, Microsoft Azure, and Google Cloud Platform (GCP) in-tree. Beginning with Velero 1.2, these plugins will be moved out of tree and installed like any other plugin.

## Velero plugins

With more and more providers wanting to support Velero, it gets more difficult to justify excluding new plugins from being in-tree while continuing to maintain the AWS, Microsoft Azure, and GCP plugins in-tree. At the same time, if we were to include any more plugins in-tree, it would ultimately become the responsibility of the Velero team to maintain an increasing number of plugins in an unsustainable way. As the opportunity to move to a new GitHub organization presented itself, we thought it was a good time to make structural changes.

The three original native plugins and their respective documentation will each have their own repo under the new VMware Tanzu GitHub organization as of version 1.2. You will be able to find them by looking up our list of [Velero supported providers][3].

Maintenance of these plugins will continue to be done by the Velero core team as usual, although we will gladly promote active contributors to maintainers. This change mainly aims to achieve the following goals:

- Interface with all plugins equally and consistently
- Encourage developers to get involved with the smaller code base of each plugin and potentially be promoted to plugin maintainers
- Iterate on plugins separately from the core codebase
- Reduce the size of the Velero binaries and images by extracting these SDKs and having a separate release for each individual provider

Instructions for upgrading to version 1.2 and installing Velero and its plugins will be added to [our documentation][4].

## Feedback

As always, we welcome feedback and participation in the development of Velero. All information on how to contact us or become involved can be found here: https://velero.io/community/

[1]: https://github.com/vmware-tanzu
[2]: https://blogs.vmware.com/cloudnative/2019/10/01/open-source-in-vmware-tanzu/
[3]: ../docs/main/supported-providers
[4]: https://velero.io/docs/main/
[5]: https://github.com/velero-io/velero/issues#workspaces/velero-5c59c15e39d47b774b5864e3/board?milestones=v1.2%232019-10-31&filterLogic=any&repos=99143276&showPipelineDescriptions=false
