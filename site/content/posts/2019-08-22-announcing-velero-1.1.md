---
title: "Announcing Velero 1.1: Improved restic Support and More Visibility" 
slug: announcing-velero-1.1
# image: https://placehold.it/200x200
excerpt: For this release, we’ve focused on improving Velero’s restic integration - making repository locks shorter lived, giving more visibility into restic repositories when migrating clusters, and expanding support to more volume types.
author_name: Nolan Brubaker
# author_avatar: https://placehold.it/64x64
categories: ['velero','release']
# Tag should match author to drive author pages
tags: ['Velero Team', 'Nolan Brubaker']
---
We’ve made big strides in improving Velero. Since our release of version 1.0 in May 2019, we have been hard at work improving our restic support and planning for the future of Velero. In addition, we’ve seen some helpful contributions from the community that will make life easier for all of our users. Also, the Velero community has reached **100 contributors**!

For this release, we’ve focused on improving Velero’s restic integration: making repository locks shorter lived, giving more visibility into restic repositories when migrating clusters, and expanding support to more volume types. Additionally, we have made several quality-of-life improvements to the Velero deployment and client.

Let’s take a look at some of the highlights of this release.


## Improved Restic Support

A big focus of our work this cycle was continuing to improve support for restic. To that end, we’ve fixed the following bugs:


- Prior to version 1.1, restic backups could be delayed or failed due to long-lived locks on the repository. Now, Velero removes stale locks from restic repositories every 5 minutes, ensuring they do not interrupt normal operations.  
- Previously, the PodVolumeBackup custom resources that represented a restic backup within a cluster were not synchronized between clusters, making it unclear what restic volumes were available to restore into a new cluster. In version 1.1, these resources are synced into clusters, so they are more visible to you when you are trying to restore volumes.  
- Originally, Velero would not validate the host path in which volumes were mounted on a given node. If a node did not expose the filesystem correctly, you wouldn’t know about it until a backup failed. Now, Velero’s restic server will validate that the directory structure is correct on startup, providing earlier feedback when it’s not.  
- Velero’s restic support is intended to work on a broad range of volume types. With the general release of the [Container Storage Interface API](https://kubernetes.io/blog/2019/01/15/container-storage-interface-ga/), Velero can now use restic to back up CSI volumes.  

Along with our bug fixes, we’ve provided an easier way to move restic backups between storage providers. Different providers often have different StorageClasses, requiring user intervention to make restores successfully complete.

To make cross-provider moves simpler, we’ve introduced a StorageClass remapping plugin. It allows you to automatically translate one StorageClass on PersistentVolumeClaims and PersistentVolumes to another. You can read more about it in our [documentation](https://velero.io/docs/v1.1.0/restore-reference/#changing-pv-pvc-storage-classes).

## Quality-of-Life Improvements

We’ve also made several other enhancements to Velero that should benefit all users.

Users sometimes ask about recommendations for Velero’s resource allocation within their cluster. To help with this concern, we’ve added default resource requirements to the Velero Deployment and restic init containers, along with configurable requests and limits for the restic DaemonSet. All these values can be adjusted if your environment requires it.

We’ve also taken some time to improve Velero for the future by updating the Deployment and DaemonSet to use the apps/v1 API group, which will be the [default in Kubernetes 1.16](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.16.md#action-required-3). This change means that `velero install` and the `velero plugin` commands will require Kubernetes 1.9 or later to work. Existing Velero installs will continue to work without needing changes, however.

In order to help you better understand what resources have been backed up, we’ve added a list of resources in the `velero backup describe --details` command. This change makes it easier to inspect a backup without having to download and extract it.

In the same vein, we’ve added the ability to put custom tags on cloud-provider snapshots. This approach should provide a better way to keep track of the resources being created in your cloud account. To add a label to a snapshot at backup time, use the `--labels` argument in the `velero backup create` command.

Our final change for increasing visibility into your Velero installation is the `velero plugin get` command. This command will report all the plugins within the Velero deployment..

Velero has previously used a restore-only flag on the server to control whether a cluster could write backups to object storage. With Velero 1.1, we’ve now moved the restore-only behavior into read-only BackupStorageLocations. This move means that the Velero server can use a BackupStorageLocation as a source to restore from, but not for backups, while still retaining the ability to back up to other configured locations. In the future, the `--restore-only` flag will be removed in favor of configuring read-only BackupStorageLocations.

## Community Contributions

We appreciate all community contributions, whether they be pull requests, bug reports, feature requests, or just questions. With this release, we wanted to draw attention to a few contributions in particular:

For users of node-based IAM authentication systems such as kube2iam, `velero install` now supports the `--pod-annotations` argument for applying necessary annotations at install time. This support should make `velero install` more flexible for scenarios that do not use Secrets for access to their cloud buckets and volumes. You can read more about how to use this new argument in our [AWS documentation](https://velero.io/docs/v1.1.0/aws-config/#alternative-setup-permissions-using-kube2iam). Huge thanks to [Traci Kamp](https://github.com/tlkamp) for this contribution.

Structured logging is important for any application, and Velero is no different. Starting with version 1.1, the Velero server can now output its logs in a JSON format, allowing easier parsing and ingestion. Thank you to [Donovan Carthew](https://github.com/carthewd) for this feature.

AWS supports multiple profiles for accessing object storage, but in the past Velero only used the default. With v.1.1, you can set the `profile` key on yourBackupStorageLocation to specify an alternate profile. If no profile is set, the default one is used, making this change backward compatible. Thanks [Pranav Gaikwad](https://github.com/pranavgaikwad) for this change.

Finally, thanks to testing by [Dylan Murray](https://github.com/dymurray) and [Scott Seago](https://github.com/sseago), an issue with running Velero in non-default namespaces was found in our beta version for this release. If you’re running Velero in a namespace other than `velero`, please follow the [upgrade instructions](https://velero.io/docs/v1.1.0/upgrade-to-1.1/).

## Help Us Build the Future

For Velero 1.2, the current plan is to begin implementing CSI snapshot support at a beta level. If accepted, this approach would align Velero with the larger community, and in the future, it would allow Velero to snapshot far more volume providers. We have posted a [design document](https://github.com/velero-io/velero/pull/1661) for community review, so please be sure to take a look if this interests you.

We are also working on volume cloning, so that a persistent volume could be snapshotted and then duplicated for use within another namespace in the cluster.

The team has also been discussing different approaches to concurrent backup jobs. This is a longer term goal, that will not be included in 1.2. Comments on the [design document](https://github.com/velero-io/velero/pull/1653) would be really helpful.

## Take the Survey

Finally, we’re running [a survey](https://velero.io/survey) for our users. Let us know how you use Velero and what you’d like the community to address in the future. We’ll be using this feedback to guide our roadmap planning. Anonymized results will be shared back with the community shortly after the survey closes.

## Join the Movement – Contribute!

Velero is better because of our contributors and maintainers. It is because of them that we can bring great software to the community. Please join us during our [online community meetings every first Tuesday](https://github.com/velero-io/velero-community) and catch up with past meetings on YouTube on the [Velero Community Meetings playlist](https://www.youtube.com/watch?v=nc48ocI-6go&list=PL7bmigfV0EqQRysvqvqOtRNk4L5S7uqwM).

You can always find the latest project information at [velero.io](https://velero.io). Look for issues on GitHub marked [“Good first issue”](https://github.com/velero-io/velero/issues?q=is:open+is:issue+label:%22Good+first+issue%22) or [“Help wanted”](https://github.com/velero-io/velero/issues?utf8=✓&q=is:open+is:issue+label:%22Help+wanted%22+) if you want to roll up your sleeves and write some code with us.

You can find us on [Kubernetes Slack in the #velero channel](https://kubernetes.slack.com/messages/C6VCGP4MT), and follow us on Twitter at [@projectvelero](https://twitter.com/projectvelero).
