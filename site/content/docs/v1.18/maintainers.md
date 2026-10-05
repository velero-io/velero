---
title: "Instructions for Maintainers"
layout: docs
toc: "true"
---

There are some guidelines maintainers need to follow. We list them here for quick reference, especially for new maintainers. These guidelines apply to all projects in the Velero org, including the main project, the Velero Helm chart, and all other [related repositories](https://github.com/velero-io/velero/blob/v1.18.0/GOVERNANCE.md#code-repositories).

Please be sure to also go through the guidance under the entire [Contribute](start-contributing/) section.

## Reviewing PRs
- PRs require 2 approvals before it is mergeable.
- The second reviewer usually merges the PR (if you notice a PR open for a while and with 2 approvals, go ahead and merge it!)
- As you review a PR that is not yet ready to merge, please check if the "request review" needs to be refreshed for any reviewer (this is better than @mention at them)
- Refrain from @mention other maintainers to review the PR unless it is an immediate need. All maintainers already get notified through the automated add to the "request review". If it is an urgent need, please add a helpful message as to why it is so people can properly prioritize work.
- There is no need to manually request reviewers: after the PR is created, all maintainers will be automatically added to the list (note: feel free to remove people if they are on PTO, etc).
- Be familiar with the [lazy consensus](https://github.com/velero-io/velero/blob/v1.18.0/GOVERNANCE.md#lazy-consensus) policy for the project.

Some tips for doing reviews:
- There are some [code standards and general guidelines](https://velero.io/docs/v1.18.0/code-standards) we aim for
- We have [guidelines for writing and reviewing documentation](https://velero.io/docs/v1.18.0/style-guide/)
- When reviewing a design document, ensure it follows [our format and guidelines]( https://github.com/velero-io/velero/blob/v1.18.0/design/_template.md). Also, when reviewing a PR that implements a previously accepted design, ensure the associated design doc is moved to the [design/implemented](https://github.com/velero-io/velero/tree/main/design/implemented) folder.


## Creating a release
Maintainers are expected to create releases for the project. We have parts of the process automated, and full [instructions](release-instructions).
We are working towards automating more the Velero testing, but there is still a need for manual testing as part of the release process.
The manual test cases for release testing are documented [here](./manual-testing).

## Community support
Maintainers are expected to participate in the community support rotation. We have guidelines for how we handle the [support](support-process).

## Community engagement
Maintainers for the Velero project are highly involved with the open source community. All the online community meetings for the project are listed in our [community](community) page.

## How do I become a maintainer?
The Velero project welcomes contributors of all kinds. We are also always on the look out for a high level of engagement from contributors and opportunities to bring in new maintainers. If this is of interest, take a look at how [adding a maintainer](https://github.com/velero-io/velero/blob/v1.18.0/GOVERNANCE.md#maintainers) is decided.
