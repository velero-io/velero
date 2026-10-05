---
title: "Release Instructions"
layout: docs
---

## Ahead of Time

### (GA Only) Release Blog Post PR

Prepare a PR containing the release blog post. It's usually easiest to make a copy of the most recent existing post, then replace the content as appropriate.

You also need to update `site/index.html` to have "Latest Release Information" contain a link to the new post.

### (Pre-Release and GA) Changelog and Docs PR

1.  In a branch, create the file `changelogs/CHANGELOG-<major>.<minor>.md` (if it doesn't already exist) by copying the most recent one.
1.  Run `make changelog` to generate a list of all unreleased changes. Copy/paste the output into `CHANGELOG-<major>.<minor>.md`, under the "All Changes" section for the release.
    - You *may* choose to tweak formatting on the list of changes by adding code blocks, etc.
1.  (GA Only) Remove all changelog files from `changelogs/unreleased`.
1.  Update the main `CHANGELOG.md` file to properly reference the release-specific changelog file:
    - (Pre-Release) List the release under "Development release"
    - (GA) List the release  under "Current release", remove any pre-releases from "Development release", and move the previous release into "Older releases".
1.  If there is an existing set of pre-release versioned docs for the version you are releasing (i.e. `site/docs/v1.2.0-beta.1` exists, and you're releasing `v1.2.0-beta.2` or `v1.2.0`):
    - Remove the directory containing the pre-release docs, i.e. `site/docs/<pre-release-version>`.
    - Delete the pre-release docs table of contents file, i.e. `site/_data/<pre-release-version>-toc.yml`.
    - Remove the pre-release docs table of contents mapping entry from `site/_data/toc-mapping.yml`.
    - Remove all references to the pre-release docs from `site/_config.yml`.
1.  Run `NEW_DOCS_VERSION=<VERSION> make gen-docs` (e.g. `NEW_DOCS_VERSION=v1.2.0 make gen-docs` or `NEW_DOCS_VERSION=v1.2.0-beta.1 make gen-docs`).
1.  Follow the additional instructions at `site/README-JEKYLL.md` to complete the docs generation process.
1.  Do a review of the diffs, and/or run `make serve-docs` and review the site.
1.  Submit a PR containing the changelog and the version-tagged docs.

### (Pre-Release and GA) GitHub Token

To run the `goreleaser` process to generate a GitHub release, you'll need to have a GitHub token. See https://goreleaser.com/environment/ for more details. 

You may regenerate the token for every release if you prefer.

#### If you don't already have a token
1.  Go to https://github.com/settings/tokens/new.
1.  Choose a name for your token.
1.  Check the "repo" scope.
1.  Click "Generate token".
1.  Save the token value somewhere - you'll need it during the release, in the `GITHUB_TOKEN` environment variable.

#### If you do already have a token, but need to regenerate it
1.  Go to https://github.com/settings/tokens.
1.  Click on the name of the relevant token.
1.  Click "Regenerate token".
1.  Save the token value somewhere - you'll need it during the release, in the `GITHUB_TOKEN` environment variable.

## During Release

This process is the same for both pre-release and GA, except for the fact that there will not be a blog post PR to merge for pre-release versions.

1.  Merge the changelog + docs PR, so that it's included in the release tag.
1.  Make sure your working directory is clean: `git status` should show `nothing to commit, working tree clean`. 
1.  Run `git fetch upstream main && git checkout upstream/main`.
1.  Run `git tag <VERSION>` (e.g. `git tag v1.2.0` or `git tag v1.2.0-beta.1`).
1.  Run `git push upstream <VERSION>` (e.g. `git push upstream v1.2.0` or `git push upstream v1.2.0-beta.1`). This will trigger the Travis CI job that builds/publishes the Docker images.
1.  Generate the GitHub release (it will be created in "Draft" status, which means it's not visible to the outside world until you click "Publish"):

    ```bash
    GITHUB_TOKEN=your-github-token \
    RELEASE_NOTES_FILE=changelogs/CHANGELOG-<major>.<minor>.md \
    PUBLISH=true \
    make release
    ```

1.  Navigate to the draft GitHub release, at https://github.com/velero-io/velero/releases.
1.  If this is a patch release (e.g. `v1.2.1`), note that the full `CHANGELOG-1.2.md` contents will be included in the body of the GitHub release. You need to delete the previous releases' content (e.g. `v1.2.0`'s changelog) so that only the latest patch release's changelog shows.
1.  Do a quick review for formatting. **Note:** the `goreleaser` process should detect if it's a pre-release version, and check that box in the GitHub release appropriately, but it's always worth double-checking.
1.  Publish the release.
1.  By now, the Docker images should have been published. Perform a smoke-test - for example:
    - Download the CLI from the GitHub release
    - Use it to install Velero into a cluster (or manually update an existing deployment to use the new images)
    - Verify that `velero version` shows the expected output
    - Run a backup/restore and ensure it works
1.  (GA Only) Merge the blog post PR.
1.  Announce the release:
    - Twitter (mention a few highlights, link to the blog post)
    - Slack channel
    - Google group (this doesn't get a lot of traffic, and recent releases may not have been posted here)
