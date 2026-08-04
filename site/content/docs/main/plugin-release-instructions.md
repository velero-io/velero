---
title: Releasing Velero plugins
layout: docs
toc: "true"
---

Velero plugins maintained by the core maintainers do not have any shipped binaries, only container images, so there is no need to invoke a GoReleaser script.
Container images are built via a CI job on git push.

Plugins the Velero core team is responsible include all those listed in [the Velero-supported providers list](supported-providers.md) _except_ the vSphere plugin.


## Steps
### Open a PR to prepare the repo
1. Update the README.md file to update the compatibility matrix and `velero install` instructions with the expected version number and open a PR.
1. Determining the version number is based on semantic versioning and whether the plugin uses any newly introduced, changed, or removed methods or variables from Velero.
2. Roll all unreleased changelogs into a new `CHANGELOG-v<version>.md` file and delete the content of the `unreleased` folder. Edit the new changelog file as needed.
### Tag
1. Once the PR is merged, checkout the upstream `main` branch. Your local upstream might be named `upstream` or `origin`, so use this command: `git checkout <upstream-name>/main`.
1. Tag the git version - `git tag v<version>`.
1. Push the git tag - `git push --tags <upstream-name>` to trigger the image build.
2. Wait for the container images to build. You may check the progress of the GH action that triggers the image build at `https://github.com/velero-io/<plugin-name>/actions`
3. Verify that an image with the new tag is available at `https://hub.docker.com/repository/docker/velero/<plugin-name>/`.
4. Run the Velero [e2e tests][2] using the new image. Until it is made configurable, you will have to edit the [plugin version][1] in the test.
### Release
1. If all e2e tests pass, go to the GitHub release page of the plugin (`https://github.com/velero-io/<plugin-name>/releases`) and manually create a release for the new tag. 
1. Copy and paste the content of the new changelog file into the release description field.

[1]: https://github.com/velero-io/velero/blob/c8dfd648bbe85db0184ea53296de4220895497e6/test/e2e/velero_utils.go#L27
[2]: https://github.com/velero-io/velero/tree/main/test/e2e
