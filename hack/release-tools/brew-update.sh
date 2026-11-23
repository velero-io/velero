#!/usr/bin/env bash

# This script assumes that 2 environment variables are defined outside of it:
#   VELERO_VERSION - a full version version string, starting with v. example: v1.4.2
#   HOMEBREW_GITHUB_API_TOKEN - the GitHub API token that the brew command will use to create a PR on the user's behalf.


# Check if brew is found on the user's $PATH; exit if not.
if [ -z $(which brew) ];
then
    echo "Homebrew must first be installed to use this script!"
    exit 1
fi

# GitHub URL which contains the source code archive for the tagged release
URL=https://github.com/velero-io/velero/archive/$VELERO_VERSION.tar.gz

# Update brew so we're sure we have the latest Velero formula
brew update

# Invoke brew's helper function, which will run all their tests and end up opening a browser with the resulting PR.
brew bump-formula-pr velero --url=$URL
