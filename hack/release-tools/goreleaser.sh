#!/bin/bash

# Copyright 2018 the Velero contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

if [[ -z "${GITHUB_TOKEN}" ]]; then
    echo "GITHUB_TOKEN must be set"
    exit 1
fi

# TODO derive this from the major+minor version
if [ -z "${RELEASE_NOTES_FILE}" ]; then
    echo "RELEASE_NOTES_FILE must be set"
    exit 1
fi

if [ -z "${REGISTRY}" ]; then
    echo "REGISTRY must be set"
    exit 1
fi

GIT_DIRTY=$(git status --porcelain 2> /dev/null)
if [[ -z "${GIT_DIRTY}" ]]; then
    export GIT_TREE_STATE=clean
else
    export GIT_TREE_STATE=dirty
fi

# Verify .goreleaser.yml format first.
echo "Start to verify .goreleaser.yml format"
goreleaser check

# $PUBLISH must explicitly be set to 'TRUE' for goreleaser
# to publish the release to GitHub.
if [[ "${PUBLISH:-}" != "TRUE" ]]; then
    echo "Not set to publish"
    goreleaser release \
        --clean \
        --parallelism 2 \
        --release-notes="${RELEASE_NOTES_FILE}" \
        --snapshot # Generate an unversioned snapshot release, skipping all validations and without publishing any artifacts (implies --skip-publish, --skip-announce and --skip-validate)
else
    echo "Getting ready to publish"
    goreleaser release \
        --clean \
        --parallelism 2 \
        --release-notes="${RELEASE_NOTES_FILE}"
fi
