#!/bin/bash

# Copyright 2020 the Velero contributors.
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


set +x

if [[ -z "$CI" ]]; then
   echo "This script is intended to be run only on Github Actions." >&2
   exit 1
fi

CHANGELOG_PATH='changelogs/unreleased'

# https://help.github.com/en/actions/reference/events-that-trigger-workflows#pull-request-event-pull_request
# GITHUB_REF is something like "refs/pull/:prNumber/merge"
pr_number=$(echo $GITHUB_REF | cut -d / -f 3)

change_log_file="${CHANGELOG_PATH}/${pr_number}-*"

if ls ${change_log_file} 1> /dev/null 2>&1; then
    echo "changelog for PR ${pr_number} exists"
    exit 0
fi

# Some kinds of pull requests do not require a changelog entry. Rather than
# relying on the (frozen) event payload, query the PR's current labels so the
# check reflects the latest state. This makes re-runs and labels added after
# the initial run behave correctly.
EXEMPT_LABELS=("kind/changelog-not-required" "Design" "Website" "Documentation")

has_exempt_label() {
    local current_labels
    current_labels=$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}" --jq '.labels[].name' 2>/dev/null || true)
    for label in "${EXEMPT_LABELS[@]}"; do
        if grep -Fxq "$label" <<< "$current_labels"; then
            echo "PR ${pr_number} has the '${label}' label; changelog not required."
            return 0
        fi
    done
    return 1
}

if command -v gh > /dev/null 2>&1; then
    # auto_label_prs.yml applies kind/changelog-not-required (and other exempt
    # labels) from a separate workflow triggered by the same PR-open event.
    # That workflow checks out the repo and diffs file globs, so it routinely
    # takes a few seconds longer than this job to land the label. Poll briefly
    # instead of failing on that race: this job's own "labeled" trigger would
    # otherwise just re-run and pass a few seconds later anyway, after already
    # reporting a confusing red X on the PR.
    attempts=6
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if has_exempt_label; then
            exit 0
        fi
        if ((attempt < attempts)); then
            sleep 5
        fi
    done
fi

echo "PR ${pr_number} is missing a changelog. Please refer https://velero.io/docs/main/code-standards/#adding-a-changelog and add a changelog."
exit 1

