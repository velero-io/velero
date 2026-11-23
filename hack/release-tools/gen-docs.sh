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

# gen-docs.sh is used for the "make gen-docs" target. It generates a new 
# versioned docs directory under site/content/docs. It follows
# the following process:
#   1. Copies the contents of the most recently tagged docs directory into the new
#      directory, to establish a useful baseline to diff against.
#   2. Adds all copied content from step 1 to git's staging area via 'git add'.
#   3. Replaces the contents of the new docs directory with the contents of the
#      'main' docs directory, updating any version-specific links (e.g. to a
#      specific branch of the GitHub repository) to use the new version
#   4. Copies the previous version's ToC file and runs 'git add' to establish
#      a useful baseline to diff against.
#   5. Replaces the content of the new ToC file with the main ToC.
#   6. Update site/config.yaml and site/_data/toc-mapping.yml to include entries
#      for the new version.
#
# The unstaged changes in the working directory can now easily be diff'ed against the
# staged changes using 'git diff' to review all docs changes made since the previous 
# tagged version. Once the unstaged changes are ready, they can be added to the
# staging area using 'git add' and then committed.
#
# NEW_DOCS_VERSION defines the version that the docs will be tagged with 
# (i.e. what’s in the URL, what shows up in the version dropdown on the site). 
# This should be formatted as either v1.4 (for any GA release, including minor), or v1.5.0-beta.1/v1.5.0-rc.1 (for an alpha/beta/RC).

# To run gen-docs: "VELERO_VERSION=v1.4.0 NEW_DOCS_VERSION=v1.4 PREVIOUS_DOCS_VERSION= make gen-docs"
# Note: if PREVIOUS_DOCS_VERSION is not set, the script will copy from the 
# latest version.
#
# **NOTE**: there are additional manual steps required to finalize the process of generating
# a new versioned docs site. The full process is documented in site/README-HUGO.md

set -o errexit
set -o nounset
set -o pipefail

DOCS_DIRECTORY=site/content/docs
DATA_DOCS_DIRECTORY=site/data/docs
CONFIG_FILE=site/config.yaml
MAIN_BRANCH=main

# don't run if there's already a directory for the target docs version
if [[ -d $DOCS_DIRECTORY/$NEW_DOCS_VERSION ]]; then
    echo "ERROR: $DOCS_DIRECTORY/$NEW_DOCS_VERSION already exists"
    exit 1
fi

# get the alphabetically last item in $DOCS_DIRECTORY to use as PREVIOUS_DOCS_VERSION
# if not explicitly specified by the user
if [[ -z "${PREVIOUS_DOCS_VERSION:-}" ]]; then
    echo "PREVIOUS_DOCS_VERSION was not specified, getting the latest version"
    PREVIOUS_DOCS_VERSION=$(ls -1 $DOCS_DIRECTORY/ | tail -n 1)
fi

# make a copy of the previous versioned docs dir
echo "Creating copy of docs directory $DOCS_DIRECTORY/$PREVIOUS_DOCS_VERSION in $DOCS_DIRECTORY/$NEW_DOCS_VERSION"
cp -r $DOCS_DIRECTORY/${PREVIOUS_DOCS_VERSION}/ $DOCS_DIRECTORY/${NEW_DOCS_VERSION}/

# 'git add' the previous version's docs as-is so we get a useful diff when we copy the $MAIN_BRANCH docs in
echo "Running 'git add' for previous version's doc contents to use as a base for diff"
git add -f $DOCS_DIRECTORY/${NEW_DOCS_VERSION}

# now copy the contents of $DOCS_DIRECTORY/$MAIN_BRANCH into the same directory so we can get a nice
# git diff of what changed since previous version
echo "Copying $DOCS_DIRECTORY/$MAIN_BRANCH/ to $DOCS_DIRECTORY/${NEW_DOCS_VERSION}/"
rm -rf $DOCS_DIRECTORY/${NEW_DOCS_VERSION}/ && cp -r $DOCS_DIRECTORY/$MAIN_BRANCH/ $DOCS_DIRECTORY/${NEW_DOCS_VERSION}/

# make a copy of the previous versioned ToC
NEW_DOCS_TOC="$(echo ${NEW_DOCS_VERSION} | tr . -)-toc"
PREVIOUS_DOCS_TOC="$(echo ${PREVIOUS_DOCS_VERSION} | tr . -)-toc"

echo "Creating copy of $DATA_DOCS_DIRECTORY/$PREVIOUS_DOCS_TOC.yml at $DATA_DOCS_DIRECTORY/$NEW_DOCS_TOC.yml"
cp $DATA_DOCS_DIRECTORY/$PREVIOUS_DOCS_TOC.yml $DATA_DOCS_DIRECTORY/$NEW_DOCS_TOC.yml

# 'git add' the previous version's ToC content as-is so we get a useful diff when we copy the $MAIN_BRANCH ToC in
echo "Running 'git add' for previous version's ToC to use as a base for diff"
git add $DATA_DOCS_DIRECTORY/$NEW_DOCS_TOC.yml

# now copy the $MAIN_BRANCH ToC so we can get a nice git diff of what changed since previous version
echo "Copying $DATA_DOCS_DIRECTORY/$MAIN_BRANCH-toc.yml to $DATA_DOCS_DIRECTORY/$NEW_DOCS_TOC.yml"
rm $DATA_DOCS_DIRECTORY/$NEW_DOCS_TOC.yml && cp $DATA_DOCS_DIRECTORY/$MAIN_BRANCH-toc.yml $DATA_DOCS_DIRECTORY/$NEW_DOCS_TOC.yml

# replace known version-specific links -- the sed syntax is slightly different in OS X and Linux,
# so check which OS we're running on.
if [[ $(uname) == "Darwin" ]]; then
    echo "[OS X] updating version-specific links"
    find $DOCS_DIRECTORY/${NEW_DOCS_VERSION} -type f -name "*.md" | xargs sed -i '' "s|https://velero.io/docs/$MAIN_BRANCH|https://velero.io/docs/$VELERO_VERSION|g"
    find $DOCS_DIRECTORY/${NEW_DOCS_VERSION} -type f -name "*.md" | xargs sed -i '' "s|https://github.com/velero-io/velero/blob/$MAIN_BRANCH|https://github.com/velero-io/velero/blob/$VELERO_VERSION|g"
    find $DOCS_DIRECTORY/${NEW_DOCS_VERSION} -type f -name "_index.md" | xargs sed -i '' "s|version: $MAIN_BRANCH|version: $NEW_DOCS_VERSION|g"

    echo "[OS X] Updating latest version in $CONFIG_FILE"
    sed -i '' "s/latest: ${PREVIOUS_DOCS_VERSION}/latest: ${NEW_DOCS_VERSION}/" $CONFIG_FILE

    # newlines and lack of indentation are requirements for this sed syntax
    # which is doing an append
    echo "[OS X] Adding latest version to versions list in $CONFIG_FILE"
    sed -i '' "/- $MAIN_BRANCH/a\\
\ \ \ \ - ${NEW_DOCS_VERSION}
" $CONFIG_FILE

    echo "[OS X] Adding ToC mapping entry"
    sed -i '' "/$MAIN_BRANCH: $MAIN_BRANCH-toc/a\\
${NEW_DOCS_VERSION}: ${NEW_DOCS_TOC}
" $DATA_DOCS_DIRECTORY/toc-mapping.yml

else
    echo "[Linux] updating version-specific links"
    find $DOCS_DIRECTORY/${NEW_DOCS_VERSION} -type f -name "*.md" | xargs sed -i'' "s|https://velero.io/docs/$MAIN_BRANCH|https://velero.io/docs/$VELERO_VERSION|g"
    find $DOCS_DIRECTORY/${NEW_DOCS_VERSION} -type f -name "*.md" | xargs sed -i'' "s|https://github.com/velero-io/velero/blob/$MAIN_BRANCH|https://github.com/velero-io/velero/blob/$VELERO_VERSION|g"

    echo "[Linux] Updating latest version in $CONFIG_FILE"
    sed -i'' "s/latest: ${PREVIOUS_DOCS_VERSION}/latest: ${NEW_DOCS_VERSION}/" $CONFIG_FILE
    
    echo "[Linux] Adding latest version to versions list in $CONFIG_FILE"
    sed -i'' "/- $MAIN_BRANCH/a - ${NEW_DOCS_VERSION}" $CONFIG_FILE
    
    echo "[Linux] Adding ToC mapping entry"
    sed -i'' "/$MAIN_BRANCH: $MAIN_BRANCH-toc/a ${NEW_DOCS_VERSION}: ${NEW_DOCS_TOC}" $DATA_DOCS_DIRECTORY/toc-mapping.yml
fi

echo "Success! $DOCS_DIRECTORY/$NEW_DOCS_VERSION has been created."
echo ""
echo "The next steps are:"
echo "  1. Consult site/README-HUGO.md for further manual steps required to finalize the new versioned docs generation."
echo "  2. Run a 'git diff' to review all changes made to the docs since the previous version."
echo "  3. Make any manual changes/corrections necessary."
echo "  4. Run 'git add' to stage all unstaged changes, then 'git commit'."
