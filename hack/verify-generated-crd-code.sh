#!/bin/bash -e
#
# Copyright the Velero contributors.
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

HACK_DIR=$(dirname "${BASH_SOURCE}")

${HACK_DIR}/update-3generated-crd-code.sh

# ensure no changes to generated CRDs
if ! git diff --exit-code config/crd/v1/crds/crds.go config/crd/v2alpha1/crds/crds.go >/dev/null; then
  # revert changes to state before running CRD generation to stay consistent
  # with code-generator `--verify-only` option which discards generated changes
  git checkout config/crd

  echo "CRD verification - failed! Generated CRDs are out-of-date, please run 'make update' and 'git add' the generated file(s)."
  exit 1
fi
