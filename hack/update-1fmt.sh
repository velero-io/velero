#!/bin/bash
#
# Copyright 2017 the Velero contributors.
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

if [[ ${1:-} == '--verify' ]]; then
  # List file diffs that need formatting updates
  MODE='-d'
  ACTION='Verifying'
else
  # Write formatting updates to files
  MODE='-w'
  ACTION='Updating'
fi

if ! command -v goimports > /dev/null; then
  echo 'goimports is missing - please run "go get golang.org/x/tools/cmd/goimports"'
  exit 1
fi

files="$(find . -type f -name '*.go' -not -path './.go/*' -not -path './vendor/*' -not -path './site/*' -not -path './.git/*' -not -path '*/generated/*' -not -name 'zz_generated*' -not -path '*/mocks/*')"
echo "${ACTION} gofmt"
output=$(gofmt "${MODE}" -s ${files})
if [[ -n "${output}" ]]; then
  VERIFY_FMT_FAILED=1
  echo "${output}"
fi
if [[ -n "${VERIFY_FMT_FAILED:-}" ]]; then
  echo "${ACTION} gofmt - failed! Please run 'make update'."
else
  echo "${ACTION} gofmt - done!"
fi

echo "${ACTION} goimports"
output=$(goimports "${MODE}" -local github.com/vmware-tanzu/velero ${files})
if [[ -n "${output}" ]]; then
  VERIFY_IMPORTS_FAILED=1
  echo "${output}"
fi
if [[ -n "${VERIFY_IMPORTS_FAILED:-}" ]]; then
  echo "${ACTION} goimports - failed! Please run 'make update'."
else
  echo "${ACTION} goimports - done!"
fi

if [[ -n "${VERIFY_FMT_FAILED:-}" || -n "${VERIFY_IMPORTS_FAILED:-}" ]]; then
  exit 1
fi
