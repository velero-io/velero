#!/bin/bash

# Copyright 2016 The Kubernetes Authors.
# Modifications Copyright 2020 The Velero Contributors
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

export CGO_ENABLED=0

TARGETS=($(go list ./pkg/... ./internal/...| grep -vE "/pkg/builder|pkg/apis|pkg/test|pkg/generated|pkg/plugin/generated|mocks|internal/restartabletest"))
TARGETS+=(
  ./cmd/...
)

if [[ ${#@} -ne 0 ]]; then
  TARGETS=("$@")
fi

echo "Running all short tests in:" "${TARGETS[@]}"

if [[ -n "${GOFLAGS:-}" ]]; then
  echo "GOFLAGS: ${GOFLAGS}"
fi

# After bumping up "sigs.k8s.io/controller-runtime" to v0.10.2, get the error "panic: mkdir /.cache/kubebuilder-envtest: permission denied"
# when running this script with "make test" command. This is caused by that "make test" runs inside a container with user and group specified,
# but the user and group don't exist inside the container, when the code(https://github.com/kubernetes-sigs/controller-runtime/blob/v0.10.2/pkg/internal/testing/addr/manager.go#L44)
# tries to get the cache directory, it gets the directory "/" and then get the permission error when trying to create directory under "/".
# Specifying the cache directory by environment variable "XDG_CACHE_HOME" to workaround it
# Add -vet parameter to filter out `printf` rule to avoid the false positive report for `non-constant format string in call to ...`.
# https://pkg.go.dev/cmd/go#hdr-Test_packages:~:text=Only%20a%20high%2Dconfidence%20subset%20of%20the%20default%20go%20vet%20checks%20are%20used.%20That%20subset%20is%3A%20atomic%2C%20bool%2C%20buildtags%2C%20directive%2C%20errorsas%2C%20ifaceassert%2C%20nilfunc%2C%20printf%2C%20stringintconv%2C%20and%20tests.
XDG_CACHE_HOME=/tmp/ go test -vet="atomic,bool,buildtags,directive,errorsas,ifaceassert,nilfunc,stringintconv,tests" -installsuffix "static" -short -timeout 1200s -coverprofile=coverage.out "${TARGETS[@]}"
echo "Success!"
