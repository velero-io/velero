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

TARGETS=($(go list ./pkg/... | grep -v "github.com/vmware-tanzu/velero/pkg/builder"))
TARGETS+=(
  ./cmd/...
  ./internal/...
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
XDG_CACHE_HOME=/tmp/ go test -installsuffix "static" -short -timeout 1200s "${TARGETS[@]}"
echo "Success!"
