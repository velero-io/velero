#!/usr/bin/env bash
# Copyright 2026 the Velero contributors.
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

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOCKERFILE="${ROOT_DIR}/hack/build-image/Dockerfile"

verify_block() {
    local tool=$1
    local start=$2
    local end=$3
    local hash_variable=$4
    local install_pattern=$5
    shift 5
    local expected_arches=("$@")
    local block

    block=$(awk -v start="${start}" -v end="${end}" '
        $0 ~ start { printing = 1 }
        printing { print }
        printing && $0 ~ end { exit }
    ' "${DOCKERFILE}")

    if [[ -z "${block}" ]]; then
        echo "Unable to find ${tool} install block" >&2
        return 1
    fi

    local actual_arches
    actual_arches=$(printf '%s\n' "${block}" |
        sed -nE "s/^[[:space:]]*([[:alnum:]_|]+)\).*${hash_variable}=\"([[:xdigit:]]+)\".*/\1 \2/p")

    local expected_arch
    for expected_arch in "${expected_arches[@]}"; do
        if ! printf '%s\n' "${actual_arches}" | awk -v arch="${expected_arch}" '
            $1 == arch && length($2) == 64 && $2 ~ /^[0-9a-f]+$/ { found = 1 }
            END { exit !found }
        '; then
            echo "${tool} is missing a lowercase 64-hex SHA-256 for ${expected_arch}" >&2
            return 1
        fi
    done

    local actual_count
    actual_count=$(printf '%s\n' "${actual_arches}" | sed '/^$/d' | wc -l | tr -d ' ')
    if [[ "${actual_count}" -ne "${#expected_arches[@]}" ]]; then
        echo "${tool} architecture mapping changed; update this verification gate" >&2
        printf '%s\n' "${actual_arches}" >&2
        return 1
    fi

    if ! printf '%s\n' "${block}" | grep -Eq '^        \*\).*Unsupported .+ architecture:.+exit 1'; then
        echo "${tool} does not fail closed for unknown architectures" >&2
        return 1
    fi

    local download_line checksum_line install_line
    download_line=$(printf '%s\n' "${block}" | grep -n 'wget --quiet' | head -1 | cut -d: -f1)
    checksum_line=$(printf '%s\n' "${block}" | grep -n "echo \"\$${hash_variable}  \$FILE\" | sha256sum -c -" | head -1 | cut -d: -f1)
    install_line=$(printf '%s\n' "${block}" | grep -nE "${install_pattern}" | head -1 | cut -d: -f1)

    if [[ -z "${download_line}" || -z "${checksum_line}" || -z "${install_line}" ||
          "${download_line}" -ge "${checksum_line}" || "${checksum_line}" -ge "${install_line}" ]]; then
        echo "${tool} must download, verify, then install/extract in that order" >&2
        return 1
    fi

    if ! printf '%s\n' "${block}" | grep -q '^RUN set -eux;'; then
        echo "${tool} install block must use strict shell error handling" >&2
        return 1
    fi
}

verify_block \
    kubebuilder \
    '^RUN set -eux;.*$' \
    '^# get controller-tools$' \
    KUBEBUILDER_SHA256 \
    'mv "\$FILE"' \
    amd64 arm64 ppc64le

verify_block \
    protoc \
    '^# cpu names:' \
    '^RUN go install google.golang.org/protobuf' \
    PROTOC_SHA256 \
    'unzip "\$FILE"' \
    amd64 386 arm64 'ppc64|ppc64le' s390x

verify_block \
    goreleaser \
    '^# goreleaser name template' \
    '^# get golangci-lint$' \
    GORELEASER_SHA256 \
    'tar xvf "\$FILE"' \
    amd64 386 arm64 arm 'ppc64|ppc64le'

echo "Verified pinned build-tool checksums and fail-closed install ordering"
