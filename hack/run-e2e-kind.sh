#!/usr/bin/env bash

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

# Runs the e2e suite against a kind cluster and a MinIO container that this
# script creates and removes again, so running the tests locally does not need
# a cluster, an object store or a set of environment variables to be assembled
# by hand first.
#
# The cluster's kubeconfig is written to a temporary directory and never merged
# into the caller's: ~/.kube/config is untouched and the current context does
# not change. Everything created is removed on exit, including when the tests
# fail or the run is interrupted. FAIL_FAST=true leaves it all up when the run
# failed, as it does for the suite itself, and CLEANUP=false leaves it up
# whatever the outcome.
#
# Usage:
#   make -C test/ run-e2e-kind GINKGO_LABELS='Basic && ClusterResource'
#   FEATURES=EnableCSI make -C test/ run-e2e-kind GINKGO_LABELS='BackupVolumeInfo && CSISnapshot'
#   CLEANUP=false make -C test/ run-e2e-kind GINKGO_LABELS='Basic && NodePort'

set -euo pipefail

KIND_CLUSTER="${KIND_CLUSTER:-velero-e2e}"
KIND_IMAGE="${KIND_IMAGE:-}"
# Named after the cluster so a run cannot remove a MinIO container someone else
# is using. The teardown force-removes this name.
MINIO_CONTAINER="${MINIO_CONTAINER:-minio-${KIND_CLUSTER}}"
# MinIO's own images are no longer pullable anonymously, which is why CI builds
# one from the reviewed bitnami/containers commit instead of pulling. There is
# therefore no tag worth defaulting to that is guaranteed to resolve: the image
# has to be present already, or named explicitly. Checked before anything is
# created, since a pull failure three minutes into a run is a poor way to find out.
MINIO_IMAGE="${MINIO_IMAGE:-minio/minio:latest}"
# The image's own entrypoint is left to run by default, which is what CI relies
# on: its bitnami image starts the server itself and would fail if a command
# replaced that, since it runs as UID 1001 and cannot create a data directory at
# the filesystem root. Upstream minio/minio needs an explicit command instead,
# so set MINIO_ARGS="server /data" for that one.
MINIO_ARGS="${MINIO_ARGS:-}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-minio}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-minio123}"
BSL_BUCKET="${BSL_BUCKET:-bucket}"
ADDITIONAL_BSL_BUCKET="${ADDITIONAL_BSL_BUCKET:-additional-bucket}"

VELERO_IMAGE="${VELERO_IMAGE:-velero:e2e-local}"
if [ "${VELERO_IMAGE}" = "${VELERO_IMAGE%:*}" ]; then
  echo "ERROR: VELERO_IMAGE must include a tag, for example velero:e2e-local." >&2
  echo "       Without one the image and tag would both be '${VELERO_IMAGE}'." >&2
  exit 1
fi
# Skip rebuilding the image and CLI when re-running against an unchanged tree.
SKIP_BUILD="${SKIP_BUILD:-false}"

FEATURES="${FEATURES:-}"
GINKGO_LABELS="${GINKGO_LABELS:-}"

# --features takes a comma-separated list, so an exact comparison stops
# matching as soon as a second feature is enabled. Mirrors FeatureEnabled in
# test/types.go.
feature_enabled() {
  local want="$1" entry
  local IFS=,
  for entry in ${FEATURES}; do
    entry="$(echo "${entry}" | tr -d '[:space:]')"
    if [ "$(echo "${entry}" | tr '[:upper:]' '[:lower:]')" = "$(echo "${want}" | tr '[:upper:]' '[:lower:]')" ]; then
      return 0
    fi
  done
  return 1
}
FAIL_FAST="${FAIL_FAST:-false}"
# CLEANUP=false keeps the cluster and MinIO after the run whatever the outcome,
# for poking at a passing run. FAIL_FAST only keeps them when the run failed.
CLEANUP="${CLEANUP:-true}"

repo_root="$(git rev-parse --show-toplevel)"
work_dir="$(mktemp -d -t velero-e2e-XXXXXX)"
export KUBECONFIG="${work_dir}/kubeconfig"
creds_file="${work_dir}/credentials"

minio_started=false
# Ownership, not just existence. Teardown removes the cluster only if this run
# created it, for the same reason it refuses to remove a MinIO container it did
# not create.
cluster_created=false

# Printed whenever the test bed is deliberately left behind, so the caller is
# never left guessing what to remove.
keep_notice() {
  echo
  echo "$1"
  echo "  cluster:    ${KIND_CLUSTER}"
  echo "  kubeconfig: ${KUBECONFIG}"
  echo "  MinIO:      ${MINIO_CONTAINER}"
  echo "Remove them with:"
  echo "  kind delete cluster --name ${KIND_CLUSTER} && docker rm -f ${MINIO_CONTAINER} && rm -rf ${work_dir}"
}

cleanup() {
  local status=$?
  if [ "${CLEANUP}" = "false" ]; then
    keep_notice "CLEANUP is false, so the test bed is being kept."
    return
  fi
  if [ "${FAIL_FAST}" = "true" ] && [ "${status}" -ne 0 ]; then
    keep_notice "FAIL_FAST is set and the run failed, so the test bed is being kept."
    return
  fi
  echo "==> Removing the test bed"
  if [ "${cluster_created}" = "true" ]; then
    kind delete cluster --name "${KIND_CLUSTER}" > /dev/null 2>&1 || true
  fi
  if [ "${minio_started}" = "true" ]; then
    docker rm -f "${MINIO_CONTAINER}" > /dev/null 2>&1 || true
  fi
  rm -rf "${work_dir}"
}
trap cleanup EXIT

if ! docker image inspect "${MINIO_IMAGE}" > /dev/null 2>&1; then
  if ! docker pull -q "${MINIO_IMAGE}" > /dev/null 2>&1; then
    echo "ERROR: ${MINIO_IMAGE} is neither present locally nor pullable." >&2
    echo "       MinIO's images are not available anonymously, so build one the way" >&2
    echo "       CI does, from the bitnami/containers commit pinned in" >&2
    echo "       .github/workflows/e2e-test-kind.yaml as BITNAMI_CONTAINERS_COMMIT:" >&2
    echo >&2
    echo "         git clone --depth 1 https://github.com/bitnami/containers /tmp/bitnami-containers" >&2
    echo "         docker build -t minio:local /tmp/bitnami-containers/bitnami/minio/<ver>/debian-12" >&2
    echo "         MINIO_IMAGE=minio:local make -C test/ run-e2e-kind" >&2
    echo >&2
    echo "       Or set MINIO_IMAGE to any S3-compatible image you already have." >&2
    exit 1
  fi
fi

if kind get clusters 2>/dev/null | grep -qx "${KIND_CLUSTER}"; then
  echo "ERROR: a kind cluster named ${KIND_CLUSTER} already exists, and this script" >&2
  echo "       will not delete one it did not create. Remove it yourself, or set" >&2
  echo "       KIND_CLUSTER to a name that is free." >&2
  exit 1
fi

if docker inspect "${MINIO_CONTAINER}" > /dev/null 2>&1; then
  echo "ERROR: a container named ${MINIO_CONTAINER} already exists, and this script" >&2
  echo "       will not remove one it did not create. Remove it yourself, or set" >&2
  echo "       MINIO_CONTAINER or KIND_CLUSTER to a name that is free." >&2
  exit 1
fi

echo "==> Creating kind cluster ${KIND_CLUSTER}"
# --kubeconfig keeps this out of the caller's kubeconfig entirely.
# Set before the command rather than after, so a cluster left half created by a
# failure part way through is still torn down.
cluster_created=true
if [ -n "${KIND_IMAGE}" ]; then
  kind create cluster --name "${KIND_CLUSTER}" --image "${KIND_IMAGE}" --kubeconfig "${KUBECONFIG}" --wait 120s
else
  kind create cluster --name "${KIND_CLUSTER}" --kubeconfig "${KUBECONFIG}" --wait 120s
fi

echo "==> Starting MinIO"
# Published on an ephemeral host port rather than 9000, so a MinIO already
# running on the usual port does not stop the run. The port is published on all
# interfaces because the cluster reaches it over the kind gateway, so this is a
# throwaway store with throwaway credentials and nothing else should use it.
# shellcheck disable=SC2086 # MINIO_ARGS is a command line and must word-split.
docker run -d --name "${MINIO_CONTAINER}" -p 9000 \
  -e "MINIO_ROOT_USER=${MINIO_ROOT_USER}" \
  -e "MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}" \
  "${MINIO_IMAGE}" ${MINIO_ARGS} > /dev/null
minio_started=true
minio_port="$(docker port "${MINIO_CONTAINER}" 9000/tcp | head -1 | sed 's/.*://')"

# mc ships inside the MinIO image. minio/mc is no longer available on Docker Hub.
minio_ready=false
for _ in $(seq 1 30); do
  if docker exec "${MINIO_CONTAINER}" mc alias set local \
      "http://127.0.0.1:9000" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" > /dev/null 2>&1; then
    minio_ready=true
    break
  fi
  sleep 2
done
# Without this the loop falls through and the next command fails on its own,
# reporting a bucket error for what is really a MinIO that never came up.
if [ "${minio_ready}" != "true" ]; then
  echo "ERROR: MinIO did not become ready within 60s. Container logs:" >&2
  docker logs --tail 20 "${MINIO_CONTAINER}" >&2 || true
  if [ -z "${MINIO_ARGS}" ]; then
    echo >&2
    echo "       If the logs show a usage message, this image needs an explicit" >&2
    echo "       command. Upstream minio/minio does: MINIO_ARGS=\"server /data\"." >&2
  fi
  exit 1
fi
docker exec "${MINIO_CONTAINER}" mc mb --ignore-existing \
  "local/${BSL_BUCKET}" "local/${ADDITIONAL_BSL_BUCKET}" > /dev/null

# The cluster reaches MinIO over the kind network's gateway. Do not use
# `hostname -i`, which resolves to a different address under WSL2 and leaves the
# BackupStorageLocation unreachable from inside the cluster.
minio_host="$(docker network inspect kind \
  -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' | tr ' ' '\n' | grep -m1 '\.')"
bsl_config="region=minio,s3ForcePathStyle=\"true\",s3Url=http://${minio_host}:${minio_port}"
echo "==> MinIO reachable at ${minio_host}:${minio_port}"

cat > "${creds_file}" <<EOF
[default]
aws_access_key_id=${MINIO_ROOT_USER}
aws_secret_access_key=${MINIO_ROOT_PASSWORD}
EOF

# Strip only the final :tag, so a registry port survives: with %%:* the name
# localhost:5000/velero:e2e-local would reduce to "localhost".
velero_image_name="${VELERO_IMAGE%:*}"
velero_image_tag="${VELERO_IMAGE##*:}"
# The container target appends -linux-<arch>: with BUILD_OUTPUT_TYPE=docker the
# Makefile fixes ALL_OS to linux and takes only the architecture from go env, so
# the OS is linux even on a Darwin host, which still needs a Linux image to load
# into kind. Hardcoding the architecture instead would load a tag that does not
# exist on an arm64 workstation.
velero_image_arch="$(go env GOARCH 2>/dev/null)"
if [ -z "${velero_image_arch}" ]; then
  echo "ERROR: could not read the build architecture from 'go env'. The image tag the" >&2
  echo "       container target produces ends in -linux-<arch>, so this script needs" >&2
  echo "       go on PATH to know which tag to load." >&2
  exit 1
fi
velero_image_built="${VELERO_IMAGE}-linux-${velero_image_arch}"

if [ "${SKIP_BUILD}" != "true" ]; then
  echo "==> Building the Velero CLI and image"
  make -C "${repo_root}" local
  IMAGE="${velero_image_name}" VERSION="${velero_image_tag}" BUILD_OUTPUT_TYPE=docker \
    make -C "${repo_root}" container
fi
echo "==> Loading ${velero_image_built} into the cluster"
kind load docker-image "${velero_image_built}" --name "${KIND_CLUSTER}"

# The suite's own StorageClass comes from testdata/storage-class/<provider>.yaml
# unless told otherwise, and the kind one provisions with rancher.io/local-path.
# A CSI run needs a CSI-backed class or the driver installed below has nothing
# to snapshot, which is the same file the CSI job in CI passes.
storage_class_file=""
if feature_enabled EnableCSI; then
  if [ -x "${repo_root}/hack/install-csi-hostpath.sh" ]; then
    echo "==> Installing CSI snapshot support"
    "${repo_root}/hack/install-csi-hostpath.sh"
  else
    echo "ERROR: FEATURES=EnableCSI needs hack/install-csi-hostpath.sh to install a" >&2
    echo "       CSI driver that can snapshot; kind's default storage cannot." >&2
    exit 1
  fi
  storage_class_file="../testdata/storage-class/kind-csi.yaml"
fi

echo "==> Running the e2e suite"
CLOUD_PROVIDER=kind \
OBJECT_STORE_PROVIDER=aws \
FEATURES="${FEATURES}" \
BSL_CONFIG="${bsl_config}" \
BSL_BUCKET="${BSL_BUCKET}" \
CREDS_FILE="${creds_file}" \
ADDITIONAL_OBJECT_STORE_PROVIDER=aws \
ADDITIONAL_BSL_CONFIG="${bsl_config}" \
ADDITIONAL_BSL_BUCKET="${ADDITIONAL_BSL_BUCKET}" \
ADDITIONAL_CREDS_FILE="${creds_file}" \
GINKGO_LABELS="${GINKGO_LABELS}" \
STORAGE_CLASS_FILE="${storage_class_file}" \
FAIL_FAST="${FAIL_FAST}" \
make -C "${repo_root}/test" run-e2e VELERO_IMAGE="${velero_image_built}"
