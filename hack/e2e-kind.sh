#!/usr/bin/env bash
# Driver for `make test-e2e-kind`. Builds the wrapper image (see hack/e2e-kind/)
# and runs it --privileged --rm: the nested dockerd, the kind cluster, MinIO, the
# velero build, and the e2e test run all happen inside that one container. The
# kind cluster, its kubeconfig, and MinIO never exist on the host; the host
# engine only ever sees the wrapper image and, while the run is active, the
# wrapper container itself. Nothing is written to the host filesystem outside
# this repo checkout (which a native `make test-e2e` run would also write build
# output into).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER_TOOL="${CONTAINER_TOOL:-docker}"

for tool in "${CONTAINER_TOOL}" git; do
	command -v "${tool}" >/dev/null 2>&1 || {
		echo "error: ${tool} is required on PATH to run test-e2e-kind" >&2
		exit 1
	}
done

case "$(uname -m)" in
	x86_64) TARGETARCH=amd64 ;;
	aarch64 | arm64) TARGETARCH=arm64 ;;
	*)
		echo "error: unsupported host architecture $(uname -m)" >&2
		exit 1
		;;
esac

WRAPPER_IMAGE="velero-e2e-kind:local"

# If this checkout is a git worktree, its .git is a pointer file to the real
# repo's git dir elsewhere on the host (e.g. /path/to/main-clone/.git/worktrees/x)
# - bind-mount that too, or every git invocation inside the container fails to
# resolve it. For a plain (non-worktree) clone this just re-mounts a path already
# under REPO_ROOT, which is a harmless no-op.
GIT_COMMON_DIR="$(cd "${REPO_ROOT}" && git rev-parse --path-format=absolute --git-common-dir)"

EXTRA_MOUNTS=()
if [[ "${GIT_COMMON_DIR}" != "${REPO_ROOT}"/* ]]; then
	EXTRA_MOUNTS+=(-v "${GIT_COMMON_DIR}:${GIT_COMMON_DIR}")
fi

# buildx-backed docker needs --load to land the image in the local store; other
# tools (podman) load locally by default and may not accept the flag.
BUILD_FLAGS=()
if "${CONTAINER_TOOL}" build --help 2>&1 | grep -q -- '--load'; then
	BUILD_FLAGS+=(--load)
fi

echo "==> building wrapper image (${WRAPPER_IMAGE})"
"${CONTAINER_TOOL}" build \
	"${BUILD_FLAGS[@]}" \
	--build-arg "TARGETARCH=${TARGETARCH}" \
	-t "${WRAPPER_IMAGE}" \
	"${REPO_ROOT}/hack/e2e-kind"

# Run by immutable image ID, not tag, so a concurrent invocation re-tagging
# velero-e2e-kind:local can't swap the image out from under this run.
WRAPPER_IMAGE_ID="$("${CONTAINER_TOOL}" image inspect --format '{{.Id}}' "${WRAPPER_IMAGE}")"

echo "==> running e2e tests in a self-contained container (kind + MinIO + build, all inside)"
exec "${CONTAINER_TOOL}" run --rm --privileged \
	-v "${REPO_ROOT}:${REPO_ROOT}" \
	"${EXTRA_MOUNTS[@]}" \
	-w "${REPO_ROOT}" \
	-e "BSL_BUCKET=${BSL_BUCKET:-velero}" \
	-e "PLUGINS=${PLUGINS:-velero/velero-plugin-for-aws:main}" \
	-e "GINKGO_LABELS=${GINKGO_LABELS:-}" \
	-e "HOST_UID=$(id -u)" \
	-e "HOST_GID=$(id -g)" \
	"${WRAPPER_IMAGE_ID}" "$@"
