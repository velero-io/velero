#!/usr/bin/env bash
# Runs entirely inside this one container: nested dockerd, the repo's own build
# targets, a kind cluster, MinIO, and test/Makefile's run-e2e target. The
# kubeconfig, the kind cluster, and MinIO live only in this container's own
# filesystem/engine and disappear when the container is removed. The repo is
# bind-mounted read-write at the same path it lives at on the host (see
# hack/e2e-kind.sh) purely so build caches/output behave exactly like a native
# `make local`/`make test-e2e` run would.
set -euo pipefail

CLUSTER_NAME="velero-e2e"
KUBECONFIG_PATH="/root/.kube/config"
CREDS_PATH="/root/minio-credentials"
BUCKET="${BSL_BUCKET:-velero}"
PLUGINS="${PLUGINS:-velero/velero-plugin-for-aws:main}"
GINKGO_LABELS="${GINKGO_LABELS:-}"

# On native-Linux hosts this container runs as root against the bind-mounted
# repo, which would leave root-owned build artifacts behind (the repo's own
# `make shell` avoids this with -u). Hand everything we may have written back to
# the host user on the way out. On macOS engines (Docker Desktop/podman machine)
# the mount is UID-mapped and this is a no-op that may not even be permitted,
# hence the blanket error suppression.
cleanup_ownership() {
	if [ -n "${HOST_UID:-}" ] && [ "${HOST_UID}" != "0" ]; then
		chown -R "${HOST_UID}:${HOST_GID:-${HOST_UID}}" \
			_output .go test/e2e/report.xml 2>/dev/null || true
	fi
}
trap cleanup_ownership EXIT

echo "==> starting inner dockerd"
# cgroup v2: delegate all available controllers to child cgroups before dockerd
# starts. Without this, dockerd's own cgroup has an empty cgroup.subtree_control
# (nothing delegated down), so the kind node's nested systemd fails outright
# ("Structure needs cleaning" on /init.scope) or, one layer deeper, kubelet's own
# startup script hits the same wall ("this script needs cgroup.procs to be empty").
# This is normally handled by docker:dind's own default entrypoint, which our
# custom ENTRYPOINT bypasses, so it's reproduced here (same shape as upstream's
# dind script). The procs move must happen before subtree_control is written
# ("no internal processes" rule); errors moving individual PIDs are ignored like
# upstream does (a process may exit mid-move), but a failed delegation write is
# fatal and reported.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
	mkdir -p /sys/fs/cgroup/init
	xargs -rn1 </sys/fs/cgroup/cgroup.procs >/sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
	sed -e 's/^/+/' -e 's/ / +/g' </sys/fs/cgroup/cgroup.controllers >/sys/fs/cgroup/cgroup.subtree_control || {
		echo "failed to delegate cgroup v2 controllers; nested kind will not boot" >&2
		exit 1
	}
fi

dockerd >/var/log/dockerd.log 2>&1 &
for _ in $(seq 1 30); do
	docker info >/dev/null 2>&1 && break
	sleep 1
done
docker info >/dev/null 2>&1 || {
	echo "inner dockerd did not come up; last log lines:" >&2
	tail -n 50 /var/log/dockerd.log >&2
	exit 1
}

# The repo is bind-mounted from the host, owned by the host user's UID; git
# refuses to operate on a repo it doesn't own unless told it's safe. Optional
# locks are disabled so read-only commands (git status in the Makefile) don't
# opportunistically rewrite the host repo's index as root.
git config --global --add safe.directory '*'
export GIT_OPTIONAL_LOCKS=0

# Create the cluster before the heavy build steps so the timing-sensitive
# systemd boot inside the kind node isn't competing with the Go compile and
# BuildKit for CPU/IO.
echo "==> creating kind cluster ${CLUSTER_NAME}"
kind create cluster --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}"
export KUBECONFIG="${KUBECONFIG_PATH}"

echo "==> building velero CLI (make local)"
make local CONTAINER_TOOL=docker

echo "==> building velero server image (make container)"
docker buildx inspect --bootstrap >/dev/null
make container CONTAINER_TOOL=docker BUILD_OUTPUT_TYPE=docker IMAGE=velero VERSION=e2e-kind-local

ARCH="$(go env GOARCH)"
VELERO_IMAGE="velero:e2e-kind-local-linux-${ARCH}"

echo "==> loading ${VELERO_IMAGE} into kind"
kind load docker-image "${VELERO_IMAGE}" --name "${CLUSTER_NAME}"

echo "==> starting MinIO"
docker run -d --name minio --network kind \
	-e MINIO_ACCESS_KEY=minio -e MINIO_SECRET_KEY=minio123 \
	minio/minio:latest server /data >/dev/null
minio_ready=false
for _ in $(seq 1 30); do
	if docker run --rm --network kind curlimages/curl:latest -sf -o /dev/null \
		http://minio:9000/minio/health/live; then
		minio_ready=true
		break
	fi
	sleep 1
done
if [ "${minio_ready}" != "true" ]; then
	echo "MinIO did not become healthy in time; container logs:" >&2
	docker logs minio 2>&1 | tail -n 50 >&2
	exit 1
fi

echo "==> creating bucket ${BUCKET}"
docker run --rm --network kind \
	--entrypoint /bin/sh minio/mc:latest -c "
		mc alias set local http://minio:9000 minio minio123 >/dev/null &&
		mc mb -p local/${BUCKET} >/dev/null
	"

cat >"${CREDS_PATH}" <<-EOF
	[default]
	aws_access_key_id = minio
	aws_secret_access_key = minio123
EOF

echo "==> running e2e tests (make -C test run-e2e)"
set +e
make -C test run-e2e \
	CREDS_FILE="${CREDS_PATH}" \
	BSL_BUCKET="${BUCKET}" \
	CLOUD_PROVIDER=kind \
	OBJECT_STORE_PROVIDER=aws \
	BSL_CONFIG="region=minio,s3ForcePathStyle=true,s3Url=http://minio:9000" \
	VELERO_IMAGE="${VELERO_IMAGE}" \
	PLUGINS="${PLUGINS}" \
	GINKGO_LABELS="${GINKGO_LABELS}" \
	"$@"
code=$?
set -e

echo "==> e2e tests exited with code ${code}"
exit "${code}"
