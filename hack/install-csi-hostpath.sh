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

# Installs a CSI driver that can take snapshots into a kind cluster, so the
# e2e suite's CSI cases have something to snapshot. Installs, in order:
# the snapshot CRDs, the snapshot controller, the sidecar RBAC, and
# csi-driver-host-path with a StorageClass.
#
# Versions are pinned. Bump them deliberately, the same way the workflow pins
# the Kibishii and MinIO sources it clones.

set -euo pipefail

SNAPSHOTTER_VERSION="${SNAPSHOTTER_VERSION:-v8.6.0}"
HOSTPATH_VERSION="${HOSTPATH_VERSION:-v1.18.0}"
# Which deploy/<dir> of csi-driver-host-path to apply. It has to name a real
# directory: deploy/kubernetes-latest is a symlink, and raw.githubusercontent
# does not follow symlinks, so it 404s.
HOSTPATH_DEPLOY_DIR="${HOSTPATH_DEPLOY_DIR:-kubernetes-1.34}"
PROVISIONER_VERSION="${PROVISIONER_VERSION:-v6.3.0}"
ATTACHER_VERSION="${ATTACHER_VERSION:-v4.12.0}"
RESIZER_VERSION="${RESIZER_VERSION:-v2.2.1}"
HEALTH_MONITOR_VERSION="${HEALTH_MONITOR_VERSION:-v0.18.0}"

# The StorageClass the tests can be pointed at with --storage-class.
STORAGE_CLASS_NAME="${STORAGE_CLASS_NAME:-csi-hostpath-sc}"

# VolumeGroupSnapshot is behind a feature gate that neither project enables in
# its own manifests, and it has to be on in both the controller and the
# sidecar or group snapshots silently never become ready.
ENABLE_VOLUME_GROUP_SNAPSHOT="${ENABLE_VOLUME_GROUP_SNAPSHOT:-true}"

KUBECTL="${KUBECTL:-kubectl}"

snapshotter_raw="https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/${SNAPSHOTTER_VERSION}"
hostpath_raw="https://raw.githubusercontent.com/kubernetes-csi/csi-driver-host-path/${HOSTPATH_VERSION}"

echo "==> Installing snapshot CRDs (external-snapshotter ${SNAPSHOTTER_VERSION})"
crds=(
  snapshot.storage.k8s.io_volumesnapshotclasses
  snapshot.storage.k8s.io_volumesnapshotcontents
  snapshot.storage.k8s.io_volumesnapshots
)
if [ "${ENABLE_VOLUME_GROUP_SNAPSHOT}" = "true" ]; then
  # Group snapshots live under their own API group, not snapshot.storage.k8s.io.
  crds+=(
    groupsnapshot.storage.k8s.io_volumegroupsnapshotclasses
    groupsnapshot.storage.k8s.io_volumegroupsnapshotcontents
    groupsnapshot.storage.k8s.io_volumegroupsnapshots
  )
fi
# The file names are <group>_<plural>; the object names are <plural>.<group>.
established=()
for crd in "${crds[@]}"; do
  $KUBECTL apply -f "${snapshotter_raw}/client/config/crd/${crd}.yaml"
  established+=("crd/${crd#*_}.${crd%%_*}")
done
$KUBECTL wait --for=condition=established --timeout=60s "${established[@]}"

echo "==> Installing the snapshot controller"
$KUBECTL apply -f "${snapshotter_raw}/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml"
$KUBECTL apply -f "${snapshotter_raw}/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml"
if [ "${ENABLE_VOLUME_GROUP_SNAPSHOT}" = "true" ]; then
  $KUBECTL -n kube-system patch deployment snapshot-controller --type=json -p \
    '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--feature-gates=CSIVolumeGroupSnapshot=true"}]'
fi
$KUBECTL -n kube-system rollout status deployment/snapshot-controller --timeout=180s

echo "==> Installing the CSI sidecar RBAC"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-provisioner/${PROVISIONER_VERSION}/deploy/kubernetes/rbac.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-attacher/${ATTACHER_VERSION}/deploy/kubernetes/rbac.yaml"
$KUBECTL apply -f "${snapshotter_raw}/deploy/kubernetes/csi-snapshotter/rbac-csi-snapshotter.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-resizer/${RESIZER_VERSION}/deploy/kubernetes/rbac.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-health-monitor/${HEALTH_MONITOR_VERSION}/deploy/kubernetes/external-health-monitor-controller/rbac.yaml"

echo "==> Installing csi-driver-host-path ${HOSTPATH_VERSION} (${HOSTPATH_DEPLOY_DIR})"
$KUBECTL apply -f "${hostpath_raw}/deploy/${HOSTPATH_DEPLOY_DIR}/hostpath/csi-hostpath-driverinfo.yaml"
$KUBECTL apply -f "${hostpath_raw}/deploy/${HOSTPATH_DEPLOY_DIR}/hostpath/csi-hostpath-plugin.yaml"
if [ "${ENABLE_VOLUME_GROUP_SNAPSHOT}" = "true" ]; then
  # Look the container up by name: its index moves between releases. Tolerate a
  # miss here rather than letting the pipeline's exit status end the script: a
  # grep that matches nothing exits 1, pipefail propagates it, and the run would
  # stop with no output at all.
  container_names=$($KUBECTL get statefulset csi-hostpathplugin \
    -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\n"}{end}')
  snapshotter_index=$(printf '%s\n' "${container_names}" | grep -n '^csi-snapshotter$' | cut -d: -f1 || true)
  if [ -z "${snapshotter_index}" ]; then
    echo "ERROR: no csi-snapshotter container in statefulset/csi-hostpathplugin, so the" >&2
    echo "       CSIVolumeGroupSnapshot feature gate cannot be set. Its containers are:" >&2
    printf '         %s\n' ${container_names} >&2
    echo "       Check the container names in deploy/${HOSTPATH_DEPLOY_DIR}/hostpath/csi-hostpath-plugin.yaml" >&2
    echo "       at csi-driver-host-path ${HOSTPATH_VERSION}, in case the sidecar was renamed" >&2
    echo "       there, or set ENABLE_VOLUME_GROUP_SNAPSHOT=false to install without group" >&2
    echo "       snapshots." >&2
    exit 1
  fi
  $KUBECTL patch statefulset csi-hostpathplugin --type=json -p \
    "[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/$((snapshotter_index - 1))/args/-\",\"value\":\"--feature-gates=CSIVolumeGroupSnapshot=true\"}]"
fi
$KUBECTL rollout status statefulset/csi-hostpathplugin --timeout=300s

echo "==> Creating StorageClass ${STORAGE_CLASS_NAME}"
$KUBECTL apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${STORAGE_CLASS_NAME}
provisioner: hostpath.csi.k8s.io
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
EOF

# The csi-snapshotter sidecar watches every snapshot API it knows about. If one
# of them is not served, for instance because the group snapshot CRDs are
# missing while the feature gate is on, it waits for a cache that never syncs
# and no snapshot ever becomes ready, without logging an error. Fail here
# instead, where the cause is obvious.
echo "==> Waiting for the csi-snapshotter sidecar to sync its caches"
expected_caches=$([ "${ENABLE_VOLUME_GROUP_SNAPSHOT}" = "true" ] && echo 4 || echo 2)
for _ in $(seq 1 30); do
  synced=$($KUBECTL logs csi-hostpathplugin-0 -c csi-snapshotter 2>/dev/null | grep -c "Caches populated" || true)
  [ "${synced}" -ge "${expected_caches}" ] && break
  sleep 2
done
if [ "${synced:-0}" -lt "${expected_caches}" ]; then
  echo "ERROR: the csi-snapshotter sidecar populated ${synced:-0} of ${expected_caches} caches." >&2
  echo "       Snapshots would hang rather than fail. Check that SNAPSHOTTER_VERSION serves every API the sidecar watches." >&2
  $KUBECTL logs csi-hostpathplugin-0 -c csi-snapshotter --tail=40 >&2 || true
  exit 1
fi

echo "==> CSI snapshot support installed"
$KUBECTL get csidrivers
