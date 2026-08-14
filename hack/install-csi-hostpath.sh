#!/bin/bash

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

set -euo pipefail

SNAPSHOTTER_VERSION="${SNAPSHOTTER_VERSION:-v8.6.0}"
HOSTPATH_VERSION="${HOSTPATH_VERSION:-v1.18.0}"
HOSTPATH_K8S_DIR="${HOSTPATH_K8S_DIR:-kubernetes-1.34}"

PROVISIONER_VERSION="${PROVISIONER_VERSION:-v6.3.0}"
ATTACHER_VERSION="${ATTACHER_VERSION:-v4.12.0}"
SNAPSHOTTER_SIDECAR_VERSION="${SNAPSHOTTER_SIDECAR_VERSION:-v8.6.0}"
RESIZER_VERSION="${RESIZER_VERSION:-v2.2.1}"
HEALTH_MONITOR_VERSION="${HEALTH_MONITOR_VERSION:-v0.18.0}"

ENABLE_VGS="${ENABLE_VGS:-true}"
KUBECTL="${KUBECTL:-kubectl}"

ES_RAW="https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/${SNAPSHOTTER_VERSION}"
HP_RAW="https://raw.githubusercontent.com/kubernetes-csi/csi-driver-host-path/${HOSTPATH_VERSION}"

echo "==> [1/4] Installing VolumeSnapshot and VolumeGroupSnapshot CRDs (${SNAPSHOTTER_VERSION})"
for crd in \
  snapshot.storage.k8s.io_volumesnapshotclasses \
  snapshot.storage.k8s.io_volumesnapshotcontents \
  snapshot.storage.k8s.io_volumesnapshots \
  groupsnapshot.storage.k8s.io_volumegroupsnapshotclasses \
  groupsnapshot.storage.k8s.io_volumegroupsnapshotcontents \
  groupsnapshot.storage.k8s.io_volumegroupsnapshots ; do
  $KUBECTL apply -f "${ES_RAW}/client/config/crd/${crd}.yaml"
done
$KUBECTL wait --for=condition=established --timeout=60s \
  crd/volumesnapshots.snapshot.storage.k8s.io \
  crd/volumegroupsnapshots.groupsnapshot.storage.k8s.io

echo "==> [2/4] Installing snapshot-controller"
$KUBECTL apply -f "${ES_RAW}/deploy/kubernetes/snapshot-controller/rbac-snapshot-controller.yaml"
$KUBECTL apply -f "${ES_RAW}/deploy/kubernetes/snapshot-controller/setup-snapshot-controller.yaml"
$KUBECTL -n kube-system set image deployment/snapshot-controller \
  snapshot-controller="registry.k8s.io/sig-storage/snapshot-controller:${SNAPSHOTTER_VERSION}"
if [ "$ENABLE_VGS" = "true" ]; then
  $KUBECTL -n kube-system patch deployment snapshot-controller --type=strategic -p '
spec:
  template:
    spec:
      containers:
        - name: snapshot-controller
          args:
            - "--v=5"
            - "--leader-election=true"
            - "--feature-gates=CSIVolumeGroupSnapshot=true"
'
fi
$KUBECTL -n kube-system rollout status deployment/snapshot-controller --timeout=180s

echo "==> [3/4] Installing CSI sidecar ClusterRoles"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-provisioner/${PROVISIONER_VERSION}/deploy/kubernetes/rbac.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-attacher/${ATTACHER_VERSION}/deploy/kubernetes/rbac.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/${SNAPSHOTTER_SIDECAR_VERSION}/deploy/kubernetes/csi-snapshotter/rbac-csi-snapshotter.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-resizer/${RESIZER_VERSION}/deploy/kubernetes/rbac.yaml"
$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes-csi/external-health-monitor/${HEALTH_MONITOR_VERSION}/deploy/kubernetes/external-health-monitor-controller/rbac.yaml"

echo "==> [4/4] Installing csi-driver-host-path (${HOSTPATH_VERSION}, ${HOSTPATH_K8S_DIR})"
$KUBECTL apply -f "${HP_RAW}/deploy/${HOSTPATH_K8S_DIR}/hostpath/csi-hostpath-driverinfo.yaml"
$KUBECTL apply -f "${HP_RAW}/deploy/${HOSTPATH_K8S_DIR}/hostpath/csi-hostpath-plugin.yaml"
if [ "$ENABLE_VGS" = "true" ]; then
  $KUBECTL patch statefulset csi-hostpathplugin --type=strategic -p '
spec:
  template:
    spec:
      containers:
        - name: csi-snapshotter
          args:
            - "-v=5"
            - "--csi-address=/csi/csi.sock"
            - "--feature-gates=CSIVolumeGroupSnapshot=true"
'
fi
$KUBECTL rollout restart statefulset/csi-hostpathplugin
$KUBECTL rollout status statefulset/csi-hostpathplugin --timeout=300s

echo "==> Verifying the csi-snapshotter sidecar synced its caches"
synced=0
for _ in $(seq 1 30); do
  synced=$($KUBECTL logs csi-hostpathplugin-0 -c csi-snapshotter 2>/dev/null \
    | grep -c "Caches populated" || true)
  [ "${synced}" -ge 4 ] && break
  sleep 2
done
if [ "${synced}" -lt 4 ]; then
  echo "ERROR: csi-snapshotter populated ${synced} of 4 caches."
  echo "       A CRD version that does not serve every API the sidecar watches will hang it"
  echo "       silently, and no VolumeSnapshot will ever become ready. Check SNAPSHOTTER_VERSION."
  $KUBECTL logs csi-hostpathplugin-0 -c csi-snapshotter --tail=40 || true
  exit 1
fi

echo "==> CSI snapshot stack installed"
$KUBECTL get csidrivers
