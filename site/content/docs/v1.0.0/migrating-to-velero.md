---
title: "Migrating from Heptio Ark to Velero"
layout: docs
---

As of v0.11.0, Heptio Ark has become Velero. This means the following changes have been made:

* The `ark` CLI client is now `velero`.
* The default Kubernetes namespace and ServiceAccount are now named `velero` (formerly `heptio-ark`).
* The container image name is now `gcr.io/heptio-images/velero` (formerly `gcr.io/heptio-images/ark`).
* CRDs are now under the new `velero.io` API group name (formerly `ark.heptio.com`).


The following instructions will help you migrate your existing Ark installation to Velero.

# Prerequisites

*  Ark v0.10.x installed. See the v0.10.x [upgrade instructions][1] to upgrade from older versions.
* `kubectl` installed.
* `cluster-admin` permissions.

# Migration process

At a high level, the migration process involves the following steps:

* Scale down the `ark` deployment, so it will not process schedules, backups, or restores during the migration period.
* Create a new namespace (named `velero` by default).
* Apply the new CRDs.
* Migrate existing Ark CRD objects, labels, and annotations to the new Velero equivalents.
* Recreate the existing cloud credentials secret(s) in the velero namespace.
* Apply the updated Kubernetes deployment and daemonset (for restic support) to use the new container images and namespace.
* Remove the existing Ark namespace (which includes the deployment), CRDs, and ClusterRoleBinding.

These steps are provided in a script here:

```bash
kubectl scale --namespace heptio-ark deployment/ark --replicas 0
 OS=$(uname | tr '[:upper:]' '[:lower:]') # Determine if the OS is Linux or macOS
 ARCH="amd64"

# Download the velero client/example tarball to and unpack
curl -L https://github.com/velero-io/velero/releases/download/v0.11.0/velero-v0.11.0-${OS}-${ARCH}.tar.gz --output velero-v0.11.0-${OS}-${ARCH}.tar.gz
tar xvf velero-v0.11.0-${OS}-${ARCH}.tar.gz

# Create the prerequisite CRDs and namespace
kubectl apply -f config/common/00-prereqs.yaml

# Download and unpack the crd-migrator tool
curl -L https://github.com/vmware/crd-migration-tool/releases/download/v1.0.0/crd-migration-tool-v1.0.0-${OS}-${ARCH}.tar.gz --output crd-migration-tool-v1.0.0-${OS}-${ARCH}.tar.gz
tar xvf crd-migration-tool-v1.0.0-${OS}-${ARCH}.tar.gz

# Run the tool against your cluster.
./crd-migrator \
    --from ark.heptio.com/v1 \
    --to velero.io/v1 \
    --label-mappings ark.heptio.com:velero.io,ark-schedule:velero.io/schedule-name \
    --annotation-mappings ark.heptio.com:velero.io \
    --namespace-mappings heptio-ark:velero


# Copy the necessary secret from the ark namespace
kubectl get secret --namespace heptio-ark cloud-credentials --export -o yaml | kubectl apply --namespace velero -f -

# Apply the Velero deployment and restic DaemonSet for your platform
## GCP
#kubectl apply -f config/gcp/10-deployment.yaml
#kubectl apply -f config/gcp/20-restic-daemonset.yaml
## AWS
#kubectl apply -f config/aws/10-deployment.yaml
#kubectl apply -f config/aws/20-restic-daemonset.yaml
## Azure
#kubectl apply -f config/azure/00-deployment.yaml
#kubectl apply -f config/azure/20-restic-daemonset.yaml

# Verify your data is still present
./velero get backup
./velero get restore

# Remove old Ark data
kubectl delete namespace heptio-ark
kubectl delete crds -l component=ark 
kubectl delete clusterrolebindings -l component=ark
```

[1]: https://velero.io/docs/v0.10.0/upgrading-to-v0.10
