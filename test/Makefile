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

# If you update this file, please follow:
# https://suva.sh/posts/well-documented-makefiles/

# Use GOPROXY environment variable if set

.DEFAULT_GOAL:=help

ARCH ?= $(shell go env GOOS)-$(shell go env GOARCH)
platform_temp = $(subst -, ,$(ARCH))
GOOS = $(word 1, $(platform_temp))
GOARCH = $(word 2, $(platform_temp))

GOPROXY := $(shell go env GOPROXY)
ifeq ($(GOPROXY),)
GOPROXY := https://proxy.golang.org
endif
export GOPROXY

REPO_ROOT := $(shell git rev-parse --show-toplevel)

help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

## --------------------------------------
## Binaries
## --------------------------------------

TOOLS_DIR := $(REPO_ROOT)/hack/tools
BIN_DIR := bin

# Try to not modify PATH if possible
GOBIN := $(REPO_ROOT)/.go/bin

TOOLS_BIN_DIR := $(TOOLS_DIR)/$(BIN_DIR)

GINKGO := $(GOBIN)/ginkgo
GINKGO_VERSION := $(shell go list -m -f '{{.Version}}' github.com/onsi/ginkgo/v2 2>/dev/null)

KUSTOMIZE := $(TOOLS_BIN_DIR)/kustomize

OUTPUT_DIR := _output/$(GOOS)/$(GOARCH)/bin

# Please reference to this document for Ginkgo label spec format.
# https://onsi.github.io/ginkgo/#spec-labels
GINKGO_LABELS ?=

# When --fail-fast is set, the entire suite will stop when the first failure occurs.
# Enable --fail-fast by default.
# https://onsi.github.io/ginkgo/#mental-model-how-ginkgo-handles-failure
FAIL_FAST ?= false

VERSION ?= main

VELERO_CLI ?=$$(pwd)/../_output/bin/$(GOOS)/$(GOARCH)/velero

VELERO_IMAGE ?= velero/velero:main

PLUGINS ?=

# Flag used to tell E2E whether the Velero vSphere plugin is installed.
HAS_VSPHERE_PLUGIN ?= false

RESTORE_HELPER_IMAGE ?=

#Released version only
UPGRADE_FROM_VELERO_VERSION ?= v1.15.2,v1.16.2,v1.17.2

# UPGRADE_FROM_VELERO_CLI can has the same format(a list divided by comma) with UPGRADE_FROM_VELERO_VERSION
# Upgrade tests will be executed sequently according to the list by UPGRADE_FROM_VELERO_VERSION
# So although length of UPGRADE_FROM_VELERO_CLI list is not equal with UPGRADE_FROM_VELERO_VERSION
# Script will still read UPGRADE_FROM_VELERO_CLI list to match UPGRADE_FROM_VELERO_VERSION list from beginning
# to the end, nil string will be set if UPGRADE_FROM_VELERO_CLI is shorter than UPGRADE_FROM_VELERO_VERSION
UPGRADE_FROM_VELERO_CLI ?=

MIGRATE_FROM_VELERO_VERSION ?= v1.17.2,$(VERSION)
MIGRATE_FROM_VELERO_CLI ?=

VELERO_NAMESPACE ?= velero
CREDS_FILE ?=
DEFAULT_CLS_SERVICE_ACCOUNT_NAME ?=
STANDBY_CLS_SERVICE_ACCOUNT_NAME ?=
BSL_BUCKET ?=
BSL_PREFIX ?=
BSL_CONFIG ?=
VSL_CONFIG ?=
CLOUD_PROVIDER ?=
STANDBY_CLUSTER_CLOUD_PROVIDER ?=
STANDBY_CLUSTER_PLUGINS ?=
STANDBY_CLUSTER_OBJECT_STORE_PROVIDER ?=
OBJECT_STORE_PROVIDER ?=
INSTALL_VELERO ?= true
REGISTRY_CREDENTIAL_FILE ?=
KIBISHII_DIRECTORY ?= github.com/vmware-tanzu-experiments/distributed-data-generator/kubernetes/yaml/
IMAGE_REGISTRY_PROXY ?=

# Parameters for labels and annotations for Velero pods and service accounts.
POD_LABELS ?=
SA_ANNOTATIONS ?=

# Flags to create an additional BSL for multiple credentials tests
ADDITIONAL_BSL_PLUGINS ?=
ADDITIONAL_OBJECT_STORE_PROVIDER ?=
ADDITIONAL_CREDS_FILE ?=
ADDITIONAL_BSL_BUCKET ?=
ADDITIONAL_BSL_PREFIX ?=
ADDITIONAL_BSL_CONFIG ?=

FEATURES ?=
DEBUG_VELERO_POD_RESTART ?= false
VELERO_SERVER_DEBUG_MODE ?= false

ITEM_BLOCK_WORKER_COUNT ?= 1

WORKER_OS ?= linux

# Parameters to run migration tests along with all other E2E tests, and both of them should
#   be provided or left them all empty to skip migration tests with no influence to other
#   E2E tests.
DEFAULT_CLUSTER ?=
STANDBY_CLUSTER ?=

UPLOADER_TYPE ?=

SNAPSHOT_MOVE_DATA ?= false
DATA_MOVER_PLUGIN ?=
DISABLE_INFORMER_CACHE ?= false

DEFAULT_CLUSTER_NAME ?=
STANDBY_CLUSTER_NAME ?=
EKS_POLICY_ARN ?=

# perf test related parameters
TEST_CASE_DESCRIBE ?= 'velero performance test'
BACKUP_FOR_RESTORE ?=
Delete_Cluster_Resource ?= false
Debug_Velero_Pod_Restart ?= false
NODE_AGENT_POD_CPU_LIMIT ?= 4
NODE_AGENT_POD_MEM_LIMIT ?= 4Gi
NODE_AGENT_POD_CPU_REQUEST ?= 2
NODE_AGENT_POD_MEM_REQUEST ?= 2Gi
VELERO_POD_CPU_LIMIT ?= 4
VELERO_POD_MEM_LIMIT ?= 4Gi
VELERO_POD_CPU_REQUEST ?= 2
VELERO_POD_MEM_REQUEST ?= 2Gi
POD_VOLUME_OPERATION_TIMEOUT ?= 6h

COMMON_ARGS := --velerocli=$(VELERO_CLI) \
	--velero-image=$(VELERO_IMAGE) \
	--plugins=$(PLUGINS) \
	--velero-version=$(VERSION) \
	--restore-helper-image=$(RESTORE_HELPER_IMAGE) \
	--velero-namespace=$(VELERO_NAMESPACE) \
	--credentials-file=$(CREDS_FILE) \
	--bucket=$(BSL_BUCKET) \
	--prefix=$(BSL_PREFIX) \
	--bsl-config=$(BSL_CONFIG) \
	--vsl-config=$(VSL_CONFIG) \
	--cloud-provider=$(CLOUD_PROVIDER) \
	--object-store-provider="$(OBJECT_STORE_PROVIDER)" \
	--features=$(FEATURES) \
	--install-velero=$(INSTALL_VELERO) \
	--registry-credential-file=$(REGISTRY_CREDENTIAL_FILE) \
	--velero-server-debug-mode=$(VELERO_SERVER_DEBUG_MODE) \
	--uploader-type=$(UPLOADER_TYPE) \
	--debug-velero-pod-restart=$(DEBUG_VELERO_POD_RESTART) \
	--fail-fast=$(FAIL_FAST) \
	--has-vsphere-plugin=$(HAS_VSPHERE_PLUGIN) \
	--item-block-worker-count=$(ITEM_BLOCK_WORKER_COUNT)

# Make sure ginkgo is in $GOBIN
.PHONY:ginkgo
ginkgo: ${GOBIN}/ginkgo

# This target does not run if ginkgo is already in $GOBIN
${GOBIN}/ginkgo:
	GOBIN=${GOBIN} go install github.com/onsi/ginkgo/v2/ginkgo@${GINKGO_VERSION}

.PHONY: run-e2e
run-e2e: ginkgo
		@[ "${CREDS_FILE}" ] && echo "Using credentials from ${CREDS_FILE}" || \
			( echo "A credentials file is required to run E2E tests, please re-run the make target with CREDS_FILE=<PathToCredentialsFile>"; exit 1 )
		@[ "${BSL_BUCKET}" ] && echo "Using bucket ${BSL_BUCKET} to store backups from E2E tests" || \
			(echo "Bucket to store the backups from E2E tests is required, please re-run with BSL_BUCKET=<BucketName>"; exit 1 )
		@[ "${CLOUD_PROVIDER}" ] && echo "Using cloud provider ${CLOUD_PROVIDER}" || \
			(echo "Cloud provider for target cloud/plugin provider is required, please rerun with CLOUD_PROVIDER=<aws,azure,kind,vsphere>"; exit 1)
	@$(GINKGO) run \
		-v \
		--junit-report e2e/report.xml \
		--label-filter="$(GINKGO_LABELS)" \
		--timeout=5h \
		--fail-fast=$(FAIL_FAST) \
		./e2e \
		-- $(COMMON_ARGS) \
		--upgrade-from-velero-cli=$(UPGRADE_FROM_VELERO_CLI) \
		--upgrade-from-velero-version=$(UPGRADE_FROM_VELERO_VERSION) \
		--migrate-from-velero-cli=$(MIGRATE_FROM_VELERO_CLI) \
		--migrate-from-velero-version=$(MIGRATE_FROM_VELERO_VERSION) \
		--additional-bsl-plugins=$(ADDITIONAL_BSL_PLUGINS) \
		--additional-bsl-object-store-provider="$(ADDITIONAL_OBJECT_STORE_PROVIDER)" \
		--additional-bsl-credentials-file=$(ADDITIONAL_CREDS_FILE) \
		--additional-bsl-bucket=$(ADDITIONAL_BSL_BUCKET) \
		--additional-bsl-prefix=$(ADDITIONAL_BSL_PREFIX) \
		--additional-bsl-config=$(ADDITIONAL_BSL_CONFIG) \
		--default-cluster-context=$(DEFAULT_CLUSTER) \
		--standby-cluster-context=$(STANDBY_CLUSTER) \
		--snapshot-move-data=$(SNAPSHOT_MOVE_DATA) \
		--data-mover-plugin=$(DATA_MOVER_PLUGIN) \
		--standby-cluster-cloud-provider=$(STANDBY_CLUSTER_CLOUD_PROVIDER) \
		--standby-cluster-plugins=$(STANDBY_CLUSTER_PLUGINS) \
		--standby-cluster-object-store-provider=$(STANDBY_CLUSTER_OBJECT_STORE_PROVIDER) \
		--default-cluster-name=$(DEFAULT_CLUSTER_NAME) \
		--standby-cluster-name=$(STANDBY_CLUSTER_NAME) \
		--eks-policy-arn=$(EKS_POLICY_ARN) \
		--default-cls-service-account-name=$(DEFAULT_CLS_SERVICE_ACCOUNT_NAME) \
		--standby-cls-service-account-name=$(STANDBY_CLS_SERVICE_ACCOUNT_NAME) \
		--kibishii-directory=$(KIBISHII_DIRECTORY) \
		--disable-informer-cache=$(DISABLE_INFORMER_CACHE) \
		--image-registry-proxy=$(IMAGE_REGISTRY_PROXY) \
		--worker-os=$(WORKER_OS) \
		--pod-labels=$(POD_LABELS) \
		--sa-annotations=$(SA_ANNOTATIONS)

.PHONY: run-perf
run-perf: ginkgo
		@[ "${CREDS_FILE}" ] && echo "Using credentials from ${CREDS_FILE}" || \
			( echo "A credentials file is required to run E2E tests, please re-run the make target with CREDS_FILE=<PathToCredentialsFile>"; exit 1 )
		@[ "${BSL_BUCKET}" ] && echo "Using bucket ${BSL_BUCKET} to store backups from E2E tests" || \
			(echo "Bucket to store the backups from E2E tests is required, please re-run with BSL_BUCKET=<BucketName>"; exit 1 )
		@[ "${CLOUD_PROVIDER}" ] && echo "Using cloud provider ${CLOUD_PROVIDER}" || \
			(echo "Cloud provider for target cloud/plugin provider is required, please rerun with CLOUD_PROVIDER=<aws,azure,kind,vsphere>"; exit 1)
	@$(GINKGO) run \
		-v \
		--junit-report perf/report.xml \
		--label-filter="$(GINKGO_LABELS)" \
		--timeout=5h \
		--fail-fast=$(FAIL_FAST) \
		./perf \
		-- $(COMMON_ARGS) \
		--nfs-server-path=$(NFS_SERVER_PATH) \
		--test-case-describe=$(TEST_CASE_DESCRIBE) \
		--backup-for-restore=$(BACKUP_FOR_RESTORE) \
		--delete-cluster-resource=$(Delete_Cluster_Resource) \
		--node-agent-pod-cpu-limit=$(NODE_AGENT_POD_CPU_LIMIT) \
		--node-agent-pod-mem-limit=$(NODE_AGENT_POD_MEM_LIMIT) \
		--node-agent-pod-cpu-request=$(NODE_AGENT_POD_CPU_REQUEST) \
		--node-agent-pod-mem-request=$(NODE_AGENT_POD_MEM_REQUEST) \
		--velero-pod-cpu-limit=$(VELERO_POD_CPU_LIMIT) \
		--velero-pod-mem-limit=$(VELERO_POD_MEM_LIMIT) \
		--velero-pod-cpu-request=$(VELERO_POD_CPU_REQUEST) \
		--velero-pod-mem-request=$(VELERO_POD_MEM_REQUEST) \
		--pod-volume-operation-timeout=$(POD_VOLUME_OPERATION_TIMEOUT)

build: ginkgo
	mkdir -p $(OUTPUT_DIR)
	$(GINKGO) build . 