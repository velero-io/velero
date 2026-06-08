# Copyright 2016 The Kubernetes Authors.
#
# Modifications Copyright 2020 the Velero contributors.
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

# The binary to build (just the basename).
BIN ?= velero

# This repo's root import path (under GOPATH).
PKG := github.com/vmware-tanzu/velero

# Where to push the docker image.
REGISTRY ?= velero
# In order to push images to an insecure registry, follow the two steps:
#   1. Set "INSECURE_REGISTRY=true" 
#   2. Provide your own buildx builder instance by setting "BUILDX_INSTANCE=your-own-builder-instance"
#      The builder can be created with the following command:
#        cat << EOF > buildkitd.toml
#        [registry."insecure-registry-ip:port"]
#        http = true
#        insecure = true
#        EOF
#        docker buildx create --name=velero-builder --driver=docker-container --bootstrap --use --config ./buildkitd.toml
#      Refer to https://github.com/docker/buildx/issues/1370#issuecomment-1288516840 for more details
INSECURE_REGISTRY ?= false

# Image name
IMAGE ?= $(REGISTRY)/$(BIN)

# We allow the Dockerfile to be configurable to enable the use of custom Dockerfiles
# that pull base images from different registries.
VELERO_DOCKERFILE ?= Dockerfile
VELERO_DOCKERFILE_WINDOWS ?= Dockerfile-Windows
BUILDER_IMAGE_DOCKERFILE ?= hack/build-image/Dockerfile

# Calculate the realpath of the build-image Dockerfile as we `cd` into the hack/build
# directory before this Dockerfile is used and any relative path will not be valid.
BUILDER_IMAGE_DOCKERFILE_REALPATH := $(shell realpath $(BUILDER_IMAGE_DOCKERFILE))

# Build image handling. We push a build image for every changed version of
# /hack/build-image/Dockerfile. We tag the dockerfile with the short commit hash
# of the commit that changed it. When determining if there is a build image in
# the registry to use we look for one that matches the current "commit" for the
# Dockerfile else we make one.
# In the case where the Dockerfile for the build image has been overridden using
# the BUILDER_IMAGE_DOCKERFILE variable, we always force a build.

ifneq "$(origin BUILDER_IMAGE_DOCKERFILE)" "file"
	BUILDER_IMAGE_TAG := "custom"
else
	BUILDER_IMAGE_TAG := $(shell git log -1 --pretty=%h $(BUILDER_IMAGE_DOCKERFILE))
endif

BUILDER_IMAGE := $(REGISTRY)/build-image:$(BUILDER_IMAGE_TAG)
BUILDER_IMAGE_CACHED := $(shell docker images -q ${BUILDER_IMAGE} 2>/dev/null )

HUGO_IMAGE := ghcr.io/gohugoio/hugo

# Which architecture to build - see $(ALL_ARCH) for options.
# if the 'local' rule is being run, detect the ARCH from 'go env'
# if it wasn't specified by the caller.
local : ARCH ?= $(shell go env GOOS)-$(shell go env GOARCH)
ARCH ?= linux-amd64

VERSION ?= main

TAG_LATEST ?= false

ifeq ($(TAG_LATEST), true)
	IMAGE_TAGS ?= $(IMAGE):$(VERSION) $(IMAGE):latest
else
	IMAGE_TAGS ?= $(IMAGE):$(VERSION)
endif

# check buildx is enabled only if docker is in path
# macOS/Windows docker cli without Docker Desktop license: https://github.com/abiosoft/colima
# To add buildx to docker cli: https://github.com/abiosoft/colima/discussions/273#discussioncomment-2684502
ifeq ($(shell which docker 2>/dev/null 1>&2 && docker buildx inspect 2>/dev/null | awk '/Status/ { print $$2 }'), running)
	BUILDX_ENABLED ?= true
# if emulated docker cli from podman, assume enabled
# emulated docker cli from podman: https://podman-desktop.io/docs/migrating-from-docker/emulating-docker-cli-with-podman
# podman known issues:
# - on remote podman, such as on macOS,
#   --output issue: https://github.com/containers/podman/issues/15922
else ifeq ($(shell which docker 2>/dev/null 1>&2 && cat $(shell which docker) | grep -c "exec podman"), 1)
	BUILDX_ENABLED ?= true
else
	BUILDX_ENABLED ?= false
endif

define BUILDX_ERROR
buildx not enabled, refusing to run this recipe
see: https://velero.io/docs/main/build-from-source/#making-images-and-updating-velero for more info
endef
# comma cannot be escaped and can only be used in Make function arguments by putting into variable
comma=,

CLI_PLATFORMS ?= linux-amd64 linux-arm linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 linux-ppc64le linux-s390x
BUILD_OUTPUT_TYPE ?= docker
BUILD_OS ?= linux
BUILD_ARCH ?= amd64
BUILD_WINDOWS_VERSION ?= ltsc2022

ifeq ($(BUILD_OUTPUT_TYPE), docker)
	ALL_OS = linux
	ALL_ARCH.linux = $(word 2, $(subst -, ,$(shell go env GOOS)-$(shell go env GOARCH)))
else
	ALL_OS = $(subst $(comma), ,$(BUILD_OS))
	ALL_ARCH.linux = $(subst $(comma), ,$(BUILD_ARCH))
endif

ALL_ARCH.windows = $(if $(filter windows,$(ALL_OS)),amd64,)
ALL_OSVERSIONS.windows = $(if $(filter windows,$(ALL_OS)),$(BUILD_WINDOWS_VERSION),)
ALL_OS_ARCH.linux =  $(foreach os, $(filter linux,$(ALL_OS)), $(foreach arch, ${ALL_ARCH.linux}, ${os}-$(arch)))
ALL_OS_ARCH.windows = $(foreach os, $(filter windows,$(ALL_OS)), $(foreach arch, $(ALL_ARCH.windows), $(foreach osversion, ${ALL_OSVERSIONS.windows}, ${os}-${osversion}-${arch})))
ALL_OS_ARCH = $(ALL_OS_ARCH.linux)$(ALL_OS_ARCH.windows)

ALL_IMAGE_TAGS = $(IMAGE_TAGS)

# set git sha and tree state
GIT_SHA = $(shell git rev-parse HEAD)
ifneq ($(shell git status --porcelain 2> /dev/null),)
	GIT_TREE_STATE ?= dirty
else
	GIT_TREE_STATE ?= clean
endif

###
### These variables should not need tweaking.
###

platform_temp = $(subst -, ,$(ARCH))
GOOS = $(word 1, $(platform_temp))
GOARCH = $(word 2, $(platform_temp))
GOPROXY ?= https://proxy.golang.org
GOBIN=$$(pwd)/.go/bin

# If you want to build all binaries, see the 'all-build' rule.
# If you want to build all containers, see the 'all-containers' rule.
all:
	@$(MAKE) build

build-%:
	@$(MAKE) --no-print-directory ARCH=$* build

all-build: $(addprefix build-, $(CLI_PLATFORMS))

all-containers:
	@$(MAKE) --no-print-directory container

local: build-dirs
# Add DEBUG=1 to enable debug locally
	GOOS=$(GOOS) \
	GOARCH=$(GOARCH) \
	GOBIN=$(GOBIN) \
	VERSION=$(VERSION) \
	REGISTRY=$(REGISTRY) \
	PKG=$(PKG) \
	BIN=$(BIN) \
	GIT_SHA=$(GIT_SHA) \
	GIT_TREE_STATE=$(GIT_TREE_STATE) \
	OUTPUT_DIR=$$(pwd)/_output/bin/$(GOOS)/$(GOARCH) \
	./hack/build.sh

build: _output/bin/$(GOOS)/$(GOARCH)/$(BIN)

_output/bin/$(GOOS)/$(GOARCH)/$(BIN): build-dirs
	@echo "building: $@"
	$(MAKE) shell CMD="-c '\
		GOOS=$(GOOS) \
		GOARCH=$(GOARCH) \
		GOBIN=$(GOBIN) \
		VERSION=$(VERSION) \
		REGISTRY=$(REGISTRY) \
		PKG=$(PKG) \
		BIN=$(BIN) \
		GIT_SHA=$(GIT_SHA) \
		GIT_TREE_STATE=$(GIT_TREE_STATE) \
		OUTPUT_DIR=/output/$(GOOS)/$(GOARCH) \
		./hack/build.sh'"

TTY := $(shell tty -s && echo "-t")

# Example: make shell CMD="date > datefile"
shell: build-dirs build-env
	@# bind-mount the Velero root dir in at /github.com/vmware-tanzu/velero
	@# because the Kubernetes code-generator tools require the project to
	@# exist in a directory hierarchy ending like this (but *NOT* necessarily
	@# under $GOPATH).
	@docker run \
		-e GOFLAGS \
		-e GOPROXY \
		-i $(TTY) \
		--rm \
		-u $$(id -u):$$(id -g) \
		-v "$$(pwd):/github.com/vmware-tanzu/velero:delegated" \
		-v "$$(pwd)/_output/bin:/output:delegated" \
		-v "$$(pwd)/.go/pkg:/go/pkg:delegated" \
		-v "$$(pwd)/.go/std:/go/std:delegated" \
		-v "$$(pwd)/.go/std/$(GOOS)/$(GOARCH):/usr/local/go/pkg/$(GOOS)_$(GOARCH)_static:delegated" \
		-v "$$(pwd)/.go/go-build:/.cache/go-build:delegated" \
		-v "$$(pwd)/.go/golangci-lint:/.cache/golangci-lint:delegated" \
        -v "$$(pwd)/.go/goimports:/.cache/goimports:delegated" \
		-w /github.com/vmware-tanzu/velero \
		$(BUILDER_IMAGE) \
		/bin/sh $(CMD)

container:
ifneq ($(BUILDX_ENABLED), true)
	$(error $(BUILDX_ERROR))
endif

ifeq ($(BUILDX_INSTANCE),)
	@echo creating a buildx instance
	-docker buildx rm velero-builder || true
	@docker buildx create --use --name=velero-builder
else
	@echo using a specified buildx instance $(BUILDX_INSTANCE)
	@docker buildx use $(BUILDX_INSTANCE)
endif

	@mkdir -p _output

	@for osarch in $(ALL_OS_ARCH); do \
		$(MAKE) container-$${osarch}; \
	done

ifeq ($(BUILD_OUTPUT_TYPE), registry)
	@for tag in $(ALL_IMAGE_TAGS); do \
		IMAGE_TAG=$${tag} $(MAKE) push-manifest; \
	done
endif

container-linux-%:
	@BUILDX_ARCH=$* $(MAKE) container-linux

container-linux:
	@echo "building container: $(IMAGE):$(VERSION)-linux-$(BUILDX_ARCH)"

	@docker buildx build --pull \
	--output="type=$(BUILD_OUTPUT_TYPE)$(if $(findstring tar, $(BUILD_OUTPUT_TYPE)),$(comma)dest=_output/$(BIN)-$(VERSION)-linux-$(BUILDX_ARCH).tar,)" \
	--platform="linux/$(BUILDX_ARCH)" \
	$(addprefix -t , $(addsuffix "-linux-$(BUILDX_ARCH)",$(ALL_IMAGE_TAGS))) \
	--build-arg=GOPROXY=$(GOPROXY) \
	--build-arg=PKG=$(PKG) \
	--build-arg=BIN=$(BIN) \
	--build-arg=VERSION=$(VERSION) \
	--build-arg=GIT_SHA=$(GIT_SHA) \
	--build-arg=GIT_TREE_STATE=$(GIT_TREE_STATE) \
	--build-arg=REGISTRY=$(REGISTRY) \
	--provenance=false \
	--sbom=false \
	-f $(VELERO_DOCKERFILE) .

	@echo "built container: $(IMAGE):$(VERSION)-linux-$(BUILDX_ARCH)"

container-windows-%:
	@BUILDX_OSVERSION=$(firstword $(subst -, ,$*)) BUILDX_ARCH=$(lastword $(subst -, ,$*)) $(MAKE) container-windows

container-windows:
	@echo "building container: $(IMAGE):$(VERSION)-windows-$(BUILDX_OSVERSION)-$(BUILDX_ARCH)"

	@docker buildx build --pull \
	--output="type=$(BUILD_OUTPUT_TYPE)$(if $(findstring tar, $(BUILD_OUTPUT_TYPE)),$(comma)dest=_output/$(BIN)-$(VERSION)-windows-$(BUILDX_OSVERSION)-$(BUILDX_ARCH).tar,)" \
	--platform="windows/$(BUILDX_ARCH)" \
	$(addprefix -t , $(addsuffix "-windows-$(BUILDX_OSVERSION)-$(BUILDX_ARCH)",$(ALL_IMAGE_TAGS))) \
	--build-arg=GOPROXY=$(GOPROXY) \
	--build-arg=PKG=$(PKG) \
	--build-arg=BIN=$(BIN) \
	--build-arg=VERSION=$(VERSION) \
	--build-arg=OS_VERSION=$(BUILDX_OSVERSION) \
	--build-arg=GIT_SHA=$(GIT_SHA) \
    --build-arg=GIT_TREE_STATE=$(GIT_TREE_STATE) \
	--build-arg=REGISTRY=$(REGISTRY) \
	--provenance=false \
	--sbom=false \
	-f $(VELERO_DOCKERFILE_WINDOWS) .

	@echo "built container: $(IMAGE):$(VERSION)-windows-$(BUILDX_OSVERSION)-$(BUILDX_ARCH)"

push-manifest:
	@echo "building manifest: $(IMAGE_TAG) for $(foreach osarch, $(ALL_OS_ARCH), $(IMAGE_TAG)-${osarch})"
	@docker manifest create --amend --insecure=$(INSECURE_REGISTRY) $(IMAGE_TAG) $(foreach osarch, $(ALL_OS_ARCH), $(IMAGE_TAG)-${osarch})

	@set -x; \
	for arch in $(ALL_ARCH.windows); do \
		for osversion in $(ALL_OSVERSIONS.windows); do \
			BASEIMAGE=mcr.microsoft.com/windows/nanoserver:$${osversion}; \
			full_version=`docker manifest inspect --insecure=$(INSECURE_REGISTRY) $${BASEIMAGE} | jq -r '.manifests[0].platform["os.version"]'`; \
			docker manifest annotate --os windows --arch $${arch} --os-version $${full_version} $(IMAGE_TAG) $(IMAGE_TAG)-windows-$${osversion}-$${arch}; \
		done; \
	done

	@echo "pushing manifest $(IMAGE_TAG)"
	@docker manifest push --purge --insecure=$(INSECURE_REGISTRY) $(IMAGE_TAG)

	@echo "pushed manifest $(IMAGE_TAG):"
	@docker manifest inspect --insecure=$(INSECURE_REGISTRY) $(IMAGE_TAG)

SKIP_TESTS ?=
test: build-dirs
ifneq ($(SKIP_TESTS), 1)
	@$(MAKE) shell CMD="-c 'hack/test.sh $(WHAT)'"
endif

test-local: build-dirs
ifneq ($(SKIP_TESTS), 1)
	hack/test.sh $(WHAT)
endif

verify:
ifneq ($(SKIP_TESTS), 1)
	@$(MAKE) shell CMD="-c 'hack/verify-all.sh'"
endif

lint:
ifneq ($(SKIP_TESTS), 1)
	@$(MAKE) shell CMD="-c 'hack/lint.sh'"
endif

local-lint:
ifneq ($(SKIP_TESTS), 1)
	@hack/lint.sh
endif

update:
	@$(MAKE) shell CMD="-c 'hack/update-all.sh'"

# update-crd is for development purpose only, it is faster than update, so is a shortcut when you want to generate CRD changes only
update-crd:
	@$(MAKE) shell CMD="-c 'hack/update-3generated-crd-code.sh'"	

build-dirs:
	@mkdir -p _output/bin/$(GOOS)/$(GOARCH)
	@mkdir -p .go/src/$(PKG) .go/pkg .go/bin .go/std/$(GOOS)/$(GOARCH) .go/go-build .go/golangci-lint .go/goimports

build-env:
	@# if we have overridden the value for the build-image Dockerfile,
	@# force a build using that Dockerfile
	@# if we detect changes in dockerfile force a new build-image
	@# else if we dont have a cached image make one
	@# finally use the cached image
ifneq "$(origin BUILDER_IMAGE_DOCKERFILE)" "file"
	@echo "Dockerfile for builder image has been overridden to $(BUILDER_IMAGE_DOCKERFILE)"
	@echo "Preparing a new builder-image"
	$(MAKE) build-image
else ifneq ($(shell git diff --quiet HEAD -- $(BUILDER_IMAGE_DOCKERFILE); echo $$?), 0)
	@echo "Local changes detected in $(BUILDER_IMAGE_DOCKERFILE)"
	@echo "Preparing a new builder-image"
	$(MAKE) build-image
else ifneq ($(BUILDER_IMAGE_CACHED),)
	@echo "Using Cached Image: $(BUILDER_IMAGE)"
else
	@echo "Trying to pull build-image: $(BUILDER_IMAGE)"
	docker pull -q $(BUILDER_IMAGE) || $(MAKE) build-image
endif

build-image:
	@# When we build a new image we just untag the old one.
	@# This makes sure we don't leave the orphaned image behind.
	$(eval old_id=$(shell docker image inspect  --format '{{ .ID }}' ${BUILDER_IMAGE} 2>/dev/null))
ifeq ($(BUILDX_ENABLED), true)
	@cd hack/build-image && docker buildx build --build-arg=GOPROXY=$(GOPROXY) --output=type=docker --pull -t $(BUILDER_IMAGE) -f $(BUILDER_IMAGE_DOCKERFILE_REALPATH) .
else
	@cd hack/build-image && docker build --build-arg=GOPROXY=$(GOPROXY) --pull -t $(BUILDER_IMAGE) -f $(BUILDER_IMAGE_DOCKERFILE_REALPATH) .
endif
	$(eval new_id=$(shell docker image inspect  --format '{{ .ID }}' ${BUILDER_IMAGE} 2>/dev/null))
	@if [ "$(old_id)" != "" ] && [ "$(old_id)" != "$(new_id)" ]; then \
		docker rmi -f $$id || true; \
	fi

push-build-image:
	@# this target will push the build-image it assumes you already have docker
	@# credentials needed to accomplish this.
	@# Pushing will be skipped if a custom Dockerfile was used to build the image.
ifneq "$(origin BUILDER_IMAGE_DOCKERFILE)" "file"
	@echo "Dockerfile for builder image has been overridden"
	@echo "Skipping push of custom image"
else
	docker push $(BUILDER_IMAGE)
endif

build-image-hugo:
	cd site && docker build --pull -t $(HUGO_IMAGE) .

clean:
# if we have a cached image then use it to run go clean --modcache
# this test checks if we there is an image id in the BUILDER_IMAGE_CACHED variable.
ifneq ($(strip $(BUILDER_IMAGE_CACHED)),)
	$(MAKE) shell CMD="-c 'go clean --modcache'"
	docker rmi -f $(BUILDER_IMAGE) || true
endif
	rm -rf .go _output
	docker rmi $(HUGO_IMAGE)


.PHONY: modules
modules:
	go mod tidy


.PHONY: verify-modules
verify-modules: modules
	@if !(git diff --quiet HEAD -- go.sum go.mod); then \
		echo "go module files are out of date, please commit the changes to go.mod and go.sum"; exit 1; \
	fi


ci: verify-modules verify all test


changelog:
	hack/release-tools/changelog.sh

# release builds a GitHub release using goreleaser within the build container.
#
# To dry-run the release, which will build the binaries/artifacts locally but
# will *not* create a GitHub release:
#		GITHUB_TOKEN=an-invalid-token-so-you-dont-accidentally-push-release \
#		RELEASE_NOTES_FILE=changelogs/CHANGELOG-1.2.md \
#		PUBLISH=false \
#		make release
#
# To run the release, which will publish a *DRAFT* GitHub release in github.com/vmware-tanzu/velero
# (you still need to review/publish the GitHub release manually):
#		GITHUB_TOKEN=your-github-token \
#		RELEASE_NOTES_FILE=changelogs/CHANGELOG-1.2.md \
#		PUBLISH=true \
#		make release
release:
	$(MAKE) shell CMD="-c '\
		GITHUB_TOKEN=$(GITHUB_TOKEN) \
		RELEASE_NOTES_FILE=$(RELEASE_NOTES_FILE) \
		PUBLISH=$(PUBLISH) \
		REGISTRY=$(REGISTRY) \
		./hack/release-tools/goreleaser.sh'"

serve-docs: build-image-hugo
	docker run \
	--rm \
	-v "$$(pwd)/site:/project" \
	-it -p 1313:1313 \
	$(HUGO_IMAGE) \
	server --bind=0.0.0.0 --enableGitInfo=false
# gen-docs generates a new versioned docs directory under site/content/docs.
# Please read the documentation in the script for instructions on how to use it.
gen-docs:
	@hack/release-tools/gen-docs.sh

.PHONY: test-e2e
test-e2e: local
	$(MAKE) -e VERSION=$(VERSION) -C test/ run-e2e

.PHONY: test-perf
test-perf: local
	$(MAKE) -e VERSION=$(VERSION) -C test/ run-perf

go-generate:
	go generate ./pkg/...

# requires an authenticated gh cli
# gh: https://cli.github.com/
# First create a PR
# gh pr create --title 'Title name' --body 'PR body'
# by default uses PR title as changelog body but can be overwritten like so
# make new-changelog CHANGELOG_BODY="Changes you have made"
new-changelog: GH_LOGIN ?= $(shell gh pr view --json author --jq .author.login 2> /dev/null)
new-changelog: GH_PR_NUMBER ?= $(shell gh pr view --json number --jq .number 2> /dev/null)
new-changelog: CHANGELOG_BODY ?= '$(shell gh pr view --json title --jq .title)'
new-changelog:
	@if [ "$(GH_LOGIN)" = "" ]; then \
		echo "branch does not have PR or cli not logged in, try 'gh auth login' or 'gh pr create'"; \
		exit 1; \
	fi
	@mkdir -p ./changelogs/unreleased/ && \
	echo $(CHANGELOG_BODY) > ./changelogs/unreleased/$(GH_PR_NUMBER)-$(GH_LOGIN) && \
	echo \"$(CHANGELOG_BODY)\" added to "./changelogs/unreleased/$(GH_PR_NUMBER)-$(GH_LOGIN)"