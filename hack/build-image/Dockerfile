# Copyright 2018, 2019, 2020 the Velero contributors.
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

FROM --platform=$TARGETPLATFORM golang:1.26-trixie

ARG GOPROXY
ARG PROTOC_GEN_GO_VERSION
ARG GOIMPORTS_VERSION

ENV GO111MODULE=on
# Use a proxy for go modules to reduce the likelihood of various hosts being down and breaking the build
ENV GOPROXY=${GOPROXY}

# kubebuilder test bundle is separated from kubebuilder. Need to setup it for CI test.
# Using setup-envtest to download envtest binaries
RUN go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.0.0-20260305094418-8122a6266696 && \
    mkdir -p /usr/local/kubebuilder/bin && \
    ENVTEST_ASSETS_DIR=$(setup-envtest use 1.33.0 --bin-dir /usr/local/kubebuilder/bin -p path) && \
    cp -r ${ENVTEST_ASSETS_DIR}/* /usr/local/kubebuilder/bin/

RUN set -eux; \
    ARCH="$(go env GOARCH)"; \
    case "$ARCH" in \
        amd64) KUBEBUILDER_SHA256="102bb0f586dcb50951aded67856483a2ee114057c56475b3cda6051a12832a72" ;; \
        arm64) KUBEBUILDER_SHA256="0a340ea925c801aa71344becdefce96eda6fa0bc92352b9c7bcb36a4f8c56314" ;; \
        ppc64le) KUBEBUILDER_SHA256="74473d094908caad852a77088f64bb64eb4c79497f6695eb5e9e8bc4bacd9409" ;; \
        *) echo "Unsupported kubebuilder architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    FILE="kubebuilder_linux_$ARCH"; \
    wget --quiet "https://github.com/kubernetes-sigs/kubebuilder/releases/download/v3.2.0/$FILE"; \
    echo "$KUBEBUILDER_SHA256  $FILE" | sha256sum -c -; \
    mv "$FILE" /usr/local/kubebuilder/bin/kubebuilder; \
    chmod +x /usr/local/kubebuilder/bin/kubebuilder

# get controller-tools
RUN go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.5

# get goimports, version derived from go.mod's golang.org/x/tools requirement
# (see https://github.com/velero-io/velero/issues/10023)
RUN go install golang.org/x/tools/cmd/goimports@${GOIMPORTS_VERSION}

# get protoc compiler and golang plugin
WORKDIR /root
RUN apt-get update && apt-get install -y unzip
# protobuf uses bazel cpunames except following
#   if cpu == "systemz":
#   cpu = "s390_64"
#   elif cpu == "aarch64":
#   cpu = "aarch_64"
#   elif cpu == "ppc64":
#   cpu = "ppcle_64"
# snippet from: https://github.com/protocolbuffers/protobuf/blob/d445953603e66eb8992a39b4e10fcafec8501f24/protobuf_release.bzl#L18-L24
# cpu names: https://github.com/bazelbuild/platforms/blob/main/cpu/BUILD
RUN set -eux; \
    GOARCH="$(go env GOARCH)"; \
    case "$GOARCH" in \
        amd64) ARCH="x86_64"; PROTOC_SHA256="78ab9c3288919bdaa6cfcec6127a04813cf8a0ce406afa625e48e816abee2878" ;; \
        386) ARCH="x86_32"; PROTOC_SHA256="cc1c6e31a9b333c3e6d026aac5fdc1f7d70c6cd8851631505188ca9826acee5a" ;; \
        arm64) ARCH="aarch_64"; PROTOC_SHA256="07683afc764e4efa3fa969d5f049fbc2bdfc6b4e7786a0b233413ac0d8753f6b" ;; \
        ppc64|ppc64le) ARCH="ppcle_64"; PROTOC_SHA256="cea283337101ed08ff6c76a98461b1d871bac21f41dc1dabdfddaa5d99df9339" ;; \
        s390x) ARCH="s390_64"; PROTOC_SHA256="8a13ec6518585f7664d58f929417c9e6d0c4aeedf3bcdd854aeafceb5ef0a389" ;; \
        *) echo "Unsupported protoc architecture: $GOARCH" >&2; exit 1 ;; \
    esac; \
    echo "ARCH=$ARCH"; \
    FILE="protoc-25.2-linux-$ARCH.zip"; \
    wget --quiet "https://github.com/protocolbuffers/protobuf/releases/download/v25.2/$FILE"; \
    echo "$PROTOC_SHA256  $FILE" | sha256sum -c -; \
    unzip "$FILE"; \
    rm "$FILE"; \
    mv bin/protoc /usr/bin/protoc; \
    mv include/google /usr/include; \
    chmod a+x /usr/include/google; \
    chmod a+x /usr/include/google/protobuf; \
    chmod a+r -R /usr/include/google; \
    chmod +x /usr/bin/protoc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION} \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

# get goreleaser
# goreleaser name template per arch is basically goarch except for amd64 and 386 https://github.com/goreleaser/goreleaser/blob/ec8819a95c5527fae65e5cb41673f5bbc3245fda/.goreleaser.yaml#L167C1-L173C42
#   {{- .ProjectName }}_
#   {{- title .Os }}_
#   {{- if eq .Arch "amd64" }}x86_64
#   {{- else if eq .Arch "386" }}i386
#   {{- else }}{{ .Arch }}{{ end }}
#   {{- if .Arm }}v{{ .Arm }}{{ end -}}
RUN set -eux; \
    GOARCH="$(go env GOARCH)"; \
    case "$GOARCH" in \
        amd64) ARCH="x86_64"; GORELEASER_SHA256="cfbdf12e3ea20e4c3a209d07311f43c2e0baf20d5cce09bcdc232567e0f34307" ;; \
        386) ARCH="i386"; GORELEASER_SHA256="21c236575cccd29588182b570b4ffe83ad8fb96cd3b13b2af79feafd8ae37b1b" ;; \
        arm64) ARCH="arm64"; GORELEASER_SHA256="2b984e2932b24be0d638c7dab7357a59d86eb79ca7fee1afd31be5ebb1847cbb" ;; \
        arm) ARCH="armv7"; GORELEASER_SHA256="6db2899885be19f123b36192a42dcfb3bb2b3e1009fec7277517969e96d8a7c6" ;; \
        ppc64|ppc64le) ARCH="ppc64"; GORELEASER_SHA256="76d060ebb8d48e76fde45983f87040fe3ac0ca37c5ace4648a956959b81bfdf0" ;; \
        *) echo "Unsupported goreleaser architecture: $GOARCH" >&2; exit 1 ;; \
    esac; \
    FILE="goreleaser_Linux_$ARCH.tar.gz"; \
    wget --quiet "https://github.com/goreleaser/goreleaser/releases/download/v1.26.2/$FILE"; \
    echo "$GORELEASER_SHA256  $FILE" | sha256sum -c -; \
    tar xvf "$FILE"; \
    mv goreleaser /usr/bin/goreleaser; \
    chmod +x /usr/bin/goreleaser

# get golangci-lint
# Use "go install" so the download goes through GOPROXY instead of the GitHub
# release API/CDN, which has been returning intermittent/persistent HTTP 504s.
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0

# Fix the "dubious ownership" issue from git when running goreleaser.sh
RUN echo "[safe] \n\t directory = *" > /.gitconfig
