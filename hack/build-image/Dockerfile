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

FROM --platform=$TARGETPLATFORM golang:1.25-trixie

ARG GOPROXY

ENV GO111MODULE=on
# Use a proxy for go modules to reduce the likelihood of various hosts being down and breaking the build
ENV GOPROXY=${GOPROXY}

# kubebuilder test bundle is separated from kubebuilder. Need to setup it for CI test.
# Using setup-envtest to download envtest binaries
RUN go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.0.0-20260305094418-8122a6266696 && \
    mkdir -p /usr/local/kubebuilder/bin && \
    ENVTEST_ASSETS_DIR=$(setup-envtest use 1.33.0 --bin-dir /usr/local/kubebuilder/bin -p path) && \
    cp -r ${ENVTEST_ASSETS_DIR}/* /usr/local/kubebuilder/bin/

RUN wget --quiet https://github.com/kubernetes-sigs/kubebuilder/releases/download/v3.2.0/kubebuilder_linux_$(go env GOARCH) && \
    mv kubebuilder_linux_$(go env GOARCH) /usr/local/kubebuilder/bin/kubebuilder && \
    chmod +x /usr/local/kubebuilder/bin/kubebuilder

# get controller-tools
RUN go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.5

# get goimports (the revision is pinned so we don't indiscriminately update, but the particular commit
# is not important)
RUN go install golang.org/x/tools/cmd/goimports@v0.33.0

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
RUN ARCH=$(go env GOARCH) && \
    if [ "$ARCH" = "s390x" ] ; then \
        ARCH="s390_64"; \
    elif [ "$ARCH" = "arm64" ] ; then \
        ARCH="aarch_64"; \
    elif [ "$ARCH" = "ppc64le" ] ; then \
        ARCH="ppcle_64"; \
    elif [ "$ARCH" = "ppc64" ] ; then \
        ARCH="ppcle_64"; \
    else \
        ARCH=$(uname -m); \
    fi && echo "ARCH=$ARCH" && \
    wget --quiet https://github.com/protocolbuffers/protobuf/releases/download/v25.2/protoc-25.2-linux-$ARCH.zip && \
    unzip protoc-25.2-linux-$ARCH.zip; \
    rm *.zip && \
    mv bin/protoc /usr/bin/protoc && \
    mv include/google /usr/include && \
    chmod a+x /usr/include/google && \
    chmod a+x /usr/include/google/protobuf && \
    chmod a+r -R /usr/include/google && \
    chmod +x /usr/bin/protoc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33.0 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

# get goreleaser
# goreleaser name template per arch is basically goarch except for amd64 and 386 https://github.com/goreleaser/goreleaser/blob/ec8819a95c5527fae65e5cb41673f5bbc3245fda/.goreleaser.yaml#L167C1-L173C42
#   {{- .ProjectName }}_
#   {{- title .Os }}_
#   {{- if eq .Arch "amd64" }}x86_64
#   {{- else if eq .Arch "386" }}i386
#   {{- else }}{{ .Arch }}{{ end }}
#   {{- if .Arm }}v{{ .Arm }}{{ end -}}
RUN ARCH=$(go env GOARCH) && \
    if [ "$ARCH" = "amd64" ] ; then \
        ARCH="x86_64"; \
    elif [ "$ARCH" = "386" ] ; then \
        ARCH="i386"; \
    elif [ "$ARCH" = "ppc64le" ] ; then \
        ARCH="ppc64"; \
    fi && \
    wget --quiet "https://github.com/goreleaser/goreleaser/releases/download/v2.14.3/goreleaser_Linux_$ARCH.tar.gz" && \
    tar xvf goreleaser_Linux_$ARCH.tar.gz; \
    mv goreleaser /usr/bin/goreleaser && \
    chmod +x /usr/bin/goreleaser

# get golangci-lint
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.5.0

# install kubectl
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/$(go env GOARCH)/kubectl
RUN chmod +x ./kubectl
RUN mv ./kubectl /usr/local/bin

# Fix the "dubious ownership" issue from git when running goreleaser.sh
RUN echo "[safe] \n\t directory = *" > /.gitconfig
