# Wrapper image for `make test-e2e-kind`: runs a nested dockerd, builds Velero
# from the mounted repo source, creates a kind cluster, runs MinIO, and drives the
# existing test/Makefile e2e target — all entirely inside one container.
# See hack/e2e-kind.sh (driver) and test/e2e/README.md for usage.
#
# Each tool is fetched in its own stage so layer caching is per-tool: bumping one
# version only re-downloads that tool, editing entrypoint.sh re-downloads nothing,
# and cold builds fetch all three in parallel.
#
# Future investigation: a podman-in-podman base (quay.io/podman/stable) could
# replace docker:dind, but two things block it today: kind's podman provider is
# still experimental (KIND_EXPERIMENTAL_PROVIDER=podman, with a known rootless
# log-driver issue that breaks kind's boot detection), and the root Makefile's
# `container` target hard-requires docker buildx (errors on CONTAINER_TOOL=podman),
# so the inner Velero image build would need a separate podman build path.

# KIND_VERSION and KUBECTL_VERSION must be bumped together: kubectl should match
# the Kubernetes version of this kind release's default node image.
ARG KIND_VERSION=v0.27.0
ARG KUBECTL_VERSION=v1.32.2
ARG GO_VERSION=1.26.0

FROM alpine:3.21 AS fetch-kind
ARG KIND_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl \
	&& curl -fsSLo /kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${TARGETARCH}" \
	&& curl -fsSLo /kind.sha256sum "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${TARGETARCH}.sha256sum" \
	&& echo "$(cut -d' ' -f1 /kind.sha256sum)  /kind" | sha256sum -c - \
	&& chmod +x /kind

FROM alpine:3.21 AS fetch-kubectl
ARG KUBECTL_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl \
	&& curl -fsSLo /kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
	&& curl -fsSLo /kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256" \
	&& echo "$(cat /kubectl.sha256)  /kubectl" | sha256sum -c - \
	&& chmod +x /kubectl

FROM alpine:3.21 AS fetch-go
ARG GO_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl \
	&& curl -fsSLo /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" \
	&& curl -fsSLo /tmp/go.tar.gz.sha256 "https://dl.google.com/go/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz.sha256" \
	&& echo "$(cat /tmp/go.tar.gz.sha256)  /tmp/go.tar.gz" | sha256sum -c - \
	&& tar -C /usr/local -xzf /tmp/go.tar.gz

FROM docker:dind

RUN apk add --no-cache bash git make ca-certificates

COPY --from=fetch-kind /kind /usr/local/bin/kind
COPY --from=fetch-kubectl /kubectl /usr/local/bin/kubectl
COPY --from=fetch-go /usr/local/go /usr/local/go

ENV PATH="/usr/local/go/bin:${PATH}"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
