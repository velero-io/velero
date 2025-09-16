FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_9_golang_1.24 AS builder
COPY . /workspace
WORKDIR /workspace/
ENV GOEXPERIMENT strictfipsruntime
RUN CGO_ENABLED=1 GOOS=linux go build -a -mod=mod -tags strictfipsruntime -o ./bin/velero-restore-helper ./cmd/velero-restore-helper

FROM registry.redhat.io/ubi9/ubi:latest
RUN dnf -y install nmap-ncat openssl && dnf -y reinstall tzdata && dnf clean all
COPY --from=builder /workspace/bin/velero-restore-helper velero-restore-helper
COPY --from=builder /workspace/LICENSE /licenses/

USER 65534:65534

ENTRYPOINT ["/velero-restore-helper"]

