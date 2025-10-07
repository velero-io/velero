FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:rhel_9_golang_1.24 AS builder
COPY . /workspace

#######################################################################
#######################################################################
#                                                                     #
#      W     W    AA     RRRR     N   N    III    N   N     GGG       #
#      W     W   A  A    R   R    NN  N     I     NN  N    G          #
#      W  W  W   AAAA    RRRR     N N N     I     N N N    G  GG      #
#       W W W    A  A    R R      N  NN     I     N  NN    G   G      #
#        W W     A  A    R  RR    N   N    III    N   N     GGG       #
#                                                                     #
#  Any changes to the `velero` and `restic` sections below must also  #
#  be reconciled in oadp-mustgather/Dockerfile.in for consistency.    #
#######################################################################
# BEGIN                                                               #
#######################################################################

# velero
WORKDIR /workspace/
ENV GOEXPERIMENT strictfipsruntime
RUN CGO_ENABLED=1 GOOS=linux go build -a -mod=mod -ldflags '-X github.com/vmware-tanzu/velero/pkg/buildinfo.Version=v1.12.4-OADP' -tags strictfipsruntime -o ./bin/velero ./cmd/velero
RUN CGO_ENABLED=1 GOOS=linux go build -a -mod=mod -tags strictfipsruntime -o ./bin/velero-helper ./cmd/velero-helper


# restic
WORKDIR /workspace/restic/
ENV GOEXPERIMENT strictfipsruntime
RUN CGO_ENABLED=1 GOOS=linux go build -a -mod=mod -tags strictfipsruntime -o ./bin/restic ./cmd/restic
USER nobody:nobody

#######################################################################
# END                                                                 #
#######################################################################

FROM registry.redhat.io/ubi9/ubi:latest
RUN dnf -y reinstall tzdata && dnf clean all
RUN dnf -y install less nmap-ncat openssl && dnf clean all
COPY --from=builder /workspace/bin/velero velero
COPY --from=builder /workspace/bin/velero-helper velero-helper
COPY --from=builder /workspace/restic/bin/restic /usr/bin/restic
COPY --from=builder /workspace/LICENSE /licenses/

RUN mkdir -p /home/velero
RUN chmod -R 777 /home/velero

USER 65534:65534
ENV HOME=/home/velero

ENTRYPOINT ["/velero"]

LABEL description="OpenShift API for Data Protection - Velero"
LABEL io.k8s.description="OpenShift API for Data Protection - Velero"
LABEL io.k8s.display-name="OADP Velero"
LABEL io.openshift.tags="migration"
LABEL summary="OpenShift API for Data Protection - Velero"
