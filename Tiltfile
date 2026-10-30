# -*- mode: Python -*-

# The CRDs are globbed rather than listed, so that a dev branch adding one is
# picked up without editing this file. Globbing needs a local() call, which Tilt
# refuses while the current kube context might be a production one, so the
# k8s_yaml() for it lives below allow_k8s_contexts().

# default values
settings = {
    "default_registry": "docker.io/velero",
    "use_node_agent": False,
    "enable_debug": False,
    "debug_continue_on_start": True,  # Continue the velero process by default when in debug mode
    "create_backup_locations": False,
    "setup-minio": False,
    # Both are detected when left unset; set them only to override:
    #   cluster_goarch: "amd64" or "arm64" -- the target cluster's node arch
}

# global settings
settings.update(read_json(
    "tilt-resources/tilt-settings.json",
    default = {},
))

k8s_yaml(kustomize('tilt-resources'))
k8s_yaml('tilt-resources/deployment.yaml')
if settings.get("enable_debug"):
    k8s_resource('velero', port_forwards = '2345')
    # TODO: Need to figure out how to apply port forwards for all node-agent pods
if settings.get("use_node_agent"):
    k8s_yaml('tilt-resources/node-agent.yaml')
if settings.get("create_backup_locations"):
    k8s_yaml('tilt-resources/velero_v1_backupstoragelocation.yaml')
if settings.get("setup-minio"):
    k8s_yaml('examples/minio/00-minio-deployment.yaml', allow_duplicates = True)

# By default, Tilt automatically allows Minikube, Docker for Desktop, Microk8s, Red Hat CodeReady Containers, Kind, K3D, and Krucible.
allow_k8s_contexts(settings.get("allowed_contexts"))

# Every CRD under config/crd, so a branch that adds one needs no edit here.
# Deliberately after allow_k8s_contexts(): see the note at the top of the file.
k8s_yaml(str(local('ls config/crd/*/bases/*.yaml', quiet = True, echo_off = True)).splitlines())

# An empty registry means "local cluster, don't push" (kind loads the image
# directly), and Tilt rejects default_registry("") as a missing host.
if settings.get("default_registry"):
    default_registry(settings.get("default_registry"))

local_goos = str(local("go env GOOS", quiet = True, echo_off = True)).strip()
local_goarch = str(local("go env GOARCH", quiet = True, echo_off = True)).strip()
git_sha = str(local("git rev-parse HEAD", quiet = True, echo_off = True)).strip()


def detect_cluster_goarch():
    """
    Best-effort node architecture of the target cluster.

    Every binary in the image and the base image must match the node arch, and
    getting it wrong shows up only later as an "exec format error" in the pod.
    The cluster usually knows the answer, so ask it. Any failure (no cluster
    yet, no nodes, kubectl missing) yields "" and the caller falls back to the
    local architecture, which is correct when the cluster shares the machine
    (kind, minikube, Docker Desktop).
    """
    probe = "kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}' 2>/dev/null || true"
    return str(local(probe, quiet = True, echo_off = True)).strip()


cluster_goarch = settings.get("cluster_goarch") or detect_cluster_goarch() or local_goarch


def detect_container_engine():
    """
    Pick the CLI used for image builds.

    "docker buildx build --load" is preferred: it works against Docker and
    also against Podman's Docker-compatible socket (buildx runs BuildKit in a
    builder container and --load imports the result back through the API), and
    --load defeats the docker-container driver quirk where images otherwise
    never reach the local store. Fall back to the podman CLI when docker (or
    its buildx plugin) is unavailable.
    """
    if str(local("docker buildx version >/dev/null 2>&1 && echo yes || true", quiet = True, echo_off = True)).strip() == "yes":
        return "docker"
    if str(local("podman --version >/dev/null 2>&1 && echo yes || true", quiet = True, echo_off = True)).strip() == "yes":
        return "podman"
    return "docker"


def check_daemon_match(container_engine):
    """
    Fail at load time if the image build and Tilt would use different daemons.

    Tilt looks the built image up through its own client (DOCKER_HOST, else the
    default socket), not through the docker CLI's context. If the engine that
    built the image stored it somewhere else, the failure shows up much later
    as "No such image". Probes that cannot answer (no docker CLI, unreachable
    socket) skip the check rather than block.
    """
    tilt_host = os.getenv("DOCKER_HOST", "") or "unix:///var/run/docker.sock"

    if container_engine == "docker":
        cli_host = str(local("docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true", quiet = True, echo_off = True)).strip()
        if cli_host and cli_host != tilt_host:
            fail("The docker CLI builds against {} but Tilt reads images from {}. Run: export DOCKER_HOST={}".format(cli_host, tilt_host, cli_host))
    elif container_engine == "podman":
        server = str(local("docker --host {} version --format '{{{{range .Server.Components}}}}{{{{.Name}}}};{{{{end}}}}' 2>/dev/null || true".format(tilt_host), quiet = True, echo_off = True)).strip()
        if server and "Podman" not in server:
            fail("container_engine is podman, but Tilt reads images from {}, which is not Podman, so it will never see the image. Use container_engine \"docker\", or point DOCKER_HOST at the Podman socket.".format(tilt_host))


container_engine = settings.get("container_engine") or detect_container_engine()
check_daemon_match(container_engine)

# Native docker_build drives the daemon's BuildKit gRPC API, which Podman's
# Docker-compatible socket does not implement -- it answers 404 "unable to
# upgrade to h2c". Both images below therefore build through a container engine
# CLI via custom_build(), which never touches that endpoint.
if container_engine == "podman":
    # With no default_registry Tilt passes a short name ("velero/velero:...").
    # Docker stores that as docker.io/velero/velero, but Podman stores it as
    # localhost/velero/velero, so Tilt's lookup of the docker.io name fails
    # ("No such image"). Qualify the tag unless it already names a registry.
    # The case is a plain statement, not inside $(...): macOS /bin/sh
    # mis-parses the closing ")" of a case pattern inside a substitution.
    image_build_cmd = (
        'REF="$EXPECTED_REF"; ' +
        'case "${REF%%/*}" in *.*|*:*|localhost) ;; *) REF="docker.io/$REF";; esac; ' +
        "podman build"
    )
    image_tag = '"$REF"'
else:
    image_build_cmd = "docker buildx build --load"
    image_tag = "$EXPECTED_REF"


def get_build_registry():
    """
    Value for hack/build.sh's REGISTRY, which refuses an empty one. It is only
    baked into the binary as the default image prefix; it is not where Tilt
    pushes. An empty default_registry means "local cluster, don't push", so
    fall back to the stock prefix for the build.
    """
    return settings.get("default_registry") or "docker.io/velero"


# Docker's static CLI download archives use their own arch names.
docker_cli_arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(cluster_goarch, cluster_goarch)

print("Tilt: cluster_goarch={} (local {}), container_engine={}".format(cluster_goarch, local_goarch, container_engine))

tilt_helper_dockerfile_header = """
# Tilt image
FROM golang:1.26 as tilt-helper

# Support live reloading with Tilt
RUN wget --output-document /restart.sh --quiet https://raw.githubusercontent.com/windmilleng/rerun-process-wrapper/master/restart.sh  && \
    wget --output-document /start.sh --quiet https://raw.githubusercontent.com/windmilleng/rerun-process-wrapper/master/start.sh && \
    chmod +x /start.sh && chmod +x /restart.sh
"""

# Pinned so the debugger in the image does not change under you between
# builds; @latest made every rebuild a different dlv.
#
# Delve refuses a binary built by a newer Go than it understands ("Version of
# Delve is too old for Go version go1.x.y"), so this pin has to move together
# with the golang image below.
DLV_VERSION = "v1.27.2"

additional_docker_helper_commands = """
# Install delve to allow debugging. A cross-compiled `go install` places the
# binary in $GOPATH/bin/linux_<arch>/ rather than $GOPATH/bin/.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=%s go install github.com/go-delve/delve/cmd/dlv@%s && \\
    if [ -x "$(go env GOPATH)/bin/dlv" ]; then cp "$(go env GOPATH)/bin/dlv" /usr/local/bin/dlv; \\
    else cp "$(go env GOPATH)/bin/linux_%s/dlv" /usr/local/bin/dlv; fi

RUN wget -qO- https://dl.k8s.io/v1.25.2/kubernetes-client-linux-%s.tar.gz | tar xvz -C /tmp
RUN wget -qO- https://download.docker.com/linux/static/stable/%s/docker-27.5.1.tgz | tar xvz -C /tmp && \\
    install -D /tmp/docker/docker /usr/local/bin/docker
""" % (cluster_goarch, DLV_VERSION, cluster_goarch, cluster_goarch, docker_cli_arch)

additional_docker_build_commands = """
COPY --from=tilt-helper /usr/local/bin/dlv /usr/bin/dlv
COPY --from=tilt-helper /usr/local/bin/docker /usr/bin/docker
COPY --from=tilt-helper /tmp/kubernetes/client/bin/kubectl /usr/bin/kubectl
"""

##############################
# Setup Velero
##############################

def get_debug_flag():
    """
    Returns the flag to enable debug building of Velero if debug
    mode is enabled.
    """

    if settings.get('enable_debug'):
        return "DEBUG=1"
    return ""


# Set up a local_resource build of the Velero binary. The binary is written to _tiltbuild/velero.
# GOBIN is required by hack/build.sh and is not otherwise set in a fresh shell.
local_resource(
    "velero_server_binary",
    cmd = 'cd ' + '.' + ';mkdir -p _tiltbuild;PKG=. BIN=velero GOBIN=$(pwd)/_tiltbuild GOOS=linux GOARCH=' + cluster_goarch + ' GIT_SHA=' + git_sha + ' VERSION=main GIT_TREE_STATE=dirty OUTPUT_DIR=_tiltbuild ' + get_debug_flag() + ' REGISTRY=' + get_build_registry() + ' ./hack/build.sh',
    deps = ["cmd", "internal", "pkg"],
    ignore = ["pkg/cmd"],
)

local_resource(
    "velero_local_binary",
    cmd = 'cd ' + '.' + ';mkdir -p _tiltbuild/local;PKG=. BIN=velero GOBIN=$(pwd)/_tiltbuild/local GOOS=' + local_goos + ' GOARCH=' + local_goarch + ' GIT_SHA=' + git_sha + ' VERSION=main GIT_TREE_STATE=dirty OUTPUT_DIR=_tiltbuild/local ' + get_debug_flag() + ' REGISTRY=' + get_build_registry() + ' ./hack/build.sh',
    deps = ["internal", "pkg/cmd"],
)

# Note: we need a distro with a bash shell to exec into the Velero container.
# The runtime stage is built for the cluster's architecture; its apt-get RUN
# executes under emulation (Rosetta/qemu) when that differs from the build
# machine's.
tilt_dockerfile_header = """
FROM --platform=linux/%s ubuntu:22.04 as tilt

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y ca-certificates tzdata && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=tilt-helper /start.sh .
COPY --from=tilt-helper /restart.sh .
COPY velero .
""" % cluster_goarch

dockerfile_contents = "\n".join([
    tilt_helper_dockerfile_header,
    additional_docker_helper_commands,
    tilt_dockerfile_header,
    additional_docker_build_commands,
])

def get_velero_entrypoint():
    """
    Returns the entrypoint for the Velero container image.
    """

    entrypoint = ["sh", "/start.sh"]

    if settings.get("enable_debug"):
        # If debug mode is enabled, start the velero process using Delve
        entrypoint.extend(
            ["dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec"])

        # Set whether or not to continue the debugged process on start
        # See https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv_exec.md
        if settings.get("debug_continue_on_start"):
            entrypoint.append("--continue")

        entrypoint.append("--")

    entrypoint.append("/velero")

    return entrypoint


# Set up an image build for Velero. The live update configuration syncs the output from the local_resource
# build into the container.
#
# The Dockerfile is written to _tiltbuild and handed to the engine CLI by path,
# because custom_build() shells out rather than driving the BuildKit API.
local("mkdir -p _tiltbuild", quiet = True, echo_off = True)
velero_dockerfile_path = "_tiltbuild/Tiltfile.Dockerfile"
local("cat > " + velero_dockerfile_path + " << 'TILTEOF'\n" + dockerfile_contents + "\nTILTEOF", quiet = True, echo_off = True)

custom_build(
    ref = "velero/velero",
    command = (
        image_build_cmd +
        " --platform linux/" + cluster_goarch +
        " -f " + velero_dockerfile_path +
        " --target tilt" +
        " -t " + image_tag +
        " _tiltbuild"
    ),
    deps = ["./_tiltbuild/velero"],
    entrypoint = get_velero_entrypoint(),
    live_update = [
        sync("./_tiltbuild/velero", "/velero"),
        run("sh /restart.sh"),
    ])


##############################
# Setup plugins
##############################

def load_provider_tiltfiles():
    all_providers = settings.get("providers", {})
    enable_providers = settings.get("enable_providers", [])
    providers = []

    ## Load settings only for providers to enable
    for name in enable_providers:
        repo = all_providers.get(name)
        if not repo:
            print("Enabled provider '{}' does not exist in list of supported providers".format(name))
            continue
        file = repo + "/tilt-provider.json"
        if not os.path.exists(file):
            print("Provider settings not found for \"{}\". Please ensure this plugin repository has a tilt-provider.json file included.".format(name))
            continue
        provider_details = read_json(file, default = {})
        if type(provider_details) == "dict":
            provider_details["name"] = name
            if "context" in provider_details:
                provider_details["context"] = os.path.join(repo, "/", provider_details["context"])
            else:
                provider_details["context"] = repo
            if "go_main" not in provider_details:
                provider_details["go_main"] = "main.go"
            providers.append(provider_details)

    return providers


# Enable each provider
def enable_providers(providers):
    if not providers:
        print("No providers to enable.")
        return
    for p in providers:
        enable_provider(p)


# Configures a provider by doing the following:
#
# 1. Enables a local_resource go build of the provider's local binary
# 2. Configures a docker build for the provider, with live updating of the local binary
def enable_provider(provider):
    name = provider.get("name")
    plugin_name = provider.get("plugin_name")

    # Note: we need a distro with a shell to do a copy of the plugin binary
    tilt_dockerfile_header = """
    FROM --platform=linux/""" + cluster_goarch + """ ubuntu:22.04 as tilt
    WORKDIR /
    COPY --from=tilt-helper /start.sh .
    COPY --from=tilt-helper /restart.sh .
    COPY """ + plugin_name + """ .
    """

    dockerfile_contents = "\n".join([
        tilt_helper_dockerfile_header,
        additional_docker_helper_commands,
        tilt_dockerfile_header,
        additional_docker_build_commands,
    ])

    context = provider.get("context")
    go_main = provider.get("go_main", "main.go")

    live_reload_deps = []
    for d in provider.get("live_reload_deps", []):
        live_reload_deps.append(os.path.join(context, "/", d))

    # Set up a local_resource build of the plugin binary. The main.go path must be provided via go_main option. The binary is written to _tiltbuild/<NAME>.
    local_resource(
        name + "_plugin",
        cmd = 'cd ' + context + ';mkdir -p _tiltbuild;PKG=' + context + ' BIN=' + go_main + ' GOOS=linux GOARCH=' + cluster_goarch + ' OUTPUT_DIR=_tiltbuild ./hack/build.sh',
        deps = live_reload_deps,
    )

    # Set up an image build for the plugin. The live update configuration syncs the output from the local_resource
    # build into the init container, and that restarts the Velero container.
    #
    # custom_build like the Velero image, so this path works with Podman too. A
    # provider checkout has no Tiltfile of its own, so the Dockerfile is written
    # into its _tiltbuild directory here. That directory is created first: on a
    # clean checkout it does not exist yet, and the local_resource that builds
    # the binary is what would otherwise create it (later, and only when it
    # runs).
    provider_context = os.path.join(context, "_tiltbuild")
    provider_dockerfile_path = os.path.join(provider_context, "Tiltfile.provider.Dockerfile")
    local("mkdir -p " + provider_context, quiet = True, echo_off = True)
    local(
        "cat > " + provider_dockerfile_path + " << 'TILTEOF'\n" + dockerfile_contents + "\nTILTEOF",
        quiet = True,
        echo_off = True,
    )
    custom_build(
        ref = provider.get("image"),
        command = (
            image_build_cmd +
            " --platform linux/" + cluster_goarch +
            " -f " + provider_dockerfile_path +
            " --target tilt" +
            " -t " + image_tag +
            " " + provider_context
        ),
        deps = [os.path.join(provider_context, plugin_name)],
        entrypoint = ["/bin/bash", "-c", "cp /" + plugin_name + " /target/."],
        live_update = [
            sync(os.path.join(context, "/_tiltbuild/", plugin_name), os.path.join("/", plugin_name))
        ]
    )


##############################
# Start
#############################

enable_providers(load_provider_tiltfiles())
