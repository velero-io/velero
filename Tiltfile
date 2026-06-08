# -*- mode: Python -*-

k8s_yaml([
    'config/crd/v1/bases/velero.io_backups.yaml',
    'config/crd/v1/bases/velero.io_backupstoragelocations.yaml',
    'config/crd/v1/bases/velero.io_deletebackuprequests.yaml',
    'config/crd/v1/bases/velero.io_downloadrequests.yaml',
    'config/crd/v1/bases/velero.io_podvolumebackups.yaml',
    'config/crd/v1/bases/velero.io_podvolumerestores.yaml',
    'config/crd/v1/bases/velero.io_backuprepositories.yaml',
    'config/crd/v1/bases/velero.io_restores.yaml',
    'config/crd/v1/bases/velero.io_schedules.yaml',
    'config/crd/v1/bases/velero.io_serverstatusrequests.yaml',
    'config/crd/v1/bases/velero.io_volumesnapshotlocations.yaml',
    'config/crd/v2alpha1/bases/velero.io_datauploads.yaml',
    'config/crd/v2alpha1/bases/velero.io_datadownloads.yaml',    
])

# default values
settings = {
    "default_registry": "docker.io/velero",
    "use_node_agent": False,
    "enable_debug": False,
    "debug_continue_on_start": True,  # Continue the velero process by default when in debug mode
    "create_backup_locations": False,
    "setup-minio": False,
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
default_registry(settings.get("default_registry"))
local_goos = str(local("go env GOOS", quiet = True, echo_off = True)).strip()
git_sha = str(local("git rev-parse HEAD", quiet = True, echo_off = True)).strip()

tilt_helper_dockerfile_header = """
# Tilt image
FROM golang:1.26 as tilt-helper

# Support live reloading with Tilt
RUN wget --output-document /restart.sh --quiet https://raw.githubusercontent.com/windmilleng/rerun-process-wrapper/master/restart.sh  && \
    wget --output-document /start.sh --quiet https://raw.githubusercontent.com/windmilleng/rerun-process-wrapper/master/start.sh && \
    chmod +x /start.sh && chmod +x /restart.sh
"""

additional_docker_helper_commands = """
# Install delve to allow debugging
RUN go install github.com/go-delve/delve/cmd/dlv@latest

RUN wget -qO- https://dl.k8s.io/v1.25.2/kubernetes-client-linux-amd64.tar.gz | tar xvz
RUN wget -qO- https://get.docker.com | sh
"""

additional_docker_build_commands = """
COPY --from=tilt-helper /go/bin/dlv /usr/bin/dlv
COPY --from=tilt-helper /usr/bin/docker /usr/bin/docker
COPY --from=tilt-helper /go/kubernetes/client/bin/kubectl /usr/bin/kubectl
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
local_resource(
    "velero_server_binary",
    cmd = 'cd ' + '.' + ';mkdir -p _tiltbuild;PKG=. BIN=velero GOOS=linux GOARCH=amd64 GIT_SHA=' + git_sha + ' VERSION=main GIT_TREE_STATE=dirty OUTPUT_DIR=_tiltbuild ' + get_debug_flag() + ' REGISTRY=' + settings.get("default_registry") + ' ./hack/build.sh',
    deps = ["cmd", "internal", "pkg"],
    ignore = ["pkg/cmd"],
)

local_resource(
    "velero_local_binary",
    cmd = 'cd ' + '.' + ';mkdir -p _tiltbuild/local;PKG=. BIN=velero GOOS=' + local_goos + ' GOARCH=amd64 GIT_SHA=' + git_sha + ' VERSION=main GIT_TREE_STATE=dirty OUTPUT_DIR=_tiltbuild/local ' + get_debug_flag() + ' REGISTRY=' + settings.get("default_registry") + ' ./hack/build.sh',
    deps = ["internal", "pkg/cmd"],
)

# Note: we need a distro with a bash shell to exec into the Velero container
tilt_dockerfile_header = """
FROM ubuntu:22.04 as tilt

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y ca-certificates tzdata && rm -rf /var/lib/apt/lists/*

WORKDIR /
COPY --from=tilt-helper /start.sh .
COPY --from=tilt-helper /restart.sh .
COPY velero .
"""

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
docker_build(
    ref = "velero/velero",
    context = "_tiltbuild",
    dockerfile_contents = dockerfile_contents,
    target = "tilt",
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
    FROM ubuntu:22.04 as tilt
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
        cmd = 'cd ' + context + ';mkdir -p _tiltbuild;PKG=' + context + ' BIN=' + go_main + ' GOOS=linux GOARCH=amd64 OUTPUT_DIR=_tiltbuild ./hack/build.sh',
        deps = live_reload_deps,
    )

    # Set up an image build for the plugin. The live update configuration syncs the output from the local_resource
    # build into the init container, and that restarts the Velero container.
    docker_build(
        ref = provider.get("image"),
        context = os.path.join(context, "/_tiltbuild/"),
        dockerfile_contents = dockerfile_contents,
        target = "tilt",
        entrypoint = ["/bin/bash", "-c", "cp /" + plugin_name + " /target/."],
        live_update = [
            sync(os.path.join(context, "/_tiltbuild/", plugin_name), os.path.join("/", plugin_name))
        ]
    )


##############################
# Start
#############################

enable_providers(load_provider_tiltfiles())
