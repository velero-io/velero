---
title: "Upgrading to Velero 1.2"
layout: docs
---

## Prerequisites

- Velero [v1.1][0] or [v1.0][1] installed.

_Note: if you're upgrading from v1.0, follow the [upgrading to v1.1][2] instructions first._

## Instructions

1. Install the Velero v1.2 command-line interface (CLI) by following the [instructions here][3].

    Verify that you've properly installed it by running:

    ```bash
    velero version --client-only
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.2.0
        Git commit: <git SHA>
    ```

1. Scale down the existing Velero deployment:

    ```bash
    kubectl scale deployment/velero \
        --namespace velero \
        --replicas 0
    ```

1. Update the container image used by the Velero deployment and, optionally, the restic daemon set:

    ```bash
    kubectl set image deployment/velero \
        velero=velero/velero:v1.2.0 \
        --namespace velero

    # optional, if using the restic daemon set
    kubectl set image daemonset/restic \
        restic=velero/velero:v1.2.0 \
        --namespace velero
    ```

1. If using AWS, Azure, or GCP, add the respective plugin to your Velero deployment:

    For AWS:

    ```bash
    velero plugin add velero/velero-plugin-for-aws:v1.0.0
    ```

    For Azure:

    ```bash
    velero plugin add velero/velero-plugin-for-microsoft-azure:v1.0.0
    ```

    For GCP:

    ```bash
    velero plugin add velero/velero-plugin-for-gcp:v1.0.0
    ```

1. Update the Velero custom resource definitions (CRDs) to include the structural schemas:

    ```bash
    velero install --crds-only --dry-run -o yaml | kubectl apply -f -
    ```

1. Scale back up the existing Velero deployment:

    ```bash
    kubectl scale deployment/velero \
        --namespace velero \
        --replicas 1
    ```

1. Confirm that the deployment is up and running with the correct version by running:

    ```bash
    velero version
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.2.0
        Git commit: <git SHA>

    Server:
        Version: v1.2.0
    ```

[0]: https://github.com/velero-io/velero/releases/tag/v1.1.0
[1]: https://github.com/velero-io/velero/releases/tag/v1.0.0
[2]: https://velero.io/docs/v1.1.0/upgrade-to-1.1/
[3]: basic-install.md#install-the-cli
