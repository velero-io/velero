---
title: "Upgrading to Velero 1.3"
layout: docs
---

## Prerequisites

- Velero [v1.3.1][5], [v1.3.0][4] or [v1.2][3] installed.

If you're not yet running at least Velero v1.2, see the following:

- [Upgrading to v1.1][1]
- [Upgrading to v1.2][2]

## Instructions

1. Install the Velero v1.3 command-line interface (CLI) by following the [instructions here][0].

    Verify that you've properly installed it by running:

    ```bash
    velero version --client-only
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.3.2
        Git commit: <git SHA>
    ```

1. Update the container image used by the Velero deployment and, optionally, the restic daemon set:

    ```bash
    kubectl set image deployment/velero \
        velero=velero/velero:v1.3.2 \
        --namespace velero

    # optional, if using the restic daemon set
    kubectl set image daemonset/restic \
        restic=velero/velero:v1.3.2 \
        --namespace velero
    ```

1. Confirm that the deployment is up and running with the correct version by running:

    ```bash
    velero version
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.3.2
        Git commit: <git SHA>

    Server:
        Version: v1.3.2
    ```

[0]: basic-install.md#install-the-cli
[1]: https://velero.io/docs/v1.1.0/upgrade-to-1.1/
[2]: https://velero.io/docs/v1.2.0/upgrade-to-1.2/
[3]: https://github.com/velero-io/velero/releases/tag/v1.2.0
[4]: https://github.com/velero-io/velero/releases/tag/v1.3.0
[5]: https://github.com/velero-io/velero/releases/tag/v1.3.1
