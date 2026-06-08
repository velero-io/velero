---
title: "Upgrading to Velero 1.4"
layout: docs
---

## Prerequisites

- Velero [v1.4.2][8], [v1.4.0][7] or [v1.3.x][4] installed.

Note: The v1.4.1 tag was created in code, but has no associated docker image due to misconfigured building infrastructure. v1.4.2 fixed this.

If you're not yet running at least Velero v1.3, see the following:

- [Upgrading to v1.1][1]
- [Upgrading to v1.2][2]
- [Upgrading to v1.3][3]

Before upgrading, check the [Velero compatibility matrix](https://github.com/velero-io/velero#velero-compatibility-matrix) to make sure your version of Kubernetes is supported by the new version of Velero.

## Instructions

1. Install the Velero v1.4 command-line interface (CLI) by following the [instructions here][0].

    Verify that you've properly installed it by running:

    ```bash
    velero version --client-only
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.4.3
        Git commit: <git SHA>
    ```

1. Update the container image used by the Velero deployment and, optionally, the restic daemon set:

    ```bash
    kubectl set image deployment/velero \
        velero=velero/velero:v1.4.3 \
        --namespace velero

    # optional, if using the restic daemon set
    kubectl set image daemonset/restic \
        restic=velero/velero:v1.4.3 \
        --namespace velero
    ```

1. Update the Velero custom resource definitions (CRDs) to include the new backup progress fields:

    ```bash
    velero install --crds-only --dry-run -o yaml | kubectl apply -f -
    ```

    **NOTE:** If you are upgrading Velero in Kubernetes 1.14.x or earlier, you will need to use `kubectl apply`'s `--validate=false` option when applying the CRD configuration above. See [issue 2077][5] and [issue 2311][6] for more context.

1. Confirm that the deployment is up and running with the correct version by running:

    ```bash
    velero version
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.4.3
        Git commit: <git SHA>

    Server:
        Version: v1.4.3
    ```

[0]: basic-install.md#install-the-cli
[1]: https://velero.io/docs/v1.1.0/upgrade-to-1.1/
[2]: https://velero.io/docs/v1.2.0/upgrade-to-1.2/
[3]: https://velero.io/docs/v1.3.2/upgrade-to-1.3/
[4]: https://github.com/velero-io/velero/releases/tag/v1.3.2
[5]: https://github.com/velero-io/velero/issues/2077
[6]: https://github.com/velero-io/velero/issues/2311
[7]: https://github.com/velero-io/velero/releases/tag/v1.4.0
[8]: https://github.com/velero-io/velero/releases/tag/v1.4.2
