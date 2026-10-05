---
title: "Upgrading to Velero 1.17"
layout: docs
---

## Prerequisites

- Velero [v1.16.x][9] installed.

If you're not yet running at least Velero v1.16, see the following:

- [Upgrading to v1.8][1]
- [Upgrading to v1.9][2]
- [Upgrading to v1.10][3]
- [Upgrading to v1.11][4]
- [Upgrading to v1.12][5]
- [Upgrading to v1.13][6]
- [Upgrading to v1.14][7]
- [Upgrading to v1.15][8]
- [Upgrading to v1.16][9]

Before upgrading, check the [Velero compatibility matrix](https://github.com/velero-io/velero#velero-compatibility-matrix) to make sure your version of Kubernetes is supported by the new version of Velero.

## Instructions

### Upgrade from v1.16
1. Install the Velero v1.17 command-line interface (CLI) by following the [instructions here][0].

    Verify that you've properly installed it by running:

    ```bash
    velero version --client-only
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.17.0
        Git commit: <git SHA>
    ```

2. Update the Velero custom resource definitions (CRDs) to include schema changes across all CRDs that are at the core of the new features in this release:

    ```bash
    velero install --crds-only --dry-run -o yaml | kubectl apply -f -
    ```

3. (optional) Update the `uploader-type` to `kopia` if you are using `restic`:  
    ```bash
    kubectl get deploy -n velero -ojson \
    | sed "s/\"--uploader-type=restic\"/\"--uploader-type=kopia\"/g" \
    | kubectl apply -f -
    ```

4. Update the container image used by the Velero deployment, plugin and (optionally) the node agent daemon set:
    ```bash
   # set the container and image of the init container for plugin accordingly,
   # if you are using other plugin
    kubectl set image deployment/velero \
        velero=velero/velero:v1.17.0 \
        velero-plugin-for-aws=velero/velero-plugin-for-aws:v1.13.0 \
        --namespace velero

    # optional, if using the node agent daemonset
    kubectl set image daemonset/node-agent \
        node-agent=velero/velero:v1.17.0 \
        --namespace velero
    ```
5. Confirm that the deployment is up and running with the correct version by running:

    ```bash
    velero version
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.17.0
        Git commit: <git SHA>

    Server:
        Version: v1.17.0
    ```

[0]: basic-install.md#install-the-cli
[1]: https://velero.io/docs/v1.8/upgrade-to-1.8
[2]: https://velero.io/docs/v1.9/upgrade-to-1.9
[3]: https://velero.io/docs/v1.10/upgrade-to-1.10
[4]: https://velero.io/docs/v1.11/upgrade-to-1.11
[5]: https://velero.io/docs/v1.12/upgrade-to-1.12
[6]: https://velero.io/docs/v1.13/upgrade-to-1.13
[7]: https://velero.io/docs/v1.14/upgrade-to-1.14
[8]: https://velero.io/docs/v1.15/upgrade-to-1.15
[9]: https://velero.io/docs/v1.16/upgrade-to-1.16