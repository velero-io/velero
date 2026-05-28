---
title: "Upgrading to Velero 1.9"
layout: docs
---

## Prerequisites

- Velero [v1.8.x][8] installed.

If you're not yet running at least Velero v1.6, see the following:

- [Upgrading to v1.1][1]
- [Upgrading to v1.2][2]
- [Upgrading to v1.3][3]
- [Upgrading to v1.4][4]
- [Upgrading to v1.5][5]
- [Upgrading to v1.6][6]
- [Upgrading to v1.7][7]
- [Upgrading to v1.8][8]

Before upgrading, check the [Velero compatibility matrix](https://github.com/velero-io/velero#velero-compatibility-matrix) to make sure your version of Kubernetes is supported by the new version of Velero.

## Instructions

1. Install the Velero v1.9 command-line interface (CLI) by following the [instructions here][0].

    Verify that you've properly installed it by running:

    ```bash
    velero version --client-only
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.9.0
        Git commit: <git SHA>
    ```

1. Update the Velero custom resource definitions (CRDs) to include schema changes across all CRDs that are at the core of the new features in this release:

    ```bash
    velero install --crds-only --dry-run -o yaml | kubectl apply -f -
    ```

    **NOTE:** Since velero v1.9.0 only v1 CRD will be supported during installation, therefore, the v1.9.0 will only work on kubernetes version >= v1.16

1. Update the container image used by the Velero deployment and, optionally, the restic daemon set:

    ```bash
    kubectl set image deployment/velero \
        velero=velero/velero:v1.9.0 \
        --namespace velero

    # optional, if using the restic daemon set
    kubectl set image daemonset/restic \
        restic=velero/velero:v1.9.0 \
        --namespace velero
    ```

1. Confirm that the deployment is up and running with the correct version by running:

    ```bash
    velero version
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.9.0
        Git commit: <git SHA>

    Server:
        Version: v1.9.0
    ```

## Notes
### Default backup storage location
We have deprecated the way to indicate the default backup storage location. Previously, that was indicated according to the backup storage location name set on the velero server-side via the flag `velero server --default-backup-storage-location`. Now we configure the default backup storage location on the velero client-side. Please refer to the [About locations][9] on how to indicate which backup storage location is the default one.

After upgrading, if there is a previously created backup storage location with the name that matches what was defined on the server side as the default, it will be automatically set as the `default`.

[0]: basic-install.md#install-the-cli
[1]: https://velero.io/docs/v1.1.0/upgrade-to-1.1/
[2]: https://velero.io/docs/v1.2.0/upgrade-to-1.2/
[3]: https://velero.io/docs/v1.3.2/upgrade-to-1.3/
[4]: https://velero.io/docs/v1.4/upgrade-to-1.4/
[5]: https://velero.io/docs/v1.5/upgrade-to-1.5
[6]: https://velero.io/docs/v1.6/upgrade-to-1.6
[7]: https://velero.io/docs/v1.7/upgrade-to-1.7
[8]: https://velero.io/docs/v1.8/upgrade-to-1.8
[9]: https://velero.io/docs/v1.9/locations
