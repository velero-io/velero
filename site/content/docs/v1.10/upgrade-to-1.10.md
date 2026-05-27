---
title: "Upgrading to Velero 1.10"
layout: docs
---

## Prerequisites

- Velero [v1.9.x][5] installed.

If you're not yet running at least Velero v1.6, see the following:

- [Upgrading to v1.5][1]
- [Upgrading to v1.6][2]
- [Upgrading to v1.7][3]
- [Upgrading to v1.8][4]
- [Upgrading to v1.9][5]

Before upgrading, check the [Velero compatibility matrix](https://github.com/velero-io/velero#velero-compatibility-matrix) to make sure your version of Kubernetes is supported by the new version of Velero.

## Instructions

**Caution:** From Velero v1.10, except for using restic to do file-system level backup and restore, kopia is also been integrated, so there would be a little bit of difference when upgrading to v1.10 from a version lower than v1.10.0.

1. Install the Velero v1.10 command-line interface (CLI) by following the [instructions here][0].

    Verify that you've properly installed it by running:

    ```bash
    velero version --client-only
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.10.0
        Git commit: <git SHA>
    ```

1. Update the Velero custom resource definitions (CRDs) to include schema changes across all CRDs that are at the core of the new features in this release:

    ```bash
    velero install --crds-only --dry-run -o yaml | kubectl apply -f -
    ```

    **NOTE:** Since velero v1.10.0 only v1 CRD will be supported during installation, therefore, the v1.10.0 will only work on kubernetes version >= v1.16

1. Update the container image and objects fields used by the Velero deployment and, optionally, the restic daemon set:

    ```bash
    # uploader_type value could be restic or kopia
    kubectl get deploy -n velero -ojson \
    | sed "s#\"image\"\: \"velero\/velero\:v[0-9]*.[0-9]*.[0-9]\"#\"image\"\: \"velero\/velero\:v1.10.0\"#g" \
    | sed "s#\"server\",#\"server\",\"--uploader-type=$uploader_type\",#g" \
    | sed "s#default-volumes-to-restic#default-volumes-to-fs-backup#g" \
    | sed "s#default-restic-prune-frequency#default-repo-maintain-frequency#g" \
    | sed "s#restic-timeout#fs-backup-timeout#g" \
    | kubectl apply -f -

    # optional, if using the restic daemon set
    echo $(kubectl get ds -n velero restic -ojson) \
    | sed "s#\"image\"\: \"velero\/velero\:v[0-9]*.[0-9]*.[0-9]\"#\"image\"\: \"velero\/velero\:v1.10.0\"#g" \
    | sed "s#\"name\"\: \"restic\"#\"name\"\: \"node-agent\"#g" \
    | sed "s#\[ \"restic\",#\[ \"node-agent\",#g" \
    | kubectl apply -f -
    kubectl delete ds -n velero restic --force --grace-period 0
    ```

1. Confirm that the deployment is up and running with the correct version by running:

    ```bash
    velero version
    ```

    You should see the following output:

    ```bash
    Client:
        Version: v1.10.0
        Git commit: <git SHA>

    Server:
        Version: v1.10.0
    ```
## Notes
If upgraded from v1.9.x, there still remains some resources left over in the cluster and never used in v1.10.x, which could be deleted through kubectl and it is based on your desire:

    - resticrepository CRD and related CRs
    - velero-restic-credentials secret in velero install namespace


[0]: basic-install.md#install-the-cli
[1]: https://velero.io/docs/v1.5/upgrade-to-1.5
[2]: https://velero.io/docs/v1.6/upgrade-to-1.6
[3]: https://velero.io/docs/v1.7/upgrade-to-1.7
[4]: https://velero.io/docs/v1.8/upgrade-to-1.8
[5]: https://velero.io/docs/v1.9/upgrade-to-1.9
