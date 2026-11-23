---
title: "Run Velero locally in development"
layout: docs
---

Running the Velero server locally can speed up iterative development. This eliminates the need to rebuild the Velero server
image and redeploy it to the cluster with each change.

## Run Velero locally with a remote cluster

Velero runs against the Kubernetes API server as the endpoint (as per the `kubeconfig` configuration), so both the Velero server and client use the same `client-go` to communicate with Kubernetes. This means the Velero server can be run locally just as functionally as if it was running in the remote cluster.

### Prerequisites

When running Velero, you will need to ensure that you set up all of the following:

* Appropriate RBAC permissions in the cluster
  * Read access for all data from the source cluster and namespaces
  * Write access to the target cluster and namespaces
* Cloud provider credentials
  * Read/write access to volumes
  * Read/write access to object storage for backup data
* A [BackupStorageLocation][20] object definition for the Velero server
* (Optional) A [VolumeSnapshotLocation][21] object definition for the Velero server, to take PV snapshots

### 1. Install Velero

See documentation on how to install Velero in some specific providers: [Install overview][22]

### 2. Scale deployment down to zero

After you use the `velero install` command to install Velero into your cluster, you scale the Velero deployment down to 0 so it is not simultaneously being run on the remote cluster and potentially causing things to get out of sync:

`kubectl scale --replicas=0 deployment velero -n velero`

#### 3. Start the Velero server locally

* To run the server locally, use the full path according to the binary you need. Example, if you are on a Mac, and using `AWS` as a provider, this is how to run the binary you built from source using the full path: `AWS_SHARED_CREDENTIALS_FILE=<path-to-credentials-file> ./_output/bin/darwin/amd64/velero`. Alternatively, you may add the `velero` binary to your `PATH`.

* Start the server: `velero server [CLI flags]`. The following CLI flags may be useful to customize, but see `velero server --help` for full details:
  * `--log-level`: set the Velero server's log level (default `info`, use `debug` for the most logging)
  * `--kubeconfig`: set the path to the kubeconfig file the Velero server uses to talk to the Kubernetes apiserver (default `$KUBECONFIG`)
  * `--namespace`: the set namespace where the Velero server should look for backups, schedules, restores (default `velero`)
  * `--plugin-dir`: set the directory where the Velero server looks for plugins (default `/plugins`)
    * The `--plugin-dir` flag requires the plugin binary to be present locally, and should be set to the directory containing this built binary.
  * `--metrics-address`: set the bind address and port where Prometheus metrics are exposed (default `:8085`)

[15]: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#the-shared-credentials-file
[16]: https://cloud.google.com/docs/authentication/getting-started#setting_the_environment_variable
[18]: https://eksctl.io/
[20]: api-types/backupstoragelocation.md
[21]: api-types/volumesnapshotlocation.md
[22]: basic-install.md
