---
title: "Quick start evaluation install with Minio"
layout: docs
---

The following example sets up the Velero server and client, then backs up and restores a sample application.

For simplicity, the example uses Minio, an S3-compatible storage service that runs locally on your cluster.
For additional functionality with this setup, see the section below on how to [expose Minio outside your cluster][1].

**NOTE** The example lets you explore basic Velero functionality. Configuring Minio for production is out of scope.

See [Set up Velero on your platform][3] for how to configure Velero for a production environment.

If you encounter issues with installing or configuring, see [Debugging Installation Issues](debugging-install.md).

## Prerequisites

* Access to a Kubernetes cluster, version 1.7 or later.  **Note:** File System Backup support requires Kubernetes version 1.10 or later, or an earlier version with the mount propagation feature enabled. File System Backup support is not required for this example, but may be of interest later. See [File System Backup][17].
* A DNS server on the cluster
* `kubectl` installed
* Sufficient disk space to store backups in Minio.  You will need sufficient disk space available to handle any
backups plus at least 1GB additional.  Minio will not operate if less than 1GB of free disk space is available.

## Install the CLI

### Option 1: MacOS - Homebrew

On macOS, you can use [Homebrew](https://brew.sh) to install the `velero` client:

```bash
brew install velero
```

### Option 2: GitHub release

1. Download the [latest official release's](https://github.com/vmware-tanzu/velero/releases) tarball for your client platform.

    _We strongly recommend that you use an [official release](https://github.com/vmware-tanzu/velero/releases) of
Velero. The tarballs for each release contain the `velero` command-line client. The code in the main branch
of the Velero repository is under active development and is not guaranteed to be stable!_

1. Extract the tarball:

    ```bash
    tar -xvf <RELEASE-TARBALL-NAME>.tar.gz -C /dir/to/extract/to
    ```

    The directory you extracted is called the "Velero directory" in subsequent steps.

1. Move the `velero` binary from the Velero directory to somewhere in your PATH.

## Set up server

These instructions start the Velero server and a Minio instance that is accessible from within the cluster only. See [Expose Minio outside your cluster](#expose-minio-outside-your-cluster-with-a-service) for information about configuring your cluster for outside access to Minio. Outside access is required to access logs and run `velero describe` commands.

1. Create a Velero-specific credentials file (`credentials-velero`) in your Velero directory:

    ```
    [default]
    aws_access_key_id = minio
    aws_secret_access_key = minio123
    ```

1. Start the server and the local storage service. In the Velero directory, run:

    ```
    kubectl apply -f examples/minio/00-minio-deployment.yaml
    ```
    _Note_: The example Minio yaml provided uses "empty dir".  Your node needs to have enough space available to store the
    data being backed up plus 1GB of free space.  If the node does not have enough space, you can modify the example yaml to
    use a Persistent Volume instead of "empty dir"

    ```
    velero install \
        --provider aws \
        --plugins velero/velero-plugin-for-aws:v1.13.2 \
        --bucket velero \
        --secret-file ./credentials-velero \
        --use-volume-snapshots=false \
        --backup-location-config region=minio,s3ForcePathStyle="true",s3Url=http://minio.velero.svc:9000
    ```

    * This example assumes that it is running within a local cluster without a volume provider capable of snapshots, so no `VolumeSnapshotLocation` is created (`--use-volume-snapshots=false`). You may need to update AWS plugin version to one that is [compatible](https://github.com/vmware-tanzu/velero-plugin-for-aws#compatibility) with the version of Velero you are installing.

    * Additionally, you can specify `--use-node-agent` to enable File System Backup support, and `--wait` to wait for the deployment to be ready.

    * This example also assumes you have named your Minio bucket "velero".

    * Please make sure to set parameter `s3ForcePathStyle=true`. The parameter is used to set the Velero integrated AWS SDK data query address style. There are two types of the address: [virtual-host and path-style](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html). If the `s3ForcePathStyle=true` is not set, the default value is false, then the AWS SDK will query in virtual-host style, but the MinIO server only support path-style address by default. The miss match will mean Velero can upload data to MinIO, but **cannot download from MinIO**. This [link](https://github.com/vmware-tanzu/velero/issues/7268) is an example of this issue.
    It can be resolved by two ways:
      * Set `s3ForcePathStyle=true` for parameter `--backup-location-config` when installing Velero. This is the preferred way.
      * Make MinIO server support virtual-host style address. Add the [MINIO_DOMAIN environment variable](https://min.io/docs/minio/linux/reference/minio-server/settings/core.html#id5) for MinIO server will do the magic.


1. Deploy the example nginx application:

    ```bash
    kubectl apply -f examples/nginx-app/base.yaml
    ```

1. Check to see that both the Velero and nginx deployments are successfully created:

    ```
    kubectl get deployments -l component=velero --namespace=velero
    kubectl get deployments --namespace=nginx-example
    ```

## Back up

1. Create a backup for any object that matches the `app=nginx` label selector:

    ```
    velero backup create nginx-backup --selector app=nginx
    ```

    Alternatively if you want to backup all objects *except* those matching the label `backup=ignore`:

    ```
    velero backup create nginx-backup --selector 'backup notin (ignore)'
    ```

1. (Optional) Create regularly scheduled backups based on a cron expression using the `app=nginx` label selector:

    ```
    velero schedule create nginx-daily --schedule="0 1 * * *" --selector app=nginx
    ```

    Alternatively, you can use some non-standard shorthand cron expressions:

    ```
    velero schedule create nginx-daily --schedule="@daily" --selector app=nginx
    ```

    See the [cron package's documentation][30] for more usage examples.

1. Simulate a disaster:

    ```
    kubectl delete namespace nginx-example
    ```

1. To check that the nginx deployment and service are gone, run:

    ```
    kubectl get deployments --namespace=nginx-example
    kubectl get services --namespace=nginx-example
    kubectl get namespace/nginx-example
    ```

    You should get no results.

    NOTE: You might need to wait for a few minutes for the namespace to be fully cleaned up.

## Restore

1. Run:

    ```
    velero restore create --from-backup nginx-backup
    ```

1. Run:

    ```
    velero restore get
    ```

    After the restore finishes, the output looks like the following:

    ```
    NAME                          BACKUP         STATUS      WARNINGS   ERRORS    CREATED                         SELECTOR
    nginx-backup-20170727200524   nginx-backup   Completed   0          0         2017-07-27 20:05:24 +0000 UTC   <none>
    ```

NOTE: The restore can take a few moments to finish. During this time, the `STATUS` column reads `InProgress`.

After a successful restore, the `STATUS` column is `Completed`, and `WARNINGS` and `ERRORS` are 0. All objects in the `nginx-example` namespace should be just as they were before you deleted them.

If there are errors or warnings, you can look at them in detail:

```
velero restore describe <RESTORE_NAME>
```

For more information, see [the debugging information][18].

## Clean up

If you want to delete any backups you created, including data in object storage and persistent
volume snapshots, you can run:

```
velero backup delete BACKUP_NAME
```

This asks the Velero server to delete all backup data associated with `BACKUP_NAME`.  You need to do
this for each backup you want to permanently delete. A future version of Velero will allow you to
delete multiple backups by name or label selector.

Once fully removed, the backup is no longer visible when you run:

```
velero backup get BACKUP_NAME
```

To completely uninstall Velero, minio, and the nginx example app from your Kubernetes cluster:

```
kubectl delete namespace/velero clusterrolebinding/velero
kubectl delete crds -l component=velero
kubectl delete -f examples/nginx-app/base.yaml
```

## Expose Minio outside your cluster with a Service

When you run commands to get logs or describe a backup, the Velero server generates a pre-signed URL to download the requested items. To access these URLs from outside the cluster -- that is, from your Velero client -- you need to make Minio available outside the cluster. You can:

- Change the Minio Service type from `ClusterIP` to `NodePort`.
- Set up Ingress for your cluster, keeping Minio Service type `ClusterIP`.

You can also specify a `publicUrl` config field for the pre-signed URL in your backup storage location config.

### Expose Minio with Service of type NodePort

The Minio deployment by default specifies a Service of type `ClusterIP`. You can change this to `NodePort` to easily expose a cluster service externally if you can reach the node from your Velero client.

You must also get the Minio URL, which you can then specify as the value of the `publicUrl` field in your backup storage location config.

1.  In `examples/minio/00-minio-deployment.yaml`, change the value of Service `spec.type` from `ClusterIP` to `NodePort`.

1.  Get the Minio URL:

  - if you're running Minikube:

      ```shell
      minikube service minio --namespace=velero --url
      ```

  - in any other environment:
    1.  Get the value of an external IP address or DNS name of any node in your cluster. You must be able to reach this address from the Velero client.
    1.  Append the value of the NodePort to get a complete URL. You can get this value by running:

        ```shell
        kubectl -n velero get svc/minio -o jsonpath='{.spec.ports[0].nodePort}'
        ```

1.  Edit your `BackupStorageLocation` YAML, adding `publicUrl: <URL_FROM_PREVIOUS_STEP>` as a field under `spec.config`. You must include the `http://` or `https://` prefix.

## Accessing logs with an HTTPS endpoint

If you're using Minio with HTTPS, you may see unintelligible text in the output of `velero describe`, or `velero logs` commands.

To fix this, you can add a public URL to the `BackupStorageLocation`.

In a terminal, run the following:

```shell
kubectl patch -n velero backupstoragelocation default --type merge -p '{"spec":{"config":{"publicUrl":"https://<a public IP for your Minio instance>:9000"}}}'
```

If your certificate is self-signed, see the [documentation on self-signed certificates][32].

## Expose Minio outside your cluster with Kubernetes in Docker (KinD):

Kubernetes in Docker does not have support for NodePort services (see [this issue](https://github.com/kubernetes-sigs/kind/issues/99)). In this case, you can use a port forward to access the Minio bucket.

In a terminal, run the following:

```shell
MINIO_POD=$(kubectl get pods -n velero -l component=minio -o jsonpath='{.items[0].metadata.name}')

kubectl port-forward $MINIO_POD -n velero 9000:9000
```

Then, in another terminal:

```shell
kubectl edit backupstoragelocation default -n velero
```

Add `publicUrl: http://localhost:9000` under the `spec.config` section.


### Work with Ingress

Configuring Ingress for your cluster is out of scope for the Velero documentation. If you have already set up Ingress, however, it makes sense to continue with it while you run the example Velero configuration with Minio.

In this case:

1.  Keep the Service type as `ClusterIP`.

1.  Edit your `BackupStorageLocation` YAML, adding `publicUrl: <URL_AND_PORT_OF_INGRESS>` as a field under `spec.config`.

[1]: #expose-minio-with-service-of-type-nodeport
[3]: ../customize-installation.md
[17]: ../file-system-backup.md
[18]: ../debugging-restores.md
[26]: https://github.com/vmware-tanzu/velero/releases
[30]: https://godoc.org/github.com/robfig/cron
[32]: ../self-signed-certificates.md
