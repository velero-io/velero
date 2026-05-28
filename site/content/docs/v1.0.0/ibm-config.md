---
title: "Use IBM Cloud Object Storage as Velero's storage destination."
layout: docs
---
You can deploy Velero on IBM [Public][5] or [Private][4] clouds, or even on any other Kubernetes cluster, but anyway you can use IBM Cloud Object Store as a destination for Velero's backups.

To set up IBM Cloud Object Storage (COS) as Velero's destination, you:

* Download an official release of Velero
* Create your COS instance
* Create an S3 bucket
* Define a service that can store data in the bucket
* Configure and start the Velero server

## Download Velero

1. Download the [latest official release's](https://github.com/velero-io/velero/releases) tarball for your client platform.

    _We strongly recommend that you use an [official release](https://github.com/velero-io/velero/releases) of
Velero. The tarballs for each release contain the `velero` command-line client. The code in the main branch
of the Velero repository is under active development and is not guaranteed to be stable!_

1. Extract the tarball:

    ```bash
    tar -xvf <RELEASE-TARBALL-NAME>.tar.gz -C /dir/to/extract/to
    ```

    We'll refer to the directory you extracted to as the "Velero directory" in subsequent steps.

1. Move the `velero` binary from the Velero directory to somewhere in your PATH.

## Create COS instance
If you don’t have a COS instance, you can create a new one, according to the detailed instructions in [Creating a new resource instance][1].

## Create an S3 bucket
Velero requires an object storage bucket to store backups in. See instructions in [Create some buckets to store your data][2].

## Define a service that can store data in the bucket.
The process of creating service credentials is described in [Service credentials][3].
Several comments:

1. The Velero service will write its backup into the bucket, so it requires the “Writer” access role.

2. Velero uses an AWS S3 compatible API. Which means it authenticates using a signature created from a pair of access and secret keys — a set of HMAC credentials. You can create these HMAC credentials by specifying `{“HMAC”:true}` as an optional inline parameter. See step 3 in the [Service credentials][3] guide.

3. After successfully creating a Service credential, you can view the JSON definition of the credential. Under the `cos_hmac_keys` entry there are `access_key_id` and `secret_access_key`. We will use them in the next step.

4. Create a Velero-specific credentials file (`credentials-velero`) in your local directory:

    ```
    [default]
    aws_access_key_id=<ACCESS_KEY_ID>
    aws_secret_access_key=<SECRET_ACCESS_KEY>
    ```

    where the access key id and secret are the values that we got above.

## Install and start Velero

Install Velero, including all prerequisites, into the cluster and start the deployment. This will create a namespace called `velero`, and place a deployment named `velero` in it.

```bash
velero install \
    --provider aws \
    --bucket <YOUR_BUCKET> \
    --secret-file ./credentials-velero \
    --use-volume-snapshots=false \
    --backup-location-config region=<YOUR_REGION>,s3ForcePathStyle="true",s3Url=<YOUR_URL_ACCESS_POINT>
```

Velero does not currently have a volume snapshot plugin for IBM Cloud, so creating volume snapshots is disabled.

Additionally, you can specify `--use-restic` to enable restic support, and `--wait` to wait for the deployment to be ready.

Once the installation is complete, remove the default `VolumeSnapshotLocation` that was created by `velero install`, since it's specific to AWS and won't work for IBM Cloud:

```bash
kubectl -n velero delete volumesnapshotlocation.velero.io default
```

For more complex installation needs, use either the Helm chart, or add `--dry-run -o yaml` options for generating the YAML representation for the installation.

## Installing the nginx example (optional)

If you run the nginx example, in file `examples/nginx-app/with-pv.yaml`:

Uncomment `storageClassName: <YOUR_STORAGE_CLASS_NAME>` and replace with your `StorageClass` name.


[0]: namespace.md
[1]: https://console.bluemix.net/docs/services/cloud-object-storage/basics/order-storage.html#creating-a-new-resource-instance
[2]: https://console.bluemix.net/docs/services/cloud-object-storage/getting-started.html#create-buckets
[3]: https://console.bluemix.net/docs/services/cloud-object-storage/iam/service-credentials.html#service-credentials
[4]: https://www.ibm.com/support/knowledgecenter/SSBS6K_2.1.0/kc_welcome_containers.html
[5]: https://console.bluemix.net/docs/containers/container_index.html#container_index
[6]: api-types/backupstoragelocation.md#aws
[14]: http://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html
