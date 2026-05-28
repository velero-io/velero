---
title: "Run Velero on GCP"
layout: docs
---

You can run Kubernetes on Google Cloud Platform in either:

* Kubernetes on Google Compute Engine virtual machines
* Google Kubernetes Engine

If you do not have the `gcloud` and `gsutil` CLIs locally installed, follow the [user guide][16] to set them up.

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

## Create GCS bucket

Velero requires an object storage bucket in which to store backups, preferably unique to a single Kubernetes cluster (see the [FAQ][20] for more details). Create a GCS bucket, replacing the <YOUR_BUCKET> placeholder with the name of your bucket:

```bash
BUCKET=<YOUR_BUCKET>

gsutil mb gs://$BUCKET/
```

## Create service account

To integrate Velero with GCP, create a Velero-specific [Service Account][15]:

1. View your current config settings:

    ```bash
    gcloud config list
    ```

    Store the `project` value from the results in the environment variable `$PROJECT_ID`.

    ```bash
    PROJECT_ID=$(gcloud config get-value project)
    ```

2. Create a service account:

    ```bash
    gcloud iam service-accounts create velero \
        --display-name "Velero service account"
    ```

    > If you'll be using Velero to backup multiple clusters with multiple GCS buckets, it may be desirable to create a unique username per cluster rather than the default `velero`.

    Then list all accounts and find the `velero` account you just created:

    ```bash
    gcloud iam service-accounts list
    ```

    Set the `$SERVICE_ACCOUNT_EMAIL` variable to match its `email` value.

    ```bash
    SERVICE_ACCOUNT_EMAIL=$(gcloud iam service-accounts list \
      --filter="displayName:Velero service account" \
      --format 'value(email)')
    ```

3. Attach policies to give `velero` the necessary permissions to function:

    ```bash
    ROLE_PERMISSIONS=(
        compute.disks.get
        compute.disks.create
        compute.disks.createSnapshot
        compute.snapshots.get
        compute.snapshots.create
        compute.snapshots.useReadOnly
        compute.snapshots.delete
        compute.zones.get
    )

    gcloud iam roles create velero.server \
        --project $PROJECT_ID \
        --title "Velero Server" \
        --permissions "$(IFS=","; echo "${ROLE_PERMISSIONS[*]}")"    

    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member serviceAccount:$SERVICE_ACCOUNT_EMAIL \
        --role projects/$PROJECT_ID/roles/velero.server

    gsutil iam ch serviceAccount:$SERVICE_ACCOUNT_EMAIL:objectAdmin gs://${BUCKET}
    ```

4. Create a service account key, specifying an output file (`credentials-velero`) in your local directory:

    ```bash
    gcloud iam service-accounts keys create credentials-velero \
        --iam-account $SERVICE_ACCOUNT_EMAIL
    ```

## Credentials and configuration

If you run Google Kubernetes Engine (GKE), make sure that your current IAM user is a cluster-admin. This role is required to create RBAC objects.
See [the GKE documentation][22] for more information.


## Install and start Velero

Install Velero, including all prerequisites, into the cluster and start the deployment. This will create a namespace called `velero`, and place a deployment named `velero` in it.

```bash
velero install \
    --provider gcp \
    --bucket $BUCKET \
    --secret-file ./credentials-velero
```

Additionally, you can specify `--use-restic` to enable restic support, and `--wait` to wait for the deployment to be ready.

(Optional) Specify `--snapshot-location-config snapshotLocation=<YOUR_LOCATION>` to keep snapshots in a specific availability zone.  See the [VolumeSnapshotLocation definition][8] for details.

(Optional) Specify [additional configurable parameters][7] for the `--backup-location-config` flag.

(Optional) Specify [additional configurable parameters][8] for the `--snapshot-location-config` flag.

(Optional) Specify [CPU and memory resource requests and limits][23] for the Velero/restic pods.

For more complex installation needs, use either the Helm chart, or add `--dry-run -o yaml` options for generating the YAML representation for the installation.

[0]: namespace.md
[7]: api-types/backupstoragelocation.md#gcp
[8]: api-types/volumesnapshotlocation.md#gcp
[15]: https://cloud.google.com/compute/docs/access/service-accounts
[16]: https://cloud.google.com/sdk/docs/
[20]: faq.md
[22]: https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control#iam-rolebinding-bootstrap
[23]: install-overview.md#velero-resource-requirements
