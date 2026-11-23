---
title: "Debugging Installation Issues"
layout: docs
---

## General

### `invalid configuration: no configuration has been provided`
This typically means that no `kubeconfig` file can be found for the Velero client to use. Velero looks for a kubeconfig in the
following locations:
* the path specified by the `--kubeconfig` flag, if any
* the path specified by the `$KUBECONFIG` environment variable, if any
* `~/.kube/config`

### Backups or restores stuck in `New` phase
This means that the Velero controllers are not processing the backups/restores, which usually happens because the Velero server is not running. Check the pod description and logs for errors:
```
kubectl -n velero describe pods
kubectl -n velero logs deployment/velero
```


## AWS

### `NoCredentialProviders: no valid providers in chain`

#### Using credentials
This means that the secret containing the AWS IAM user credentials for Velero has not been created/mounted properly
into the Velero server pod. Ensure the following:

* The `cloud-credentials` secret exists in the Velero server's namespace
* The `cloud-credentials` secret has a single key, `cloud`, whose value is the contents of the `credentials-velero` file
* The `credentials-velero` file is formatted properly and has the correct values:

    ```
    [default]
    aws_access_key_id=<your AWS access key ID>
    aws_secret_access_key=<your AWS secret access key>
    ```

* The `cloud-credentials` secret is defined as a volume for the Velero deployment
* The `cloud-credentials` secret is being mounted into the Velero server pod at `/credentials`

#### Using kube2iam
This means that Velero can't read the content of the S3 bucket. Ensure the following:

* A Trust Policy document exists that allows the role used by kube2iam to assume Velero's role, as stated in the AWS config documentation.
* The new Velero role has all the permissions listed in the documentation regarding S3.


## Azure

### `Failed to refresh the Token` or `adal: Refresh request failed`
This means that the secrets containing the Azure service principal credentials for Velero has not been created/mounted
properly into the Velero server pod. Ensure the following:

* The `cloud-credentials` secret exists in the Velero server's namespace
* The `cloud-credentials` secret has all of the expected keys and each one has the correct value (see [setup instructions][0])
* The `cloud-credentials` secret is defined as a volume for the Velero deployment
* The `cloud-credentials` secret is being mounted into the Velero server pod at `/credentials`


## GCE/GKE

### `open credentials/cloud: no such file or directory`
This means that the secret containing the GCE service account credentials for Velero has not been created/mounted properly
into the Velero server pod. Ensure the following:

* The `cloud-credentials` secret exists in the Velero server's namespace
* The `cloud-credentials` secret has a single key, `cloud`, whose value is the contents of the `credentials-velero` file
* The `cloud-credentials` secret is defined as a volume for the Velero deployment
* The `cloud-credentials` secret is being mounted into the Velero server pod at `/credentials`

[0]: azure-config.md#create-service-principal
