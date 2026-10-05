---
title: "Use Oracle Cloud as a Backup Storage Provider for Velero"
layout: docs
---

## Introduction

[Velero](https://velero.io/) is a tool used to backup and migrate Kubernetes applications. Here are the steps to use [Oracle Cloud Object Storage](https://docs.cloud.oracle.com/iaas/Content/Object/Concepts/objectstorageoverview.htm) as a destination for Velero backups. 

1. [Download Velero](#download-velero)
2. [Create A Customer Secret Key](#create-a-customer-secret-key)
3. [Create An Oracle Object Storage Bucket](#create-an-oracle-object-storage-bucket)
4. [Install Velero](#install-velero)
5. [Clean Up](#clean-up)
6. [Examples](#examples)
7. [Additional Reading](#additional-reading)

## Download Velero

1. Download the [latest release](https://github.com/velero-io/velero/releases/) of Velero to your development environment. This includes the `velero` CLI utility and example Kubernetes manifest files. For example: 

    ```
    wget https://github.com/velero-io/velero/releases/download/v1.0.0/velero-v1.0.0-linux-amd64.tar.gz
    ```

    *We strongly recommend that you use an official release of Velero. The tarballs for each release contain the velero command-line client. The code in the main branch of the Velero repository is under active development and is not guaranteed to be stable!*

2. Untar the release in your `/usr/bin` directory:  `tar -xzvf <RELEASE-TARBALL-NAME>.tar.gz` 

   You may choose to rename the directory `velero` for the sake of simplicity: `mv velero-v1.0.0-linux-amd64 velero` 

3. Add it to your PATH: `export PATH=/usr/local/bin/velero:$PATH`

4. Run `velero` to confirm the CLI has been installed correctly. You should see an output like this:

```
$ velero
Velero is a tool for managing disaster recovery, specifically for Kubernetes
cluster resources. It provides a simple, configurable, and operationally robust
way to back up your application state and associated data.

If you're familiar with kubectl, Velero supports a similar model, allowing you to
execute commands such as 'velero get backup' and 'velero create schedule'. The same
operations can also be performed as 'velero backup get' and 'velero schedule create'.

Usage:
  velero [command]
```



## Create A Customer Secret Key 

1. Oracle Object Storage provides an API to enable interoperability with Amazon S3. To use this Amazon S3 Compatibility API, you need to generate the signing key required to authenticate with Amazon S3. This special signing key is an Access Key/Secret Key pair. Follow these steps to [create a Customer Secret Key](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingcredentials.htm#To4). Refer to this link for more information about [Working with Customer Secret Keys](https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingcredentials.htm#s3). 

2. Create a Velero credentials file with your Customer Secret Key:

   ```
   $ vi credentials-velero 
   
   [default]
   aws_access_key_id=bae031188893d1eb83719648790ac850b76c9441
   aws_secret_access_key=MmY9heKrWiNVCSZQ2Mf5XTJ6Ys93Bw2d2D6NMSTXZlk=
   ```



## Create An Oracle Object Storage Bucket 

Create an Oracle Cloud Object Storage bucket called `velero` in the root compartment of your Oracle Cloud tenancy. Refer to this page for [more information about creating a bucket with Object Storage](https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/managingbuckets.htm#usingconsole). 



## Install Velero 

You will need the following information to install Velero into your Kubernetes cluster with Oracle Object Storage as the Backup Storage provider: 

```
velero install \
    --provider [provider name] \
    --bucket [bucket name] \
    --prefix [tenancy name] \
    --use-volume-snapshots=false \
    --secret-file [secret file location] \
    --backup-location-config region=[region],s3ForcePathStyle="true",s3Url=[storage API endpoint]
```

- `--provider` Because we are using the S3-compatible API, we will use `aws` as our provider. 
- `--bucket` The name of the bucket created in Oracle Object Storage - in our case this is named `velero`.
- ` --prefix` The name of your Oracle Cloud tenancy - in our case this is named `oracle-cloudnative`.
- `--use-volume-snapshots=false` Velero does not currently have a volume snapshot plugin for Oracle Cloud creating volume snapshots is disabled.
- `--secret-file` The path to your `credentials-velero` file.
- `--backup-location-config` The path to your Oracle Object Storage bucket. This consists of your `region` which corresponds to your Oracle Cloud region name ([List of Oracle Cloud Regions](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm?Highlight=regions)) and the `s3Url`, the S3-compatible API endpoint for Oracle Object Storage based on your region: `https://oracle-cloudnative.compat.objectstorage.[region name].oraclecloud.com`

For example: 

```
velero install \
    --provider aws \
    --bucket velero \
    --prefix oracle-cloudnative \
    --use-volume-snapshots=false \
    --secret-file /Users/mboxell/bin/velero/credentials-velero \
    --backup-location-config region=us-phoenix-1,s3ForcePathStyle="true",s3Url=https://oracle-cloudnative.compat.objectstorage.us-phoenix-1.oraclecloud.com
```

This will create a `velero` namespace in your cluster along with a number of CRDs, a ClusterRoleBinding, ServiceAccount, Secret, and Deployment for Velero. If your pod fails to successfully provision, you can troubleshoot your installation by running: `kubectl logs [velero pod name]`. 



## Clean Up

To remove Velero from your environment, delete the namespace, ClusterRoleBinding, ServiceAccount, Secret, and Deployment and delete the CRDs, run:

```
kubectl delete namespace/velero clusterrolebinding/velero
kubectl delete crds -l component=velero
```

This will remove all resources created by `velero install`. 



## Examples

After creating the Velero server in your cluster, try this example: 

### Basic example (without PersistentVolumes)

1. Start the sample nginx app: `kubectl apply -f examples/nginx-app/base.yaml`

   This will create an `nginx-example` namespace with a `nginx-deployment` deployment, and `my-nginx` service. 

   ```
   $ kubectl apply -f examples/nginx-app/base.yaml
   namespace/nginx-example created
   deployment.apps/nginx-deployment created
   service/my-nginx created
   ```

   You can see the created resources by running `kubectl get all`

   ```
   $ kubectl get all
   NAME                                    READY   STATUS    RESTARTS   AGE
   pod/nginx-deployment-67594d6bf6-4296p   1/1     Running   0          20s
   pod/nginx-deployment-67594d6bf6-f9r5s   1/1     Running   0          20s
   
   NAME               TYPE           CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE
   service/my-nginx   LoadBalancer   10.96.69.166   <pending>     80:31859/TCP   21s
   
   NAME                               DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
   deployment.apps/nginx-deployment   2         2         2            2           21s
   
   NAME                                          DESIRED   CURRENT   READY   AGE
   replicaset.apps/nginx-deployment-67594d6bf6   2         2         2       21s
   ```

2. Create a backup: `velero backup create nginx-backup --include-namespaces nginx-example`

   ```
   $ velero backup create nginx-backup --include-namespaces nginx-example
   Backup request "nginx-backup" submitted successfully.
   Run `velero backup describe nginx-backup` or `velero backup logs nginx-backup` for more details.
   ```

   At this point you can navigate to appropriate bucket, which we called `velero`, in the Oracle Cloud Object Storage console to see the resources backed up using Velero. 

3. Simulate a disaster by deleting the `nginx-example` namespace: `kubectl delete namespaces nginx-example`

   ```
   $ kubectl delete namespaces nginx-example
   namespace "nginx-example" deleted
   ```

   Wait for the namespace to be deleted. To check that the nginx deployment, service, and namespace are gone, run:

   ```
   kubectl get deployments --namespace=nginx-example
   kubectl get services --namespace=nginx-example
   kubectl get namespace/nginx-example
   ```

   This should return: `No resources found.`

4. Restore your lost resources: `velero restore create --from-backup nginx-backup`

   ```
   $ velero restore create --from-backup nginx-backup
   Restore request "nginx-backup-20190604102710" submitted successfully.
   Run `velero restore describe nginx-backup-20190604102710` or `velero restore logs nginx-backup-20190604102710` for more details.
   ```

   Running `kubectl get namespaces` will show that the `nginx-example` namespace has been restored along with its contents. 

5. Run: `velero restore get` to view the list of restored resources. After the restore finishes, the output looks like the following:

   ```
   $ velero restore get
   NAME                          BACKUP         STATUS      WARNINGS   ERRORS   CREATED                         SELECTOR
   nginx-backup-20190604104249   nginx-backup   Completed   0          0        2019-06-04 10:42:39 -0700 PDT   <none>
   ```

   NOTE: The restore can take a few moments to finish. During this time, the `STATUS` column reads `InProgress`. 

   After a successful restore, the `STATUS` column shows `Completed`, and `WARNINGS` and `ERRORS` will show `0`. All objects in the `nginx-example` namespace should be just as they were before you deleted them.

   If there are errors or warnings, for instance if the `STATUS` column displays `FAILED` instead of `InProgress`, you can look at them in detail with `velero restore describe <RESTORE_NAME>`


6. Clean up the environment with `kubectl delete -f examples/nginx-app/base.yaml` 

   ```
   $ kubectl delete -f examples/nginx-app/base.yaml
   namespace "nginx-example" deleted
   deployment.apps "nginx-deployment" deleted
   service "my-nginx" deleted
   ```

   If you want to delete any backups you created, including data in object storage, you can run: `velero backup delete BACKUP_NAME`

   ```
   $ velero backup delete nginx-backup
   Are you sure you want to continue (Y/N)? Y
   Request to delete backup "nginx-backup" submitted successfully.
   The backup will be fully deleted after all associated data (disk snapshots, backup files, restores) are removed.
   ```

   This asks the Velero server to delete all backup data associated with `BACKUP_NAME`. You need to do this for each backup you want to permanently delete. A future version of Velero will allow you to delete multiple backups by name or label selector.

   Once fully removed, the backup is no longer visible when you run: `velero backup get BACKUP_NAME` or more generally `velero backup get`:
   
   ```
   $ velero backup get nginx-backup
   An error occurred: backups.velero.io "nginx-backup" not found
   ```

   ```
   $ velero backup get 
   NAME     STATUS      CREATED     EXPIRES     STORAGE     LOCATION        SELECTOR 
   ```



## Additional Reading 

* [Official Velero Documentation](https://velero.io/docs/v1.4/)
* [Oracle Cloud Infrastructure Documentation](https://docs.cloud.oracle.com/)
