---
title: "Troubleshooting"
layout: docs
---

These tips can help you troubleshoot known issues. If they don't help, you can [file an issue][4], or talk to us on the [#velero channel][25] on the Kubernetes Slack server.

## Debug installation/ setup issues

- [Debug installation/setup issues][2]

## Debug restores

- [Debug restores][1]

## General troubleshooting information

You can use the `velero bug` command to open a [Github issue][4] by launching a browser window with some prepopulated values. Values included are OS, CPU architecture, `kubectl` client and server versions (if available) and the `velero` client version. This information isn't submitted to Github until you click the `Submit new issue` button in the Github UI, so feel free to add, remove or update whatever information you like.

Some general commands for troubleshooting that may be helpful:

* `velero backup describe <backupName>` - describe the details of a backup
* `velero backup logs <backupName>` - fetch the logs for this specific backup. Useful for viewing failures and warnings, including resources that could not be backed up.
* `velero restore describe <restoreName>` - describe the details of a restore
* `velero restore logs <restoreName>` - fetch the logs for this specific restore. Useful for viewing failures and warnings, including resources that could not be restored.
* `kubectl logs deployment/velero -n velero` - fetch the logs of the Velero server pod. This provides the output of the Velero server processes.

### Getting velero debug logs

You can increase the verbosity of the Velero server by editing your Velero deployment to look like this:


```
kubectl edit deployment/velero -n velero
...
   containers:
     - name: velero
       image: velero/velero:latest
       command:
         - /velero
       args:
         - server
         - --log-level # Add this line
         - debug       # Add this line
...
```

## Known issue with restoring LoadBalancer Service

Because of how Kubernetes handles Service objects of `type=LoadBalancer`, when you restore these objects you might encounter an issue with changed values for Service UIDs. Kubernetes automatically generates the name of the cloud resource based on the Service UID, which is different when restored, resulting in a different name for the cloud load balancer. If the DNS CNAME for your application points to the DNS name of your cloud load balancer, you'll need to update the CNAME pointer when you perform a Velero restore.

Alternatively, you might be able to use the Service's `spec.loadBalancerIP` field to keep connections valid, if your cloud provider supports this value. See [the Kubernetes documentation about Services of Type LoadBalancer](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer).

## Miscellaneous issues

### Velero reports `custom resource not found` errors when starting up.

Velero's server will not start if the required Custom Resource Definitions are not found in Kubernetes. Run `velero install` again to install any missing custom resource definitions.

### `velero backup logs` returns a `SignatureDoesNotMatch` error

Downloading artifacts from object storage utilizes temporary, signed URLs. In the case of S3-compatible
providers, such as Ceph, there may be differences between their implementation and the official S3
API that cause errors.

Here are some things to verify if you receive `SignatureDoesNotMatch` errors:

  * Make sure your S3-compatible layer is using [signature version 4][5] (such as Ceph RADOS v12.2.7)
  * For Ceph, try using a native Ceph account for credentials instead of external providers such as OpenStack Keystone

## Velero (or a pod it was backing up) restarted during a backup and the backup is stuck InProgress

Velero cannot resume backups that were interrupted. Backups stuck in the `InProgress` phase can be deleted with `kubectl delete backup <name> -n <velero-namespace>`.
Backups in the `InProgress` phase have not uploaded any files to object storage.

## Velero is not publishing prometheus metrics

Steps to troubleshoot:

- Confirm that your velero deployment has metrics publishing enabled. The [latest Velero helm charts][6] have been setup with [metrics enabled by default][7].
- Confirm that the Velero server pod exposes the port on which the metrics server listens on. By default, this value is 8085.

```yaml
          ports:
          - containerPort: 8085
            name: metrics
            protocol: TCP
```

- Confirm that the metric server is listening for and responding to connections on this port. This can be done using [port-forwarding][9] as shown below

```bash
$ kubectl -n <YOUR_VELERO_NAMESPACE> port-forward <YOUR_VELERO_POD> 8085:8085
Forwarding from 127.0.0.1:8085 -> 8085
Forwarding from [::1]:8085 -> 8085
.
.
.
```

Now, visiting http://localhost:8085/metrics on a browser should show the metrics that are being scraped from Velero.

- Confirm that the Velero server pod has the necessary [annotations][8] for prometheus to scrape metrics.
- Confirm, from the Prometheus UI, that the Velero pod is one of the targets being scraped from Prometheus.


## Is Velero using the correct cloud credentials?

Cloud provider credentials are given to Velero to store and retrieve backups from the object store and to perform volume snapshotting operations.

These credentials are either passed to Velero at install time using:
1. `--secret-file` flag to the `velero install` command.  OR
1. `--set-file credentials.secretContents.cloud` flag to the `helm install` command.

Or, they are specified when creating a `BackupStorageLocation` using the `--credential` flag.

### Troubleshooting credentials provided during install

If using the credentials provided at install time, they are stored in the cluster as a Kubernetes secret named `cloud-credentials` in the same namespace in which Velero is installed.

Follow the below troubleshooting steps to confirm that Velero is using the correct credentials:
1. Confirm that the `cloud-credentials` secret exists and has the correct content.
    ```bash
    $ kubectl -n velero get secrets cloud-credentials
    NAME                TYPE     DATA   AGE
    cloud-credentials   Opaque   1      11h
    $ kubectl -n velero get secrets cloud-credentials -ojsonpath={.data.cloud} | base64 --decode
    <Output should be your credentials>
    ```

1. Confirm that velero deployment is mounting the `cloud-credentials` secret.
    ```bash
    $ kubectl -n velero get deploy velero -ojson | jq .spec.template.spec.containers[0].volumeMounts
      [
      {
          "mountPath": "/plugins",
          "name": "plugins"
      },
      {
          "mountPath": "/scratch",
          "name": "scratch"
      },
      {
          "mountPath": "/credentials",
          "name": "cloud-credentials"
      }
      ]
    ```

    If [restic-integration][3] is enabled, then, confirm that the restic daemonset is also mounting the `cloud-credentials` secret.
    ```bash
    $ kubectl -n velero get ds restic -ojson |jq .spec.template.spec.containers[0].volumeMounts
    [
      {
        "mountPath": "/host_pods",
        "mountPropagation": "HostToContainer",
        "name": "host-pods"
      },
      {
        "mountPath": "/scratch",
        "name": "scratch"
      },
      {
        "mountPath": "/credentials",
        "name": "cloud-credentials"
      }
    ]
    ```

1. Confirm if the correct credentials are mounted into the Velero pod.
    ```bash
    $ kubectl -n velero exec -ti deploy/velero -- bash
    nobody@velero-69f9c874c-l8mqp:/$ cat /credentials/cloud
    <Output should be your credentials>
    ```

### Troubleshooting `BackupStorageLocation` credentials

Follow the below troubleshooting steps to confirm that Velero is using the correct credentials if using credentials specific to a [`BackupStorageLocation`][10]:
1. Confirm that the object storage provider plugin being used supports multiple credentials.

   If the logs from the Velero deployment contain the error message `"config has invalid keys credentialsFile"`, the version of your object storage plugin does not yet support multiple credentials.

   The object storage plugins [maintained by the Velero team][11] support this feature, so please update your plugin to the latest version if you see the above error message.

   If you are using a plugin from a different provider, please contact them for further advice.

1. Confirm that the secret and key referenced by the `BackupStorageLocation` exists in the Velero namespace and has the correct content:
   ```bash
   # Determine which secret and key the BackupStorageLocation is using
   BSL_SECRET=$(kubectl get backupstoragelocations.velero.io -n velero <bsl-name> -o yaml -o jsonpath={.spec.credential.name})
   BSL_SECRET_KEY=$(kubectl get backupstoragelocations.velero.io -n velero <bsl-name> -o yaml -o jsonpath={.spec.credential.key})

   # Confirm that the secret exists
   kubectl -n velero get secret $BSL_SECRET

   # Print the content of the secret and ensure it is correct
   kubectl -n velero get secret $BSL_SECRET -ojsonpath={.data.$BSL_SECRET_KEY} | base64 --decode
   ```
   If the secret can't be found, the secret does not exist within the Velero namespace and must be created.

   If no output is produced when printing the contents of the secret, the key within the secret may not exist or may have no content.
   Ensure that the key exists within the secret's data by checking the output from `kubectl -n velero describe secret $BSL_SECRET`.
   If it does not exist, follow the instructions for [editing a Kubernetes secret][12] to add the base64 encoded credentials data.


[1]: debugging-restores.md
[2]: debugging-install.md
[3]: restic.md
[4]: https://github.com/velero-io/velero/issues
[5]: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
[6]: https://github.com/vmware-tanzu/helm-charts/blob/main/charts/velero
[7]: https://github.com/vmware-tanzu/helm-charts/blob/main/charts/velero/values.yaml#L44
[8]: https://github.com/vmware-tanzu/helm-charts/blob/main/charts/velero/values.yaml#L49-L52
[9]: https://kubectl.docs.kubernetes.io/pages/container_debugging/port_forward_to_pods.html
[10]: locations.md
[11]: /plugins
[12]: https://kubernetes.io/docs/concepts/configuration/secret/#editing-a-secret
[25]: https://kubernetes.slack.com/messages/velero
