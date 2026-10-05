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

Velero cannot currently resume backups that were interrupted. Backups stuck in the `InProgress` phase can be deleted with `kubectl delete backup <name> -n <velero-namespace>`.
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

[1]: debugging-restores.md
[2]: debugging-install.md
[4]: https://github.com/velero-io/velero/issues
[5]: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
[6]: https://github.com/vmware-tanzu/helm-charts/blob/main/charts/velero
[7]: https://github.com/vmware-tanzu/helm-charts/blob/main/charts/velero/values.yaml#L44
[8]: https://github.com/vmware-tanzu/helm-charts/blob/main/charts/velero/values.yaml#L49-L52
[9]: https://kubectl.docs.kubernetes.io/pages/container_debugging/port_forward_to_pods.html
[25]: https://kubernetes.slack.com/messages/velero
