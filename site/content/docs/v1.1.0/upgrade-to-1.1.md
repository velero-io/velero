---
title: "Upgrading to Velero 1.1"
layout: docs
---

## Prerequisites
- [Velero v1.0][1] installed.

Velero v1.1 only requires user intervention if Velero is running in a namespace other than `velero`.

## Instructions

### Adding VELERO_NAMESPACE environment variable to the deployment

Previous versions of Velero's server detected the namespace in which it was running by inspecting the container's filesystem.
With v1.1, this is no longer the case, and the server must be made aware of the namespace it is running in with the `VELERO_NAMESPACE` environment variable.

`velero install` automatically writes this for new deployments, but existing installations will need to add the environment variable before upgrading.

You can use the following command to patch the deployment:

```bash
kubectl patch deployment/velero -n <YOUR_NAMESPACE> \
--type='json' \
-p='[{"op":"add","path":"/spec/template/spec/containers/0/env/0","value":{"name":"VELERO_NAMESPACE", "valueFrom":{"fieldRef":{"fieldPath":"metadata.namespace"}}}}]'
```

[1]: https://github.com/velero-io/velero/releases/tag/v1.0.0
