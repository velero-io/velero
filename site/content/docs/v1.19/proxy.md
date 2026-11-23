---
title: "Behind Proxy"
layout: docs
toc: "true"
---

This document explains how to make Velero work behind proxy.
The procedures described in this document are concluded from the scenario that Velero is deployed behind proxy, and Velero needs to connect to a public MinIO server as storage location. Maybe other scenarios' configurations are not exactly the same, but basically they should share most parts.

## Set the proxy server address
Specify the proxy server address by environment variables in Velero deployment and node-agent DaemonSet.
Take the following as an example:
``` yaml
    ...
    spec:
      containers:
      - args:
        - server
        - --features=EnableCSI
        command:
        - /velero
        env:
        ...
        - name: HTTP_PROXY
          value: <proxy_address>
        - name: HTTPS_PROXY
          value: <proxy_address>
        # In case not all destinations that Velero connects to need go through proxy, users can specify the NO_PROXY to bypass proxy. 
        - name: NO_PROXY
          value: <address_list_not_use_proxy>
```

## Set the proxy required certificates
In some cases, the proxy requires certificate to connect. You can provide certificates in the BSL configuration.
It's possible that the object storage also requires certificate, then include both certificates together.

### Method 1: Using Kubernetes Secrets (Recommended)

The recommended approach is to store certificates in a Kubernetes Secret and reference them using `caCertRef`:

1. Create a file containing all required certificates:

   ``` bash
   cat certs
   -----BEGIN CERTIFICATE-----
   certificates first content
   -----END CERTIFICATE-----

   -----BEGIN CERTIFICATE-----
   certificates second content
   -----END CERTIFICATE-----
   ```

2. Create a Secret from the certificate file:

   ``` bash
   kubectl create secret generic proxy-ca-certs \
     --from-file=ca-bundle.crt=certs \
     -n velero
   ```

3. Reference the Secret in your BackupStorageLocation:

``` yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
  namespace: velero
spec:
  provider: <YOUR_PROVIDER>
  default: true
  objectStorage:
    bucket: velero
    caCertRef:
      name: proxy-ca-certs
      key: ca-bundle.crt
  # ... other configuration
```

### Method 2: Using inline certificates (Deprecated)

**Note:** The `caCert` field is deprecated. Use `caCertRef` for better security and management.

If you must use the inline method, encode the certificate content with base64:

``` bash
cat certs | base64
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmNlcnRpZmljYXRlcyBmaXJzdCBjb250ZW50Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpjZXJ0aWZpY2F0ZXMgc2Vjb25kIGNvbnRlbnQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
```

``` yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
# ...
spec:
  # ...
  default: true
  objectStorage:
    bucket: velero
    caCert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCmNlcnRpZmljYXRlcyBmaXJzdCBjb250ZW50Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpjZXJ0aWZpY2F0ZXMgc2Vjb25kIGNvbnRlbnQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  # ...
```
