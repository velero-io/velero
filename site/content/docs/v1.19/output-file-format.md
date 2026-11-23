---
title: "Output file format"
layout: docs
---

A backup is a gzip-compressed tar file whose name matches the Backup API resource's `metadata.name` (what is specified during `velero backup create <NAME>`).

In cloud object storage, each backup file is stored in its own subdirectory in the bucket specified in the Velero server configuration. This subdirectory includes an additional file called `velero-backup.json`. The JSON file lists all information about your associated Backup resource, including any default values. This gives you a complete historical record of the backup configuration. The JSON file also specifies `status.version`, which corresponds to the output file format.

The directory structure in your cloud storage looks something like:

```
rootBucket/
    backup1234/
        velero-backup.json
        backup1234.tar.gz
```

## Example backup JSON file

```json
{
  "kind": "Backup",
  "apiVersion": "velero.io/v1",
  "metadata": {
    "name": "test-backup",
    "namespace": "velero",
    "selfLink": "/apis/velero.io/v1/namespaces/velero/backups/test-backup",
    "uid": "a12345cb-75f5-11e7-b4c2-abcdef123456",
    "resourceVersion": "337075",
    "creationTimestamp": "2017-07-31T13:39:15Z"
  },
  "spec": {
    "includedNamespaces": [
      "*"
    ],
    "excludedNamespaces": null,
    "includedResources": [
      "*"
    ],
    "excludedResources": null,
    "labelSelector": null,
    "snapshotVolumes": true,
    "ttl": "24h0m0s"
  },
  "status": {
    "version": 1,
    "formatVersion": "1.1.0",
    "expiration": "2017-08-01T13:39:15Z",
    "phase": "Completed",
    "volumeBackups": {
      "pvc-e1e2d345-7583-11e7-b4c2-abcdef123456": {
        "snapshotID": "snap-04b1a8e11dfb33ab0",
        "type": "gp2",
        "iops": 100
      }
    },
    "validationErrors": null
  }
}
```
Note that this file includes detailed info about your volume snapshots in the `status.volumeBackups` field, which can be helpful if you want to manually check them in your cloud provider GUI.

## Output File Format Versioning

The Velero output file format is intended to be relatively stable, but may change over time to support new features.

To accommodate this, Velero follows [Semantic Versioning](http://semver.org/) for the file format version.

Minor and patch versions will indicate backwards-compatible changes that previous versions of Velero can restore, including new directories or files.

A major version would indicate that a version of Velero older than the version that created the backup could not restore it, usually because of moved or renamed directories or files.

Major versions of the file format will be incremented with major version releases of Velero.
However, a major version release of Velero does not necessarily mean that the backup format version changed - Velero 3.0 could still use backup file format 2.0, as an example.

## Versions

### File Format Version: 1.1 (Current)

Version 1.1 added support of API groups versions as part of the backup. Previously, only the preferred version of each API groups was backed up. Each resource has one or more sub-directories: one sub-directory for each supported version of the API group. The preferred version API Group of each resource has the suffix "-preferredversion" as part of the sub-directory name. For backward compatibility, we kept the classic directory structure without the API group version, which sits on the same level as the API group sub-directory versions.

By default, only the preferred API group of each resource is backed up. To take a backup of all API group versions, you need to run the Velero server with the `--features=EnableAPIGroupVersions` feature flag. This is an experimental flag and the restore logic to handle multiple API group versions is documented at [EnableAPIGroupVersions](enable-api-group-versions-feature.md).

When unzipped, a typical backup directory (`backup1234.tar.gz`) taken with this file format version looks like the following (with the feature flag):

```
resources/
    persistentvolumes/
        cluster/
            pv01.json
            ...
        v1-preferredversion/
            cluster/
                pv01.json
                ...
    configmaps/
        namespaces/
            namespace1/
                myconfigmap.json
                ...
            namespace2/
                ...
        v1-preferredversion/
            namespaces/
                namespace1/
                    myconfigmap.json
                    ...
                namespace2/
                    ...
    pods/
        namespaces/
            namespace1/
                mypod.json
                ...
            namespace2/
                ...
        v1-preferredversion/
            namespaces/
                namespace1/
                    mypod.json
                    ...
                namespace2/
                    ...
    jobs.batch/
        namespaces/
            namespace1/
                awesome-job.json
                ...
            namespace2/
                ...
        v1-preferredversion/
            namespaces/
                namespace1/
                    awesome-job.json
                    ...
                namespace2/
                    ...
    deployments/
        namespaces/
            namespace1/
                cool-deployment.json
                ...
            namespace2/
                ...
	v1-preferredversion/
		namespaces/
		    namespace1/
			cool-deployment.json
			...
		    namespace2/
			...
    horizontalpodautoscalers.autoscaling/
        namespaces/
            namespace1/
                hpa-to-the-rescue.json
                ...
            namespace2/
                ...
        v1-preferredversion/
            namespaces/
                namespace1/
                    hpa-to-the-rescue.json
                    ...
                namespace2/
                    ...
        v2beta1/
            namespaces/
                namespace1/
                    hpa-to-the-rescue.json
                    ...
                namespace2/
                    ...
        v2beta2/
            namespaces/
                namespace1/
                    hpa-to-the-rescue.json
                    ...
                namespace2/
                    ...

    ...
```

### File Format Version: 1

When unzipped, a typical backup directory (`backup1234.tar.gz`) looks like the following:

```
resources/
    persistentvolumes/
        cluster/
            pv01.json
            ...
    configmaps/
        namespaces/
            namespace1/
                myconfigmap.json
                ...
            namespace2/
                ...
    pods/
        namespaces/
            namespace1/
                mypod.json
                ...
            namespace2/
                ...
    jobs/
        namespaces/
            namespace1/
                awesome-job.json
                ...
            namespace2/
                ...
    deployments/
        namespaces/
            namespace1/
                cool-deployment.json
                ...
            namespace2/
                ...
    ...
```
