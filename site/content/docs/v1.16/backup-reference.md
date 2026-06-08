---
title: "Backup Reference"
layout: docs
---

## Exclude Specific Items from Backup

It is possible to exclude individual items from being backed up, even if they match the resource/namespace/label selectors defined in the backup spec. To do this, label the item as follows:

```bash
kubectl label -n <ITEM_NAMESPACE> <RESOURCE>/<NAME> velero.io/exclude-from-backup=true
```
## Parallel Files Upload
If using fs-backup with Kopia uploader or CSI snapshot data movements, it's allowed to configure the option for parallel files upload, which could accelerate the backup:
```bash
velero backup create <BACKUP_NAME> --include-namespaces <NAMESPACE> --parallel-files-upload <NUM> --wait
```

## Specify Backup Orders of Resources of Specific Kind

To backup resources of specific Kind in a specific order, use option --ordered-resources to specify a mapping Kinds to an ordered list of specific resources of that Kind.  Resource names are separated by commas and their names are in format 'namespace/resourcename'. For cluster scope resource, simply use resource name. Key-value pairs in the mapping are separated by semi-colon.  Kind name is in plural form.

```bash
velero backup create backupName --include-cluster-resources=true --ordered-resources 'pods=ns1/pod1,ns1/pod2;persistentvolumes=pv4,pv8' --include-namespaces=ns1
velero backup create backupName --ordered-resources 'statefulsets=ns1/sts1,ns1/sts0' --include-namespaces=ns1
```
## Schedule a Backup

The **schedule** operation allows you to create a backup of your data at a specified time, defined by a [Cron expression](https://en.wikipedia.org/wiki/Cron).

```
velero schedule create NAME --schedule="* * * * *" [flags]
```

Cron schedules use the following format.

```
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of the month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday;
# │ │ │ │ │                                   7 is also Sunday on some systems)
# │ │ │ │ │
# │ │ │ │ │
# * * * * *
```

For example, the command below creates a backup that runs every day at 3am.

```
velero schedule create example-schedule --schedule="0 3 * * *"
```

This command will create the backup, `example-schedule`, within Velero, but the backup will not be taken until the next scheduled time, 3am. Backups created by a schedule are saved with the name `<SCHEDULE NAME>-<TIMESTAMP>`, where `<TIMESTAMP>` is formatted as *YYYYMMDDhhmmss*. For a full list of available configuration flags use the Velero CLI help command.

```
velero schedule create --help
```

Once you create the scheduled backup, you can then trigger it manually using the `velero backup` command.

```
velero backup create --from-schedule example-schedule
```

This command will immediately trigger a new backup based on your template for `example-schedule`. This will not affect the backup schedule, and another backup will trigger at the scheduled time.

### Time zone specification
Time zone can be specified in the schedule cron. The format is `CRON_TZ=<timezone> <cron>`.

Specifying timezones can reduce disputes in the case of daylight saving time changes. For example, if the schedule is set to run at 3am, and daylight saving time changes, the schedule will still run at 3am in the timezone specified.

Be aware that jobs scheduled during daylight-savings leap-ahead transitions will not be run!

For example, the command below creates a backup that runs every day at 3am in the timezone `America/New_York`.

```
velero schedule create example-schedule --schedule="CRON_TZ=America/New_York 0 3 * * *"
```

Another example, the command below creates a backup that runs every day at 3am in the timezone `Asia/Shanghai`.

```
velero schedule create example-schedule --schedule="CRON_TZ=Asia/Shanghai 0 3 * * *"
```

The supported timezone names are listed in the [IANA Time Zone Database](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones#List) under 'TZ identifier'.
<!--
cron's WithLocation functions uses time.Location as parameter, and [time.LoadLocation](https://pkg.go.dev/time#LoadLocation) support names from IANA timezone database in following locations in this order
- the directory or uncompressed zip file named by the ZONEINFO environment variable
- on a Unix system, the system standard installation location
- $GOROOT/lib/time/zoneinfo.zip
- the time/tzdata package, if it was imported
 -->

### Limitation

#### Backup's OwnerReference with Schedule
Backups created from schedule can have owner reference to the schedule. This can be achieved by command:

```
velero schedule create --use-owner-references-in-backup <backup-name>
```
By this way, schedule is the owner of it created backups. This is useful for some GitOps scenarios, or the resource tree of k8s synchronized from other places.

Please do notice there is also side effect that may not be expected. Because schedule is the owner, when the schedule is deleted, the related backups CR (Just backup CR is deleted. Backup data still exists in object store and snapshots) will be deleted by k8s GC controller, too, but Velero controller will sync these backups from object store's metadata into k8s. Then k8s GC controller and Velero controller will fight over whether these backups should exist all through.

If there is possibility the schedule will be disable to not create backup anymore, and the created backups are still useful. Please do not enable this option. For detail, please reference to [Backups created by a schedule with useOwnerReferenceInBackup set do not get synced properly](https://github.com/velero-io/velero/issues/4093).

Some GitOps tools have configurations to avoid pruning the day 2 backups generated from the schedule.
For example, the ArgoCD has two ways to do that:
* Add annotations to schedule. This method makes ArgoCD ignore the schedule from syncing, so the generated backups are ignored too, but it has a side effect. When deleting the schedule from the GitOps manifest, the schedule can not be deleted. User needs to do it manually.
``` yaml
    annotations:
      argocd.argoproj.io/compare-options: IgnoreExtraneous
      argocd.argoproj.io/sync-options: Delete=false,Prune=false
```
* If ArgoCD is deployed by ArgoCD-Operator, there is another option: [resourceExclusions](https://argocd-operator.readthedocs.io/en/latest/reference/argocd/#resource-exclusions-example). This is an example, which means ArgoCD operator should ignore `Backup` and `Restore` in `velero.io` group in the `velero` namespace for all managed k8s cluster.
``` yaml
apiVersion: argoproj.io/v1alpha1
kind: ArgoCD
metadata:
  name: velero-argocd
  namespace: velero
spec:
  resourceExclusions: |
    - apiGroups:
      - velero.io
      kinds:
      - Backup
      - Restore
      clusters:
      - "*"
```

#### Cannot support backup data immutability
Starting from 1.11, Velero's backups may not work as expected when the target object storage has some kind of an "immutability" option configured. These options are known by different names (see links below for some examples). The main reason is that Velero first saves the state of a backup as Finalizing and then checks whether there are any async operations in progress. If there are, it needs to wait for all of them to be finished before moving the backup state to Complete. If there are no async operations, the state is moved to Complete right away. In either case, Velero needs to modify the metadata in object storage and that will not be possible if some kind of immutability is configured on the object storage.

Even with versions prior to 1.11, there was no explicit support in Velero to work with object storage that has "immutability" configuration. As a result, you may see some problems even though backups seem to work (e.g. versions objects not being deleted when backup is deleted).

Note that backups may still work in some cases depending on specific providers and configurations.

* For AWS S3 service, backups work because S3's object lock only applies to versioned buckets, and the object data can still be updated as the new version. But when backups are deleted, old versions of the objects will not be deleted.
* Azure Storage Blob supports both versioned-level immutability and container-level immutability. For the versioned-level scenario, data immutability can still work in Velero, but the container-level cannot.
* GCP Cloud storage policy only supports bucket-level immutability, so there is no way to make it work in the GCP environment.

The following are the links to cloud providers' documentation in this regard:

* [AWS S3 Using S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
* [Azure Storage Blob Containers - Lock Immutability Policy](https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-version-scope?tabs=azure-portal)
* [GCP cloud storage Retention policies and retention policy locks](https://cloud.google.com/storage/docs/bucket-lock)
 
## Kubernetes API Pagination

By default, Velero will paginate the LIST API call for each resource type in the Kubernetes API when collecting items into a backup. The `--client-page-size` flag for the Velero server configures the size of each page.

Depending on the cluster's scale, tuning the page size can improve backup performance. You can experiment with higher values, noting their impact on the relevant `apiserver_request_duration_seconds_*` metrics from the Kubernetes apiserver.

Pagination can be entirely disabled by setting `--client-page-size` to `0`. This will request all items in a single unpaginated LIST call.

## Deleting Backups

Use the following commands to delete Velero backups and data:

* `kubectl delete backup <backupName> -n <veleroNamespace>` will delete the backup custom resource only and will not delete any associated data from object/block storage
* `velero backup delete <backupName>` will delete the backup resource including all data in object/block storage
