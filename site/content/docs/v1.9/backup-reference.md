---
title: "Backup Reference"
layout: docs
---

## Exclude Specific Items from Backup

It is possible to exclude individual items from being backed up, even if they match the resource/namespace/label selectors defined in the backup spec. To do this, label the item as follows:

```bash
kubectl label -n <ITEM_NAMESPACE> <RESOURCE>/<NAME> velero.io/exclude-from-backup=true
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


### Limitation
Backups created from schedule can have owner reference to the schedule. This can be achieved by command:

```
velero schedule create --use-owner-references-in-backup <backup-name>
```
By this way, schedule is the owner of it created backups. This is useful for some GitOps scenarios, or the resource tree of k8s synchronized from other places.

Please do notice there is also side effect that may not be expected. Because schedule is the owner, when the schedule is deleted, the related backups CR (Just backup CR is deleted. Backup data still exists in object store and snapshots) will be deleted by k8s GC controller, too, but Velero controller will sync these backups from object store's metadata into k8s. Then k8s GC controller and Velero controller will fight over whether these backups should exist all through.

If there is possibility the schedule will be disable to not create backup anymore, and the created backups are still useful. Please do not enable this option. For detail, please reference to [Backups created by a schedule with useOwnerReferenceInBackup set do not get synced properly](https://github.com/velero-io/velero/issues/4093).


## Kubernetes API Pagination

By default, Velero will paginate the LIST API call for each resource type in the Kubernetes API when collecting items into a backup. The `--client-page-size` flag for the Velero server configures the size of each page.

Depending on the cluster's scale, tuning the page size can improve backup performance. You can experiment with higher values, noting their impact on the relevant `apiserver_request_duration_seconds_*` metrics from the Kubernetes apiserver.

Pagination can be entirely disabled by setting `--client-page-size` to `0`. This will request all items in a single unpaginated LIST call.

## Deleting Backups

Use the following commands to delete Velero backups and data:

* `kubectl delete backup <backupName> -n <veleroNamespace>` will delete the backup custom resource only and will not delete any associated data from object/block storage
* `velero backup delete <backupName>` will delete the backup resource including all data in object/block storage
