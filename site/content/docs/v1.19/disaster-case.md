---
title: "Disaster recovery"
layout: docs
---

*Using Schedules and Read-Only Backup Storage Locations*

If you periodically back up your cluster's resources, you are able to return to a previous state in case of some unexpected mishap, such as a service outage. Doing so with Velero looks like the following:

1.  After you first run the Velero server on your cluster, set up a daily backup (replacing `<SCHEDULE NAME>` in the command as desired):

    ```
    velero schedule create <SCHEDULE NAME> --schedule "0 7 * * *"
    ```
    
    This creates a Backup object with the name `<SCHEDULE NAME>-<TIMESTAMP>`. The default backup retention period, expressed as TTL (time to live), is 30 days (720 hours); you can use the `--ttl <DURATION>` flag to change this as necessary. See [how velero works][1] for more information about backup expiry. 

1.  A disaster happens and you need to recreate your resources.

1.  Update your backup storage location to read-only mode (this prevents backup objects from being created or deleted in the backup storage location during the restore process):

    ```bash
    kubectl patch backupstoragelocation <STORAGE LOCATION NAME> \
        --namespace velero \
        --type merge \
        --patch '{"spec":{"accessMode":"ReadOnly"}}'
    ```

1.  Create a restore with your most recent Velero Backup:

    ```
    velero restore create --from-backup <SCHEDULE NAME>-<TIMESTAMP>
    ```

1. When ready, revert your backup storage location to read-write mode:

    ```bash
    kubectl patch backupstoragelocation <STORAGE LOCATION NAME> \
       --namespace velero \
       --type merge \
       --patch '{"spec":{"accessMode":"ReadWrite"}}'
    ```
    
[1]: how-velero-works.md#set-a-backup-to-expire
