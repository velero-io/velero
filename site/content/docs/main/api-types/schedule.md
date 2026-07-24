---
title: "Schedule API Type"
layout: docs
---

## Use

The `Schedule` API type is used as a repeatable request for the Velero server to perform a backup for a given cron notation. Once created, the
Velero Server will start the backup process. It will then wait for the next valid point of the given cron expression and execute the backup
process on a repeating basis.

### Schedule Control Fields

The Schedule API provides several fields to control backup execution behavior:

- **paused**: When set to `true`, the schedule is paused and no new backups will be created. When set back to `false`, the schedule is unpaused and will resume creating backups according to the cron schedule.

- **skipImmediately**: Controls whether to skip an immediate backup when a schedule is created or unpaused. By default (when `false`), if a backup is due immediately upon creation or unpausing, it will be executed right away. When set to `true`, the controller will:
  1. Skip the immediate backup
  2. Record the current time in the `lastSkipped` status field
  3. Automatically reset `skipImmediately` back to `false` (one-time use)
  4. Schedule the next backup based on the cron expression, using `lastSkipped` as the reference time

- **lastSkipped**: A status field (not directly settable) that records when a backup was last skipped due to `skipImmediately` being `true`. The controller uses this timestamp, if more recent than `lastBackup`, to calculate the next scheduled backup time.

This "consume and reset" pattern for `skipImmediately` ensures that after skipping one immediate backup, the schedule returns to normal behavior for subsequent runs without requiring user intervention.

## API GroupVersion

Schedule belongs to the API group version `velero.io/v1`.

## Definition

Here is a sample `Schedule` object with each of the fields documented:

```yaml
# Standard Kubernetes API Version declaration. Required.
apiVersion: velero.io/v1
# Standard Kubernetes Kind declaration. Required.
kind: Schedule
# Standard Kubernetes metadata. Required.
metadata:
  # Schedule name. May be any valid Kubernetes object name. Required.
  name: a
  # Schedule namespace. Must be the namespace of the Velero server. Required.
  namespace: velero
# Parameters about the scheduled backup. Required.
spec:
  # Paused specifies whether the schedule is paused or not
  paused: false
  # SkipImmediately specifies whether to skip backup if schedule is due immediately when unpaused or created.
  # This is a one-time flag that will be automatically reset to false after being consumed.
  # When true, the controller will skip the immediate backup, set LastSkipped timestamp, and reset this to false.
  skipImmediately: false
  # Schedule is a Cron expression defining when to run the Backup
  schedule: 0 7 * * *
  # Specifies whether to use OwnerReferences on backups created by this Schedule. 
  # Notice: if set to true, when schedule is deleted, backups will be deleted too. Optional.
  useOwnerReferencesInBackup: false
  # Template is the spec that should be used for each backup triggered by this schedule.
  template:
    # CSISnapshotTimeout specifies the time used to wait for
    # CSI VolumeSnapshot status turns to ReadyToUse during creation, before
    # returning error as timeout. The default value is 10 minute.
    csiSnapshotTimeout: 10m
    # ItemOperationTimeout specifies the time used to wait for
    # asynchronous BackupItemAction operations
    # The default value is 4 hour.
    itemOperationTimeout: 4h
    # resourcePolicy specifies the referenced resource policies that backup should follow
    # optional
    resourcePolicy:
      kind: configmap
      name: resource-policy-configmap
    # Array of namespaces to include in the scheduled backup. If unspecified, all namespaces are included.
    # Optional.
    includedNamespaces:
    - '*'
    # Array of namespaces to exclude from the scheduled backup. Optional.
    excludedNamespaces:
    - some-namespace
    # Array of resources to include in the scheduled backup. Resources may be shortcuts (for example 'po' for 'pods')
    # or fully-qualified. If unspecified, all resources are included. Optional.
    includedResources:
    - '*'
    # Array of resources to exclude from the scheduled backup. Resources may be shortcuts (for example 'po' for 'pods')
    # or fully-qualified. Optional.
    excludedResources:
    - storageclasses.storage.k8s.io
    orderedResources:
      pods: mysql/mysql-cluster-replica-0,mysql/mysql-cluster-replica-1,mysql/mysql-cluster-source-0
      persistentvolumes: pvc-87ae0832-18fd-4f40-a2a4-5ed4242680c4,pvc-63be1bb0-90f5-4629-a7db-b8ce61ee29b3
    # Whether to include cluster-scoped resources. Valid values are true, false, and
    # null/unset. If true, all cluster-scoped resources are included (subject to included/excluded
    # resources and the label selector). If false, no cluster-scoped resources are included. If unset,
    # all cluster-scoped resources are included if and only if all namespaces are included and there are
    # no excluded namespaces. Otherwise, if there is at least one namespace specified in either
    # includedNamespaces or excludedNamespaces, then the only cluster-scoped resources that are backed
    # up are those associated with namespace-scoped resources included in the scheduled backup. For example, if a
    # PersistentVolumeClaim is included in the backup, its associated PersistentVolume (which is
    # cluster-scoped) would also be backed up.
    includeClusterResources: null
    # Array of cluster-scoped resources to exclude from the backup. Resources may be shortcuts 
    # (for example 'sc' for 'storageclasses'), or fully-qualified. If unspecified, 
    # no additional cluster-scoped resources are excluded. Optional.
    # Cannot work with include-resources, exclude-resources and include-cluster-resources.
    excludedClusterScopedResources: {}
    # Array of cluster-scoped resources to include from the backup. Resources may be shortcuts 
    # (for example 'sc' for 'storageclasses'), or fully-qualified. If unspecified, 
    # no additional cluster-scoped resources are included. Optional.
    # Cannot work with include-resources, exclude-resources and include-cluster-resources.
    includedClusterScopedResources: {}
    # Array of namespace-scoped resources to exclude from the backup. Resources may be shortcuts 
    # (for example 'cm' for 'configmaps'), or fully-qualified. If unspecified, 
    # no namespace-scoped resources are excluded. Optional.
    # Cannot work with include-resources, exclude-resources and include-cluster-resources.
    excludedNamespaceScopedResources: {}
    # Array of namespace-scoped resources to include from the backup. Resources may be shortcuts 
    # (for example 'cm' for 'configmaps'), or fully-qualified. If unspecified, 
    # all namespace-scoped resources are included. Optional.
    # Cannot work with include-resources, exclude-resources and include-cluster-resources.
    includedNamespaceScopedResources: {}
    # Individual objects must match this label selector to be included in the scheduled backup. Optional.
    labelSelector:
      matchLabels:
        app: velero
        component: server
    # Individual object when matched with any of the label selector specified in the set are to be included in the backup. Optional.
    # orLabelSelectors as well as labelSelector cannot co-exist, only one of them can be specified in the backup request
    orLabelSelectors:
      - matchLabels:
          app: velero
      - matchLabels:
          app: data-protection
    # Whether to snapshot volumes. Valid values are true, false, and null/unset. If unset, Velero performs snapshots as long as
    # a persistent volume provider is configured for Velero.
    snapshotVolumes: null
    # Where to store the tarball and logs.
    storageLocation: aws-primary
    # The list of locations in which to store volume snapshots created for backups under this schedule.
    volumeSnapshotLocations:
      - aws-primary
      - gcp-primary
    # The amount of time before backups created on this schedule are eligible for garbage collection. If not specified,
    # a default value of 30 days will be used. The default can be configured on the velero server
    # by passing the flag --default-backup-ttl.
    ttl: 24h0m0s
    # whether pod volume file system backup should be used for all volumes by default.
    defaultVolumesToFsBackup: true
    # Whether snapshot data should be moved. If set, data movement is launched after the snapshot is created.
    snapshotMoveData: true
    # The data mover to be used by the backup. If the value is "" or "velero", the built-in data mover will be used.
    datamover: velero
    # UploaderConfig specifies the configuration for the uploader
    uploaderConfig:
        # ParallelFilesUpload is the number of files parallel uploads to perform when using the uploader.
        parallelFilesUpload: 10
    # The labels/annotations you want on backup objects, created from this schedule (instead of copying the labels/annotations you have on schedule object itself).
    # When this field is set, the labels/annotations from the Schedule resource are not copied to the Backup resource.
    metadata:
      labels:
        labelname: somelabelvalue
      annotations:
        annotationname: someannotationvalue
    # Actions to perform at different times during a backup. The only hook supported is
    # executing a command in a container in a pod using the pod exec API. Optional.
    hooks:
      # Array of hooks that are applicable to specific resources. Optional.
      resources:
        -
          # Name of the hook. Will be displayed in backup log.
          name: my-hook
          # Array of namespaces to which this hook applies. If unspecified, the hook applies to all
          # namespaces. Optional.
          includedNamespaces:
          - '*'
          # Array of namespaces to which this hook does not apply. Optional.
          excludedNamespaces:
          - some-namespace
          # Array of resources to which this hook applies. The only resource supported at this time is
          # pods.
          includedResources:
          - pods
          # Array of resources to which this hook does not apply. Optional.
          excludedResources: []
          # This hook only applies to objects matching this label selector. Optional.
          labelSelector:
            matchLabels:
              app: velero
              component: server
          # An array of hooks to run before executing custom actions. Only "exec" hooks are supported.
          pre:
            -
              # The type of hook. This must be "exec".
              exec:
                # The name of the container where the command will be executed. If unspecified, the
                # first container in the pod will be used. Optional.
                container: my-container
                # The command to execute, specified as an array. Required.
                command:
                  - /bin/uname
                  - -a
                # How to handle an error executing the command. Valid values are Fail and Continue.
                # Defaults to Fail. Optional.
                onError: Fail
                # How long to wait for the command to finish executing. Defaults to 30 seconds. Optional.
                timeout: 10s
          # An array of hooks to run after all custom actions and additional items have been
          # processed. Only "exec" hooks are supported.
          post:
            # Same content as pre above.
status:
  # The current phase.
  # Valid values are New, Enabled, FailedValidation.
  phase: ""
  # Date/time of the last backup for a given schedule
  lastBackup:
  # Date/time when a backup was last skipped due to skipImmediately being true
  lastSkipped:
  # An array of any validation errors encountered.
  validationErrors:
```
