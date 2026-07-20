---
title: "Backup API Type"
layout: docs
---

## Use

Use the `Backup` API type to request the Velero server to perform a backup. Once created, the
Velero Server immediately starts the backup process.

## API GroupVersion

Backup belongs to the API group version `velero.io/v1`.

## Definition

Here is a sample `Backup` object with each of the fields documented:

**Note:** Namespace includes/excludes support glob patterns (`*`, `?`, `[abc]`). See [Namespace Glob Patterns](../namespace-glob-patterns) for more details.

```yaml
# Standard Kubernetes API Version declaration. Required.
apiVersion: velero.io/v1
# Standard Kubernetes Kind declaration. Required.
kind: Backup
# Standard Kubernetes metadata. Required.
metadata:
  # Backup name. May be any valid Kubernetes object name. Required.
  name: a
  # Backup namespace. Must be the namespace of the Velero server. Required.
  namespace: velero
# Parameters about the backup. Required.
spec:
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
  # Array of namespaces to include in the backup. Accepts glob patterns (*, ?, [abc]).
  # Note: '*' alone is reserved for empty fields, which means all namespaces.
  # If unspecified, all namespaces are included. Optional.
  includedNamespaces:
  - '*'
  # Array of namespaces to exclude from the backup. Accepts glob patterns (*, ?, [abc]). Optional.
  excludedNamespaces:
  - some-namespace
  # Array of resources to include in the backup. Resources may be shortcuts (for example 'po' for 'pods')
  # or fully-qualified. If unspecified, all resources are included. Optional.
  includedResources:
  - '*'
  # Array of resources to exclude from the backup. Resources may be shortcuts (for example 'po' for 'pods')
  # or fully-qualified. Optional.
  excludedResources:
  - storageclasses.storage.k8s.io
  # Order of the resources to be collected during the backup process.  It's a map with key being the plural resource
  # name, and the value being a list of object names separated by comma.  Each resource name has format "namespace/objectname".
  # For cluster resources, simply use "objectname". Optional
  orderedResources:
    pods: mysql/mysql-cluster-replica-0,mysql/mysql-cluster-replica-1,mysql/mysql-cluster-source-0
    persistentvolumes: pvc-87ae0832-18fd-4f40-a2a4-5ed4242680c4,pvc-63be1bb0-90f5-4629-a7db-b8ce61ee29b3
  # Whether to include cluster-scoped resources. Valid values are true, false, and
  # null/unset. If true, all cluster-scoped resources are included (subject to included/excluded
  # resources and the label selector). If false, no cluster-scoped resources are included. If unset,
  # all cluster-scoped resources are included if and only if all namespaces are included and there are
  # no excluded namespaces. Otherwise, if there is at least one namespace specified in either
  # includedNamespaces or excludedNamespaces, then the only cluster-scoped resources that are backed
  # up are those associated with namespace-scoped resources included in the backup. For example, if a
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
  # Individual objects must match this label selector to be included in the backup. Optional.
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
  # Whether or not to snapshot volumes. Valid values are true, false, and null/unset. If unset, Velero performs snapshots as long as
  # a persistent volume provider is configured for Velero.
  snapshotVolumes: null
  # Where to store the tarball and logs.
  storageLocation: aws-primary
  # The list of locations in which to store volume snapshots created for this backup.
  volumeSnapshotLocations:
    - aws-primary
    - gcp-primary
  # The amount of time before this backup is eligible for garbage collection. If not specified,
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
  # BackupType specifies how volume data is backed up, with possible values including Full and Incremental.
	# BackupType is optional. If it's not set, it will default to Full.
  # BackupType is only meaningful for data mover backup, including CSI snapshot fs backup, CSI snapshot block backup, and fs backup.
  # For CSI only backup and Velero native backup, backupType doesn't take effect.
  # Full means data mover will forcefully upload all data in volumes.
  # Incremental means data mover will only upload data change since last snapshot. 
  backupType: Full
# Status about the Backup. Users should not set any data here.
status:
  # The version of this Backup. The only version supported is 1.
  version: 1
  # The date and time when the Backup is eligible for garbage collection.
  expiration: null
  # The current phase.
  # Valid values are New, FailedValidation, InProgress, WaitingForPluginOperations,
  # WaitingForPluginOperationsPartiallyFailed, FinalizingafterPluginOperations,
  # FinalizingPartiallyFailed, Completed, PartiallyFailed, Failed.
  phase: ""
  # An array of any validation errors encountered.
  validationErrors: null
  # Date/time when the backup started being processed.
  startTimestamp: 2019-04-29T15:58:43Z
  # Date/time when the backup finished being processed.
  completionTimestamp: 2019-04-29T15:58:56Z
  # Number of volume snapshots that Velero tried to create for this backup.
  volumeSnapshotsAttempted: 2
  # Number of volume snapshots that Velero successfully created for this backup.
  volumeSnapshotsCompleted: 1
  # Number of attempted BackupItemAction operations for this backup.
  backupItemOperationsAttempted: 2
  # Number of BackupItemAction operations that Velero successfully completed for this backup.
  backupItemOperationsCompleted: 1
  # Number of BackupItemAction operations that ended in failure for this backup.
  backupItemOperationsFailed: 0
  # Number of warnings that were logged by the backup.
  warnings: 2
  # Number of errors that were logged by the backup.
  errors: 0
  # An error that caused the entire backup to fail.
  failureReason: ""
```
