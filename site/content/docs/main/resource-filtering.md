---
title: "Resource filtering"
layout: docs
---

*Filter objects by namespace, type, labels or resource policies.*

This page describes how to filter resource for backup and restore.
User could use the include and exclude flags with the `velero backup` and `velero restore` commands. And user could also use resource policies to handle backup.
By default, Velero includes all objects in a backup or restore when no filtering options are used.

## Includes

Only specific resources are included, all others are excluded.

Wildcard takes precedence when both a wildcard and specific resource are included.

### --include-namespaces

Namespaces to include. Accepts glob patterns (`*`, `?`, `[abc]`). Default is `*`, all namespaces.

See [Namespace Glob Patterns](namespace-glob-patterns) for more details on supported patterns.

Note: `*` alone is reserved for empty fields, which means all namespaces.

* Backup a namespace and it's objects.

  ```bash
  velero backup create <backup-name> --include-namespaces <namespace>
  ```

* Restore two namespaces and their objects.

  ```bash
  velero restore create <backup-name> --include-namespaces <namespace1>,<namespace2>
  ```

### --include-resources

Kubernetes resources to include in the backup, formatted as resource.group, such as storageclasses.storage.k8s.io (use `*` for all resources). Cannot work with `--include-cluster-scoped-resources`, `--exclude-cluster-scoped-resources`, `--include-namespace-scoped-resources` and `--exclude-namespace-scoped-resources`.

* Backup all deployments in the cluster.

  ```bash
  velero backup create <backup-name> --include-resources deployments
  ```

* Restore all deployments and configmaps in the cluster.

  ```bash
  velero restore create <backup-name> --include-resources deployments,configmaps
  ```

* Backup the deployments in a namespace.

  ```bash
  velero backup create <backup-name> --include-resources deployments --include-namespaces <namespace>
  ```

### --include-cluster-resources

Includes cluster-scoped resources. Cannot work with `--include-cluster-scoped-resources`, `--exclude-cluster-scoped-resources`, `--include-namespace-scoped-resources` and `--exclude-namespace-scoped-resources`. This option can have three possible values:

* `true`: all cluster-scoped resources are included.

* `false`: no cluster-scoped resources are included.

* `nil` ("auto" or not supplied):

  - Cluster-scoped resources are included when backing up or restoring all namespaces. Default: `true`.

  - Cluster-scoped resources are not included when namespace filtering is used. Default: `false`.

    * Some related cluster-scoped resources may still be backed/restored up if triggered by a custom action (for example, PVC->PV) unless `--include-cluster-resources=false`.

* Backup entire cluster including cluster-scoped resources.

  ```bash
  velero backup create <backup-name>
  ```

* Restore only namespaced resources in the cluster.

  ```bash
  velero restore create <backup-name> --include-cluster-resources=false
  ```

* Backup a namespace and include cluster-scoped resources.

  ```bash
  velero backup create <backup-name> --include-namespaces <namespace> --include-cluster-resources=true
  ```

### --selector

* Include resources matching the label selector.

  ```bash
  velero backup create <backup-name> --selector <key>=<value>
  ```
* Include resources that are not matching the selector
  ```bash
  velero backup create <backup-name> --selector "<key> notin (<value>)"
  ```

For more information read the [Kubernetes label selector documentation](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors)

### --or-selector

To include the resources that match at least one of the label selectors from the list. Separate the selectors with ` or `. The ` or ` is used as a separator to split label selectors, and it is not an operator.

This option cannot be used together with `--selector`.

* Include resources matching any one of the label selector, `foo=bar` or `baz=qux`

  ```bash
  velero backup create backup1 --or-selector "foo=bar or baz=qux"
  ```

* Include resources that are labeled `environment=production` or `env=prod` or `env=production` or `environment=prod`.

  ```bash
  velero restore create restore-prod --from-backup=prod-backup --or-selector "env in (prod,production) or environment in (prod, production)"
  ```

### --include-cluster-scoped-resources
Kubernetes cluster-scoped resources to include in the backup, formatted as resource.group, such as `storageclasses.storage.k8s.io`(use '*' for all resources). Cannot work with `--include-resources`, `--exclude-resources` and `--include-cluster-resources`. This parameter only works for backup, not for restore.

* Backup all StorageClasses and ClusterRoles in the cluster.

  ```bash
  velero backup create <backup-name> --include-cluster-scoped-resources="storageclasses,clusterroles"
  ```

* Backup all cluster-scoped resources in the cluster.

  ```bash
  velero backup create <backup-name> --include-cluster-scoped-resources="*"
  ```


### --include-namespace-scoped-resources
Kubernetes namespace resources to include in the backup, formatted as resource.group, such as `deployments.apps`(use '*' for all resources). Cannot work with `--include-resources`, `--exclude-resources` and `--include-cluster-resources`. This parameter only works for backup, not for restore.

* Backup all Deployments and ConfigMaps in the cluster.

  ```bash
  velero backup create <backup-name> --include-namespace-scoped-resources="deployments.apps,configmaps"
  ```

* Backup all namespace resources in the cluster.

  ```bash
  velero backup create <backup-name> --include-namespace-scoped-resources="*"
  ```

## Excludes

Exclude specific resources from the backup.

Wildcard excludes are ignored.

### --exclude-namespaces

Namespaces to exclude. Accepts glob patterns (`*`, `?`, `[abc]`).

See [Namespace Glob Patterns](namespace-glob-patterns.md) for more details on supported patterns.

* Exclude kube-system from the cluster backup.

  ```bash
  velero backup create <backup-name> --exclude-namespaces kube-system
  ```

* Exclude two namespaces during a restore.

  ```bash
  velero restore create <backup-name> --exclude-namespaces <namespace1>,<namespace2>
  ```

### --exclude-resources

Kubernetes resources to exclude, formatted as resource.group, such as storageclasses.storage.k8s.io. Cannot work with `--include-cluster-scoped-resources`, `--exclude-cluster-scoped-resources`, `--include-namespace-scoped-resources` and `--exclude-namespace-scoped-resources`.

* Exclude secrets from the backup.

  ```bash
  velero backup create <backup-name> --exclude-resources secrets
  ```

* Exclude secrets and rolebindings.

  ```bash
  velero backup create <backup-name> --exclude-resources secrets,rolebindings
  ```

### velero.io/exclude-from-backup=true

* Resources with the label `velero.io/exclude-from-backup=true` are not included in backup, even if it contains a matching selector label.

### --exclude-cluster-scoped-resources
Kubernetes cluster-scoped resources to exclude from the backup, formatted as resource.group, such as `storageclasses.storage.k8s.io`(use '*' for all resources). Cannot work with `--include-resources`, `--exclude-resources` and `--include-cluster-resources`. This parameter only works for backup, not for restore.

* Exclude StorageClasses and ClusterRoles from the backup.

  ```bash
  velero backup create <backup-name> --exclude-cluster-scoped-resources="storageclasses,clusterroles"
  ```

* Exclude all cluster-scoped resources from the backup.

  ```bash
  velero backup create <backup-name> --exclude-cluster-scoped-resources="*"
  ```

### --exclude-namespace-scoped-resources
Kubernetes namespace resources to exclude from the backup, formatted as resource.group, such as `deployments.apps`(use '*' for all resources). Cannot work with `--include-resources`, `--exclude-resources` and `--include-cluster-resources`. This parameter only works for backup, not for restore.

* Exclude all Deployments and ConfigMaps from the backup.

  ```bash
  velero backup create <backup-name> --exclude-namespace-scoped-resources="deployments.apps,configmaps"
  ```

* Exclude all namespace resources from the backup.

  ```bash
  velero backup create <backup-name> --exclude-namespace-scoped-resources="*"
  ```

## Resource policies
Velero provides resource policies to filter resources to do backup, which may contain `includeExcludePolicy` and `volumePolicies`.

### Creating resource policies

Below is the two-step of using resource policies in backup:
1. Creating resource policies configmap

   Users need to create one configmap in Velero install namespace from a YAML file that defined resource policies. The creating command would be like the below:
   ```bash
   kubectl create cm <configmap-name> --from-file <yaml-file> -n velero
   ```
2. Creating a backup reference to the defined resource policies

   Users create a backup with the flag `--resource-policies-configmap`, which will reference the current backup to the defined resource policies. The creating command would be like the below:
   ```bash
   velero backup create --resource-policies-configmap <configmap-name>
   ```
   This flag could also be combined with the other include and exclude filters above

### YAML template
The policies YAML config file would look like this:
- Yaml template:
    ```yaml
    # currently only supports v1 version
    version: v1
    # The filters in includeExcludePolicy work the same as the scoped resources filters in the Spec of a Backup 
    # NOTE: similar to scoped filters in Backup Spec, the includeExcludePolicy does not work with --include-resources, --exclude-resources and --include-cluster-resources filters in Backup.
    includeExcludePolicy:
      includedClusterScopedResources:
        - "crd"
        - "pv"
      excludedClusterScopedResources: []
      includedNamespaceScopedResources:
        - "pod"
        - "service"
        - "deployment"
        - "pvc"
      excludedNamespaceScopedResources:
        - "configmap"
        - "secret"
    volumePolicies:
    # each policy consists of a list of conditions and an action
    # we could have lots of policies, but if the resource matched the first policy, the latter will be ignored
    # each key in the object is one condition, and one policy will apply to resources that meet ALL conditions
    # NOTE: capacity or storageClass is suited for [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes), and pod [Volume](https://kubernetes.io/docs/concepts/storage/volumes) not support it.
    - conditions:
        # capacity condition matches the volumes whose capacity falls into the range
        capacity: "10,100Gi"
        # pv matches specific csi driver
        csi:
          driver: ebs.csi.aws.com
        # pv matches one of the storage class list
        storageClass:
          - gp2
          - standard
        # pvc matches specific phase(s)
        pvcPhase:
          - Pending
        # pvc matches specific volume mode(s)
        pvcVolumeMode:
          - Block
      action:
        type: skip
    - conditions:
        capacity: "0,100Gi"
        # nfs volume source with specific server and path (nfs could be empty or only config server or path)
        nfs:
          server: 192.168.200.90
          path: /mnt/data
      action:
        type: skip
    - conditions:
        nfs:
          server: 192.168.200.90
      action:
        type: fs-backup
    - conditions:
        # nfs could be empty which matches any nfs volume source
        nfs: {}
      action:
        type: skip
    - conditions:
        # csi could be empty which matches any csi volume source
        csi: {}
      action:
        type: snapshot
    - conditions:
        volumeTypes:
          - emptyDir
          - downwardAPI
          - configmap
          - cinder
      action:
        type: skip
    ```
### IncludeExcludePolicy
The `includeExcludePolicy` is used to filter resources based on the namespace-scoped and cluster-scoped resources. User can use it 
to define a group of filters and reuse them across different backups.

For example, user can configmap `my-policy` of resource policies with following content:
```yaml
version: v1
includeExcludePolicy:
  includedClusterScopedResources:
    - "crd"
  excludedClusterScopedResources: []
  includedNamespaceScopedResources: []
  excludedNamespaceScopedResources:
    - "configmap"
    - "event"
```
If the user creates a backup via command like
```bash
velero backup create <backup-name> --resource-policies-configmap my-policy --include-namespaces my-workload-ns
```
The backup will include all resources in namespace `my-workload-ns` except for `configmap` and `event`, and all CRDs in the cluster.

#### Limitations 
The `includeExcludePolicy` does not work with `--include-resources`, `--exclude-resources` and `--include-cluster-resources` filters in Backup.
If the user create the backup with command like `velero backup create my-backup --include-cluster-resources --include-namespaces workload-ns --resource-policies-configmap my-policy`
the backup will fail with status `FailedValidation`

The filters in `includeExcludePolicy` cannot include `*`.  Only specific resources can be set in the filters.

#### "includeExcludePolicy" .vs. filters in Backup Spec
User can use the includeExcludePolicy with other _scoped filters_ when creating a backup.  velero will combine the filters
when it's collecting the resources during the backup.  During this process the filters in the Backup Spec have higher priority.
For example, if the user use this command to create a backup, reusing the resource policies created in the previous example:
```bash
velero backup create <backup-name> --resource-policies-configmap my-policy --include-namespace-scoped-resources * --include-cluster-scoped-resources -apiservices --include-namespaces my-workload-ns
```
The backup will include all resources in namespace `my-workload-ns`, including `configmap` and `event`, and all CRDs and
`apiservices` in the cluster.

### VolumePolicy
VolumePolicy is a data structure to control how velero handle the volumes matching certain conditions.

#### Supported VolumePolicy actions
There are three actions supported via the VolumePolicy feature:
* skip: don't back up the action matching volume's data.
* snapshot: back up the action matching volume's data by the snapshot way.
* fs-backup: back up the action matching volumes' data by the fs-backup way.

#### Supported conditions

Currently, Velero supports the volume attributes listed below:
- capacity: matching volumes have the capacity that falls within this `capacity` range. The capacity value should include the lower value and upper value concatenated by commas, the unit of each value in capacity could be `Ti`, `Gi`, `Mi`, `Ki` etc, which is a standard storage unit in Kubernetes. And it has several combinations below:
  - "0,5Gi" or "0Gi,5Gi" which means capacity or size matches from 0 to 5Gi, including value 0 and value 5Gi
  - ",5Gi" which is equal to "0,5Gi"
  - "5Gi," which means capacity or size matches larger than 5Gi, including value 5Gi
  - "5Gi" which is not supported and will be failed in validating the configuration
- storageClass: matching volumes those with specified `storageClass`, such as `gp2`, `ebs-sc` in eks
- volume sources: matching volumes that used specified volume sources. Currently we support nfs or csi backend volume source
- pvcPhase: matching volumes based on the phase of their associated PVCs (Pending, Bound, Lost)
- pvcVolumeMode: matching volumes based on the volume mode of their associated PVCs (Filesystem, Block)

Velero supported conditions and format listed below:
- capacity
  ```yaml
  # match volume has the size between 10Gi and 100Gi
  capacity: "10Gi,100Gi"
  ```
- storageClass
  ```yaml
  # match volume has the storage class gp2 or ebs-sc
  storageClass:
    - gp2
    - ebs-sc
  ```
- volume sources (currently only support below format and attributes)
1. Specify the volume source name, the name could be `nfs`, `rbd`, `iscsi`, `csi` etc, but Velero only support `nfs` and `csi` currently.
    ```yaml
    # match any volume has nfs volume source
    nfs : {}
    # match any volume has csi volume source
    csi : {}
    ```

2. Specify details for the related volume source (currently we only support csi driver filter and nfs server or path filter)
    ```yaml
    # match volume has csi volume source and using `aws.efs.csi.driver`
    csi:
      driver: aws.efs.csi.driver 
    # match volume has nfs volume source and using below server and path
    nfs:
      server: 192.168.200.90
      path: /mnt/nfs
    ```
    For volume provisioned by [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes) support all above attributes, but for pod [Volume](https://kubernetes.io/docs/concepts/storage/volumes) only support filtered by volume source.

- volume types

  Support filter volumes by types
  ```yaml
  volumeTypes: 
    # matches volumes listed below
    - emptyDir
    - downwardAPI
    - configmap
    - cinder
  ```
   Volume types could be found in [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes) and pod [Volume](https://kubernetes.io/docs/concepts/storage/volumes)

- pvc Labels

  This condition filters volumes based on the labels on their associated PVCs. The condition is specified as a simple key/value mapping. The volume matches this condition if all the key/value pairs defined in the policy are present on the PVC. 
    ```yaml
    pvcLabels:
      environment: production
    ```

    Some examples:
  - Environment specific labels: Snapshot volumes whose associated PVC has the label `environment: production`.
      ```yaml
      volumePolicies:
      - conditions:
          pvcLabels:
            environment: production
        action:
          type: snapshot
      ```
  - Subset Matching: Even if the PVC contains extra labels, it will match as long as the required key/value pair is present. For example, if the PVC has:
      ```yaml
      labels:
        environment: production
        team: backend
      ```
    the following policy will match because it only requires `environment: production`:
      ```yaml
      volumePolicies:
      - conditions:
          pvcLabels:
            environment: production
        action:
          type: skip
      ```
  - Mismatched PVC Labels: If the policy requires both `environment: production` and `app: frontend`, but the PVC only has `environment: production`, the volume will not match.
      ```yaml
      volumePolicies:
      - conditions:
          pvcLabels:
            environment: production
            app: frontend
        action:
          type: skip
      ```

- pvc Phase

  This condition filters volumes based on the phase of their associated PVCs. The condition is specified as a list of phases to match. The volume matches this condition if the PVC's phase matches any of the phases in the list. Supported phases are: `Pending`, `Bound`, and `Lost`.
    ```yaml
    pvcPhase:
      - Pending
    ```

    Some examples:
  - Skip Pending PVCs: Skip backup of volumes whose associated PVC is in `Pending` phase (useful for PVCs that haven't been bound to a PV yet).
      ```yaml
      volumePolicies:
      - conditions:
          pvcPhase:
            - Pending
        action:
          type: skip
      ```
  - Skip multiple phases: Skip backup of volumes whose associated PVC is either in `Pending` or `Lost` phase.
      ```yaml
      volumePolicies:
      - conditions:
          pvcPhase:
            - Pending
            - Lost
        action:
          type: skip
      ```
  - Backup only Bound PVCs: Only backup volumes whose associated PVC is in `Bound` phase.
      ```yaml
      volumePolicies:
      - conditions:
          pvcPhase:
            - Bound
        action:
          type: snapshot
      ```
  - Combine with other conditions: You can combine PVC phase conditions with other conditions like storage class or labels.
      ```yaml
      volumePolicies:
      - conditions:
          pvcPhase:
            - Pending
          storageClass:
            - gp2
        action:
          type: skip
      ```

- pvc VolumeMode

  This condition filters volumes based on the volume mode of their associated PVCs. The condition is specified as a list of volume modes to match. The volume matches this condition if the PVC's volume mode matches any of the volume modes in the list. Supported volume modes are: `Filesystem` and `Block`. PVCs without an explicit volume mode are treated as `Filesystem`, matching the Kubernetes default.
    ```yaml
    pvcVolumeMode:
      - Block
    ```

    Some examples:
  - Skip Block PVCs: Skip backup of volumes whose associated PVC uses `Block` volume mode.
      ```yaml
      volumePolicies:
      - conditions:
          pvcVolumeMode:
            - Block
        action:
          type: skip
      ```
  - Match multiple volume modes: Apply an action to volumes whose associated PVC uses either `Filesystem` or `Block` volume mode.
      ```yaml
      volumePolicies:
      - conditions:
          pvcVolumeMode:
            - Filesystem
            - Block
        action:
          type: snapshot
      ```
  - Combine with other conditions: You can combine PVC volume mode conditions with other conditions like PVC phase, storage class, or labels.
      ```yaml
      volumePolicies:
      - conditions:
          pvcVolumeMode:
            - Block
          pvcPhase:
            - Bound
        action:
          type: snapshot
      ```



### Resource policies rules
- Velero already has lots of include or exclude filters. the resource policies are the final filters after others include or exclude filters in one backup processing workflow. So if use a defined similar filter like the opt-in approach to backup one pod volume but skip backup of the same pod volume in resource policies, as resource policies are the final filters that are applied, the volume will not be backed up.
- If volume resource policies conflict with themselves the first matched policy will be respected when many policies are defined.

#### VolumePolicy priority with existing filters
* [Includes filters](#includes) and [Excludes filters](#excludes) have the highest priority. The filtered-out resources by them cannot reach to the VolumePolicy.
* The VolumePolicy has the second priority. It supersedes all the other filters.
* The filesystem volume backup opt-in/opt-out way has the third priority.
* The `backup.Spec.SnapshotVolumes` has the fourth priority.

#### Support for `fs-backup` and `snapshot` actions via volume policy feature
- Starting from velero 1.14, the volume policy feature has been extended to support more actions like `fs-backup` and `snapshot`.
- This feature only extends the action aspect of volume policy and not criteria aspect, the criteria components as described above remain the same.
- When we are using the volume policy approach for backing up the volumes then the volume policy criteria and action need to be specific and explicit, 
there is no default behaviour, if a volume matches fs-backup action then fs-backup method will be used for that volume and similarly if the volume matches
the criteria for snapshot action then the snapshot workflow will be used for the volume backup.
- Another thing to note is that the volume policy workflow uses the legacy opt-in/opt-out approach as a fallback option. For instance, the user specifies
a volume policy but for a particular volume included in the backup there are no actions(fs-backup/snapshot) matching in the volume policy for that volume,
in such a scenario the legacy approach will be used for backing up the particular volume. Considering everything, the recommendation would be to use only one
of the approaches to backup volumes - volume policy approach or the opt-in/opt-out legacy approach, and not mix them for clarity.
- Snapshot action can either be a native snapshot or a csi snapshot or csi snapshot datamover, as is the case with the current flow where velero itself makes the decision based on the backup CR's existing options.
- The `snapshot` action via Volume Policy has higher priority if there is a `snapshot` action matching for a particular volume, this volume would be backed up via snapshot irrespective of the value of `backup.Spec.SnapshotVolumes`.
- If for a particular volume there is no `snapshot` matching action then the volume will be backed up via snapshot given that `backup.Spec.SnapshotVolumes` is not explicitly set to false.
- Let's see some examples on how to use the volume policy feature for `fs-backup` and `snapshot` action purposes:

We will use a simple application example in which there is an application pod which has 2 volumes: 
- Volume 1 has associated Persistent Volume Claim 1 and Persistent Volume 1 which uses storage class `gp2-csi`
- Volume 2 has associated Persistent Volume Claim 2 and Persistent Volume 2 which uses storage class `gp3-csi`

Now lets go through some example uses-cases and their outcomes:

***Example 1: User wants to use `fs-backup` action for backing up the volumes having storage class as `gp2-csi`*** 
1. User specifies the volume policy as follows:
```yaml
version: v1
volumePolicies:
- conditions:
    storageClass:
    - gp2-csi
  action:
    type: fs-backup
```

2. User creates a backup using this volume policy
3. The outcome would be that velero would perform `fs-backup` operation ***only*** on `Volume 1` as ***only*** `Volume 1` satisfies the criteria for `fs-backup` action.

***Example 2: User wants to use `snapshot` action for backing up the volumes having storage class as `gp2-csi`***
1. User specifies the volume policy as follows:
```yaml
version: v1
volumePolicies:
- conditions:
    storageClass:
    - gp2-csi
  action:
    type: snapshot
```
2. User creates a backup using this volume policy
3. The outcome would be that velero would perform `snapshot` operation ***only*** on `Volume 1` as ***only*** `Volume 1` satisfies the criteria for `snapshot` action.

***Example 3: User wants to use `snapshot` action for backing up the volumes having storage class as `gp2-csi` and wants to use `fs-backup` action for backing up the volumes having storage class as `gp3-csi`***
1. User specifies the volume policy as follows:
```yaml
version: v1
volumePolicies:
- conditions:
    storageClass:
    - gp2-csi
  action:
    type: snapshot
- conditions:
    storageClass:
    - gp3-csi
  action:
    type: fs-backup
```
2. User creates a backup using this volume policy
3. The outcome would be that velero would perform `snapshot` operation ***only*** on `Volume 1` as ***only*** `Volume 1` satisfies the criteria for `snapshot` action. Also, velero would perform `fs-backup` operation ***only*** on `Volume 2` as ***only*** `Volume 2` satisfies the criteria for `fs-backup` action.

***Example 4: User wants to use `snapshot` action for backing up the volumes having storage class as `gp3-csi` and at the same time also annotates the pod to use opt-in fs-backup legacy approach for Volume 1***
1. User specifies the volume policy as follows and also annotates the pod with `backup.velero.io/backup-volumes=Volume 1`
```yaml
version: v1
volumePolicies:
- conditions:
    storageClass:
    - gp3-csi
  action:
    type: snapshot
```
2. User creates a backup using this volume policy
3. The outcome would be that velero would perform `snapshot` operation for `Volume 2` as it matches the action criteria and velero would also perform the `fs-backup` operation for `Volume-1` via the legacy annotations based fallback approach as there is no matching action for `Volume-1`  

***Example 5: User wants to use `fs-backup` action for backing up the volumes having storage class as `gp2-csi` and at the same time also specifies `defaultVolumesToFSBackup: true` (fallback option for no action matching volumes)***
1. User specifies the volume policy as follows and specifies `defaultVolumesToFSBackup: true`:
```yaml
version: v1
volumePolicies:
- conditions:
    storageClass:
    - gp2-csi
  action:
    type: fs-backup
```
2. User creates a backup using this volume policy
3. The outcome would be that velero would perform `fs-backup` operation on both the volumes
   - `fs-backup` on `Volume 1` because `Volume 1` satisfies the criteria for `fs-backup` action. 
   - Also, for Volume 2 as no matching action was found so legacy approach will be used as a fallback option for this volume (`fs-backup` operation will be done as `defaultVolumesToFSBackup: true` is specified by the user).
