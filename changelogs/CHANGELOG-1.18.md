## v1.18.3

### Download
https://github.com/vmware-tanzu/velero/releases/tag/v1.18.3

### Container Image
`velero/velero:v1.18.3`

### Documentation
https://velero.io/docs/v1.18/

### Upgrading
https://velero.io/docs/v1.18/upgrade-to-1.18/

### All Changes
  * Avoid duplicated InitContainer names generated in velero install CLI. (#10396, @blackpiglet)
  * Bound WaitRestoreExecHook polling with resourceTimeout to avoid an infinite wait when restore exec hooks never complete. (#10394, @nitishmalang)
  * fix log format string mismatches that produce wrong or mangled output (#10392, @samay43)
  * Skip DeleteSnapshot when ProviderSnapshotID is empty (#10381, @kaovilai)
  * Fail backup validation when built-in data mover is requested but no node-agent pods are running (#10360, @Joeavaikath)
  * Fix issue #10341, avoid mutating the cached node-agent LoadAffinity so the OS node selector term is not appended repeatedly to data mover pods (#10348, @shubham-pampattiwar)
  * Fix PodVolumeBackup metadata loss on fs-backup timeout, which caused all fs-backup volumes to become unrestorable (#9999, @shubham-pampattiwar)
  * Fix repo connection contest of the two repositories with the same storage type (#10377, @Lyndon-Li)
  * Only sync finished backups from object storage (#10347, @chlins)
  * Support copying namespace-scoped secrets and configmaps for backup and restore PVC provisioning to enable datamover backup/restore of encrypted CSI volumes (#10335, @shubham-pampattiwar)
  * Remove PVC and PV inclusion check during creating PVR. (#10319, @blackpiglet)
  * Fix a potential deadlock when resultsLock is held by the informer but blocked on resChan because the early quit of RestorePodVolumes (#10263, @Lyndon-Li)
  * Fix restore-wait init container ignoring pod-level securityContext, falling back to hardcoded runAsUser 1000 instead of the workload's own uid/gid, causing fs-backup restores to deadlock at Init:0/1 on owner-restricted volumes (#10224, @kaovilai)
  * Add use guide for restore fine-grained filters via resource policy (#10164, @adam-jian-zhang)
  * Add restore.velero.io/must-include-additional-items so RestoreItemActions can opt in to bypassing global restore filters for AdditionalItems (mirrors the backup-side must-include annotation; no default behavior change for existing restores/plugins). Stop force-including VolumeSnapshotContents via resourceMustHave on every restore; CSI VolumeSnapshot/PVC RestoreItemActions now set restore.velero.io/must-include-additional-items so bound snapshot dependencies are restored only when their parent is restored (fixes #9957) (#10101, @adam-jian-zhang)
  * User guide for backup fine-grained filters via resource policy, and add set based label selectors for fine-grained filters (#10072, @adam-jian-zhang)
  * Fix issue #10032, prioritize exact namespace match in restore (#10052, @adam-jian-zhang)
  * Fix issue #9997, cancel ongoing PVB on timeout and wait for all PVBs to terminal state (#10039, @Lyndon-Li)
  * Add fine-grained filters for restore via resource policy, introduced resourcePolicy field for restoreSpec, which contains ClusterScopedFilterPolicy and NamespacedFilterPolicy section (#10015, @adam-jian-zhang)
  * Add support for matching PVCs by volume mode and access mode in resource policies, and introduce the `--global-backup-volume-policies-configmap` server flag to merge cluster-wide backup volume policies into every backup. (#10012, @chlins)
  * Add fine-grained filters for backup via resource policy, introduced ClusterScopedFilterPolicy and NamespacedFilterPolicy section for resource policy (#10011, @adam-jian-zhang)
  * Add operation context to user-facing error messages in CR statuses and CLI output (#10474, @chlins)
  * Fix issue 10454, enforce resource filter policies in memory in stage 1 to fix wildcard namespace bypassing issue (#10473, @adam-jian-zhang)

## v1.18.2

### Download
https://github.com/vmware-tanzu/velero/releases/tag/v1.18.2

### Container Image
`velero/velero:v1.18.2`

### Documentation
https://velero.io/docs/v1.18/

### Upgrading
https://velero.io/docs/v1.18/upgrade-to-1.18/

### All Changes
  * Skip VGS cleanup when backup did not use VolumeGroupSnapshots (#9900, @shubham-pampattiwar)
  * Fix backup performance regression when using includedNamespaces ["*"] by restoring cross-namespace API listing optimization (#9870, @shubham-pampattiwar)
  * Fix DataUploadDeleteAction creating snapshot-info ConfigMaps labeled with the wrong backup name when a DataUpload CR from another backup is incidentally captured in the backup tarball, which caused Kopia snapshots to be leaked in object storage on expiry of the real owning backup. (#9842, @christian-schlichtherle)

## v1.18.1

### Download
https://github.com/vmware-tanzu/velero/releases/tag/v1.18.1

### Container Image
`velero/velero:v1.18.1`

### Documentation
https://velero.io/docs/v1.18/

### Upgrading
https://velero.io/docs/v1.18/upgrade-to-1.18/

### All Changes
  * Fix wildcard expansion when includes is empty and excludes has wildcards (#9743, @Joeavaikath)
  * Backporting PR #9700 and #9693, fix issue #9699, add a 2-second gap between temporary CSI VolumeSnapshotContent create and delete operations. Enhance backup deletion logic to handle tarball download failures (#9731, @priyansh17)
  * Fix issue #9703, fix CSI PVC Backup Plugin list options to only list in installed namespace (#9708, @adam-jian-zhang)
  * Bump external-snapshotter to v8.4.0 and migrate VolumeGroupSnapshot API from v1beta1 to v1beta2 for Kubernetes 1.34+ compatibility (#9706, @shubham-pampattiwar)
  * Fix issue #9681, fix restores and podvolumerestores list options to only list in installed namespace (#9696, @adam-jian-zhang)
  * Fix issue #9659, in the case that PVB/PVR/DU/DD is cancelled before the data path is really started, call EndEvent to prevent data mover pod from crashing because of delay event distribution (#9672, @Lyndon-Li)
  * Fix issue #9626, let go for uninitialized repo under readonly mode (#9669, @Lyndon-Li)
  * Fix issue #9460, flush buffer before data mover completes (#9610, @Lyndon-Li)
  * Fix issue #9475, use node-selector instead of nodName for generic restore (#9609, @Lyndon-Li)
  * Fix issue #9496, support customized host os (#9606, @Lyndon-Li)
  * Fix issue #9343, include PV topology to data mover pod affinities (#9594, @Lyndon-Li)
  * Fix VolumeGroupSnapshot restore failure with Ceph RBD CSI driver by creating stub VolumeGroupSnapshotContent during restore and looking up VolumeSnapshotClass by driver for credential support (#9687, @shubham-pampattiwar)
  * Add custom action type to volume policies (#9678, @sseago)
  * Fix issue #9666, fix node-agent node detection in multiple instances scenario (#9671, @adam-jian-zhang)
  * Add check for file extraction from tarball. (#9661, @blackpiglet)
  * Fix issue #9636, fix configmap lookup in non-default namespaces (#9637, @adam-jian-zhang)
  * Optimize VSC handle readiness polling for VSS backups (#9629, @sseago)
  * Fix DBR stuck when CSI snapshot no longer exists in cloud provider (#9604, @shubham-pampattiwar)
  * If BIA return updateObj with SkipFromBackupAnnotation, treat it as skip the resource from backup. (#9597, @blackpiglet)
  * Add ephemeral storage limit and request support for data mover and maintenance job (#9596, @blackpiglet)
  * Remove wildcard check from getNamespacesToList. (#9587, @blackpiglet)


## v1.18

### Download
https://github.com/vmware-tanzu/velero/releases/tag/v1.18.0

### Container Image
`velero/velero:v1.18.0`

### Documentation
https://velero.io/docs/v1.18/

### Upgrading
https://velero.io/docs/v1.18/upgrade-to-1.18/

### Highlights
#### Concurrent backup
In v1.18, Velero is capable to process multiple backups concurrently. This is a significant usability improvement, especially for multiple tenants or multiple users case, backups submitted from different users could run their backups simultaneously without interfering with each other.  

Check design https://github.com/vmware-tanzu/velero/blob/main/design/Implemented/concurrent-backup-processing.md for more details.

#### Cache volume for data movers
In v1.18, Velero allows users to configure cache volumes for data mover pods during restore for CSI snapshot data movement and fs-backup. This brings below benefits:
- Solve the problem that data mover pods fail to when pod's ephemeral disk is limited
- Solve the problem that multiple data mover pods fail to run concurrently in one node when the node's ephemeral disk is limited
- Working together with backup repository's cache limit configuration, cache volume with appropriate size helps to improve the restore throughput

Check design https://github.com/vmware-tanzu/velero/blob/main/design/Implemented/backup-repo-cache-volume.md for more details.

#### Incremental size for data movers
In v1.18, Velero allows users to observe the incremental size of data movers backups for CSI snapshot data movement and fs-backup, so that users could visually see the data reduction due to incremental backup.

#### Wildcard support for namespaces
In v1.18, Velero allows to use Glob regular expressions for namespace filters during backup and restore, so that users could filter namespaces in a batch manner.

#### VolumePolicy for PVC phase
In v1.18, Velero VolumePolicy supports actions by PVC phase, which help users to do special operations for PVCs with a specific phase, e.g., skip PVCs in Pending/Lost status from the backup.  

#### Scalability and Resiliency improvements
##### Prevent Velero server OOM Kill for large backup repositories
In v1.18, some backup repository operations are delay executed out of Velero server, so Velero server won't be OOM Killed.

#### Performance improvement for VolumePolicy
In v1.18, VolumePolicy is enhanced for large number of pods/PVCs so that the performance is significantly improved.

#### Events for data mover pod diagnostic
In v1.18, events are recorded into data mover pod diagnostic, which allows user to see more information for troubleshooting when the data mover pod fails.

### Runtime and dependencies
Golang runtime: 1.25.7  
kopia: 0.22.3

### Limitations/Known issues

### Breaking changes
#### Deprecation of PVC selected node feature
According to [Velero deprecation policy](https://github.com/vmware-tanzu/velero/blob/main/GOVERNANCE.md#deprecation-policy), PVC selected node feature is deprecated in v1.18. Velero could appropriately handle PVC's selected-node annotation, so users don't need to do anything particularly.

### All Changes
* Remove backup from running list when backup fails validation (#9498, @sseago)
* Maintenance Job only uses the first element of the LoadAffinity array (#9494, @blackpiglet)
* Fix issue #9478, add diagnose info on expose peek fails (#9481, @Lyndon-Li)
* Add Role, RoleBinding, ClusterRole, and ClusterRoleBinding in restore sequence. (#9474, @blackpiglet)
* Add maintenance job and data mover pod's labels and annotations setting. (#9452, @blackpiglet)
* Fix plugin init container names exceeding DNS-1123 limit (#9445, @mpryc)
* Add PVC-to-Pod cache to improve volume policy performance (#9441, @shubham-pampattiwar)
* Remove VolumeSnapshotClass from CSI B/R process. (#9431, @blackpiglet)
* Use hookIndex for recording multiple restore exec hooks. (#9366, @blackpiglet)
* Sanitize Azure HTTP responses in BSL status messages (#9321, @shubham-pampattiwar)
* Remove labels associated with previous backups (#9206, @Joeavaikath)
* Add VolumePolicy support for PVC Phase conditions to allow skipping Pending PVCs (#9166, @claude)
* feat: Enhance BackupStorageLocation with Secret-based CA certificate support (#9141, @kaovilai)
* Add `--apply` flag to `install` command, allowing usage of Kubernetes apply to make changes to existing installs (#9132, @mjnagel)
* Fix issue #9194, add doc for GOMAXPROCS behavior change (#9420, @Lyndon-Li)
* Apply volume policies to VolumeGroupSnapshot PVC filtering (#9419, @shubham-pampattiwar)
* Fix issue #9276, add doc for cache volume support (#9418, @Lyndon-Li)
* Add Prometheus metrics for maintenance jobs (#9414, @shubham-pampattiwar)
* Fix issue #9400, connect repo first time after creation so that init params could be written (#9407, @Lyndon-Li)
* Cache volume for PVR (#9397, @Lyndon-Li)
* Cache volume support for DataDownload (#9391, @Lyndon-Li)
* don't copy securitycontext from first container if configmap found (#9389, @sseago)
* Refactor repo provider interface for static configuration (#9379, @Lyndon-Li)
* Fix issue #9365, prevent fake completion notification due to multiple update of single PVR (#9375, @Lyndon-Li)
* Add cache volume configuration (#9370, @Lyndon-Li)
* Track actual resource names for GenerateName in restore status (#9368, @shubham-pampattiwar)
* Fix managed fields patch for resources using GenerateName (#9367, @shubham-pampattiwar)
* Support cache volume for generic restore exposer and pod volume exposer (#9362, @Lyndon-Li)
* Add incrementalSize to DU/PVB for reporting new/changed size (#9357, @sseago)
* Add snapshotSize for DataDownload, PodVolumeRestore (#9354, @Lyndon-Li)
* Add cache dir configuration for udmrepo (#9353, @Lyndon-Li)
* Fix the Job build error when BackupReposiotry name longer than 63. (#9350, @blackpiglet)
* Add cache configuration to VGDP (#9342, @Lyndon-Li)
* Fix issue #9332, add bytesDone for cache files (#9333, @Lyndon-Li)
* Fix typos in documentation (#9329, @T4iFooN-IX)
* Concurrent backup processing (#9307, @sseago)
* VerifyJSONConfigs verify every elements in Data. (#9302, @blackpiglet)
* Fix issue #9267, add events to data mover prepare diagnostic (#9296, @Lyndon-Li)
* Add option for privileged fs-backup pod (#9295, @sseago)
* Fix issue #9193, don't connect repo in repo controller (#9291, @Lyndon-Li)
* Implement concurrency control for cache of native VolumeSnapshotter plugin. (#9281, @0xLeo258)
* Fix issue #7904, remove the code and doc for PVC node selection (#9269, @Lyndon-Li)
* Fix schedule controller to prevent backup queue accumulation during extended blocking scenarios by properly handling empty backup phases (#9264, @shubham-pampattiwar)
* Fix repository maintenance jobs to inherit allowlisted tolerations from Velero deployment (#9256, @shubham-pampattiwar)
* Implement wildcard namespace pattern expansion for backup namespace includes/excludes. This change adds support for wildcard patterns (*, ?, [abc], {a,b,c}) in namespace includes and excludes during backup operations (#9255, @Joeavaikath)
* Protect VolumeSnapshot field from race condition during multi-thread backup (#9248, @0xLeo258)
* Update AzureAD Microsoft Authentication Library to v1.5.0 (#9244, @priyansh17)
* Get pod list once per namespace in pvc IBA (#9226, @sseago)
* Fix issue #7725, add design for backup repo cache configuration (#9148, @Lyndon-Li)
* Fix issue #9229, don't attach backupPVC to the source node (#9233, @Lyndon-Li)
* feat: Permit specifying annotations for the BackupPVC (#9173, @clementnuss)