## v1.19

### Download
https://github.com/velero-io/velero/releases/tag/v1.19.0

### Container Image
`velero/velero:v1.19.0`

### Documentation
https://velero.io/docs/v1.19/

### Upgrading
https://velero.io/docs/v1.19/upgrade-to-1.19/

### Highlights

#### Block data mover

Velero 1.19 introduces a block data mover (velero-block) for CSI snapshot data movement, enabling block-level backup and restore for both file system and block volumes backed by block storage. It integrates with the Kubernetes CSI Changed Block Tracking (CBT) API (https://kubernetes.io/blog/2025/09/25/csi-changed-block-tracking/) to transfer only changed blocks during incremental backups and restores with compatible CSI drivers, avoiding file system scanning overhead and improving backup and restore efficiency. For more information, check Velero document https://velero.io/docs/v1.19/csi-snapshot-data-movement/.    

#### Volume data in-place restore

Velero 1.19 introduces volume data in-place restore, allowing backup data to be restored directly into existing volumes. It supports both full and incremental restores for CSI snapshot data movement (velero-fs and velero-block) and File System Backup, with incremental restores skipping unchanged data to reduce data transfer and recovery time. It also supports clone-and-restore workflows, where users first clone a volume from a snapshot and then perform an in-place restore into the cloned volume. For more information, check Velero document https://velero.io/docs/v1.19/volume-data-inplace-restore/.  

#### Fine-grained filters

Velero 1.19 introduces fine-grained filters for backups and restores through ResourcePolicy ConfigMaps. Users can define per-namespace and per-resource-kind rules with independent label selectors and resource name patterns, providing more precise control over which namespaced and cluster-scoped resources are backed up or restored. For more information, check Velero document https://velero.io/docs/v1.19/fine-grained-backup-filters/ and https://velero.io/docs/v1.19/fine-grained-restore-filters/.  

#### Namespace selection by labels

Velero 1.19 supports dynamically including or excluding namespaces from backups based on namespace labels through ResourcePolicy ConfigMaps. This simplifies backup and schedule management by automatically selecting matching namespaces when each backup starts, without maintaining explicit namespace lists. For more information, check Velero document https://velero.io/docs/v1.19/resource-filtering/#namespace-selection-by-label-backup-only.   

#### Global volume policy

Velero 1.19 introduces global volume policies, allowing administrators to configure default volume backup rules for all backups through a shared ConfigMap. Backup-specific volume policies take precedence over global rules, providing consistent defaults while allowing customization for individual backups. For more information, check Velero document https://velero.io/docs/v1.19/resource-filtering/#global-backup-volume-policies.  

#### Custom action type in volume policy

Velero 1.19 adds a `custom` action type to volume policies, allowing third-party BackupItemAction plugins to handle volume backups using custom methods. Users can select volumes for custom handling and pass plugin-specific parameters alongside existing snapshot and file system backup policies. For more information, check the Velero document https://velero.io/docs/v1.19/resource-filtering/#custom-volume-policy-actions.  

#### Default restore resource modifier

Velero 1.19 allows administrators to configure a default restore resource modifier through a shared ConfigMap, automatically applying common resource transformations during restores. Individual restores can override the default with their own modifier or explicitly skip it, simplifying consistent restore customization. For more information, check the Velero document https://velero.io/docs/v1.19/restore-resource-modifiers/#default-resource-modifiers.  

### Runtime And Dependencies
Golang runtime: 1.27.3  
kopia: 0.23.1

### Limitations/Known Issues

#### Block data mover gap on snapshot preservation

Block data mover incremental backups and restores support CSI drivers that can compute changed blocks without keeping the parent backup's snapshot; the [CSI Changed Block Tracking KEP](https://github.com/kubernetes/enhancements/tree/master/keps/sig-storage/3314-csi-changed-block-tracking) allows drivers either way.  
Drivers that need the parent snapshot to still exist, for example Ceph RBD, are not supported in 1.19.0: their incremental backups read all allocated blocks instead of only the changed ones, and incremental restores run as full restores.  
Support for these drivers is tracked in https://github.com/velero-io/velero/issues/10743.  

#### CSI snapshot data movement restore limitation on pods with both Immediate and WaitForFirstConsumer PVCs
CSI snapshot data movement restoring a pod that has both Immediate and WaitForFirstConsumer PVCs may stall, and the restore goes PartiallyFailed. If you are not running a multiple-zone cluster with storage topologies, you could work around this issue by setting the node-agent configuration `restorePVC.ignoreDelayBinding: true`; otherwise, you should avoid mounting both Immediate and WaitForFirstConsumer PVCs to a single pod.  

### Breaking Changes

#### GitHub repository change

Velero's code repository and Go module path changed from github.com/vmware-tanzu/velero to github.com/velero-io/velero. Downstream projects that import Velero as a library must update their imports and go.mod. Container images and CLI usage are unchanged.   

#### Restic removal

Restic path for fs-backup is completely removed in 1.19. Therefore, Velero 1.19 marks restores from backups with Restic path as FailedValidation; backup sync ignores backups with Restic path, so they won't appear in the cluster even though they are kept as is in the backup storage; if there are existing backups with Restic path in the cluster, after upgrade to 1.19, deletion request of these backups will fail.   

#### Default prepare queue length

A default prepare queue length (5) is set for data movers, so that pending data mover pods won't occupy large amount of resources from the cluster. In the previous versions there is no limit. For more information about data mover prepare queue length, check Velero document https://velero.io/docs/v1.19/node-agent-prepare-queue-length/.  

#### Hashing algorithm for Kopia repository

Kopia repository's hashing algorithm is changed from `BLAKE2B-256-128` to `HMAC-SHA256-128` for security compliance. This change applies to new repositories only, existing repositories still use `BLAKE2B-256-128`.  

#### User-provided credentials file paths ignored

For security compliance, Velero 1.19 ignores user-provided `spec.config.credentialsFile` values in BackupStorageLocation (BSL) and VolumeSnapshotLocation (VSL). If you previously configured credentials this way, store them in a Kubernetes Secret in the Velero namespace and reference it using `spec.credential.name` and `spec.credential.key`.  

### All Changes

  * Remove the possible nil object from object list retrieved from BSL (#10771, @Lyndon-Li)
  * Revert #9943: include pkg/apis in the root Velero Go module again. (#10770, @blackpiglet)
  * Ignore incomplete PVB for backup sync to avoid unexpected execution from tampered data from BSL (#10769, @Lyndon-Li)
  * Run the FSBackup backup deletion case on kind in CI when CSI is enabled (#10764, @krishhna24)
  * Restic deprecation: ignore invalid PVB uploader for backup sync, backup delete and restore (#10762, @Lyndon-Li)
  * Add 1.19 release notes (#10761, @Lyndon-Li)
  * Add doc for custom action in volume policy (#10760, @Lyndon-Li)
  * Move internal/resourcemodifiers to pkg/resourcemodifiers for plugin reuse (#10759, @adam-jian-zhang)
  * Rollback creating retain snapshot according to snapshotClass for data movers and add the doc for snapshotClass selection (#10753, @Lyndon-Li)
  * Run the BSL deletion snapshot case on kind in CI when CSI is enabled (#10747, @krishhna24)
  * Fix issue #10724, add parallel upload/download control for Velero fs and block data mover (#10740, @Lyndon-Li)
  * Treat a kopia snapshot not found after a repo refresh as deleted, so an interrupted backup deletion can be retried (#10700, @kaovilai)
  * Fix block data mover restore not zeroing unallocated ranges, BLKZEROOUT ioctl used the wrong request number (BLKPBSZGET) (#10698, @kaovilai)
  * Let velero backup logs and velero restore logs fetch logs while the backup or restore is Finalizing or FinalizingPartiallyFailed (#10684, @MaxFreedomPollard)
  * Run the Kibishii file system backup cases on kind in CI when CSI is enabled (#10680, @krishhna24)
  * Run the namespace-mapping cases with real volumes on kind when CSI is enabled (#10679, @krishhna24)
  * Match the last CSI feature check against the comma-separated --features list (#10678, @krishhna24)
  * Fail the e2e suite when a Ginkgo label filter selects no specs (#10674, @krishhna24)
  * Recognize the GCS object-not-found error (storage: object doesn't exist) as a permanent not-found condition during backup deletion, so the Backup no longer stays stuck in Deleting when the tarball is already gone (#10673, @sapnasingh4852-source)
  * Fix restore resource priorities aliasing that can skip restoring resources (#10665, @abd-ulbasit)
  * Match --features as the comma-separated list it is when checking for EnableCSI (#10661, @krishhna24)
  * Drop the SKIP_KIND e2e label, which no filter reads (#10660, @krishhna24)
  * Run the Kibishii snapshot cases on kind in CI when CSI is enabled (#10658, @krishhna24)
  * Point Kibishii at the kind-csi overlay when CSI is enabled on kind (#10657, @krishhna24)
  * Reuse cached Go modules across CI jobs (#10656, @MannXo)
  * Clarify client and server version mismatch warnings with compatibility guidance and the component to update. (#10655, @Harshil-1603)
  * Add a make target that runs the e2e tests against a kind cluster and MinIO it creates itself (#10652, @krishhna24)
  * Introduce "AllowExistingVolumeMismatch" in restore to support bypassing same volume handle pre-flight checking (#10651, @ywk253100)
  * Update for "vmware-tanzu" to "velero-io" update (#10650, @reasonerjt)
  * Makefile: fix make serve-docs on buildx setups (#10649, @Joeavaikath)
  * Run the CSI e2e cases on kind in CI (#10644, @krishhna24)
  * Document the StorageClass flag for CSI e2e on kind instead of editing shared test data (#10643, @krishhna24)
  * Update legacy vmware-tanzu repository issue URLs in velero bug command and templates (#10640, @abhayrajjais01)
  * Fix broken anchor links in the main docs (#10638, @SatvikMishra08)
  * Fix issue #10614, fix the repo metadata cache duration and stale problem (#10637, @Lyndon-Li)
  * Correct the comment explaining why the kind backup cases are skipped (#10636, @krishhna24)
  * Fix concurrent map writes crash in pvcPvMap when multiple ItemBlock workers back up PVs at the same time (#10635, @shubham-pampattiwar)
  * Fix the MinIO image cache key in the kind e2e workflow so the cached image is found (#10631, @krishhna24)
  * Document running the CSI e2e cases on a kind cluster (#10630, @krishhna24)
  * Propagate caller context during backup request preparation and snapshot location validation in backup controller (#10621, @abhayrajjais01)
  * Align error messages in uninstall command with Velero lowercase standards (#10619, @abhayrajjais01)
  * Fixed broken links to contributor guidance and code ownership in the documentation. (#10617, @git-jxj)
  * Defer VGS cleanup until backup finalization (#10612, @prasadjoshi12)
  * Regenerate CRD manifests to include the status.activities field added by #10552 (#10608, @kaovilai)
  * Use GetGlobalResourcePolicies to replace GetResourcePoliciesFromBackup. (#10607, @blackpiglet)
  * Propagate caller context in backup repository BSL invalidation handler (#10605, @abhayrajjais01)
  * Detect the VolumeGroupSnapshot API version (v1/v1beta2/v1beta1) at runtime so VGS backup and restore work across clusters serving different versions (#10601, @shubham-pampattiwar)
  * Add e2e coverage for CSI VolumeGroupSnapshot backups (#10598, @krishhna24)
  * Add hack/install-csi-hostpath.sh to install CSI snapshot support on a kind cluster (#10596, @krishhna24)
  * Verify CSI snapshots on kind in the e2e snapshot checks (#10593, @krishhna24)
  * Make the e2e StorageClass definitions configurable via --storage-class-file and --storage-class-file-2 (#10588, @krishhna24)
  * Fix the PodVolumeBackup Node print column to read the node from spec instead of status (#10585, @officialasishkumar)
  * Add kind VolumeGroupSnapshotClass e2e test data (#10582, @krishhna24)
  * Fix issue #10576, change hashing algorithm to HMAC-SHA256-128 for kopia repo (#10579, @Lyndon-Li)
  * Fix issue #10575, enable VGDP soothing by default and set queue length as 5 (#10578, @Lyndon-Li)
  * Fix panic in ChangeImageNameAction when a restored container image field is not a string (#10574, @Kaizhe)
  * Warn when the volume data of an existing PVC backed up by snapshot is not restored (#10570, @chlins)
  * Add e2e test coverage for namespace selection by label in resource policy (#10565, @kaovilai)
  * Dedup the entries in backuprequest.spec.excludeNamespaces (#10562, @reasonerjt)
  * Align block and kopia snapshot error messages with Velero lowercase standards (#10558, @abhayrajjais01)
  * Propagate caller context in repository manager Forget/BatchForget, and fix BatchForget returning a nil error instead of the real connection error (#10554, @pujitha24)
  * Add configurable tolerations to the repository maintenance job ConfigMap (global section); deployment tolerations matching the third-party allowlist (kubernetes.azure.com/scalesetpriority, CriticalAddonsOnly) and Windows toleration continue to be inherited and merged with configured tolerations. (#10553, @blackpiglet)
  * Fail the in-place restore pre-flight check when the backed-up pod exists (#10550, @chlins)
  * Fix velero schedule create silently dropping --annotations (#10549, @shoemoney)
  * Reset the PVC binding information in pvc_action.go when it references PVB. (#10538, @blackpiglet)
  * Add doc for block data mover (#10537, @Lyndon-Li)
  * Propagate context to node client in GetNodeOS (#10536, @abhayrajjais01)
  * Fix issue #10429, sync the calls to IsConstrained (#10533, @Lyndon-Li)
  * Identify the backed-up volume by CSI volume handle in the in-place restore pre-flight check (#10530, @chlins)
  * Fix schedule create dropping backup type (#10526, @Daniel-1600)
  * Support skipped PVC in VolumeInfos. (#10525, @blackpiglet)
  * Use the Kind constant instead of the kind string literal in the e2e tests (#10524, @krishhna24)
  * Don't change restoreType from plugin, let uploader to control fallback centrally (#10523, @Lyndon-Li)
  * Fix backup queue permanently stuck when a dequeued backup completes during the patch (#10521, @pujitha24)
  * Fix the VolumeGroupSnapshotClass example in the VolumeGroupSnapshot docs (#10520, @krishhna24)
  * Add fallback full to DU/DD/PVB/PVR CRs, volume info and backup/restore describe (#10517, @Lyndon-Li)
  * Update volume info in restore finalizing stage to record info from DataDownload result (#10513, @ywk253100)
  * Add in-place restore pre-flight check: PVC must be large enough for the backed-up data (#10512, @chlins)
  * Add --wait flag to velero install to wait for Velero deployment to be ready (#10507, @mmustafasenoglu)
  * Save source size to volume info for DU and PVB (#10506, @Lyndon-Li)
  * Add MustIncludeAdditionalItemPVCs to help track BIA added PVC's PVB creation. (#10501, @blackpiglet)
  * Add ID to repo snapshot and modify block uploader to use snapshot ID in logs (#10500, @Lyndon-Li)
  * Fix user version priorities parsing to handle CRLF line endings (#10496, @lhjnano)
  * Fix redundant schedule patching by comparing SkipImmediately and LastSkipped by value (#10490, @lhjnano)
  * Scope velero schedule get/describe/pause/unpause and velero repo get to the Velero namespace instead of listing across all namespaces (#10482, @MaxFreedomPollard)
  * Enhance data mover progress update to include a message field so that critical activity messages such as incremental fallback could be saved to the message field of DU/DD/PVB/PVR (#10479, @Lyndon-Li)
  * Ignore e2e debug bundles in .gitignore (#10477, @krishhna24)
  * Add in-place restore pre-flight check: PVC must be bound to the backed-up PV (#10475, @chlins)
  * Add operation context to user-facing error messages in CR statuses and CLI output (#10464, @chlins)
  * Update code to support namespace mapping when perform the in-p lace restore with block data mover (#10461, @ywk253100)
  * Fix issue 10454, enforce resource filter policies in memory in stage 1 to fix wildcard namespace bypassing issue (#10455, @adam-jian-zhang)
  * test: resolve remaining Ginkgo V2 and Gomega anti-patterns (#10440) (#10453, @opbot-xd)
  * Fix snapshot-location get --selector flag to actually filter VolumeSnapshotLocations by label (#10449, @PratikMane0112)
  * Add printer columns for BackupStorageLocation so kubectl shows provider and access mode (#10441, @Ralthos)
  * Add block data mover support for Velero backup/restore describe CLI. (#10436, @blackpiglet)
  * Enhance the doc for backup deletion (#10430, @Lyndon-Li)
  * Add "IncrementalBytes" field to status of DataDownload and PVR to indicate data transferred by the incremental restore (#10421, @ywk253100)
  * Add in-place restore pre-flight check: target PVC must not be in use (#10419, @chlins)
  * Add unit tests for pkg/itemblock (#10418, @opbot-xd)
  * Check both node-agent daemonsets before returning a non-NotFound lookup error in IsReady, so a transient error fetching one daemonset no longer masks the other daemonset being ready (#10403, @kaovilai)
  * Fix context propagation bug in GetDefaultBackupStorageLocations and add missing test coverage for core components (#10376, @opbot-xd)
  * prevent panic when the restore hook init container command annotation is empty (#10371, @samay43)
  * fix log format string mismatches that produce wrong or mangled output (#10370, @samay43)
  * stop routing credential selection on AZURE_USERNAME after username/password removal (#10363, @samay43)
  * Unify duplicate test harness structs across restore and delete tests into a shared pkg/test.Harness (#10362, @opbot-xd)
  * Fix e2e kind test matrix generation misparsing kindest/node pre-release tags (e.g. v1.37.0-rc.1) as bogus patch versions (#10359, @lubronzhan)
  * translate parent snapshot "auto" to an empty parent snapshot in both data mover micro services (#10357, @samay43)
  * Reject velero backup delete when backup storage location is read-only (#10353, @PranjalManhgaye)
  * Fix nil pointer dereference in WaitUntilVSCHandleIsReady when a VolumeSnapshotContent error has no message (#10352, @samay43)
  * Fix: Strip ServiceAccount token volume mounts from EphemeralContainers during restore (#10349, @opbot-xd)
  * Double check the label for backup when deleting VSC- #10346 (#10346, @reasonerjt)
  * Fix repo connection contest of the two repositories with the same storage type (#10344, @Lyndon-Li)
  * Only sync finished backups from object storage (#10343, @chlins)
  * Fix issue #10341, avoid mutating the cached node-agent LoadAffinity so the OS node selector term is not appended repeatedly to data mover pods (#10342, @shubham-pampattiwar)
  * Add readWriteOncePod backupPVC config to enable mount-level SELinux labeling (#10339, @shubham-pampattiwar)
  * Avoid duplicated InitContainer names generated in velero install CLI. (#10338, @blackpiglet)
  * Enforce namespace of the "musthave" resources in restore (#10333, @reasonerjt)
  * Replace generated `config/crd/{v1,v2alpha1}/crds/crds.go` with `go:embed` of the CRD YAML bases, removing the codegen step and itsCI drift check (#10329, @lubronzhan)
  * Fix issue #10321, when data mover pod is evicted get the message from the data mover pod instead of the terminal message (#10322, @Lyndon-Li)
  * Fix datamover backup pod arg mismatch for CSI CBT service account name (#10318, @kaovilai)
  * Cleanup: Remove deprecated --wait flag from velero uninstall (#10317, @opbot-xd)
  * Testing: Implement missing unit tests for pkg/backup/snapshots.go (#10315, @opbot-xd)
  * Assert expected errors from the test case rather than the returned error in pkg/util/csi tests (#10312, @samay43)
  * Report a measured zero-byte incremental instead of erasing it from status (#10309, @kaovilai)
  * Fix block data mover cancellation being reported as a backup failure (#10308, @kaovilai)
  * Fix generic CSI changeID retrieval and honor snapshot class deletion policy for CBT retention (#10307, @kaovilai)
  * Fix nil pointer dereference in EnsureDeletePVC, EnsureDeletePV and EnsureDeletePod when the API call times out before the object is retrieved (#10293, @samay43)
  * Fix nil pointer dereference in EnsureDeleteVS and EnsureDeleteVSC when the API call times out before the object is retrieved (#10292, @samay43)
  * test: add verification for skippedPVTracker in backup tests (#10283, @opbot-xd)
  * Bound WaitRestoreExecHook polling with resourceTimeout to avoid an infinite wait when restore exec hooks never complete. (#10280, @nitishmalang)
  * Use the well-known label constants exported by k8s.io/api/core/v1 instead of hardcoded label strings for kubernetes.io/hostname, kubernetes.io/os, kubernetes.io/arch, topology.kubernetes.io/zone and failure-domain.beta.kubernetes.io/zone (#10279, @harshitsaini17)
  * Add includedNamespacesByLabel/excludedNamespacesByLabel and labelSelectorLogic to ResourcePolicy's includeExcludePolicy, allowing namespace selection by Kubernetes label selector without enumerating names in BackupSpec. (#10275, @kaovilai)
  * Cap the metadata decompression in object store (#10270, @Lyndon-Li)
  * Remove PVC and PV inclusion check during creating PVR. (#10269, @blackpiglet)
  * Add cap for backup data extraction (#10260, @Lyndon-Li)
  * Trim spaces around resource names in --ordered-resources so comma-separated lists with spaces still match (#10259, @Jay2006sawant)
  * Cap the unzip of metadata download to avoid OOM kill (#10258, @Lyndon-Li)
  * Clarify the security context to Velero server (#10256, @Lyndon-Li)
  * Use thread safe map for cancel recorder (#10255, @Lyndon-Li)
  * Ignore credentialFile filled into BSL by users to avoid unexpected credentials used by Velero (#10254, @Lyndon-Li)
  * Skip signing a download URL when no artifacts can exist yet, and set a Failed phase with the reason so callers stop waiting (#10252, @Ralthos)
  * Fix wrong node-agent check result when PVR restorer run concurrently (#10251, @Lyndon-Li)
  * Fix a potential deadlock when resultsLock is held by the informer but blocked on resChan because the early quit of RestorePodVolumes (#10250, @Lyndon-Li)
  * Refactor: Replace context.TODO() with properly plumbed contexts in CSI backup actions and utility functions to enable proper cancellation of in-flight API requests. (#10247, @opbot-xd)
  * Document that the DownloadRequest Processed phase means a URL has been signed, and that it does not imply the target object exists(#10245, @Ralthos)
  * Mark the existed resource as skipped during restore (#10243, @reasonerjt)
  * Fix schedule reconciler aliasing &c.skipImmediately into Schedule specs, corrupting the server-wide --schedule-skip-immediately default after the first reconcile (#10242, @beep-boopp)
  * Make velero restore logs return errors instead of calling os.Exit directly, matching velero backup logs, and enable the two previously skipped tests (#10234, @Ralthos)
  * Add a troubleshooting entry for artifact downloads failing when the BackupStorageLocation s3Url is only resolvable inside the cluster (#10231, @Ralthos)
  * Add printer columns for DownloadRequest and ServerStatusRequest so kubectl shows their target, status and server version (#10229, @Ralthos)
  * Add "SnapshotClass" to DataUploadResult (#10227, @ywk253100)
  * Add prefetch mechanism to object reader so as to improve the restore throughput of block data mover (#10225, @Lyndon-Li)
  * Add missing test assertions for PVCBackupSummary in podvolume backupper (#10218, @opbot-xd)
  * Fix archive extraction path check so a sibling directory sharing the destination directory's name prefix can no longer bypass the Zip Slip containment check (#10212, @hsdfat)
  * Add printer columns for VolumeSnapshotLocation so kubectl shows provider and phase (#10211, @Ralthos)
  * Show n/a instead of <nil> for unset timestamps in velero backup get and velero restore get (#10201, @Ralthos)
  * Add printer columns for Backup and Restore CRDs so kubectl shows status, errors, warnings and timing (#10200, @Ralthos)
  * add test coverage for CleanupVolumeSnapshot (#10198, @samay43)
  * Support full backup for file system data mover and pod volume backup (#10185, @Lyndon-Li)
  * Support to set data mover for the uploader from volume policy. (#10176, @blackpiglet)
  * Add curl --fail flag to kubectl download in e2e kind workflow (#10174, @samay43)
  * Validate backup name format before contacting the API server (#10167, @samay43)
  * Fixed a bug in the backup sync controller where transient API errors could cause backups to incorrectly lose their schedule owner references. (#10161, @AftAb-25)
  * Fix excluded namespace objects leaking into backups when using cross-namespace listing (#10159, @Pragati5-DEBUG)
  * Add GitHub Action to automate backport/cherry-pick onto release branches (#10158, @Pragati5-DEBUG)
  * Verify downloaded build tools against architecture-specific SHA-256 checksums before installation. (#10155, @chlins)
  * Drop node-agent host path mounts from data mover pods (#10150, @chlins)
  * Fix block uploader restore validation and BatchForget error handling (#10138, @Jay2006sawant)
  * Fix a panic when a port name in the last-applied-configuration annotation is not a string (#10132, @arpitjain099)
  * Add `velero client config set namespace-mode=auto` to make operational commands resolve their default namespace from the current kubeconfig context on every invocation (#10127, @lubronzhan)
  * Use "" as parentSnapshot for DU when BackupType is incremental. (#10126, @blackpiglet)
  * Cancel hook exec stream on timeout and bound hook timeouts (#10125, @chlins)
  * Fix some issues for CBT features: logs, CRD change, GetDataMover. (#10106, @blackpiglet)
  * Verify extracted item paths stay inside the backup directory (#10102, @chlins)
  * Implement server default restore resource modifier (#10098, @shubham-pampattiwar)
  * Replace rebase action with GitHub CLI (#10093, @chlins)
  * Refactor block uploader thread module for better thread safety and code reading (#10091, @Lyndon-Li)
  * Stop force-including VolumeSnapshotContents via resourceMustHave on every restore; CSI VolumeSnapshot/PVC RestoreItemActions now set restore.velero.io/must-include-additional-items so bound snapshot dependencies are restored only when their parent is restored (fixes #9957) (#10087, @adam-jian-zhang)
  * Add restore.velero.io/must-include-additional-items so RestoreItemActions can opt in to bypassing global restore filters for AdditionalItems (mirrors the backup-side must-include annotation; no default behavior change for existing restores/plugins) (#10082, @adam-jian-zhang)
  * Fix issue #9828, add implementation for block uploader restore (#10071, @Lyndon-Li)
  * Add snapshotClass parameter to volume policy snapshot action (#10070, @shubham-pampattiwar)
  * Backup workflow for block data mover. (#10067, @blackpiglet)
  * Add set based label selectors for fine-grained filters (#10064, @adam-jian-zhang)
  * RIA must include additional items design (#10056, @adam-jian-zhang)
  * Fix restore-wait init container ignoring pod-level securityContext, falling back to hardcoded runAsUser 1000 instead of the workload's own uid/gid, causing fs-backup restores to deadlock at Init:0/1 on owner-restricted volumes (#10047, @kaovilai)
  * Fix issue #5836, respect schedule.spec.template.metadata.annotations to override annotations copied from the Schedule to Backup objects, matching the existing behavior for labels (#10045, @lubronzhan)
  * Trim whitespace around plugin image entries during install. (#10035, @HajimohammadiNet)
  * Fix issue #10032, prioritize exact namespace match in restore (#10033, @adam-jian-zhang)
  * Fix issue #9938, add use guide for restore fine-grained filters via resource policy (#10016, @adam-jian-zhang)
  * Add block dev restore operations for block data mover (#10013, @Lyndon-Li)
  * Add CRD short names for all Velero custom resources (#10009, @shubham-pampattiwar)
  * Fix issue #9997, cancel ongoing PVB on timeout and wait for all PVBs to terminal state (#10007, @Lyndon-Li)
  * Fix issue #9973, fail earlier when PVR pod is not ready (#10005, @Lyndon-Li)
  * Support selecting the data mover type (velero-fs or velero-block) through the volume policy snapshot action's dataMover parameter (#10004, @chlins)
  * Fix stale backupLastSuccessfulTimestamp metric after schedule deletion (#10000, @shubham-pampattiwar)
  * Fix PodVolumeBackup metadata loss on fs-backup timeout, which caused all fs-backup volumes to become unrestorable (#9995, @shubham-pampattiwar)
  * Add block device operations for block uploader backup (#9994, @Lyndon-Li)
  * Surface DeleteItemAction plugin errors from InvokeDeleteActions so backup deletion fails and retries instead of silently orphaningdata mover snapshots and other private artifacts (#9993, @chlins)
  * Fix globalExcludes lookup, it should be lookup against lower case (#9989, @adam-jian-zhang)
  * Fix ResourceDeletionStatusTracker key mismatch so restore into a terminating namespace waits once per namespace instead of once per resource (#9987, @Shashank1306s)
  * Add structured JSON output support for velero restore describe command (#9983, @prajoshi)
  * Validate user-provided labels and annotations in maintenance job (#9982, @shubham-pampattiwar)
  * Add the backup implementation for block data mover (#9979, @Lyndon-Li)
  * Add image volume type support to volume policies (#9978, @shubham-pampattiwar)
  * Disable fips140 enforcement because Kopia doesn't support it. (#9974, @blackpiglet)
  * Use forward slash as the path separator to make sure it works on both Linux and Windows nodes (#9968, @ywk253100)
  * Fix issue #9820, user guide for backup fine-grained filters via resource policy (#9967, @adam-jian-zhang)
  * Fix issue #9937, add CLI support for restore filters via resource policy (#9966, @adam-jian-zhang)
  * Optimize VSC handle readiness polling for VSS backups (#9955, @sseago)
  * Add BackupType in backup.spec (#9954, @blackpiglet)
  * Fix e2e-test-kind workflow cache miss on force push by saving build artifacts explicitly instead of relying on the actions/cache post-job hook (#9952, @alliasgher)
  * Fix issue #9936, restore filters via resource policy implementation (#9946, @adam-jian-zhang)
  * Add snapshot operations for block uploader (#9945, @Lyndon-Li)
  * Fix flaky TestWaitExecHandleHooks test for 2-container hook ordering by synchronizing pod state changes with hook execution using channels (#9944, @lubronzhan)
  * Decide restorePVC volumeMode by data mover type for block data mover (#9941, @Lyndon-Li)
  * Fix issue #9935, add resource policy on restore CRD (#9939, @adam-jian-zhang)
  * Recall the old rebind volume way for the case that volumeMode is not changed; and use the new way for volumeMode changed case (#9933, @Lyndon-Li)
  * Wait restorePV detached before binding the cloned PV to avoid confusing the CSI driver (#9932, @Lyndon-Li)
  * Support fsType in DUCR and DDCR for data mover (#9930, @Lyndon-Li)
  * Add `--global-backup-volume-policies-configmap` server flag to configure cluster-wide global backup volume policies that are merged into every backup (#9928, @chlins)
  * Design: Server default restore resource modifier (#9921, @shubham-pampattiwar)
  * Support copying namespace-scoped secrets and configmaps for backup and restore PVC provisioning to enable datamover backup/restoreof encrypted CSI volumes (#9920, @shubham-pampattiwar)
  * Refactor generic restore exposer to clone the PV during rebind, so as to support block data mover (#9913, @Lyndon-Li)
  * Fix issue #9907, add cache for the GetNamespaceFilter call (#9908, @adam-jian-zhang)
  * feat(resourcepolicies): support PVC volume mode and access mode matching (#9906, @chlins)
  * Add CONTAINER_TOOL variable to Makefile for podman support (#9904, @Joeavaikath)
  * Fix restore finalization overwriting dynamically provisioned PV labels with stale backup values (#9903, @Joeavaikath)
  * Refactor object writer interface to align with incremental aware object writer (#9899, @Lyndon-Li)
  * Skip VGS cleanup when backup did not use VolumeGroupSnapshots (#9896, @shubham-pampattiwar)
  * Enhance RebindVolume method for generic restore exposer to support block data mover (#9892, @Lyndon-Li)
  * Add WriteAt implementation for Incremental aware object writer for block data mover (#9887, @Lyndon-Li)
  * Fix issue #9816, add cli support for backup with ClusterScopedFilterPolicy and NamespacedFilterPolicies (#9881, @adam-jian-zhang)
  * Fix issue #9815, implement core logic of backup with ClusterScopedFilterPolicy and NamespacedFilterPolicies (#9880, @adam-jian-zhang)
  * Add totalSize to repo snapshot operation; and pin unified repo snapshots to Kopia repository and so pin them with Velero backup lifecycle (#9875, @Lyndon-Li)
  * Remove Restic cases and workflow from E2E (#9867, @Joeavaikath)
  * Add cbt service parameters to node-agent-config for block data mover (#9864, @Lyndon-Li)
  * Support change-id and volume-id in backup workflow. (#9863, @blackpiglet)
  * Enhance backup exposer for block data mover (#9862, @Lyndon-Li)
  * Remove restic command package (#9861, @Lyndon-Li)
  * Add the Write implementation for incremental aware object writer (#9853, @Lyndon-Li)
  * Fix issue #9814, add validations for NamespacedFilterPolicies (#9848, @adam-jian-zhang)
  * Fix issue #9813, add validations for ClusterScopedFilterPolicy (#9847, @adam-jian-zhang)
  * Implement the CBT service. (#9846, @blackpiglet)
  * Fix issue #9823, add incremental aware object writer for block data mover (#9845, @Lyndon-Li)
  * Replace vmware-tanzu/velero GitHub org references with velero-io/velero (#9844) (#9844, @Copilot)
  * Fix issue #9812, validate ClusterScopedFilterPolicy and NamespacedFilterPolicy incompatible with legacy filters  (#9840, @adam-jian-zhang)
  * Fix issue #9811, add interface to support ClusterScopedFilterPolicy and NamespacedFilterPolicy (#9821, @adam-jian-zhang)
  * Data path naming adjustment for block data mover (#9819, @Lyndon-Li)
  * Add metadata operation to Kopia repo for block data mover (#9817, @Lyndon-Li)
  * Add Kopia repo snapshot operations for block data mover (#9808, @Lyndon-Li)
  * Uploader interface for block data mover (#9807, @Lyndon-Li)
  * Skip DeleteSnapshot when ProviderSnapshotID is empty (#9795, @kaovilai)
  * Restores from backups not in a completed or partially failed phase are now rejected. (#9792, @subhramit)
  * Fix DataUploadDeleteAction creating snapshot-info ConfigMaps labeled with the wrong backup name when a DataUpload CR from another backup is incidentally captured in the backup tarball, which caused Kopia snapshots to be leaked in object storage on expiry of the real owning backup. (#9791, @christian-schlichtherle)
  * docs(aws-plugin): update version (#9773, @emirot)
  * fix: lint permission issue (#9740, @emirot)
  * Add CBT bitmap implementation for block data mover (#9736, @Lyndon-Li)
  * Remove Restic code path from PodVolumeRestore. (#9732, @blackpiglet)
  * Remove Restic build from Dockerfile, Makefile and Tiltfile. (#9728, @blackpiglet)
  * Fix issue #9723, extend Unified Repo Interface to support block uploader (#9724, @Lyndon-Li)
  * Add dynamic resource autocompletion to Velero CLI (#9720, @Joeavaikath)
  * Fix issue #9709, add interfaces for CBT service and CBT bitmap (#9716, @Lyndon-Li)
  * perf: better string concatenation (#9705, @emirot)
  * Fix issue #9703, fix CSI PVC Backup Plugin list options to only list in installed namespace (#9704, @adam-jian-zhang)
  * Update Debian base image from bookworm to trixie (#9701, @emirot)
  * Fix issue #9699, add a 2-second gap between temporary CSI VolumeSnapshotContent create and delete operations (#9700, @priyansh17)
  * Fail backup validation when built-in data mover is requested but no node-agent pods are running (#9697, @Joeavaikath)
  * Bump external-snapshotter to v8.4.0 and migrate VolumeGroupSnapshot API from v1beta1 to v1beta2 for Kubernetes 1.34+ compatibility(#9695, @shubham-pampattiwar)
  * Enhance backup deletion logic to handle tarball download failures (#9693, @priyansh17)
  * Fix wildcard expansion when includes is empty and excludes has wildcards (#9684, @Joeavaikath)
  * Fix issue #9428, increase repo maintenance history queue length from 3 to 25 (#9683, @Lyndon-Li)
  * Fix issue #9681, fix restores and podvolumerestores list options to only list in installed namespace (#9682, @adam-jian-zhang)
  * Fix issue #9469, remove restic for uploader (#9677, @Lyndon-Li)
  * Fix issue #9470, remove restic from repository (#9676, @Lyndon-Li)
  * Fix issue #9666, fix node-agent node detection in multiple instances scenario (#9668, @adam-jian-zhang)
  * Fix issue #9659, in the case that PVB/PVR/DU/DD is cancelled before the data path is really started, call EndEvent to prevent datamover pod from crashing because of delay event distribution (#9663, @Lyndon-Li)
  * Fix issue #9658, Honor --stderrthreshold when --logtostderr is enabled (#9654, @pierluigilenoci)
  * Fix service restore with null healthCheckNodePort in last-applied-configuration label (#9653, @BassinD)
  * Fix backup-finalizer: do not set backup phase to Completed before PutBackupMetadata succeeds (#9646, @kaovilai)
  * Fix issue #9641, Remove redundant ReadyToUse polling in CSI VolumeSnapshotContent delete plugin (#9643, @priyansh17)
  * Fix issue #9636, fix configmap lookup in non-default namespaces (#9638, @adam-jian-zhang)
  * Fix issue #9626, let go for uninitialized repo under readonly mode (#9634, @Lyndon-Li)
  * Implement original VolumeSnapshotContent deletion for legacy backups (#9628, @priyansh17)
  * Add check for file extraction from tarball. (#9614, @blackpiglet)
  * update go-hclog to current version (#9613, @pjjw)
  * Fix DBR stuck when CSI snapshot no longer exists in cloud provider (#9581, @shubham-pampattiwar)
  * Add configurable tolerations to the node-agent-configmap for PodVolumeBackup and data mover pods; DaemonSet tolerations matching the existing third-party allowlist (kubernetes.azure.com/scalesetpriority, CriticalAddonsOnly) continue to be inherited automatically and are merged with the configmap value (#9575, @kaovilai)
  * Add ephemeral storage limit and request support for data mover and maintenance job (#9574, @blackpiglet)
  * Add schedule_expected_interval_seconds metric for dynamic backup alerting thresholds (#9559) (#9570, @H-M-Quang-Ngo)
  * Fix issue #9460, flush buffer before data mover completes (#9561, @Lyndon-Li)
  * Fix issue #9475, use node-selector instead of nodName for generic restore (#9560, @Lyndon-Li)
  * Wildcard namespaces: Log warning on empty resolution (#9558, @Joeavaikath)
  * Issue #9544: Add test coverage for S3 bucket name in MRAP ARN notation and fix bucket validation to accept ARN format (#9554, @testsabirweb)
  * If BIA return updateObj with SkipFromBackupAnnotation, treat it as skip the resource from backup. (#9547, @blackpiglet)
  * Add custom action type to volume policies (#9540, @sseago)
  * Fix issue #9496, support customized host os (#9533, @Lyndon-Li)
  * Fix issue #9343, include PV topology to data mover pod affinities (#9532, @Lyndon-Li)
  * Add block data mover design for block level incremental backup by integrating with Kubernetes CBT (#9528, @Lyndon-Li)
  * Fix VolumeGroupSnapshot restore failure with Ceph RBD CSI driver by creating stub VolumeGroupSnapshotContent during restore and looking up VolumeSnapshotClass by driver for credential support (#9516, @shubham-pampattiwar)
  * Fix VolumePolicy PVC phase condition filter for unbound PVCs (#9507) (#9508, @kaovilai)
  * Support all glob wildcard characters in namespace validation (#9502, @Joeavaikath)
  * Include InitContainer configured as Sidecars when validating the existence of the target containers configured for the Backup Hooks (#9403, @GabriFedi97)
  * docs: Add documentation about --write-sparse-files flag for disk space issues during restore (#9221, @kaovilai)