---
title: "Volume Group Snapshots"
description: "A guide to using Volume Group Snapshots with Velero for consistent backups of multi-volume applications."
layout: docs
---

Velero provides robust support for **Volume Group Snapshots (VGS)**, a powerful Kubernetes feature for creating atomic, crash-consistent snapshots of multiple volumes simultaneously. This capability is essential for stateful applications that distribute data across several PersistentVolumeClaims (PVCs) and require that all data be captured at the exact same moment to ensure data integrity.

> **Who is this for?** This guide is for application owners and backup administrators who need to ensure data consistency for multi-volume stateful applications, such as distributed databases (e.g., Cassandra, Zookeeper) or complex stateful services.

## When to Use Volume Group Snapshots

You should consider using Volume Group Snapshots when:

- Your application uses multiple PVCs that are logically related.
- You need to ensure write-order consistency across all volumes.
- Your storage provider's CSI driver supports the Volume Group Snapshot feature.

## Key Concepts

Before diving in, let's clarify the Kubernetes resources involved in this process:

- **VolumeGroupSnapshot (VGS):** A request to your storage provider to create a snapshot of a group of volumes.
- **VolumeGroupSnapshotContent (VGSC):** Represents the actual snapshot of the volume group, provisioned by the CSI driver.
- **VolumeGroupSnapshotClass (VGSClass):** A cluster-level resource that defines the configuration for a VGS, including the CSI driver and other parameters.
- **VolumeSnapshot (VS) & VolumeSnapshotContent (VSC):** The individual volume snapshots that are created as part of the VGS process.

## Velero's VGS Backup and Restore Workflow

Velero's integration with VGS is designed to be as seamless as possible, automating the complexities of group snapshots. Velero supports three distinct workflows depending on your configuration:

### Three VGS Workflow Branches

Velero automatically selects the appropriate workflow based on your backup configuration:

#### 1. VGS + Data Mover
**When**: PVCs have VGS labels AND `--snapshot-move-data=true` flag is used

**Use case**: Need atomic consistency + long-term storage/cross-cloud portability

- Creates `VolumeGroupSnapshot` for write-order consistency across all labeled PVCs
- Extracts individual `VolumeSnapshot` objects from the VGS
- Creates `DataUpload` CRs that move each volume's data to object storage
- Cleans up temporary VGS and VGS Content resources
- **Result**: Volume data stored in object storage, no local snapshots retained

#### 2. VGS without Data Mover  
**When**: PVCs have VGS labels BUT `--snapshot-move-data=false` (or flag omitted)

**Use case**: Need atomic consistency with local snapshot storage

- Creates `VolumeGroupSnapshot` for write-order consistency across all labeled PVCs
- Extracts individual `VolumeSnapshot` objects from the VGS
- Backup depends only on `VolumeSnapshots`, no `DataUpload` or data mover involved
- Cleans up temporary VGS and VGS Content resources
- **Result**: Individual `VolumeSnapshots` stored on your storage system

#### 3. Individual Volume Snapshots
**When**: PVCs have NO VGS labels (standard CSI snapshot behavior)

**Use case**: Independent volume backups, no consistency requirements

- Creates individual `VolumeSnapshot` per PVC independently
- No atomic consistency guarantees across volumes
- Optionally uses data movement if `--snapshot-move-data=true` flag is set
- **Result**: Independent volume snapshots (local or in object storage)

### Choosing the Right Workflow

Select your workflow based on your application's requirements:

| Scenario | VGS Labels | Data Movement Flag | Workflow | Best For |
|----------|------------|-------------------|----------|----------|
| Multi-volume app + cross-cloud backup | ✅ | `--snapshot-move-data=true` | **VGS + Data Movement** | Distributed databases with portability needs |
| Multi-volume app + local snapshots | ✅ | `--snapshot-move-data=false` (or omitted) | **VGS Only** | Applications requiring consistency with fast local snapshots |
| Single volumes or independent backups | ❌ | `--snapshot-move-data=true` (optional) | **Individual Snapshots** | Simple applications, testing, or independent services |

**Example Commands:**
```bash
# VGS + Data Movement (cross-cloud, long-term storage)
velero backup create db-backup --include-namespaces my-database --snapshot-move-data=true

# VGS Only (atomic consistency, local storage)  
velero backup create db-backup --include-namespaces my-database --snapshot-move-data=false

# Individual Snapshots (standard CSI behavior)
velero backup create app-backup --include-namespaces my-app
```

### The Backup Process

The VGS backup workflow is triggered by a simple label on your PVCs.

1.  **Grouping PVCs:** When a backup is initiated, Velero's `PVCAction` plugin scans for PVCs with the VGS label (the default is `velero.io/volume-group`). All PVCs within the same namespace that share the same label value are collected into a single `ItemBlock`. This ensures they are processed as a single, atomic unit.

2.  **Orchestrating the Snapshot:** The CSI plugin takes over to manage the snapshot creation:
    *   **Driver Verification:** It first confirms that all PVCs in the group are managed by the same CSI driver.
    *   **Class Selection:** It then determines the correct `VolumeGroupSnapshotClass` to use based on your configuration.
    *   **VGS Creation:** A `VolumeGroupSnapshot` resource is created, signaling the CSI driver to begin the snapshot process for the entire group.

3.  **Snapshot Finalization:** Velero monitors the process, and once the `VolumeGroupSnapshot` is ready, it performs these final steps:
    *   Waits for the CSI driver to create the individual `VolumeSnapshot` objects.
    *   Applies the backup's labels to each `VolumeSnapshot` for tracking.

4.  **Resource Cleanup:** To keep your cluster tidy, Velero deletes the temporary `VolumeGroupSnapshot` and `VolumeGroupSnapshotContent` resources after the individual `VolumeSnapshots` have been created and secured.

Here is a visual representation of the backup workflow:

![VGS Backup Workflow](/img/vgs-flow.svg)

### The Restore Process

Restoring from a VGS backup is simple and flexible. During backup, Velero creates individual `VolumeSnapshots` from the `VolumeGroupSnapshot`, so the restore process works with standard volume snapshot restoration.

> **Good to know:** No special VGS-related logic is needed during the restore. This means you can restore your data to a cluster that doesn't have VGS support enabled, providing excellent portability.

## Prerequisites

Before using Volume Group Snapshots with Velero, ensure your environment meets these requirements:

### 1. Kubernetes Version
- Kubernetes 1.20+ (when VolumeGroupSnapshot API was introduced)
- Check your client and server versions: `kubectl version`

### 2. VolumeGroupSnapshot CRDs
Check the Volume Group Snapshot CRDs on your cluster:

```bash
# Check if VGS CRDs are installed
kubectl get crd | grep volumegroup
```

### 3. CSI Driver Support
Verify your CSI driver supports Volume Group Snapshots:

```bash
# Check if your CSI driver has VolumeGroupSnapshotClass resources
kubectl get volumegroupsnapshotclass

# Verify CSI driver capabilities (example for AWS EBS)
kubectl describe csidriver ebs.csi.aws.com
```

### 4. VolumeGroupSnapshotClass Configuration
Ensure a VolumeGroupSnapshotClass exists for your storage and is properly labeled for Velero discovery:

```bash
# List available VolumeGroupSnapshotClasses
kubectl get volumegroupsnapshotclass -o wide
```

**Important:** The VolumeGroupSnapshotClass must have the label `velero.io/csi-volumegroupsnapshot-class: "true"` for Velero to automatically discover and use it:

```yaml
apiVersion: groupsnapshot.storage.k8s.io/v1alpha1
kind: VolumeGroupSnapshotClass
metadata:
  name: csi-vgs-class
  labels:
    velero.io/csi-volumegroupsnapshot-class: "true"
spec:
  driver: ebs.csi.aws.com
  deletionPolicy: Delete
```

Verify your VolumeGroupSnapshotClass has the correct label:
```bash
# Check if VolumeGroupSnapshotClass has the required label
kubectl get volumegroupsnapshotclass --show-labels
```

## Step-by-Step: Using VGS with Velero

Here's how to get started with VGS backups:

1.  **Verify Prerequisites:** Ensure all prerequisites above are met.

2.  **Label Your PVCs:** The key to grouping volumes is to apply a consistent label to all PVCs that should be snapshotted together. **Important:** All PVCs in a group must use the same CSI driver and exist in the same namespace.

### Complete Workflow Example

Here's a complete end-to-end example of using VGS with a database application that has multiple volumes:

#### 1. Set Up the Application

Deploy a database application with multiple PVCs:

**PVC for Primary Data:**
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: db-data-pvc
  namespace: my-database
  labels:
    velero.io/volume-group: db-cluster-1
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: my-csi-storage-class
```

**PVC for Transaction Logs:**
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: db-logs-pvc
  namespace: my-database
  labels:
    velero.io/volume-group: db-cluster-1
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
  storageClassName: my-csi-storage-class
```

When you next back up the `my-database` namespace, Velero will see the `velero.io/volume-group: db-cluster-1` label on both PVCs and will trigger a `VolumeGroupSnapshot` for the `db-cluster-1` group.

#### 2. Create the Backup

```bash
# Create backup that will use VGS for labeled PVCs
velero backup create my-app-backup --include-namespaces my-database

# Monitor backup progress
velero backup describe my-app-backup
velero backup logs my-app-backup
```

#### 3. Verify VGS Processing

```bash
# Verify VolumeSnapshots were created from the VGS
kubectl get volumesnapshot -n my-database -o wide

# Check that snapshots have the correct labels
kubectl get volumesnapshot -n my-database --show-labels

# Confirm backup completed successfully
velero backup describe my-app-backup | grep Phase
```

#### 4. Test Restore

```bash
# Create a test namespace for restore
kubectl create namespace my-database-restore

# Restore to the new namespace
velero restore create test-restore \
  --from-backup my-app-backup \
  --namespace-mappings my-database:my-database-restore

# Monitor restore progress
velero restore describe test-restore
velero restore logs test-restore

# Verify PVCs were restored correctly
kubectl get pvc -n my-database-restore --show-labels
```

#### 5. Cleanup Test Resources

```bash
# Remove test namespace after verification
kubectl delete namespace my-database-restore

# List backups and restores
velero backup get
velero restore get
```

## Advanced Configuration

You can customize the label key that Velero uses to identify VGS groups. This is useful if you have pre-existing labels or want to use a different convention. The configuration is applied with the following order of precedence:

1.  **Backup Resource Spec (Highest Priority):** For the most granular control, you can specify the label key directly in your `Backup` resource definition.
    ```yaml
    apiVersion: velero.io/v1
    kind: Backup
    metadata:
      name: my-app-backup
      namespace: velero
    spec:
      volumeGroupSnapshotLabelKey: "my-organization.io/snapshot-group"
      includedNamespaces: [ "my-database" ]
      # ... other backup spec details
    ```

2.  **Velero Server Argument:** You can set a cluster-wide default by providing the `--volume-group-snapshot-label-key` command-line argument when you install or start the Velero server.

3.  **Default Value (Lowest Priority):** If you don't provide any custom configuration, Velero defaults to using `velero.io/volume-group`.

## Troubleshooting

### Common Issues and Solutions

#### VGS Not Created During Backup

**Symptoms:** Backup completes but individual VolumeSnapshots are created instead of VGS
```bash
# Check if PVCs have the correct label
kubectl get pvc -n my-database --show-labels

# Verify all PVCs use the same CSI driver
kubectl get pv $(kubectl get pvc -n my-database -o jsonpath='{.items[*].spec.volumeName}') -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.csi.driver}{"\n"}{end}'
```

**Solutions:**
- Ensure all PVCs have the same volume group label value
- Verify all PVCs use the same CSI driver
- Check that VolumeGroupSnapshotClass exists for your CSI driver

#### VGS Creation Fails

**Symptoms:** Backup fails with VGS-related errors
```bash
# Check Velero logs for VGS errors
velero backup logs my-app-backup | grep -i "VolumeGroup"

# Check CSI driver logs
kubectl logs -n kube-system -l app=ebs-csi-controller --tail=100
```

**Solutions:**
- Verify CSI driver supports VolumeGroupSnapshots
- Check VolumeGroupSnapshotClass configuration
- Ensure storage backend supports group snapshots

#### VolumeGroupSnapshot Setup: Default VolumeSnapshotClass Required

**Issue**

When creating VolumeGroupSnapshot backups, you may encounter this error:

```
VolumeSnapshot has a temporary error Failed to set default snapshot class with error cannot find default snapshot class. Snapshot controller will retry later.
```

**Cause**

The Kubernetes snapshot controller requires a default VolumeSnapshotClass to be configured in the cluster, but none is currently set.

**Solution**

Set a default VolumeSnapshotClass that uses the same CSI driver as your VolumeGroupSnapshotClass:

```bash
# List available VolumeSnapshotClasses
kubectl get volumesnapshotclasses

# Set the appropriate class as default for your CSI driver
kubectl patch volumesnapshotclass <snapshot-class-name> \
  -p '{"metadata":{"annotations":{"snapshot.storage.kubernetes.io/is-default-class":"true"}}}'

# Example for Ceph RBD:
kubectl patch volumesnapshotclass ocs-storagecluster-rbdplugin-snapclass \
  -p '{"metadata":{"annotations":{"snapshot.storage.kubernetes.io/is-default-class":"true"}}}'
```

**Important:** Ensure the default VolumeSnapshotClass uses the same CSI driver as your VolumeGroupSnapshotClass. For example, if your VolumeGroupSnapshotClass uses `ebs.csi.aws.com`, the default VolumeSnapshotClass should also use `ebs.csi.aws.com`.

**Note:** Only one VolumeSnapshotClass should be marked as default per CSI driver to avoid conflicts. The default VolumeSnapshotClass driver must match the CSI driver used by your VolumeGroupSnapshotClass.

### Best Practices

1. **Test VGS Support:** Always test VGS functionality in a non-production environment first
2. **Monitor Resource Usage:** VGS operations may consume more resources than individual snapshots
3. **Label Consistency:** Use consistent labeling across your organization
4. **Backup Validation:** Always verify backup success before relying on it for disaster recovery
5. **Storage Quotas:** Ensure sufficient storage quota for group snapshots

