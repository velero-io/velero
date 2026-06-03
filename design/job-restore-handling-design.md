# Design proposal for handling restoration of Kubernetes Jobs

This aids in review of the document as changes to a line are not obscured by the reflowing those changes caused and has a side effect of avoiding debate about one or two space after a period.

## Abstract
This design proposes a solution for handling Kubernetes Jobs during Velero restore operations, specifically addressing the challenges with running, failed, and completed Jobs.
The goal is to provide users with configurable options to control Job restoration behavior to prevent unintended re-execution while maintaining the ability to restore Job resources when needed.

## Background
Velero currently skips restoring completed Jobs (those with a completionTime set) but restores failed Jobs and running Jobs.
This can lead to unintended consequences where Jobs are executed again during restore operations, potentially causing side effects or duplicate work.
Jobs in running status from a backup will most likely be completed by the time a restore is run, but the current behavior would still attempt to restore and run them.
Failed Jobs with a restartPolicy of OnFailure will be rerun when restored, which may not be the desired behavior.
Some users have workflows that depend on the presence of Job resources (even completed ones), while others want to avoid re-execution of Jobs.

## Goals
- Provide a configurable way to handle running Jobs during restore operations
- Prevent unintended re-execution of Jobs during restore
- Support users who need Job resources to be present after restore, even if they were completed or failed
- Maintain backward compatibility with existing Velero behavior

## Non Goals
- Modifying the backup behavior for Jobs
- Handling CronJob resources differently than they are currently handled
- Implementing a solution that requires changes to the Kubernetes Jobs controller
- Providing a mechanism to selectively restore only certain Jobs based on complex criteria

## High-Level Design
The proposed solution extends the existing ResourcePolicy framework (similar to VolumePolicy) to control how Velero handles Jobs during restore operations.
By default, Velero will continue to skip completed Jobs but will restore running or failed Jobs with parallelism set to 0, effectively pausing them to prevent immediate execution.
Users will be able to override this behavior using ResourcePolicy rules with label selectors (for granular control) or through restore annotations (for default fallback behavior).

## Detailed Design

### Job Restoration Logic

The current logic for handling Jobs during restore will be modified as follows:

1. **Completed Jobs** (with completionTime set):
   - Default behavior: Skip restoration (current behavior)
   - Optional behavior: Restore with original configuration or with parallelism=0

2. **Running Jobs** (active but not completed):
   - Default behavior: Restore with parallelism=0 (new behavior)
   - Optional behavior: Skip restoration or restore with original configuration

3. **Failed Jobs** (failed but not completed):
   - Default behavior: Restore with parallelism=0 (new behavior)
   - Optional behavior: Skip restoration or restore with original configuration

### Implementation Details

#### 1. ResourcePolicy for Jobs

We will extend the existing ResourcePolicy framework to support Job restore policies.
This follows the same pattern as VolumePolicy, allowing users to define policies in a ConfigMap that is referenced during restore operations.
This approach provides better user experience compared to Job annotations because:
- Jobs are often dynamically created and deleted by controllers (e.g., CronJobs, Argo Workflows)
- Jobs may be short-lived, making annotation difficult before backup
- Large numbers of Jobs would require modifying the owning controller
- ResourcePolicy provides a centralized, label-based approach that doesn't require modifying Jobs

##### ResourcePolicy ConfigMap Structure

The ResourcePolicy ConfigMap will be extended to include a `jobRestorePolicies` section:

```yaml
version: v1
volumePolicies:
  # ... existing volume policies ...
jobRestorePolicies:
  - conditions:
      jobPhase:
        - completed
        - failed
      jobLabels:
        app: my-batch-processor
    action:
      type: restore-paused
  - conditions:
      jobPhase:
        - running
    action:
      type: skip
  - conditions:
      # Default policy for all other jobs (no conditions specified)
    action:
      type: restore-paused
```

##### Condition Fields

- `jobPhase`: List of Job phases to match. Valid values are:
  - `completed`: Job had a completionTime set
  - `failed`: Job had failed status
  - `running`: Job was actively running
  - `pending`: Job was created but not yet started
- `jobLabels`: Simple key/value map for label matching (consistent with VolumePolicy's `pvcLabels`). All specified labels must match.

##### Action Types

The `action.type` field can be one of:
- `skip`: Skip restoration of matching Jobs
- `restore-paused`: Restore matching Jobs with parallelism=0 (paused)
- `restore-as-is`: Restore matching Jobs with their original configuration

##### Policy Matching

Policies are evaluated in order.
The first policy whose conditions match the Job will be applied.
If no policy matches, the default behavior is applied (based on Restore annotations or built-in defaults).

#### 2. Restore Annotations (Default Fallback)

Restore annotations provide default fallback behavior when no ResourcePolicy rule matches a Job.
These annotations are applied to the Velero Restore object and affect all Jobs that don't have a matching ResourcePolicy rule.

##### Precedence Order

1. **ResourcePolicy rules** (highest priority): If a Job matches a rule in the ResourcePolicy ConfigMap, that rule's action is applied
2. **Restore annotations** (fallback): If no ResourcePolicy rule matches, these annotations determine the behavior
3. **Built-in defaults** (lowest priority): If neither ResourcePolicy nor Restore annotations are specified

##### Phase-Specific Restore Policies

```
velero.io/job-restore-policy-completed: <policy>
velero.io/job-restore-policy-failed: <policy>
velero.io/job-restore-policy-running: <policy>
```

##### General Restore Policy

```
velero.io/job-restore-policy: <policy>
```

Where `<policy>` can be one of: `skip`, `restore-paused`, or `restore-as-is`.

These annotations can be added to the Restore object through the CLI:

```
# Set a general policy for all Jobs (applies when no ResourcePolicy matches)
velero restore create --from-backup=my-backup \
  --annotations velero.io/job-restore-policy=<policy>

# Set phase-specific fallback policies
velero restore create --from-backup=my-backup \
  --annotations velero.io/job-restore-policy-completed=skip \
  --annotations velero.io/job-restore-policy-failed=restore-paused \
  --annotations velero.io/job-restore-policy-running=restore-paused
```

The built-in default behavior (if neither ResourcePolicy nor annotations are specified) will be:
- `skip` for completed Jobs
- `restore-paused` for running and failed Jobs

#### 3. Implementation Changes

The implementation will require changes to the following components:

1. **ResourcePolicy Framework** (`internal/resourcepolicies/`):
   - Extend `ResourcePolicies` struct to include `JobRestorePolicies` field
   - Implement `jobPolicy` struct with conditions and actions (following VolumePolicy pattern)
   - Implement `jobPhaseCondition` to match Job phases
   - Implement `jobLabelsCondition` to match Job labels (similar to `pvcLabelsCondition`)
   - Add `GetJobMatchAction` function to evaluate policies against Jobs

2. **Restore Controller** (`pkg/restore/restore.go`):
   - Modify the `restoreItem` function to check for Job restore policies
   - Determine the Job phase from the backup data (status.completionTime, status.failed, status.active)
   - Load ResourcePolicy from ConfigMap if specified in Restore
   - Evaluate ResourcePolicy rules first, then fall back to Restore annotations
   - Implement logic to modify the Job spec based on the determined policy
   - Apply the appropriate default policy if no policy matches

3. **Restore Annotations**:
   - Implement support for the new annotations on Restore objects
   - Update the CLI documentation to explain the new annotations
   - Implement validation for the annotation values
   - Ensure proper precedence of phase-specific over general policies

4. **Documentation**:
   - Update documentation to explain the new behavior and options
   - Document the ResourcePolicy ConfigMap structure for Jobs
   - Explain why parallelism is modified for certain Jobs
   - Provide examples of common use cases with label-based selection

#### 4. Modification of Job Resources

When a Job is restored with the `restore-paused` policy, the following changes will be made to the Job spec:

```yaml
spec:
  parallelism: 0  # Set to 0 regardless of original value
```

This change effectively pauses the Job, preventing it from creating new pods until the user explicitly increases the parallelism.

##### Transparency and Documentation

To ensure users understand why a Job's parallelism was modified:

1. The Velero logs will include information about which policy was applied to each Job and why
2. The backup data itself contains the Job's phase at backup time for verification if needed
3. The documentation will clearly explain:
   - The default behavior for each Job phase
   - Why parallelism is set to 0 for certain Jobs (to prevent unintended re-execution)
   - How to restore Jobs with their original configuration if needed
   - The precedence order (ResourcePolicy > Restore annotations > built-in defaults)

### User Experience

#### Example 1: Default Behavior

By default, a restore operation will:
- Skip completed Jobs
- Restore running and failed Jobs with parallelism=0

This prevents unintended re-execution while preserving the Job resources.

#### Example 2: Using ResourcePolicy for Dynamic Jobs

For Jobs that are dynamically created by controllers (e.g., CronJobs, Argo Workflows), users can define a ResourcePolicy ConfigMap with label-based selection:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: job-restore-policy
  namespace: velero
data:
  policy.yaml: |
    version: v1
    jobRestorePolicies:
      # Skip all jobs managed by Argo Workflows
      - conditions:
          jobLabels:
            managed-by: argo-workflows
        action:
          type: skip
      # Restore critical failed jobs as-is for investigation
      - conditions:
          jobLabels:
            critical: "true"
          jobPhase:
            - failed
        action:
          type: restore-as-is
      # Default: pause all other running/failed jobs
      - conditions:
          jobPhase:
            - running
            - failed
        action:
          type: restore-paused
```

This allows users to control Job restoration based on labels without modifying the Job manifests or controllers.

#### Example 3: Using ResourcePolicy with Restore

To use the ResourcePolicy ConfigMap during restore:

```bash
velero restore create --from-backup=my-backup \
  --resource-policy-configmap job-restore-policy
```

Jobs will be processed according to the rules defined in the ConfigMap.

#### Example 4: Using Restore Annotations as Fallback

When ResourcePolicy is not specified or a Job doesn't match any rule, Restore annotations provide fallback behavior:

```bash
velero restore create --from-backup=my-backup \
  --annotations velero.io/job-restore-policy-completed=skip \
  --annotations velero.io/job-restore-policy-failed=restore-paused \
  --annotations velero.io/job-restore-policy-running=restore-as-is
```

This will:
- Skip completed Jobs (default behavior)
- Restore failed Jobs with parallelism=0
- Restore running Jobs with their original configuration

#### Example 5: Using General Restore Annotations

A user can specify a global fallback policy for all Jobs during restore:

```bash
velero restore create --from-backup=my-backup \
  --annotations velero.io/job-restore-policy=skip
```

This will skip restoration of all Jobs that don't match any ResourcePolicy rule.

## Alternatives Considered

### 1. Skip All Jobs During Restore

One alternative is to simply skip all Jobs during restore operations, regardless of their status.
This would prevent any unintended re-execution but would not satisfy users who need Job resources to be present after restore.

### 2. Restore All Jobs As-Is

Another alternative is to restore all Jobs with their original configuration.
This would satisfy users who need Job resources but would cause unintended re-execution of Jobs.

### 3. Use Velero Server Flag

We considered adding a server-side flag to the Velero server to control the default behavior for Job restoration.
However, this approach has several drawbacks:
- It would be a cluster-wide setting that applies to all users and all restore operations
- It may not be applicable to all Jobs in the cluster, requiring many overrides via annotations
- It would require restarting the Velero server to change the behavior
- It would make it difficult to have different behaviors for different restore operations in the same cluster

### 4. Modify the Restore CRD

We considered adding a new field to the Velero Restore CRD to control the Job restoration behavior.
While this would provide a more structured approach than using annotations, we decided against it for the following reasons:
- It would require changes to the CRD, which could impact backward compatibility
- CRD changes require more careful versioning and migration planning
- Annotations provide a more flexible and extensible mechanism for adding metadata without schema changes

However, if this feature proves valuable and widely used, adding a dedicated field to the Restore CRD could be considered in a future release with proper deprecation notices for the annotation-based approach.

### 5. Job Annotations

We initially considered using annotations directly on Job resources to control restoration behavior.
However, this approach was rejected due to poor user experience:
- Jobs are often dynamically created and deleted by controllers (e.g., CronJobs, Argo Workflows)
- Jobs may be short-lived, making annotation difficult before backup
- Large numbers of Jobs would require modifying the owning controller
- ResourcePolicy provides a centralized, label-based approach that doesn't require modifying Jobs

While annotations could work for static, long-lived Jobs that users create manually, the ResourcePolicy approach is more practical for real-world use cases where Jobs are managed by controllers.

### 6. Backup Phase Recording Annotation

We considered adding a `velero.io/job-phase-at-backup` annotation to Jobs during backup to record their phase (completed, failed, running, pending).
This annotation would help users understand why a Job was restored with specific modifications.
However, this approach was rejected because:
- The backup data itself is the authoritative source of truth for the Job's phase
- Users who need to verify a Job's phase at backup time can examine the backup data directly
- Adding annotations during backup modifies the resources unnecessarily
- In most cases, users don't need this double-check mechanism

## Security Considerations

The proposed changes do not introduce any new security considerations.
The solution operates within the existing security model of Velero and Kubernetes.

## Compatibility

### Backward Compatibility

The proposed changes maintain backward compatibility with existing Velero behavior for completed Jobs.
The default behavior for running and failed Jobs will change, but this change is intended to prevent unintended consequences rather than break existing workflows.

### Forward Compatibility

The design is flexible enough to accommodate future changes to the Kubernetes Jobs API.
If new Job states or features are introduced, the policy-based approach can be extended to handle them.

## Implementation

### Timeline

1. Phase 1: Implement the core functionality
   - Add the annotation support
   - Modify the restore logic to handle Jobs according to the policy
   - Update documentation

2. Phase 2: Add CLI support
   - Add documentation for the restore annotation
   - Implement validation for the annotation
   - Add examples to the CLI help text

### Resources

The implementation will be carried out by the Velero team with input from the community.
Community members who have expressed interest in this feature may be invited to review or contribute to the implementation.

## Open Issues

1. Should we provide more granular control over Job restoration based on other criteria, such as Job age or labels?
2. How should we handle Jobs that are part of a workflow or have dependencies on other resources?
3. Should we extend similar functionality to other resources that might have similar concerns, such as Pods or StatefulSets?
