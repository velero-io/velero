# Design proposal for handling restoration of Kubernetes Jobs

## Abstract
This design proposes a solution for handling Kubernetes Jobs during Velero restore operations, specifically addressing the challenges with running, failed, and completed Jobs.
The goal is to provide users with configurable options to control Job restoration behavior to prevent unintended re-execution while maintaining the ability to restore Job resources when needed.

## Background
Velero currently skips restoring completed Jobs (those with a completionTime set) but restores failed Jobs and running Jobs.
This can lead to unintended consequences where Jobs are executed again during restore operations, potentially causing side effects or duplicate work.
Jobs in running status from a backup will most likely be completed by the time a restore is run, but the current behavior would still attempt to restore and run them.
Failed Jobs with a restartPolicy of OnFailure will be rerun when restored, which may not be the desired behavior.
Some users have workflows that depend on the presence of Job resources (even completed ones), while others want to avoid re-execution of Jobs.
For example, [#3519](https://github.com/velero-io/velero/issues/3519) describes a disaster-recovery scenario where one-shot provisioning Jobs must actually re-run on restore, because other Pods' init-containers block on that Job's completion; skipping the Job leaves the recovered namespace stuck.

## Goals
- Provide a configurable way to handle running Jobs during restore operations
- Prevent unintended re-execution of Jobs during restore
- Support users who need Job resources to be present after restore, even if they were completed or failed
- Preserve current behavior for completed Jobs (skipped by default); intentionally change the default for running and failed Jobs (restored paused instead of re-executed), since the current behavior can cause unintended re-execution — see Compatibility

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

2. **Running Jobs** (active, or previously started and awaiting retry, but not completed):
   - Default behavior: Restore with parallelism=0 (new behavior)
   - Optional behavior: Skip restoration or restore with original configuration

3. **Failed Jobs** (failed but not completed):
   - Default behavior: Restore with parallelism=0 (new behavior)
   - Optional behavior: Skip restoration or restore with original configuration

4. **Pending Jobs** (created but never started — no active Pods, no recorded failures, no start time, no completion/failure condition):
   - Default behavior: Restore with original configuration (current behavior). A pending Job never ran, so restoring it as-is carries no risk of unintended re-execution.
   - Optional behavior: Skip restoration or restore with parallelism=0

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

- `jobPhase`: List of Job phases to match. Phases are mutually exclusive and assigned by evaluating the following in order, using the Job's backed-up `status`; the first match wins:
  1. `completed`: `status.completionTime` is set, or a `Complete` condition with `status: "True"` is present — either signal alone is sufficient, checked independently of one another and regardless of whether other conditions exist. A Job that failed and was retried before eventually succeeding is classified as `completed`, not `failed`.
  2. `failed`: a `Failed` condition with `status: "True"` is present (retries exhausted) and no `Complete` condition with `status: "True"` is present (and `completionTime` is not set). A `Complete` condition that is merely present but not `"True"` (e.g., `status: "False"`) does not block this classification.
  3. `running`: neither `completed` nor `failed` above, and the Job has already started — `status.active > 0` (Pods currently running), OR `status.startTime` is set, OR `status.failed > 0` (retried at least once). This covers Jobs with currently-active Pods as well as Jobs that started, hit failures, and are between retries/backoff with zero active Pods at backup time.
  4. `pending`: none of the above — Job created but never started: no active Pods, no recorded failures, no `status.startTime`, and no completion/failure condition.
- `jobLabels`: Simple key/value map for label matching (consistent with VolumePolicy's `pvcLabels`). Matching is by exact equality on all specified key/value pairs: every label defined here must exist on the Job with the same value; no partial, substring, or regex matching is performed.

##### Action Types

The `action.type` field can be one of:
- `skip`: Skip restoration of matching Jobs
- `restore-paused`: Restore matching Jobs with parallelism=0 (paused)
- `restore-as-is`: Restore matching Jobs with their original configuration

##### Policy Matching

Policies are evaluated in order.
The first policy whose conditions match the Job will be applied.
If no policy matches, the default behavior is applied (based on Restore annotations or built-in defaults).

##### Validation and Error Handling

Invalid input is rejected up front and never silently treated as `restore-as-is` (the most permissive, highest-risk action) or any other fallback:
- An unrecognized `action.type` value in a `jobRestorePolicies` rule, or an unrecognized value in `jobPhase`, fails ResourcePolicy validation. The Restore is marked `Failed` (or `PartiallyFailed`, consistent with how VolumePolicy validation errors are surfaced today) before any Job in the backup is processed.
- A `--resource-policy-configmap` reference that is missing or fails to parse fails the Restore the same way, before any Job is processed — matching existing VolumePolicy ConfigMap validation behavior.
- An unrecognized value for `velero.io/job-restore-policy` or any `velero.io/job-restore-policy-<phase>` annotation fails Restore validation before any Job is processed, rather than being ignored or treated as a default.
- These validations run once, at Restore-object admission/start time, not per-Job — so a single bad rule or annotation fails the whole Restore rather than partially applying policies to some Jobs and not others.

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
- `restore-as-is` for pending Jobs

There is no `velero.io/job-restore-policy-pending` phase-specific annotation, since the default for pending Jobs is already non-disruptive; the general `velero.io/job-restore-policy` annotation still applies to pending Jobs as a fallback, and a `jobPhase: pending` ResourcePolicy rule can override it if a user needs different behavior.

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
   - Determine the Job phase from the backed-up status using the ordered classification defined in Condition Fields (`completionTime`/`Complete` condition, then `Failed` condition, then started-but-not-terminal via `active`/`startTime`/`failed`, else pending) — not a shorthand check of individual fields, which could misclassify a Job that failed and was retried before eventually succeeding, or misclassify a previously-started Job awaiting retry as pending
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

Setting `parallelism: 0` only prevents the Job controller from creating *new* Pods; it does not affect Pods directly.
This guarantee holds when Pods owned by the Job are not themselves included in the restore — which is the default, since Velero does not back up or restore Pods owned by a controller (Jobs included); they're expected to be recreated by their owning controller, not restored individually.
If a user explicitly configures a restore to include such Pods (e.g., via `includedResources`), those Pods are restored independently of the Job's `parallelism` setting, and `restore-paused` does not stop or clean them up; that scenario is out of scope for this design (see Non Goals).
Restore hooks are a separate mechanism and don't change this: hooks only run against Pods that are already part of the restore set (via the default exclusion or an explicit `includedResources` override) — they don't themselves cause additional Pods to be included.
Under the default configuration, a `restore-paused` Job is restored with zero currently-running Pods regardless of its state at backup time, and stays that way until the user raises `parallelism` above 0.
This `parallelism: 0` guarantee applies when Velero creates the Job fresh in the target namespace, which is the common restore case (e.g., the DR scenario in Example 2b where the namespace itself was deleted and is being recreated).
If a Job with the same name already exists in the target namespace, standard Velero existing-resource handling applies (see Example 2b) instead of this design's Job-spec modification: depending on that behavior, Velero may skip the Job entirely, in which case the pre-existing Job and any Pods it currently owns are left completely unaffected — they are not paused, updated, or otherwise touched by `restore-paused`.
`restore-paused` only sets `parallelism: 0`; it does not touch `spec.suspend`.
If the backed-up Job had `spec.suspend: true`, that value is restored unchanged, and the Job remains suspended even after the user raises `parallelism` — resuming such a Job requires both raising `parallelism` above 0 and setting `spec.suspend: false`.
If the backed-up Job had `spec.suspend: false` (or unset, the default), `parallelism: 0` alone is sufficient to keep it paused, and raising `parallelism` alone is sufficient to resume it.

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

#### Example 2b: Re-running Completed Provisioning Jobs ([#3519](https://github.com/velero-io/velero/issues/3519))

For one-shot provisioning Jobs that other resources depend on (e.g., an init-container waiting for a completed Job), the default "skip completed Jobs" behavior leaves the restored namespace stuck.
A ResourcePolicy rule can opt specific completed Jobs back into restoration, by label, without changing the default for every other Job:

```yaml
jobRestorePolicies:
  # Re-run completed provisioning jobs that other resources depend on
  - conditions:
      jobLabels:
        velero.io/reapply-on-restore: "true"
      jobPhase:
        - completed
    action:
      type: restore-as-is
```

This targets only the labeled provisioning Jobs; all other completed Jobs continue to be skipped by default.
`restore-as-is` only controls whether Velero attempts to (re-)create the Job — it does not change Velero's existing-resource handling.
If a Job with the same name already exists in the target namespace (e.g., restoring into a namespace where the original, already-completed Job was never deleted), the standard Velero existing-resource behavior applies and the Job is skipped regardless of this policy.
This use case works when the target namespace does not already contain the Job — the typical case for the DR scenario in #3519, where the namespace was deleted and is being recreated from backup.

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

The `restore-as-is` action (and the built-in fallback for annotation-driven restores) can cause a completed or failed Job to run again with its original, potentially privileged, `spec.template` — including its ServiceAccount, image, and command.
This is a Velero controller trust-boundary consideration, not a claim that the restoring user already holds Job-create authorization: the Velero server/controller itself performs the write in the target namespace, using its own (typically elevated, cluster-wide) permissions, on behalf of whoever created or modified the Restore object or the referenced ResourcePolicy ConfigMap.
That means `restore-as-is` can let a user re-execute a privileged Job in a namespace even if that user does not personally hold `create` on Jobs there — the same way any Velero restore already lets a user materialize arbitrary backed-up resources into a namespace via the controller's permissions.
Because of this, `restore-as-is` should be treated the same as any other Velero restore capability: access to create/modify Restores and to edit ResourcePolicy ConfigMaps must be restricted to users already trusted with that namespace's restore capacity, and Velero should not introduce a separate, weaker authorization check for `restore-as-is` specifically.
However, broad label selectors (e.g., matching on `jobPhase` alone with no `jobLabels`) can unintentionally re-run Jobs with unexpected side effects, so:
- Restore and ResourcePolicy ConfigMap access should be governed by the same RBAC controls already required for restore operations in general.
- Velero logs should record which policy/action was applied to each Job (see Transparency and Documentation) so re-executions are auditable.
- Users should be encouraged to scope `jobRestorePolicies` rules with specific `jobLabels` rather than relying solely on `jobPhase` when using `restore-as-is`, to avoid unintentionally re-running unrelated Jobs.

## Compatibility

### Backward Compatibility

The proposed changes maintain backward compatibility with existing Velero behavior for completed Jobs in the common case, where `status.completionTime` is set exactly when the `Complete` condition is `True` (the normal Kubernetes behavior).
The `jobPhase: completed` classification (see Condition Fields) additionally treats a `Complete` condition of `status: "True"` as sufficient on its own, without requiring `completionTime` to be set — a deliberate broadening versus the legacy completionTime-only check, to correctly classify the rare case where API skew or an older cluster reports the condition before (or without) `completionTime`. In that narrow, previously-unhandled case, a Job that legacy Velero would have restored (since it did not match completionTime) is now skipped by default instead, which is intentional: without this change such a Job would have been treated as running/failed/pending and been made to re-execute despite having actually completed.
The default behavior for running and failed Jobs will change, but this change is intended to prevent unintended consequences rather than break existing workflows.

### Forward Compatibility

The design is flexible enough to accommodate future changes to the Kubernetes Jobs API.
If new Job states or features are introduced, the policy-based approach can be extended to handle them.

## Implementation

### Timeline

1. Phase 1: Implement ResourcePolicy-based core functionality
   - Define the ResourcePolicy ConfigMap structure for Job restore policies
   - Implement matching logic between Jobs and ResourcePolicy definitions
   - Implement policy evaluation in the restore logic to determine Job restore behavior
   - Add initial documentation for ResourcePolicy-based Job restore handling

2. Phase 2: Add annotation support integrated with ResourcePolicy
   - Add annotation support for configuring Job restore behavior as a fallback to ResourcePolicy (never an override — ResourcePolicy rules always take precedence, per the Precedence Order)
   - Modify the restore logic to combine ResourcePolicy evaluation with annotation-based configuration
   - Update documentation to describe the interaction between annotations and ResourcePolicy

3. Phase 3: Add CLI support
   - Add CLI documentation and examples for configuring Job restore behavior via ResourcePolicy and annotations
   - Implement validation for annotations and any CLI-provided configuration related to Job restore policies

### Resources

The implementation will be carried out by the Velero team with input from the community.
Community members who have expressed interest in this feature may be invited to review or contribute to the implementation.

## Open Issues

1. Should we provide more granular control over Job restoration based on other criteria, such as Job age or labels?
2. How should we handle Jobs that are part of a workflow or have dependencies on other resources?
3. Should we extend similar functionality to other resources that might have similar concerns, such as Pods or StatefulSets?
