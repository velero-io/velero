# Add PVC VolumeMode and AccessModes as Criteria for Volume Policy

## Abstract
This proposal extends Velero VolumePolicy conditions with two PVC-based criteria, `pvcVolumeMode` and `pvcAccessModes`.
These conditions allow users to select volumes according to the `volumeMode` and `accessModes` of the associated PersistentVolumeClaim (PVC), enabling backup behavior such as skipping block-mode PVCs or choosing a specific backup method for volumes with selected access modes.

## Background
Velero VolumePolicy already supports selecting volumes by attributes such as capacity, storage class, volume source, volume type, PVC labels, and PVC phase.
PVC metadata and spec fields are often the most direct way for users to express the intended storage semantics of a workload.

Kubernetes PVCs include a `spec.volumeMode` field that describes whether the volume is exposed as a filesystem or as a raw block device.
The field supports values such as `Filesystem` and `Block`.

Kubernetes PVCs also include a `spec.accessModes` field that describes how the volume can be mounted.
Common values are `ReadWriteOnce`, `ReadOnlyMany`, `ReadWriteMany`, and `ReadWriteOncePod`.
For resource policies, `pvcAccessModes` uses an exact set match against the PVC's `spec.accessModes`, so a policy does not match PVCs that have missing or additional access modes.

## Goals
- Add a `pvcVolumeMode` VolumePolicy condition to match volumes by a single `spec.volumeMode` value of their associated PVC.
- Add a `pvcAccessModes` VolumePolicy condition to match volumes whose associated PVC has exactly the configured `spec.accessModes` values, regardless of order.
- Keep the new conditions consistent with existing VolumePolicy behavior, where all conditions in a policy must match and the first matching policy wins.

## Non-Goals
- This proposal does not add new VolumePolicy actions.
- This proposal does not change how PVCs are discovered or passed into the resource policy matching code.
- This proposal does not add set-based or negative matching operators such as `NotIn`, `Exists`, or `DoesNotExist`.
- This proposal does not change Kubernetes PVC semantics or validate storage provider capabilities.

## Use-cases/Scenarios

### Skip block-mode PVCs
A user wants to skip volumes whose associated PVC is configured with raw block volume mode.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcVolumeMode: Block
  action:
    type: skip
```

### Snapshot filesystem PVCs
A user wants to use snapshots only for volumes whose associated PVC has filesystem mode.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcVolumeMode: Filesystem
  action:
    type: snapshot
```

### Match PVCs by access mode
A user wants to apply a policy only to PVCs whose `spec.accessModes` is exactly `ReadWriteOnce`.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcAccessModes:
      - ReadWriteOnce
  action:
    type: skip
```

### Match an exact access mode set
A user wants to match volumes whose associated PVC access modes are exactly `ReadOnlyMany` and `ReadWriteMany`.
A PVC that includes only one of these modes, or includes additional modes, does not match.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcAccessModes:
      - ReadOnlyMany
      - ReadWriteMany
  action:
    type: snapshot
```

### Combine PVC spec criteria
A user wants to select block-mode PVCs whose access modes are exactly `ReadWriteOnce`.
Because VolumePolicy conditions are conjunctive, the volume must satisfy both conditions.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcVolumeMode: Block
    pvcAccessModes:
      - ReadWriteOnce
  action:
    type: snapshot
```

## High-Level Design
The VolumePolicy condition schema is extended with two optional fields, `pvcVolumeMode` and `pvcAccessModes`.
`pvcVolumeMode` is represented as a single string value in the resource policy YAML.
`pvcAccessModes` is represented as a string list in the resource policy YAML.

The internal `structuredVolume` representation is extended to store the associated PVC's volume mode and access modes.
The existing PVC parsing path populates these fields when a PVC is available in `VolumeFilterData`.

The policy builder creates a `pvcVolumeModeCondition` when `pvcVolumeMode` is specified and creates a `pvcAccessModesCondition` when `pvcAccessModes` is specified.
The existing matching flow remains unchanged: each condition implements the `volumeCondition` interface, all conditions in a policy must match, and the first matching policy's action is returned.

## Detailed Design

### Resource policy YAML schema
Two new fields are added under `volumePolicies[].conditions`.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcVolumeMode: Block
    pvcAccessModes:
      - ReadWriteOnce
      - ReadWriteMany
  action:
    type: snapshot
```

`pvcVolumeMode` is a string.
The intended values are Kubernetes PVC volume mode values, including `Filesystem` and `Block`.
The condition matches only when the PVC volume mode value observed by Velero exactly equals the configured value.
Matching is case-sensitive, so `block` does not match `Block`.

`pvcAccessModes` is a list of strings.
The intended values are Kubernetes PVC access mode values, including `ReadWriteOnce`, `ReadOnlyMany`, `ReadWriteMany`, and `ReadWriteOncePod`.
The condition matches only when the configured access modes exactly equal the PVC's `spec.accessModes`, ignoring order.
Matching is case-sensitive, so `readwriteonce` does not match `ReadWriteOnce`.

The implementation validates that `pvcVolumeMode`, when present, is a string.
The implementation validates that `pvcAccessModes`, when present, is a list of strings.
The implementation does not strictly reject unknown string values so that the condition format remains tolerant of Kubernetes additions or storage-provider-specific behavior.
Unknown `pvcVolumeMode` values match only when the PVC has the same string value, and unknown `pvcAccessModes` values match only as part of the same exact access-mode set.

### Volume condition struct
The parsed condition struct is extended as follows.

```go
type volumeConditions struct {
    Capacity       string            `yaml:"capacity,omitempty"`
    StorageClass   []string          `yaml:"storageClass,omitempty"`
    NFS            *nFSVolumeSource  `yaml:"nfs,omitempty"`
    CSI            *csiVolumeSource  `yaml:"csi,omitempty"`
    VolumeTypes    []SupportedVolume `yaml:"volumeTypes,omitempty"`
    PVCLabels      map[string]string `yaml:"pvcLabels,omitempty"`
    PVCPhase       []string          `yaml:"pvcPhase,omitempty"`
    PVCVolumeMode  string            `yaml:"pvcVolumeMode,omitempty"`
    PVCAccessModes []string          `yaml:"pvcAccessModes,omitempty"`
}
```

### Structured volume data
The internal `structuredVolume` is extended with `pvcVolumeMode` and `pvcAccessModes`.

```go
type structuredVolume struct {
    capacity       resource.Quantity
    storageClass   string
    nfs            *nFSVolumeSource
    csi            *csiVolumeSource
    volumeType     SupportedVolume
    pvcLabels      map[string]string
    pvcPhase       string
    pvcVolumeMode  string
    pvcAccessModes []string
}
```

When a PVC is available, `parsePVC` extracts PVC attributes into `structuredVolume` for later condition evaluation.
This parsing step does not create or imply a `pvcVolumeMode` policy condition; `pvcVolumeMode` only constrains matching when the user explicitly configures `conditions.pvcVolumeMode` in the VolumePolicy.
Velero uses `pvc.Spec.VolumeMode` as-is when it is present.
If `pvc.Spec.VolumeMode` is nil, `pvcVolumeMode` remains empty and does not match any non-empty `pvcVolumeMode` condition.
If `pvc.Spec.AccessModes` is empty, `pvcAccessModes` remains empty and does not match any non-empty `pvcAccessModes` condition.

```go
func (s *structuredVolume) parsePVC(pvc *corev1api.PersistentVolumeClaim) {
    if pvc != nil {
        if len(pvc.GetLabels()) > 0 {
            s.pvcLabels = pvc.Labels
        }
        s.pvcPhase = string(pvc.Status.Phase)
        if pvc.Spec.VolumeMode != nil {
            s.pvcVolumeMode = string(*pvc.Spec.VolumeMode)
        }
        if len(pvc.Spec.AccessModes) > 0 {
            s.pvcAccessModes = make([]string, 0, len(pvc.Spec.AccessModes))
            for _, accessMode := range pvc.Spec.AccessModes {
                s.pvcAccessModes = append(s.pvcAccessModes, string(accessMode))
            }
        }
    }
}
```

### PVC volume mode condition
`pvcVolumeModeCondition` matches when the associated PVC's parsed volume mode exactly equals the configured value.
The comparison is case-sensitive and does not normalize values.
An empty configured value is treated as no constraint and always matches, consistent with other VolumePolicy conditions.
A non-empty configured value does not match if no PVC volume mode is available.

```go
type pvcVolumeModeCondition struct {
    volumeMode string
}

func (c *pvcVolumeModeCondition) match(v *structuredVolume) bool {
    if c.volumeMode == "" {
        return true
    }
    if v.pvcVolumeMode == "" {
        return false
    }
    return v.pvcVolumeMode == c.volumeMode
}
```

### PVC access modes condition
`pvcAccessModesCondition` matches when the configured access modes exactly equal the associated PVC's access modes, ignoring order.
The comparison is case-sensitive and does not normalize values.
An empty configured list is treated as no constraint and always matches.
A non-empty configured list does not match if the structured volume has no PVC access modes, has a different number of access modes, or has a different access-mode set.

```go
type pvcAccessModesCondition struct {
    accessModes []string
}

func (c *pvcAccessModesCondition) match(v *structuredVolume) bool {
    if len(c.accessModes) == 0 {
        return true
    }
    if len(v.pvcAccessModes) == 0 || len(v.pvcAccessModes) != len(c.accessModes) {
        return false
    }

    return sets.New(c.accessModes...).Equal(sets.New(v.pvcAccessModes...))
}
```

### Condition validation
Both `pvcVolumeModeCondition` and `pvcAccessModesCondition` implement the `validate()` method required by the `volumeCondition` interface.
The `validate()` method returns nil for both conditions.

```go
func (c *pvcVolumeModeCondition) validate() error {
    return nil
}

func (c *pvcAccessModesCondition) validate() error {
    return nil
}
```

YAML shape validation is handled when resource policy conditions are unmarshaled.
`pvcVolumeMode` must be a string, and `pvcAccessModes` must be a list of strings.
Condition-level validation intentionally does not reject unknown string values.
This keeps the policy format forward-compatible with future Kubernetes values and consistent with other string-based VolumePolicy conditions.
Unknown values simply do not match normal PVCs unless the evaluated PVC has the same exact value or access-mode set.

### Policy builder integration
The policy builder appends the new conditions only when the corresponding YAML fields are present.

```go
func (p *Policies) BuildPolicy(resPolicies *ResourcePolicies) error {
    for _, vp := range resPolicies.VolumePolicies {
        con, err := unmarshalVolConditions(vp.Conditions)
        if err != nil {
            return errors.WithStack(err)
        }

        // Existing conditions are appended here.

        if con.PVCVolumeMode != "" {
            volP.conditions = append(volP.conditions, &pvcVolumeModeCondition{volumeMode: con.PVCVolumeMode})
        }
        if len(con.PVCAccessModes) > 0 {
            volP.conditions = append(volP.conditions, &pvcAccessModesCondition{accessModes: con.PVCAccessModes})
        }
    }
    return nil
}
```

### Matching behavior with other conditions
The new conditions follow the existing VolumePolicy matching behavior.
Within a single policy, every configured condition must match.
If `pvcVolumeMode` is omitted from a policy, Velero does not add a volume mode condition and the policy does not restrict volume mode.
`pvcVolumeMode` and `pvcAccessModes` are PVC-specific conditions and only match when the volume policy evaluation has associated PVC data.
For non-PVC volumes such as `emptyDir`, `configMap`, or inline volumes without an associated PVC, the parsed PVC fields are empty and policies requiring `pvcVolumeMode` or `pvcAccessModes` do not match.
Across multiple policies, the first matching policy wins.

For example, this policy matches only PVC-backed volumes that are both `Block` mode and have exactly `ReadWriteOnce` as their access modes.

```yaml
version: v1
volumePolicies:
- conditions:
    pvcVolumeMode: Block
    pvcAccessModes:
      - ReadWriteOnce
  action:
    type: snapshot
```

## Alternatives Considered

### A single `pvcSpec` condition object
One alternative is to add a nested object such as `pvcSpec.volumeMode` and `pvcSpec.accessModes`.
This was not chosen because existing PVC-based VolumePolicy conditions use flat field names such as `pvcLabels` and `pvcPhase`.
Flat names keep the YAML concise and consistent with existing conditions.

### List-based `pvcVolumeMode`
One alternative is to make `pvcVolumeMode` a list, similar to `pvcPhase`.
This was not chosen because Kubernetes PVC `spec.volumeMode` is a single value and the policy condition is intended to describe an exact match against that value.
Using a string avoids implying that multiple volume modes can apply to one PVC.

### Contains-based access mode matching
Another alternative is to make `pvcAccessModes` match when any or all configured access modes are present on the PVC.
This was not chosen because contains-based matching would also select PVCs with additional access modes.
Using exact set matching keeps `pvcAccessModes` consistent with `pvcVolumeMode`'s exact-match behavior and avoids matching PVCs whose access mode set differs from the policy.

### Strict validation of allowed Kubernetes values
Another alternative is to reject `pvcVolumeMode` or `pvcAccessModes` values that are not currently known Kubernetes constants.
This was not chosen because accepting strings is more forward-compatible and keeps behavior consistent with other string-based resource policy conditions.
Invalid or unknown values naturally fail to match unless a PVC has the same value.

## Security Considerations
This proposal does not introduce new privileges or access to additional Kubernetes resources.
It only uses PVC data already available to the volume policy matching path.

The new conditions can cause Velero to skip or choose different backup actions for matched volumes.
Users should review policy configuration carefully because an overly broad policy can exclude data from backup or select an unintended backup method.

## Compatibility
The new fields are optional and do not affect existing resource policy files.
Existing VolumePolicy behavior remains unchanged when `pvcVolumeMode` and `pvcAccessModes` are not configured.

PVCs without a parsed `spec.volumeMode` value do not match non-empty `pvcVolumeMode` conditions.
PVCs without `spec.accessModes` do not match non-empty `pvcAccessModes` conditions.

Unknown `pvcVolumeMode` or `pvcAccessModes` string values in a policy are accepted as strings but will not match normal Kubernetes PVCs unless the evaluated PVC has the same exact value or access-mode set.

## Implementation
Implementation requires changes in the resource policies package and documentation.

- Extend `volumeConditions` with `PVCVolumeMode string` and `PVCAccessModes []string`.
- Extend `structuredVolume` with `pvcVolumeMode string` and `pvcAccessModes []string`.
- Update `parsePVC` to populate the new fields from the PVC spec.
- Add `pvcVolumeModeCondition` and `pvcAccessModesCondition` implementations.
- Update `Policies.BuildPolicy` to append the new conditions.
- Add YAML type validation to ensure `pvcVolumeMode` is a string and `pvcAccessModes` is a string list.
- Add unit tests for parsing, validation, condition matching, and end-to-end `GetMatchAction` behavior.
- Update user documentation in `site/content/docs/main/resource-filtering.md`.
