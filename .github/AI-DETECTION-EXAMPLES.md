# AI Issue Detection - Examples

This document provides examples to help understand what triggers AI detection.

## Example 1: High AI Score (Score: 6/8) ❌

**This would be flagged:**

```markdown
## Description
When deploying Velero on an EKS cluster with `hostNetwork: true`, the application fails to start.

## Critical Problem
```
time="2026-01-26T16:40:55Z" level=fatal msg="failed to start metrics server"
```

Status: BLOCKER

## Affected Environment

| Parameter | Value |
|----------|----------|
| Cluster | Amazon EKS |
| Velero Version | 1.8.2 |
| Kubernetes | 1.33 |

## Root Cause Analysis

The controller-runtime metrics uses port 8080 as a hardcoded default...

## Resolution Attempts

### Attempt 1: Use extraArgs
Result: Failed

### Attempt 2: Configure metricsAddress  
Result: Failed

## Expected Permanent Solution

Velero should:
1. Auto-detect an available port
2. Accept configuring the controller-runtime port

## Questions for Maintainers
1. Why does controller-runtime use hardcoded 8080?
2. Is there a roadmap to support hostNetwork?

## Labels and Metadata
Severity: CRITICAL
```

**Why flagged (Patterns detected: 6/8):**
- ✓ `futureDates` - References "2026-01-26" and "Kubernetes 1.33"
- ✓ `excessiveHeaders` - 8+ section headers
- ✓ `formalPhrases` - "Root Cause Analysis", "Expected Permanent Solution", "Questions for Maintainers", "Labels and Metadata"
- ✓ `aiSectionHeaders` - "## Description", "## Critical Problem", "## Affected Environment", "## Resolution Attempts"
- ✓ `perfectFormatting` - Perfect table structure
- ✓ `genericSolutions` - Mentions "auto-detect"

---

## Example 2: Medium AI Score (Score: 2/8) ✅

**This would NOT be flagged (below threshold):**

```markdown
**What steps did you take and what happened:**

I'm trying to restore a backup but getting this error:
```
error: backup "my-backup" not found
```

**What did you expect to happen:**
The backup should restore successfully

**Environment:**
- Velero version: 1.13.0
- Kubernetes version: 1.28
- Cloud provider: AWS

**Additional context:**
I can see the backup in S3 but Velero doesn't list it. Running `velero backup get` shows no backups.
```

**Why NOT flagged (Patterns detected: 2/8):**
- ✗ `futureDates` - Uses realistic versions
- ✗ `excessiveHeaders` - Only 3 headers
- ✗ `formalPhrases` - No formal AI phrases
- ✓ `excessiveTables` - Has a table but only 1
- ✗ `perfectFormatting` - Normal formatting
- ✗ `aiSectionHeaders` - Standard issue template headers
- ✓ `excessiveFormatting` - Has code blocks
- ✗ `genericSolutions` - No generic solutions

---

## Example 3: Legitimate Detailed Issue (Score: 3/8) ⚠️

**This would be flagged but is actually legitimate:**

```markdown
## Problem Description

VolumeGroupSnapshot restore fails with Ceph RBD driver.

## Environment

- Velero: 1.14.0
- Kubernetes: 1.28.3
- ODF: 4.14.2 with Ceph RBD CSI driver

## Root Cause

Ceph RBD stores group snapshot metadata in journal as `csi.groupid` omap key. During restore, when creating pre-provisioned VSC, the RBD driver reads this and populates `status.volumeGroupSnapshotHandle`.

The CSI snapshot controller looks for a VGSC with matching handle. Since Velero deletes VGSC after backup, it's not found.

## Reproduction Steps

1. Create backup with VGS
2. Delete namespace
3. Restore backup
4. Observe VS stuck with "cannot find group snapshot"

## Workaround

Create stub VGSC with matching `volumeGroupSnapshotHandle` and patch status.

## Proposed Fix

1. Backup: Capture `volumeGroupSnapshotHandle` in CSISnapshotInfo
2. Restore: Create stub VGSC if handle exists

## Code References

- Ceph RBD: https://github.com/ceph/ceph-csi/blob/devel/internal/rbd/snapshot.go#L167
- Velero deletion: https://github.com/vmware-tanzu/velero/blob/main/pkg/backup/actions/csi/pvc_action.go#L1124
```

**Why flagged (Patterns detected: 3/8):**
- ✗ `futureDates` - Uses current versions
- ✓ `excessiveHeaders` - Has 6 section headers
- ✓ `formalPhrases` - "Root Cause", "Proposed Fix"
- ✗ `excessiveTables` - No tables
- ✗ `perfectFormatting` - Normal formatting
- ✗ `aiSectionHeaders` - Technical, not generic
- ✗ `excessiveFormatting` - Reasonable formatting
- ✓ `genericSolutions` - Structured solution with code refs

**Maintainer Action**: This is a legitimate, well-researched issue. Verify the details with the contributor and remove the `potential-ai-generated` label.

---

## Example 4: Simple Valid Issue (Score: 0/8) ✅

**This would NOT be flagged:**

```markdown
Velero backup fails with error: `rpc error: code = Unavailable desc = connection error`

Running Velero 1.13 on GKE. Backups were working yesterday but now all fail with this error.

Logs show the node-agent pod is crashing. Any ideas?
```

**Why NOT flagged (Patterns detected: 0/8):**
- All patterns: None detected

---

## Key Takeaways

### Will Trigger Detection ❌
- Future dates/versions (2026+, K8s 1.33+)
- 4+ formal AI phrases
- 8+ section headers
- Perfect table formatting across multiple tables
- Generic AI section titles
- Auto-detect/generic solution patterns

### Will NOT Trigger ✅
- Realistic version numbers
- Actual error messages from real systems
- Normal issue formatting
- Moderate level of detail
- Standard GitHub issue template

### May Trigger (But Legitimate) ⚠️
- Very detailed technical analysis
- Multiple code references
- Well-structured proposals
- Extensive testing documentation

For these cases, maintainers will verify with the contributor and remove the flag once confirmed.
