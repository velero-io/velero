# Maintainer Guide: AI-Generated Issue Detection

This guide helps Velero maintainers understand and work with the AI-generated issue detection system.

## Overview

The AI detection system automatically analyzes new and edited issues to identify potential AI-generated content. This helps maintain issue quality and ensures contributors verify their submissions.

## How It Works

### Automatic Detection

When an issue is opened or edited, the workflow:

1. **Analyzes** the issue body for 8 different AI patterns
2. **Calculates** an AI confidence score (0-8)
3. **If score ≥ 3**: Adds labels and posts a comment
4. **If score < 3**: Takes no action (issue proceeds normally)

### Detection Patterns

| Pattern | Description | Weight |
|---------|-------------|--------|
| `excessiveTables` | More than 5 markdown tables | 1 |
| `excessiveHeaders` | More than 8 section headers | 1 |
| `formalPhrases` | 4+ AI-typical phrases (e.g., "Root Cause Analysis") | 1 |
| `excessiveFormatting` | Multiple horizontal rules (---) | 1 |
| `futureDates` | Dates/versions in 2026+ or 2030s | 1 |
| `perfectFormatting` | Multiple identical table structures | 1 |
| `aiSectionHeaders` | 4+ generic AI headers (e.g., "Critical Problem") | 1 |
| `genericSolutions` | Auto-detect patterns with multiple YAML blocks | 1 |

## Working with Flagged Issues

### Step 1: Review the Issue

When you see an issue labeled `potential-ai-generated`:

1. **Read the issue carefully**
2. **Check the detected patterns** (listed in the auto-comment)
3. **Look for red flags**:
   - Future version numbers (e.g., "Kubernetes 1.33")
   - Future dates (e.g., "2026-01-27")
   - Non-existent features or configurations
   - Perfect table formatting with no actual content
   - Generic solutions that don't match Velero's architecture

### Step 2: Engage with the Contributor

**If the issue seems legitimate but over-formatted:**

```markdown
Thanks for the detailed report! Could you confirm:
1. Are you running Velero version X.Y.Z (you mentioned version A.B.C)?
2. Is the error message exactly as shown?
3. Have you actually tried the workarounds mentioned?

Once verified, we'll remove the AI-generated flag and investigate.
```

**If the issue appears to be unverified AI content:**

```markdown
This issue appears to contain AI-generated content that hasn't been verified.

Please review our [AI contribution guidelines](https://github.com/vmware-tanzu/velero/blob/main/site/content/docs/main/code-standards.md#ai-generated-content) and:
1. Confirm this describes a real problem in your environment
2. Verify all version numbers and error messages
3. Remove any placeholder or example content
4. Test that the issue is reproducible

If you can't verify the issue, please close it. We're happy to help with real problems!
```

### Step 3: Take Action

**For verified issues:**
1. Remove the `potential-ai-generated` label
2. Keep or remove `needs-triage` as appropriate
3. Proceed with normal issue triage

**For unverified/invalid issues:**
1. Request verification (see templates above)
2. If no response after 7 days, consider closing as `stale`
3. If clearly invalid, close with explanation

## Common Patterns

### False Positives (Legitimate Issues)

These may trigger the detector but are usually valid:

- **Very detailed bug reports** with extensive logs and testing
- **Technical design proposals** with multiple sections
- **Well-organized feature requests** with tables and examples

**Action**: Engage with contributor, ask clarifying questions, remove flag if verified.

### True Positives (AI-Generated)

Red flags that indicate unverified AI content:

- **Future version numbers**: "Kubernetes 1.33" (doesn't exist yet)
- **Future dates**: "2026-01-27" (if current date is before)
- **Non-existent features**: References to Velero features that don't exist
- **Generic solutions**: "Auto-detect available port" (not how Velero works)
- **Perfect formatting, wrong content**: Beautiful tables with incorrect info

**Action**: Request verification, ask for actual environment details, consider closing if unverified.

### Edge Cases

**Contributor using AI as a writing assistant:**
- Issue content is verified and accurate
- Just used AI to help structure/format the report
- **Action**: This is acceptable! Remove flag if content is verified.

**Legitimate issue that happens to match patterns:**
- Real problem with detailed analysis
- Includes proper version numbers and logs
- **Action**: Verify with contributor, remove flag once confirmed.

## Statistics and Monitoring

You can search for flagged issues:

```
is:issue label:potential-ai-generated
```

Monitor trends:
- High detection rate → May need to adjust thresholds
- Low detection rate → Patterns working well or need refinement

## Adjusting the System

### Modifying Detection Patterns

Edit `.github/workflows/ai-issue-detector.yml`:

```javascript
// Increase threshold to reduce false positives
if (aiScore >= 4) {  // was 3

// Adjust pattern sensitivity
excessiveTables: (issueBody.match(/\|.*\|/g) || []).length > 8,  // was 5
```

### Adding New Patterns

Add to the `aiPatterns` object:

```javascript
// Example: Detect excessive use of emojis
excessiveEmojis: (issueBody.match(/[\u{1F300}-\u{1F9FF}]/gu) || []).length > 10,
```

### Disabling the Workflow

Rename or delete `.github/workflows/ai-issue-detector.yml`

## Best Practices

1. **Be courteous**: Contributors may not realize their AI tool generated incorrect info
2. **Verify, don't assume**: Some detailed issues are legitimate
3. **Educate**: Point to the AI guidelines in code-standards.md
4. **Track patterns**: Note common AI-generated patterns for future improvements
5. **Iterate**: Adjust detection thresholds based on false positive rates

## FAQ

**Q: Should we reject all AI-assisted contributions?**
A: No! AI assistance is fine if the contributor verifies accuracy. We only flag unverified AI content.

**Q: What if a contributor is offended by the flag?**
A: Explain it's automated and not personal. We just need verification of technical details.

**Q: Can we automatically close flagged issues?**
A: No. Always engage with the contributor first. Some are legitimate.

**Q: What's an acceptable false positive rate?**
A: Aim for <10%. If higher, increase the threshold from 3 to 4 or 5.

## Support

Questions about the AI detection system? Tag @vmware-tanzu/velero-maintainers in issue #9501.
