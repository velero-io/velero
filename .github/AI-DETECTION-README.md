# AI-Generated Content Detection

This directory contains the AI-generated content detection system for Velero issues.

## Overview

The Velero project has implemented automated detection of potentially AI-generated issues to help maintain quality and ensure that issues describe real, verified problems.

## How It Works

### Detection Workflow

The workflow (`.github/workflows/ai-issue-detector.yml`) runs automatically when:
- A new issue is opened
- An existing issue is edited

### Detection Patterns

The detector analyzes issues for several AI-generation patterns:

1. **Excessive Tables** - More than 5 markdown tables
2. **Excessive Headers** - More than 8 consecutive section headers
3. **Formal Phrases** - Multiple formal section headers typical of AI (e.g., "Root Cause Analysis", "Operational Impact", "Expected Permanent Solution")
4. **Excessive Formatting** - Multiple horizontal rules and perfect formatting
5. **Future Dates** - Version numbers or dates that are unrealistic or in the future
6. **Perfect Formatting** - Overly structured tables with perfect alignment
7. **AI Section Headers** - Generic AI-style headers like "Critical Problem", "Resolution Attempts"
8. **Generic Solutions** - Auto-generated solution patterns with multiple YAML examples

### Scoring System

Each detected pattern adds to the AI score. If the score is 3 or higher (out of 8), the issue is flagged as potentially AI-generated.

### Actions Taken

When an issue is flagged:
1. A `potential-ai-generated` label is added
2. A `needs-triage` label is added
3. An automated comment is posted explaining:
   - Why the issue was flagged
   - What patterns were detected
   - Guidelines for contributors to follow
   - Request for verification

## For Contributors

If your issue is flagged:

1. **Don't panic** - This is not an accusation, just a request for verification
2. **Review the guidelines** in our [Code Standards](../site/content/docs/main/code-standards.md#ai-generated-content)
3. **Verify your content**:
   - Ensure all version numbers are accurate
   - Confirm error messages are from your actual environment
   - Remove any placeholder or example content
   - Simplify overly structured formatting
4. **Update the issue** with corrections if needed
5. **Comment to confirm** that the issue describes a real problem

## For Maintainers

When reviewing flagged issues:

1. Check if the technical details are realistic and verifiable
2. Look for signs of hallucinated content (fake version numbers, non-existent features)
3. Engage with the issue author to verify the problem
4. Remove the `potential-ai-generated` label once verified
5. Close issues that cannot be verified or describe non-existent problems

## Configuration

The detection patterns can be adjusted in the workflow file if needed. The threshold is currently set at 3 out of 8 patterns to balance false positives with detection accuracy.

## False Positives

The detector may occasionally flag legitimate issues, especially those that are:
- Very detailed and well-structured
- Using formal technical documentation style
- Reporting complex problems with extensive details

This is intentional - we prefer to verify detailed issues rather than miss AI-generated ones.
