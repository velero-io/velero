---
title: "Namespace Glob Patterns"
layout: docs
---

When using `--include-namespaces` and `--exclude-namespaces` flags with backup and restore commands, you can use glob patterns to match multiple namespaces.

Note: If the resolution of namespace patterns results in no namespaces, the backup will succeed with a warning.

## Supported Patterns

Velero supports the following glob pattern characters:

- `*` - Matches any sequence of characters
  ```bash
  velero backup create my-backup --include-namespaces "app-*"
  # Matches: app-prod, app-staging, app-dev, etc.
  ```

- `?` - Matches exactly one character
  ```bash
  velero backup create my-backup --include-namespaces "ns?"
  # Matches: ns1, ns2, nsa, but NOT ns10
  ```

- `[abc]` - Matches any single character in the brackets
  ```bash
  velero backup create my-backup --include-namespaces "ns[123]"
  # Matches: ns1, ns2, ns3
  ```

- `[a-z]` - Matches any single character in the range
  ```bash
  velero backup create my-backup --include-namespaces "ns[a-c]"
  # Matches: nsa, nsb, nsc
  ```

## Unsupported Patterns

The following patterns are **not supported** and will cause validation errors:

- `**` - Consecutive asterisks
- `|` - Alternation (regex operator)
- `()` - Grouping (regex operators)
- `!` - Negation
- `{}` - Brace expansion
- `,` - Comma (used in brace expansion) 

## Special Cases

- `*` alone means "all namespaces" and is not expanded
- Empty brackets `[]` are invalid
- Unmatched or unclosed brackets will cause validation errors

## Examples

Combine patterns with include and exclude flags:

```bash
# Backup all production namespaces except test
velero backup create prod-backup \
  --include-namespaces "*-prod" \
  --exclude-namespaces "test-*"

# Backup specific numbered namespaces
velero backup create numbered-backup \
  --include-namespaces "app-[0-9]"

# Restore namespaces matching multiple patterns
velero restore create my-restore \
  --from-backup my-backup \
  --include-namespaces "frontend-*,backend-*"
```
