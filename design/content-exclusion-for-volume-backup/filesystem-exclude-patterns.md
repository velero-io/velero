# Filesystem Exclude Patterns

This document specifies how **filesystem data movers** compile Volume Policy `exclude` (an ordered list of patterns) onto the volume source tree. It is the user-facing contract for `fs-backup` and for `snapshot` with a filesystem data mover.

The pattern language is independent of the filesystem uploader. Behavior specific to the current Kopia-backed uploader is described in [Current filesystem uploader behavior (Kopia)](#current-filesystem-uploader-behavior-kopia).

Future data movers can define a different language for their source tree (for example a database/table tree). Support for such movers is outside this proposal. See [Pattern Contract](content-exclusion-for-volume-backup.md#pattern-contract).

This feature adds no new in-volume ignore-file interface. The current Kopia uploader still reads `.kopiaignore`, whose rules can override Volume Policy patterns. `.gitignore` and `.veleroignore` are not added as interfaces. See [Existing Kopia filters and precedence](#existing-kopia-filters-and-precedence).

---

## Where patterns apply

Patterns are matched against paths **relative to the volume source root**:

- PodVolume `fs-backup`: the host path containing the volume data, mounted inside the dedicated data mover pod.
- CSI snapshot + filesystem data mover: the exposed snapshot filesystem root.

A leading `/` in a pattern means that volume root, not the node's POSIX `/`.

Raw-block sources have no filesystem paths to match. When `velero-fs` copies a raw-block source, exclusions are ignored with a backup warning and the full volume is backed up. See [Data-Mover Compatibility](content-exclusion-for-volume-backup.md#data-mover-compatibility).

---

## Syntax (gitignore-style)

The language is the common gitignore subset operators need for volume backups. Gitignore takes a list of patterns and matches them against a tree; filesystem movers do the same with `exclude`.

| Construct | Meaning |
| :--- | :--- |
| Unanchored name (`*.tmp`, `cache/`) | Match at any depth under the volume root |
| Leading `/` (`/cache/*`) | Match only from the volume root |
| Trailing `/` (`cache/`) | Directories only |
| `**` | Cross-directory wildcard (see below) |
| `!` | Negation: re-include a path excluded by an earlier pattern |
| `#` | Not a comment inside the YAML list. A pattern that starts with `#` is a literal pattern, not a comment — this differs from `.gitignore`, where `#` begins a comment. |

**`**` semantics** follow the gitignore rules:

- `**/b` — matches `b` at any depth under the volume root.
- `a/**` — matches everything under `a/` (any depth).
- `a/**/b` — matches `b` at any depth under `a/` (zero or more intermediate levels, e.g. `a/b`, `a/x/b`, `a/x/y/b`).
- A bare `**` matches every path.

**YAML quoting.** Patterns beginning with `!` (negation) or `#` (literal) **must be quoted** in YAML, because an unquoted `!` is parsed as a tag indicator and an unquoted `#` begins a YAML comment. Write `"!keep.tmp"` and `"#literal"`, not `!keep.tmp` or `#literal`. Quote every pattern for consistency. A leading `*` also requires quoting because YAML interprets it as an alias indicator.

Evaluation is **last match wins**, in the order of the **effective** `exclude` list (global patterns followed by per-backup patterns; see [Policy Evaluation and Precedence](content-exclusion-for-volume-backup.md#policy-evaluation-and-precedence)). Existing Kopia filters can subsequently affect this result; see [Existing Kopia filters and precedence](#existing-kopia-filters-and-precedence).

**Parent-directory rule.** A path cannot be re-included if any of its parent directories is excluded. An excluded directory is pruned — the walker never descends into it — so the entries below it are never evaluated against the list. `["cache/", "!cache/keep.txt"]` still skips `keep.txt`, because `cache/` is pruned at the top level and `keep.txt` is never reached. To keep one item under an otherwise-excluded directory, exclude the directory's *contents* instead of the directory itself: `["cache/*", "!cache/keep.txt"]`. (Equivalently, re-include the directory and then re-narrow: `["cache/", "!cache/", "cache/*", "!cache/keep.txt"]` — longer, and easier to get wrong.) This rule matters most for overlays: a backup-level `!` pattern cannot reach under a directory a global rule excluded (see [Inheriting and overriding patterns](content-exclusion-for-volume-backup.md#inheriting-and-overriding-patterns)).

| Pattern | Example match | Example non-match |
| :--- | :--- | :--- |
| `*.tmp` | `<root>/data/temp.tmp` | `<root>/data/temp.tmp.keep` (unless another pattern hits it) |
| `/cache/*` | `<root>/cache/db.sqlite` | `<root>/app/cache/x` (not at root `cache/`) |
| `cache/` | `<root>/var/cache/`, `<root>/app/cache/` | a file named `cache` |
| `logs/**/*.log` | `<root>/logs/2026/08/app.log` | `<root>/other/app.log` |
| `*.tmp` then `!important.tmp` | `<root>/data/important.tmp` is kept | other `.tmp` files are skipped |
| `/*` then `"!/important/"` | only `<root>/important/` is backed up | everything else at the top level is skipped (see [Include-only and reset workflows](#include-only-and-reset-workflows)) |

---

## Comparison with Git `gitignore`

| Aspect | Git `gitignore` | Velero filesystem `exclude` |
| :--- | :--- | :--- |
| Root of `/` | Working tree / `.git` root | Volume mount / snapshot root |
| Extra sources | `~/.config/git/ignore`, `.git/info/exclude`, nested `.gitignore` files | Resolved Volume Policy list plus existing uploader filters; Kopia reads nested `.kopiaignore` files |
| Who can change rules | Anyone who can write the tree | Policy authors through RBAC-protected ConfigMaps; volume writers can also change `.kopiaignore` |
| Case sensitivity | Follows `core.ignorecase` / OS | Not specified by Velero; see [Current filesystem uploader behavior (Kopia)](#current-filesystem-uploader-behavior-kopia) for the current uploader |
| Directory symlink + trailing `/` | Path match on the symlink | See [Current filesystem uploader behavior (Kopia)](#current-filesystem-uploader-behavior-kopia) |

Volume Policy patterns use **volume-root** anchoring. Existing `.kopiaignore` rules use the directory containing the ignore file as their scope.

---

## Current filesystem uploader behavior (Kopia)

The following behavior is specific to the current uploader. It is not guaranteed for every future filesystem uploader.

### Existing Kopia filters and precedence

The current uploader assembles Volume Policy patterns and mandatory platform exclusions in this order, with later matches taking precedence:

1. Patterns from the matching global Volume Policy rule.
2. Patterns from the matching per-backup rule.
3. Mandatory uploader exclusions, including the Windows system-directory exclusions below.

Policy inheritance and first-match selection determine which patterns contribute to steps 1 and 2. Mandatory exclusions are appended by the uploader after the effective Volume Policy list and cannot be overridden by that list, including through `!**` or targeted negation. This precedence guarantee covers Volume Policy patterns; user-managed in-volume ignore files are outside this policy contract.

The current Kopia uploader also reads applicable `.kopiaignore` rules, including rules in nested directories that the walker reaches. A `.kopiaignore` file can add exclusions or re-include paths excluded by policy patterns. Nested rules are scoped to their directory and descendants; deeper rules can override inherited rules there. An excluded parent directory is still pruned, so a nested ignore file cannot re-include content beneath a directory the walker never enters.

Kopia also recognizes valid `CACHEDIR.TAG` markers and treats tagged directories as empty. This check is separate from ordered patterns; negation, including `!**`, does not override it.

`inheritExcludes: false` discards global policy patterns only. Neither that setting nor an empty policy list disables `.kopiaignore`, cache-directory filtering, or mandatory Windows exclusions. Backup logs record the resolved policy list, not every filter that ultimately affects the payload.

### Case sensitivity

The current matcher compiles patterns case-sensitively. `*.tmp` does **not** match `FILE.TMP` on Windows or macOS volumes. Users on case-insensitive filesystems should use lowercase names or test a restore.

To match both lowercase and uppercase extensions, list both cases explicitly, e.g. `exclude: ["*.tmp", "*.TMP"]`. Velero does not normalize case at the API level; a future FS uploader is free to choose case-insensitive matching, so users should not rely on case-sensitive behavior as a Velero-wide guarantee.

### Symlinks

Patterns match the symlink’s own name. A directory-only pattern (`cache/`) does **not** exclude a symlink named `cache`, even if it points at a directory. The symlink object is backed up.

To exclude the symlink by name, use `cache` without a trailing slash.

### Mandatory Windows exclusions

On Windows, the uploader appends `/System Volume Information/` and `/$Recycle.Bin/` after all effective Volume Policy patterns. These directories must be excluded to avoid backup failures. Volume Policy negations, including `!**`, `!/System Volume Information/`, and `!/$Recycle.Bin/`, cannot re-include them. `inheritExcludes: false` clears only inherited global patterns and does not remove these mandatory uploader exclusions.

---

## Portability across filesystem uploaders

Replacement filesystem uploaders must preserve the ordered pattern list and the gitignore-style semantics in [Syntax (gitignore-style)](#syntax-gitignore-style), including root anchoring, `**`, directory-only matching, negation, and last-match-wins evaluation. Uploaders may impose mandatory exclusions required for a successful backup. They must append these after the effective Volume Policy patterns and document the restrictions; last-match-wins still applies within the user-supplied list. Platform defaults and additional filters must be documented separately, including whether they can be overridden. The current uploader’s behavior is specified above; it is not a guarantee that every uploader reads `.kopiaignore` or recognizes cache tags.

---

## Include-only and reset workflows

There is no `include` counterpart to `exclude`. To back up only a specific subtree, use a root-anchored broad exclude followed by a negation:

```yaml
exclude:
  - "/*"
  - "!/important/"
```

`/*` excludes every top-level entry under the volume root; `!/important/` re-includes the `important/` directory entry itself, so the walker descends into it and keeps everything below (last-match-wins). The policy list retains only `/important/`, **with its contents**, subject to existing uploader filters.

Use the **anchored** `/*`, not a bare `*`. An unanchored `*` matches names at any depth — including the files inside `important/` — so `["*", "!/important/"]` re-includes the directory entry but still excludes its contents, producing a backup of an empty directory.

Caveats:

- Negation is evaluated against every entry — directories included — during the parent directory's iteration, before the walker decides whether to descend. That is why `!/important/` works: it re-includes the directory entry itself. But negation cannot reach *inside* a directory that remains excluded (the parent-directory rule, [Syntax (gitignore-style)](#syntax-gitignore-style)): `"!/important/db.sqlite"` alone cannot re-include that file while `important/` is excluded.
- To include only specific files (not a whole subtree), re-include the directory, exclude its contents, then re-include the files: `["/*", "!/important/", "/important/*", "!/important/db.sqlite", "!/important/config.yaml"]`.

### Resetting inherited exclusions

There are two ways to reset or override an inherited global baseline:

#### Policy Attribute `inheritExcludes: false` (Canonical & Mover-Agnostic)

The standard, mover-agnostic way to discard inherited global exclusions is to set `inheritExcludes: false` on the matching per-backup rule (see [Discarding or replacing global exclusions](content-exclusion-for-volume-backup.md#discarding-or-replacing-global-exclusions)):

```yaml
# Discard global policy exclusions (existing uploader filters still apply):
- conditions:
    pvcLabels: { app: postgres }
  action:
    type: fs-backup
  inheritExcludes: false

# Or replace the global baseline with this volume's own list:
- conditions:
    pvcLabels: { app: web }
  action:
    type: fs-backup
  inheritExcludes: false
  exclude:
    - "*.log"
```

This operates at the policy engine level: patterns from the matching global rule are omitted from the effective list. It requires no pattern matching, works identically for any data mover, and does not require knowledge of filesystem wildcard syntax.

#### Pattern-Level Re-Include via `!**` (Filesystem Matcher Technique)

Within filesystem matchers, a rule inheriting the baseline can also neutralize prior patterns using the gitignore wildcard negation idiom:

```yaml
exclude:
  - "!**"     # re-include anything an inherited (global) pattern excluded
  - "*.log"   # ...then apply this backup's own exclusions
```

A bare `**` matches every path, so `!**` re-includes every entry as it is evaluated: earlier Volume Policy patterns, including inherited global patterns, take no effect, while patterns listed after it (here `*.log`) apply normally. Mandatory uploader exclusions are appended afterward and remain in effect. While effective in gitignore trees, `inheritExcludes: false` is preferred for clarity and cross-mover portability.
