# GitHub Copilot instructions for velero-io/velero

## Changelog requirement

Velero uses per-PR changelog fragments that are assembled into release notes.

### File naming convention

Every shipping PR must add exactly **one** file at:

```
changelogs/unreleased/<PR_NUMBER>-<github_username>
```

- `<PR_NUMBER>` is the pull request number (e.g. `10200`).
- `<github_username>` is the GitHub login of the PR author (e.g. `jdoe`).
- The file has **no extension**.
- The file content is a single line describing the change (the PR title is a
  sensible default).

**Example:** PR #10200 by `jdoe` → `changelogs/unreleased/10200-jdoe`

The easiest way to create this file is:

```bash
make new-changelog CHANGELOG_BODY="Brief description of the change"
```

`make new-changelog` reads the PR number and author from `gh pr view`; the file
is written automatically to the correct path with the correct name.

The CI check (`hack/changelog-check.sh`) looks for
`changelogs/unreleased/<PR_NUMBER>-*` and fails if no file is found.

### When a changelog is NOT required

A changelog entry is **not** required when a PR exclusively changes non-shipping
content, i.e. the only files touched belong to one or more of these categories:

| Category | Paths |
|---|---|
| GitHub Actions / CI workflows | `.github/**` |
| Documentation | `site/content/docs/**`, `site/**`, `docs/**`, `*.md` |
| Website (non-docs) | `site/**` (excluding `site/content/docs/**`) |

When you open or review a PR that falls into one of the above categories (and does
**not** modify `pkg/`, `internal/`, `cmd/`, `vendor/`, `hack/`, `Makefile`,
`go.mod`, `go.sum`, or `changelogs/**`), apply the label
**`kind/changelog-not-required`** instead of requesting a changelog entry.  The
`labeler.yml` auto-labeler handles this automatically for most cases; apply the
label manually if the auto-labeler did not.

## Backport / cherry-pick workflow

Velero uses `.github/workflows/backport.yml` to automate cherry-picks onto release
branches.

- **Before merge:** comment `/backport release-1.17` (or `/cherrypick release-1.17`)
  to add the label `backport release-1.17` to the PR.  Multiple branches can be
  space-delimited: `/backport release-1.17 release-1.18`.  The label causes the
  backport to run automatically when the PR merges.
- **After merge:** the same comment immediately creates the backport PR.
- **Shorthand:** a bare version like `/backport 1.17` is automatically expanded
  to `release-1.17`; this works generically for any `X.Y` version.
- **Changelog filename:** the cherry-picked commit(s) carry over the source
  PR's `changelogs/unreleased/<source_pr>-<user>` file. The workflow
  automatically renames it to `<backport_pr>-<user>` on the backport branch so
  `hack/changelog-check.sh` passes and release notes cite the correct PR.
- **Changelog-not-required:** if the source PR is labeled
  `kind/changelog-not-required`, that label is copied to the backport PR so
  it isn't flagged as missing a changelog.
- **DCO signoff:** every commit on a backport branch is re-signed with the
  bot's `Signed-off-by` trailer (`git rebase --signoff`), including
  cherry-picked commits from the original author, so the DCO check always
  passes on backport PRs.
- Only repository **owners, members, and collaborators** may trigger these commands.

## General coding guidelines

- Follow the existing code style of the file being edited.
- Add unit tests for new exported functions in `pkg/`.
- Do not commit secrets, credentials, or API tokens.
- Keep PRs focused; prefer small, reviewable changes over large omnibus PRs.
