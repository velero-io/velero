# CRD Schema Validation at Server Startup

## Background

Velero server can currently start against CRDs from any Velero version — for example v1.15.x CRDs installed alongside a v1.16.x server. The existing startup check, `veleroResourcesExist()`, only verifies that the Velero CRDs exist and expose the expected API group/version. It does not verify that the installed CRD's schema actually contains the fields the running server's Go API types expect.

When CRDs are stale relative to the server, this produces silent failures, confusing runtime errors far from their root cause, and no proactive signal telling the user to run `velero install --crds-only` (added in #9132) to bring the CRDs up to date.

Issue #9260 requests a startup-time compatibility check so that mismatches are caught immediately, with a clear message, instead of surfacing later as an unrelated-looking bug.

## Goals

- Validate at server startup that installed CRD schemas contain the fields the server's Go API types expect.
- Fail fast with an actionable error message (naming the missing fields and suggesting `velero install --crds-only`) when validation is configured to be strict.
- Default to warn-only behavior so existing deployments are not broken by upgrading to a server with this check.

## Non Goals

- Enforcing CRD compatibility via a `ValidatingAdmissionWebhook` (considered, see Alternatives Considered).
- Detecting/handling patch-version-only CRD differences specially; the schema-property comparison already tolerates patch releases that changed no fields, so no separate version-matching logic is needed.
- Introducing a stored, hand-maintained schema/version map that must be kept in sync manually; the expected schema is derived from the Go API types at runtime instead.

## Design

### CRD version identification approaches considered

| Approach | Verdict |
|---|---|
| `controller-gen.kubebuilder.io/version` annotation | Insufficient — CRD schema can change without a controller-gen version bump |
| `app.kubernetes.io/version` label on CRDs | Rejected — forces a CRD reapply on every patch release even when the schema is unchanged |
| Schema hash validation | Rejected — a hash mismatch says *that* something differs, not *what*, and is brittle to non-semantic YAML differences |
| Static resource-version compatibility matrix in server code | Rejected — another hand-maintained artifact that drifts from the real API types |
| **Schema property validation (chosen)** | Reflects on the Go API types for expected top-level JSON field names, and compares them against the installed CRD's `openAPIV3Schema.properties`. Directly answers "does the CRD have what the server needs," and missing fields are named in the resulting message. |

### Expected schema derivation

A new file `pkg/cmd/server/crd_check.go` builds the expected schema for each Velero CRD kind from the existing type registries `velerov1api.CustomResources()` and `velerov2alpha1api.CustomResources()` (`pkg/apis/velero/{v1,v2alpha1}/register.go`), rather than a hand-maintained map:

```go
type crdSchemaExpectation struct {
	crdName            string
	specType           reflect.Type
	statusType         reflect.Type
	apiGroupVersion    string
	storedVersionLabel string
}

func expectedCRDSchemas() []crdSchemaExpectation
```

For each registered kind, the `Spec`/`Status` field types are read off the registered item type via reflection. `jsonFieldNames(t reflect.Type)` walks a struct's fields (following anonymous/embedded fields) and collects the top-level `json` tag names, skipping untagged and `json:"-"` fields.

### Installed schema extraction and comparison

`schemaPropertyNames(schema *apiextv1.JSONSchemaProps, path string)` walks the CRD's `openAPIV3Schema` down a dotted path (`"spec"` or `"status"`) and returns the property names defined at that node.

`checkMissing(goType, schema, section, crdName)` diffs the expected (Go) field set against the installed (CRD) field set and returns only fields the **server expects but the CRD does not have** — i.e. an outdated CRD. Fields present in the CRD but not in the current Go type are intentionally not flagged, since a CRD newer than the server is forward-compatible.

### Validation flow

`(s *server) validateCRDSchemas() error`:

1. Returns immediately, logging at info level, if `s.config.CRDSchemaCheck == "skip"`.
2. Builds an `apiextclient.Interface` from the server's existing kube client config — no new RBAC is required, since Velero's server already needs `get` on CRDs for other startup checks.
3. Delegates to `runCRDSchemaValidation()`, which for each expected CRD:
   - `Get`s the CRD by name (`<plural>.velero.io`); a fetch error is logged as a warning and that CRD is skipped rather than failing the whole check.
   - Locates the schema for the CRD version matching `apiGroupVersion`.
   - Runs `checkMissing` against both `spec` and `status`.
   - Aggregates all missing fields across all CRDs into one message, naming each as `<crd>: <section>.<field>` and suggesting `velero install --crds-only`.
4. In `strict` mode, the aggregated message is returned as an error (server startup fails). In `warn` mode (default), it is logged at error level and startup continues.

### Integration point

In `pkg/cmd/server/server.go`, `(s *server) run()` calls `s.validateCRDSchemas()` immediately after the existing `veleroResourcesExist()` check succeeds, keeping the two CRD-related startup checks (existence, then schema) colocated:

```go
if err := s.validateCRDSchemas(); err != nil {
	return err
}
```

### Configuration

A new server flag, `--crd-schema-check`, is added to `pkg/cmd/server/config/config.go`:

- New `Config.CRDSchemaCheck string` field, default `"warn"`.
- Valid values: `warn` (log an error-level message but continue starting — default, preserves current behavior for existing deployments), `strict` (fail startup on mismatch), `skip` (perform no check).
- A named-mode string flag was chosen over a bool so that `skip` remains available independently of `strict`/`warn` — for example during a rolling upgrade window where a mismatch is expected and should not even be logged.

## Implementation

- **Expected schema + validation logic.** New `pkg/cmd/server/crd_check.go`: `crdSchemaExpectation`, `expectedCRDSchemas()`, `jsonFieldNames()`, `schemaPropertyNames()`, `validateCRDSchemas()`, `runCRDSchemaValidation()`, `checkMissing()`.
- **Server flag and config.** Add `CRDSchemaCheck` to `Config` in `pkg/cmd/server/config/config.go`, default it to `"warn"` in `GetDefaultConfig`, and bind `--crd-schema-check` in `Config.BindFlags`.
- **Call site.** In `pkg/cmd/server/server.go`, call `s.validateCRDSchemas()` in `run()` right after `veleroResourcesExist()` succeeds.
- **Unit tests.** New `pkg/cmd/server/crd_check_test.go` covering `jsonFieldNames` (tags, embedding, `omitempty`/`-`), `schemaPropertyNames` (path traversal), `checkMissing` (matching/missing/extra fields), `expectedCRDSchemas` (all registered kinds produce an expectation), and `runCRDSchemaValidation` across `warn`/`strict`/`skip` against a fake apiextensions client.

Reference implementation: [PR #9910](https://github.com/velero-io/velero/pull/9910).

## Security Considerations

None. The check uses the server's existing kube client config and the same CRD `get` permission Velero's server already requires for other startup validation (see the documented [restricted RBAC](https://github.com/velero-io/velero/blob/main/site/content/docs/main/rbac.md)). No new RBAC scope is introduced, and no new data is exposed.

## Compatibility

- The feature is on by default in `warn` mode, but `warn` mode only logs — it never fails startup — so no existing deployment's server will fail to start as a result of upgrading to a server version that includes this check.
- `strict` mode is opt-in and is the only mode that changes startup behavior (fails startup on a real mismatch).
- `skip` mode fully disables the check, matching today's behavior exactly.

## Alternatives Considered

- **Schema hash validation.** Simpler to compute, but a hash mismatch is opaque — it doesn't say which field is missing — and is brittle to cosmetic/non-semantic differences in generated CRD YAML.
- **Admission webhook enforcement.** Would prevent an incompatible Pod from ever running, but requires webhook infrastructure and certificate management disproportionate to a startup self-check; could be revisited later if `warn`/`strict` prove insufficient.
- **Strict patch-version matching.** Raised during issue discussion as an alternative to schema diffing, but rejected because it would either force a CRD reapply on every patch release (if CRD version is always incremented) or require a separate mechanism to know which patch releases changed the schema. Schema-property comparison naturally tolerates patch releases with no schema changes.

## Open Issues

- Whether `strict` should become the default in a future major version once the check has proven reliable across the community.
- Whether the aggregated warning should also be surfaced as a Kubernetes `Event` on the Velero deployment/pod for better operator visibility, in addition to server logs.
