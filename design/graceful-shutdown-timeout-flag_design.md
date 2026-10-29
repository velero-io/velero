# Graceful Shutdown Timeout for Velero Server

## Abstract
The `velero server` process builds its `controller-runtime` manager without setting `manager.Options.GracefulShutdownTimeout`, so it silently inherits `controller-runtime`'s hardcoded 30 second default regardless of the pod's `terminationGracePeriodSeconds`.
This proposal makes `velero server` derive that timeout automatically from its own Pod's live `terminationGracePeriodSeconds` (so it stays in sync with the value the operator already configured, with no new number to keep in step), and adds a `--graceful-shutdown-timeout` flag as an explicit override for cases where auto-derivation isn't available or isn't wanted.

## Background
`pkg/cmd/server/server.go` constructs the manager like this:
```go
mgr, err = ctrl.NewManager(clientConfig, ctrl.Options{
    Scheme: scheme,
    Cache: cache.Options{
        DefaultNamespaces: map[string]cache.Config{f.Namespace(): {}},
    },
})
```
No `GracefulShutdownTimeout` is set.
`sigs.k8s.io/controller-runtime`'s `pkg/manager/internal.go` fills that gap with `defaultGracefulShutdownPeriod = 30 * time.Second` whenever the field is `nil`.
When the manager is asked to stop, it waits at most that long for all running controllers to return before logging `failed waiting for all runnables to end within grace period of 30s` and exiting anyway.

This becomes a real availability problem on clusters that reschedule pods for reasons other than a Deployment rollout, e.g. Kubernetes node-autoscaler-driven node disruption (Karpenter drift/consolidation, cluster-autoscaler, cloud-provider maintenance events).
In that scenario the pod is deleted directly rather than replaced by a `Recreate`/`RollingUpdate` rollout, so:
- the running Velero pod receives `SIGTERM` and has up to `terminationGracePeriodSeconds` (commonly set well above 30s, e.g. the official Helm chart defaults to 3600s) to shut down cleanly, but
- the manager itself force-exits after only 30 seconds, well before that window, cutting off any backup/restore reconcile that hasn't finished.

The 30 second value is `controller-runtime`'s default, not a deliberate Velero choice, and today there is no way to change it short of patching Velero's source - it isn't exposed by any existing `velero server` flag (confirmed against the full flag list in `pkg/cmd/server/config/config.go`).

A natural first fix is "just add a flag for it" - but that creates a second number (`terminationGracePeriodSeconds` on the Pod, and the new flag on the container command) that the operator must set and keep in sync by hand.
Kubernetes' Downward API can't close that gap by itself: its `fieldRef` mechanism only supports a small fixed allowlist of fields (`metadata.name/namespace/uid/labels/annotations`, plus `spec.nodeName`, `spec.serviceAccountName`, `status.hostIP`, `status.podIP(s)` - confirmed against `k8s.io/kubernetes/pkg/fieldpath.ExtractFieldPathAsString`), and `spec.terminationGracePeriodSeconds` isn't in it, for any Pod, in any tool.
However, Velero doesn't need the Downward API for this: it already runs with a full `kubeClient` clientset and a namespaced `Role` granting `apiGroups: ["*"], resources: ["*"], verbs: ["*"]`, so it can simply `Get` its own Pod object from the API server and read `pod.Spec.TerminationGracePeriodSeconds` directly - no RBAC change needed, just one more Downward-API-*supported* env var so it knows its own Pod name.

## Goals
- Make `velero server`'s shutdown window track the value the operator already configured on the Pod (`terminationGracePeriodSeconds`), with no second number to set or keep in sync for the common case.
- Still let operators override that derived value explicitly, for cases where auto-derivation isn't available (e.g. running outside a real Pod, such as in tests) or isn't desired (e.g. leaving headroom for a `preStop` hook).
- Preserve today's effective behavior for installs that never touched `terminationGracePeriodSeconds` - Kubernetes defaults that field to 30s itself, so auto-derivation reproduces the current 30s cutoff for the common case and only changes behavior for installs that deliberately raised it.

## Non Goals
- This does **not** fix the separate race where a *replacement* Velero pod, started while the old pod is still terminating, unconditionally marks any `InProgress` backup/restore as `Failed` on startup (`markInProgressCRsFailed` in `pkg/cmd/server/server.go`). That race is tracked upstream as [#9036](https://github.com/velero-io/velero/issues/9036) and is unaffected by this proposal - raising the shutdown timeout only helps the *old* pod finish faster, it does not stop the *new* pod from failing the backup independently.
- This does not add multi-replica or leader-election support to the Velero server ([#9062](https://github.com/velero-io/velero/issues/9062)). That is a materially larger change (the manager, the Helm chart's hardcoded `replicas: 1`, and in-flight CR handoff would all need work) and is out of scope here.

## High-Level Design
Add a `POD_NAME` Downward-API env var (a field the API *does* support), have `newServer()` use it plus the existing `VELERO_NAMESPACE` to `Get` its own Pod and read `pod.Spec.TerminationGracePeriodSeconds`, and use that (minus a safety buffer) as the manager's `GracefulShutdownTimeout` by default.
Add `GracefulShutdownTimeout` and `GracefulShutdownSafetyBuffer time.Duration` fields to `config.Config`, bound to new `--graceful-shutdown-timeout` and `--graceful-shutdown-safety-buffer` flags; the former takes precedence over the derived value whenever it's explicitly set (and rejects a non-positive explicit value at flag-parse time), the latter controls the buffer subtracted during derivation instead of being a fixed constant.
Pass the resolved value's address into the `ctrl.Options{}` literal used to build the manager in `newServer()`.
The `POD_NAME` env var is added both to the Helm chart (as originally proposed, in a follow-up PR to that separate repo) and to the `velero install`-generated Deployment in `pkg/install/deployment.go`, so non-Helm installs also get real auto-derivation.

## Detailed Design

*The code below reflects what was actually implemented (see `pkg/cmd/server/config/config.go` and `pkg/cmd/server/server.go` for the shipped source).*

**`pkg/cmd/server/config/config.go`**
- Add two fields to `Config`: the timeout defaults to the zero value (meaning "not explicitly set - derive it"); the safety buffer is configurable, not a fixed constant, defaulting to 10s:
  ```go
  GracefulShutdownTimeout      time.Duration
  GracefulShutdownSafetyBuffer time.Duration
  ```
- The timeout flag can't use a plain `DurationVar`, because its own zero value already means "derive automatically" (FR2), so a runtime check can't distinguish "flag not passed" from "flag explicitly passed as `0`" - but only the latter must be rejected.
  Instead, bind it via a small unexported `pflag.Value` (the same idiom as `pkg/cmd/util/flag/optional_bool.go`) whose `Set()` is only invoked when the operator actually passes the flag:
  ```go
  type gracefulShutdownTimeoutValue struct {
      duration *time.Duration
  }

  func (f *gracefulShutdownTimeoutValue) Set(val string) error {
      d, err := time.ParseDuration(val)
      if err != nil {
          return err
      }
      if d <= 0 {
          return errors.New("--graceful-shutdown-timeout must be positive; omit the flag to derive it automatically from the pod's terminationGracePeriodSeconds")
      }
      *f.duration = d
      return nil
  }
  ```
- Bind both flags in `BindFlags()`:
  ```go
  flags.Var(&gracefulShutdownTimeoutValue{duration: &c.GracefulShutdownTimeout}, "graceful-shutdown-timeout",
      "How long the server waits for in-flight controller work to finish before force-exiting on shutdown. If unset (default), derived automatically from the pod's terminationGracePeriodSeconds minus --graceful-shutdown-safety-buffer.")
  flags.DurationVar(&c.GracefulShutdownSafetyBuffer, "graceful-shutdown-safety-buffer", c.GracefulShutdownSafetyBuffer,
      "Buffer subtracted from the pod's terminationGracePeriodSeconds when auto-deriving --graceful-shutdown-timeout. Default is 10 seconds.")
  ```

**Helm chart (`vmware-tanzu/helm-charts`, `charts/velero`) - `templates/deployment.yaml`**
- Add a `POD_NAME` env var next to the existing `VELERO_NAMESPACE` one, using a Downward API field that Kubernetes *does* support:
  ```yaml
  - name: POD_NAME
    valueFrom:
      fieldRef:
        apiVersion: v1
        fieldPath: metadata.name
  ```
- No other chart change is required.
  If an explicit override is wanted, `configuration.extraArgs: ["--graceful-shutdown-timeout=55m"]` already works today via the existing `extraArgs` passthrough once the flag exists upstream.
- This chart PR lives in a separate repository and ships as a sequenced follow-up after the `velero-io/velero` code change merges (see Implementation below).

**`pkg/install/deployment.go` (discovered during implementation - not in the original proposal)**
- The Helm chart is not the only way to install Velero; `velero install` generates its own Deployment manifest in this file, which also lacked a `POD_NAME` env var.
  Without it, non-Helm installs would only ever hit the warn-and-fallback path (self-lookup always fails), defeating the point of auto-derivation for the majority of Velero's install base.
  A `POD_NAME` entry was added to the file's own default `Env` slice, next to `VELERO_NAMESPACE`, mirroring its `FieldRef` shape - and, unlike the Helm chart change, ships in the same PR as the Go code change since it lives in this repository.

**`pkg/cmd/server/server.go`**
- Add a small helper that looks up the server's own Pod and returns its `terminationGracePeriodSeconds`:
  ```go
  func selfTerminationGracePeriod(ctx context.Context, kubeClient kubernetes.Interface, namespace string) (time.Duration, error) {
      podName := os.Getenv("POD_NAME")
      if podName == "" {
          return 0, errors.New("POD_NAME environment variable is not set")
      }
      pod, err := kubeClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
      if err != nil {
          return 0, errors.WithStack(err)
      }
      if pod.Spec.TerminationGracePeriodSeconds == nil {
          return 0, errors.New("pod's terminationGracePeriodSeconds is not set")
      }
      return time.Duration(*pod.Spec.TerminationGracePeriodSeconds) * time.Second, nil
  }
  ```
- A second helper resolves the manager's shutdown timeout with the flag taking precedence, then the derived value, then today's 30s as a last-resort fallback, and is called once in `newServer()` before the existing manager-construction retry loop:
  ```go
  func resolveGracefulShutdownTimeout(ctx context.Context, kubeClient kubernetes.Interface, namespace string, cfg *config.Config, logger logrus.FieldLogger) time.Duration {
      if cfg.GracefulShutdownTimeout > 0 {
          return cfg.GracefulShutdownTimeout
      }

      terminationGracePeriod, err := selfTerminationGracePeriod(ctx, kubeClient, namespace)
      if err != nil {
          logger.WithError(err).Warnf("Could not determine this pod's terminationGracePeriodSeconds, falling back to the default graceful shutdown timeout of %s", defaultGracefulShutdownTimeout)
          return defaultGracefulShutdownTimeout
      }

      derived := terminationGracePeriod - cfg.GracefulShutdownSafetyBuffer
      if derived <= 0 {
          logger.Warnf("Derived graceful shutdown timeout (%s terminationGracePeriodSeconds - %s safety buffer) is not positive, falling back to the default graceful shutdown timeout of %s", terminationGracePeriod, cfg.GracefulShutdownSafetyBuffer, defaultGracefulShutdownTimeout)
          return defaultGracefulShutdownTimeout
      }

      return derived
  }

  // in newServer(), before the manager-construction retry loop:
  gracefulShutdownTimeout := resolveGracefulShutdownTimeout(ctx, kubeClient, f.Namespace(), config, logger)

  mgr, err = ctrl.NewManager(clientConfig, ctrl.Options{
      Scheme: scheme,
      Cache: cache.Options{
          DefaultNamespaces: map[string]cache.Config{f.Namespace(): {}},
      },
      GracefulShutdownTimeout: &gracefulShutdownTimeout,
  })
  ```
  where `defaultGracefulShutdownTimeout = 30 * time.Second` matches `controller-runtime`'s own default, and `cfg.GracefulShutdownSafetyBuffer` is the configurable flag above (not a fixed constant as originally proposed - see Open Issues).

## Alternatives Considered
- **A plain opt-in flag with no auto-derivation** (the original version of this proposal). Rejected as the primary mechanism: it works, but it permanently leaves two numbers (`terminationGracePeriodSeconds` and the flag) for every operator to set and keep in sync by hand, which is exactly the kind of drift that caused this bug in the first place (the Pod's `terminationGracePeriodSeconds` was already raised to 3600s in the official chart, while the manager's internal timeout silently stayed at 30s). Kept as the explicit-override escape hatch, not the default path.
- **Expose `terminationGracePeriodSeconds` via a Downward API `fieldRef`/`resourceFieldRef` env var**, avoiding the need for an API call. Rejected: not possible. `spec.terminationGracePeriodSeconds` is not in the Downward API's supported field allowlist (confirmed against `k8s.io/kubernetes/pkg/fieldpath.ExtractFieldPathAsString`), for any Pod, in any tool - there is no `fieldRef` path for it today.
- **Raise the hardcoded default instead of adding any configurability.** Rejected: there is no single value that fits every deployment, and it wouldn't adapt per-install the way deriving from the live Pod spec does.
- **Rely solely on a pod `preStop` hook with a `sleep`.** This delays *when* `SIGTERM` is delivered, but once it is delivered the manager's internal 30s timeout still applies, so it only shifts the problem rather than solving it. It remains a valid complementary mitigation, not a substitute.
- **Solve this via leader election / multiple replicas (a second Velero instance takes over the in-flight backup).** Rejected for this proposal's scope: `controller-runtime` supports leader election, but Velero's manager never enables it, the official Helm chart hardcodes `replicas: 1`, and there is no design today for safely handing off an in-flight `Backup`/`Restore` CR between instances. This is tracked separately as [#9062](https://github.com/velero-io/velero/issues/9062) and would be a much larger effort.

## Security Considerations
None.
The self-lookup uses a `Get` on the server's own Pod, which its existing namespaced `Role` (`apiGroups: ["*"], resources: ["*"], verbs: ["*"]`) already permits - no RBAC change needed.
No new privileges, network exposure, or data handling is introduced.

## Compatibility
Backward compatible in practice, though the *effective* default value can change for installs that raised `terminationGracePeriodSeconds` above 30s: Kubernetes itself defaults that field to 30s when unset, so installs that never touched it keep today's ~30s cutoff unchanged; installs that deliberately raised it (like the official Helm chart's `terminationGracePeriodSeconds: 3600`) now get a shutdown window that matches what they already asked Kubernetes for, instead of being silently capped at 30s.
This is the intended fix, but it's a real behavior change and should be called out prominently in the release notes, with the `--graceful-shutdown-timeout` flag documented as the way to pin the old 30s behavior explicitly if needed.

## Implementation
- [x] Added the `GracefulShutdownTimeout` and `GracefulShutdownSafetyBuffer` `Config` fields and flag bindings in `pkg/cmd/server/config/config.go`, with flag-parse-time rejection of a non-positive explicit `--graceful-shutdown-timeout`.
- [x] Added the self-lookup helper and the precedence logic (flag → derived-from-Pod → 30s fallback) in `pkg/cmd/server/server.go`, with unit tests (`TestResolveGracefulShutdownTimeout` in `pkg/cmd/server/server_test.go`) covering: flag set, Pod lookup succeeds, Pod lookup fails (`POD_NAME` unset), `terminationGracePeriodSeconds` unset on the Pod, and a derived value that underflows to non-positive.
- [x] Added the `POD_NAME` Downward API env var to the `velero install`-generated Deployment in `pkg/install/deployment.go` (in scope for this repo; discovered during implementation - not in the original proposal).
- [x] Added a changelog fragment per Velero's contribution process.
- [x] Documented the flags and the auto-derivation behavior on `site/content/docs/main/customize-installation.md`, explicitly noting the non-goal above: this does not, by itself, prevent a replacement pod from marking an in-flight backup `Failed` (see [#9036](https://github.com/velero-io/velero/issues/9036)); it only extends how long the *current* pod is given to finish before being force-stopped.
- [ ] The Helm chart's `templates/deployment.yaml` `POD_NAME` env var ships as a separate, sequenced follow-up PR in `vmware-tanzu/helm-charts`, opened only after this repo's change merges (per the Alternatives/High-Level Design sections above).

## Open Issues
The original proposal left three questions open; all three were resolved before implementation.

- Is a fixed `gracefulShutdownSafetyBuffer` good enough, or should it also be configurable? **Resolved: configurable.** A `--graceful-shutdown-safety-buffer` flag was added (default 10s) instead of a hardcoded constant, since reviewers/operators may run in environments where 10s isn't the right margin.
- Should there be validation that rejects an explicit `--graceful-shutdown-timeout` of 0 or negative, given `controller-runtime` treats a negative value as "wait forever"? **Resolved: reject both**, rather than exposing that "wait forever" semantic. Rejection happens at flag-parse time via a custom `pflag.Value` (see Detailed Design), with an error message directing the operator to omit the flag for auto-derivation.
- Should the self-lookup failure (e.g. `POD_NAME` unset) be a hard error instead of a warn-and-fallback? **Resolved: warn-and-fallback**, as originally leaned toward. Any self-lookup failure (`POD_NAME` unset, API error, or `terminationGracePeriodSeconds` unset) logs a capitalized warning and falls back to the 30s default rather than blocking server startup.
