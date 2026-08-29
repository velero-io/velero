---
title: "Run in a non-default namespace"
layout: docs
---

The Velero installation and backups by default are run in the `velero` namespace. However, it is possible to use a different namespace.

## Customize the namespace during install

Use the `--namespace` flag, in conjunction with the other flags in the `velero install` command (as shown in the [the Velero install instructions][0]). This will inform Velero where to install.

## Customize the namespace for operational commands

To have namespace consistency, specify the namespace for all Velero operational commands to be the same as the namespace used to install Velero:

```bash
velero client config set namespace=<NAMESPACE_VALUE>
```

If Velero was installed in the namespace of your current kubeconfig context, you can have operational commands automatically use that namespace, without having to type it out or update it every time you switch contexts:

```bash
velero client config set namespace-mode=auto
```

With `namespace-mode=auto` set, Velero resolves the namespace from the current kubeconfig context (or the context specified with `--kubecontext`) on every command invocation, instead of using the static `namespace` value. If the namespace can't be resolved from the kubeconfig context (for example, the context has no namespace set, or the kubeconfig can't be loaded), Velero falls back to the static `namespace` value, or the `velero` default if that isn't set either.

To disable `namespace-mode=auto` and go back to using the static `namespace` value, clear it by setting it to an empty value:

```bash
velero client config set namespace-mode=
```

Alternatively, you may use the global `--namespace` flag with any operational command to tell Velero where to run.

[0]: basic-install.md#install-the-cli
