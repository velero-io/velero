---
title: "Customize Velero Install"
layout: docs
---

## Plugins

During install, Velero requires that at least one plugin is added (with the `--plugins` flag). Please see the documentation under [Plugins](overview-plugins.md)

## Install in any namespace

Velero is installed in the `velero` namespace by default. However, you can install Velero in any namespace. See [run in custom namespace][2] for details.

## Use non-file-based identity mechanisms

By default, `velero install` expects a credentials file for your `velero` IAM account to be provided via the `--secret-file` flag.

If you are using an alternate identity mechanism, such as kube2iam/kiam on AWS, Workload Identity on GKE, etc., that does not require a credentials file, you can specify the `--no-secret` flag instead of `--secret-file`.

## Enable restic integration

By default, `velero install` does not install Velero's [restic integration][3]. To enable it, specify the `--use-restic` flag.

If you've already run `velero install` without the `--use-restic` flag, you can run the same command again, including the `--use-restic` flag, to add the restic integration to your existing install.

## Default Pod Volume backup to restic

By default, `velero install` does not enable the use of restic to take backups of all pod volumes. You must apply an [annotation](restic.md/#using-opt-in-pod-volume-backup) to every pod which contains volumes for Velero to use restic for the backup.

If you are planning to only use restic for volume backups, you can run the `velero install` command with the `--default-volumes-to-restic` flag. This will default all pod volumes backups to use restic without having to apply annotations to pods. Note that when this flag is set during install, Velero will always try to use restic to perform the backup, even want an individual backup to use volume snapshots, by setting the `--snapshot-volumes` flag in the `backup create` command. Alternatively, you can set the  `--default-volumes-to-restic` on an individual backup to to make sure Velero uses Restic for each volume being backed up.

## Enable features

New features in Velero will be released as beta features behind feature flags which are not enabled by default. A full listing of Velero feature flags can be found [here][11].

### Enable server side features

Features on the Velero server can be enabled using the `--features` flag to the `velero install` command. This flag takes as value a comma separated list of feature flags to enable. As an example [CSI snapshotting of PVCs][10] can be enabled using `EnableCSI` feature flag in the `velero install` command as shown below:

```bash
velero install --features=EnableCSI
```

Another example is enabling the support of multiple API group versions, as documented at [- -features=EnableAPIGroupVersions](enable-api-group-versions-feature.md).

Feature flags, passed to `velero install` will be passed to the Velero deployment and also to the `restic` daemon set, if `--use-restic` flag is used.

Similarly, features may be disabled by removing the corresponding feature flags from the `--features` flag.

Enabling and disabling feature flags will require modifying the Velero deployment and also the restic daemonset. This may be done from the CLI by uninstalling and re-installing Velero, or by editing the `deploy/velero` and `daemonset/restic` resources in-cluster.

```bash
$ kubectl -n velero edit deploy/velero
$ kubectl -n velero edit daemonset/restic
```

### Enable client side features

For some features it may be necessary to use the `--features` flag to the Velero client. This may be done by passing the `--features` on every command run using the Velero CLI or the by setting the features in the velero client config file using the `velero client config set` command as shown below:

```bash
velero client config set features=EnableCSI
```

This stores the config in a file at `$HOME/.config/velero/config.json`.

All client side feature flags may be disabled using the below command

```bash
velero client config set features=
```

### Colored CLI output

Velero CLI uses colored output for some commands, such as `velero describe`. If
the environment in which Velero is run doesn't support colored output, the
colored output will be automatically disabled. However, you can manually disable
colors with config file:

```bash
velero client config set colorized=false
```

Note that if you specify `--colorized=true` as a CLI option it will override
the config file setting.


## Customize resource requests and limits

At installation, Velero sets default resource requests and limits for the Velero pod and the restic pod, if you using the [restic integration](/docs/main/restic/).

{{< table caption="Velero Customize resource requests and limits defaults" >}}
|Setting|Velero pod defaults|restic pod defaults|
|--- |--- |--- |
|CPU request|500m|500m|
|Memory requests|128Mi|512Mi|
|CPU limit|1000m (1 CPU)|1000m (1 CPU)|
|Memory limit|512Mi|1024Mi|
{{< /table >}}

Depending on the cluster resources, especially if you are using Restic, you may need to increase these defaults. Through testing, the Velero maintainers have found these defaults work well when backing up and restoring 1000 or less resources and total size of files is 100GB or below. If the resources you are planning to backup or restore exceed this, you will need to increase the CPU or memory resources available to Velero. In general, the Velero maintainer's testing found that backup operations needed more CPU & memory resources but were less time-consuming than restore operations, when comparing backing up and restoring the same amount of data. The exact CPU and memory limits you will need depend on the scale of the files and directories of your resources and your hardware. It's recommended that you perform your own testing to find the best resource limits for your clusters and resources.

Due to a [known Restic issue](https://github.com/restic/restic/issues/2446), the Restic pod will consume large amounts of memory, especially if you are backing up millions of tiny files and directories. If you are planning to use Restic to backup 100GB of data or more, you will need to increase the resource limits to make sure backups complete successfully.

### Install with custom resource requests and limits

You can customize these resource requests and limit when you first install using the [velero install][6] CLI command.

```
velero install \
  --velero-pod-cpu-request <CPU_REQUEST> \
  --velero-pod-mem-request <MEMORY_REQUEST> \
  --velero-pod-cpu-limit <CPU_LIMIT> \
  --velero-pod-mem-limit <MEMORY_LIMIT> \
  [--use-restic] \
  [--default-volumes-to-restic] \
  [--restic-pod-cpu-request <CPU_REQUEST>] \
  [--restic-pod-mem-request <MEMORY_REQUEST>] \
  [--restic-pod-cpu-limit <CPU_LIMIT>] \
  [--restic-pod-mem-limit <MEMORY_LIMIT>]
```

### Update resource requests and limits after install

After installation you can adjust the resource requests and limits in the Velero Deployment spec or restic DeamonSet spec, if you are using the restic integration.

**Velero pod**

Update the `spec.template.spec.containers.resources.limits` and `spec.template.spec.containers.resources.requests` values in the Velero deployment.

```bash
kubectl patch deployment velero -n velero --patch \
'{"spec":{"template":{"spec":{"containers":[{"name": "velero", "resources": {"limits":{"cpu": "1", "memory": "512Mi"}, "requests": {"cpu": "1", "memory": "128Mi"}}}]}}}}'
```

**restic pod**

Update the `spec.template.spec.containers.resources.limits` and `spec.template.spec.containers.resources.requests` values in the restic DeamonSet spec.

```bash
kubectl patch daemonset restic -n velero --patch \
'{"spec":{"template":{"spec":{"containers":[{"name": "restic", "resources": {"limits":{"cpu": "1", "memory": "1024Mi"}, "requests": {"cpu": "1", "memory": "512Mi"}}}]}}}}'
```

Additionally, you may want to update the the default Velero restic pod operation timeout (default 240 minutes) to allow larger backups more time to complete. You can adjust this timeout by adding the `- --restic-timeout` argument to the Velero Deployment spec.

**NOTE:** Changes made to this timeout value will revert back to the default value if you re-run the Velero install command.

1. Open the Velero Deployment spec.

    ```
    kubectl edit deploy velero -n velero
    ```

1. Add `- --restic-timeout` to `spec.template.spec.containers`.

    ```yaml
    spec:
      template:
        spec:
          containers:
          - args:
            - --restic-timeout=240m
    ```

## Configure more than one storage location for backups or volume snapshots

Velero supports any number of backup storage locations and volume snapshot locations. For more details, see [about locations](locations.md).

However, `velero install` only supports configuring at most one backup storage location and one volume snapshot location.

To configure additional locations after running `velero install`, use the `velero backup-location create` and/or `velero snapshot-location create` commands along with provider-specific configuration. Use the `--help` flag on each of these commands for more details.

### Set default backup storage location or volume snapshot locations

When performing backups, Velero needs to know where to backup your data. This means that if you configure multiple locations, you must specify the location Velero should use each time you run `velero backup create`, or you can set a default backup storage location or default volume snapshot locations. If you only have one backup storage llocation or volume snapshot location set for a provider, Velero will automatically use that location as the default.

Set a default backup storage location by passing a `--default` flag with when running `velero backup-location create`.

```
velero backup-location create backups-primary \
    --provider aws \
    --bucket velero-backups \
    --config region=us-east-1 \
    --default
```

You can set a default volume snapshot location for each of your volume snapshot providers using the `--default-volume-snapshot-locations` flag on the `velero server` command.

```
velero server --default-volume-snapshot-locations="<PROVIDER-NAME>:<LOCATION-NAME>,<PROVIDER2-NAME>:<LOCATION2-NAME>"
```

## Do not configure a backup storage location during install

If you need to install Velero without a default backup storage location (without specifying `--bucket` or `--provider`), the `--no-default-backup-location` flag is required for confirmation.

## Install an additional volume snapshot provider

Velero supports using different providers for volume snapshots than for object storage -- for example, you can use AWS S3 for object storage, and Portworx for block volume snapshots.

However, `velero install` only supports configuring a single matching provider for both object storage and volume snapshots.

To use a different volume snapshot provider:

1. Install the Velero server components by following the instructions for your **object storage** provider

1. Add your volume snapshot provider's plugin to Velero (look in [your provider][0]'s documentation for the image name):

    ```bash
    velero plugin add <registry/image:version>
    ```

1. Add a volume snapshot location for your provider, following [your provider][0]'s documentation for configuration:

    ```bash
    velero snapshot-location create <NAME> \
        --provider <PROVIDER-NAME> \
        [--config <PROVIDER-CONFIG>]
    ```

## Generate YAML only

By default, `velero install` generates and applies a customized set of Kubernetes configuration (YAML) to your cluster.

To generate the YAML without applying it to your cluster, use the `--dry-run -o yaml` flags.

This is useful for applying bespoke customizations, integrating with a GitOps workflow, etc.

If you are installing Velero in Kubernetes 1.14.x or earlier, you need to use `kubectl apply`'s `--validate=false` option when applying the generated configuration to your cluster. See [issue 2077][7] and [issue 2311][8] for more context.

## Use a storage provider secured by a self-signed certificate

If you intend to use Velero with a storage provider that is secured by a self-signed certificate,
you may need to instruct Velero to trust that certificate. See [use Velero with a storage provider secured by a self-signed certificate][9] for details.

## Additional options

Run `velero install --help` or see the [Helm chart documentation](https://vmware-tanzu.github.io/helm-charts/) for the full set of installation options.

## Optional Velero CLI configurations

### Enabling shell autocompletion

**Velero CLI** provides autocompletion support for `Bash` and `Zsh`, which can save you a lot of typing.

Below are the procedures to set up autocompletion for `Bash` (including the difference between `Linux` and `macOS`) and `Zsh`.

#### Bash on Linux

The **Velero CLI** completion script for `Bash` can be generated with the command `velero completion bash`. Sourcing the completion script in your shell enables velero autocompletion.

However, the completion script depends on [**bash-completion**](https://github.com/scop/bash-completion), which means that you have to install this software first (you can test if you have bash-completion already installed by running `type _init_completion`).

##### Install bash-completion

`bash-completion` is provided by many package managers (see [here](https://github.com/scop/bash-completion#installation)). You can install it with `apt-get install bash-completion` or `yum install bash-completion`, etc.

The above commands create `/usr/share/bash-completion/bash_completion`, which is the main script of bash-completion. Depending on your package manager, you have to manually source this file in your `~/.bashrc` file.

To find out, reload your shell and run `type _init_completion`. If the command succeeds, you're already set, otherwise add the following to your `~/.bashrc` file:

```shell
source /usr/share/bash-completion/bash_completion
```

Reload your shell and verify that bash-completion is correctly installed by typing `type _init_completion`.

##### Enable Velero CLI autocompletion for Bash on Linux

You now need to ensure that the **Velero CLI** completion script gets sourced in all your shell sessions. There are two ways in which you can do this:

- Source the completion script in your `~/.bashrc` file:

    ```shell
    echo 'source <(velero completion bash)' >>~/.bashrc
    ```

- Add the completion script to the `/etc/bash_completion.d` directory:

    ```shell
    velero completion bash >/etc/bash_completion.d/velero
    ```

- If you have an alias for velero, you can extend shell completion to work with that alias:

    ```shell
    echo 'alias v=velero' >>~/.bashrc
    echo 'complete -F __start_velero v' >>~/.bashrc
    ```

> `bash-completion` sources all completion scripts in `/etc/bash_completion.d`.

Both approaches are equivalent. After reloading your shell, velero autocompletion should be working.

#### Bash on macOS

The **Velero CLI** completion script for Bash can be generated with `velero completion bash`. Sourcing this script in your shell enables velero completion.

However, the velero completion script depends on [**bash-completion**](https://github.com/scop/bash-completion) which you thus have to previously install.


> There are two versions of bash-completion, v1 and v2. V1 is for Bash 3.2 (which is the default on macOS), and v2 is for Bash 4.1+. The velero completion script **doesn't work** correctly with bash-completion v1 and Bash 3.2. It requires **bash-completion v2** and **Bash 4.1+**. Thus, to be able to correctly use velero completion on macOS, you have to install and use Bash 4.1+ ([*instructions*](https://itnext.io/upgrading-bash-on-macos-7138bd1066ba)). The following instructions assume that you use Bash 4.1+ (that is, any Bash version of 4.1 or newer).


##### Install bash-completion

> As mentioned, these instructions assume you use Bash 4.1+, which means you will install bash-completion v2 (in contrast to Bash 3.2 and bash-completion v1, in which case kubectl completion won't work).

You can test if you have bash-completion v2 already installed with `type _init_completion`. If not, you can install it with Homebrew:

  ```shell
  brew install bash-completion@2
  ```

As stated in the output of this command, add the following to your `~/.bashrc` file:

  ```shell
  export BASH_COMPLETION_COMPAT_DIR="/usr/local/etc/bash_completion.d"
  [[ -r "/usr/local/etc/profile.d/bash_completion.sh" ]] && . "/usr/local/etc/profile.d/bash_completion.sh"
  ```

Reload your shell and verify that bash-completion v2 is correctly installed with `type _init_completion`.

##### Enable Velero CLI autocompletion for Bash on macOS

You now have to ensure that the velero completion script gets sourced in all your shell sessions. There are multiple ways to achieve this:

- Source the completion script in your `~/.bashrc` file:

    ```shell
    echo 'source <(velero completion bash)' >>~/.bashrc

    ```

- Add the completion script to the `/usr/local/etc/bash_completion.d` directory:

    ```shell
    velero completion bash >/usr/local/etc/bash_completion.d/velero
    ```

- If you have an alias for velero, you can extend shell completion to work with that alias:

    ```shell
    echo 'alias v=velero' >>~/.bashrc
    echo 'complete -F __start_velero v' >>~/.bashrc
    ```

- If you installed velero with Homebrew (as explained [above](#install-with-homebrew-on-macos)), then the velero completion script should already be in `/usr/local/etc/bash_completion.d/velero`. In that case, you don't need to do anything.

> The Homebrew installation of bash-completion v2 sources all the files in the `BASH_COMPLETION_COMPAT_DIR` directory, that's why the latter two methods work.

In any case, after reloading your shell, velero completion should be working.

#### Autocompletion on Zsh

The velero completion script for Zsh can be generated with the command `velero completion zsh`. Sourcing the completion script in your shell enables velero autocompletion.

To do so in all your shell sessions, add the following to your `~/.zshrc` file:

  ```shell
  source <(velero completion zsh)
  ```

If you have an alias for kubectl, you can extend shell completion to work with that alias:

  ```shell
  echo 'alias v=velero' >>~/.zshrc
  echo 'complete -F __start_velero v' >>~/.zshrc
  ```

After reloading your shell, kubectl autocompletion should be working.

If you get an error like `complete:13: command not found: compdef`, then add the following to the beginning of your `~/.zshrc` file:

  ```shell
  autoload -Uz compinit
  compinit
  ```

[1]: https://github.com/velero-io/velero/releases/latest
[2]: namespace.md
[3]: restic.md
[4]: on-premises.md
[6]: velero-install.md#usage
[7]: https://github.com/velero-io/velero/issues/2077
[8]: https://github.com/velero-io/velero/issues/2311
[9]: self-signed-certificates.md
[10]: csi.md
[11]: https://github.com/velero-io/velero/blob/v1.9.0/pkg/apis/velero/v1/constants.go
