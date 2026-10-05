---
title: "Customize Velero Install"
layout: docs
---

- [Customize Velero Install](#customize-velero-install)
  - [Plugins](#plugins)
  - [Install in any namespace](#install-in-any-namespace)
  - [Use non-file-based identity mechanisms](#use-non-file-based-identity-mechanisms)
  - [Enable restic integration](#enable-restic-integration)
  - [Customize resource requests and limits](#customize-resource-requests-and-limits)
  - [Configure more than one storage location for backups or volume snapshots](#configure-more-than-one-storage-location-for-backups-or-volume-snapshots)
  - [Do not configure a backup storage location during install](#do-not-configure-a-backup-storage-location-during-install)
  - [Install an additional volume snapshot provider](#install-an-additional-volume-snapshot-provider)
  - [Generate YAML only](#generate-yaml-only)
  - [Additional options](#additional-options)
  - [Optional Velero CLI configurations](#optional-velero-cli-configurations)
    - [Enabling shell autocompletion](#enabling-shell-autocompletion)
      - [Bash on Linux](#bash-on-linux)
        - [Install bash-completion](#install-bash-completion)
        - [Enable Velero CLI autocompletion for Bash on Linux](#enable-velero-cli-autocompletion-for-bash-on-linux)
      - [Bash on macOS](#bash-on-macos)
        - [Install bash-completion](#install-bash-completion-1)
        - [Enable Velero CLI autocompletion for Bash on macOS](#enable-velero-cli-autocompletion-for-bash-on-macos)
      - [Autocompletion on Zsh](#autocompletion-on-zsh)

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

## Customize resource requests and limits

By default, the Velero deployment requests 500m CPU, 128Mi memory and sets a limit of 1000m CPU, 256Mi.
Default requests and limits are not set for the restic pods as CPU/Memory usage can depend heavily on the size of volumes being backed up.

Customization of these resource requests and limits may be performed using the [velero install][6] CLI command.

## Configure more than one storage location for backups or volume snapshots

Velero supports any number of backup storage locations and volume snapshot locations. For more details, see [about locations](locations.md).

However, `velero install` only supports configuring at most one backup storage location and one volume snapshot location.

To configure additional locations after running `velero install`, use the `velero backup-location create` and/or `velero snapshot-location create` commands along with provider-specific configuration. Use the `--help` flag on each of these commands for more details.

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
