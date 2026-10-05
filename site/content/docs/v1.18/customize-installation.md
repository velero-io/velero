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

## Enable file system backup

By default, `velero install` does not install Velero's [File System Backup][3]. To enable it, specify the `--use-node-agent` flag.

If you've already run `velero install` without the `--use-node-agent` flag, you can run the same command again, including the `--use-node-agent` flag, to add the file system backup to your existing install.

Note that for some use cases (including installation on OpenShift clusters) the fs-backup pods must run in a Privileged security context. This is configured through the node-agent configmap (see below) by setting `privilegedFsBackup` to `true` in the configmap.

## CSI Snapshot Data Movement

Velero node-agent is required by [CSI Snapshot Data Movement][12] when Velero built-in data mover is used. By default, `velero install` does not install Velero's node-agent. To enable it, specify the `--use-node-agent` flag.

For some use cases, Velero node-agent requires to run under privileged mode. For example, when backing up block volumes, it is required to allow the node-agent to access the block device. To enable it set velero install flags `--privileged-node-agent`.

If you've already run `velero install` without the `--use-node-agent` or `--privileged-node-agent` flag, you can run the same command again, including the `--use-node-agent` or `--privileged-node-agent` flag, to add CSI snapshot data movement to your existing install.

## Customize the kubelet root path of the node-agent
When installing with the `--use-node-agent` flag, the node-agent will mount the default kubelet paths `/var/lib/kubelet/pods` and `/var/lib/kubelet/plugins` (hostPath). To customize these kubelet mount paths, use the `--kubelet-root-dir` flag.

## Default Pod Volume backup to file system backup

By default, `velero install` does not enable the use of File System Backup (FSB) to take backups of all pod volumes. You must apply an [annotation](file-system-backup.md/#using-opt-in-pod-volume-backup) to every pod which contains volumes for Velero to use FSB for the backup.

If you are planning to only use FSB for volume backups, you can run the `velero install` command with the `--default-volumes-to-fs-backup` flag. This will default all pod volumes backups to use FSB without having to apply annotations to pods. Note that when this flag is set during install, Velero will always try to use FSB to perform the backup, even want an individual backup to use volume snapshots, by setting the `--snapshot-volumes` flag in the `backup create` command. Alternatively, you can set the  `--default-volumes-to-fs-backup` on an individual backup to to make sure Velero uses FSB for each volume being backed up.

## Update an existing installation

By default, the `velero install` command creates new resources in your cluster. If you're updating an existing Velero installation, you can use the `--apply` flag to apply changes to existing resources instead of attempting to create new ones:

```bash
velero install --apply
```

When the `--apply` flag is specified, Velero uses server-side apply to update existing resources. This is particularly useful when updating Velero to a new version or when modifying your installation configuration. While this can be used as part of an upgrade process, please note that for version upgrades, additional steps may be required depending on the specific changes between versions. Also ensure when using this flag that you are setting any additional flags previously used for your existing configuration so that you don't introduce unexpected changes.

## Enable features

New features in Velero will be released as beta features behind feature flags which are not enabled by default. A full listing of Velero feature flags can be found [here][11].

### Enable server side features

Features on the Velero server can be enabled using the `--features` flag to the `velero install` command. This flag takes as value a comma separated list of feature flags to enable. As an example [CSI snapshotting of PVCs][10] can be enabled using `EnableCSI` feature flag in the `velero install` command as shown below:

```bash
velero install --features=EnableCSI
```

Another example is enabling the support of multiple API group versions, as documented at [- -features=EnableAPIGroupVersions](enable-api-group-versions-feature.md).

Feature flags, passed to `velero install` will be passed to the Velero deployment and also to the `node-agent` daemon set, if `--use-node-agent` flag is used.

Similarly, features may be disabled by removing the corresponding feature flags from the `--features` flag.

Enabling and disabling feature flags will require modifying the Velero deployment and also the node-agent daemonset. This may be done from the CLI by uninstalling and re-installing Velero, or by editing the `deploy/velero` and `daemonset/node-agent` resources in-cluster.

```bash
$ kubectl -n velero edit deploy/velero
$ kubectl -n velero edit daemonset/node-agent
```

### Enable client side features

For some features it may be necessary to use the `--features` flag to the Velero client. This may be done by passing the `--features` on every command run using the Velero CLI or the by setting the features in the velero client config file using the `velero client config set` command as shown below:

```bash
velero client config set features=feature1,feature2...
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


## Set priority class names for Velero components

You can set priority class names for different Velero components during installation. This allows you to influence the scheduling and eviction behavior of Velero pods, which can be useful in clusters where resource contention is high.

### Priority class configuration options:

1. **Velero server deployment**: Use the `--server-priority-class-name` flag
2. **Node agent daemonset**: Use the `--node-agent-priority-class-name` flag
3. **Data mover pods**: Configure through the node-agent configmap (see below)
4. **Maintenance jobs**: Configure through the repository maintenance job configmap (see below)

```bash
velero install \
    --server-priority-class-name=<SERVER_PRIORITY_CLASS> \
    --node-agent-priority-class-name=<NODE_AGENT_PRIORITY_CLASS>
```

### Configuring priority classes for data mover pods and maintenance jobs

For data mover pods and maintenance jobs, priority classes are configured through ConfigMaps that must be created before installation:

**Data mover pods** (via node-agent configmap):
```bash
kubectl create configmap node-agent-config -n velero --from-file=config.json=/dev/stdin <<EOF
{
    "priorityClassName": "low-priority"
}
EOF

velero install --node-agent-configmap node-agent-config # ... other flags
```

**Maintenance jobs** (via repository maintenance job configmap):
```bash
kubectl create configmap repo-maintenance-job-config -n velero --from-file=config.json=/dev/stdin <<EOF
{
    "global": {
        "priorityClassName": "low-priority"
    }
}
EOF

velero install --repo-maintenance-job-configmap repo-maintenance-job-config # ... other flags
```

Note that you need to create the priority classes before installing Velero. For more information on priority classes, see the [Kubernetes documentation on Pod Priority and Preemption](https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/).

## Customize resource requests and limits

At installation, You could set resource requests and limits for the Velero pod, the node-agent pod and the [repository maintenance job][14], if you are using the [File System Backup][3] or [CSI Snapshot Data Movement][12].  

{{< table caption="Velero Customize resource requests and limits defaults" >}}
|Setting|Velero pod defaults|node-agent pod defaults|
|--- |--- |--- |
|CPU request|500m|N/A|
|Memory requests|128Mi|N/A|
|CPU limit|1000m (1 CPU)|N/A|
|Memory limit|512Mi|N/A|
{{< /table >}}
  
For Velero pod, through testing, the Velero maintainers have found these defaults work well when backing up and restoring 1000 or less resources. If you are enabling concurrent backups and your backups tend to be large, you may need to increase these limits.
For node-agent pod, by default it doesn't have CPU/memory request/limit, so that the backups/restores won't break due to resource throttling. The Velero maintainers have also done some [Performance Tests][13] to show the relationship of CPU/memory usage and the scale of data being backed up/restored.

For repository maintenance job, it's no limit on resources by default. You could configure the job resource limitation based on target data to be backed up, some further settings please refer to [repository maintenance job][14].

You don't have to change the defaults all the time, but if you need, it's recommended that you perform your own testing to find the best resource limits for your clusters and resources.   

### Install with custom resource requests and limits

You can customize these resource requests and limit when you first install using the [velero install][6] CLI command.

```
velero install \
  --velero-pod-cpu-request <CPU_REQUEST> \
  --velero-pod-mem-request <MEMORY_REQUEST> \
  --velero-pod-cpu-limit <CPU_LIMIT> \
  --velero-pod-mem-limit <MEMORY_LIMIT> \
  [--use-node-agent] \
  [--default-volumes-to-fs-backup] \
  [--node-agent-pod-cpu-request <CPU_REQUEST>] \
  [--node-agent-pod-mem-request <MEMORY_REQUEST>] \
  [--node-agent-pod-cpu-limit <CPU_LIMIT>] \
  [--node-agent-pod-mem-limit <MEMORY_LIMIT>] \
  [--maintenance-job-cpu-request <CPU_REQUEST>] \
  [--maintenance-job-mem-request <MEMORY_REQUEST>] \
  [--maintenance-job-cpu-limit <CPU_LIMIT>] \
  [--maintenance-job-mem-limit <MEMORY_LIMIT>]
```

### Update resource requests and limits after install

After installation you can adjust the resource requests and limits in the Velero Deployment spec or node-agent DaemonSet spec, if you are using the File System Backup.

**Velero pod**

Update the `spec.template.spec.containers.resources.limits` and `spec.template.spec.containers.resources.requests` values in the Velero deployment.

```bash
kubectl patch deployment velero -n velero --patch \
'{"spec":{"template":{"spec":{"containers":[{"name": "velero", "resources": {"limits":{"cpu": "1", "memory": "512Mi"}, "requests": {"cpu": "1", "memory": "128Mi"}}}]}}}}'
```

**node-agent pod**

Update the `spec.template.spec.containers.resources.limits` and `spec.template.spec.containers.resources.requests` values in the node-agent DaemonSet spec.

```bash
kubectl patch daemonset node-agent -n velero --patch \
'{"spec":{"template":{"spec":{"containers":[{"name": "node-agent", "resources": {"limits":{"cpu": "1", "memory": "1024Mi"}, "requests": {"cpu": "1", "memory": "512Mi"}}}]}}}}'
```

Additionally, you may want to update the the default File System Backup operation timeout (default 240 minutes) to allow larger backups more time to complete. You can adjust this timeout by adding the `- --fs-backup-timeout` argument to the Velero Deployment spec.

**NOTE:** Changes made to this timeout value will revert back to the default value if you re-run the Velero install command.

1. Open the Velero Deployment spec.

    ```
    kubectl edit deploy velero -n velero
    ```

1. Add `- --fs-backup-timeout` to `spec.template.spec.containers`.

    ```yaml
    spec:
      template:
        spec:
          containers:
          - args:
            - --fs-backup-timeout=240m
    ```

### Ephemeral-storage Requests and Limits

Velero does not set ephemeral-storage limits during installation. Limits and requests can be edited after install for clusters that monitor and restrict ephemeral-storage usage. 

Plugins will use ephemeral-storage. There needs to be a sufficient requests and limit set to account for plugins and the additional ephemeral-storage used to maintain credentials and cache space for datamovers. Object storage plugins will fit comfortably into an allocation of 100MB of ephemeral-storage.

## Configure more than one storage location for backups or volume snapshots

Velero supports any number of backup storage locations and volume snapshot locations. For more details, see [about locations](locations.md).

However, `velero install` only supports configuring at most one backup storage location and one volume snapshot location.

To configure additional locations after running `velero install`, use the `velero backup-location create` and/or `velero snapshot-location create` commands along with provider-specific configuration. Use the `--help` flag on each of these commands for more details.

### Set default backup storage location or volume snapshot locations

When performing backups, Velero needs to know where to backup your data. This means that if you configure multiple locations, you must specify the location Velero should use each time you run `velero backup create`, or you can set a default backup storage location or default volume snapshot locations. If you only have one backup storage location or volume snapshot location set for a provider, Velero will automatically use that location as the default.

#### Set default backup storage location
currently, Velero could set the default backup storage location as below:
- First way: Set a default backup storage location by passing a `--default` flag when running `velero backup-location create`.

  ```
  velero backup-location create backups-primary \
    --provider aws \
    --bucket velero-backups \
    --config region=us-east-1 \
    --default
  ```
- Second way: Set a default backup storage location by passing a  `--default` flag when running `velero backup-location set`.
  ```bash
  velero backup-location set backups-primary --default
  ```
  We also could remove the default backup storage location by this command, below is one example
  ```bash
  velero backup-location set backups-primary --default=false
  ```
- Third way: Set a default backup storage location by passing `--default-backup-storage-location` flag on the `velero server` command.
   ```bash
  velero server --default-backup-storage-location backups-primary
   ```
Note: Only could have one default backup storage location, which means it's not allowed to set two default backup storage locations at the same time, the priorities among these three are as follows:
- if velero server side has specified one default backup storage location, suppose it's `A`
  - if `A` backup storage location exists, it's not allowed to set a new default backup storage location
  - if `A` does not exist
    - if using `velero backup-location set` or `velero backup-location create --default` command
      - it could be successful if no default backup storage location exists.
      - it would fail if already exist one default backup storage location. (So it need to remove other default backup storage location at first)
- if velero server side has not specified one default backup storage location
  - if using `velero backup-location set` or `velero backup-location create --default` command
    - it could be successful if no default backup storage location exists.
    - it would fail if already exist one default backup storage location. (So it need to remove other default backup storage location at first)
#### Set default volume snapshot location
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

## Advanced configuration through external ConfigMaps

Velero supports to configure its some advanced behaviors by external ConfigMaps.
Velero itself isn't responsible for creating and maintaining these ConfigMaps, instead the users should do that.

By far, `velero install` supports the following parameters to specify the external ConfigMap names:
* --backup-repository-configmap: [backup repository configuration document][15]
* --node-agent-configmap: [node-agent concurrency configuration document][16], and there are some other documents specify other parts of node-agent-config.
* --repo-maintenance-job-configmap: [repository maintenance configuration document][17]

From v1.17, Velero adds verification for the ConfigMaps in CLI and server side, which means `velero install` CLI will fail and velero server and node-agent pod will exit if the specified ConfigMaps don't exist or are invalid.

The change's aim is validating the ConfigMaps and fail early instead of finding the ConfigMaps are not valid during running data mover pod or repository maintenance job.

However, there means the user cannot just running `velero install` CLI then get a working environment, when the external ConfigMaps are involved.

The new workflow is:
* Create the needed namespace: `kubectl create ns velero`
* Add PSA labels to the namespace: `kubectl label ns velero pod-security.velero.io/enforce=privileged`
* Create the needed ConfigMaps.
* Run the `velero install` CLI:
  ``` bash
  velero install \
    --provider aws \
    ......
    --backup-repository-configmap=... \
    --node-agent-configmap=... \
    --repo-maintenance-job-configmap=...
  ```


[1]: https://github.com/velero-io/velero/releases/latest
[2]: namespace.md
[3]: file-system-backup.md
[4]: on-premises.md
[6]: velero-install.md#usage
[7]: https://github.com/velero-io/velero/issues/2077
[8]: https://github.com/velero-io/velero/issues/2311
[9]: self-signed-certificates.md
[10]: csi.md
[11]: https://github.com/velero-io/velero/blob/v1.18.0/pkg/apis/velero/v1/constants.go
[12]: csi-snapshot-data-movement.md
[13]: performance-guidance.md
[14]: repository-maintenance.md
[15]: backup-repository-configuration.md
[16]: node-agent-concurrency.md
[17]: repository-maintenance.md
