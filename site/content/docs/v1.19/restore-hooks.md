---
title: "Restore Hooks"
layout: docs
---

Velero supports Restore Hooks, custom actions that can be executed during or after the restore process. There are two kinds of Restore Hooks:

1. InitContainer Restore Hooks: These will add init containers into restored pods to perform any necessary setup before the application containers of the restored pod can start.
1. Exec Restore Hooks: These can be used to execute custom commands or scripts in containers of a restored Kubernetes pod.

## InitContainer Restore Hooks

Use an `InitContainer` hook to add init containers into a pod before it's restored. You can use these init containers to run any setup needed for the pod to resume running from its backed-up state.
The InitContainer added by the restore hook will be the first init container in the `podSpec` of the restored pod.
In the case where the pod had volumes backed up using File System Backup, then, the restore hook InitContainer will be added after the `restore-wait` InitContainer.

NOTE: This ordering can be altered by any mutating webhooks that may be installed in the cluster.

There are two ways to specify `InitContainer` restore hooks:
1. Specifying restore hooks in annotations
1. Specifying restore hooks in the restore spec

### Specifying Restore Hooks As Pod Annotations

Below are the annotations that can be added to a pod to specify restore hooks:
* `init.hook.restore.velero.io/container-image`
    * The container image for the init container to be added. Optional.
* `init.hook.restore.velero.io/container-name`
    * The name for the init container that is being added. Optional.
* `init.hook.restore.velero.io/command`
    * This is the `ENTRYPOINT` for the init container being added. This command is not executed within a shell and the container image's `ENTRYPOINT` is used if this is not provided. If a shell is needed to run your command, include a shell command, like `/bin/sh`, that is supported by the container at the beginning of your command. If you need multiple arguments, specify the command as a JSON array, such as `["/usr/bin/uname", "-a"]`. See [InitContainer As Pod Annotation Example](#initcontainer-restore-hooks-as-pod-annotation-example). Optional.

#### InitContainer Restore Hooks As Pod Annotation Example

Use the below commands to add annotations to the pods before taking a backup.

```bash
$ kubectl annotate pod -n <POD_NAMESPACE> <POD_NAME> \
    init.hook.restore.velero.io/container-name=restore-hook \
    init.hook.restore.velero.io/container-image=alpine:latest \
    init.hook.restore.velero.io/command='["/bin/ash", "-c", "date"]'
```

With the annotation above, Velero will add the following init container to the pod when it's restored.

```json
{
  "command": [
    "/bin/ash",
    "-c",
    "date"
  ],
  "image": "alpine:latest",
  "imagePullPolicy": "Always",
  "name": "restore-hook"
  ...
}
```

### Specifying Restore Hooks In Restore Spec

Init container restore hooks can also be specified using the `RestoreSpec`.
Please refer to the documentation on the [Restore API Type][1] for how to specify hooks in the Restore spec.
Init container restore hook command is not executed within a shell by default. If a shell is needed to run your command, include a shell command, like /bin/sh, that is supported by the container at the beginning of your command.

#### Example

Below is an example of specifying restore hooks in `RestoreSpec`

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: r2
  namespace: velero
spec:
  backupName: b2
  excludedResources:
  ...
  includedNamespaces:
  - '*'
  hooks:
    resources:
    - name: restore-hook-1
      includedNamespaces:
      - app
      postHooks:
      - init:
          initContainers:
          - name: restore-hook-init1
            image: alpine:latest
            volumeMounts:
            - mountPath: /restores/pvc1-vm
              name: pvc1-vm
            command:
            - /bin/ash
            - -c
            - echo -n "FOOBARBAZ" >> /restores/pvc1-vm/foobarbaz
          - name: restore-hook-init2
            image: alpine:latest
            volumeMounts:
            - mountPath: /restores/pvc2-vm
              name: pvc2-vm
            command:
            - /bin/ash
            - -c
            - echo -n "DEADFEED" >> /restores/pvc2-vm/deadfeed
```

The `hooks` in the above `RestoreSpec`, when restored, will add two init containers to every pod in the `app` namespace

```json
{
  "command": [
    "/bin/ash",
    "-c",
    "echo -n \"FOOBARBAZ\" >> /restores/pvc1-vm/foobarbaz"
  ],
  "image": "alpine:latest",
  "imagePullPolicy": "Always",
  "name": "restore-hook-init1",
  "resources": {},
  "terminationMessagePath": "/dev/termination-log",
  "terminationMessagePolicy": "File",
  "volumeMounts": [
    {
      "mountPath": "/restores/pvc1-vm",
      "name": "pvc1-vm"
    }
  ]
  ...
}
```

and

```json
{
  "command": [
    "/bin/ash",
    "-c",
    "echo -n \"DEADFEED\" >> /restores/pvc2-vm/deadfeed"
  ],
  "image": "alpine:latest",
  "imagePullPolicy": "Always",
  "name": "restore-hook-init2",
  "resources": {},
  "terminationMessagePath": "/dev/termination-log",
  "terminationMessagePolicy": "File",
  "volumeMounts": [
    {
      "mountPath": "/restores/pvc2-vm",
      "name": "pvc2-vm"
    }
  ]
  ...
}
```

## Exec Restore Hooks

Use an Exec Restore hook to execute commands in a restored pod's containers after they start.

There are two ways to specify `Exec` restore hooks:
1. Specifying exec restore hooks in annotations
1. Specifying exec restore hooks in the restore spec

If a pod has the annotation `post.hook.restore.velero.io/command` then that is the only hook that will be executed in the pod.
No hooks from the restore spec will be executed in that pod.

### Specifying Exec Restore Hooks As Pod Annotations

Below are the annotations that can be added to a pod to specify exec restore hooks:
* `post.hook.restore.velero.io/container`
    * The container name where the hook will be executed. Defaults to the first container. Optional.
* `post.hook.restore.velero.io/command`
    * The command that will be executed in the container. This command is not executed within a shell by default. If a shell is needed to run your command, include a shell command, like `/bin/sh`, that is supported by the container at the beginning of your command. If you need multiple arguments, specify the command as a JSON array, such as `["/usr/bin/uname", "-a"]`. See [Exec Restore Hooks As Pod Annotation Example](#exec-restore-hooks-as-pod-annotation-example). Optional.
* `post.hook.restore.velero.io/on-error`
    * How to handle execution failures. Valid values are `Fail` and `Continue`. Defaults to `Continue`. With `Continue` mode, execution failures are logged only. With `Fail` mode, no more restore hooks will be executed in any container in any pod and the status of the Restore will be `PartiallyFailed`. Optional.
* `post.hook.restore.velero.io/exec-timeout`
    * How long to wait once execution begins. Defaults is 30 seconds. Optional.
* `post.hook.restore.velero.io/wait-timeout`
    * How long to wait for a container to become ready. This should be long enough for the container to start plus any preceding hooks in the same container to complete. The wait timeout begins when the container is restored and may require time for the image to pull and volumes to mount. If not set the restore will wait indefinitely. Optional.
* `post.hook.restore.velero.io/wait-for-ready`
    * String representation of a boolean that ensure command will be launched when underlying container is fully [Ready](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes). Use with caution because if only one restore hook for a pod consists of `WaitForReady` flag as "true", all the other hook executions for that pod, whatever their origin (`Backup` or `Restore` CRD), will wait for `Ready` state too. Any value except "true" will be considered as "false". Defaults is false. Optional.

#### Exec Restore Hooks As Pod Annotation Example

Use the below commands to add annotations to the pods before taking a backup.

```bash
$ kubectl annotate pod -n <POD_NAMESPACE> <POD_NAME> \
    post.hook.restore.velero.io/container=postgres \
    post.hook.restore.velero.io/command='["/bin/bash", "-c", "psql < /backup/backup.sql"]' \
    post.hook.restore.velero.io/wait-timeout=5m \
    post.hook.restore.velero.io/exec-timeout=45s \
    post.hook.restore.velero.io/on-error=Continue
```

### Specifying Exec Restore Hooks in Restore Spec

Exec restore hooks can also be specified using the `RestoreSpec`.
Please refer to the documentation on the [Restore API Type][1] for how to specify hooks in the Restore spec.
Exec restore hook command is not executed within a shell by default. If a shell is needed to run your command, include a shell command, like /bin/sh, that is supported by the container at the beginning of your command.

#### Multiple Exec Restore Hooks Example

Below is an example of specifying restore hooks in  a `RestoreSpec`.
When using the restore spec it is possible to specify multiple hooks for a single pod, as this example demonstrates.

All hooks applicable to a single container will be executed sequentially in that container once it starts.
The ordering of hooks executed in a single container follows the order of the restore spec.
In this example, the `pg_isready` hook is guaranteed to run before the `psql` hook because they both apply to the same container and the `pg_isready` hook is defined first.

If a pod has multiple containers with applicable hooks, all hooks for a single container will be executed before executing hooks in another container.
In this example, if the postgres container starts before the sidecar container, both postgres hooks will run before the hook in the sidecar.
This means the sidecar container may be running for several minutes before its hook is executed.

Velero guarantees that no two hooks for a single pod are executed in parallel, but hooks executing in different pods may run in parallel.


```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: r2
  namespace: velero
spec:
  backupName: b2
  excludedResources:
  ...
  includedNamespaces:
  - '*'
  hooks:
    resources:
    - name: restore-hook-1
      includedNamespaces:
      - app
      postHooks:
      - exec:
          execTimeout: 1m
          waitTimeout: 5m
          onError: Fail
          container: postgres
          command:
          - /bin/bash
          - '-c'
          - 'while ! pg_isready; do sleep 1; done'
      - exec:
          container: postgres
          waitTimeout: 6m
          execTimeout: 1m
          command:
          - /bin/bash
          - '-c'
          - 'psql < /backup/backup.sql'
      - exec:
          container: sidecar
          command:
          - /bin/bash
          - '-c'
          - 'date > /start'
```

## Restore hook commands using scenarios
### Using environment variables

You are able to use environment variables from your pods in your pre and post hook commands by including a shell command before using the environment variable. For example, `MYSQL_ROOT_PASSWORD` is an environment variable defined in pod called `mysql`. To use `MYSQL_ROOT_PASSWORD` in your pre-hook, you'd include a shell, like `/bin/sh`, before calling your environment variable:

```
postHooks:
- exec:
    container: mysql
    command:
      - /bin/sh
      - -c
      - mysql --password=$MYSQL_ROOT_PASSWORD -e "FLUSH TABLES WITH READ LOCK"
    onError: Fail
```

Note that the container must support the shell command you use. 

## Restore Hook Execution Results
### Viewing Results

Velero records the execution results of hooks, allowing users to obtain this information by running the following command:

```bash
$ velero restore describe <restore name>
```

The displayed results include the number of hooks that were attempted to be executed and the number of hooks that failed execution. Any detailed failure reasons will be present in `Errors` section if applicable. 

```bash
HooksAttempted:   1
HooksFailed:      0
```


[1]: api-types/restore.md
