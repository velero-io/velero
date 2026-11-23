---
title: "Enable API Group Versions Feature"
layout: docs
---

## Background

Velero serves to both restore and migrate Kubernetes applications. Typically, backup and restore does not involve upgrading Kubernetes API group versions. However, when migrating from a source cluster to a destination cluster, it is not unusual to see the API group versions differing between clusters.  

**NOTE:** Kubernetes applications are made up of various resources. Common resources are pods, jobs, and deployments. Custom resources are created via custom resource definitions (CRDs). Every resource, whether custom or not, is part of a group, and each group has a version called the API group version.

Kubernetes by default allows changing API group versions between clusters as long as the upgrade is a single version, for example, v1 -> v2beta1. Jumping multiple versions, for example, v1 -> v3, is not supported out of the box. This is where the Velero Enable API Group Version feature can help you during an upgrade.

Currently, the Enable API Group Version feature is in beta and can be enabled by installing Velero with a [feature flag](customize-installation.md/#enable-server-side-features), `--features=EnableAPIGroupVersions`.

For the most up-to-date information on Kubernetes API version compatibility, you should always review the [Kubernetes release notes](https://github.com/kubernetes/kubernetes/tree/master/CHANGELOG) for the source and destination cluster version to before starting an upgrade, migration, or restore. If there is a difference between Kubernetes API versions, use the Enable API Group Version feature to help mitigate compatibility issues.

## How the Enable API Group Versions Feature Works

When the Enable API Group Versions feature is enabled on the source cluster, Velero will not only back up Kubernetes preferred API group versions, but it will also back up all supported versions on the cluster. As an example, consider the resource `horizontalpodautoscalers` which falls under the `autoscaling` group. Without the feature flag enabled, only the preferred API group version for autoscaling, `v2` will be backed up. With the feature enabled, the remaining supported versions, `v1` will also be backed up. Once the versions are stored in the backup tarball file, they will be available to be restored on the destination cluster.

When the Enable API Group Versions feature is enabled on the destination cluster, Velero restore will choose the version to restore based on an API group version priority order.

The version priorities are listed from highest to lowest priority below:

- Priority 1: destination cluster preferred version
- Priority 2: source cluster preferred version
- Priority 3: non-preferred common supported version with the highest [Kubernetes version priority](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#version-priority)

The highest priority (Priority 1) will be the destination cluster's preferred API group version. If the destination preferred version is found in the backup tarball, it will be the API group version chosen for restoration for that resource. However, if the destination preferred version is not found in the backup tarball, the next version in the list will be selected: the source cluster preferred version (Priority 2).

If the source cluster preferred version is found to be supported by the destination cluster, it will be chosen as the API group version to restore. However, if the source preferred version is not supported by the destination cluster, then the next version in the list will be considered: a non-preferred common supported version (Priority 3).

In the case that there are more than one non-preferred common supported version, which version will be chosen? The answer requires understanding the [Kubernetes version priority order](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#version-priority). Kubernetes prioritizes group versions by making the latest, most stable version the highest priority. The highest priority version is the Kubernetes preferred version. Here is a sorted version list example from the Kubernetes.io documentation:

- v10
- v2
- v1
- v11beta2
- v10beta3
- v3beta1
- v12alpha1
- v11alpha2
- foo1
- foo10

Of the non-preferred common versions, the version that has the highest Kubernetes version priority will be chosen. See the example for Priority 3 below.

To better understand which API group version will be chosen, the following provides some concrete examples. The examples use the term "target cluster" which is synonymous to "destination cluster".

![Priority 1 Case A example](/docs/main/img/gv_priority1-caseA.png)

![Priority 1 Case B example](/docs/main/img/gv_priority1-caseB.png)

![Priority 2 Case C example](/docs/main/img/gv_priority2-caseC.png)

![Priority 3 Case D example](/docs/main/img/gv_priority3-caseD.png)

## Procedure for Using the Enable API Group Versions Feature

1. [Install Velero](basic-install.md) on source cluster with the [feature flag enabled](customize-installation.md/#enable-server-side-features). The flag is `--features=EnableAPIGroupVersions`. For the enable API group versions feature to work, the feature flag needs to be used for Velero installations on both the source and destination clusters.
2. Back up and restore following the [migration case instructions](migration-case.md). Note that "Cluster 1" in the instructions refers to the source cluster, and "Cluster 2" refers to the destination cluster.

## Advanced Procedure for Customizing the Version Prioritization

Optionally, users can create a config map to override the default API group prioritization for some or all of the resources being migrated. For each resource that is specified by the user, Velero will search for the version in both the backup tarball and the destination cluster. If there is a match, the user-specified API group version will be restored. If the backup tarball and the destination cluster does not have or support any of the user-specified versions, then the default version prioritization will be used.

Here are the steps for creating a config map that allows users to override the default version prioritization. These steps must happen on the destination cluster before a Velero restore is initiated.

1. Create a file called `restoreResourcesVersionPriority`. The file name will become a key in the `data` field of the config map.
    - In the file, write a line for each resource group you'd like to override. Make sure each line follows the format `<resource>.<group>=<highest user priority version>,<next highest>`
    - Note that the resource group and versions are separated by a single equal (=) sign. Each version is listed in order of user's priority separated by commas.
    - Here is an example of the contents of a config map file:

    ```cm
    rockbands.music.example.io=v2beta1,v2beta2
    orchestras.music.example.io=v2,v3alpha1
    subscriptions.operators.coreos.com=v2,v1
    ```

2. Apply config map with

    ```bash
    kubectl create configmap enableapigroupversions --from-file=<absolute path>/restoreResourcesVersionPriority -n velero
    ```

3. See the config map with

    ```bash
    kubectl describe configmap enableapigroupversions -n velero
    ```

    The config map should look something like

    ```bash
    Name:         enableapigroupversions
    Namespace:    velero
    Labels:       <none>
    Annotations:  <none>

    Data
    ====
    restoreResourcesVersionPriority:
    ----
    rockbands.music.example.io=v2beta1,v2beta2
    orchestras.music.example.io=v2,v3alpha1
    subscriptions.operators.coreos.com=v2,v1
    Events:  <none>
    ```

## Troubleshooting

1. Refer to the [troubleshooting section](troubleshooting.md) of the docs as the techniques generally apply here as well.
2. The [debug logs](troubleshooting.md/#getting-velero-debug-logs) will contain information on which version was chosen to restore.
3. If no API group version could be found that both exists in the backup tarball file and is supported by the destination cluster, then the following error will be recorded (no need to activate debug level logging): `"error restoring rockbands.music.example.io/rockstars/beatles: the server could not find the requested resource"`.
