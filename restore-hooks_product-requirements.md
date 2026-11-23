Velero Restore Hooks - PRD (Product Requirements Document) 

MVP Feature Set

Relates to:  [https://github.com/velero-io/velero/issues/2116](https://github.com/velero-io/velero/issues/2116)


# **Change tracking**

_This is a live document, you can reach me on the following channels for more information or for any questions:_



*   _Email:  [bstephanie@vmware.com](mailto:bstephanie@vmware.com)_
*   _Kubernetes slack:  _
    *   _Channel:  #velero_
    *   _@Stephanie Bauman_
*   _VMware internal slack:_
    *   _@bstephanie_


# **Relates to Git Issues:**



*   [https://app.zenhub.com/workspaces/velero-5c59c15e39d47b774b5864e3/issues/vmware-tanzu/velero/2465](https://app.zenhub.com/workspaces/velero-5c59c15e39d47b774b5864e3/issues/vmware-tanzu/velero/2465)
    *   [https://github.com/velero-io/velero/pull/2465/files?short_path=140e0c6#diff-140e0c6b370f250ee97f6ecafc8dbb7a](https://github.com/velero-io/velero/pull/2465/files?short_path=140e0c6#diff-140e0c6b370f250ee97f6ecafc8dbb7a)
*   [https://github.com/velero-io/velero/issues/1150](https://github.com/velero-io/velero/issues/1150)

Background

Velero supports restore operations but there are gaps in the process.  Gaps in the restore process require users to manually carry out steps to start, clean up, and end the restore process. Other gaps in the restore process can cause issues with application performance for applications running in a pod when a restore operation is carried out. 

On a restore, Velero currently does not include hooks to execute a pre- or -post restore script. As a result, users are required to perform additional actions following a velero restore operation. Some gaps that currently exist in the Velero restore process are:



*   Users can create a restore operation but has no option to customize or automate commands during the start of the restore operation
*   Users can perform post restore operations but have no option to customize or automate commands during the end of the restore operation

Strategic Fit

Adding a restore hook action today would allow Velero to unpack the data that was backed up in an automated way by enabling Velero to execute commands in containers during a restore. This will also improve the restore operations on a container and mitigate against any negative performance impacts of apps running in the container during restore.

Purpose / Goal

The purpose of this feature is to improve the extensibility and user experience of pre and post restore operations for Velero users.

Goals for this feature include:



*   Enhance application performance during and following restore events 
*   Provide pre-restore hooks for customizing start restore operations
*   Provide actions for things like retry actions, event logging, etc... during restore operations 
*   Provide observability/status of restore commands run in restored pods
*   Extend restore logs to include status, error codes and necessary metadata for restore commands run during restore operations for enhanced troubleshooting capabilities 
*   Provide post-restore hooks for customizing end of restore operations
*   Include pre-populated data that has been serialized by a Velero backup hook into a container or external service prior to allowing a restore to be marked as completed. 

Non-goals

Feature Description

This feature will automate the restore operations/processes in Velero, and will provide restore hook actions in Velero that allows users to execute restore commands on a container. Restore hooks include pre-hook actions and post-hook actions.

This feature will mirror the actions of a Velero backup by allowing Velero to check for any restore hooks specified for a pod. 

Assumptions



*   Restore operations will be run at the pod level instead of at the volume level. Some databases require the pod to be running and in some cases a user cannot manipulate a volume without the pod running. We need to support more than one type of database for this feature and so we need to ensure that this works broadly as opposed to providing support only for specific dbs. 
*   Velero will be responsible for invoking the restore hook. 

 

MVP Use Cases 

The following use cases must be included as part of the Velero restore hooks MVP (minimum viable product). 

**Note: **Processing of concurrent vs sequential workloads is slated later in the Velero roadmap (see [https://github.com/velero-io/velero/pull/2548/files](https://github.com/velero-io/velero/pull/2548/files)). The MVP for this feature set will align with restore of single workloads vs concurrent workload restores. A second epic will be created to address the concurrent restore operations and will be added to the backlog for priority visibility. 

**Note: **Please refer to the Requirements section of this document for more details on what items are P0 (must have in the MVP), P1 (should not ship without for the MVP), P2 (nice to haves).

**<span style="text-decoration:underline;">USE CASE 1</span>**


    **Title:** Run restore hook before pod restart.


    **Description:  **As a user, I would like to run a restore hook before the applications in my pod are restarted.

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 2</span>**


    **Title: **Allow restore hook to run on non-kubernetes databases


    **Description: **As a user, I would like to run restore hook operations even on databases that are external to Kubernetes (such as postgres, elastic, etc…).

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 3</span>**


    **Title: **Run restore at pod level.


    **Description: **As a user, I would like to make sure that I can run the restore hook at the pod level. And, I would like the option to run this with an annotation flag in line or using an init container.**<span style="text-decoration:underline;"> </span>**The restore pre-hook should allow the user to run the command on the container where the pre-hook should be executed. Similar to the backup hooks, this hook should run to default to run on the first container in the pod. 

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 4</span>**


    **Title:** Specify container in which to run pre-hook


    **Description: **As a user, if I do not want to run the pre-hook command on the first container in the pod (default container), I would like the option to annotate the specific container that i would like the hook to run in.

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 5</span>**


    **Title: **Check for latest snapshot 


    **Description: **As a user, I would like Velero to run a check for the latest snapshot in object storage prior to starting restore operations on a pod. 

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 6</span>**


    **Title: **Display/surface output from restore hooks/restore status 


    **Description:** As a user, I would like to see the output of the restore hooks/status of my restore surfaced from the pod volume restore status. Including statuses:  Pending, Running/In Progress, Succeeded, Failed, Unknown.

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 7</span>**


    **Title: **Restore metadata


    **Description: **As a user, I would like to have the metadata of the contents of what was restored using Velero.


    _Note: Kubernetes patterns may result in some snapshot metadata being overwritten during restore operations._

**<span style="text-decoration:underline;">______________________________________________________________</span>**

**<span style="text-decoration:underline;">USE CASE 8</span>*

    **Title: **Increase default restore and retry limits. 


    **Description: **As a user, I would like to increase the default restore retry and timeout limits from the default values to some other value I would like to specify. 


    _Note: See use case 11 for the default value specifications. _

**<span style="text-decoration:underline;">______________________________________________________________</span>**

User Experience

The following is representative of what the user experience could look like for Velero restore pre-hooks and post-hooks. 

**_Note: These examples are representative and are not to be considered for use in pre- and post- restore hook operations until the technical design is complete._**

**Restore Pre-Hooks**

<span style="text-decoration:underline;">Container Command</span>


```
pre.hook.restore.velero.io/container

kubectl patch backupstoragelocation <STORAGE LOCATION NAME> \
    --namespace velero \
    --type merge \
    --patch '{"spec":{"accessMode":"ReadOnly"}}'
```


<span style="text-decoration:underline;">Command Execute</span>


```
pre.hook.restore.velero.io/command
```


Includes commands for:



*   Create
    *   Create from most recent backup
    *   Create from specific backup - allow user to list backups
*   Set backup storage location to read only 

    ```
    kubectl patch backupstoragelocation <STORAGE LOCATION NAME> \
        --namespace velero \
        --type merge \
        --patch '{"spec":{"accessMode":"ReadOnly"}}
    ```


*   Set backup storage location to read-write

    ```
    kubectl patch backupstoragelocation <STORAGE LOCATION NAME> \
        --namespace velero \
        --type merge \
        --patch '{"spec":{"accessMode":"ReadWrite"}}'

    ```


<span style="text-decoration:underline;">Error handling </span>


```
pre.hook.restore.velero.io/on-error
```


<span style="text-decoration:underline;">Timeout </span>


```
pre.hook.restore.velero.io/retry
```


Requirements 

**_P0_** = must not ship without 


    (absolute requirement for MVP, engineering requirements for long term viability usually fall in here for ex., and incompletion nearing or by deadline means delaying code freeze and GA date)

**_P1_** = should not ship without 


    (required for feature to achieve general adoption, should be scoped into feature but can be pushed back to later iterations if needed)

**_P2_** = nice to have 


    (opportunistic, should not be scoped into the overall feature if it has dependencies and could cause delay)

**P0 Requirements**
P0. Use Case 1 - Run restore hook before pod restart.

P0.  Use Case 3- Run restore at pod level.

P0. Use Case 5 - Check for latest snapshot

P0. Use Case 9 - ** **Display/surface restore status 

P0. Use Case 10 - Restore metadata 

P0. Use Case 11 - Retry restore upon restore failure/error/timeout

P0. Use Case 12 - Increase default restore and retry limits. 

**P1 Requirements**
P1.  Use Case 2 - Allow restore hook to run on non-kubernetes databases

P1. Use Case 4 - Specify container in which to run pre-hook

P1. Use Case 6 - Specify backup snapshot to use for restore

P1. Use Case 7 - ** **Include or exclude namespaces from restore

**P2 Requirements**
P2. 

**Out of scope**

The following requirements are out of scope for the Velero Restore Hooks MVP:


1. Verifying the integrity of a backup, resource, or other artifact will not be included in the scope of this effort. 
2. Verifying the integrity of a snapshot using Kubernetes hash checks.
3. Running concurrent restore operations (for the MVP) a secondary epic will be opened to align better with the concurrent workload operations currently set on the Velero roadmap for Q4 timeframe. 

**Questions** 



1. For USE CASE 1:  Init vs app containers - if multiple containers are specified for a pod kubelet will run each init container sequentially - does this have an impact on things like concurrent workload processing? 
2. Can velero allow a user to specify a specific backup if the most recent backup is not desired in a restore?
3. If a backup specified for a restore operation fails, can velero retry and pick up the next most recent backup in the restore?
4. Can velero provide a delta between the two backups if a different backup needs to be picked up (other than the most recent because the most recent backup cannot be accessed?)
5. What types of errors can velero surface about backups, namespaces, pods, resources, if a backup has an issue with it preventing a restore from being done? 

 

For questions, please contact michaelmi@vmware.com,  [bstephanie@vmware.com](mailto:bstephanie@vmware.com) 
