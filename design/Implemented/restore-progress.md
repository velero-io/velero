# Restore progress reporting

Velero _Backup_ resource provides real-time progress of an ongoing backup by means of a _Progress_ field in the CR. Velero _Restore_, on the other hand, only shows one of the phases (InProgress, Completed, PartiallyFailed, Failed) of the ongoing restore. In this document, we propose detailed progress reporting for Velero _Restore_. With the introduction of the proposed _Progress_ field, Velero _Restore_ CR will look like:

```yml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: test-restore
  namespace: velero
spec:
    [...]
status:
  phase: InProgress
  progress:
    itemsRestored: 100
    totalItems: 140
```

## Goals

- Enable progress reporting for Velero Restore

## Non Goals

- Estimate time to completion

## Background

The current _Restore_ CR lets users know whether a restore is in-progress or completed (failed/succeeded). While this basic piece of information is useful to the end user, there seems to be room for improvement in the user experience. The _Restore_ CR can show detailed progress in terms of the number of resources restored so far and the total number of resources to be restored. This will be particularly useful for restores that run for a longer duration of time. Such progress reporting already exists for Velero _Backup_. This document proposes similar implementation for Velero _Restore_.

## High-Level Design

We propose to divide the restore process in two steps. The first step will collect all the items to be restored from the backup tarball. It will apply the label selector and include/exclude rules on the resources / items and store them (preserving the priority order) in an in-memory data structure. The second step will read the collected items and restore them. 

## Detailed Design

### Progress struct

A new struct will be introduced to store progress information:

```go
type RestoreProgress struct {
    TotalItems    int `json:"totalItems,omitempty`
    ItemsRestored int `json:"itemsRestored,omitempty`
}
```

`RestoreStatus` will include the above struct:

```go
type RestoreStatus struct {
    [...]

    Progress *RestoreProgress `json:"progress,omitempty"`
}
```

### Modifications to restore.go

Currently, the restore process works by looping through the resources in the backup tarball and restoring them one-by-one in the same pass:

```go
func (ctx *context) execute(...) {
    [...]

    for _, resource := range getOrderedResources(...) {
        [...]

        for namespace, items := range resourceList.ItemsByNamespace {
            [...]

            for _, item := range items {
                [...]

                // restore item here
                w, e := restoreItem(...)
            }
        }
    }
}
```

We propose to remove the call to `restoreItem()` in the inner most loop and instead store the item in a data structure. Once all the items are collected, we loop through the array of collected items and make a call to `restoreItem()`:

```go
func (ctx *context) getOrderedResourceCollection(...) {
    collectedResources := []restoreResource
    for _, resource := range getOrderedResources(...) {
        [...]

        for namespace, items := range resourceList.ItemsByNamespace {
            [...]
            collectedResource := restoreResource{}
            for _, item := range items {
                [...]

                // store item in a data structure
                collectedResource.itemsByNamespace[originalNamespace] = append(collectedResource.itemsByNamespace[originalNamespace], item)
            }
        }
        collectedResources.append(collectedResources, collectedResource)
    }
    return collectedResources
}

func (ctx *context) execute(...) {
    [...]

    // get all items
    resources := ctx.getOrderedResourceCollection(...)

    for _, resource := range resources {
        [...]

        for _, items := range resource.itemsByNamespace {
            [...]

            for _, item := range items {
                [...]

                // restore the item
                w, e := restoreItem(...)
            }
        }
    }

    [...]
}
```

We introduce two new structs to hold the collected items:

```go
type restoreResource struct {
    resource            string
    itemsByNamespace    map[string][]restoreItem
    totalItems          int
}

type restoreItem struct {
    targetNamespace string
    name            string
}
```

Each group resource is represented by `restoreResource`. The map `itemsByNamespace` is indexed by `originalNamespace`, and the values are list of `items` in the original namespace. `totalItems` is simply the count of all items which are present in the nested map of namespace and items. It is updated every time an item is added to the map. Each item represented by `restoreItem` has `name` and the resolved `targetNamespace`.

### Calculating progress

The total number of items can be calculated by simply adding the number of total items present in the map of all resources.

```go
totalItems := 0

for _, resource := range collectedResources {
	totalItems += resource.totalItems
}
```

The additional items returned by the plugins will still be discovered at the time of plugin execution. The number of `totalItems` will be adjusted to include such additional items. As a result, the number of total items is expected to change whenever plugins execute:

```go
    i := 0
    for _, resource := range resources {
        [...]

        for _, items := range resource.itemsByNamespace {
            [...]

            for _, item := range items {
                [...]

                // restore the item
                w, e := restoreItem(...)
		i++
		// calculate the actual count of resources
		actualTotalItems := len(ctx.restoredItems) + (totalItems - i)
            }
        }
    }
```

### Updating progress 

The updates to the `progress` field in the CR can be sent on a channel as soon as an item is restored. A goroutine receiving update on that channel can make an `Update()` call to update the _Restore_ CR. This will require us to pass an instance of `RestoresGetter` to the `kubernetesRestorer` struct.


## Alternatives Considered

As an alternative, we have considered an approach which doesn't divide the restore process in two steps. 

With that approach, the total number of items will be read from the Backup CR. We will keep three counters, `totalItems`, `skippedItems` and `restoredItems`:

```yml
status:
  phase: InProgress
  progress:
    totalItems: 100
    skippedItems: 20
    restoredItems: 79
```

This approach doesn't require us to find the number of total items beforehand.

## Security Considerations

Omitted

## Compatibility

Omitted

## Implementation

TBD

## Open Issues

https://github.com/vmware-tanzu/velero/issues/21