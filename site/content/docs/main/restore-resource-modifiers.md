---
title: "Restore Resource Modifiers"
layout: docs
---

## Resource Modifiers
Velero provides a generic ability to modify the resources during restore by specifying json patches. The json patches are applied to the resources before they are restored. The json patches are specified in a configmap and the configmap is referenced in the restore command. 

**Creating resource Modifiers**

Below is the two-step of using resource modifiers to modify the resources during restore.
1. Creating resource modifiers configmap

   You need to create one configmap in Velero install namespace from a YAML file that defined resource modifiers. The creating command would be like the below:
   ```bash
   kubectl create cm <configmap-name> --from-file <yaml-file> -n velero
   ```
2. Creating a restore reference to the defined resource policies

   You can create a restore with the flag `--resource-modifier-configmap`, which will apply the defined resource modifiers to the current restore. The creating command would be like the below:
   ```bash
   velero restore create --resource-modifier-configmap <configmap-name>
   ```

**YAML template**

- Yaml template:
```yaml
version: v1
resourceModifierRules:
- conditions:
     groupResource: persistentvolumeclaims
     resourceNameRegex: "^mysql.*$"
     namespaces:
     - bar
     - foo
     labelSelector:
        matchLabels:
           foo: bar
  patches:
  - operation: replace
    path: "/spec/storageClassName"
    value: "premium"
  - operation: remove
    path: "/metadata/labels/test"
 ```

- The above configmap will apply the JSON Patch to all the PVCs in the namespaces bar and foo with name starting with mysql and match label `foo: bar`. The JSON Patch will replace the storageClassName with "premium" and remove the label "test" from the PVCs.
- Note that the Namespace here is the original namespace of the backed up resource, not the new namespace where the resource is going to be restored.
- You can specify multiple JSON Patches for a particular resource. The patches will be applied in the order specified in the configmap. A subsequent patch is applied in order and if multiple patches are specified for the same path, the last patch will override the previous patches.
- You can specify multiple resourceModifierRules in the configmap. The rules will be applied in the order specified in the configmap. 

### Operations supported by the JSON Patch RFC: 
- add
- remove
- replace
- move
- copy
- test (covered below)

### Advanced scenarios
#### **Conditional patches using test operation**
 The `test` operation can be used to check if a particular value is present in the resource. If the value is present, the patch will be applied. If the value is not present, the patch will not be applied. This can be used to apply a patch only if a particular value is present in the resource. For example, if you wish to change the storage class of a PVC only if the PVC is using a particular storage class, you can use the following configmap.
```yaml
version: v1
resourceModifierRules:
- conditions:
    groupResource: persistentvolumeclaims
    resourceNameRegex: ".*"
    namespaces:
    - bar
    - foo
  patches:
  - operation: test
    path: "/spec/storageClassName"
    value: "premium"
  - operation: replace
    path: "/spec/storageClassName"
    value: "standard"
```

#### **Other examples**
```yaml
version: v1
resourceModifierRules:
- conditions:
    groupResource: deployments.apps
    resourceNameRegex: "^test-.*$"
    namespaces:
    - bar
    - foo
  patches:
    # Dealing with complex values by escaping the yaml
  - operation: add
    path: "/spec/template/spec/containers/0"
    value: "{\"name\": \"nginx\", \"image\": \"nginx:1.14.2\", \"ports\": [{\"containerPort\": 80}]}"
    # Copy Operator
  - operation: copy
    from: "/spec/template/spec/containers/0"
    path: "/spec/template/spec/containers/1"
```

**Note:** 
- The design and approach is inspired from [kubectl patch command](https://github.com/kubernetes/kubectl/blob/0a61782351a027411b8b45b1443ec3dceddef421/pkg/cmd/patch/patch.go#L102C2-L104C1)
-  Update a container's image using a json patch with positional arrays
kubectl patch pod valid-pod -type='json' -p='[{"op": "replace", "path": "/spec/containers/0/image", "value":"new image"}]'
- Before creating the resource modifier yaml, you can try it out using kubectl patch command. The same commands should work as it is.

#### JSON Merge Patch
You can modify a resource using JSON Merge Patch
```yaml
version: v1
resourceModifierRules:
- conditions:
    groupResource: pods
    namespaces:
    - ns1
  mergePatches:
  - patchData: |
      {
        "metadata": {
          "annotations": {
            "foo": null
          }
        }
      }
```
- The above configmap will apply the Merge Patch to all the pods in namespace ns1 and remove the annotation `foo` from the pods.
- Both json and yaml format are supported for the patchData.
- For more details, please refer to [this doc](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/)

#### Strategic Merge Patch
You can modify a resource using Strategic Merge Patch
```yaml
version: v1
resourceModifierRules:
- conditions:
    groupResource: pods
    resourceNameRegex: "^my-pod$"
    namespaces:
    - ns1
  strategicPatches:
  - patchData: |
      {
        "spec": {
          "containers": [
            {
              "name": "nginx",
              "image": "repo2/nginx"
            }
          ]
        }
      }
```
- The above configmap will apply the Strategic Merge Patch to the pod with name my-pod in namespace ns1 and update the image of container nginx to `repo2/nginx`.
- Both json and yaml format are supported for the patchData.
- For more details, please refer to [this doc](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/update-api-object-kubectl-patch/)


### Conditional Patches in ALL Patch Types
A new field `matches` is added in conditions to support conditional patches.

Example of matches in conditions
```yaml
version: v1
resourceModifierRules:
- conditions:
    groupResource: persistentvolumeclaims.storage.k8s.io
    matches:
    - path: "/spec/storageClassName"
      value: "premium"
  mergePatches:
  - patchData: |
      {
        "metadata": {
          "annotations": {
            "foo": null
          }
        }
      }
```
- The above configmap will apply the Merge Patch to all the PVCs in all namespaces with storageClassName premium and remove the annotation `foo` from the PVCs.
- You can specify multiple rules in the `matches` list. The patch will be applied only if all the matches are satisfied.

### Wildcard Support for GroupResource
The user can specify a wildcard for groupResource in the conditions' struct. This will allow the user to apply the patches for all the resources of a particular group or all resources in all groups. For example, `*.apps` will apply to all the resources in the `apps` group, `*` will apply to all the resources in core group, `*.*` will apply to all the resources in all groups.
- If both `*.groupName` and `namespaces` are specified, the patches will be applied to all the namespaced resources in this group in the specified namespaces and all the cluster resources in this group.

## Default Resource Modifiers

Velero supports a server-level default resource modifier that applies automatically to all restores without requiring per-restore configuration.
This is useful for common transformations like stripping stale CNI annotations that can break workloads after restore.

### Configuration

1. Create a ConfigMap in the Velero namespace with your default resource modifier rules:

```bash
kubectl apply -f examples/default-resource-modifier-cni.yaml
```

2. Configure the Velero server to use it, either during install:

```bash
velero install --default-resource-modifier-configmap=default-restore-resource-modifiers ...
```

Or by editing an existing deployment:

```bash
kubectl -n velero edit deploy velero
# Add to the server args: --default-resource-modifier-configmap=default-restore-resource-modifiers
```

### Precedence

When a per-restore modifier is specified via `--resource-modifier-configmap`, it takes exclusive precedence and the default is not applied.

### Opt-out

To skip the default modifier for a specific restore without specifying a per-restore modifier:

```bash
velero restore create --from-backup my-backup --skip-default-resource-modifier
```

### Error Handling

If the default ConfigMap is missing or contains invalid data, Velero logs a warning and proceeds with the restore.
Per-restore modifier errors remain fatal and cause the restore to fail validation.