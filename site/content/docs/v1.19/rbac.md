---
title: "Run Velero more securely with restrictive RBAC settings"
layout: docs
---

By default Velero runs with an RBAC policy of ClusterRole `cluster-admin`. This is to make sure that Velero can back up or restore anything in your cluster. But `cluster-admin` access is wide open -- it gives Velero components access to everything in your cluster. Depending on your environment and your security needs, you should consider whether to configure additional RBAC policies with more restrictive access. 

**Note:** Roles and RoleBindings are associated with a single namespaces, not with an entire cluster. PersistentVolume backups are associated only with an entire cluster. This means that any backups or restores that use a restrictive Role and RoleBinding pair can manage only the resources that belong to the namespace. You do not need a wide open RBAC policy to manage PersistentVolumes, however. You can configure a ClusterRole and ClusterRoleBinding that allow backups and restores only of PersistentVolumes, not of all objects in the cluster.

For more information about RBAC and access control generally in Kubernetes, see the Kubernetes documentation about [access control][1], [managing service accounts][2], and [RBAC authorization][3].

## Set up with restricted RBAC permissions

Here's a sample of restricted permission setting.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: YOUR_NAMESPACE_HERE
  name: ROLE_NAME_HERE
  labels:
    component: velero
rules:
  - apiGroups:
      - velero.io
    verbs:
      - "*"
    resources:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ROLEBINDING_NAME_HERE
  namespace: YOUR_NAMESPACE_HERE
subjects:
  - kind: ServiceAccount
    name: YOUR_SERVICEACCOUNT_HERE
roleRef:
  kind: Role
  name: ROLE_NAME_HERE
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: velero-clusterrole
rules:
- apiGroups: 
  - ""
  resources:
  - persistentvolumes
  - namespaces
  verbs:
  - '*'
- apiGroups: 
  - '*'
  resources:
  - '*'
  verbs:
  - list
- apiGroups:
  - 'apiextensions.k8s.io'
  resources:
  - 'customresourcedefinitions'
  verbs:
  - get
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: velero-clusterrolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: velero-clusterrole
subjects:
  - kind: ServiceAccount
    name: YOUR_SERVICEACCOUNT_HERE
    namespace: YOUR_NAMESPACE_HERE
```

You can add more permissions into the `Role` setting according to the need.
`velero-clusterrole` ClusterRole is verified to work in most cases.
`Namespaces` resource permission is needed to create namespace during restore. If you don't need that, the `create` permission can be removed, but `list` and `get` permissions of `Namespaces` resource is still needed, because Velero needs to know whether the namespace it's assigned exists in the cluster.
`PersistentVolumes` resource permission is needed for back up and restore volumes. If that is not needed, it can be removed too.
`CustomResourceDefinitions` resource permission is needed to backup CR instances' CRD. It's better to keep them.
It's better to have the `list` permission for all resources, because Velero needs to read some resources during backup, for example, `ClusterRoles` is listed for backing `ServiceAccount` up, and `VolumeSnapshotContent` for CSI `PersistentVolumeClaim`. If you just enable `list` permissions for the resources you want to back up and restore, it's possible that backup or restore end with failure.

[1]: https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/
[2]: https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/
[3]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
[4]: namespace.md

