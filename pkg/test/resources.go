/*
Copyright 2019 the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package test

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// APIResource stores information about a specific Kubernetes API
// resource.
type APIResource struct {
	Group      string
	Version    string
	Name       string
	Kind       string
	ShortName  string
	Namespaced bool
	Items      []metav1.Object
}

// GVR returns a GroupVersionResource representing the resource.
func (r *APIResource) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    r.Group,
		Version:  r.Version,
		Resource: r.Name,
	}
}

// Pods returns an APIResource describing core/v1's Pods.
func Pods(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "pods",
		ShortName:  "po",
		Namespaced: true,
		Items:      items,
		Kind:       "Pod",
	}
}

func PVCs(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "persistentvolumeclaims",
		ShortName:  "pvc",
		Kind:       "PersistentVolumeClaim",
		Namespaced: true,
		Items:      items,
	}
}

func PVs(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "persistentvolumes",
		ShortName:  "pv",
		Kind:       "PersistentVolume",
		Namespaced: false,
		Items:      items,
	}
}

func Secrets(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "secrets",
		ShortName:  "secrets",
		Kind:       "Secret",
		Namespaced: true,
		Items:      items,
	}
}

func Deployments(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "apps",
		Version:    "v1",
		Name:       "deployments",
		ShortName:  "deploy",
		Kind:       "Deployment",
		Namespaced: true,
		Items:      items,
	}
}

func ExtensionsDeployments(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "extensions",
		Version:    "v1",
		Name:       "deployments",
		ShortName:  "deploy",
		Kind:       "Deployment",
		Namespaced: true,
		Items:      items,
	}
}

// test CRD
func VeleroDeployments(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "velero.io",
		Version:    "v1",
		Name:       "deployments",
		ShortName:  "deploy",
		Kind:       "Deployment",
		Namespaced: true,
		Items:      items,
	}
}

func Namespaces(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "namespaces",
		ShortName:  "ns",
		Kind:       "Namespace",
		Namespaced: false,
		Items:      items,
	}
}

func ServiceAccounts(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "serviceaccounts",
		ShortName:  "sa",
		Kind:       "ServiceAccount",
		Namespaced: true,
		Items:      items,
	}
}

func ConfigMaps(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "configmaps",
		ShortName:  "cm",
		Kind:       "ConfigMap",
		Namespaced: true,
		Items:      items,
	}
}

func CRDs(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "apiextensions.k8s.io",
		Version:    "v1beta1",
		Name:       "customresourcedefinitions",
		ShortName:  "crd",
		Kind:       "CustomResourceDefinition",
		Namespaced: false,
		Items:      items,
	}
}

func VSLs(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "velero.io",
		Version:    "v1",
		Name:       "volumesnapshotlocations",
		Kind:       "VolumeSnapshotLocation",
		Namespaced: true,
		Items:      items,
	}
}

func Backups(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "velero.io",
		Version:    "v1",
		Name:       "backups",
		Kind:       "Backup",
		Namespaced: true,
		Items:      items,
	}
}

func Services(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "",
		Version:    "v1",
		Name:       "services",
		ShortName:  "svc",
		Kind:       "Service",
		Namespaced: true,
		Items:      items,
	}
}

func DataUploads(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "velero.io",
		Version:    "v2alpha1",
		Name:       "datauploads",
		Kind:       "DataUpload",
		Namespaced: true,
		Items:      items,
	}
}

func StorageClasses(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "storage.k8s.io",
		Version:    "v1",
		Name:       "storageclasses",
		ShortName:  "sc",
		Kind:       "StorageClass",
		Namespaced: false,
		Items:      items,
	}
}

func VolumeSnapshotContents(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "snapshot.storage.k8s.io",
		Version:    "v1",
		Name:       "volumesnapshotcontents",
		Kind:       "VolumeSnapshotContent",
		Namespaced: false,
		Items:      items,
	}
}

func VolumeSnapshots(items ...metav1.Object) *APIResource {
	return &APIResource{
		Group:      "snapshot.storage.k8s.io",
		Version:    "v1",
		Name:       "volumesnapshots",
		Kind:       "VolumeSnapshot",
		Namespaced: true,
		Items:      items,
	}
}
