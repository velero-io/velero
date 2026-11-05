/*
Copyright the Velero contributors.

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

package csi

import (
	"context"

	"github.com/cockroachdb/errors"
	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// VolumeGroupSnapshot (VGS) API access.
//
// Different clusters serve different versions of the VGS API (e.g. OCP 5.0
// serves groupsnapshot.storage.k8s.io/v1, OCP 4.22 serves v1beta2), so the
// version cannot be hardcoded. Rather than a typed controller-runtime client
// (which sends the GVK of the Go type and can't negotiate), these helpers do
// all VGS I/O with *unstructured.Unstructured on the existing crClient: the
// object's GVK is stamped to the served version and controller-runtime routes
// it via its RESTMapper. Objects are converted to/from the canonical v1beta2
// typed structs, whose field layout is identical across v1beta1/v1beta2/v1 for
// everything Velero reads or writes.
//
// Upstream uses the v1 structs here. This branch pins external-snapshotter
// client v8.4.0, which predates the v1 package, so the identical v1beta2
// structs are used instead. This is a compile-time choice only: the version
// sent on the wire is still whatever ResolveVGSGroupVersion negotiates.
const (
	// VGSGroup is the VolumeGroupSnapshot API group.
	VGSGroup = "groupsnapshot.storage.k8s.io"

	kindVGS            = "VolumeGroupSnapshot"
	kindVGSList        = "VolumeGroupSnapshotList"
	kindVGSClass       = "VolumeGroupSnapshotClass"
	kindVGSClassList   = "VolumeGroupSnapshotClassList"
	kindVGSContent     = "VolumeGroupSnapshotContent"
	kindVGSContentList = "VolumeGroupSnapshotContentList"
)

// vgsPreferredVersions lists the VGS API versions Velero supports, most
// preferred first.
var vgsPreferredVersions = []string{"v1", "v1beta2", "v1beta1"}

// ErrVGSAPINotAvailable is returned when the cluster serves no VolumeGroupSnapshot
// API version. Callers that only clean up VGS resources can treat it as a no-op.
var ErrVGSAPINotAvailable = errors.New("VolumeGroupSnapshot API is not available in the cluster")

// ResolveVGSGroupVersion returns the highest-preference VolumeGroupSnapshot
// GroupVersion served by the cluster (v1 > v1beta2 > v1beta1), using the
// client's RESTMapper. Returns ErrVGSAPINotAvailable if none is served.
func ResolveVGSGroupVersion(mapper meta.RESTMapper) (schema.GroupVersion, error) {
	mappings, err := mapper.RESTMappings(schema.GroupKind{Group: VGSGroup, Kind: kindVGS})
	if err != nil {
		if meta.IsNoMatchError(err) {
			return schema.GroupVersion{}, ErrVGSAPINotAvailable
		}
		return schema.GroupVersion{}, errors.Wrap(err, "failed to get REST mappings for VolumeGroupSnapshot")
	}
	if len(mappings) == 0 {
		return schema.GroupVersion{}, ErrVGSAPINotAvailable
	}

	served := map[string]bool{}
	for _, m := range mappings {
		served[m.GroupVersionKind.Version] = true
	}
	for _, v := range vgsPreferredVersions {
		if served[v] {
			return schema.GroupVersion{Group: VGSGroup, Version: v}, nil
		}
	}

	versions := make([]string, 0, len(served))
	for v := range served {
		versions = append(versions, v)
	}
	return schema.GroupVersion{}, errors.Errorf(
		"cluster serves VolumeGroupSnapshot but no version Velero supports (served: %v, supported: %v)",
		versions, vgsPreferredVersions)
}

func toUnstructured(obj client.Object, gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert object to unstructured")
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetGroupVersionKind(gvk)
	return u, nil
}

func fromUnstructured(u *unstructured.Unstructured, out any) error {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, out); err != nil {
		return errors.Wrap(err, "failed to convert unstructured to typed object")
	}
	return nil
}

// ---- VolumeGroupSnapshotClass (cluster-scoped) ----

// ListVGSClasses lists all VolumeGroupSnapshotClasses served by the cluster.
func ListVGSClasses(ctx context.Context, c client.Client) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotClassList, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	ul := &unstructured.UnstructuredList{}
	ul.SetGroupVersionKind(gv.WithKind(kindVGSClassList))
	if err := c.List(ctx, ul); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotClassList{}
	for i := range ul.Items {
		item := volumegroupsnapshotv1beta2.VolumeGroupSnapshotClass{}
		if err := fromUnstructured(&ul.Items[i], &item); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// ---- VolumeGroupSnapshot (namespaced) ----

// CreateVGS creates a VolumeGroupSnapshot and returns the created object.
func CreateVGS(ctx context.Context, c client.Client, vgs *volumegroupsnapshotv1beta2.VolumeGroupSnapshot) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshot, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u, err := toUnstructured(vgs, gv.WithKind(kindVGS))
	if err != nil {
		return nil, err
	}
	if err := c.Create(ctx, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetVGS fetches a VolumeGroupSnapshot by namespace/name.
func GetVGS(ctx context.Context, c client.Client, namespace, name string) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshot, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gv.WithKind(kindVGS))
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListVGS lists VolumeGroupSnapshots in a namespace matching the given labels.
func ListVGS(ctx context.Context, c client.Client, namespace string, matchLabels map[string]string) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotList, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	ul := &unstructured.UnstructuredList{}
	ul.SetGroupVersionKind(gv.WithKind(kindVGSList))
	opts := []client.ListOption{client.InNamespace(namespace)}
	if len(matchLabels) > 0 {
		opts = append(opts, client.MatchingLabels(matchLabels))
	}
	if err := c.List(ctx, ul, opts...); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotList{}
	for i := range ul.Items {
		item := volumegroupsnapshotv1beta2.VolumeGroupSnapshot{}
		if err := fromUnstructured(&ul.Items[i], &item); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// DeleteVGS deletes a VolumeGroupSnapshot by namespace/name.
func DeleteVGS(ctx context.Context, c client.Client, namespace, name string) error {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gv.WithKind(kindVGS))
	u.SetNamespace(namespace)
	u.SetName(name)
	return c.Delete(ctx, u)
}

// ---- VolumeGroupSnapshotContent (cluster-scoped) ----

// CreateVGSC creates a VolumeGroupSnapshotContent and returns the created object.
func CreateVGSC(ctx context.Context, c client.Client, vgsc *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u, err := toUnstructured(vgsc, gv.WithKind(kindVGSContent))
	if err != nil {
		return nil, err
	}
	if err := c.Create(ctx, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetVGSC fetches a VolumeGroupSnapshotContent by name.
func GetVGSC(ctx context.Context, c client.Client, name string) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gv.WithKind(kindVGSContent))
	if err := c.Get(ctx, client.ObjectKey{Name: name}, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListVGSC lists VolumeGroupSnapshotContents matching the given labels.
func ListVGSC(ctx context.Context, c client.Client, matchLabels map[string]string) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentList, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	ul := &unstructured.UnstructuredList{}
	ul.SetGroupVersionKind(gv.WithKind(kindVGSContentList))
	var opts []client.ListOption
	if len(matchLabels) > 0 {
		opts = append(opts, client.MatchingLabels(matchLabels))
	}
	if err := c.List(ctx, ul, opts...); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentList{}
	for i := range ul.Items {
		item := volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
		if err := fromUnstructured(&ul.Items[i], &item); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// UpdateVGSC updates a VolumeGroupSnapshotContent (spec/metadata).
func UpdateVGSC(ctx context.Context, c client.Client, vgsc *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u, err := toUnstructured(vgsc, gv.WithKind(kindVGSContent))
	if err != nil {
		return nil, err
	}
	if err := c.Update(ctx, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateVGSCStatus updates the status subresource of a VolumeGroupSnapshotContent.
func UpdateVGSCStatus(ctx context.Context, c client.Client, vgsc *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent) (*volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u, err := toUnstructured(vgsc, gv.WithKind(kindVGSContent))
	if err != nil {
		return nil, err
	}
	if err := c.Status().Update(ctx, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteVGSC deletes a VolumeGroupSnapshotContent by name.
func DeleteVGSC(ctx context.Context, c client.Client, name string) error {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gv.WithKind(kindVGSContent))
	u.SetName(name)
	return c.Delete(ctx, u)
}
