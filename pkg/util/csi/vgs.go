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
	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
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
// it via its RESTMapper. Objects are converted to/from the canonical v1 typed
// structs, whose field layout is identical across v1beta1/v1beta2/v1 for
// everything Velero reads or writes.
const (
	// VGSGroup is the VolumeGroupSnapshot API group.
	VGSGroup = "groupsnapshot.storage.k8s.io"

	kindVGS            = "VolumeGroupSnapshot"
	kindVGSList        = "VolumeGroupSnapshotList"
	kindVGSClass       = "VolumeGroupSnapshotClass"
	kindVGSClassList   = "VolumeGroupSnapshotClassList"
	kindVGSContent     = "VolumeGroupSnapshotContent"
	kindVGSContentList = "VolumeGroupSnapshotContentList"

	// vgsContentBoundProtectionFinalizer is the finalizer the external-snapshotter
	// common controller adds to a VolumeGroupSnapshotContent once a VolumeGroupSnapshot
	// is actually bound to it (Spec.VolumeGroupSnapshotRef.UID set). The common
	// controller's own add-finalizer step early-returns for any content whose ref
	// has no UID yet, treating it as "waiting to be bound" — which a static content
	// with a deliberately dangling ref (no real VolumeGroupSnapshot behind it, as
	// here) never will be. Without this finalizer, deleting the content removes it
	// from the API server immediately instead of setting DeletionTimestamp, so the
	// sidecar never gets a live object to act on and the real CSI
	// DeleteVolumeGroupSnapshot call never happens. Velero sets it explicitly for
	// exactly this reason (verified against external-snapshotter v8.6.0 source).
	// The sidecar removes it itself once the real delete succeeds.
	vgsContentBoundProtectionFinalizer = "groupsnapshot.storage.kubernetes.io/volumegroupsnapshotcontent-bound-protection"
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
func ListVGSClasses(ctx context.Context, c client.Client) (*volumegroupsnapshotv1.VolumeGroupSnapshotClassList, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	ul := &unstructured.UnstructuredList{}
	ul.SetGroupVersionKind(gv.WithKind(kindVGSClassList))
	if err := c.List(ctx, ul); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotClassList{}
	for i := range ul.Items {
		item := volumegroupsnapshotv1.VolumeGroupSnapshotClass{}
		if err := fromUnstructured(&ul.Items[i], &item); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// ---- VolumeGroupSnapshot (namespaced) ----

// CreateVGS creates a VolumeGroupSnapshot and returns the created object.
func CreateVGS(ctx context.Context, c client.Client, vgs *volumegroupsnapshotv1.VolumeGroupSnapshot) (*volumegroupsnapshotv1.VolumeGroupSnapshot, error) {
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
	out := &volumegroupsnapshotv1.VolumeGroupSnapshot{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetVGS fetches a VolumeGroupSnapshot by namespace/name.
func GetVGS(ctx context.Context, c client.Client, namespace, name string) (*volumegroupsnapshotv1.VolumeGroupSnapshot, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gv.WithKind(kindVGS))
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1.VolumeGroupSnapshot{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListVGS lists VolumeGroupSnapshots in a namespace matching the given labels.
func ListVGS(ctx context.Context, c client.Client, namespace string, matchLabels map[string]string) (*volumegroupsnapshotv1.VolumeGroupSnapshotList, error) {
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
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotList{}
	for i := range ul.Items {
		item := volumegroupsnapshotv1.VolumeGroupSnapshot{}
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
func CreateVGSC(ctx context.Context, c client.Client, vgsc *volumegroupsnapshotv1.VolumeGroupSnapshotContent) (*volumegroupsnapshotv1.VolumeGroupSnapshotContent, error) {
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
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetVGSC fetches a VolumeGroupSnapshotContent by name.
func GetVGSC(ctx context.Context, c client.Client, name string) (*volumegroupsnapshotv1.VolumeGroupSnapshotContent, error) {
	gv, err := ResolveVGSGroupVersion(c.RESTMapper())
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gv.WithKind(kindVGSContent))
	if err := c.Get(ctx, client.ObjectKey{Name: name}, u); err != nil {
		return nil, err
	}
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListVGSC lists VolumeGroupSnapshotContents matching the given labels.
func ListVGSC(ctx context.Context, c client.Client, matchLabels map[string]string) (*volumegroupsnapshotv1.VolumeGroupSnapshotContentList, error) {
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
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotContentList{}
	for i := range ul.Items {
		item := volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
		if err := fromUnstructured(&ul.Items[i], &item); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// UpdateVGSC updates a VolumeGroupSnapshotContent (spec/metadata).
func UpdateVGSC(ctx context.Context, c client.Client, vgsc *volumegroupsnapshotv1.VolumeGroupSnapshotContent) (*volumegroupsnapshotv1.VolumeGroupSnapshotContent, error) {
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
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
	if err := fromUnstructured(u, out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateVGSCStatus updates the status subresource of a VolumeGroupSnapshotContent.
func UpdateVGSCStatus(ctx context.Context, c client.Client, vgsc *volumegroupsnapshotv1.VolumeGroupSnapshotContent) (*volumegroupsnapshotv1.VolumeGroupSnapshotContent, error) {
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
	out := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{}
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

// EnsureStaticVGSCForHandle ensures a static VolumeGroupSnapshotContent named
// name exists for groupSnapshotHandle, creating it with the given deletion
// policy, labels and VolumeGroupSnapshotRef if needed, and adds
// snapshotHandle to its member handle list when non-empty. The group
// snapshotter deletion secrets are resolved from the live
// VolumeGroupSnapshotClass for driver. The content status is populated with
// the group handle so that the CSI snapshotter sidecar can act on the
// content without waiting for a driver status sync.
func EnsureStaticVGSCForHandle(
	ctx context.Context,
	c client.Client,
	log logrus.FieldLogger,
	name, driver, groupSnapshotHandle, snapshotHandle string,
	policy snapshotv1.DeletionPolicy,
	labels map[string]string,
	ref corev1api.ObjectReference,
) error {
	existing, err := GetVGSC(ctx, c, name)
	if err == nil {
		return AddSnapshotHandleToVGSC(ctx, c, log, existing, snapshotHandle)
	}
	if !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "failed to check for existing VGSC %s", name)
	}

	handles := []string{}
	if snapshotHandle != "" {
		handles = append(handles, snapshotHandle)
	}
	vgsClasses, err := ListVGSClasses(ctx, c)
	if err != nil {
		log.WithError(err).Warn("Failed to list VolumeGroupSnapshotClasses for group snapshot deletion secrets")
		vgsClasses = nil
	}
	created, err := CreateStaticVGSCForHandles(ctx, c, log, name, driver, groupSnapshotHandle, handles, policy, labels, ref, vgsClasses)
	if err != nil && !errors.Is(err, ErrStaticVGSCStatusNotSet) {
		return err
	}
	if err != nil {
		// The restore stub VGSC is long-lived and reconciled independently of
		// this call, unlike the short-lived content the release path creates
		// and deletes seconds later: a failure to set status here does not
		// risk losing the only record of this handle the way it would for a
		// release, so it is logged and tolerated rather than failing the
		// restore item, matching this function's behavior before status was
		// introduced.
		log.WithError(err).Warnf("Static VGSC %s created but its status could not be set", name)
	}
	if !created {
		// Another item created the content between the Get and Create.
		// Re-fetch and add this handle.
		raceVGSC, getErr := GetVGSC(ctx, c, name)
		if getErr != nil {
			return errors.Wrapf(getErr, "failed to get VGSC %s after race", name)
		}
		return AddSnapshotHandleToVGSC(ctx, c, log, raceVGSC, snapshotHandle)
	}
	return nil
}

// CreateStaticVGSCForHandles creates a static VolumeGroupSnapshotContent
// named name for groupSnapshotHandle carrying the complete list of member
// snapshotHandles, the given deletion policy, labels and
// VolumeGroupSnapshotRef. The content is created once, complete: the CSI
// CRDs mark source, deletionPolicy and volumeGroupSnapshotRef immutable, and
// groupSnapshotHandles is additionally required to carry both the group
// handle and the member handle list, so an incomplete content can never be
// completed afterwards. Callers must therefore know the full member list
// before calling this. If the content already exists it is left untouched
// and created is false, which makes the create idempotent for retries. The
// group snapshotter deletion secrets for driver are resolved from vgsClasses,
// which the caller resolves once (via ListVGSClasses) and shares across every
// content it creates in one operation, rather than this function re-listing
// identical cluster-wide data per call. The content status is populated with
// the group handle so that the CSI snapshotter sidecar can act on the
// content without waiting for a driver status sync.
func CreateStaticVGSCForHandles(
	ctx context.Context,
	c client.Client,
	log logrus.FieldLogger,
	name, driver, groupSnapshotHandle string,
	snapshotHandles []string,
	policy snapshotv1.DeletionPolicy,
	labels map[string]string,
	ref corev1api.ObjectReference,
	vgsClasses *volumegroupsnapshotv1.VolumeGroupSnapshotClassList,
) (created bool, err error) {
	log.Infof("Creating static VGSC %s for VolumeGroupSnapshotHandle %s with %d member snapshot handles",
		name, groupSnapshotHandle, len(snapshotHandles))

	// volumeSnapshotHandles is a required field of groupSnapshotHandles, so
	// the list is always initialized even when no member handle is known.
	handles := make([]string, 0, len(snapshotHandles))
	handles = append(handles, snapshotHandles...)

	// The sidecar's first sync of a pre-provisioned content (GroupSnapshotHandles
	// set) calls GetVolumeGroupSnapshot to validate it before anything else can
	// happen, including the later delete. That call has no annotation-based
	// credential fallback the way the later delete does: it resolves credentials
	// solely through VolumeGroupSnapshotClassName and a specific
	// "...-get-secret-name" class parameter that commonly isn't configured,
	// since normal group lifecycle never needs it (verified against
	// external-snapshotter v8.6.0 source). Rather than depend on that
	// parameter existing, Status.ReadyToUse is set to true below, which makes
	// the sidecar skip the validation call entirely on its next reconcile:
	// our own handle is already known good (it came from a group that really
	// was created), and this content exists only to be deleted seconds from
	// now. Deliberately not setting VolumeGroupSnapshotClassName here: with
	// readyToUse covering every case where the class parameter is missing
	// (the common one) and providing no benefit on its own in the narrow
	// window where the sidecar might race in before readyToUse lands even
	// when the parameter is present, it would only add an unused field for
	// no gain. The deletion-secret annotations set below are independently
	// required either way: the actual delete reads credentials from them
	// exclusively, never from the class.
	vgsc := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: groupSnapshotDeletionSecrets(vgsClasses, driver),
			// The common controller never adds its own bound-protection
			// finalizer to this content, since VolumeGroupSnapshotRef is
			// deliberately left pointing at a VolumeGroupSnapshot that does
			// not exist (see the constant's doc comment). Without it,
			// deleting this content removes it immediately instead of
			// giving the sidecar a live object to process the real delete
			// against.
			Finalizers: []string{vgsContentBoundProtectionFinalizer},
		},
		Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{
			DeletionPolicy: policy,
			Driver:         driver,
			Source: volumegroupsnapshotv1.VolumeGroupSnapshotContentSource{
				GroupSnapshotHandles: &volumegroupsnapshotv1.GroupSnapshotHandles{
					VolumeGroupSnapshotHandle: groupSnapshotHandle,
					VolumeSnapshotHandles:     handles,
				},
			},
			VolumeGroupSnapshotRef: ref,
		},
	}

	created = true
	if _, err := CreateVGSC(ctx, c, vgsc); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return false, errors.Wrapf(err, "failed to create static VGSC %s", name)
		}
		// Either a genuine race with another item building the same
		// deterministically-named content, or a previous call to this
		// function created the object but failed to set its status below
		// (see ErrStaticVGSCStatusNotSet) and is now being retried. Both
		// cases fall through to the status update: name is derived from the
		// same group snapshot handle either way, so re-setting the same
		// status values on it is always safe and idempotent.
		log.Infof("Static VGSC %s already exists, ensuring its status is set", name)
		created = false
	}

	// Set volumeGroupSnapshotHandle and readyToUse in status. Re-fetch inside
	// the retry to pick up the latest resourceVersion and avoid conflicts
	// with the CSI controller. readyToUse=true is what actually makes the
	// sidecar skip GetVolumeGroupSnapshot validation on its next reconcile of
	// this content (see the comment above): the handle alone is not enough,
	// since Spec.Source.GroupSnapshotHandles being set is what routes the
	// sidecar into that validation in the first place, independent of the
	// handle's own value.
	readyToUse := true
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		createdVGSC, err := GetVGSC(ctx, c, name)
		if err != nil {
			return err
		}
		if createdVGSC.Status == nil {
			createdVGSC.Status = &volumegroupsnapshotv1.VolumeGroupSnapshotContentStatus{}
		}
		createdVGSC.Status.VolumeGroupSnapshotHandle = &groupSnapshotHandle
		createdVGSC.Status.ReadyToUse = &readyToUse
		_, err = UpdateVGSCStatus(ctx, c, createdVGSC)
		return err
	}); err != nil {
		// The object exists (created here or already present), so created
		// reflects that. Callers that delete this content seconds from now
		// (the release path) must not treat this as success, since without
		// readyToUse the sidecar's GetVolumeGroupSnapshot validation can
		// fail on missing credentials and the real delete may never run.
		// Wrapping ErrStaticVGSCStatusNotSet itself (rather than wrapping err
		// with it attached via errors.Mark) keeps it discoverable through the
		// ordinary Unwrap chain, so callers that can tolerate it (the
		// long-lived restore stub) can distinguish this outcome from a hard
		// creation failure with errors.Is.
		return created, errors.Wrapf(ErrStaticVGSCStatusNotSet, "setting static VGSC %s status: %s", name, err)
	}

	return created, nil
}

// ErrStaticVGSCStatusNotSet indicates that CreateStaticVGSCForHandles created
// the VolumeGroupSnapshotContent object but could not set its status
// (ReadyToUse, VolumeGroupSnapshotHandle) after retrying. Callers that rely
// on ReadyToUse to avoid the CSI snapshotter sidecar's credential-requiring
// GetVolumeGroupSnapshot validation — the release path deleting this content
// seconds later — must treat this as a failure to retry rather than success.
var ErrStaticVGSCStatusNotSet = errors.New("failed to set static VolumeGroupSnapshotContent status")

// AddSnapshotHandleToVGSC adds a snapshot handle to an existing static
// VolumeGroupSnapshotContent if not already present, so that items sharing a
// group snapshot accumulate their handles on the same content.
func AddSnapshotHandleToVGSC(
	ctx context.Context,
	c client.Client,
	log logrus.FieldLogger,
	vgsc *volumegroupsnapshotv1.VolumeGroupSnapshotContent,
	snapshotHandle string,
) error {
	if snapshotHandle == "" {
		return nil
	}
	if vgsc.Spec.Source.GroupSnapshotHandles != nil {
		for _, handle := range vgsc.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles {
			if handle == snapshotHandle {
				return nil
			}
		}
	}

	// Add the snapshot handle to the list. Re-fetch inside the retry to pick
	// up the latest resourceVersion and avoid conflicts with concurrent
	// items.
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		latest, err := GetVGSC(ctx, c, vgsc.Name)
		if err != nil {
			return err
		}

		if latest.Spec.Source.GroupSnapshotHandles == nil {
			latest.Spec.Source.GroupSnapshotHandles = &volumegroupsnapshotv1.GroupSnapshotHandles{}
		}
		for _, handle := range latest.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles {
			if handle == snapshotHandle {
				return nil
			}
		}

		latest.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles = append(
			latest.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles,
			snapshotHandle,
		)

		_, err = UpdateVGSC(ctx, c, latest)
		return err
	}); err != nil {
		return errors.Wrapf(err, "failed to add snapshot handle to VGSC %s", vgsc.Name)
	}

	log.Infof("Added snapshot handle %s to existing VGSC %s", snapshotHandle, vgsc.Name)
	return nil
}

// groupSnapshotDeletionSecrets resolves the group snapshotter deletion
// secrets for a driver from vgsClasses. The list is resolved once by the
// caller (ListVGSClasses lists every VolumeGroupSnapshotClass in the
// cluster, cluster-scoped data that does not vary per VolumeGroupSnapshotContent
// being created) and shared across every content built in one operation,
// rather than re-listing identical data once per content. A nil list is
// treated as "no classes found" rather than an error, matching the
// best-effort nature of this lookup: without the secrets the CSI snapshotter
// sidecar cannot authenticate against drivers that require them, but content
// creation still proceeds.
func groupSnapshotDeletionSecrets(vgsClasses *volumegroupsnapshotv1.VolumeGroupSnapshotClassList, driver string) map[string]string {
	annotations := map[string]string{}
	class := matchingVGSClass(vgsClasses, driver)
	if class == nil {
		return annotations
	}
	if secretName, ok := class.Parameters["csi.storage.k8s.io/group-snapshotter-secret-name"]; ok {
		annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-name"] = secretName
	}
	if secretNS, ok := class.Parameters["csi.storage.k8s.io/group-snapshotter-secret-namespace"]; ok {
		annotations["groupsnapshot.storage.kubernetes.io/deletion-secret-namespace"] = secretNS
	}
	return annotations
}

// matchingVGSClass returns the first VolumeGroupSnapshotClass in vgsClasses
// whose driver matches, or nil if none does or vgsClasses is nil.
func matchingVGSClass(vgsClasses *volumegroupsnapshotv1.VolumeGroupSnapshotClassList, driver string) *volumegroupsnapshotv1.VolumeGroupSnapshotClass {
	if vgsClasses == nil {
		return nil
	}
	for i := range vgsClasses.Items {
		if vgsClasses.Items[i].Driver == driver {
			return &vgsClasses.Items[i]
		}
	}
	return nil
}
