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
	"encoding/json"
	"fmt"
	"slices"

	"github.com/cockroachdb/errors"
	volumegroupsnapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/client"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/label"
	plugincommon "github.com/velero-io/velero/pkg/plugin/framework/common"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/util"
	"github.com/velero-io/velero/pkg/util/boolptr"
	csiutil "github.com/velero-io/velero/pkg/util/csi"
)

// volumeSnapshotRestoreItemAction is a Velero restore item
// action plugin for VolumeSnapshots
type volumeSnapshotRestoreItemAction struct {
	log      logrus.FieldLogger
	crClient crclient.Client
}

// AppliesTo returns information indicating that
// VolumeSnapshotRestoreItemAction should be invoked while
// restoring volumesnapshots.snapshot.storage.k8s.io resources.
func (p *volumeSnapshotRestoreItemAction) AppliesTo() (
	velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"volumesnapshots.snapshot.storage.k8s.io"},
	}, nil
}

func resetVolumeSnapshotSpecForRestore(vs *snapshotv1api.VolumeSnapshot, vscName *string) {
	// Spec of the backed-up object used the PVC as the source
	// of the volumeSnapshot.  Restore operation will however,
	// restore the VolumeSnapshot from the VolumeSnapshotContent
	vs.Spec.Source.PersistentVolumeClaimName = nil
	vs.Spec.Source.VolumeSnapshotContentName = vscName
}

func resetVolumeSnapshotAnnotation(vs *snapshotv1api.VolumeSnapshot) {
	if vs.ObjectMeta.Annotations == nil {
		vs.ObjectMeta.Annotations = make(map[string]string)
	}
	vs.ObjectMeta.Annotations[velerov1api.VSCDeletionPolicyAnnotation] =
		string(snapshotv1api.VolumeSnapshotContentRetain)
}

// ensureStubVGSCExists creates a stub VolumeGroupSnapshotContent if the snapshot
// was created as part of a VolumeGroupSnapshot. This is needed for CSI drivers
// like Ceph RBD that populate volumeGroupSnapshotHandle on pre-provisioned snapshots.
// The CSI snapshot controller requires a VGSC with matching handle to exist.
func (p *volumeSnapshotRestoreItemAction) ensureStubVGSCExists(
	ctx context.Context,
	vs *snapshotv1api.VolumeSnapshot,
	restore *velerov1api.Restore,
) error {
	vgsh, ok := vs.Annotations[velerov1api.VolumeGroupSnapshotHandleAnnotation]
	if !ok || vgsh == "" {
		// No VolumeGroupSnapshotHandle, nothing to do
		return nil
	}

	snapshotHandle, ok := vs.Annotations[velerov1api.VolumeSnapshotHandleAnnotation]
	if !ok || snapshotHandle == "" {
		p.log.Warnf("VS %s/%s has VolumeGroupSnapshotHandle but no SnapshotHandle annotation",
			vs.Namespace, vs.Name)
		return nil
	}

	driver, ok := vs.Annotations[velerov1api.DriverNameAnnotation]
	if !ok || driver == "" {
		p.log.Warnf("VS %s/%s has VolumeGroupSnapshotHandle but no Driver annotation",
			vs.Namespace, vs.Name)
		return nil
	}

	// Generate a deterministic name for the stub VGSC based on the group handle
	vgscName := util.GenerateSha256FromRestoreUIDAndVsName(string(restore.UID), vgsh)

	// Check if VGSC already exists. A stub created for another member of the
	// group already lists every member, and its snapshot handles are immutable.
	_, err := csiutil.GetVGSC(ctx, p.crClient, vgscName)
	if err == nil {
		p.log.Infof("Stub VGSC %s already exists for VolumeGroupSnapshotHandle %s", vgscName, vgsh)
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "failed to check for existing VGSC %s", vgscName)
	}

	// Create stub VGSC
	p.log.Infof("Creating stub VGSC %s for VolumeGroupSnapshotHandle %s", vgscName, vgsh)

	// Look up VolumeGroupSnapshotClass to get secret annotations
	vgscAnnotations := map[string]string{}
	if vgscList, err := csiutil.ListVGSClasses(ctx, p.crClient); err == nil {
		for _, vgsClass := range vgscList.Items {
			if vgsClass.Driver == driver {
				// Found matching class, extract secret parameters
				if secretName, ok := vgsClass.Parameters["csi.storage.k8s.io/group-snapshotter-secret-name"]; ok {
					vgscAnnotations["groupsnapshot.storage.kubernetes.io/deletion-secret-name"] = secretName
				}
				if secretNS, ok := vgsClass.Parameters["csi.storage.k8s.io/group-snapshotter-secret-namespace"]; ok {
					vgscAnnotations["groupsnapshot.storage.kubernetes.io/deletion-secret-namespace"] = secretNS
				}
				break
			}
		}
	}

	vgsc := &volumegroupsnapshotv1.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: vgscName,
			Labels: map[string]string{
				velerov1api.RestoreNameLabel: label.GetValidName(restore.Name),
			},
			Annotations: vgscAnnotations,
		},
		Spec: volumegroupsnapshotv1.VolumeGroupSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
			Driver:         driver,
			Source: volumegroupsnapshotv1.VolumeGroupSnapshotContentSource{
				GroupSnapshotHandles: &volumegroupsnapshotv1.GroupSnapshotHandles{
					VolumeGroupSnapshotHandle: vgsh,
					VolumeSnapshotHandles:     p.groupMemberHandles(vs, snapshotHandle),
				},
			},
			VolumeGroupSnapshotRef: corev1api.ObjectReference{
				Name:      "stub-vgs-" + vgscName[:8],
				Namespace: vs.Namespace,
			},
		},
	}

	if _, err := csiutil.CreateVGSC(ctx, p.crClient, vgsc); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another VS restore created the VGSC between our Get and Create.
			p.log.Infof("Stub VGSC %s was created by another VS restore", vgscName)
			return nil
		}
		return errors.Wrapf(err, "failed to create stub VGSC %s", vgscName)
	}

	// Set volumeGroupSnapshotHandle in status. Re-fetch inside the retry to pick up
	// the latest resourceVersion and avoid conflicts with the CSI controller.
	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		createdVGSC, err := csiutil.GetVGSC(ctx, p.crClient, vgscName)
		if err != nil {
			return err
		}
		if createdVGSC.Status == nil {
			createdVGSC.Status = &volumegroupsnapshotv1.VolumeGroupSnapshotContentStatus{}
		}
		createdVGSC.Status.VolumeGroupSnapshotHandle = &vgsh
		_, err = csiutil.UpdateVGSCStatus(ctx, p.crClient, createdVGSC)
		return err
	}); err != nil {
		p.log.Warnf("Failed to set stub VGSC %s status: %v", vgscName, err)
	}

	p.log.Infof("Successfully created stub VGSC %s", vgscName)
	return nil
}

// groupMemberHandles returns the snapshot handles of every member of the
// VolumeSnapshot's group, as recorded at backup time. The CSI driver rejects a
// stub VGSC whose handles do not match the group. Backups taken before the
// handles were recorded only give this VolumeSnapshot's own handle.
func (p *volumeSnapshotRestoreItemAction) groupMemberHandles(vs *snapshotv1api.VolumeSnapshot, snapshotHandle string) []string {
	recorded, ok := vs.Annotations[velerov1api.VolumeGroupSnapshotMemberHandlesAnnotation]
	if !ok {
		p.log.Warnf("VS %s/%s has no group member snapshot handles, so the stub VGSC lists only its own snapshot. "+
			"The CSI driver may reject it, and the restored VolumeSnapshots of the group then never become ready",
			vs.Namespace, vs.Name)
		return []string{snapshotHandle}
	}

	var handles []string
	if err := json.Unmarshal([]byte(recorded), &handles); err != nil {
		p.log.WithError(err).Warnf("VS %s/%s has unreadable group member snapshot handles", vs.Namespace, vs.Name)
		return []string{snapshotHandle}
	}
	if !slices.Contains(handles, snapshotHandle) {
		handles = append(handles, snapshotHandle)
	}
	return handles
}

func (p *volumeSnapshotRestoreItemAction) Execute(
	input *velero.RestoreItemActionExecuteInput,
) (*velero.RestoreItemActionExecuteOutput, error) {
	p.log.Info("Starting VolumeSnapshotRestoreItemAction")

	if boolptr.IsSetToFalse(input.Restore.Spec.RestorePVs) {
		p.log.Infof("Restore %s/%s did not request for PVs to be restored.",
			input.Restore.Namespace, input.Restore.Name)
		return &velero.RestoreItemActionExecuteOutput{SkipRestore: true}, nil
	}

	var vs snapshotv1api.VolumeSnapshot
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.Item.UnstructuredContent(), &vs); err != nil {
		return &velero.RestoreItemActionExecuteOutput{},
			errors.Wrapf(err, "failed to convert input.Item from unstructured")
	}
	// Restored group members are restored as independent VolumeSnapshots. The
	// source VGS is not restored and cannot release source-cluster finalizers.
	controllerutil.RemoveFinalizer(&vs, csiutil.VolumeSnapshotInGroupFinalizer)
	controllerutil.RemoveFinalizer(&vs, csiutil.VolumeSnapshotAsSourceFinalizer)

	var vsFromBackup snapshotv1api.VolumeSnapshot
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.ItemFromBackup.UnstructuredContent(), &vsFromBackup); err != nil {
		return &velero.RestoreItemActionExecuteOutput{},
			errors.Wrapf(err, "failed to convert input.Item from unstructured")
	}

	// Create stub VGSC if this snapshot was created via VolumeGroupSnapshot
	// This must happen before VSC is created, as the CSI controller requires VGSC to exist
	if err := p.ensureStubVGSCExists(context.Background(), &vsFromBackup, input.Restore); err != nil {
		p.log.Warnf("Failed to create stub VGSC for VS %s/%s: %v", vsFromBackup.Namespace, vsFromBackup.Name, err)
		// Continue with restore, VGSC creation failure should not block restore
	}

	generatedName := util.GenerateSha256FromRestoreUIDAndVsName(string(input.Restore.UID), vsFromBackup.Name)

	// Reset Spec to convert the VolumeSnapshot from using
	// the dynamic VolumeSnapshotContent to the static one.
	resetVolumeSnapshotSpecForRestore(&vs, &generatedName)
	// Also reset the VS name to avoid potential conflict caused by multiple restores of the same backup.
	// Both VS and VSC share the same generated name.
	vs.Name = generatedName

	// Reset VolumeSnapshot annotation. By now, only change
	// DeletionPolicy to Retain.
	resetVolumeSnapshotAnnotation(&vs)

	if vs.Spec.VolumeSnapshotClassName != nil {
		// Delete VolumeSnapshotClass from the VolumeSnapshot.
		// This is necessary to make the restore independent of the VolumeSnapshotClass.
		vs.Spec.VolumeSnapshotClassName = nil
		p.log.Debugf("Deleted VolumeSnapshotClassName from VolumeSnapshot %s/%s to make restore independent of VolumeSnapshotClass",
			vs.Namespace, vs.Name)
	}

	if vsFromBackup.Status == nil ||
		vsFromBackup.Status.BoundVolumeSnapshotContentName == nil {
		p.log.Errorf("VS %s doesn't have bound VSC", vsFromBackup.Name)
		return nil, fmt.Errorf("VS %s doesn't have bound VSC", vsFromBackup.Name)
	}

	vsc := velero.ResourceIdentifier{
		GroupResource: kuberesource.VolumeSnapshotContents,
		Name:          *vsFromBackup.Status.BoundVolumeSnapshotContentName,
	}

	// Force-restore the bound VSC even when restore resource filters would
	// otherwise exclude it (mirrors backup-side must-include for CSI deps).
	annotations := vs.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[velerov1api.MustIncludeAdditionalItemRestoreAnnotation] = "true"
	vs.SetAnnotations(annotations)

	vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&vs)
	if err != nil {
		p.log.Errorf("Fail to convert VS %s to unstructured", vs.Namespace+"/"+vs.Name)
		return nil, errors.WithStack(err)
	}

	p.log.Infof(`Returning from VolumeSnapshotRestoreItemAction with 
		VolumeSnapshotContent in additionalItems`)

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem:     &unstructured.Unstructured{Object: vsMap},
		AdditionalItems: []velero.ResourceIdentifier{vsc},
	}, nil
}

func (p *volumeSnapshotRestoreItemAction) Name() string {
	return "VolumeSnapshotRestoreItemAction"
}

func (p *volumeSnapshotRestoreItemAction) Progress(
	operationID string,
	restore *velerov1api.Restore,
) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

func (p *volumeSnapshotRestoreItemAction) Cancel(
	operationID string,
	restore *velerov1api.Restore,
) error {
	// CSI Specification doesn't support canceling a snapshot creation.
	return nil
}

func (p *volumeSnapshotRestoreItemAction) AreAdditionalItemsReady(
	additionalItems []velero.ResourceIdentifier,
	restore *velerov1api.Restore,
) (bool, error) {
	return true, nil
}

func NewVolumeSnapshotRestoreItemAction(
	f client.Factory,
) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}

		return &volumeSnapshotRestoreItemAction{
			log:      logger,
			crClient: crClient,
		}, nil
	}
}
