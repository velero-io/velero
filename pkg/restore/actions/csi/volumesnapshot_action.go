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
	"fmt"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
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

	// Check if VGSC already exists
	existingVGSC := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
	err := p.crClient.Get(ctx, crclient.ObjectKey{Name: vgscName}, existingVGSC)
	if err == nil {
		// VGSC already exists, add this snapshot handle if not already present
		p.log.Infof("Stub VGSC %s already exists for VolumeGroupSnapshotHandle %s", vgscName, vgsh)
		return p.addSnapshotHandleToVGSC(ctx, existingVGSC, snapshotHandle)
	}
	if !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "failed to check for existing VGSC %s", vgscName)
	}

	// Create stub VGSC
	p.log.Infof("Creating stub VGSC %s for VolumeGroupSnapshotHandle %s", vgscName, vgsh)

	// Look up VolumeGroupSnapshotClass to get secret annotations
	vgscAnnotations := map[string]string{}
	vgscList := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotClassList{}
	if err := p.crClient.List(ctx, vgscList); err == nil {
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

	vgsc := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: vgscName,
			Labels: map[string]string{
				velerov1api.RestoreNameLabel: restore.Name,
			},
			Annotations: vgscAnnotations,
		},
		Spec: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
			Driver:         driver,
			Source: volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentSource{
				GroupSnapshotHandles: &volumegroupsnapshotv1beta2.GroupSnapshotHandles{
					VolumeGroupSnapshotHandle: vgsh,
					VolumeSnapshotHandles:     []string{snapshotHandle},
				},
			},
			VolumeGroupSnapshotRef: corev1api.ObjectReference{
				Name:      "stub-vgs-" + vgscName[:8],
				Namespace: vs.Namespace,
			},
		},
	}

	if err := p.crClient.Create(ctx, vgsc); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another VS restore created the VGSC between our Get and Create.
			// Re-fetch and add our snapshot handle.
			p.log.Infof("Stub VGSC %s was created by another VS restore, adding our handle", vgscName)
			raceVGSC := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
			if getErr := p.crClient.Get(ctx, crclient.ObjectKey{Name: vgscName}, raceVGSC); getErr != nil {
				return errors.Wrapf(getErr, "failed to get VGSC %s after race", vgscName)
			}
			return p.addSnapshotHandleToVGSC(ctx, raceVGSC, snapshotHandle)
		}
		return errors.Wrapf(err, "failed to create stub VGSC %s", vgscName)
	}

	// Re-fetch to get server-assigned metadata (resourceVersion) needed for patching
	createdVGSC := &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent{}
	if err := p.crClient.Get(ctx, crclient.ObjectKey{Name: vgscName}, createdVGSC); err != nil {
		p.log.Warnf("Failed to fetch stub VGSC %s for status patch: %v", vgscName, err)
		return nil
	}

	// Set volumeGroupSnapshotHandle in status using Patch to avoid conflicts with the CSI controller.
	patchBase := createdVGSC.DeepCopy()
	if createdVGSC.Status == nil {
		createdVGSC.Status = &volumegroupsnapshotv1beta2.VolumeGroupSnapshotContentStatus{}
	}
	createdVGSC.Status.VolumeGroupSnapshotHandle = &vgsh
	if err := p.crClient.Status().Patch(ctx, createdVGSC, crclient.MergeFrom(patchBase)); err != nil {
		p.log.Warnf("Failed to patch stub VGSC %s status: %v", vgscName, err)
	}

	p.log.Infof("Successfully created stub VGSC %s", vgscName)
	return nil
}

// addSnapshotHandleToVGSC adds a snapshot handle to an existing VGSC if not already present.
// This is needed when multiple VolumeSnapshots from the same VolumeGroupSnapshot are restored.
func (p *volumeSnapshotRestoreItemAction) addSnapshotHandleToVGSC(
	ctx context.Context,
	vgsc *volumegroupsnapshotv1beta2.VolumeGroupSnapshotContent,
	snapshotHandle string,
) error {
	// Check if handle is already in the list
	if vgsc.Spec.Source.GroupSnapshotHandles != nil {
		for _, handle := range vgsc.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles {
			if handle == snapshotHandle {
				p.log.Infof("Snapshot handle %s already present in VGSC %s", snapshotHandle, vgsc.Name)
				return nil
			}
		}
	}

	// Add the snapshot handle to the list
	patchBase := vgsc.DeepCopy()
	if vgsc.Spec.Source.GroupSnapshotHandles == nil {
		vgsc.Spec.Source.GroupSnapshotHandles = &volumegroupsnapshotv1beta2.GroupSnapshotHandles{}
	}
	vgsc.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles = append(
		vgsc.Spec.Source.GroupSnapshotHandles.VolumeSnapshotHandles,
		snapshotHandle,
	)

	if err := p.crClient.Patch(ctx, vgsc, crclient.MergeFrom(patchBase)); err != nil {
		return errors.Wrapf(err, "failed to add snapshot handle to VGSC %s", vgsc.Name)
	}

	p.log.Infof("Added snapshot handle %s to existing VGSC %s", snapshotHandle, vgsc.Name)
	return nil
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

	vsMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&vs)
	if err != nil {
		p.log.Errorf("Fail to convert VS %s to unstructured", vs.Namespace+"/"+vs.Name)
		return nil, errors.WithStack(err)
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

		return &volumeSnapshotRestoreItemAction{logger, crClient}, nil
	}
}
