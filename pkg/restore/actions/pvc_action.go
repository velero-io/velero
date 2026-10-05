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

package actions

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/podvolume/configs"
	"github.com/vmware-tanzu/velero/pkg/util"
)

const (
	AnnBindCompleted          = "pv.kubernetes.io/bind-completed"
	AnnBoundByController      = "pv.kubernetes.io/bound-by-controller"
	AnnStorageProvisioner     = "volume.kubernetes.io/storage-provisioner"
	AnnBetaStorageProvisioner = "volume.beta.kubernetes.io/storage-provisioner"
	AnnSelectedNode           = "volume.kubernetes.io/selected-node"
)

// PVCAction removes the Velero-backup related annotations and auto generated binding annotations.
// It also resets the PVC's bound info if it has a referenced PodVolumeBackup.
type PVCAction struct {
	logger   logrus.FieldLogger
	crClient crclient.Client
}

// NewPVCAction is the constructor for PVCAction.
func NewPVCAction(
	logger logrus.FieldLogger,
	crClient crclient.Client,
) *PVCAction {
	return &PVCAction{
		logger:   logger,
		crClient: crClient,
	}
}

// AppliesTo returns the resources that PVCAction should be run for
func (p *PVCAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"persistentvolumeclaims"},
	}, nil
}

// PVC actions for restore:
//  1. removes some additional annotations
//  2. returns bound PV as an additional item
//  3. resets bound if PVC references a PVB
func (p *PVCAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	p.logger.Info("Executing PVCAction")
	defer p.logger.Info("Done executing PVCAction")

	var pvc, pvcFromBackup corev1api.PersistentVolumeClaim
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.Item.UnstructuredContent(), &pvc); err != nil {
		return nil, errors.WithStack(err)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
		input.ItemFromBackup.UnstructuredContent(), &pvcFromBackup); err != nil {
		return nil, errors.WithStack(err)
	}

	log := p.logger.WithFields(map[string]any{
		"kind":      pvc.Kind,
		"namespace": pvc.Namespace,
		"name":      pvc.Name,
	})

	// Remove PVC annotations
	removePVCAnnotations(
		&pvc,
		[]string{
			AnnBindCompleted,
			AnnBoundByController,
			AnnStorageProvisioner,
			AnnBetaStorageProvisioner,
			AnnSelectedNode,
			velerov1api.VolumeSnapshotLabel,
			velerov1api.DataUploadNameAnnotation,
		},
	)

	hasPVB, err := p.hasPodVolumeBackup(context.Background(), input.Restore, &pvcFromBackup)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if hasPVB {
		log.Info("PVC has a matching PodVolumeBackup, resetting its volume name")
		pvc.Spec.VolumeName = ""
		pvc.Spec.DataSource = nil
		pvc.Spec.DataSourceRef = nil
	}

	pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pvc)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	output := &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{Object: pvcMap},
	}

	// Add PV as additional item if bound
	// use pvcFromBackup because we need to look at status fields, which have been removed from pvc
	if pvcFromBackup.Status.Phase != corev1api.ClaimBound || pvcFromBackup.Spec.VolumeName == "" {
		log.Info("PVC is not bound or its volume name is empty")
	} else if hasPVB {
		log.Info("PVC has a matching PodVolumeBackup, skipping PV inclusion")
	} else {
		log.Infof("Adding PV %s as an additional item to restore", pvcFromBackup.Spec.VolumeName)
		output.AdditionalItems = []velero.ResourceIdentifier{
			{
				GroupResource: kuberesource.PersistentVolumes,
				Name:          pvcFromBackup.Spec.VolumeName,
			},
		}
	}
	return output, nil
}

func (p *PVCAction) hasPodVolumeBackup(ctx context.Context, restore *velerov1api.Restore, pvc *corev1api.PersistentVolumeClaim) (bool, error) {
	if p.crClient == nil || restore == nil || pvc == nil {
		return false, nil
	}

	opts := &crclient.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			velerov1api.BackupNameLabel: label.GetValidName(restore.Spec.BackupName),
			velerov1api.PVCUIDLabel:     string(pvc.UID),
		}),
		Namespace: restore.Namespace,
	}
	podVolumeBackupList := new(velerov1api.PodVolumeBackupList)
	if err := p.crClient.List(ctx, podVolumeBackupList, opts); err != nil {
		return false, errors.WithStack(err)
	}

	var found bool
	for _, pvb := range podVolumeBackupList.Items {
		if pvb.Status.Phase != velerov1api.PodVolumeBackupPhaseCompleted || pvb.Status.SnapshotID == "" {
			continue
		}
		if pvb.Spec.Pod.Namespace == pvc.Namespace && pvb.GetAnnotations()[configs.PVCNameAnnotation] == pvc.Name {
			found = true
			break
		}
	}
	return found, nil
}

func removePVCAnnotations(pvc *corev1api.PersistentVolumeClaim, remove []string) {
	for k := range pvc.Annotations {
		if util.Contains(remove, k) {
			delete(pvc.Annotations, k)
		}
	}
}
