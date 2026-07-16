/*
Copyright 2017 the Velero contributors.

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
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/actionhelpers"
)

// PVCAction inspects a PersistentVolumeClaim for the PersistentVolume
// that it references and backs it up
type PVCAction struct {
	log logrus.FieldLogger
}

func NewPVCAction(logger logrus.FieldLogger) *PVCAction {
	return &PVCAction{log: logger}
}

func (a *PVCAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"persistentvolumeclaims"},
	}, nil
}

// Execute finds the PersistentVolume bound by the provided
// PersistentVolumeClaim, if any, and backs it up
func (a *PVCAction) Execute(item runtime.Unstructured, backup *v1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, error) {
	a.log.Info("Executing PVCAction")

	pvc := new(corev1api.PersistentVolumeClaim)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.UnstructuredContent(), &pvc); err != nil {
		return nil, nil, errors.Wrap(err, "unable to convert unstructured item to persistent volume claim")
	}

	if pvc.Status.Phase != corev1api.ClaimBound || pvc.Spec.VolumeName == "" {
		return item, nil, nil
	}

	// remove dataSource if exists from prior restored CSI volumes
	if pvc.Spec.DataSource != nil {
		pvc.Spec.DataSource = nil
	}
	if pvc.Spec.DataSourceRef != nil {
		pvc.Spec.DataSourceRef = nil
	}

	// When StorageClassName is set to "", it means no StorageClass is specified,
	// even the default StorageClass is not used. Only keep the Selector for this case.
	// https://kubernetes.io/docs/concepts/storage/persistent-volumes/#reserving-a-persistentvolume
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != "" {
		// Clean the selector to make the PVC to dynamically allocate PV.
		pvc.Spec.Selector = nil
	}

	// Clean stale Velero labels from PVC metadata and selector
	a.cleanupStaleVeleroLabels(pvc, backup)

	pvcMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pvc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to convert pvc to unstructured item")
	}

	return &unstructured.Unstructured{Object: pvcMap}, actionhelpers.RelatedItemsForPVC(pvc, a.log), nil
}

// cleanupStaleVeleroLabels removes stale Velero labels from both the PVC metadata
// and the selector's match labels to ensure clean backups
func (a *PVCAction) cleanupStaleVeleroLabels(pvc *corev1api.PersistentVolumeClaim, backup *v1.Backup) {
	// Clean stale Velero labels from selector match labels
	if pvc.Spec.Selector != nil && pvc.Spec.Selector.MatchLabels != nil {
		for k := range pvc.Spec.Selector.MatchLabels {
			if strings.HasPrefix(k, "velero.io/") {
				a.log.Infof("Deleting stale Velero label %s from PVC %s selector", k, pvc.Name)
				delete(pvc.Spec.Selector.MatchLabels, k)
			}
		}
	}

	// Clean stale Velero labels from main metadata
	if pvc.Labels != nil {
		for k, v := range pvc.Labels {
			// Only remove labels that are clearly stale from previous operations
			shouldRemove := false

			// Always remove restore-name labels as these are from previous restores
			if k == v1.RestoreNameLabel {
				shouldRemove = true
			}

			if k == v1.MustIncludeAdditionalItemAnnotation {
				shouldRemove = true
			}

			// Remove backup-name labels that don't match current backup
			if k == v1.BackupNameLabel && v != backup.Name {
				shouldRemove = true
			}

			// Remove volume-snapshot-name labels from previous CSI backups
			// Note: If this backup creates new CSI snapshots, the CSI action will add them back
			if k == v1.VolumeSnapshotLabel {
				shouldRemove = true
			}

			if shouldRemove {
				a.log.Infof("Deleting stale Velero label %s=%s from PVC %s", k, v, pvc.Name)
				delete(pvc.Labels, k)
			}
		}
	}
}
