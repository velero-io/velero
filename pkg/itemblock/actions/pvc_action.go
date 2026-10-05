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
	"k8s.io/apimachinery/pkg/runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/actionhelpers"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// PVCAction inspects a PersistentVolumeClaim for the PersistentVolume
// that it references and backs it up
type PVCAction struct {
	log      logrus.FieldLogger
	crClient crclient.Client
	// map[namespace]->[map[pvcVolumes]->[]podName]
	nsPVCs map[string]map[string][]string
}

func NewPVCAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		return &PVCAction{
			log:      logger,
			crClient: crClient,
		}, nil
	}
}

func (a *PVCAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"persistentvolumeclaims"},
	}, nil
}

func (a *PVCAction) GetRelatedItems(item runtime.Unstructured, backup *v1.Backup) ([]velero.ResourceIdentifier, error) {
	a.log.Info("Executing PVC ItemBlockAction")
	defer a.log.Info("Done executing PVC ItemBlockAction")

	pvc := new(corev1api.PersistentVolumeClaim)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.UnstructuredContent(), &pvc); err != nil {
		return nil, errors.Wrap(err, "unable to convert unstructured item to persistent volume claim")
	}

	if pvc.Status.Phase != corev1api.ClaimBound || pvc.Spec.VolumeName == "" {
		return nil, nil
	}
	// returns the PV for the PVC (shared with BIA additionalItems)
	relatedItems := actionhelpers.RelatedItemsForPVC(pvc, a.log)

	// Adds pods mounting this PVC to ensure that multiple pods mounting the same RWX
	// volume get backed up together.
	pvcs, err := a.getPVCList(pvc.Namespace)
	if err != nil {
		return nil, err
	}

	for _, pod := range pvcs[pvc.Name] {
		a.log.Infof("Adding related Pod %s to PVC %s", pod, pvc.Name)
		relatedItems = append(relatedItems, velero.ResourceIdentifier{
			GroupResource: kuberesource.Pods,
			Namespace:     pvc.Namespace,
			Name:          pod,
		})
	}

	// Gather groupedPVCs based on VGS label provided in the backup
	groupedPVCs, err := a.getGroupedPVCs(context.Background(), pvc, backup)
	if err != nil {
		return nil, err
	}

	// Add the groupedPVCs to relatedItems so that they processed in a single item block
	relatedItems = append(relatedItems, groupedPVCs...)

	return relatedItems, nil
}

func (a *PVCAction) getPVCList(ns string) (map[string][]string, error) {
	if a.nsPVCs == nil {
		a.nsPVCs = make(map[string]map[string][]string)
	}
	pvcList, ok := a.nsPVCs[ns]
	if ok {
		return pvcList, nil
	}
	pvcList = make(map[string][]string)
	pods := new(corev1api.PodList)
	err := a.crClient.List(context.Background(), pods, crclient.InNamespace(ns))
	if err != nil {
		return nil, errors.Wrap(err, "failed to list pods")
	}
	for i := range pods.Items {
		if kube.IsPodRunning(&pods.Items[i]) != nil {
			a.log.Debugf("Pod %s is not running, not adding to Pod list for PVC IBA plugin", pods.Items[i].Name)
			continue
		}
		for _, volume := range pods.Items[i].Spec.Volumes {
			if volume.VolumeSource.PersistentVolumeClaim != nil {
				pvcList[volume.VolumeSource.PersistentVolumeClaim.ClaimName] = append(pvcList[volume.VolumeSource.PersistentVolumeClaim.ClaimName], pods.Items[i].Name)
			}
		}
	}
	a.nsPVCs[ns] = pvcList
	return pvcList, nil
}

func (a *PVCAction) Name() string {
	return "PVCItemBlockAction"
}

// getGroupedPVCs returns other PVCs in the same group based on the VGS label key in the Backup spec.
func (a *PVCAction) getGroupedPVCs(ctx context.Context, pvc *corev1api.PersistentVolumeClaim, backup *v1.Backup) ([]velero.ResourceIdentifier, error) {
	var related []velero.ResourceIdentifier

	vgsLabelKey := backup.Spec.VolumeGroupSnapshotLabelKey
	if vgsLabelKey == "" {
		a.log.Debug("No VolumeGroupSnapshotLabelKey provided in backup spec; skipping PVC grouping")
		return nil, nil
	}

	groupID, ok := pvc.Labels[vgsLabelKey]
	if !ok || groupID == "" {
		// PVC does not belong to any VGS group or groupID has empty value
		a.log.Debug("PVC does not belong to any PVC group or group label value is empty; skipping PVC grouping")
		return nil, nil
	}

	pvcList := new(corev1api.PersistentVolumeClaimList)
	if err := a.crClient.List(
		ctx,
		pvcList,
		crclient.InNamespace(pvc.Namespace),
		crclient.MatchingLabels{vgsLabelKey: groupID},
	); err != nil {
		return nil, errors.Wrapf(err, "failed to list PVCs for VGS grouping with label %s=%s in namespace %s", vgsLabelKey, groupID, pvc.Namespace)
	}

	if len(pvcList.Items) <= 1 {
		// Only the current PVC exists in this group
		return nil, nil
	}

	for _, groupPVC := range pvcList.Items {
		if groupPVC.Name == pvc.Name {
			continue
		}

		a.log.Infof("Adding grouped PVC %s (group %s) to relatedItems for PVC %s", groupPVC.Name, groupID, pvc.Name)

		related = append(related, velero.ResourceIdentifier{
			GroupResource: kuberesource.PersistentVolumeClaims,
			Namespace:     groupPVC.Namespace,
			Name:          groupPVC.Name,
		})
	}

	return related, nil
}
