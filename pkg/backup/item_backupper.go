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

package backup

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	kbClient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/hook"
	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/archive"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/itemblock"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	vsv1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/volumesnapshotter/v1"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	csiutil "github.com/vmware-tanzu/velero/pkg/util/csi"
	"github.com/vmware-tanzu/velero/pkg/util/volumehelper"
)

const (
	csiBIAPluginName     = "velero.io/csi-pvc-backupper"
	vsphereBIAPluginName = "velero.io/vsphere-pvc-backupper"
)

// itemBackupper can back up individual items to a tar writer.
type itemBackupper struct {
	backupRequest            *Request
	tarWriter                tarWriter
	dynamicFactory           client.DynamicFactory
	kbClient                 kbClient.Client
	discoveryHelper          discovery.Helper
	podVolumeBackupper       podvolume.Backupper
	podVolumeContext         context.Context
	podVolumeSnapshotTracker *podvolume.Tracker
	kubernetesBackupper      *kubernetesBackupper
	volumeSnapshotterCache   *VolumeSnapshotterCache
	itemHookHandler          hook.ItemHookHandler
	hookTracker              *hook.HookTracker
	volumeHelperImpl         volumehelper.VolumeHelper
}

type FileForArchive struct {
	FilePath  string
	Header    *tar.Header
	FileBytes []byte
}

// backupItem backs up an individual item to tarWriter. The item may be excluded based on the
// namespaces IncludesExcludes list.
// If finalize is true, then it returns the bytes instead of writing them to the tarWriter
// In addition to the error return, backupItem also returns a bool indicating whether the item
// was actually backed up.
func (ib *itemBackupper) backupItem(logger logrus.FieldLogger, obj runtime.Unstructured, groupResource schema.GroupResource, preferredGVR schema.GroupVersionResource, mustInclude, finalize bool, itemBlock *BackupItemBlock) (bool, []FileForArchive, error) {
	selectedForBackup, files, err := ib.backupItemInternal(logger, obj, groupResource, preferredGVR, mustInclude, finalize, itemBlock)
	// return if not selected, an error occurred, there are no files to add, or for finalize
	if !selectedForBackup || err != nil || len(files) == 0 || finalize {
		return selectedForBackup, files, err
	}
	ib.tarWriter.Lock()
	defer ib.tarWriter.Unlock()
	for _, file := range files {
		if err := ib.tarWriter.WriteHeader(file.Header); err != nil {
			return false, []FileForArchive{}, errors.WithStack(err)
		}

		if _, err := ib.tarWriter.Write(file.FileBytes); err != nil {
			return false, []FileForArchive{}, errors.WithStack(err)
		}
	}
	return true, []FileForArchive{}, nil
}

func (ib *itemBackupper) itemInclusionChecks(log logrus.FieldLogger, mustInclude bool, metadata metav1.Object, obj runtime.Unstructured, groupResource schema.GroupResource) bool {
	if mustInclude {
		log.Infof("Skipping the exclusion checks for this resource")
	} else {
		if metadata.GetLabels()[velerov1api.ExcludeFromBackupLabel] == "true" {
			log.Infof("Excluding item because it has label %s=true", velerov1api.ExcludeFromBackupLabel)
			ib.trackSkippedPV(obj, groupResource, "", fmt.Sprintf("item has label %s=true", velerov1api.ExcludeFromBackupLabel), log)
			return false
		}
		// NOTE: we have to re-check namespace & resource includes/excludes because it's possible that
		// backupItem can be invoked by a custom action.
		namespace := metadata.GetNamespace()
		if namespace != "" && !ib.backupRequest.NamespaceIncludesExcludes.ShouldInclude(namespace) {
			log.Info("Excluding item because namespace is excluded")
			return false
		}

		// NOTE: we specifically allow namespaces to be backed up even if it's excluded.
		// This check is more permissive for cluster resources to let those passed in by
		// plugins' additional items to get involved.
		// Only expel cluster resource when it's specifically listed in the excluded list here.
		if namespace == "" && groupResource != kuberesource.Namespaces &&
			ib.backupRequest.ResourceIncludesExcludes.ShouldExclude(groupResource.String()) {
			log.Info("Excluding item because resource is cluster-scoped and is excluded by cluster filter.")
			return false
		}

		// Only check namespace-scoped resource to avoid expelling cluster resources
		// are not specified in included list.
		if namespace != "" && !ib.backupRequest.ResourceIncludesExcludes.ShouldInclude(groupResource.String()) {
			log.Info("Excluding item because resource is excluded")
			return false
		}
	}

	if metadata.GetDeletionTimestamp() != nil {
		log.Info("Skipping item because it's being deleted.")
		return false
	}
	return true
}

func (ib *itemBackupper) backupItemInternal(logger logrus.FieldLogger, obj runtime.Unstructured, groupResource schema.GroupResource, preferredGVR schema.GroupVersionResource, mustInclude, finalize bool, itemBlock *BackupItemBlock) (bool, []FileForArchive, error) {
	var itemFiles []FileForArchive
	metadata, err := meta.Accessor(obj)
	if err != nil {
		return false, itemFiles, err
	}

	namespace := metadata.GetNamespace()
	name := metadata.GetName()

	log := logger.WithFields(map[string]any{
		"name":      name,
		"resource":  groupResource.String(),
		"namespace": namespace,
	})

	if !ib.itemInclusionChecks(log, mustInclude, metadata, obj, groupResource) {
		return false, itemFiles, nil
	}

	key := itemKey{
		resource:  resourceKey(obj),
		namespace: namespace,
		name:      name,
	}

	if ib.backupRequest.BackedUpItems.Has(key) {
		log.Info("Skipping item because it's already been backed up.")
		// returning true since this item *is* in the backup, even though we're not backing it up here
		return true, itemFiles, nil
	}
	ib.backupRequest.BackedUpItems.AddItem(key)
	log.Info("Backing up item")

	var (
		backupErrs []error
		pod        *corev1api.Pod
		pvbVolumes []string
	)

	if optedOut, podName := ib.podVolumeSnapshotTracker.OptedoutByPod(namespace, name); optedOut {
		ib.trackSkippedPV(obj, groupResource, podVolumeApproach, fmt.Sprintf("opted out due to annotation in pod %s", podName), log)
	}

	if groupResource == kuberesource.Pods {
		// pod needs to be initialized for the unstructured converter
		pod = new(corev1api.Pod)
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pod); err != nil {
			backupErrs = append(backupErrs, errors.WithStack(err))
			// nil it on error since it's not valid
			pod = nil
		} else {
			// Get the list of volumes to back up using pod volume backup from the pod's annotations
			// or volume policy approach. Remove from this list any volumes that use a PVC that we've
			// already backed up (this would be in a read-write-many scenario,
			// where it's been backed up from another pod), since we don't need >1 backup per PVC.
			for _, volume := range pod.Spec.Volumes {
				shouldDoFSBackup, err := ib.volumeHelperImpl.ShouldPerformFSBackup(volume, *pod)
				if err != nil {
					backupErrs = append(backupErrs, errors.WithStack(err))
				}

				if shouldDoFSBackup {
					// track the volumes backing up by PVB , so that when we backup PVCs/PVs
					// via an item action in the next step, we don't snapshot PVs that will have their data backed up
					// with pod volume backup.
					ib.podVolumeSnapshotTracker.Track(pod, volume.Name)

					if found, pvcName := ib.podVolumeSnapshotTracker.TakenForPodVolume(pod, volume.Name); found {
						log.WithFields(map[string]any{
							"podVolume": volume,
							"pvcName":   pvcName,
						}).Info("Pod volume uses a persistent volume claim which has already been backed up from another pod, skipping.")
						continue
					}
					pvbVolumes = append(pvbVolumes, volume.Name)
				} else {
					ib.podVolumeSnapshotTracker.Optout(pod, volume.Name)
				}
			}
		}
	}

	// capture the version of the object before invoking plugin actions as the plugin may update
	// the group version of the object.
	versionPath := resourceVersion(obj)

	updatedObj, additionalItemFiles, err := ib.executeActions(log, obj, groupResource, name, namespace, metadata, finalize, itemBlock)
	if err != nil {
		backupErrs = append(backupErrs, err)
		return false, itemFiles, kubeerrs.NewAggregate(backupErrs)
	}

	// If err is nil and updatedObj is nil, it means the item is skipped by plugin action,
	// we should return here to avoid backing up the item, and avoid potential NPE in the following code.
	if updatedObj == nil {
		log.Infof("Remove item from the backup's backupItems list and totalItems list because it's skipped by plugin action.")
		ib.backupRequest.BackedUpItems.DeleteItem(key)
		return false, itemFiles, nil
	}

	itemFiles = append(itemFiles, additionalItemFiles...)
	obj = updatedObj
	if metadata, err = meta.Accessor(obj); err != nil {
		return false, itemFiles, errors.WithStack(err)
	}
	// update name and namespace in case they were modified in an action
	name = metadata.GetName()
	namespace = metadata.GetNamespace()

	if groupResource == kuberesource.PersistentVolumes {
		if err := ib.addVolumeInfo(obj, log); err != nil {
			backupErrs = append(backupErrs, err)
		}

		if err := ib.takePVSnapshot(obj, log); err != nil {
			backupErrs = append(backupErrs, err)
		}
	}

	if groupResource == kuberesource.Pods && pod != nil {
		// this function will return partial results, so process podVolumeBackups
		// even if there are errors.
		podVolumeBackups, podVolumePVCBackupSummary, errs := ib.backupPodVolumes(log, pod, pvbVolumes)

		backupErrs = append(backupErrs, errs...)

		// Mark the volumes that has been processed by pod volume backup as Taken in the tracker.
		for _, pvb := range podVolumeBackups {
			ib.podVolumeSnapshotTracker.Take(pod, pvb.Spec.Volume)
		}

		// Track/Untrack the volumes based on podVolumePVCBackupSummary
		if podVolumePVCBackupSummary != nil {
			for _, skippedPVC := range podVolumePVCBackupSummary.Skipped {
				if obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(skippedPVC.PVC); err != nil {
					backupErrs = append(backupErrs, errors.WithStack(err))
				} else {
					ib.trackSkippedPV(&unstructured.Unstructured{Object: obj}, kuberesource.PersistentVolumeClaims,
						podVolumeApproach, skippedPVC.Reason, log)
				}
			}
			for _, pvc := range podVolumePVCBackupSummary.Backedup {
				if obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvc); err != nil {
					backupErrs = append(backupErrs, errors.WithStack(err))
				} else {
					ib.unTrackSkippedPV(&unstructured.Unstructured{Object: obj}, kuberesource.PersistentVolumeClaims, log)
				}
			}
		}
	}

	if len(backupErrs) != 0 {
		return false, itemFiles, kubeerrs.NewAggregate(backupErrs)
	}

	itemBytes, err := json.Marshal(obj.UnstructuredContent())
	if err != nil {
		return false, itemFiles, errors.WithStack(err)
	}

	if versionPath == preferredGVR.Version {
		// backing up preferred version backup without API Group version - for backward compatibility
		log.Debugf("Resource %s/%s, version= %s, preferredVersion=%s", groupResource.String(), name, versionPath, preferredGVR.Version)
		itemFiles = append(itemFiles, getFileForArchive(namespace, name, groupResource.String(), "", itemBytes))
		versionPath = versionPath + velerov1api.PreferredVersionDir
	}

	itemFiles = append(itemFiles, getFileForArchive(namespace, name, groupResource.String(), versionPath, itemBytes))
	return true, itemFiles, nil
}

func getFileForArchive(namespace, name, groupResource, versionPath string, itemBytes []byte) FileForArchive {
	filePath := archive.GetVersionedItemFilePath("", groupResource, namespace, name, versionPath)
	hdr := &tar.Header{
		Name:     filePath,
		Size:     int64(len(itemBytes)),
		Typeflag: tar.TypeReg,
		Mode:     0755,
		ModTime:  time.Now(),
	}
	return FileForArchive{FilePath: filePath, Header: hdr, FileBytes: itemBytes}
}

// backupPodVolumes triggers pod volume backups of the specified pod volumes, and returns a list of PodVolumeBackups
// for volumes that were successfully backed up, and a slice of any errors that were encountered.
func (ib *itemBackupper) backupPodVolumes(log logrus.FieldLogger, pod *corev1api.Pod, volumes []string) ([]*velerov1api.PodVolumeBackup, *podvolume.PVCBackupSummary, []error) {
	if len(volumes) == 0 {
		return nil, nil, nil
	}

	if ib.podVolumeBackupper == nil {
		log.Warn("No pod volume backupper, not backing up pod's volumes")
		return nil, nil, nil
	}

	return ib.podVolumeBackupper.BackupPodVolumes(ib.backupRequest.Backup, pod, volumes, ib.backupRequest.ResPolicies, log)
}

func (ib *itemBackupper) executeActions(
	log logrus.FieldLogger,
	obj runtime.Unstructured,
	groupResource schema.GroupResource,
	name, namespace string,
	metadata metav1.Object,
	finalize bool,
	itemBlock *BackupItemBlock,
) (runtime.Unstructured, []FileForArchive, error) {
	var itemFiles []FileForArchive
	for _, action := range ib.backupRequest.ResolvedActions {
		if !action.ShouldUse(groupResource, namespace, metadata, log) {
			continue
		}
		log.Info("Executing custom action")
		actionName := action.Name()
		if act, err := ib.getMatchAction(obj, groupResource, actionName); err != nil {
			return nil, itemFiles, errors.WithStack(err)
		} else if act != nil && act.Type == resourcepolicies.Skip {
			log.Infof("Skip executing Backup Item Action: %s of resource %s: %s/%s for the matched resource policies", actionName, groupResource, namespace, name)
			ib.trackSkippedPV(obj, groupResource, "", "skipped due to resource policy ", log)
			continue
		}

		// If the EnableCSI feature is not enabled, but the executing action is from CSI plugin, skip the action.
		if csiutil.ShouldSkipAction(actionName) {
			log.Infof("Skip action %s for resource %s:%s/%s, because the CSI feature is not enabled. Feature setting is %s.",
				actionName, groupResource.String(), metadata.GetNamespace(), metadata.GetName(), features.Serialize())
			continue
		}

		if groupResource == kuberesource.PersistentVolumeClaims &&
			actionName == csiBIAPluginName {
			snapshotVolume, err := ib.volumeHelperImpl.ShouldPerformSnapshot(obj, kuberesource.PersistentVolumeClaims)
			if err != nil {
				return nil, itemFiles, errors.WithStack(err)
			}

			if !snapshotVolume {
				ib.trackSkippedPV(
					obj,
					kuberesource.PersistentVolumeClaims,
					volumeSnapshotApproach,
					"not satisfy the criteria for VolumePolicy or the legacy snapshot way",
					log,
				)
				continue
			}
		}

		updatedItem, additionalItemIdentifiers, operationID, postOperationItems, err := action.Execute(obj, ib.backupRequest.Backup)
		if err != nil {
			return nil, itemFiles, errors.Wrapf(err, "error executing custom action (groupResource=%s, namespace=%s, name=%s)", groupResource.String(), namespace, name)
		}

		u := &unstructured.Unstructured{Object: updatedItem.UnstructuredContent()}

		if _, ok := u.GetAnnotations()[velerov1api.SkipFromBackupAnnotation]; ok {
			log.Infof("Resource (groupResource=%s, namespace=%s, name=%s) is skipped from backup by action %s.",
				groupResource.String(), namespace, name, actionName)
			return nil, itemFiles, nil
		}

		if actionName == csiBIAPluginName {
			if additionalItemIdentifiers == nil && u.GetAnnotations()[velerov1api.SkippedNoCSIPVAnnotation] == "true" {
				// snapshot was skipped by CSI plugin
				log.Infof("skip CSI snapshot for PVC %s as it's not a CSI compatible volume", namespace+"/"+name)
				ib.trackSkippedPV(obj, groupResource, csiSnapshotApproach, "skipped b/c it's not a CSI volume", log)
				delete(u.GetAnnotations(), velerov1api.SkippedNoCSIPVAnnotation)
			} else {
				// the snapshot has been taken by the BIA plugin
				log.Infof("Untrack the PVC %s, because it's backed up by CSI BIA.", namespace+"/"+name)
				ib.unTrackSkippedPV(obj, kuberesource.PersistentVolumeClaims, log)
			}
		}

		mustInclude := u.GetAnnotations()[velerov1api.MustIncludeAdditionalItemAnnotation] == "true" || finalize
		// remove the annotation as it's for communication between BIA and velero server,
		// we don't want the resource be restored with this annotation.
		delete(u.GetAnnotations(), velerov1api.MustIncludeAdditionalItemAnnotation)
		obj = u

		// If async plugin started async operation, add it to the ItemOperations list
		// ignore during finalize phase
		if operationID != "" {
			if finalize {
				return nil, itemFiles, fmt.Errorf("backup Item Action created operation during finalize (groupResource=%s, namespace=%s, name=%s)", groupResource.String(), namespace, name)
			}
			resourceIdentifier := velero.ResourceIdentifier{
				GroupResource: groupResource,
				Namespace:     namespace,
				Name:          name,
			}
			now := metav1.Now()
			newOperation := itemoperation.BackupOperation{
				Spec: itemoperation.BackupOperationSpec{
					BackupName:         ib.backupRequest.Backup.Name,
					BackupUID:          string(ib.backupRequest.Backup.UID),
					BackupItemAction:   action.Name(),
					ResourceIdentifier: resourceIdentifier,
					OperationID:        operationID,
				},
				Status: itemoperation.OperationStatus{
					Phase:   itemoperation.OperationPhaseNew,
					Created: &now,
				},
			}
			newOperation.Spec.PostOperationItems = postOperationItems
			itemOperList := ib.backupRequest.GetItemOperationsList()
			*itemOperList = append(*itemOperList, &newOperation)
		}

		for _, additionalItem := range additionalItemIdentifiers {
			var itemList []itemblock.ItemBlockItem

			// get item content from itemBlock if it's there to avoid the additional APIServer call
			// We could have multiple versions to back up if EnableAPIGroupVersions is set
			if itemBlock != nil {
				itemList = itemBlock.FindItem(additionalItem.GroupResource, additionalItem.Namespace, additionalItem.Name)
			}
			// if item is not in itemblock, pull it from the cluster
			if len(itemList) == 0 {
				log.Infof("Additional Item %s %s/%s not found in ItemBlock, getting from cluster", additionalItem.GroupResource, additionalItem.Namespace, additionalItem.Name)

				gvr, resource, err := ib.discoveryHelper.ResourceFor(additionalItem.GroupResource.WithVersion(""))
				if err != nil {
					return nil, itemFiles, err
				}

				client, err := ib.dynamicFactory.ClientForGroupVersionResource(gvr.GroupVersion(), resource, additionalItem.Namespace)
				if err != nil {
					return nil, itemFiles, err
				}

				item, err := client.Get(additionalItem.Name, metav1.GetOptions{})

				if apierrors.IsNotFound(err) {
					log.WithFields(logrus.Fields{
						"groupResource": additionalItem.GroupResource,
						"namespace":     additionalItem.Namespace,
						"name":          additionalItem.Name,
					}).Warnf("Additional item was not found in Kubernetes API, can't back it up")
					continue
				}
				if err != nil {
					return nil, itemFiles, errors.WithStack(err)
				}
				itemList = append(itemList, itemblock.ItemBlockItem{
					Gr:           additionalItem.GroupResource,
					Item:         item,
					PreferredGVR: gvr,
				})
			}

			for _, item := range itemList {
				_, additionalItemFiles, err := ib.backupItem(log, item.Item, additionalItem.GroupResource, item.PreferredGVR, mustInclude, finalize, itemBlock)
				if err != nil {
					return nil, itemFiles, err
				}
				itemFiles = append(itemFiles, additionalItemFiles...)
			}
		}
	}
	return obj, itemFiles, nil
}

// zoneLabelDeprecated is the label that stores availability-zone info
// on PVs this is deprecated on Kubernetes >= 1.17.0
// zoneLabel is the label that stores availability-zone info
// on PVs
const (
	zoneLabelDeprecated = "failure-domain.beta.kubernetes.io/zone"
	// this is reused for nodeAffinity requirements
	zoneLabel = "topology.kubernetes.io/zone"

	awsEbsCsiZoneKey = "topology.ebs.csi.aws.com/zone"
	azureCsiZoneKey  = "topology.disk.csi.azure.com/zone"
	gkeCsiZoneKey    = "topology.gke.io/zone"
	gkeZoneSeparator = "__"

	// OpenStack CSI drivers topology keys
	cinderCsiZoneKey = "topology.manila.csi.openstack.org/zone"
	manilaCsiZoneKey = "topology.cinder.csi.openstack.org/zone"
)

// takePVSnapshot triggers a snapshot for the volume/disk underlying a PersistentVolume if the provided
// backup has volume snapshots enabled and the PV is of a compatible type. Also records cloud
// disk type and IOPS (if applicable) to be able to restore to current state later.
func (ib *itemBackupper) takePVSnapshot(obj runtime.Unstructured, log logrus.FieldLogger) error {
	log.Info("Executing takePVSnapshot")

	pv := new(corev1api.PersistentVolume)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pv); err != nil {
		return errors.WithStack(err)
	}

	log = log.WithField("persistentVolume", pv.Name)

	snapshotVolume, err := ib.volumeHelperImpl.ShouldPerformSnapshot(obj, kuberesource.PersistentVolumes)
	if err != nil {
		return err
	}

	if !snapshotVolume {
		ib.trackSkippedPV(
			obj,
			kuberesource.PersistentVolumes,
			volumeSnapshotApproach,
			"not satisfy the criteria for VolumePolicy or the legacy snapshot way",
			log,
		)
		return nil
	}

	// #4758 Do not take snapshot for CSI PV to avoid duplicated snapshotting, when CSI feature is enabled.
	if features.IsEnabled(velerov1api.CSIFeatureFlag) && pv.Spec.CSI != nil {
		log.Infof("Skipping snapshot of persistent volume %s, because it's handled by CSI plugin.", pv.Name)
		return nil
	}

	// TODO: Snapshot data mover is only supported for CSI plugin scenario by now.
	// Need to add a mechanism to choose running which plugin for resources.
	// After that, this warning can be removed.
	if boolptr.IsSetToTrue(ib.backupRequest.Spec.SnapshotMoveData) {
		log.Warnf("VolumeSnapshotter plugin doesn't support data movement.")

		if features.IsEnabled(velerov1api.CSIFeatureFlag) && pv.Spec.CSI == nil {
			log.Warn("Cannot use CSI data mover to handle PV, because PV doesn't contain CSI in spec.",
				" Fall back to Velero native snapshot.")
		}
	}

	if ib.backupRequest.ResPolicies != nil {
		pvc := new(corev1api.PersistentVolumeClaim)
		if pv.Spec.ClaimRef != nil {
			err = ib.kbClient.Get(context.Background(), kbClient.ObjectKey{
				Namespace: pv.Spec.ClaimRef.Namespace,
				Name:      pv.Spec.ClaimRef.Name},
				pvc)
			if err != nil {
				return err
			}
		}
		vfd := resourcepolicies.NewVolumeFilterData(pv, nil, pvc)
		if action, err := ib.backupRequest.ResPolicies.GetMatchAction(vfd); err != nil {
			log.WithError(err).Errorf("Error getting matched resource policies for pv %s", pv.Name)
			return nil
		} else if action != nil && action.Type == resourcepolicies.Skip {
			log.Infof("skip snapshot of pv %s for the matched resource policies", pv.Name)
			// at this point we are sure this object is PV therefore we'll call the tracker directly
			ib.backupRequest.SkippedPVTracker.Track(pv.Name, volumeSnapshotApproach, "matched action is 'skip' in chosen resource policies")
			return nil
		}
	}

	// TODO: -- once failure-domain.beta.kubernetes.io/zone is no longer
	// supported in any velero-supported version of Kubernetes, remove fallback checking of it
	pvFailureDomainZone, labelFound := pv.Labels[zoneLabel]
	if !labelFound {
		log.Infof("label %q is not present on PersistentVolume, checking deprecated label...", zoneLabel)
		pvFailureDomainZone, labelFound = pv.Labels[zoneLabelDeprecated]
		if !labelFound {
			var k string
			log.Infof("label %q is not present on PersistentVolume", zoneLabelDeprecated)
			k, pvFailureDomainZone = zoneFromPVNodeAffinity(pv, awsEbsCsiZoneKey, azureCsiZoneKey, gkeCsiZoneKey, cinderCsiZoneKey, manilaCsiZoneKey, zoneLabel, zoneLabelDeprecated)
			if pvFailureDomainZone != "" {
				log.Infof("zone info from nodeAffinity requirements: %s, key: %s", pvFailureDomainZone, k)
			} else {
				log.Infof("zone info not available in nodeAffinity requirements")
			}
		}
	}

	var (
		volumeID, location string
		volumeSnapshotter  vsv1.VolumeSnapshotter
	)

	for _, snapshotLocation := range ib.backupRequest.SnapshotLocations {
		log := log.WithField("volumeSnapshotLocation", snapshotLocation.Name)

		bs, err := ib.volumeSnapshotterCache.SetNX(snapshotLocation)
		if err != nil {
			log.WithError(err).Error("Error getting volume snapshotter for volume snapshot location")
			continue
		}

		if volumeID, err = bs.GetVolumeID(obj); err != nil {
			log.WithError(err).Errorf("Error attempting to get volume ID for persistent volume")
			continue
		}
		if volumeID == "" {
			log.Warn("No volume ID returned by volume snapshotter for persistent volume")
			continue
		}

		log.Infof("Got volume ID for persistent volume")
		volumeSnapshotter = bs
		location = snapshotLocation.Name
		break
	}

	if volumeSnapshotter == nil {
		// the PV may still has change to be snapshotted by CSI plugin's `PVCBackupItemAction` in PVC backup logic
		log.Info("Persistent volume is not a supported volume type for Velero-native volumeSnapshotter snapshot, skipping.")
		ib.backupRequest.SkippedPVTracker.Track(pv.Name, volumeSnapshotApproach, "no applicable volumesnapshotter found")
		return nil
	}

	log = log.WithField("volumeID", volumeID)

	// create tags from the backup's labels
	tags := map[string]string{}
	maps.Copy(tags, ib.backupRequest.GetLabels())
	tags["velero.io/backup"] = ib.backupRequest.Name
	tags["velero.io/pv"] = pv.Name

	log.Info("Getting volume information")
	volumeType, iops, err := volumeSnapshotter.GetVolumeInfo(volumeID, pvFailureDomainZone)
	if err != nil {
		return errors.WithMessage(err, "error getting volume info")
	}

	log.Info("Snapshotting persistent volume")
	snapshot := volumeSnapshot(ib.backupRequest.Backup, pv.Name, volumeID, volumeType, pvFailureDomainZone, location, iops)

	var errs []error
	log.Info("Untrack the PV %s from the skipped volumes, because it's backed by Velero native snapshot.", pv.Name)
	ib.backupRequest.SkippedPVTracker.Untrack(pv.Name)
	snapshotID, err := volumeSnapshotter.CreateSnapshot(snapshot.Spec.ProviderVolumeID, snapshot.Spec.VolumeAZ, tags)
	if err != nil {
		errs = append(errs, errors.Wrap(err, "error taking snapshot of volume"))
		snapshot.Status.Phase = volume.SnapshotPhaseFailed
	} else {
		snapshot.Status.Phase = volume.SnapshotPhaseCompleted
		snapshot.Status.ProviderSnapshotID = snapshotID
	}
	ib.backupRequest.VolumeSnapshots.Add(snapshot)

	// nil errors are automatically removed
	return kubeerrs.NewAggregate(errs)
}

func (ib *itemBackupper) getMatchAction(obj runtime.Unstructured, groupResource schema.GroupResource, backupItemActionName string) (*resourcepolicies.Action, error) {
	if ib.backupRequest.ResPolicies != nil && groupResource == kuberesource.PersistentVolumeClaims && (backupItemActionName == csiBIAPluginName || backupItemActionName == vsphereBIAPluginName) {
		pvc := &corev1api.PersistentVolumeClaim{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pvc); err != nil {
			return nil, errors.WithStack(err)
		}

		var pv *corev1api.PersistentVolume
		if pvName := pvc.Spec.VolumeName; pvName != "" {
			pv = &corev1api.PersistentVolume{}
			if err := ib.kbClient.Get(context.Background(), kbClient.ObjectKey{Name: pvName}, pv); err != nil {
				return nil, errors.WithStack(err)
			}
		}
		// If pv is nil for unbound PVCs - policy matching will use PVC-only conditions
		vfd := resourcepolicies.NewVolumeFilterData(pv, nil, pvc)
		return ib.backupRequest.ResPolicies.GetMatchAction(vfd)
	}

	return nil, nil
}

// trackSkippedPV tracks the skipped PV based on the object and the given approach and reason
// this function will be called throughout the process of backup, it needs to handle any object
func (ib *itemBackupper) trackSkippedPV(obj runtime.Unstructured, groupResource schema.GroupResource, approach string, reason string, log logrus.FieldLogger) {
	if name, err := getPVName(obj, groupResource); len(name) > 0 && err == nil {
		ib.backupRequest.SkippedPVTracker.Track(name, approach, reason)
	} else if err != nil {
		// Log at info level for tracking purposes. This is not an error because
		// it's expected for some resources (e.g., PVCs in Pending or Lost phase)
		// to not have a PV name. This occurs when volume policy skips unbound PVCs.
		log.WithError(err).Infof("unable to get PV name, skip tracking.")
	}
}

// unTrackSkippedPV removes skipped PV based on the object from the tracker
// this function will be called throughout the process of backup, it needs to handle any object
func (ib *itemBackupper) unTrackSkippedPV(obj runtime.Unstructured, groupResource schema.GroupResource, log logrus.FieldLogger) {
	if name, err := getPVName(obj, groupResource); len(name) > 0 && err == nil {
		ib.backupRequest.SkippedPVTracker.Untrack(name)
	} else if err != nil {
		// For PVCs in Pending or Lost phase, it's expected that there's no PV name.
		// Log at debug level instead of warning to reduce noise.
		if groupResource == kuberesource.PersistentVolumeClaims {
			pvc := new(corev1api.PersistentVolumeClaim)
			if convErr := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pvc); convErr == nil {
				if pvc.Status.Phase == corev1api.ClaimPending || pvc.Status.Phase == corev1api.ClaimLost {
					log.WithError(err).Debugf("unable to get PV name for %s PVC, skip untracking.", pvc.Status.Phase)
					return
				}
			}
		}
		log.WithError(err).Warnf("unable to get PV name, skip untracking.")
	}
}

func (ib *itemBackupper) addVolumeInfo(obj runtime.Unstructured, log logrus.FieldLogger) error {
	pv := new(corev1api.PersistentVolume)
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pv)
	if err != nil {
		log.WithError(err).Warnf("Fail to convert PV")
		return err
	}

	pvcName := ""
	pvcNamespace := ""
	if pv.Spec.ClaimRef != nil {
		pvcName = pv.Spec.ClaimRef.Name
		pvcNamespace = pv.Spec.ClaimRef.Namespace
	}

	ib.backupRequest.VolumesInformation.InsertPVMap(*pv, pvcName, pvcNamespace)

	return nil
}

// convert the input object to PV/PVC and get the PV name
func getPVName(obj runtime.Unstructured, groupResource schema.GroupResource) (string, error) {
	if groupResource == kuberesource.PersistentVolumes {
		pv := new(corev1api.PersistentVolume)
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pv); err != nil {
			return "", fmt.Errorf("failed to convert object to PV: %w", err)
		}
		return pv.Name, nil
	}
	if groupResource == kuberesource.PersistentVolumeClaims {
		pvc := new(corev1api.PersistentVolumeClaim)
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), pvc); err != nil {
			return "", fmt.Errorf("failed to convert object to PVC: %w", err)
		}
		if pvc.Spec.VolumeName == "" {
			return "", fmt.Errorf("PV name is not set in PVC")
		}
		return pvc.Spec.VolumeName, nil
	}
	return "", nil
}

func volumeSnapshot(backup *velerov1api.Backup, volumeName, volumeID, volumeType, az, location string, iops *int64) *volume.Snapshot {
	return &volume.Snapshot{
		Spec: volume.SnapshotSpec{
			BackupName:           backup.Name,
			BackupUID:            string(backup.UID),
			Location:             location,
			PersistentVolumeName: volumeName,
			ProviderVolumeID:     volumeID,
			VolumeType:           volumeType,
			VolumeAZ:             az,
			VolumeIOPS:           iops,
		},
		Status: volume.SnapshotStatus{
			Phase: volume.SnapshotPhaseNew,
		},
	}
}

// resourceKey returns a string representing the object's GroupVersionKind (e.g.
// apps/v1/Deployment).
func resourceKey(obj runtime.Unstructured) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return fmt.Sprintf("%s/%s", gvk.GroupVersion().String(), gvk.Kind)
}

// resourceVersion returns a string representing the object's API Version (e.g.
// v1 if item belongs to apps/v1
func resourceVersion(obj runtime.Unstructured) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return gvk.Version
}

// zoneFromPVNodeAffinity iterates the node affinity requirement of a PV to
// get its availability zone, it returns the key merely for logging.
func zoneFromPVNodeAffinity(res *corev1api.PersistentVolume, topologyKeys ...string) (string, string) {
	nodeAffinity := res.Spec.NodeAffinity
	if nodeAffinity == nil {
		return "", ""
	}
	keySet := sets.NewString(topologyKeys...)
	providerGke := false
	zones := make([]string, 0)
	for _, term := range nodeAffinity.Required.NodeSelectorTerms {
		if term.MatchExpressions == nil {
			continue
		}
		for _, exp := range term.MatchExpressions {
			if keySet.Has(exp.Key) && exp.Operator == "In" && len(exp.Values) > 0 {
				if exp.Key == gkeCsiZoneKey {
					providerGke = true
					zones = append(zones, exp.Values[0])
				} else {
					return exp.Key, exp.Values[0]
				}
			}
		}
	}

	if providerGke {
		return gkeCsiZoneKey, strings.Join(zones, gkeZoneSeparator)
	}

	return "", ""
}
