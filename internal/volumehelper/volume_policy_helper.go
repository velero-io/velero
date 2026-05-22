package volumehelper

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	podvolumeutil "github.com/vmware-tanzu/velero/pkg/util/podvolume"
	vhutil "github.com/vmware-tanzu/velero/pkg/util/volumehelper"
)

type volumeHelperImpl struct {
	volumePolicy             *resourcepolicies.Policies
	snapshotVolumes          *bool
	logger                   logrus.FieldLogger
	client                   crclient.Client
	defaultVolumesToFSBackup bool
	// This parameter is used to align the fs-backup with snapshot action,
	// because PVC is already filtered by the resource filter before getting
	// to the volume policy check, but fs-backup is based on the pod resource,
	// the resource filter on PVC and PV doesn't work on this scenario.
	backupExcludePVC bool
	// pvcPodCache provides cached PVC to Pod mappings for improved performance.
	// When there are many PVCs and pods, using this cache avoids O(N*M) lookups.
	pvcPodCache *podvolumeutil.PVCPodCache
}

// NewVolumeHelperImpl creates a VolumeHelper without PVC-to-Pod caching.
//
// Deprecated: Use NewVolumeHelperImplWithNamespaces or NewVolumeHelperImplWithCache instead
// for better performance. These functions provide PVC-to-Pod caching which avoids O(N*M)
// complexity when there are many PVCs and pods. See issue #9179 for details.
func NewVolumeHelperImpl(
	volumePolicy *resourcepolicies.Policies,
	snapshotVolumes *bool,
	logger logrus.FieldLogger,
	client crclient.Client,
	defaultVolumesToFSBackup bool,
	backupExcludePVC bool,
) vhutil.VolumeHelper {
	// Pass nil namespaces - no cache will be built, so this never fails.
	// This is used by plugins that don't need the cache optimization.
	vh, _ := NewVolumeHelperImplWithNamespaces(
		volumePolicy,
		snapshotVolumes,
		logger,
		client,
		defaultVolumesToFSBackup,
		backupExcludePVC,
		nil,
	)
	return vh
}

// NewVolumeHelperImplWithNamespaces creates a VolumeHelper with a PVC-to-Pod cache for improved performance.
// The cache is built internally from the provided namespaces list.
// This avoids O(N*M) complexity when there are many PVCs and pods.
// See issue #9179 for details.
// Returns an error if cache building fails - callers should not proceed with backup in this case.
func NewVolumeHelperImplWithNamespaces(
	volumePolicy *resourcepolicies.Policies,
	snapshotVolumes *bool,
	logger logrus.FieldLogger,
	client crclient.Client,
	defaultVolumesToFSBackup bool,
	backupExcludePVC bool,
	namespaces []string,
) (vhutil.VolumeHelper, error) {
	var pvcPodCache *podvolumeutil.PVCPodCache
	if len(namespaces) > 0 {
		pvcPodCache = podvolumeutil.NewPVCPodCache()
		if err := pvcPodCache.BuildCacheForNamespaces(context.Background(), namespaces, client); err != nil {
			return nil, err
		}
		logger.Infof("Built PVC-to-Pod cache for %d namespaces", len(namespaces))
	}

	return &volumeHelperImpl{
		volumePolicy:             volumePolicy,
		snapshotVolumes:          snapshotVolumes,
		logger:                   logger,
		client:                   client,
		defaultVolumesToFSBackup: defaultVolumesToFSBackup,
		backupExcludePVC:         backupExcludePVC,
		pvcPodCache:              pvcPodCache,
	}, nil
}

// NewVolumeHelperImplWithCache creates a VolumeHelper using an externally managed PVC-to-Pod cache.
// This is used by plugins that build the cache lazily per-namespace (following the pattern from PR #9226).
// The cache can be nil, in which case PVC-to-Pod lookups will fall back to direct API calls.
func NewVolumeHelperImplWithCache(
	backup velerov1api.Backup,
	client crclient.Client,
	logger logrus.FieldLogger,
	pvcPodCache *podvolumeutil.PVCPodCache,
) (vhutil.VolumeHelper, error) {
	resourcePolicies, err := resourcepolicies.GetResourcePoliciesFromBackup(backup, client, logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get volume policies from backup")
	}

	return &volumeHelperImpl{
		volumePolicy:             resourcePolicies,
		snapshotVolumes:          backup.Spec.SnapshotVolumes,
		logger:                   logger,
		client:                   client,
		defaultVolumesToFSBackup: boolptr.IsSetToTrue(backup.Spec.DefaultVolumesToFsBackup),
		backupExcludePVC:         boolptr.IsSetToTrue(backup.Spec.SnapshotMoveData),
		pvcPodCache:              pvcPodCache,
	}, nil
}

func (v *volumeHelperImpl) ShouldPerformSnapshot(obj runtime.Unstructured, groupResource schema.GroupResource) (bool, error) {
	// check if volume policy exists and also check if the object(pv/pvc) fits a volume policy criteria and see if the associated action is snapshot
	// if it is not snapshot then skip the code path for snapshotting the PV/PVC
	pvc := new(corev1api.PersistentVolumeClaim)
	pv := new(corev1api.PersistentVolume)
	var err error

	var pvNotFoundErr error
	if groupResource == kuberesource.PersistentVolumeClaims {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pvc); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PVC")
			return false, err
		}

		pv, err = kubeutil.GetPVForPVC(pvc, v.client)
		if err != nil {
			// Any error means PV not available - save to return later if no policy matches
			v.logger.Debugf("PV not found for PVC %s: %v", pvc.Namespace+"/"+pvc.Name, err)
			pvNotFoundErr = err
			pv = nil
		}
	}

	if groupResource == kuberesource.PersistentVolumes {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pv); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PV")
			return false, err
		}
	}

	if v.volumePolicy != nil {
		vfd := resourcepolicies.NewVolumeFilterData(pv, nil, pvc)
		action, err := v.volumePolicy.GetMatchAction(vfd)
		if err != nil {
			v.logger.WithError(err).Errorf("fail to get VolumePolicy match action for %+v", vfd)
			return false, err
		}

		// If there is a match action, and the action type is snapshot, return true,
		// or the action type is not snapshot, then return false.
		// If there is no match action, go on to the next check.
		if action != nil {
			if action.Type == resourcepolicies.Snapshot {
				v.logger.Infof("performing snapshot action for %+v", vfd)
				return true, nil
			} else {
				v.logger.Infof("Skip snapshot action for %+v as the action type is %s", vfd, action.Type)
				return false, nil
			}
		}
	}

	// If resource is PVC, and PV is nil (e.g., Pending/Lost PVC with no matching policy), return the original error
	if groupResource == kuberesource.PersistentVolumeClaims && pv == nil && pvNotFoundErr != nil {
		v.logger.WithError(pvNotFoundErr).Errorf("fail to get PV for PVC %s", pvc.Namespace+"/"+pvc.Name)
		return false, pvNotFoundErr
	}

	// If this PV is claimed, see if we've already taken a (pod volume backup)
	// snapshot of the contents of this PV. If so, don't take a snapshot.
	if pv.Spec.ClaimRef != nil {
		// Use cached lookup if available for better performance with many PVCs/pods
		pods, err := podvolumeutil.GetPodsUsingPVCWithCache(
			pv.Spec.ClaimRef.Namespace,
			pv.Spec.ClaimRef.Name,
			v.client,
			v.pvcPodCache,
		)
		if err != nil {
			v.logger.WithError(err).Errorf("fail to get pod for PV %s", pv.Name)
			return false, err
		}

		for _, pod := range pods {
			for _, vol := range pod.Spec.Volumes {
				if vol.PersistentVolumeClaim != nil &&
					vol.PersistentVolumeClaim.ClaimName == pv.Spec.ClaimRef.Name &&
					v.shouldPerformFSBackupLegacy(vol, pod) {
					v.logger.Infof("Skipping snapshot of pv %s because it is backed up with PodVolumeBackup.", pv.Name)
					return false, nil
				}
			}
		}
	}

	if !boolptr.IsSetToFalse(v.snapshotVolumes) {
		// If the backup.Spec.SnapshotVolumes is not set, or set to true, then should take the snapshot.
		v.logger.Infof("performing snapshot action for pv %s as the snapshotVolumes is not set to false", pv.Name)
		return true, nil
	}

	v.logger.Infof("skipping snapshot action for pv %s possibly due to no volume policy setting or snapshotVolumes is false", pv.Name)
	return false, nil
}

func (v volumeHelperImpl) ShouldPerformFSBackup(volume corev1api.Volume, pod corev1api.Pod) (bool, error) {
	if !v.shouldIncludeVolumeInBackup(volume) {
		v.logger.Debugf("skip fs-backup action for pod %s's volume %s, due to not pass volume check.", pod.Namespace+"/"+pod.Name, volume.Name)
		return false, nil
	}

	var pvNotFoundErr error
	if v.volumePolicy != nil {
		var resource any
		var err error
		resource = &volume
		var pvc = &corev1api.PersistentVolumeClaim{}
		if volume.VolumeSource.PersistentVolumeClaim != nil {
			pvc, err = kubeutil.GetPVCForPodVolume(&volume, &pod, v.client)
			if err != nil {
				v.logger.WithError(err).Errorf("fail to get PVC for pod %s", pod.Namespace+"/"+pod.Name)
				return false, err
			}
			pvResource, err := kubeutil.GetPVForPVC(pvc, v.client)
			if err != nil {
				// Any error means PV not available - save to return later if no policy matches
				v.logger.Debugf("PV not found for PVC %s: %v", pvc.Namespace+"/"+pvc.Name, err)
				pvNotFoundErr = err
			} else {
				resource = pvResource
			}
		}

		pv, podVolume, err := v.getVolumeFromResource(resource)
		if err != nil {
			return false, err
		}

		vfd := resourcepolicies.NewVolumeFilterData(pv, podVolume, pvc)
		action, err := v.volumePolicy.GetMatchAction(vfd)
		if err != nil {
			v.logger.WithError(err).Error("fail to get VolumePolicy match action for volume")
			return false, err
		}

		if action != nil {
			if action.Type == resourcepolicies.FSBackup {
				v.logger.Infof("Perform fs-backup action for volume %s of pod %s due to volume policy match",
					volume.Name, pod.Namespace+"/"+pod.Name)
				return true, nil
			} else {
				v.logger.Infof("Skip fs-backup action for volume %s for pod %s because the action type is %s",
					volume.Name, pod.Namespace+"/"+pod.Name, action.Type)
				return false, nil
			}
		}

		// If no policy matched and PV was not found, return the original error
		if pvNotFoundErr != nil {
			v.logger.WithError(pvNotFoundErr).Errorf("fail to get PV for PVC %s", pvc.Namespace+"/"+pvc.Name)
			return false, pvNotFoundErr
		}
	}

	if v.shouldPerformFSBackupLegacy(volume, pod) {
		v.logger.Infof("Perform fs-backup action for volume %s of pod %s due to opt-in/out way",
			volume.Name, pod.Namespace+"/"+pod.Name)
		return true, nil
	} else {
		v.logger.Infof("Skip fs-backup action for volume %s of pod %s due to opt-in/out way",
			volume.Name, pod.Namespace+"/"+pod.Name)
		return false, nil
	}
}

func (v volumeHelperImpl) shouldPerformFSBackupLegacy(
	volume corev1api.Volume,
	pod corev1api.Pod,
) bool {
	// Check volume in opt-in way
	if !v.defaultVolumesToFSBackup {
		optInVolumeNames := podvolumeutil.GetVolumesToBackup(&pod)
		return slices.Contains(optInVolumeNames, volume.Name)
	} else {
		// Check volume in opt-out way
		optOutVolumeNames := podvolumeutil.GetVolumesToExclude(&pod)
		return !slices.Contains(optOutVolumeNames, volume.Name)
	}
}

func (v *volumeHelperImpl) ShouldPerformCustomAction(obj runtime.Unstructured, groupResource schema.GroupResource, matchParams map[string]any) (bool, error) {
	// check if volume policy exists and also check if the object(pv/pvc) fits a volume policy criteria and see if the associated action is custom with the provided param values
	pvc := new(corev1api.PersistentVolumeClaim)
	pv := new(corev1api.PersistentVolume)
	var err error

	var pvNotFoundErr error
	if groupResource == kuberesource.PersistentVolumeClaims {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pvc); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PVC")
			return false, err
		}

		pv, err = kubeutil.GetPVForPVC(pvc, v.client)
		if err != nil {
			// Any error means PV not available - save to return later if no policy matches
			v.logger.Debugf("PV not found for PVC %s: %v", pvc.Namespace+"/"+pvc.Name, err)
			pvNotFoundErr = err
			pv = nil
		}
	}

	if groupResource == kuberesource.PersistentVolumes {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pv); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PV")
			return false, err
		}
	}

	if v.volumePolicy != nil {
		vfd := resourcepolicies.NewVolumeFilterData(pv, nil, pvc)
		action, err := v.volumePolicy.GetMatchAction(vfd)
		if err != nil {
			v.logger.WithError(err).Errorf("fail to get VolumePolicy match action for %+v", vfd)
			return false, err
		}

		// If there is a match action, and the action type is custom, return true
		// if the provided parameters match as well, else return false.
		// If there is no match action, also return false
		if action != nil {
			if action.Type == resourcepolicies.Custom {
				for k, requiredValue := range matchParams {
					if actionValue, ok := action.Parameters[k]; !ok || actionValue != requiredValue {
						v.logger.Infof("Skipping custom action for %+v as value for parameter %s is %s rather than the required %s", vfd, k, actionValue, requiredValue)
						return false, nil
					}
				}
				v.logger.Infof("performing custom action for %+v", vfd)
				return true, nil
			} else {
				v.logger.Infof("Skipping custom action for %+v as the action type is %s", vfd, action.Type)
				return false, nil
			}
		}
	}
	// If resource is PVC, and PV is nil (e.g., Pending/Lost PVC with no matching policy), return the original error
	// Don't error out on no PV, just return false
	if groupResource == kuberesource.PersistentVolumeClaims && pv == nil && pvNotFoundErr != nil {
		v.logger.WithError(pvNotFoundErr).Warnf("fail to get PV for PVC %s", pvc.Namespace+"/"+pvc.Name)
		return false, nil
	}

	v.logger.Infof("skipping custom action for pv %s due to no matching volume policy", pv.Name)
	return false, nil
}

// returns false if no matching action found. Returns true with the action name and Parameters map if there is a matching policy
func (v *volumeHelperImpl) GetActionParameters(obj runtime.Unstructured, groupResource schema.GroupResource) (bool, string, map[string]any, error) {
	// if volume policy exists, return action parameters.
	pvc := new(corev1api.PersistentVolumeClaim)
	pv := new(corev1api.PersistentVolume)
	var err error

	if groupResource == kuberesource.PersistentVolumeClaims {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pvc); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PVC")
			return false, "", nil, err
		}

		pv, err = kubeutil.GetPVForPVC(pvc, v.client)
		if err != nil {
			v.logger.WithError(err).Warnf("failed to get PV for PVC %s", pvc.Namespace+"/"+pvc.Name)
			return false, "", nil, nil
		}
	}

	if groupResource == kuberesource.PersistentVolumes {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pv); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PV")
			return false, "", nil, err
		}
	}

	if v.volumePolicy != nil {
		vfd := resourcepolicies.NewVolumeFilterData(pv, nil, pvc)
		action, err := v.volumePolicy.GetMatchAction(vfd)
		if err != nil {
			v.logger.WithError(err).Errorf("fail to get VolumePolicy match action for PV %s", pv.Name)
			return false, "", nil, err
		}

		// If there is a match action, and the action type is custom, return true
		// if the provided parameters match as well, else return false.
		// If there is no match action, also return false
		if action != nil {
			v.logger.Infof("found matching action for pv %s, returning parameters", pv.Name)
			return true, string(action.Type), action.Parameters, nil
		}
	}

	v.logger.Infof("no matching volume policy found for pv %s, no parameters to return", pv.Name)
	return false, "", nil, nil
}

func (v *volumeHelperImpl) shouldIncludeVolumeInBackup(vol corev1api.Volume) bool {
	includeVolumeInBackup := true
	// cannot backup hostpath volumes as they are not mounted into /var/lib/kubelet/pods
	// and therefore not accessible to the node agent daemon set.
	if vol.HostPath != nil {
		includeVolumeInBackup = false
	}
	// don't backup volumes mounting secrets. Secrets will be backed up separately.
	if vol.Secret != nil {
		includeVolumeInBackup = false
	}
	// don't backup volumes mounting ConfigMaps. ConfigMaps will be backed up separately.
	if vol.ConfigMap != nil {
		includeVolumeInBackup = false
	}
	// don't backup volumes mounted as projected volumes, all data in those come from kube state.
	if vol.Projected != nil {
		includeVolumeInBackup = false
	}
	// don't backup DownwardAPI volumes, all data in those come from kube state.
	if vol.DownwardAPI != nil {
		includeVolumeInBackup = false
	}
	if vol.PersistentVolumeClaim != nil && v.backupExcludePVC {
		includeVolumeInBackup = false
	}
	// don't include volumes that mount the default service account token.
	if strings.HasPrefix(vol.Name, "default-token") {
		includeVolumeInBackup = false
	}
	return includeVolumeInBackup
}

func (v *volumeHelperImpl) getVolumeFromResource(resource any) (*corev1api.PersistentVolume, *corev1api.Volume, error) {
	if pv, ok := resource.(*corev1api.PersistentVolume); ok {
		return pv, nil, nil
	} else if podVol, ok := resource.(*corev1api.Volume); ok {
		return nil, podVol, nil
	}
	return nil, nil, fmt.Errorf("resource is not a PersistentVolume or Volume")
}
