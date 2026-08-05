package volumehelper

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	podvolumeutil "github.com/vmware-tanzu/velero/pkg/util/podvolume"
)

type VolumeHelper interface {
	ShouldPerformSnapshot(obj runtime.Unstructured, groupResource schema.GroupResource) (bool, error)
	ShouldPerformFSBackup(volume corev1api.Volume, pod corev1api.Pod) (bool, error)
}

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
}

func NewVolumeHelperImpl(
	volumePolicy *resourcepolicies.Policies,
	snapshotVolumes *bool,
	logger logrus.FieldLogger,
	client crclient.Client,
	defaultVolumesToFSBackup bool,
	backupExcludePVC bool,
) VolumeHelper {
	return &volumeHelperImpl{
		volumePolicy:             volumePolicy,
		snapshotVolumes:          snapshotVolumes,
		logger:                   logger,
		client:                   client,
		defaultVolumesToFSBackup: defaultVolumesToFSBackup,
		backupExcludePVC:         backupExcludePVC,
	}
}

func (v *volumeHelperImpl) ShouldPerformSnapshot(obj runtime.Unstructured, groupResource schema.GroupResource) (bool, error) {
	// check if volume policy exists and also check if the object(pv/pvc) fits a volume policy criteria and see if the associated action is snapshot
	// if it is not snapshot then skip the code path for snapshotting the PV/PVC
	pvc := new(corev1api.PersistentVolumeClaim)
	pv := new(corev1api.PersistentVolume)
	var err error

	if groupResource == kuberesource.PersistentVolumeClaims {
		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.UnstructuredContent(), &pvc); err != nil {
			v.logger.WithError(err).Error("fail to convert unstructured into PVC")
			return false, err
		}

		pv, err = kubeutil.GetPVForPVC(pvc, v.client)
		if err != nil {
			if v.defaultVolumesToFSBackup {
				v.logger.Infof("PV not found for PVC %s, skipping snapshot",
					pvc.Namespace+"/"+pvc.Name)
				return false, nil
			}
			v.logger.WithError(err).Errorf("fail to get PV for PVC %s", pvc.Namespace+"/"+pvc.Name)
			return false, err
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
			v.logger.WithError(err).Errorf("fail to get VolumePolicy match action for PV %s", pv.Name)
			return false, err
		}

		// If there is a match action, and the action type is snapshot, return true,
		// or the action type is not snapshot, then return false.
		// If there is no match action, go on to the next check.
		if action != nil {
			if action.Type == resourcepolicies.Snapshot {
				v.logger.Infof(fmt.Sprintf("performing snapshot action for pv %s", pv.Name))
				return true, nil
			} else {
				v.logger.Infof("Skip snapshot action for pv %s as the action type is %s", pv.Name, action.Type)
				return false, nil
			}
		}
	}

	// If this PV is claimed, see if we've already taken a (pod volume backup)
	// snapshot of the contents of this PV. If so, don't take a snapshot.
	if pv.Spec.ClaimRef != nil {
		pods, err := podvolumeutil.GetPodsUsingPVC(
			pv.Spec.ClaimRef.Namespace,
			pv.Spec.ClaimRef.Name,
			v.client,
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

	v.logger.Infof(fmt.Sprintf("skipping snapshot action for pv %s possibly due to no volume policy setting or snapshotVolumes is false", pv.Name))
	return false, nil
}

func (v volumeHelperImpl) ShouldPerformFSBackup(volume corev1api.Volume, pod corev1api.Pod) (bool, error) {
	if !v.shouldIncludeVolumeInBackup(volume) {
		v.logger.Debugf("skip fs-backup action for pod %s's volume %s, due to not pass volume check.", pod.Namespace+"/"+pod.Name, volume.Name)
		return false, nil
	}

	if v.volumePolicy != nil {
		var resource any
		var err error
		resource = &volume
		var pvc = &corev1api.PersistentVolumeClaim{}
		pvFound := true
		if volume.VolumeSource.PersistentVolumeClaim != nil {
			pvc, err = kubeutil.GetPVCForPodVolume(&volume, &pod, v.client)
			if err != nil {
				v.logger.WithError(err).Errorf("fail to get PVC for pod %s", pod.Namespace+"/"+pod.Name)
				return false, err
			}
			resource, err = kubeutil.GetPVForPVC(pvc, v.client)
			if err != nil {
				if v.defaultVolumesToFSBackup {
					v.logger.Infof("PV not found for PVC %s, skipping volume policy check",
						pvc.Namespace+"/"+pvc.Name)
					pvFound = false
				} else {
					v.logger.WithError(err).Errorf("fail to get PV for PVC %s", pvc.Namespace+"/"+pvc.Name)
					return false, err
				}
			}
		}

		if pvFound {
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
		for _, volumeName := range optInVolumeNames {
			if volume.Name == volumeName {
				return true
			}
		}

		return false
	} else {
		// Check volume in opt-out way
		optOutVolumeNames := podvolumeutil.GetVolumesToExclude(&pod)
		for _, volumeName := range optOutVolumeNames {
			if volume.Name == volumeName {
				return false
			}
		}

		return true
	}
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
