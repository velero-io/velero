/*
Copyright 2018 the Velero contributors.

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

package podvolume

import (
	"context"
	"fmt"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	veleroclient "github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/nodeagent"
	"github.com/vmware-tanzu/velero/pkg/podvolume/configs"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	uploaderutil "github.com/vmware-tanzu/velero/pkg/uploader/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	indexNamePod  = "POD"
	pvbKeyPattern = "%s+%s+%s"
)

// Backupper can execute pod volume backups of volumes in a pod.
type Backupper interface {
	// BackupPodVolumes backs up all specified volumes in a pod.
	BackupPodVolumes(backup *velerov1api.Backup, pod *corev1api.Pod, volumesToBackup []string, resPolicies *resourcepolicies.Policies, log logrus.FieldLogger) ([]*velerov1api.PodVolumeBackup, *PVCBackupSummary, []error)
	WaitAllPodVolumesProcessed(log logrus.FieldLogger) []*velerov1api.PodVolumeBackup
	GetPodVolumeBackupByPodAndVolume(podNamespace, podName, volume string) (*velerov1api.PodVolumeBackup, error)
	ListPodVolumeBackupsByPod(podNamespace, podName string) ([]*velerov1api.PodVolumeBackup, error)
}

type backupper struct {
	ctx                 context.Context
	repoLocker          *repository.RepoLocker
	repoEnsurer         *repository.Ensurer
	crClient            ctrlclient.Client
	uploaderType        string
	pvbInformer         ctrlcache.Informer
	handlerRegistration cache.ResourceEventHandlerRegistration
	wg                  sync.WaitGroup
	// pvbIndexer holds all PVBs created by this backuper and is capable to search
	// the PVBs based on specific properties quickly because of the embedded indexes.
	// The statuses of the PVBs are got updated when Informer receives update events.
	pvbIndexer cache.Indexer
}

type skippedPVC struct {
	PVC    *corev1api.PersistentVolumeClaim
	Reason string
}

// PVCBackupSummary is a summary for which PVCs are skipped, which are backed up after each execution of the Backupper
// The scope should be within one pod, so the volume name is the key for the maps
type PVCBackupSummary struct {
	Backedup map[string]*corev1api.PersistentVolumeClaim
	Skipped  map[string]*skippedPVC
	pvcMap   map[string]*corev1api.PersistentVolumeClaim
}

func NewPVCBackupSummary() *PVCBackupSummary {
	return &PVCBackupSummary{
		Backedup: make(map[string]*corev1api.PersistentVolumeClaim),
		Skipped:  make(map[string]*skippedPVC),
		pvcMap:   make(map[string]*corev1api.PersistentVolumeClaim),
	}
}

func (pbs *PVCBackupSummary) addBackedup(volumeName string) {
	if pvc, ok := pbs.pvcMap[volumeName]; ok {
		pbs.Backedup[volumeName] = pvc
		delete(pbs.Skipped, volumeName)
	}
}

func (pbs *PVCBackupSummary) addSkipped(volumeName string, reason string) {
	if pvc, ok := pbs.pvcMap[volumeName]; ok {
		if _, ok2 := pbs.Backedup[volumeName]; !ok2 { // if it's not backed up, add it to skipped
			pbs.Skipped[volumeName] = &skippedPVC{
				PVC:    pvc,
				Reason: reason,
			}
		}
	}
}

func podIndexFunc(obj any) ([]string, error) {
	pvb, ok := obj.(*velerov1api.PodVolumeBackup)
	if !ok {
		return nil, errors.Errorf("expected PodVolumeBackup, but got %T", obj)
	}
	if pvb == nil {
		return nil, errors.New("PodVolumeBackup is nil")
	}
	return []string{cache.NewObjectName(pvb.Spec.Pod.Namespace, pvb.Spec.Pod.Name).String()}, nil
}

// the PVB's name is auto-generated when creating the PVB, we cannot get the name or uid before creating it.
// So we cannot use namespace&name or uid as the key because we need to insert PVB into the indexer before creating it in API server
func podVolumeBackupKey(obj any) (string, error) {
	pvb, ok := obj.(*velerov1api.PodVolumeBackup)
	if !ok {
		return "", fmt.Errorf("expected PodVolumeBackup, but got %T", obj)
	}
	return fmt.Sprintf(pvbKeyPattern, pvb.Spec.Pod.Namespace, pvb.Spec.Pod.Name, pvb.Spec.Volume), nil
}

func newBackupper(
	ctx context.Context,
	log logrus.FieldLogger,
	repoLocker *repository.RepoLocker,
	repoEnsurer *repository.Ensurer,
	pvbInformer ctrlcache.Informer,
	crClient ctrlclient.Client,
	uploaderType string,
	backup *velerov1api.Backup,
) *backupper {
	b := &backupper{
		ctx:          ctx,
		repoLocker:   repoLocker,
		repoEnsurer:  repoEnsurer,
		crClient:     crClient,
		uploaderType: uploaderType,
		pvbInformer:  pvbInformer,
		wg:           sync.WaitGroup{},
		pvbIndexer: cache.NewIndexer(podVolumeBackupKey, cache.Indexers{
			indexNamePod: podIndexFunc,
		}),
	}

	b.handlerRegistration, _ = pvbInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(_, obj any) {
				pvb, ok := obj.(*velerov1api.PodVolumeBackup)
				if !ok {
					log.Errorf("expected PodVolumeBackup, but got %T", obj)
					return
				}

				if pvb.GetLabels()[velerov1api.BackupUIDLabel] != string(backup.UID) {
					return
				}

				if pvb.Status.Phase != velerov1api.PodVolumeBackupPhaseCompleted &&
					pvb.Status.Phase != velerov1api.PodVolumeBackupPhaseFailed &&
					pvb.Status.Phase != velerov1api.PodVolumeBackupPhaseCanceled {
					return
				}

				statusChangedToFinal := true
				existObj, exist, err := b.pvbIndexer.Get(pvb)
				if err == nil && exist {
					existPVB, ok := existObj.(*velerov1api.PodVolumeBackup)
					// the PVB in the indexer is already in final status, no need to call WaitGroup.Done()
					if ok && (existPVB.Status.Phase == velerov1api.PodVolumeBackupPhaseCompleted ||
						existPVB.Status.Phase == velerov1api.PodVolumeBackupPhaseFailed ||
						pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseCanceled) {
						statusChangedToFinal = false
					}
				}

				// the Indexer inserts PVB directly if the PVB to be updated doesn't exist
				if err := b.pvbIndexer.Update(pvb); err != nil {
					log.WithError(err).Errorf("failed to update PVB %s/%s in indexer", pvb.Namespace, pvb.Name)
				}

				// call WaitGroup.Done() once only when the PVB changes to final status the first time.
				// This avoid the cases that the handler gets multiple update events whose PVBs are all in final status
				// which causes panic with "negative WaitGroup counter" error
				if statusChangedToFinal {
					b.wg.Done()
				}
			},
		},
	)

	return b
}

func resultsKey(ns, name string) string {
	return fmt.Sprintf("%s/%s", ns, name)
}

func (b *backupper) getMatchAction(resPolicies *resourcepolicies.Policies, pvc *corev1api.PersistentVolumeClaim, volume *corev1api.Volume) (*resourcepolicies.Action, error) {
	if pvc != nil {
		// Ignore err, if the PV is not available (Pending/Lost PVC or PV fetch failed) - try matching with PVC only
		// GetPVForPVC returns nil for all error cases
		pv, _ := kube.GetPVForPVC(pvc, b.crClient)
		vfd := resourcepolicies.NewVolumeFilterData(pv, nil, pvc)
		return resPolicies.GetMatchAction(vfd)
	}

	if volume != nil {
		vfd := resourcepolicies.NewVolumeFilterData(nil, volume, pvc)
		return resPolicies.GetMatchAction(vfd)
	}

	return nil, errors.Errorf("failed to check resource policies for empty volume")
}

var funcGetRepositoryType = getRepositoryType

func (b *backupper) BackupPodVolumes(backup *velerov1api.Backup, pod *corev1api.Pod, volumesToBackup []string, resPolicies *resourcepolicies.Policies, log logrus.FieldLogger) ([]*velerov1api.PodVolumeBackup, *PVCBackupSummary, []error) {
	if len(volumesToBackup) == 0 {
		return nil, nil, nil
	}

	log.Infof("pod %s/%s has volumes to backup: %v", pod.Namespace, pod.Name, volumesToBackup)

	var (
		pvcSummary = NewPVCBackupSummary()
		podVolumes = make(map[string]corev1api.Volume)
		errs       = []error{}
	)

	// put the pod's volumes and the PVC associated in maps for efficient lookup below
	for _, podVolume := range pod.Spec.Volumes {
		podVolumes[podVolume.Name] = podVolume
		if podVolume.PersistentVolumeClaim != nil {
			pvc := new(corev1api.PersistentVolumeClaim)
			err := b.crClient.Get(context.TODO(), ctrlclient.ObjectKey{Namespace: pod.Namespace, Name: podVolume.PersistentVolumeClaim.ClaimName}, pvc)
			if err != nil {
				errs = append(errs, errors.Wrap(err, "error getting persistent volume claim for volume"))
				continue
			}
			pvcSummary.pvcMap[podVolume.Name] = pvc
		}
	}

	if msg, err := uploader.ValidateUploaderType(b.uploaderType); err != nil {
		skipAllPodVolumes(pod, volumesToBackup, err, pvcSummary, log)
		return nil, pvcSummary, []error{err}
	} else if msg != "" {
		log.Warn(msg)
	}

	if err := kube.IsPodRunning(pod); err != nil {
		skipAllPodVolumes(pod, volumesToBackup, err, pvcSummary, log)
		return nil, pvcSummary, nil
	}

	err := nodeagent.IsRunningInNode(b.ctx, backup.Namespace, pod.Spec.NodeName, b.crClient)
	if err != nil {
		skipAllPodVolumes(pod, volumesToBackup, err, pvcSummary, log)
		return nil, pvcSummary, []error{err}
	}

	repositoryType := funcGetRepositoryType(b.uploaderType)
	if repositoryType == "" {
		err := errors.Errorf("empty repository type, uploader %s", b.uploaderType)
		skipAllPodVolumes(pod, volumesToBackup, err, pvcSummary, log)
		return nil, pvcSummary, []error{err}
	}

	repo, err := b.repoEnsurer.EnsureRepo(b.ctx, backup.Namespace, pod.Namespace, backup.Spec.StorageLocation, repositoryType)
	if err != nil {
		skipAllPodVolumes(pod, volumesToBackup, err, pvcSummary, log)
		return nil, pvcSummary, []error{err}
	}

	// get a single non-exclusive lock since we'll wait for all individual
	// backups to be complete before releasing it.
	b.repoLocker.Lock(repo.Name)
	defer b.repoLocker.Unlock(repo.Name)

	var (
		podVolumeBackups   []*velerov1api.PodVolumeBackup
		mountedPodVolumes  = sets.Set[string]{}
		attachedPodDevices = sets.Set[string]{}
	)

	for _, container := range pod.Spec.Containers {
		for _, volumeMount := range container.VolumeMounts {
			mountedPodVolumes.Insert(volumeMount.Name)
		}
		for _, volumeDevice := range container.VolumeDevices {
			attachedPodDevices.Insert(volumeDevice.Name)
		}
	}

	repoIdentifier := ""
	if repositoryType == velerov1api.BackupRepositoryTypeRestic {
		repoIdentifier = repo.Spec.ResticIdentifier
	}

	for _, volumeName := range volumesToBackup {
		volume, ok := podVolumes[volumeName]
		if !ok {
			log.Warnf("No volume named %s found in pod %s/%s, skipping", volumeName, pod.Namespace, pod.Name)
			continue
		}
		var pvc *corev1api.PersistentVolumeClaim
		if volume.PersistentVolumeClaim != nil {
			pvc, ok = pvcSummary.pvcMap[volumeName]
			if !ok {
				// there should have been error happened retrieving the PVC and it's recorded already
				continue
			}
		}

		if resPolicies != nil {
			if action, err := b.getMatchAction(resPolicies, pvc, &volume); err != nil {
				errs = append(errs, errors.Wrapf(err, "error getting pv for pvc %s", pvc.Spec.VolumeName))
				continue
			} else if action != nil && action.Type == resourcepolicies.Skip {
				log.Infof("skip backup of volume %s for the matched resource policies", volumeName)
				pvcSummary.addSkipped(volumeName, "matched action is 'skip' in chosen resource policies")
				continue
			}
		}

		// hostPath volumes are not supported because they're not mounted into /var/lib/kubelet/pods, so our
		// daemonset pod has no way to access their data.
		isHostPath, err := isHostPathVolume(&volume, pvc, b.crClient)
		if err != nil {
			errs = append(errs, errors.Wrap(err, "error checking if volume is a hostPath volume"))
			continue
		}
		if isHostPath {
			log.Warnf("Volume %s in pod %s/%s is a hostPath volume which is not supported for pod volume backup, skipping", volumeName, pod.Namespace, pod.Name)
			continue
		}

		// check if volume is a block volume
		if attachedPodDevices.Has(volumeName) {
			msg := fmt.Sprintf("volume %s declared in pod %s/%s is a block volume. Block volumes are not supported for fs backup, skipping",
				volumeName, pod.Namespace, pod.Name)
			log.Warn(msg)
			pvcSummary.addSkipped(volumeName, msg)
			continue
		}

		// volumes that are not mounted by any container should not be backed up, because
		// its directory is not created
		if !mountedPodVolumes.Has(volumeName) {
			msg := fmt.Sprintf("volume %s is declared in pod %s/%s but not mounted by any container, skipping", volumeName, pod.Namespace, pod.Name)
			log.Warn(msg)
			pvcSummary.addSkipped(volumeName, msg)
			continue
		}

		volumeBackup := newPodVolumeBackup(backup, pod, volume, repoIdentifier, b.uploaderType, pvc)
		// the PVB must be added into the indexer before creating it in API server otherwise unexpected behavior may happen:
		// the PVB may be handled very quickly by the controller and the informer handler will insert the PVB before "b.pvbIndexer.Add(volumeBackup)" runs,
		// this causes the PVB inserted by "b.pvbIndexer.Add(volumeBackup)" overrides the PVB in the indexer while the PVB inserted by "b.pvbIndexer.Add(volumeBackup)"
		// contains empty "Status"
		if err := b.pvbIndexer.Add(volumeBackup); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to add PodVolumeBackup %s/%s to indexer", volumeBackup.Namespace, volumeBackup.Name))
			continue
		}
		// similar with above: the PVB may be handled very quickly by the controller and the informer handler will call "b.wg.Done()" before "b.wg.Add(1)" runs which causes panic
		// see https://github.com/vmware-tanzu/velero/issues/8657
		b.wg.Add(1)
		if err := veleroclient.CreateRetryGenerateName(b.crClient, b.ctx, volumeBackup); err != nil {
			b.wg.Done()
			errs = append(errs, err)
			continue
		}

		podVolumeBackups = append(podVolumeBackups, volumeBackup)
		pvcSummary.addBackedup(volumeName)
	}

	return podVolumeBackups, pvcSummary, errs
}

func (b *backupper) WaitAllPodVolumesProcessed(log logrus.FieldLogger) []*velerov1api.PodVolumeBackup {
	defer func() {
		if err := b.pvbInformer.RemoveEventHandler(b.handlerRegistration); err != nil {
			log.Debugf("failed to remove the event handler for PVB: %v", err)
		}
	}()

	log.Info("Waiting for completion of PVB")

	var podVolumeBackups []*velerov1api.PodVolumeBackup
	// if no pod volume backups are tracked, return directly to avoid issue mentioned in
	// https://github.com/vmware-tanzu/velero/issues/8723
	if len(b.pvbIndexer.List()) == 0 {
		return podVolumeBackups
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		b.wg.Wait()
	}()

	select {
	case <-b.ctx.Done():
		log.Error("timed out waiting for all PodVolumeBackups to complete")
	case <-done:
		for _, obj := range b.pvbIndexer.List() {
			pvb, ok := obj.(*velerov1api.PodVolumeBackup)
			if !ok {
				log.Errorf("expected PodVolumeBackup, but got %T", obj)
				continue
			}
			podVolumeBackups = append(podVolumeBackups, pvb)
			if pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseFailed {
				log.Errorf("pod volume backup failed: %s", pvb.Status.Message)
			} else if pvb.Status.Phase == velerov1api.PodVolumeBackupPhaseCanceled {
				log.Errorf("pod volume backup canceled: %s", pvb.Status.Message)
			}
		}
	}
	return podVolumeBackups
}

func (b *backupper) GetPodVolumeBackupByPodAndVolume(podNamespace, podName, volume string) (*velerov1api.PodVolumeBackup, error) {
	obj, exist, err := b.pvbIndexer.GetByKey(fmt.Sprintf(pvbKeyPattern, podNamespace, podName, volume))
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, nil
	}
	pvb, ok := obj.(*velerov1api.PodVolumeBackup)
	if !ok {
		return nil, errors.Errorf("expected PodVolumeBackup, but got %T", obj)
	}
	return pvb, nil
}

func (b *backupper) ListPodVolumeBackupsByPod(podNamespace, podName string) ([]*velerov1api.PodVolumeBackup, error) {
	objs, err := b.pvbIndexer.ByIndex(indexNamePod, cache.NewObjectName(podNamespace, podName).String())
	if err != nil {
		return nil, err
	}
	var pvbs []*velerov1api.PodVolumeBackup
	for _, obj := range objs {
		pvb, ok := obj.(*velerov1api.PodVolumeBackup)
		if !ok {
			return nil, errors.Errorf("expected PodVolumeBackup, but got %T", obj)
		}
		pvbs = append(pvbs, pvb)
	}
	return pvbs, nil
}

func skipAllPodVolumes(pod *corev1api.Pod, volumesToBackup []string, err error, pvcSummary *PVCBackupSummary, log logrus.FieldLogger) {
	for _, volumeName := range volumesToBackup {
		log.WithError(err).Warnf("Skip pod volume %s", volumeName)
		pvcSummary.addSkipped(volumeName, fmt.Sprintf("encountered a problem with backing up the PVC of pod %s/%s: %v", pod.Namespace, pod.Name, err))
	}
}

// isHostPathVolume returns true if the volume is either a hostPath pod volume or a persistent
// volume claim on a hostPath persistent volume, or false otherwise.
func isHostPathVolume(volume *corev1api.Volume, pvc *corev1api.PersistentVolumeClaim, crClient ctrlclient.Client) (bool, error) {
	if volume.HostPath != nil {
		return true, nil
	}

	if pvc == nil || pvc.Spec.VolumeName == "" {
		return false, nil
	}

	pv := new(corev1api.PersistentVolume)
	err := crClient.Get(context.TODO(), ctrlclient.ObjectKey{Name: pvc.Spec.VolumeName}, pv)
	if err != nil {
		return false, errors.WithStack(err)
	}

	return pv.Spec.HostPath != nil, nil
}

func newPodVolumeBackup(backup *velerov1api.Backup, pod *corev1api.Pod, volume corev1api.Volume, repoIdentifier, uploaderType string, pvc *corev1api.PersistentVolumeClaim) *velerov1api.PodVolumeBackup {
	pvb := &velerov1api.PodVolumeBackup{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    backup.Namespace,
			GenerateName: backup.Name + "-",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: velerov1api.SchemeGroupVersion.String(),
					Kind:       "Backup",
					Name:       backup.Name,
					UID:        backup.UID,
					Controller: boolptr.True(),
				},
			},
			Labels: map[string]string{
				velerov1api.BackupNameLabel: label.GetValidName(backup.Name),
				velerov1api.BackupUIDLabel:  string(backup.UID),
			},
		},
		Spec: velerov1api.PodVolumeBackupSpec{
			Node: pod.Spec.NodeName,
			Pod: corev1api.ObjectReference{
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				UID:       pod.UID,
			},
			Volume: volume.Name,
			Tags: map[string]string{
				"backup":     backup.Name,
				"backup-uid": string(backup.UID),
				"pod":        pod.Name,
				"pod-uid":    string(pod.UID),
				"ns":         pod.Namespace,
				"volume":     volume.Name,
			},
			BackupStorageLocation: backup.Spec.StorageLocation,
			RepoIdentifier:        repoIdentifier,
			UploaderType:          uploaderType,
		},
	}

	if pvc != nil {
		// this annotation is used in pkg/restore to identify if a PVC
		// has a pod volume backup.
		pvb.Annotations = map[string]string{
			configs.PVCNameAnnotation: pvc.Name,
		}

		// this label is used by the pod volume backup controller to tell
		// if a pod volume backup is for a PVC.
		pvb.Labels[velerov1api.PVCUIDLabel] = string(pvc.UID)

		// this tag is not used by velero, but useful for debugging.
		pvb.Spec.Tags["pvc-uid"] = string(pvc.UID)
	}

	if backup.Spec.UploaderConfig != nil {
		pvb.Spec.UploaderSettings = uploaderutil.StoreBackupConfig(backup.Spec.UploaderConfig)
	}

	return pvb
}
