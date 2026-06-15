/*
Copyright The Velero Contributors.

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

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	veleroutil "github.com/vmware-tanzu/velero/pkg/util/velero"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	backupSyncReconcilePeriod = time.Minute
)

type backupSyncReconciler struct {
	client                  client.Client
	namespace               string
	defaultBackupSyncPeriod time.Duration
	newPluginManager        func(logrus.FieldLogger) clientmgmt.Manager
	backupStoreGetter       persistence.ObjectBackupStoreGetter
	logger                  logrus.FieldLogger
}

// NewBackupSyncReconciler is used to generate BackupSync reconciler structure.
func NewBackupSyncReconciler(
	client client.Client,
	namespace string,
	defaultBackupSyncPeriod time.Duration,
	newPluginManager func(logrus.FieldLogger) clientmgmt.Manager,
	backupStoreGetter persistence.ObjectBackupStoreGetter,
	logger logrus.FieldLogger) *backupSyncReconciler {
	return &backupSyncReconciler{
		client:                  client,
		namespace:               namespace,
		defaultBackupSyncPeriod: defaultBackupSyncPeriod,
		newPluginManager:        newPluginManager,
		backupStoreGetter:       backupStoreGetter,
		logger:                  logger,
	}
}

// Reconcile syncs between the backups in cluster and backups metadata in object store.
func (b *backupSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := b.logger.WithField("controller", constant.ControllerBackupSync)
	log = log.WithField("backupLocation", req.String())
	log.Debug("Begin to sync between backups' metadata in BSL object storage and cluster's existing backups.")

	location := &velerov1api.BackupStorageLocation{}
	err := b.client.Get(ctx, req.NamespacedName, location)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("BackupStorageLocation is not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrapf(err, "error getting BackupStorageLocation %s", req.String())
	}
	if !veleroutil.BSLIsAvailable(*location) {
		log.Errorf("BackupStorageLocation is in unavailable state, skip syncing backup from it.")
		return ctrl.Result{}, nil
	}

	pluginManager := b.newPluginManager(log)
	defer pluginManager.CleanupClients()

	log.Debug("Checking backup location for backups to sync into cluster")

	backupStore, err := b.backupStoreGetter.Get(location, pluginManager, log)
	if err != nil {
		log.WithError(err).Error("Error getting backup store for this location")
		return ctrl.Result{}, nil
	}

	// get a list of all the backups that are stored in the backup storage location
	res, err := backupStore.ListBackups()
	if err != nil {
		log.WithError(err).Error("Error listing backups in backup store")
		return ctrl.Result{}, nil
	}
	backupStoreBackups := sets.New[string](res...)
	log.WithField("backupCount", len(backupStoreBackups)).Debug("Got backups from backup store")

	// get a list of all the backups that exist as custom resources in the cluster
	var clusterBackupList velerov1api.BackupList
	listOption := client.ListOptions{
		LabelSelector: labels.Everything(),
		Namespace:     b.namespace,
	}

	err = b.client.List(ctx, &clusterBackupList, &listOption)
	if err != nil {
		log.WithError(errors.WithStack(err)).Error("Error getting backups from cluster, proceeding with sync into cluster")
	} else {
		log.WithField("backupCount", len(clusterBackupList.Items)).Debug("Got backups from cluster")
	}

	// get a list of backups that *are* in the backup storage location and *aren't* in the cluster
	clusterBackupsSet := sets.New[string]()
	for _, b := range clusterBackupList.Items {
		clusterBackupsSet.Insert(b.Name)
	}
	backupsToSync := backupStoreBackups.Difference(clusterBackupsSet)

	if count := backupsToSync.Len(); count > 0 {
		log.Infof("Found %v backups in the backup location that do not exist in the cluster and need to be synced", count)
	} else {
		log.Debug("No backups found in the backup location that need to be synced into the cluster")
	}

	// sync each backup
	for backupName := range backupsToSync {
		log = log.WithField("backup", backupName)
		log.Info("Attempting to sync backup into cluster")

		exist, err := backupStore.BackupExists(location.Spec.ObjectStorage.Bucket, backupName)
		if err != nil {
			log.WithError(errors.WithStack(err)).Error("Error checking backup exist from backup store")
			continue
		}
		if !exist {
			log.Debugf("backup %s doesn't exist in backup store, skip", backupName)
			continue
		}

		backup, err := backupStore.GetBackupMetadata(backupName)
		if err != nil {
			log.WithError(errors.WithStack(err)).Error("Error getting backup metadata from backup store")
			continue
		}

		if backup.Status.Phase == velerov1api.BackupPhaseWaitingForPluginOperations ||
			backup.Status.Phase == velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed ||
			backup.Status.Phase == velerov1api.BackupPhaseFinalizing ||
			backup.Status.Phase == velerov1api.BackupPhaseFinalizingPartiallyFailed {
			if backup.Status.Expiration == nil || backup.Status.Expiration.After(time.Now()) {
				log.Debugf("Skipping non-expired incomplete backup %v", backup.Name)
				continue
			}
			log.Debugf("%v Backup is past expiration, syncing for garbage collection", backup.Status.Phase)
			backup.Status.Phase = velerov1api.BackupPhasePartiallyFailed
		}
		backup.Namespace = b.namespace
		backup.ResourceVersion = ""

		// update the StorageLocation field and label since the name of the location
		// may be different in this cluster than in the cluster that created the
		// backup.
		backup.Spec.StorageLocation = location.Name
		if backup.Labels == nil {
			backup.Labels = make(map[string]string)
		}
		backup.Labels[velerov1api.StorageLocationLabel] = label.GetValidName(backup.Spec.StorageLocation)

		//check for the ownership references. If they do not exist, remove them.
		backup.ObjectMeta.OwnerReferences = b.filterBackupOwnerReferences(ctx, backup, log)

		// attempt to create backup custom resource via API
		err = b.client.Create(ctx, backup, &client.CreateOptions{})
		switch {
		case err != nil && apierrors.IsAlreadyExists(err):
			log.Debug("Backup already exists in cluster")
			continue
		case err != nil && !apierrors.IsAlreadyExists(err):
			log.WithError(errors.WithStack(err)).Error("Error syncing backup into cluster")
			continue
		default:
			log.Info("Successfully synced backup into cluster")
		}

		// process the pod volume backups from object store, if any
		podVolumeBackups, err := backupStore.GetPodVolumeBackups(backupName)
		if err != nil {
			log.WithError(errors.WithStack(err)).Error("Error getting pod volume backups for this backup from backup store")
			continue
		}

		for _, podVolumeBackup := range podVolumeBackups {
			log := log.WithField("podVolumeBackup", podVolumeBackup.Name)
			log.Debug("Checking this pod volume backup to see if it needs to be synced into the cluster")

			for i, ownerRef := range podVolumeBackup.OwnerReferences {
				if ownerRef.APIVersion == velerov1api.SchemeGroupVersion.String() && ownerRef.Kind == "Backup" && ownerRef.Name == backup.Name {
					log.WithField("uid", backup.UID).Debugf("Updating pod volume backup's owner reference UID")
					podVolumeBackup.OwnerReferences[i].UID = backup.UID
				}
			}

			if _, ok := podVolumeBackup.Labels[velerov1api.BackupUIDLabel]; ok {
				podVolumeBackup.Labels[velerov1api.BackupUIDLabel] = string(backup.UID)
			}

			podVolumeBackup.Namespace = backup.Namespace
			podVolumeBackup.ResourceVersion = ""
			podVolumeBackup.Spec.BackupStorageLocation = location.Name

			err = b.client.Create(ctx, podVolumeBackup, &client.CreateOptions{})
			switch {
			case err != nil && apierrors.IsAlreadyExists(err):
				log.Debug("Pod volume backup already exists in cluster")
				continue
			case err != nil && !apierrors.IsAlreadyExists(err):
				log.WithError(errors.WithStack(err)).Error("Error syncing pod volume backup into cluster")
				continue
			default:
				log.Debug("Synced pod volume backup into cluster")
			}
		}
	}

	b.deleteOrphanedBackups(ctx, location.Name, backupStoreBackups, log)

	// update the location's last-synced time field
	statusPatch := client.MergeFrom(location.DeepCopy())
	location.Status.LastSyncedTime = &metav1.Time{Time: time.Now().UTC()}
	if err := b.client.Patch(ctx, location, statusPatch); err != nil {
		log.WithError(errors.WithStack(err)).Error("Error patching backup location's last-synced time")
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (b *backupSyncReconciler) filterBackupOwnerReferences(ctx context.Context, backup *velerov1api.Backup, log logrus.FieldLogger) []metav1.OwnerReference {
	listedReferences := backup.ObjectMeta.OwnerReferences
	foundReferences := make([]metav1.OwnerReference, 0)
	for _, v := range listedReferences {
		switch v.Kind {
		case "Schedule":
			schedule := new(velerov1api.Schedule)
			err := b.client.Get(ctx, types.NamespacedName{
				Name:      v.Name,
				Namespace: backup.Namespace,
			}, schedule)
			switch {
			case err != nil && apierrors.IsNotFound(err):
				log.Warnf("Removing missing schedule ownership reference %s/%s from backup", backup.Namespace, v.Name)
				continue
			case schedule.UID != v.UID:
				log.Warnf("Removing schedule ownership reference with mismatched UIDs. Expected %s, got %s", v.UID, schedule.UID)
				continue
			case err != nil && !apierrors.IsNotFound(err):
				log.WithError(errors.WithStack(err)).Error("Error finding schedule ownership reference, keeping schedule on backup")
			}
		default:
			log.Warnf("Unable to check ownership reference for unknown kind, %s", v.Kind)
		}
		foundReferences = append(foundReferences, v)
	}
	return foundReferences
}

// SetupWithManager is used to setup controller and its watching sources.
func (b *backupSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		location := object.(*velerov1api.BackupStorageLocation)
		return b.locationFilterFunc(location)
	})
	backupSyncSource := kube.NewPeriodicalEnqueueSource(
		b.logger.WithField("controller", constant.ControllerBackupSync),
		mgr.GetClient(),
		&velerov1api.BackupStorageLocationList{},
		backupSyncReconcilePeriod,
		kube.PeriodicalEnqueueSourceOption{
			OrderFunc:  backupSyncSourceOrderFunc,
			Predicates: []predicate.Predicate{gp},
		},
	)

	return ctrl.NewControllerManagedBy(mgr).
		// Filter all BSL events, because this controller is supposed to run periodically, not by event.
		For(&velerov1api.BackupStorageLocation{}, builder.WithPredicates(kube.FalsePredicate{})).
		WatchesRawSource(backupSyncSource).
		Named(constant.ControllerBackupSync).
		Complete(b)
}

// deleteOrphanedBackups deletes backup objects (CRDs) from Kubernetes that have the specified location
// and a phase of Completed, but no corresponding backup in object storage.
func (b *backupSyncReconciler) deleteOrphanedBackups(ctx context.Context, locationName string, backupStoreBackups sets.Set[string], log logrus.FieldLogger) {
	var backupList velerov1api.BackupList
	listOption := client.ListOptions{
		LabelSelector: labels.Set(map[string]string{
			velerov1api.StorageLocationLabel: label.GetValidName(locationName),
		}).AsSelector(),
	}
	err := b.client.List(ctx, &backupList, &listOption)
	if err != nil {
		log.WithError(errors.WithStack(err)).Error("Error listing backups from cluster")
		return
	}

	if len(backupList.Items) == 0 {
		return
	}

	for i, backup := range backupList.Items {
		log = log.WithField("backup", backup.Name)
		if !(backup.Status.Phase == velerov1api.BackupPhaseCompleted || backup.Status.Phase == velerov1api.BackupPhasePartiallyFailed) || backupStoreBackups.Has(backup.Name) {
			continue
		}

		if err := b.client.Delete(ctx, &backupList.Items[i], &client.DeleteOptions{}); err != nil {
			log.WithError(errors.WithStack(err)).Error("Error deleting orphaned backup from cluster")
		}
	}
}

// backupSyncSourceOrderFunc returns a new slice with the default backup location first (if it exists),
// followed by the rest of the locations in no particular order.
func backupSyncSourceOrderFunc(objList client.ObjectList) client.ObjectList {
	inputBSLList := objList.(*velerov1api.BackupStorageLocationList)
	resultBSLList := &velerov1api.BackupStorageLocationList{}
	bslArray := make([]runtime.Object, 0)

	if len(inputBSLList.Items) <= 0 {
		return objList
	}

	for i := range inputBSLList.Items {
		location := inputBSLList.Items[i]

		// sync the default backup storage location first, if it exists
		if location.Spec.Default {
			// put the default location first
			bslArray = append(bslArray, &inputBSLList.Items[i])
			// append everything before the default
			for _, bsl := range inputBSLList.Items[:i] {
				cpBsl := bsl
				bslArray = append(bslArray, &cpBsl)
			}
			// append everything after the default
			for _, bsl := range inputBSLList.Items[i+1:] {
				cpBsl := bsl
				bslArray = append(bslArray, &cpBsl)
			}
			if err := meta.SetList(resultBSLList, bslArray); err != nil {
				fmt.Printf("fail to sort BSL list: %s", err.Error())
				return &velerov1api.BackupStorageLocationList{}
			}

			return resultBSLList
		}
	}

	// No default BSL found. Return the input.
	return objList
}

func (b *backupSyncReconciler) locationFilterFunc(location *velerov1api.BackupStorageLocation) bool {
	syncPeriod := b.defaultBackupSyncPeriod
	if location.Spec.BackupSyncPeriod != nil {
		syncPeriod = location.Spec.BackupSyncPeriod.Duration
		if syncPeriod == 0 {
			b.logger.Debug("Backup sync period for this location is set to 0, skipping sync")
			return false
		}

		if syncPeriod < 0 {
			b.logger.Debug("Backup sync period must be non-negative")
			syncPeriod = b.defaultBackupSyncPeriod
		}
	}

	lastSync := location.Status.LastSyncedTime
	if lastSync != nil {
		b.logger.Debug("Checking if backups need to be synced at this time for this location")
		nextSync := lastSync.Add(syncPeriod)
		if time.Now().UTC().Before(nextSync) {
			return false
		}
	}
	return true
}
