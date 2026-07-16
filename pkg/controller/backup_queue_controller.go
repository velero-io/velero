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

package controller

import (
	"context"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// backupQueueReconciler reconciles a Backup object
type backupQueueReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	logger            logrus.FieldLogger
	concurrentBackups int
	backupTracker     BackupTracker
	frequency         time.Duration
}

const (
	defaultQueuedBackupRecheckFrequency = time.Minute
)

// NewBackupQueueReconciler returns a new backupQueueReconciler
func NewBackupQueueReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	logger logrus.FieldLogger,
	concurrentBackups int,
	backupTracker BackupTracker,
) *backupQueueReconciler {
	return &backupQueueReconciler{
		Client:            client,
		Scheme:            scheme,
		logger:            logger,
		concurrentBackups: max(concurrentBackups, 1),
		backupTracker:     backupTracker,
		frequency:         defaultQueuedBackupRecheckFrequency,
	}
}

func queuePositionOrderFunc(objList client.ObjectList) client.ObjectList {
	backupList := objList.(*velerov1api.BackupList)
	slices.SortFunc(backupList.Items, func(backup1, backup2 velerov1api.Backup) int {
		if backup1.Status.QueuePosition < backup2.Status.QueuePosition {
			return -1
		} else if backup1.Status.QueuePosition == backup2.Status.QueuePosition {
			return 0
		} else {
			return 1
		}
	})
	return backupList
}

// SetupWithManager adds the reconciler to the manager
func (r *backupQueueReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// For periodic requeue, only consider Queued backups, order by QueuePosition
	gp := kube.NewGenericEventPredicate(func(object client.Object) bool {
		backup := object.(*velerov1api.Backup)
		return backup.Status.Phase == velerov1api.BackupPhaseQueued
	})

	s := kube.NewPeriodicalEnqueueSource(r.logger.WithField("controller", constant.ControllerBackupQueue), mgr.GetClient(), &velerov1api.BackupList{}, r.frequency, kube.PeriodicalEnqueueSourceOption{
		Predicates: []predicate.Predicate{gp},
		OrderFunc:  queuePositionOrderFunc,
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.Backup{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(ue event.UpdateEvent) bool {
				backup := ue.ObjectNew.(*velerov1api.Backup)
				return backup.Status.Phase == "" || backup.Status.Phase == velerov1api.BackupPhaseNew
			},
			CreateFunc: func(ce event.CreateEvent) bool {
				backup := ce.Object.(*velerov1api.Backup)
				return backup.Status.Phase == "" || backup.Status.Phase == velerov1api.BackupPhaseNew
			},
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
			GenericFunc: func(ge event.GenericEvent) bool {
				return false
			},
		})).
		Watches(
			&velerov1api.Backup{},
			handler.EnqueueRequestsFromMapFunc(r.findQueuedBackupsToRequeue),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(ue event.UpdateEvent) bool {
					oldBackup := ue.ObjectOld.(*velerov1api.Backup)
					newBackup := ue.ObjectNew.(*velerov1api.Backup)
					return oldBackup.Status.Phase == velerov1api.BackupPhaseInProgress &&
						newBackup.Status.Phase != velerov1api.BackupPhaseInProgress ||
						oldBackup.Status.Phase != velerov1api.BackupPhaseQueued &&
							newBackup.Status.Phase == velerov1api.BackupPhaseQueued &&
							r.backupTracker.RunningCount() < r.concurrentBackups
				},
				CreateFunc: func(event.CreateEvent) bool {
					return false
				},
				DeleteFunc: func(de event.DeleteEvent) bool {
					return false
				},
				GenericFunc: func(ge event.GenericEvent) bool {
					return false
				},
			})).
		WatchesRawSource(s).
		Named(constant.ControllerBackupQueue).
		Complete(r)
}

func (r *backupQueueReconciler) detectNamespaceConflict(ctx context.Context, backup *velerov1api.Backup, earlierBackups []velerov1api.Backup) (bool, string, []string, error) {
	nsList := &corev1api.NamespaceList{}
	if err := r.Client.List(ctx, nsList); err != nil {
		return false, "", nil, err
	}
	var clusterNamespaces []string
	for _, ns := range nsList.Items {
		clusterNamespaces = append(clusterNamespaces, ns.Name)
	}
	foundConflict, conflictBackup := detectNSConflictsInternal(backup, earlierBackups, clusterNamespaces)
	return foundConflict, conflictBackup, clusterNamespaces, nil
}

func detectNSConflictsInternal(backup *velerov1api.Backup, earlierBackups []velerov1api.Backup, clusterNamespaces []string) (bool, string) {
	backupNamespaces := sets.NewString(namespacesForBackup(backup, clusterNamespaces)...)
	for _, earlierBackup := range earlierBackups {
		// This will never be true for the primary backup, but for the secondary
		// runnability check for queued backups ahead of the current backup, we
		// only care about backups ahead of it.
		// Backup isn't earlier than this one, skip
		if earlierBackup.Status.Phase == velerov1api.BackupPhaseQueued &&
			earlierBackup.Status.QueuePosition >= backup.Status.QueuePosition {
			continue
		}
		if backupNamespaces.HasAny(namespacesForBackup(&earlierBackup, clusterNamespaces)...) {
			return true, earlierBackup.Name
		}
	}
	return false, ""
}

// Returns true if there are backups ahead of the current backup that are runnable
// This could happen if velero just reconciled the one earlier in the queue and rejected it
// due to too many running backups, but a backup completed in between that reconcile and this one
// so exit, as the recent completion has triggered another reconcile of all queued backups
func (r *backupQueueReconciler) checkForEarlierRunnableBackups(backup *velerov1api.Backup, earlierBackups []velerov1api.Backup, clusterNamespaces []string) (bool, string) {
	for _, earlierBackup := range earlierBackups {
		// if this backup is queued and ahead of current backup, check for conflicts
		if earlierBackup.Status.Phase != velerov1api.BackupPhaseQueued ||
			earlierBackup.Status.QueuePosition >= backup.Status.QueuePosition {
			continue
		}
		conflict, _ := detectNSConflictsInternal(&earlierBackup, earlierBackups, clusterNamespaces)
		// !conflict means we've found an earlier backup that is currently runnable
		// so current reconcile should exit to run this one
		if !conflict {
			return true, earlierBackup.Name
		}
	}
	return false, ""
}

func namespacesForBackup(backup *velerov1api.Backup, clusterNamespaces []string) []string {
	// Ignore error here. If a backup has invalid namespace wildcards, the backup controller
	// will validate and fail it. Consider the ns list empty for conflict detection purposes.
	nsList, err := collections.NewNamespaceIncludesExcludes().Includes(backup.Spec.IncludedNamespaces...).Excludes(backup.Spec.ExcludedNamespaces...).ActiveNamespaces(clusterNamespaces).ResolveNamespaceList()
	if err != nil {
		return []string{}
	}
	return nsList
}
func (r *backupQueueReconciler) getMaxQueuePosition(lister *queuedBackupsLister) int {
	queuedBackups := lister.orderedQueued()
	maxPos := 0
	if len(queuedBackups) > 0 {
		maxPos = queuedBackups[len(queuedBackups)-1].Status.QueuePosition
	}
	return maxPos
}

func (r *backupQueueReconciler) findQueuedBackupsToRequeue(ctx context.Context, obj client.Object) []reconcile.Request {
	backup := obj.(*velerov1api.Backup)
	requests := []reconcile.Request{}
	allBackups := &velerov1api.BackupList{}
	if err := r.Client.List(ctx, allBackups, &client.ListOptions{Namespace: backup.Namespace}); err != nil {
		r.logger.WithError(err).Error("error listing backups")
		return requests
	}
	backups := r.newQueuedBackupsLister(allBackups).orderedQueued()
	for _, item := range backups {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			},
		})
	}
	return requests
}

// Reconcile reconciles a Backup object
func (r *backupQueueReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithField("backup", req.NamespacedName.String())

	log.Debug("Getting backup")
	backup := &velerov1api.Backup{}
	if err := r.Get(ctx, req.NamespacedName, backup); err != nil {
		log.WithError(err).Error("unable to get backup")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	switch backup.Status.Phase {
	case "", velerov1api.BackupPhaseNew:
		// queue new backup
		allBackups := &velerov1api.BackupList{}
		if err := r.Client.List(ctx, allBackups, &client.ListOptions{Namespace: backup.Namespace}); err != nil {
			r.logger.WithError(err).Error("error listing backups")
			return ctrl.Result{}, nil
		}
		lister := r.newQueuedBackupsLister(allBackups)
		maxQueuePosition := r.getMaxQueuePosition(lister)
		original := backup.DeepCopy()
		backup.Status.Phase = velerov1api.BackupPhaseQueued
		backup.Status.QueuePosition = maxQueuePosition + 1
		log.Infof("Queueing backup %v, queue position %v", backup.Name, backup.Status.QueuePosition)
		if err := kube.PatchResource(original, backup, r.Client); err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error updating Backup status to %s", backup.Status.Phase)
		}
	case velerov1api.BackupPhaseQueued:
		// handle queued backup
		// Find backups ahead of this one (InProgress, ReadyToStart, or Queued with higher position)
		allBackups := &velerov1api.BackupList{}
		if err := r.Client.List(ctx, allBackups, &client.ListOptions{Namespace: backup.Namespace}); err != nil {
			r.logger.WithError(err).Error("error listing backups")
			return ctrl.Result{}, nil
		}
		lister := r.newQueuedBackupsLister(allBackups)
		if r.backupTracker.RunningCount() >= r.concurrentBackups {
			log.Debugf("%v concurrent backups are already running, leaving %v queued", r.concurrentBackups, backup.Name)
			return ctrl.Result{}, nil
		}
		earlierBackups := lister.earlierThan(backup.Status.QueuePosition)
		foundConflict, conflictBackup, clusterNamespaces, err := r.detectNamespaceConflict(ctx, backup, earlierBackups)
		if err != nil {
			log.WithError(err).Error("error listing namespaces")
			return ctrl.Result{}, nil
		}
		if foundConflict {
			log.Infof("Backup %v has namespace conflict with %v, leaving queued", backup.Name, conflictBackup)
			return ctrl.Result{}, nil
		}
		foundEarlierRunnable, earlierRunnable := r.checkForEarlierRunnableBackups(backup, earlierBackups, clusterNamespaces)
		if foundEarlierRunnable {
			log.Infof("Earlier queued backup %v is runnable, leaving %v queued", earlierRunnable, backup.Name)
			return ctrl.Result{}, nil
		}
		log.Infof("Dequeueing backup %v, moving to ReadyToStart", backup.Name)
		original := backup.DeepCopy()
		backup.Status.Phase = velerov1api.BackupPhaseReadyToStart
		backup.Status.QueuePosition = 0
		if err := kube.PatchResource(original, backup, r.Client); err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error updating Backup status to %s", backup.Status.Phase)
		}
		r.backupTracker.AddReadyToStart(backup.Namespace, backup.Name)
		log.Debug("Updating queuePosition for remaining queued backups")
		queuedBackups := lister.orderedQueued()
		newQueuePos := 1
		for _, queuedBackup := range queuedBackups {
			if queuedBackup.Name != backup.Name {
				original := queuedBackup.DeepCopy()
				queuedBackup.Status.QueuePosition = newQueuePos
				if err := kube.PatchResource(original, &queuedBackup, r.Client); err != nil {
					log.WithError(errors.Wrapf(err, "error updating Backup %s queuePosition to %v", queuedBackup.Name, newQueuePos))
					return ctrl.Result{}, nil
				}
				newQueuePos++
			}
		}
		return ctrl.Result{}, nil
	default:
		log.Debug("Backup is not New or Queued, skipping")
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// queuedBackupsLister manages a list of all backups Queued, ReadyToStart, or InProgress
// with methods to return specific subsets as needed
type queuedBackupsLister struct {
	backups *velerov1api.BackupList
}

func (r *backupQueueReconciler) newQueuedBackupsLister(backupList *velerov1api.BackupList) *queuedBackupsLister {
	backups := []velerov1api.Backup{}
	for _, backup := range backupList.Items {
		if backup.Status.Phase == velerov1api.BackupPhaseQueued ||
			backup.Status.Phase == velerov1api.BackupPhaseInProgress ||
			backup.Status.Phase == velerov1api.BackupPhaseReadyToStart {
			backups = append(backups, backup)
		}
	}
	backupList.Items = backups
	return &queuedBackupsLister{backupList}
}

func (l *queuedBackupsLister) earlierThan(queuePos int) []velerov1api.Backup {
	backups := []velerov1api.Backup{}
	for _, backup := range l.backups.Items {
		// InProgress and ReadyToStart backups have QueuePosition==0
		if backup.Status.QueuePosition < queuePos {
			backups = append(backups, backup)
		}
	}
	return backups
}

func (l *queuedBackupsLister) orderedQueued() []velerov1api.Backup {
	var returnList []velerov1api.Backup
	orderedBackupList := queuePositionOrderFunc(l.backups).(*velerov1api.BackupList)
	for _, item := range orderedBackupList.Items {
		if item.Status.Phase == velerov1api.BackupPhaseQueued {
			returnList = append(returnList, item)
		}
	}
	return returnList
}
