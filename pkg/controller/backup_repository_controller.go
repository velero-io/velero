/*
Copyright 2018, 2019 the Velero contributors.

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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/petar/GoLLRB/llrb"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/repository/maintenance"
	repomanager "github.com/vmware-tanzu/velero/pkg/repository/manager"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

const (
	repoSyncPeriod                      = 5 * time.Minute
	defaultMaintainFrequency            = 7 * 24 * time.Hour
	defaultMaintenanceStatusQueueLength = 25
)

var maintenanceStatusQueueLength = defaultMaintenanceStatusQueueLength

type BackupRepoReconciler struct {
	client.Client
	namespace             string
	logger                logrus.FieldLogger
	clock                 clocks.WithTickerAndDelayedExecution
	maintenanceFrequency  time.Duration
	backupRepoConfig      string
	repositoryManager     repomanager.Manager
	repoMaintenanceConfig string
	logLevel              logrus.Level
	logFormat             *logging.FormatFlag
	metrics               *metrics.ServerMetrics
}

func NewBackupRepoReconciler(
	namespace string,
	logger logrus.FieldLogger,
	client client.Client,
	repositoryManager repomanager.Manager,
	maintenanceFrequency time.Duration,
	backupRepoConfig string,
	repoMaintenanceConfig string,
	logLevel logrus.Level,
	logFormat *logging.FormatFlag,
	metrics *metrics.ServerMetrics,
) *BackupRepoReconciler {
	c := &BackupRepoReconciler{
		client,
		namespace,
		logger,
		clocks.RealClock{},
		maintenanceFrequency,
		backupRepoConfig,
		repositoryManager,
		repoMaintenanceConfig,
		logLevel,
		logFormat,
		metrics,
	}

	return c
}

func (r *BackupRepoReconciler) SetupWithManager(mgr ctrl.Manager) error {
	s := kube.NewPeriodicalEnqueueSource(
		r.logger.WithField("controller", constant.ControllerBackupRepo),
		mgr.GetClient(),
		&velerov1api.BackupRepositoryList{},
		repoSyncPeriod,
		kube.PeriodicalEnqueueSourceOption{},
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.BackupRepository{}, builder.WithPredicates(kube.SpecChangePredicate{})).
		WatchesRawSource(s).
		Watches(
			// mark BackupRepository as invalid when BSL is created, updated or deleted.
			// BSL may be recreated after deleting, so also include the create event
			&velerov1api.BackupStorageLocation{},
			kube.EnqueueRequestsFromMapUpdateFunc(r.invalidateBackupReposForBSL),
			builder.WithPredicates(
				// Combine three predicates together to guarantee
				// only BSL's Delete Event and Update Event can enqueue.
				// We don't care about BSL's Generic Event and Create Event,
				// because BSL's periodical enqueue triggers Generic Event,
				// and the BackupRepository controller restart will triggers BSL create event.
				kube.NewUpdateEventPredicate(
					r.needInvalidBackupRepo,
				),
				kube.NewGenericEventPredicate(
					func(client.Object) bool { return false },
				),
				kube.NewCreateEventPredicate(
					func(client.Object) bool { return false },
				),
			),
		).
		Complete(r)
}

func (r *BackupRepoReconciler) invalidateBackupReposForBSL(ctx context.Context, bslObj client.Object) []reconcile.Request {
	bsl := bslObj.(*velerov1api.BackupStorageLocation)

	list := &velerov1api.BackupRepositoryList{}
	options := &client.ListOptions{
		LabelSelector: labels.Set(map[string]string{
			velerov1api.StorageLocationLabel: label.GetValidName(bsl.Name),
		}).AsSelector(),
	}
	if err := r.List(context.TODO(), list, options); err != nil {
		r.logger.WithField("BSL", bsl.Name).WithError(err).Error("unable to list BackupRepositories")
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}
	for i := range list.Items {
		r.logger.WithField("BSL", bsl.Name).Infof("Invalidating Backup Repository %s", list.Items[i].Name)
		if err := r.patchBackupRepository(context.Background(), &list.Items[i], repoNotReady("re-establish on BSL change, create or delete")); err != nil {
			r.logger.WithField("BSL", bsl.Name).WithError(err).Errorf("fail to patch BackupRepository %s", list.Items[i].Name)
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}})
	}

	return requests
}

// needInvalidBackupRepo returns true if the BSL's storage type, bucket, prefix, CACert, or config has changed
func (r *BackupRepoReconciler) needInvalidBackupRepo(oldObj client.Object, newObj client.Object) bool {
	oldBSL := oldObj.(*velerov1api.BackupStorageLocation)
	newBSL := newObj.(*velerov1api.BackupStorageLocation)

	oldStorage := oldBSL.Spec.StorageType.ObjectStorage
	newStorage := newBSL.Spec.StorageType.ObjectStorage
	oldConfig := oldBSL.Spec.Config
	newConfig := newBSL.Spec.Config

	if oldStorage == nil {
		oldStorage = &velerov1api.ObjectStorageLocation{}
	}

	if newStorage == nil {
		newStorage = &velerov1api.ObjectStorageLocation{}
	}

	logger := r.logger.WithField("BSL", newBSL.Name)

	if oldStorage.Bucket != newStorage.Bucket {
		logger.WithFields(logrus.Fields{
			"old bucket": oldStorage.Bucket,
			"new bucket": newStorage.Bucket,
		}).Info("BSL's bucket has changed, invalid backup repositories")

		return true
	}

	if oldStorage.Prefix != newStorage.Prefix {
		logger.WithFields(logrus.Fields{
			"old prefix": oldStorage.Prefix,
			"new prefix": newStorage.Prefix,
		}).Info("BSL's prefix has changed, invalid backup repositories")

		return true
	}

	// Check if either CACert or CACertRef has changed
	if !bytes.Equal(oldStorage.CACert, newStorage.CACert) {
		logger.Info("BSL's CACert has changed, invalid backup repositories")
		return true
	}

	// Check if CACertRef has changed
	if (oldStorage.CACertRef == nil && newStorage.CACertRef != nil) ||
		(oldStorage.CACertRef != nil && newStorage.CACertRef == nil) ||
		(oldStorage.CACertRef != nil && newStorage.CACertRef != nil &&
			(oldStorage.CACertRef.Name != newStorage.CACertRef.Name ||
				oldStorage.CACertRef.Key != newStorage.CACertRef.Key)) {
		logger.Info("BSL's CACertRef has changed, invalid backup repositories")
		return true
	}

	if !reflect.DeepEqual(oldConfig, newConfig) {
		logger.Info("BSL's storage config has changed, invalid backup repositories")

		return true
	}

	return false
}

func (r *BackupRepoReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithField("backupRepo", req.String())
	backupRepo := &velerov1api.BackupRepository{}
	if err := r.Get(ctx, req.NamespacedName, backupRepo); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warnf("backup repository %s in namespace %s is not found", req.Name, req.Namespace)
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("error getting backup repository")
		return ctrl.Result{}, err
	}

	if backupRepo.Spec.RepositoryType != velerov1api.BackupRepositoryTypeKopia {
		return ctrl.Result{}, nil
	}

	bsl, bslErr := r.getBSL(ctx, backupRepo)
	if bslErr != nil {
		log.WithError(bslErr).Error("Fail to get BSL for BackupRepository. Skip reconciling.")
		return ctrl.Result{}, nil
	}

	if backupRepo.Status.Phase == "" || backupRepo.Status.Phase == velerov1api.BackupRepositoryPhaseNew {
		if err := r.initializeRepo(ctx, backupRepo, log); err != nil {
			log.WithError(err).Error("error initialize repository")
			return ctrl.Result{}, errors.WithStack(err)
		}

		return ctrl.Result{}, nil
	}

	// If the repository is ready or not-ready, check it for stale locks, but if
	// this fails for any reason, it's non-critical so we still continue on to the
	// rest of the "process" logic.
	log.Debug("Checking repository for stale locks")
	if err := r.repositoryManager.UnlockRepo(backupRepo); err != nil {
		log.WithError(err).Error("Error checking repository for stale locks")
	}

	switch backupRepo.Status.Phase {
	case velerov1api.BackupRepositoryPhaseNotReady:
		ready, err := r.checkNotReadyRepo(ctx, backupRepo, log)
		if err != nil {
			return ctrl.Result{}, err
		} else if !ready {
			return ctrl.Result{}, nil
		}
		fallthrough
	case velerov1api.BackupRepositoryPhaseReady:
		if bsl.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly {
			log.Debugf("Skip running maintenance for BackupRepository, because its BSL is in the ReadOnly mode.")
			return ctrl.Result{}, nil
		}

		if err := r.recallMaintenance(ctx, backupRepo, log); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error handling incomplete repo maintenance jobs")
		}

		if err := r.runMaintenanceIfDue(ctx, backupRepo, log); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "error check and run repo maintenance jobs")
		}

		// Get the configured number of maintenance jobs to keep from ConfigMap
		keepJobs, err := maintenance.GetKeepLatestMaintenanceJobs(ctx, r.Client, log, r.namespace, r.repoMaintenanceConfig, backupRepo)
		if err != nil {
			log.WithError(err).Warn("Failed to get keepLatestMaintenanceJobs from ConfigMap, using CLI parameter value")
		}

		if err := maintenance.DeleteOldJobs(r.Client, *backupRepo, keepJobs, log); err != nil {
			log.WithError(err).Warn("Failed to delete old maintenance jobs")
		}
	}

	return ctrl.Result{}, nil
}

func (r *BackupRepoReconciler) getBSL(ctx context.Context, req *velerov1api.BackupRepository) (*velerov1api.BackupStorageLocation, error) {
	loc := new(velerov1api.BackupStorageLocation)

	if err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Spec.BackupStorageLocation,
	}, loc); err != nil {
		return nil, err
	}

	return loc, nil
}

func (r *BackupRepoReconciler) initializeRepo(ctx context.Context, req *velerov1api.BackupRepository, log logrus.FieldLogger) error {
	log.WithField("repoConfig", r.backupRepoConfig).Info("Initializing backup repository")

	config, err := getBackupRepositoryConfig(ctx, r, r.backupRepoConfig, r.namespace, req.Name, req.Spec.RepositoryType, log)
	if err != nil {
		log.WithError(err).Warn("Failed to get repo config, repo config is ignored")
	} else if config != nil {
		log.Infof("Init repo with config %v", config)
	}

	// defaulting - if the patch fails, return an error so the item is returned to the queue
	if err := r.patchBackupRepository(ctx, req, func(rr *velerov1api.BackupRepository) {
		if rr.Spec.MaintenanceFrequency.Duration <= 0 {
			rr.Spec.MaintenanceFrequency = metav1.Duration{Duration: r.getRepositoryMaintenanceFrequency(req)}
		}

		rr.Spec.RepositoryConfig = config
	}); err != nil {
		return err
	}

	if err := ensureRepo(req, r.repositoryManager); err != nil {
		return r.patchBackupRepository(ctx, req, repoNotReady(err.Error()))
	}

	return r.patchBackupRepository(ctx, req, func(rr *velerov1api.BackupRepository) {
		rr.Status.Phase = velerov1api.BackupRepositoryPhaseReady
		rr.Status.LastMaintenanceTime = &metav1.Time{Time: time.Now()}
	})
}

func (r *BackupRepoReconciler) getRepositoryMaintenanceFrequency(req *velerov1api.BackupRepository) time.Duration {
	if r.maintenanceFrequency > 0 {
		r.logger.WithField("frequency", r.maintenanceFrequency).Info("Set user defined maintenance frequency")
		return r.maintenanceFrequency
	}

	frequency, err := r.repositoryManager.DefaultMaintenanceFrequency(req)
	if err != nil || frequency <= 0 {
		r.logger.WithError(err).WithField("returned frequency", frequency).Warn("Failed to get maitanance frequency, use the default one")
		frequency = defaultMaintainFrequency
	} else {
		r.logger.WithField("frequency", frequency).Info("Set maintenance according to repository suggestion")
	}

	return frequency
}

// ensureRepo calls repo manager's PrepareRepo to ensure the repo is ready for use.
// An error is returned if the repository can't be connected to or initialized.
func ensureRepo(repo *velerov1api.BackupRepository, repoManager repomanager.Manager) error {
	return repoManager.PrepareRepo(repo)
}

func (r *BackupRepoReconciler) recallMaintenance(ctx context.Context, req *velerov1api.BackupRepository, log logrus.FieldLogger) error {
	history, err := maintenance.WaitAllJobsComplete(ctx, r.Client, req, maintenanceStatusQueueLength, log)
	if err != nil {
		return errors.Wrapf(err, "error waiting incomplete repo maintenance job for repo %s", req.Name)
	}

	consolidated := consolidateHistory(history, req.Status.RecentMaintenance)
	if consolidated == nil {
		return nil
	}

	lastMaintenanceTime := getLastMaintenanceTimeFromHistory(consolidated)

	log.Warn("Updating backup repository because of unrecorded histories")

	return r.patchBackupRepository(ctx, req, func(rr *velerov1api.BackupRepository) {
		if lastMaintenanceTime != nil && (rr.Status.LastMaintenanceTime == nil || lastMaintenanceTime.After(rr.Status.LastMaintenanceTime.Time)) {
			if rr.Status.LastMaintenanceTime != nil {
				log.Warnf("Updating backup repository last maintenance time (%v) from history (%v)", rr.Status.LastMaintenanceTime.Time, lastMaintenanceTime.Time)
			} else {
				log.Warnf("Setting backup repository last maintenance time from history (%v)", lastMaintenanceTime.Time)
			}
			rr.Status.LastMaintenanceTime = lastMaintenanceTime
		}

		rr.Status.RecentMaintenance = consolidated
	})
}

type maintenanceStatusWrapper struct {
	status *velerov1api.BackupRepositoryMaintenanceStatus
}

func (w maintenanceStatusWrapper) Less(other llrb.Item) bool {
	return w.status.StartTimestamp.Before(other.(maintenanceStatusWrapper).status.StartTimestamp)
}

func consolidateHistory(coming, cur []velerov1api.BackupRepositoryMaintenanceStatus) []velerov1api.BackupRepositoryMaintenanceStatus {
	if len(coming) == 0 {
		return nil
	}

	if slices.EqualFunc(cur, coming, func(a, b velerov1api.BackupRepositoryMaintenanceStatus) bool {
		return a.StartTimestamp.Equal(b.StartTimestamp)
	}) {
		return nil
	}

	consolidator := llrb.New()
	for i := range cur {
		consolidator.ReplaceOrInsert(maintenanceStatusWrapper{&cur[i]})
	}

	for i := range coming {
		consolidator.ReplaceOrInsert(maintenanceStatusWrapper{&coming[i]})
	}

	truncated := []velerov1api.BackupRepositoryMaintenanceStatus{}
	for consolidator.Len() > 0 {
		if len(truncated) == maintenanceStatusQueueLength {
			break
		}

		item := consolidator.DeleteMax()
		truncated = append(truncated, *item.(maintenanceStatusWrapper).status)
	}

	slices.Reverse(truncated)

	if slices.EqualFunc(cur, truncated, func(a, b velerov1api.BackupRepositoryMaintenanceStatus) bool {
		return a.StartTimestamp.Equal(b.StartTimestamp)
	}) {
		return nil
	}

	return truncated
}

func getLastMaintenanceTimeFromHistory(history []velerov1api.BackupRepositoryMaintenanceStatus) *metav1.Time {
	time := history[0].CompleteTimestamp

	for i := range history {
		if history[i].CompleteTimestamp == nil {
			continue
		}

		if time == nil || time.Before(history[i].CompleteTimestamp) {
			time = history[i].CompleteTimestamp
		}
	}

	return time
}

var funcStartMaintenanceJob = maintenance.StartNewJob
var funcWaitMaintenanceJobComplete = maintenance.WaitJobComplete

func (r *BackupRepoReconciler) runMaintenanceIfDue(ctx context.Context, req *velerov1api.BackupRepository, log logrus.FieldLogger) error {
	startTime := r.clock.Now()

	if !dueForMaintenance(req, startTime) {
		log.Debug("not due for maintenance")
		return nil
	}

	log.Info("Running maintenance on backup repository")

	job, err := funcStartMaintenanceJob(r.Client, ctx, req, r.repoMaintenanceConfig, r.logLevel, r.logFormat, log)
	if err != nil {
		log.WithError(err).Warn("Starting repo maintenance failed")

		// Record failure metric when job fails to start
		if r.metrics != nil {
			r.metrics.RegisterRepoMaintenanceFailure(req.Name)
		}

		return r.patchBackupRepository(ctx, req, func(rr *velerov1api.BackupRepository) {
			updateRepoMaintenanceHistory(rr, velerov1api.BackupRepositoryMaintenanceFailed, &metav1.Time{Time: startTime}, nil, fmt.Sprintf("Failed to start maintenance job, err: %v", err))
		})
	}

	// when WaitMaintenanceJobComplete fails, the maintenance result will be left aside temporarily
	// If the maintenenance still completes later, recallMaintenance recalls the left once and update LastMaintenanceTime and history
	status, err := funcWaitMaintenanceJobComplete(r.Client, ctx, job, r.namespace, log)
	if err != nil {
		return errors.Wrapf(err, "error waiting repo maintenance completion status")
	}

	if status.Result == velerov1api.BackupRepositoryMaintenanceFailed {
		log.WithError(err).Warn("Pruning repository failed")

		// Record failure metric
		if r.metrics != nil {
			r.metrics.RegisterRepoMaintenanceFailure(req.Name)
			if status.StartTimestamp != nil && status.CompleteTimestamp != nil {
				duration := status.CompleteTimestamp.Sub(status.StartTimestamp.Time).Seconds()
				r.metrics.ObserveRepoMaintenanceDuration(req.Name, duration)
			}
		}

		return r.patchBackupRepository(ctx, req, func(rr *velerov1api.BackupRepository) {
			updateRepoMaintenanceHistory(rr, velerov1api.BackupRepositoryMaintenanceFailed, status.StartTimestamp, status.CompleteTimestamp, status.Message)
		})
	}

	// Record success metric
	if r.metrics != nil {
		r.metrics.RegisterRepoMaintenanceSuccess(req.Name)
		if status.StartTimestamp != nil && status.CompleteTimestamp != nil {
			duration := status.CompleteTimestamp.Sub(status.StartTimestamp.Time).Seconds()
			r.metrics.ObserveRepoMaintenanceDuration(req.Name, duration)
		}
	}

	return r.patchBackupRepository(ctx, req, func(rr *velerov1api.BackupRepository) {
		rr.Status.LastMaintenanceTime = &metav1.Time{Time: status.CompleteTimestamp.Time}
		updateRepoMaintenanceHistory(rr, velerov1api.BackupRepositoryMaintenanceSucceeded, status.StartTimestamp, status.CompleteTimestamp, status.Message)
	})
}

func updateRepoMaintenanceHistory(repo *velerov1api.BackupRepository, result velerov1api.BackupRepositoryMaintenanceResult, startTime, completionTime *metav1.Time, message string) {
	latest := velerov1api.BackupRepositoryMaintenanceStatus{
		Result:            result,
		StartTimestamp:    startTime,
		CompleteTimestamp: completionTime,
		Message:           message,
	}

	startingPos := 0
	if len(repo.Status.RecentMaintenance) >= maintenanceStatusQueueLength {
		startingPos = len(repo.Status.RecentMaintenance) - maintenanceStatusQueueLength + 1
	}

	repo.Status.RecentMaintenance = append(repo.Status.RecentMaintenance[startingPos:], latest)
}

func dueForMaintenance(req *velerov1api.BackupRepository, now time.Time) bool {
	return req.Status.LastMaintenanceTime == nil || req.Status.LastMaintenanceTime.Add(req.Spec.MaintenanceFrequency.Duration).Before(now)
}

func (r *BackupRepoReconciler) checkNotReadyRepo(ctx context.Context, req *velerov1api.BackupRepository, log logrus.FieldLogger) (bool, error) {
	log.Info("Checking backup repository for readiness")

	// we need to ensure it (first check, if check fails, attempt to init)
	// because we don't know if it's been successfully initialized yet.
	if err := ensureRepo(req, r.repositoryManager); err != nil {
		return false, r.patchBackupRepository(ctx, req, repoNotReady(err.Error()))
	}
	err := r.patchBackupRepository(ctx, req, repoReady())
	if err != nil {
		return false, err
	}
	return true, nil
}

func repoNotReady(msg string) func(*velerov1api.BackupRepository) {
	return func(r *velerov1api.BackupRepository) {
		r.Status.Phase = velerov1api.BackupRepositoryPhaseNotReady
		r.Status.Message = msg
	}
}

func repoReady() func(*velerov1api.BackupRepository) {
	return func(r *velerov1api.BackupRepository) {
		r.Status.Phase = velerov1api.BackupRepositoryPhaseReady
		r.Status.Message = ""
	}
}

// patchBackupRepository mutates req with the provided mutate function, and patches it
// through the Kube API. After executing this function, req will be updated with both
// the mutation and the results of the Patch() API call.
func (r *BackupRepoReconciler) patchBackupRepository(ctx context.Context, req *velerov1api.BackupRepository, mutate func(*velerov1api.BackupRepository)) error {
	original := req.DeepCopy()
	mutate(req)
	if err := r.Patch(ctx, req, client.MergeFrom(original)); err != nil {
		return errors.Wrap(err, "error patching BackupRepository")
	}
	return nil
}

func getBackupRepositoryConfig(ctx context.Context, ctrlClient client.Client, configName, namespace, repoName, repoType string, log logrus.FieldLogger) (map[string]string, error) {
	if configName == "" {
		return nil, nil
	}

	loc := &corev1api.ConfigMap{}
	if err := ctrlClient.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      configName,
	}, loc); err != nil {
		return nil, errors.Wrapf(err, "error getting configMap %s", configName)
	}

	jsonData, found := loc.Data[repoType]
	if !found {
		log.Infof("No data for repo type %s in config map %s", repoType, configName)
		return nil, nil
	}

	var unmarshalled map[string]any
	if err := json.Unmarshal([]byte(jsonData), &unmarshalled); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling config data from %s for repo %s, repo type %s", configName, repoName, repoType)
	}

	result := map[string]string{}
	for k, v := range unmarshalled {
		result[k] = fmt.Sprintf("%v", v)
	}

	return result, nil
}
