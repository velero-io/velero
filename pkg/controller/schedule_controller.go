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

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	cron "github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	bld "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	scheduleSyncPeriod = time.Minute
)

type scheduleReconciler struct {
	client.Client
	namespace       string
	logger          logrus.FieldLogger
	clock           clocks.WithTickerAndDelayedExecution
	metrics         *metrics.ServerMetrics
	skipImmediately bool
}

func NewScheduleReconciler(
	namespace string,
	logger logrus.FieldLogger,
	client client.Client,
	metrics *metrics.ServerMetrics,
	skipImmediately bool,
) *scheduleReconciler {
	return &scheduleReconciler{
		Client:          client,
		namespace:       namespace,
		logger:          logger,
		clock:           clocks.RealClock{},
		metrics:         metrics,
		skipImmediately: skipImmediately,
	}
}

func (c *scheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	pred := kube.NewAllEventPredicate(func(obj client.Object) bool {
		schedule := obj.(*velerov1.Schedule)
		if pause := schedule.Spec.Paused; pause {
			c.logger.Infof("schedule %s is paused, skip", schedule.Name)
			return false
		}
		return true
	})
	s := kube.NewPeriodicalEnqueueSource(c.logger.WithField("controller", constant.ControllerSchedule), mgr.GetClient(), &velerov1.ScheduleList{}, scheduleSyncPeriod,
		kube.PeriodicalEnqueueSourceOption{
			Predicates: []predicate.Predicate{pred},
		})
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1.Schedule{}, bld.WithPredicates(kube.SpecChangePredicate{}, pred)).
		WatchesRawSource(s).
		Complete(c)
}

// +kubebuilder:rbac:groups=velero.io,resources=schedules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=schedules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=velero.io,resources=backups,verbs=create

func (c *scheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.logger.WithField("schedule", req.String())

	log.Debug("Getting schedule")
	schedule := &velerov1.Schedule{}
	if err := c.Get(ctx, req.NamespacedName, schedule); err != nil {
		if apierrors.IsNotFound(err) {
			log.WithError(err).Error("schedule not found")
			c.metrics.RemoveSchedule(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrapf(err, "error getting schedule %s", req.String())
	}
	c.metrics.InitSchedule(schedule.Name)

	original := schedule.DeepCopy()

	if schedule.Spec.SkipImmediately == nil {
		schedule.Spec.SkipImmediately = &c.skipImmediately
	}
	if schedule.Spec.SkipImmediately != nil && *schedule.Spec.SkipImmediately {
		*schedule.Spec.SkipImmediately = false
		schedule.Status.LastSkipped = &metav1.Time{Time: c.clock.Now()}
	}

	// validation - even if the item is Enabled, we can't trust it
	// so re-validate
	currentPhase := schedule.Status.Phase

	cronSchedule, errs := parseCronSchedule(schedule, c.logger)
	if len(errs) > 0 {
		schedule.Status.Phase = velerov1.SchedulePhaseFailedValidation
		schedule.Status.ValidationErrors = errs
	} else {
		schedule.Status.Phase = velerov1.SchedulePhaseEnabled
		schedule.Status.ValidationErrors = nil

		// Compute expected interval between consecutive scheduled backup runs.
		// Only meaningful when the cron expression is valid.
		now := c.clock.Now()
		nextRun := cronSchedule.Next(now)
		nextNextRun := cronSchedule.Next(nextRun)
		c.metrics.SetScheduleExpectedIntervalSeconds(schedule.Name, nextNextRun.Sub(nextRun).Seconds())
	}

	scheduleNeedsPatch := false
	errStringArr := make([]string, 0)
	if currentPhase != schedule.Status.Phase {
		scheduleNeedsPatch = true
		errStringArr = append(errStringArr, fmt.Sprintf("phase to %s", schedule.Status.Phase))
	}
	// update spec.SkipImmediately if it's changed
	if original.Spec.SkipImmediately != schedule.Spec.SkipImmediately {
		scheduleNeedsPatch = true
		errStringArr = append(errStringArr, fmt.Sprintf("spec.skipImmediately to %v", schedule.Spec.SkipImmediately))
	}
	// update status if it's changed
	if original.Status.LastSkipped != schedule.Status.LastSkipped {
		scheduleNeedsPatch = true
		errStringArr = append(errStringArr, fmt.Sprintf("last skipped to %v", schedule.Status.LastSkipped))
	}
	if scheduleNeedsPatch {
		if err := c.Patch(ctx, schedule, client.MergeFrom(original)); err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error updating %v for schedule %s", errStringArr, req.String())
		}
	}

	if schedule.Status.Phase != velerov1.SchedulePhaseEnabled {
		log.Debugf("the schedule's phase is %s, isn't %s, skip", schedule.Status.Phase, velerov1.SchedulePhaseEnabled)
		return ctrl.Result{}, nil
	}

	// Check for the schedule being due to run.
	// If there are backup created by this schedule still in New or InProgress state,
	// skip current backup creation to avoid running overlap backups.
	// As the schedule must be validated before checking whether it's due, we cannot put the checking log in Predicate
	if c.ifDue(schedule, cronSchedule) && !c.checkIfBackupInNewOrProgress(schedule) {
		if err := c.submitBackup(ctx, schedule); err != nil {
			return ctrl.Result{}, errors.Wrapf(err, "error submit backup for schedule %s", req.String())
		}
	}

	return ctrl.Result{}, nil
}

func parseCronSchedule(itm *velerov1.Schedule, logger logrus.FieldLogger) (cron.Schedule, []string) {
	var validationErrors []string
	var schedule cron.Schedule

	// cron.Parse panics if schedule is empty
	if len(itm.Spec.Schedule) == 0 {
		validationErrors = append(validationErrors, "Schedule must be a non-empty valid Cron expression")
		return nil, validationErrors
	}

	log := logger.WithField("schedule", kube.NamespaceAndName(itm))

	// adding a recover() around cron.Parse because it panics on empty string and is possible
	// that it panics under other scenarios as well.
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.WithFields(logrus.Fields{
					"schedule": itm.Spec.Schedule,
					"recover":  r,
				}).Debug("Panic parsing schedule")
				validationErrors = append(validationErrors, fmt.Sprintf("invalid schedule: %v", r))
			}
		}()

		if res, err := cron.ParseStandard(itm.Spec.Schedule); err != nil {
			log.WithError(errors.WithStack(err)).WithField("schedule", itm.Spec.Schedule).Debug("Error parsing schedule")
			validationErrors = append(validationErrors, fmt.Sprintf("invalid schedule: %v", err))
		} else {
			schedule = res
		}
	}()

	if len(validationErrors) > 0 {
		return nil, validationErrors
	}

	return schedule, nil
}

// checkIfBackupInNewOrProgress check whether there are backups created by this schedule still in New or InProgress state
func (c *scheduleReconciler) checkIfBackupInNewOrProgress(schedule *velerov1.Schedule) bool {
	log := c.logger.WithField("schedule", kube.NamespaceAndName(schedule))
	backupList := &velerov1.BackupList{}
	options := &client.ListOptions{
		Namespace: schedule.Namespace,
		LabelSelector: labels.Set(map[string]string{
			velerov1.ScheduleNameLabel: label.GetValidName(schedule.Name),
		}).AsSelector(),
	}

	err := c.List(context.Background(), backupList, options)
	if err != nil {
		log.Errorf("fail to list backup for schedule %s/%s: %s", schedule.Namespace, schedule.Name, err.Error())
		return true
	}

	for _, backup := range backupList.Items {
		if backup.Status.Phase == "" || backup.Status.Phase == velerov1.BackupPhaseNew || backup.Status.Phase == velerov1.BackupPhaseInProgress {
			log.Debugf("%s/%s still has backups that are in InProgress or New...", schedule.Namespace, schedule.Name)
			return true
		}
	}
	return false
}

// ifDue check whether schedule is due to create a new backup.
func (c *scheduleReconciler) ifDue(schedule *velerov1.Schedule, cronSchedule cron.Schedule) bool {
	isDue, nextRunTime := getNextRunTime(schedule, cronSchedule, c.clock.Now())
	log := c.logger.WithField("schedule", kube.NamespaceAndName(schedule))

	if !isDue {
		log.WithField("nextRunTime", nextRunTime).Debug("Schedule is not due, skipping")
		return false
	}

	return true
}

// submitBackup create a backup from schedule.
func (c *scheduleReconciler) submitBackup(ctx context.Context, schedule *velerov1.Schedule) error {
	c.logger.WithField("schedule", schedule.Namespace+"/"+schedule.Name).Info("Schedule is due, going to submit backup.")

	now := c.clock.Now()
	// Don't attempt to "catch up" if there are any missed or failed runs - simply
	// trigger a Backup if it's time.
	backup := getBackup(schedule, now)
	if err := c.Create(ctx, backup); err != nil {
		return errors.Wrap(err, "error creating Backup")
	}

	original := schedule.DeepCopy()
	schedule.Status.LastBackup = &metav1.Time{Time: now}

	if err := c.Patch(ctx, schedule, client.MergeFrom(original)); err != nil {
		return errors.Wrapf(err, "error updating Schedule's LastBackup time to %v", schedule.Status.LastBackup)
	}

	return nil
}

func getNextRunTime(schedule *velerov1.Schedule, cronSchedule cron.Schedule, asOf time.Time) (bool, time.Time) {
	var lastBackupTime time.Time
	if schedule.Status.LastBackup != nil {
		lastBackupTime = schedule.Status.LastBackup.Time
	} else {
		lastBackupTime = schedule.CreationTimestamp.Time
	}
	if schedule.Status.LastSkipped != nil && schedule.Status.LastSkipped.After(lastBackupTime) {
		lastBackupTime = schedule.Status.LastSkipped.Time
	}

	nextRunTime := cronSchedule.Next(lastBackupTime)

	return asOf.After(nextRunTime), nextRunTime
}

func getBackup(item *velerov1.Schedule, timestamp time.Time) *velerov1.Backup {
	name := item.TimestampedName(timestamp)
	return builder.
		ForBackup(item.Namespace, name).
		FromSchedule(item).
		Result()
}
