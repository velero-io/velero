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
	"testing"
	"time"

	cron "github.com/netresearch/go-cron"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	testclocks "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// Test reconcile function of schedule controller. Pause is not covered as event filter will not allow it through
func TestReconcileOfSchedule(t *testing.T) {
	require.NoError(t, velerov1.AddToScheme(scheme.Scheme))

	newScheduleBuilder := func(phase velerov1.SchedulePhase) *builder.ScheduleBuilder {
		return builder.ForSchedule("ns", "name").Phase(phase)
	}

	tests := []struct {
		name                      string
		scheduleKey               string
		schedule                  *velerov1.Schedule
		fakeClockTime             string
		expectedPhase             string
		expectedValidationErrors  []string
		expectedBackupCreate      *velerov1.Backup
		expectedLastBackup        string
		expectedLastSkipped       string
		backup                    *velerov1.Backup
		reconcilerSkipImmediately bool
	}{
		{
			name:        "missing schedule triggers no backup",
			scheduleKey: "foo/bar",
		},
		{
			name:     "schedule with phase FailedValidation triggers no backup",
			schedule: newScheduleBuilder(velerov1.SchedulePhaseFailedValidation).Result(),
		},
		{
			name:                     "schedule with phase New gets validated and failed if invalid",
			schedule:                 newScheduleBuilder(velerov1.SchedulePhaseNew).Result(),
			expectedPhase:            string(velerov1.SchedulePhaseFailedValidation),
			expectedValidationErrors: []string{"Schedule must be a non-empty valid Cron expression"},
		},
		{
			name:                     "schedule with phase <blank> gets validated and failed if invalid",
			schedule:                 newScheduleBuilder(velerov1.SchedulePhase("")).Result(),
			expectedPhase:            string(velerov1.SchedulePhaseFailedValidation),
			expectedValidationErrors: []string{"Schedule must be a non-empty valid Cron expression"},
		},
		{
			name:                     "schedule with phase Enabled gets re-validated and failed if invalid",
			schedule:                 newScheduleBuilder(velerov1.SchedulePhaseEnabled).Result(),
			expectedPhase:            string(velerov1.SchedulePhaseFailedValidation),
			expectedValidationErrors: []string{"Schedule must be a non-empty valid Cron expression"},
		},
		{
			name:                 "schedule with phase New gets validated and triggers a backup",
			schedule:             newScheduleBuilder(velerov1.SchedulePhaseNew).CronSchedule("@every 5m").Result(),
			fakeClockTime:        "2017-01-01 12:00:00",
			expectedPhase:        string(velerov1.SchedulePhaseEnabled),
			expectedBackupCreate: builder.ForBackup("ns", "name-20170101120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Result(),
			expectedLastBackup:   "2017-01-01 12:00:00",
		},
		{
			name:                "schedule with phase New and SkipImmediately gets validated and does not trigger a backup",
			schedule:            newScheduleBuilder(velerov1.SchedulePhaseNew).CronSchedule("@every 5m").SkipImmediately(ptr.To(true)).Result(),
			fakeClockTime:       "2017-01-01 12:00:00",
			expectedPhase:       string(velerov1.SchedulePhaseEnabled),
			expectedLastSkipped: "2017-01-01 12:00:00",
		},
		{
			name:                 "schedule with phase Enabled gets re-validated and triggers a backup if valid",
			schedule:             newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").Result(),
			fakeClockTime:        "2017-01-01 12:00:00",
			expectedPhase:        string(velerov1.SchedulePhaseEnabled),
			expectedBackupCreate: builder.ForBackup("ns", "name-20170101120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Result(),
			expectedLastBackup:   "2017-01-01 12:00:00",
		},
		{
			name:                 "schedule that's already run gets LastBackup updated",
			schedule:             newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").Result(),
			fakeClockTime:        "2017-01-01 12:00:00",
			expectedBackupCreate: builder.ForBackup("ns", "name-20170101120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Result(),
			expectedLastBackup:   "2017-01-01 12:00:00",
		},
		{
			name:                 "schedule that's already run but has SkippedImmediately=nil gets LastBackup updated",
			schedule:             newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").SkipImmediately(nil).Result(),
			fakeClockTime:        "2017-01-01 12:00:00",
			expectedBackupCreate: builder.ForBackup("ns", "name-20170101120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Result(),
			expectedLastBackup:   "2017-01-01 12:00:00",
		},
		{
			name:                 "schedule that's already run but has SkippedImmediately=false gets LastBackup updated",
			schedule:             newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").SkipImmediately(ptr.To(false)).Result(),
			fakeClockTime:        "2017-01-01 12:00:00",
			expectedBackupCreate: builder.ForBackup("ns", "name-20170101120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Result(),
			expectedLastBackup:   "2017-01-01 12:00:00",
		},
		{
			name:                      "schedule that's already run, server has skipImmediately set to true, and Schedule has SkippedImmediately=nil do not get LastBackup updated",
			schedule:                  newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").SkipImmediately(nil).Result(),
			fakeClockTime:             "2017-01-01 12:00:00",
			expectedLastBackup:        "2000-01-01 00:00:00",
			expectedLastSkipped:       "2017-01-01 12:00:00",
			reconcilerSkipImmediately: true,
		},
		{
			name:                "schedule that's already run but has SkippedImmediately=true do not get LastBackup updated",
			schedule:            newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").SkipImmediately(ptr.To(true)).Result(),
			fakeClockTime:       "2017-01-01 12:00:00",
			expectedLastBackup:  "2000-01-01 00:00:00",
			expectedLastSkipped: "2017-01-01 12:00:00",
		},
		{
			name:          "schedule already has backup in New state.",
			schedule:      newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").Result(),
			expectedPhase: string(velerov1.SchedulePhaseEnabled),
			backup:        builder.ForBackup("ns", "name-20220905120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Phase(velerov1.BackupPhaseNew).Result(),
		},
		{
			name:          "schedule already has backup with empty phase (not yet reconciled).",
			schedule:      newScheduleBuilder(velerov1.SchedulePhaseEnabled).CronSchedule("@every 5m").LastBackupTime("2000-01-01 00:00:00").Result(),
			fakeClockTime: "2017-01-01 12:00:00",
			expectedPhase: string(velerov1.SchedulePhaseEnabled),
			backup:        builder.ForBackup("ns", "name-20220905120000").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).Phase("").Result(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				client   = (&fake.ClientBuilder{}).Build()
				logger   = velerotest.NewLogger()
				testTime time.Time
				err      error
			)

			reconciler := NewScheduleReconciler("namespace", logger, client, metrics.NewServerMetrics(), test.reconcilerSkipImmediately)

			if test.fakeClockTime != "" {
				testTime, err = time.Parse("2006-01-02 15:04:05", test.fakeClockTime)
				require.NoError(t, err, "unable to parse test.fakeClockTime: %v", err)
			}
			reconciler.clock = testclocks.NewFakeClock(testTime)

			if test.schedule != nil {
				require.NoError(t, client.Create(ctx, test.schedule))
			}

			if test.backup != nil {
				require.NoError(t, client.Create(ctx, test.backup))
			}

			scheduleb4reconcile := &velerov1.Schedule{}
			err = client.Get(ctx, types.NamespacedName{Namespace: "ns", Name: "name"}, scheduleb4reconcile)
			if test.schedule != nil {
				require.NoError(t, err)
			}

			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "name"}})
			require.NoError(t, err)

			schedule := &velerov1.Schedule{}
			err = client.Get(ctx, types.NamespacedName{Namespace: "ns", Name: "name"}, schedule)
			if len(test.expectedPhase) > 0 {
				require.NoError(t, err)
				assert.Equal(t, test.expectedPhase, string(schedule.Status.Phase))
			}
			if len(test.expectedValidationErrors) > 0 {
				require.NoError(t, err)
				assert.Equal(t, test.expectedValidationErrors, schedule.Status.ValidationErrors)
			}
			if len(test.expectedLastBackup) > 0 {
				require.NoError(t, err)
				require.NotNil(t, schedule.Status.LastBackup)
				assert.Equal(t, parseTime(test.expectedLastBackup).Unix(), schedule.Status.LastBackup.Unix())
			}
			if len(test.expectedLastSkipped) > 0 {
				require.NoError(t, err)
				require.NotNil(t, schedule.Status.LastSkipped)
				assert.Equal(t, parseTime(test.expectedLastSkipped).Unix(), schedule.Status.LastSkipped.Unix())
			}

			// we expect reconcile to flip SkipImmediately to false if it's true or the server is configured to skip immediately and the schedule doesn't have it set
			if scheduleb4reconcile.Spec.SkipImmediately != nil && *scheduleb4reconcile.Spec.SkipImmediately ||
				test.reconcilerSkipImmediately && scheduleb4reconcile.Spec.SkipImmediately == nil {
				assert.Equal(t, schedule.Spec.SkipImmediately, ptr.To(false))
			}

			backups := &velerov1.BackupList{}
			require.NoError(t, client.List(ctx, backups))

			// If backup associated with schedule's status is in New or InProgress or empty phase,
			// new backup shouldn't be submitted.
			if test.backup != nil &&
				(test.backup.Status.Phase == "" || test.backup.Status.Phase == velerov1.BackupPhaseNew || test.backup.Status.Phase == velerov1.BackupPhaseInProgress) {
				assert.Len(t, backups.Items, 1)
				require.NoError(t, client.Delete(ctx, test.backup))
			}

			require.NoError(t, client.List(ctx, backups))

			if test.expectedBackupCreate == nil {
				assert.Empty(t, backups.Items)
			} else {
				assert.Len(t, backups.Items, 1)
			}
		})
	}
}

func parseTime(timeString string) time.Time {
	res, _ := time.Parse("2006-01-02 15:04:05", timeString)
	return res
}

func TestGetNextRunTime(t *testing.T) {
	defaultSchedule := func() *velerov1.Schedule {
		return builder.ForSchedule("velero", "schedule-1").CronSchedule("@every 5m").Result()
	}

	tests := []struct {
		name                      string
		schedule                  *velerov1.Schedule
		lastRanOffset             string
		expectedDue               bool
		expectedNextRunTimeOffset string
	}{
		{
			name:                      "first run",
			schedule:                  defaultSchedule(),
			expectedDue:               false,
			expectedNextRunTimeOffset: "5m",
		},
		{
			name:                      "just ran",
			schedule:                  defaultSchedule(),
			lastRanOffset:             "0s",
			expectedDue:               false,
			expectedNextRunTimeOffset: "5m",
		},
		{
			name:                      "almost but not quite time to run",
			schedule:                  defaultSchedule(),
			lastRanOffset:             "4m59s",
			expectedDue:               false,
			expectedNextRunTimeOffset: "5m",
		},
		{
			name:                      "time to run again",
			schedule:                  defaultSchedule(),
			lastRanOffset:             "5m",
			expectedDue:               true,
			expectedNextRunTimeOffset: "5m",
		},
		{
			name:                      "several runs missed",
			schedule:                  defaultSchedule(),
			lastRanOffset:             "5h",
			expectedDue:               true,
			expectedNextRunTimeOffset: "5m",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cronSchedule, err := cron.ParseStandard(test.schedule.Spec.Schedule)
			require.NoError(t, err, "unable to parse test.schedule.Spec.Schedule: %v", err)

			testClock := testclocks.NewFakeClock(time.Now())

			if test.lastRanOffset != "" {
				offsetDuration, err := time.ParseDuration(test.lastRanOffset)
				require.NoError(t, err, "unable to parse test.lastRanOffset: %v", err)

				test.schedule.Status.LastBackup = &metav1.Time{Time: testClock.Now().Add(-offsetDuration)}
				test.schedule.CreationTimestamp = *test.schedule.Status.LastBackup
			} else {
				test.schedule.CreationTimestamp = metav1.Time{Time: testClock.Now()}
			}

			nextRunTimeOffset, err := time.ParseDuration(test.expectedNextRunTimeOffset)
			if err != nil {
				panic(err)
			}

			var baseTime time.Time
			if test.lastRanOffset != "" {
				baseTime = test.schedule.Status.LastBackup.Time
			} else {
				baseTime = test.schedule.CreationTimestamp.Time
			}
			expectedNextRunTime := baseTime.Add(nextRunTimeOffset)

			due, nextRunTime := getNextRunTime(test.schedule, cronSchedule, testClock.Now())

			assert.Equal(t, test.expectedDue, due)
			// ignore diffs of under a second. the cron library does some rounding.
			assert.WithinDuration(t, expectedNextRunTime, nextRunTime, time.Second)
		})
	}
}

func TestParseCronSchedule(t *testing.T) {
	// From https://github.com/vmware-tanzu/velero/issues/30, where we originally were using cron.Parse(),
	// which treats the first field as seconds, and not minutes. We want to use cron.ParseStandard()
	// instead, which has the first field as minutes.

	now := time.Date(2017, 8, 10, 12, 27, 0, 0, time.UTC)

	// Start with a Schedule with:
	// - schedule: once a day at 9am
	// - last backup: 2017-08-10 12:27:00 (just happened)
	s := builder.ForSchedule("velero", "schedule-1").CronSchedule("0 9 * * *").LastBackupTime(now.Format("2006-01-02 15:04:05")).Result()

	logger := velerotest.NewLogger()

	c, errs := parseCronSchedule(s, logger)
	require.Empty(t, errs)

	// make sure we're not due and next backup is tomorrow at 9am
	due, next := getNextRunTime(s, c, now)
	assert.False(t, due)
	assert.Equal(t, time.Date(2017, 8, 11, 9, 0, 0, 0, time.UTC), next)

	// advance the clock a couple of hours and make sure nothing has changed
	now = now.Add(2 * time.Hour)
	due, next = getNextRunTime(s, c, now)
	assert.False(t, due)
	assert.Equal(t, time.Date(2017, 8, 11, 9, 0, 0, 0, time.UTC), next)

	// advance clock to 1 minute after due time, make sure due=true
	now = time.Date(2017, 8, 11, 9, 1, 0, 0, time.UTC)
	due, next = getNextRunTime(s, c, now)
	assert.True(t, due)
	assert.Equal(t, time.Date(2017, 8, 11, 9, 0, 0, 0, time.UTC), next)

	// record backup time
	s.Status.LastBackup = &metav1.Time{Time: now}

	// advance clock 1 minute, make sure we're not due and next backup is tomorrow at 9am
	now = time.Date(2017, 8, 11, 9, 2, 0, 0, time.UTC)
	due, next = getNextRunTime(s, c, now)
	assert.False(t, due)
	assert.Equal(t, time.Date(2017, 8, 12, 9, 0, 0, 0, time.UTC), next)
}

func TestGetBackup(t *testing.T) {
	tests := []struct {
		name           string
		schedule       *velerov1.Schedule
		testClockTime  string
		expectedBackup *velerov1.Backup
	}{
		{
			name:           "ensure name is formatted correctly (AM time)",
			schedule:       builder.ForSchedule("foo", "bar").Result(),
			testClockTime:  "2017-07-25 09:15:00",
			expectedBackup: builder.ForBackup("foo", "bar-20170725091500").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "bar")).Result(),
		},
		{
			name:           "ensure name is formatted correctly (PM time)",
			schedule:       builder.ForSchedule("foo", "bar").Result(),
			testClockTime:  "2017-07-25 14:15:00",
			expectedBackup: builder.ForBackup("foo", "bar-20170725141500").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "bar")).Result(),
		},
		{
			name: "ensure schedule backup template is copied",
			schedule: builder.ForSchedule("foo", "bar").
				Template(builder.ForBackup("", "").
					IncludedNamespaces("ns-1", "ns-2").
					ExcludedNamespaces("ns-3").
					IncludedResources("foo", "bar").
					ExcludedResources("baz").
					LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"label": "value"}}).
					TTL(time.Duration(300)).
					Result().
					Spec).
				Result(),
			testClockTime: "2017-07-25 09:15:00",
			expectedBackup: builder.ForBackup("foo", "bar-20170725091500").
				ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "bar")).
				IncludedNamespaces("ns-1", "ns-2").
				ExcludedNamespaces("ns-3").
				IncludedResources("foo", "bar").
				ExcludedResources("baz").
				LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"label": "value"}}).
				TTL(time.Duration(300)).
				Result(),
		},
		{
			name:           "ensure schedule labels are copied",
			schedule:       builder.ForSchedule("foo", "bar").ObjectMeta(builder.WithLabels("foo", "bar", "bar", "baz")).Result(),
			testClockTime:  "2017-07-25 14:15:00",
			expectedBackup: builder.ForBackup("foo", "bar-20170725141500").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "bar", "bar", "baz", "foo", "bar")).Result(),
		},
		{
			name:           "ensure schedule annotations are copied",
			schedule:       builder.ForSchedule("foo", "bar").ObjectMeta(builder.WithAnnotations("foo", "bar", "bar", "baz")).Result(),
			testClockTime:  "2017-07-25 14:15:00",
			expectedBackup: builder.ForBackup("foo", "bar-20170725141500").ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "bar"), builder.WithAnnotations("bar", "baz", "foo", "bar")).Result(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testTime, err := time.Parse("2006-01-02 15:04:05", test.testClockTime)
			require.NoError(t, err, "unable to parse test.testClockTime: %v", err)

			backup := getBackup(test.schedule, testclocks.NewFakeClock(testTime).Now())

			assert.Equal(t, test.expectedBackup.Namespace, backup.Namespace)
			assert.Equal(t, test.expectedBackup.Name, backup.Name)
			assert.Equal(t, test.expectedBackup.Labels, backup.Labels)
			assert.Equal(t, test.expectedBackup.Annotations, backup.Annotations)
			assert.Equal(t, test.expectedBackup.Spec, backup.Spec)
		})
	}
}

func TestCheckIfBackupInNewOrProgress(t *testing.T) {
	require.NoError(t, velerov1.AddToScheme(scheme.Scheme))

	client := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
	logger := velerotest.NewLogger()

	// Create testing schedule
	testSchedule := builder.ForSchedule("ns", "name").Phase(velerov1.SchedulePhaseEnabled).Result()
	err := client.Create(ctx, testSchedule)
	require.NoError(t, err, "fail to create schedule in TestCheckIfBackupInNewOrProgress: %v", err)

	// Create backup in New phase.
	newBackup := builder.ForBackup("ns", "backup-1").
		ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).
		Phase(velerov1.BackupPhaseNew).Result()
	err = client.Create(ctx, newBackup)
	require.NoError(t, err, "fail to create backup in New phase in TestCheckIfBackupInNewOrProgress: %v", err)

	reconciler := NewScheduleReconciler("ns", logger, client, metrics.NewServerMetrics(), false)
	result := reconciler.checkIfBackupInNewOrProgress(testSchedule)
	assert.True(t, result)

	// Clean backup in New phase.
	err = client.Delete(ctx, newBackup)
	require.NoError(t, err, "fail to delete backup in New phase in TestCheckIfBackupInNewOrProgress: %v", err)

	// Create backup in InProgress phase.
	inProgressBackup := builder.ForBackup("ns", "backup-2").
		ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).
		Phase(velerov1.BackupPhaseInProgress).Result()
	err = client.Create(ctx, inProgressBackup)
	require.NoError(t, err, "fail to create backup in InProgress phase in TestCheckIfBackupInNewOrProgress: %v", err)

	reconciler = NewScheduleReconciler("namespace", logger, client, metrics.NewServerMetrics(), false)
	result = reconciler.checkIfBackupInNewOrProgress(testSchedule)
	assert.True(t, result)

	// Clean backup in InProgress phase.
	err = client.Delete(ctx, inProgressBackup)
	require.NoError(t, err, "fail to delete backup in InProgress phase in TestCheckIfBackupInNewOrProgress: %v", err)

	// Create backup with empty phase (not yet reconciled).
	emptyPhaseBackup := builder.ForBackup("ns", "backup-3").
		ObjectMeta(builder.WithLabels(velerov1.ScheduleNameLabel, "name")).
		Phase("").Result()
	err = client.Create(ctx, emptyPhaseBackup)
	require.NoError(t, err, "fail to create backup with empty phase in TestCheckIfBackupInNewOrProgress: %v", err)

	reconciler = NewScheduleReconciler("namespace", logger, client, metrics.NewServerMetrics(), false)
	result = reconciler.checkIfBackupInNewOrProgress(testSchedule)
	assert.True(t, result)
}
