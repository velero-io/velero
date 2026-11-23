/*
Copyright 2019 the Velero contributors.

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

package builder

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// ScheduleBuilder builds Schedule objects.
type ScheduleBuilder struct {
	object *velerov1api.Schedule
}

// ForSchedule is the constructor for a ScheduleBuilder.
func ForSchedule(ns, name string) *ScheduleBuilder {
	return &ScheduleBuilder{
		object: &velerov1api.Schedule{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "Schedule",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built Schedule.
func (b *ScheduleBuilder) Result() *velerov1api.Schedule {
	return b.object
}

// ObjectMeta applies functional options to the Schedule's ObjectMeta.
func (b *ScheduleBuilder) ObjectMeta(opts ...ObjectMetaOpt) *ScheduleBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

// Phase sets the Schedule's phase.
func (b *ScheduleBuilder) Phase(phase velerov1api.SchedulePhase) *ScheduleBuilder {
	b.object.Status.Phase = phase
	return b
}

// ValidationError appends to the Schedule's validation errors.
func (b *ScheduleBuilder) ValidationError(err string) *ScheduleBuilder {
	b.object.Status.ValidationErrors = append(b.object.Status.ValidationErrors, err)
	return b
}

// CronSchedule sets the Schedule's cron schedule.
func (b *ScheduleBuilder) CronSchedule(expression string) *ScheduleBuilder {
	b.object.Spec.Schedule = expression
	return b
}

// LastBackupTime sets the Schedule's last backup time.
func (b *ScheduleBuilder) LastBackupTime(val string) *ScheduleBuilder {
	t, _ := time.Parse("2006-01-02 15:04:05", val)
	b.object.Status.LastBackup = &metav1.Time{Time: t}
	return b
}

// Template sets the Schedule's template.
func (b *ScheduleBuilder) Template(spec velerov1api.BackupSpec) *ScheduleBuilder {
	b.object.Spec.Template = spec
	return b
}

// SkipImmediately sets the Schedule's SkipImmediately.
func (b *ScheduleBuilder) SkipImmediately(skip *bool) *ScheduleBuilder {
	b.object.Spec.SkipImmediately = skip
	return b
}
