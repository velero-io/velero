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

package output

import (
	"fmt"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// DescribeScheduleInSF describes a schedule in structured format.
func DescribeScheduleInSF(schedule *velerov1api.Schedule, outputFormat string) string {
	return DescribeInSF(func(d *StructuredDescriber) {
		d.DescribeMetadata(schedule.ObjectMeta)

		phase := schedule.Status.Phase
		if phase == "" {
			phase = velerov1api.SchedulePhaseNew
		}
		d.Describe("phase", string(phase))

		if schedule.Spec.Template.ResourcePolicy != nil {
			DescribeResourcePoliciesInSF(d, schedule.Spec.Template.ResourcePolicy)
		}

		if schedule.Spec.Template.UploaderConfig != nil && schedule.Spec.Template.UploaderConfig.ParallelFilesUpload > 0 {
			uploaderConfig := map[string]any{
				"parallelFilesUpload": schedule.Spec.Template.UploaderConfig.ParallelFilesUpload,
			}
			d.Describe("uploaderConfig", uploaderConfig)
		}

		if len(schedule.Status.ValidationErrors) > 0 {
			d.Describe("validationErrors", schedule.Status.ValidationErrors)
		}

		d.Describe("paused", schedule.Spec.Paused)

		DescribeScheduleSpecInSF(d, schedule.Spec)

		DescribeScheduleStatusInSF(d, schedule.Status)
	}, outputFormat)
}

// DescribeScheduleSpecInSF describes a schedule spec in structured format.
func DescribeScheduleSpecInSF(d *StructuredDescriber, spec velerov1api.ScheduleSpec) {
	scheduleSpecInfo := make(map[string]any)
	scheduleSpecInfo["schedule"] = spec.Schedule
	scheduleSpecInfo["template"] = BackupSpecInSF(spec.Template)
	scheduleSpecInfo["paused"] = spec.Paused

	if spec.UseOwnerReferencesInBackup != nil {
		scheduleSpecInfo["useOwnerReferencesInBackup"] = *spec.UseOwnerReferencesInBackup
	}
	if spec.SkipImmediately != nil {
		scheduleSpecInfo["skipImmediately"] = *spec.SkipImmediately
	}

	d.Describe("spec", scheduleSpecInfo)
}

// DescribeScheduleStatusInSF describes a schedule status in structured format.
func DescribeScheduleStatusInSF(d *StructuredDescriber, status velerov1api.ScheduleStatus) {
	scheduleStatusInfo := make(map[string]any)
	lastBackup := "<never>"
	if status.LastBackup != nil && !status.LastBackup.Time.IsZero() {
		lastBackup = fmt.Sprintf("%v", status.LastBackup.Time)
	}
	scheduleStatusInfo["lastBackup"] = lastBackup

	if status.LastSkipped != nil && !status.LastSkipped.Time.IsZero() {
		scheduleStatusInfo["lastSkipped"] = fmt.Sprintf("%v", status.LastSkipped.Time)
	}

	d.Describe("status", scheduleStatusInfo)
}
