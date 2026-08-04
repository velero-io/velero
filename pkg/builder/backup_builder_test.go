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

package builder

import (
	"testing"

	"github.com/stretchr/testify/assert"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestBackupFromSchedule(t *testing.T) {
	tests := []struct {
		name                string
		schedule            *velerov1api.Schedule
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "no schedule labels/annotations and no template overrides",
			schedule: ForSchedule("velero", "test").
				Result(),
			expectedLabels:      map[string]string{velerov1api.ScheduleNameLabel: "test"},
			expectedAnnotations: nil,
		},
		{
			name: "schedule labels/annotations are copied when no template override is set",
			schedule: ForSchedule("velero", "test").
				ObjectMeta(
					WithLabels("schedule-label", "schedule-value"),
					WithAnnotations("schedule-annotation", "schedule-value"),
				).
				Result(),
			expectedLabels: map[string]string{
				"schedule-label":              "schedule-value",
				velerov1api.ScheduleNameLabel: "test",
			},
			expectedAnnotations: map[string]string{"schedule-annotation": "schedule-value"},
		},
		{
			name: "template.metadata.labels/annotations override schedule labels/annotations",
			schedule: ForSchedule("velero", "test").
				ObjectMeta(
					WithLabels("schedule-label", "schedule-value"),
					WithAnnotations("schedule-annotation", "schedule-value"),
				).
				Template(velerov1api.BackupSpec{
					Metadata: velerov1api.Metadata{
						Labels:      map[string]string{"template-label": "template-value"},
						Annotations: map[string]string{"template-annotation": "template-value"},
					},
				}).
				Result(),
			expectedLabels: map[string]string{
				"template-label":              "template-value",
				velerov1api.ScheduleNameLabel: "test",
			},
			expectedAnnotations: map[string]string{"template-annotation": "template-value"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backup := ForBackup("velero", "test-backup").FromSchedule(test.schedule).Result()
			assert.Equal(t, test.expectedLabels, backup.GetLabels())
			assert.Equal(t, test.expectedAnnotations, backup.GetAnnotations())
		})
	}
}
