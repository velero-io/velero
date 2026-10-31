package output

import (
	"testing"

	"github.com/stretchr/testify/assert"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
)

func TestDescribeSchedule(t *testing.T) {
	input1 := builder.ForSchedule("velero", "schedule-1").
		Phase(velerov1api.SchedulePhaseFailedValidation).
		ValidationError("validation failed").Result()
	expect1 := `Name:         schedule-1
Namespace:    velero
Labels:       <none>
Annotations:  <none>

Phase:  FailedValidation

Validation errors:  validation failed

Paused:  false

Schedule:  

Backup Template:
  Namespaces:
    Included:  *
    Excluded:  <none>
  
  Resources:
    Included cluster-scoped:    <none>
    Excluded cluster-scoped:    <none>
    Included namespace-scoped:  *
    Excluded namespace-scoped:  <none>
  
  Label selector:  <none>
  
  Or label selector:  <none>
  
  Storage Location:  
  
  Velero-Native Snapshot PVs:  auto
  Snapshot Move Data:          auto
  Data Mover:                  velero
  
  TTL:  0s
  
  CSISnapshotTimeout:    0s
  ItemOperationTimeout:  0s
  
  Hooks:  <none>

Last Backup:  <never>
`

	input2 := builder.ForSchedule("velero", "schedule-2").
		Phase(velerov1api.SchedulePhaseEnabled).
		CronSchedule("0 0 * * *").
		Template(builder.ForBackup("velero", "backup-1").ParallelFilesUpload(10).Result().Spec).
		LastBackupTime("2023-06-25 15:04:05").Result()
	expect2 := `Name:         schedule-2
Namespace:    velero
Labels:       <none>
Annotations:  <none>

Phase:  Enabled

Uploader config:
  Parallel files upload:   10
  Parallel blocks upload:  0

Paused:  false

Schedule:  0 0 * * *

Backup Template:
  Namespaces:
    Included:  *
    Excluded:  <none>
  
  Resources:
    Included cluster-scoped:    <none>
    Excluded cluster-scoped:    <none>
    Included namespace-scoped:  *
    Excluded namespace-scoped:  <none>
  
  Label selector:  <none>
  
  Or label selector:  <none>
  
  Storage Location:  
  
  Velero-Native Snapshot PVs:  auto
  Snapshot Move Data:          auto
  Data Mover:                  velero
  
  TTL:  0s
  
  CSISnapshotTimeout:    0s
  ItemOperationTimeout:  0s
  
  Hooks:  <none>

Last Backup:  2023-06-25 15:04:05 +0000 UTC
`

	input3 := builder.ForSchedule("velero", "schedule-3").
		Phase(velerov1api.SchedulePhaseEnabled).
		CronSchedule("0 0 * * *").
		Template(builder.ForBackup("velero", "backup-1").DefaultVolumesToFsBackup(true).Result().Spec).
		LastBackupTime("2023-06-25 15:04:05").Result()
	expect3 := `Name:         schedule-3
Namespace:    velero
Labels:       <none>
Annotations:  <none>

Phase:  Enabled

Paused:  false

Schedule:  0 0 * * *

Backup Template:
  Namespaces:
    Included:  *
    Excluded:  <none>
  
  Resources:
    Included cluster-scoped:    <none>
    Excluded cluster-scoped:    <none>
    Included namespace-scoped:  *
    Excluded namespace-scoped:  <none>
  
  Label selector:  <none>
  
  Or label selector:  <none>
  
  Storage Location:  
  
  Velero-Native Snapshot PVs:    auto
  File System Backup (Default):  true
  Snapshot Move Data:            auto
  Data Mover:                    velero
  
  TTL:  0s
  
  CSISnapshotTimeout:    0s
  ItemOperationTimeout:  0s
  
  Hooks:  <none>

Last Backup:  2023-06-25 15:04:05 +0000 UTC
`

	input4 := builder.ForSchedule("velero", "schedule-4").
		Phase(velerov1api.SchedulePhaseEnabled).
		CronSchedule("0 0 * * *").
		Template(builder.ForBackup("velero", "backup-1").DefaultVolumesToFsBackup(false).Result().Spec).
		LastBackupTime("2023-06-25 15:04:05").Result()
	expect4 := `Name:         schedule-4
Namespace:    velero
Labels:       <none>
Annotations:  <none>

Phase:  Enabled

Paused:  false

Schedule:  0 0 * * *

Backup Template:
  Namespaces:
    Included:  *
    Excluded:  <none>
  
  Resources:
    Included cluster-scoped:    <none>
    Excluded cluster-scoped:    <none>
    Included namespace-scoped:  *
    Excluded namespace-scoped:  <none>
  
  Label selector:  <none>
  
  Or label selector:  <none>
  
  Storage Location:  
  
  Velero-Native Snapshot PVs:    auto
  File System Backup (Default):  false
  Snapshot Move Data:            auto
  Data Mover:                    velero
  
  TTL:  0s
  
  CSISnapshotTimeout:    0s
  ItemOperationTimeout:  0s
  
  Hooks:  <none>

Last Backup:  2023-06-25 15:04:05 +0000 UTC
`

	testcases := []struct {
		name   string
		input  *velerov1api.Schedule
		expect string
	}{
		{
			name:   "schedule failed in validation",
			input:  input1,
			expect: expect1,
		},
		{
			name:   "schedule enabled",
			input:  input2,
			expect: expect2,
		},
		{
			name:   "schedule with DefaultVolumesToFsBackup is true",
			input:  input3,
			expect: expect3,
		},
		{
			name:   "schedule with DefaultVolumesToFsBackup is false",
			input:  input4,
			expect: expect4,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			assert.Equal(tt, tc.expect, DescribeSchedule(tc.input))
		})
	}
}
