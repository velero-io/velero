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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/velero-io/velero/pkg/apis/velero/v1"
)

func TestSortBackups(t *testing.T) {
	tests := []struct {
		name       string
		backupList *v1.BackupList
		expected   []v1.Backup
	}{
		{
			name: "non-timestamped backups",
			backupList: &v1.BackupList{Items: []v1.Backup{
				{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "c"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "b"}},
			}},
			expected: []v1.Backup{
				{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "b"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "c"}},
			},
		},
		{
			name: "timestamped backups",
			backupList: &v1.BackupList{Items: []v1.Backup{
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030405"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030406"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030407"}},
			}},
			expected: []v1.Backup{
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030407"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030406"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030405"}},
			},
		},
		{
			name: "non-timestamped and timestamped backups",
			backupList: &v1.BackupList{Items: []v1.Backup{
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030405"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030406"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030407"}},
			}},
			expected: []v1.Backup{
				{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030407"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030406"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "schedule-20170102030405"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sortBackupsByPrefixAndTimestamp(test.backupList)

			if assert.Len(t, test.backupList.Items, len(test.expected)) {
				for i := range test.expected {
					assert.Equal(t, test.expected[i].Name, test.backupList.Items[i].Name)
				}
			}
		})
	}
}
