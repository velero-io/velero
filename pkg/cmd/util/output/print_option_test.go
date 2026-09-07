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

package output

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestPrintWithFormatBackupStorageLocationServerValidationFrequency(t *testing.T) {
	t.Parallel()

	cmd := cmdWithFormat("get", "table")
	location := &velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: velerov1api.BackupStorageLocationSpec{
			Provider: "aws",
			StorageType: velerov1api.StorageType{
				ObjectStorage: &velerov1api.ObjectStorageLocation{
					Bucket: "bucket",
				},
			},
		},
	}

	printed, err := PrintWithFormat(cmd, location, WithServerValidationFrequency(5*time.Minute))
	require.NoError(t, err)
	assert.True(t, printed)
}

func TestPrintWithFormatBackupStorageLocationListServerValidationFrequency(t *testing.T) {
	t.Parallel()

	cmd := cmdWithFormat("get", "table")
	list := &velerov1api.BackupStorageLocationList{
		Items: []velerov1api.BackupStorageLocation{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
						},
					},
				},
			},
		},
	}

	printed, err := PrintWithFormat(cmd, list, WithServerValidationFrequency(5*time.Minute))
	require.NoError(t, err)
	assert.True(t, printed)
}
