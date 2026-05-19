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

package cacert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/util"
)

func TestGetInsecureSkipTLSVerifyFromBSL(t *testing.T) {
	testCases := []struct {
		name     string
		bslName  string
		bsl      *velerov1api.BackupStorageLocation
		expected bool
	}{
		{
			name:    "BSL with insecureSkipTLSVerify true",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"insecureSkipTLSVerify": "true"}).
				Result(),
			expected: true,
		},
		{
			name:    "BSL with insecureSkipTLSVerify false",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"insecureSkipTLSVerify": "false"}).
				Result(),
			expected: false,
		},
		{
			name:    "BSL with insecureSkipTLSVerify True (case insensitive)",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"insecureSkipTLSVerify": "True"}).
				Result(),
			expected: true,
		},
		{
			name:    "BSL with insecureSkipTLSVerify TRUE (case insensitive)",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"insecureSkipTLSVerify": "TRUE"}).
				Result(),
			expected: true,
		},
		{
			name:    "BSL with config missing the key",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"region": "us-east-1"}).
				Result(),
			expected: false,
		},
		{
			name:    "BSL with nil config",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Result(),
			expected: false,
		},
		{
			name:     "empty BSL name",
			bslName:  "",
			bsl:      nil,
			expected: false,
		},
		{
			name:     "BSL not found",
			bslName:  "missing-bsl",
			bsl:      nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			result, err := GetInsecureSkipTLSVerifyFromBSL(t.Context(), fakeClient, "test-ns", tc.bslName)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetInsecureSkipTLSVerifyFromBackup(t *testing.T) {
	testCases := []struct {
		name     string
		backup   *velerov1api.Backup
		bsl      *velerov1api.BackupStorageLocation
		expected bool
	}{
		{
			name: "backup with BSL having insecureSkipTLSVerify true",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"insecureSkipTLSVerify": "true"}).
				Result(),
			expected: true,
		},
		{
			name: "backup with BSL without insecureSkipTLSVerify",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Result(),
			expected: false,
		},
		{
			name: "backup without storage location",
			backup: builder.ForBackup("test-ns", "test-backup").
				Result(),
			bsl:      nil,
			expected: false,
		},
		{
			name: "BSL not found",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("missing-bsl").
				Result(),
			bsl:      nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tc.backup)
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			result, err := GetInsecureSkipTLSVerifyFromBackup(t.Context(), fakeClient, "test-ns", tc.backup)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetInsecureSkipTLSVerifyFromRestore(t *testing.T) {
	testCases := []struct {
		name     string
		restore  *velerov1api.Restore
		backup   *velerov1api.Backup
		bsl      *velerov1api.BackupStorageLocation
		expected bool
	}{
		{
			name: "restore with backup having BSL with insecureSkipTLSVerify true",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("test-backup").
				Result(),
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Config(map[string]string{"insecureSkipTLSVerify": "true"}).
				Result(),
			expected: true,
		},
		{
			name: "restore with missing backup",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("missing-backup").
				Result(),
			backup:   nil,
			bsl:      nil,
			expected: false,
		},
		{
			name: "restore with backup having BSL without insecureSkipTLSVerify",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("test-backup").
				Result(),
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Result(),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tc.restore)
			if tc.backup != nil {
				objs = append(objs, tc.backup)
			}
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			result, err := GetInsecureSkipTLSVerifyFromRestore(t.Context(), fakeClient, "test-ns", tc.restore)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}
