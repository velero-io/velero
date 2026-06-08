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

package repository

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/stretchr/testify/assert"

	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func buildBackupRepo(key BackupRepositoryKey, phase velerov1api.BackupRepositoryPhase, seqNum string) velerov1api.BackupRepository {
	return velerov1api.BackupRepository{
		Spec: velerov1api.BackupRepositorySpec{ResticIdentifier: ""},
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1api.SchemeGroupVersion.String(),
			Kind:       "BackupRepository",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1api.DefaultNamespace,
			Name:      fmt.Sprintf("%s-%s-%s-%s", key.VolumeNamespace, key.BackupLocation, key.RepositoryType, seqNum),
			Labels: map[string]string{
				velerov1api.StorageLocationLabel: key.BackupLocation,
				velerov1api.VolumeNamespaceLabel: key.VolumeNamespace,
				velerov1api.RepositoryTypeLabel:  key.RepositoryType,
			},
		},
		Status: velerov1api.BackupRepositoryStatus{
			Phase: phase,
		},
	}
}

func buildBackupRepoPointer(key BackupRepositoryKey, phase velerov1api.BackupRepositoryPhase, seqNum string) *velerov1api.BackupRepository {
	value := buildBackupRepo(key, phase, seqNum)
	return &value
}

func TestGetBackupRepository(t *testing.T) {
	testCases := []struct {
		name                string
		backupRepositories  []velerov1api.BackupRepository
		ensureReady         bool
		backupRepositoryKey BackupRepositoryKey
		expected            *velerov1api.BackupRepository
		expectedErr         string
	}{
		{
			name:        "repository not found",
			expectedErr: "backup repository not found",
		},
		{
			name: "found more than one repository",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns", "fake-bsl", "fake-repository-type"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns", "fake-bsl", "fake-repository-type"}, velerov1api.BackupRepositoryPhaseReady, "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns", "fake-bsl", "fake-repository-type"},
			expectedErr:         "more than one BackupRepository found for workload namespace \"fake-volume-ns\", backup storage location \"fake-bsl\", repository type \"fake-repository-type\"",
		},
		{
			name: "repository not ready, not expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseNotReady, "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			expected:            buildBackupRepoPointer(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseNotReady, "02"),
		},
		{
			name: "repository is new, not expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseNew, "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			expected:            buildBackupRepoPointer(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseNew, "02"),
		},
		{
			name: "repository state is empty, not expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, "", "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			expected:            buildBackupRepoPointer(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, "", "02"),
		},
		{
			name: "repository not ready, expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseNotReady, "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			ensureReady:         true,
			expectedErr:         "backup repository is not ready: ",
		},
		{
			name: "repository is new, expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseNew, "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			ensureReady:         true,
			expectedErr:         "backup repository not provisioned",
		},
		{
			name: "repository state is empty, expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, "", "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			ensureReady:         true,
			expectedErr:         "backup repository not provisioned",
		},
		{
			name: "repository ready, expect ready",
			backupRepositories: []velerov1api.BackupRepository{
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-01", "fake-bsl-01", "fake-repository-type-01"}, velerov1api.BackupRepositoryPhaseNotReady, "01"),
				buildBackupRepo(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseReady, "02")},
			backupRepositoryKey: BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"},
			ensureReady:         true,
			expected:            buildBackupRepoPointer(BackupRepositoryKey{"fake-volume-ns-02", "fake-bsl-02", "fake-repository-type-02"}, velerov1api.BackupRepositoryPhaseReady, "02"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientBuilder := velerotest.NewFakeControllerRuntimeClientBuilder(t)
			clientBuilder.WithLists(&velerov1api.BackupRepositoryList{
				Items: tc.backupRepositories,
			})
			fakeClient := clientBuilder.Build()

			backupRepo, err := GetBackupRepository(t.Context(), fakeClient, velerov1api.DefaultNamespace, tc.backupRepositoryKey, tc.ensureReady)

			if backupRepo != nil && tc.expected != nil {
				backupRepo.ResourceVersion = tc.expected.ResourceVersion
				require.Empty(t, cmp.Diff(*tc.expected, *backupRepo, cmpopts.IgnoreFields(velerov1api.BackupRepository{}, "TypeMeta")))
			} else {
				require.Equal(t, tc.expected, backupRepo)
			}

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}
