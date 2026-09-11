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

package controller

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/repository"
	repomocks "github.com/vmware-tanzu/velero/pkg/repository/mocks"
	repotypes "github.com/vmware-tanzu/velero/pkg/repository/types"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// TestBatchDeleteSnapshotsS3MixedRepoType pins how batchDeleteSnapshots
// handles a namespace whose direct snapshots carry MORE THAN ONE repository
// type (e.g. kopia + restic during uploader-type migration). The loader
// (getSnapshotsInBackup) groups snapshots by namespace only and explicitly
// admits per-snapshot RepositoryType values, so the deletion must group the
// batch per repository type and forget each group against its own repository;
// otherwise snapshots in the other repository either fail the forget or leak
// silently with no error reported.
func TestBatchDeleteSnapshotsS3MixedRepoType(t *testing.T) {
	backup := builder.ForBackup("velero", "s3-del-backup").
		StorageLocation("s3-bsl").
		Result()

	s3ReadyRepo := func(repoType string) *velerov1api.BackupRepository {
		repo := repository.NewBackupRepository("velero", repository.BackupRepositoryKey{
			VolumeNamespace: "ns1",
			BackupLocation:  "s3-bsl",
			RepositoryType:  repoType,
		})
		repo.Status.Phase = velerov1api.BackupRepositoryPhaseReady
		return repo
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, s3ReadyRepo("kopia"), s3ReadyRepo("rst"))

	type forgetCall struct {
		repoName string
		ids      []string
	}
	var calls []forgetCall

	repoMgr := repomocks.NewManager(t)
	repoMgr.On("BatchForget", mock.Anything, mock.Anything, mock.Anything).
		Return(nil).
		Run(func(args mock.Arguments) {
			repo, ok := args.Get(1).(*velerov1api.BackupRepository)
			require.True(t, ok)
			ids, ok := args.Get(2).([]string)
			require.True(t, ok)
			calls = append(calls, forgetCall{repoName: repo.Name, ids: ids})
		})

	directSnapshots := map[string][]repotypes.SnapshotIdentifier{
		"ns1": {
			{SnapshotID: "s3-snap-kopia-1", VolumeNamespace: "ns1", BackupStorageLocation: "s3-bsl", RepositoryType: "kopia"},
			{SnapshotID: "s3-snap-rst-1", VolumeNamespace: "ns1", BackupStorageLocation: "s3-bsl", RepositoryType: "rst"},
		},
	}

	errs := batchDeleteSnapshots(t.Context(), repository.NewEnsurer(fakeClient, velerotest.NewLogger(), 2*time.Second), repoMgr, directSnapshots, backup, velerotest.NewLogger())

	require.Empty(t, errs, "each repository must receive only its own snapshot IDs, with no errors")

	// Correct contract: snapshots are grouped per (namespace, repositoryType), so
	// each repository gets exactly one BatchForget call carrying only its own IDs.
	require.Len(t, calls, 2, "each repository type must get its own BatchForget call")

	sort.Slice(calls, func(i, j int) bool { return calls[i].repoName < calls[j].repoName })
	assert.Equal(t, forgetCall{repoName: "ns1-s3-bsl-kopia", ids: []string{"s3-snap-kopia-1"}}, calls[0],
		"the kopia repository must receive only the kopia snapshot")
	assert.Equal(t, forgetCall{repoName: "ns1-s3-bsl-rst", ids: []string{"s3-snap-rst-1"}}, calls[1],
		"the rst repository must receive only the rst snapshot")
}
